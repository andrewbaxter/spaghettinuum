use {
    super::fs_util::read,
    crate::interface::config::shared::IdentitySecretArg,
    loga::{
        ea,
        Log,
        ResultContext,
    },
    rand::rngs::OsRng,
    spaghettinuum::interface::public_key::{
        self,
        PublicKey,
        LocalSecret,
    },
    std::{
        path::Path,
        sync::{
            Arc,
            Mutex,
        },
    },
    tokio::fs::write,
};

pub fn new_local_identity_secret() -> (PublicKey, LocalSecret) {
    let keypair = ed25519_dalek::SigningKey::generate(&mut OsRng {});
    let ident = public_key::v1::Ed25519PublicKey(keypair.verifying_key());
    let secret = public_key::v1::Ed25519LocalSecret(keypair);
    return (
        PublicKey::V1(public_key::v1::PublicKey::Ed25519(ident)),
        LocalSecret::V1(public_key::v1::LocalSecret::Ed25519(secret)),
    );
}

pub async fn write_identity_secret(path: &Path, identity: &LocalSecret) -> Result<(), loga::Error> {
    write(path, serde_json::to_string_pretty(identity).unwrap().as_bytes())
        .await
        .context("Failed to write identity secret to file")?;
    return Ok(());
}

pub trait IdentitySigner: Send {
    fn identity(&mut self) -> Result<PublicKey, loga::Error>;
    fn sign(&mut self, data: &[u8]) -> Result<(PublicKey, Vec<u8>), loga::Error>;
}

impl IdentitySigner for LocalSecret {
    fn sign(&mut self, data: &[u8]) -> Result<(PublicKey, Vec<u8>), loga::Error> {
        return Ok((LocalSecret::public_key(self), LocalSecret::sign(&self, data)));
    }

    fn identity(&mut self) -> Result<PublicKey, loga::Error> {
        return Ok(LocalSecret::public_key(self));
    }
}

#[cfg(feature = "card")]
mod card {
    use {
        super::IdentitySigner,
        crate::utils::pgp::{
            extract_pgp_ed25519_sig,
            pgp_eddsa_to_identity,
        },
        loga::{
            ea,
            ResultContext,
        },
        openpgp_card_sequoia::{
            state::Open,
            Card,
        },
        sequoia_openpgp::{
            crypto::Signer,
            types::HashAlgorithm,
        },
        spaghettinuum::interface::public_key::{
            hash_for_ed25519,
            PublicKey,
        },
    };

    pub struct CardIdentitySigner {
        pub pcsc_id: String,
        pub pin: String,
        pub card: Card<Open>,
    }

    impl IdentitySigner for CardIdentitySigner {
        fn identity(&mut self) -> Result<PublicKey, loga::Error> {
            let mut transaction = self.card.transaction().context("Failed to start card transaction")?;
            transaction
                .verify_user_for_signing(self.pin.as_bytes())
                .context_with("Error unlocking card with pin", ea!(card = self.pcsc_id))?;
            let mut user = transaction.signing_card().unwrap();
            let signer_interact = || eprintln!("Card {} requests interaction to sign", self.pcsc_id);
            let signer = user.signer(&signer_interact).context("Failed to get signer from card")?;
            loop {
                match signer.public() {
                    sequoia_openpgp::packet::Key::V4(k) => match k.mpis() {
                        sequoia_openpgp::crypto::mpi::PublicKey::EdDSA { curve, q } => {
                            if let Some(i) = pgp_eddsa_to_identity(curve, q) {
                                return Ok(i);
                            };
                        },
                        _ => (),
                    },
                    _ => (),
                };
                return Err(loga::err("Unsupported key type - must be Ed25519"));
            }
        }

        fn sign(&mut self, data: &[u8]) -> Result<(PublicKey, Vec<u8>), loga::Error> {
            let mut transaction = self.card.transaction().context("Failed to start card transaction")?;
            transaction
                .verify_user_for_signing(self.pin.as_bytes())
                .context_with("Error unlocking card with pin", ea!(card = self.pcsc_id))?;
            let mut user = transaction.signing_card().unwrap();
            let signer_interact = || eprintln!("Card {} requests interaction to sign", self.pcsc_id);
            let mut signer = user.signer(&signer_interact).context("Failed to get signer from card")?;
            let identity;
            loop {
                match signer.public() {
                    sequoia_openpgp::packet::Key::V4(k) => match k.mpis() {
                        sequoia_openpgp::crypto::mpi::PublicKey::EdDSA { curve, q } => {
                            if let Some(i) = pgp_eddsa_to_identity(curve, q) {
                                identity = i;
                                break;
                            };
                        },
                        _ => (),
                    },
                    _ => (),
                };
                return Err(loga::err("Unsupported key type - must be Ed25519"));
            }
            return Ok(
                (
                    identity,
                    extract_pgp_ed25519_sig(
                        &signer
                            .sign(HashAlgorithm::SHA512, &hash_for_ed25519(data))
                            .map_err(|e| loga::err_with("Card signature failed", ea!(err = e)))?,
                    )
                        .to_bytes()
                        .to_vec(),
                ),
            );
        }
    }
}

pub async fn get_identity_signer(ident: IdentitySecretArg) -> Result<Arc<Mutex<dyn IdentitySigner>>, loga::Error> {
    match ident {
        IdentitySecretArg::Local(ident_config) => {
            let log = &Log::new().fork(ea!(path = ident_config.to_string_lossy()));
            let ident_data =
                serde_json::from_slice::<LocalSecret>(
                    &read(&ident_config).await.stack_context(log, "Error reading identity file")?,
                ).stack_context(log, "Error parsing json in identity file")?;
            return Ok(Arc::new(Mutex::new(ident_data)));
        },
        #[cfg(feature = "card")]
        IdentitySecretArg::Card { pcsc_id, pin } => {
            let pin = if pin == "-" {
                rpassword::prompt_password(
                    "Enter your pin to sign announcement: ",
                ).context("Error securely reading pin")?
            } else {
                pin
            };
            return Ok(Arc::new(Mutex::new(card::CardIdentitySigner {
                card: openpgp_card_pcsc::PcscBackend::open_by_ident(&pcsc_id, None)
                    .context_with("Failed to open card", ea!(card = pcsc_id))?
                    .into(),
                pcsc_id: pcsc_id,
                pin: pin,
            })));
        },
    };
}
