use {
    std::{
        sync::{
            Arc,
            Mutex,
        },
    },
    loga::{
        ea,
        Log,
        ResultContext,
    },
    crate::{
        interface::{
            config::{
                identity::LocalIdentitySecret,
                shared::IdentitySecretArg,
            },
            stored::identity::{
                Identity,
            },
        },
    },
    super::{
        blob::Blob,
        fs_util::read,
    },
};

pub trait IdentitySigner: Send {
    fn identity(&mut self) -> Result<Identity, loga::Error>;
    fn sign(&mut self, data: &[u8]) -> Result<(Identity, Blob), loga::Error>;
}

impl IdentitySigner for LocalIdentitySecret {
    fn sign(&mut self, data: &[u8]) -> Result<(Identity, Blob), loga::Error> {
        return Ok((LocalIdentitySecret::identity(self), LocalIdentitySecret::sign(&self, data)));
    }

    fn identity(&mut self) -> Result<Identity, loga::Error> {
        return Ok(LocalIdentitySecret::identity(self));
    }
}

#[cfg(feature = "card")]
mod card {
    use {
        loga::{
            ea,
            ResultContext,
        },
        openpgp_card_sequoia::{
            Card,
            state::Open,
        },
        sequoia_openpgp::{
            types::HashAlgorithm,
            crypto::Signer,
        },
        crate::{
            utils::{
                pgp::{
                    pgp_eddsa_to_identity,
                    extract_pgp_ed25519_sig,
                },
                blob::{
                    Blob,
                    ToBlob,
                },
            },
            interface::stored::identity::{
                Identity,
                hash_for_ed25519,
            },
        },
        super::IdentitySigner,
    };

    pub struct CardIdentitySigner {
        pub pcsc_id: String,
        pub pin: String,
        pub card: Card<Open>,
    }

    impl IdentitySigner for CardIdentitySigner {
        fn identity(&mut self) -> Result<Identity, loga::Error> {
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

        fn sign(&mut self, data: &[u8]) -> Result<(Identity, Blob), loga::Error> {
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
                        .blob(),
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
                serde_json::from_slice::<LocalIdentitySecret>(
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
