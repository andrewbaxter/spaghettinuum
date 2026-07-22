#[cfg(feature = "card")]
mod card {
    use {
        crate::utils::pgp::{
            extract_pgp_ed25519_sig,
            pgp_eddsa_to_identity,
        },
        loga::{
            ResultContext,
            ea,
        },
        openpgp_card_sequoia::{
            Card,
            state::Open,
        },
        sequoia_openpgp::{
            crypto::Signer,
            types::HashAlgorithm,
        },
        spaghettinuum::interface::{
            identity::{
                IdentityPublicKey,
                IdentityPublicKeyChain,
                hash_for_ed25519,
            },
            signature_chain::ChainLink,
        },
        super::IdentitySigner,
    };

    pub struct CardIdentitySigner {
        pub card: Card<Open>,
        pub pcsc_id: String,
        pub pin: String,
        pub public_key_chain: Option<IdentityPublicKeyChain>,
    }

    impl CardIdentitySigner {
        fn read_root_from_card(&mut self) -> Result<IdentityPublicKey, loga::Error> {
            let mut transaction = self.card.transaction().context("Failed to start card transaction")?;
            transaction
                .verify_user_for_signing(self.pin.as_bytes())
                .context_with("Error unlocking card with pin", ea!(card = self.pcsc_id))?;
            let mut user = transaction.signing_card().unwrap();
            let signer_interact = || eprintln!("Card {} requests interaction to sign", self.pcsc_id);
            let signer = user.signer(&signer_interact).context("Failed to get signer from card")?;
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

    impl IdentitySigner for CardIdentitySigner {
        fn chain(&mut self) -> Result<Vec<ChainLink>, loga::Error> {
            match &self.public_key_chain {
                Some(c) => return Ok(c.chain.clone()),
                None => return Ok(vec![]),
            }
        }

        fn public_key_root(&mut self) -> Result<IdentityPublicKey, loga::Error> {
            match &self.public_key_chain {
                Some(c) => return Ok(c.root),
                None => return self.read_root_from_card(),
            }
        }

        fn sign(&mut self, data: &[u8]) -> Result<(IdentityPublicKey, Vec<ChainLink>, Vec<u8>), loga::Error> {
            let (root, chain) = match &self.public_key_chain {
                Some(c) => (c.root, c.chain.clone()),
                None => (self.read_root_from_card()?, vec![]),
            };
            let mut transaction = self.card.transaction().context("Failed to start card transaction")?;
            transaction
                .verify_user_for_signing(self.pin.as_bytes())
                .context_with("Error unlocking card with pin", ea!(card = self.pcsc_id))?;
            let mut user = transaction.signing_card().unwrap();
            let signer_interact = || eprintln!("Card {} requests interaction to sign", self.pcsc_id);
            let mut signer = user.signer(&signer_interact).context("Failed to get signer from card")?;
            let sig =
                extract_pgp_ed25519_sig(
                    &signer
                        .sign(HashAlgorithm::SHA512, &hash_for_ed25519(data))
                        .map_err(|e| loga::err_with("Card signature failed", ea!(err = e)))?,
                )
                    .to_bytes()
                    .to_vec();
            return Ok((root, chain, sig));
        }
    }
}

#[cfg(feature = "card")]
pub use card::CardIdentitySigner;
use {
    crate::interface::config::shared::IdentitySecretArg,
    loga::{
        Log,
        ResultContext,
        ea,
    },
    rand::rngs::OsRng,
    spaghettinuum::interface::{
        identity::{
            IdentityPublicKey,
            IdentityPublicKeyChain,
            IdentitySecret,
            self,
            v1::{
                Ed25519LocalSecret,
                Secret,
            },
        },
        signature_chain::ChainLink,
    },
    std::{
        path::Path,
        sync::{
            Arc,
            Mutex,
        },
    },
    super::fs_util::read,
    tokio::fs::write,
};

pub trait IdentitySigner: Send {
    fn chain(&mut self) -> Result<Vec<ChainLink>, loga::Error>;
    fn public_key_root(&mut self) -> Result<IdentityPublicKey, loga::Error>;
    fn sign(&mut self, data: &[u8]) -> Result<(IdentityPublicKey, Vec<ChainLink>, Vec<u8>), loga::Error>;
}

pub async fn get_identity_signer(ident: IdentitySecretArg) -> Result<Arc<Mutex<dyn IdentitySigner>>, loga::Error> {
    let secret = read_identity_secret(&ident.path).await?;
    let (public_key_chain, inner) = match secret {
        IdentitySecret::V1(s) => (s.public_key_chain, s.secret),
    };
    match inner {
        Secret::Local(key) => {
            return Ok(Arc::new(Mutex::new(LocalIdentitySigner::new(public_key_chain, key))));
        },
        #[cfg(feature = "card")]
        Secret::Card { pcsc_id } => {
            let pin = match ident.pin {
                Some(pin) => if pin == "-" {
                    rpassword::prompt_password("Enter your pin to sign: ").context("Error securely reading pin")?
                } else {
                    pin
                },
                None => {
                    return Err(
                        loga::err_with(
                            "Identity secret references a card but no pin was provided",
                            ea!(card = pcsc_id),
                        ),
                    );
                },
            };
            return Ok(Arc::new(Mutex::new(CardIdentitySigner {
                public_key_chain: public_key_chain,
                card: openpgp_card_pcsc::PcscBackend::open_by_ident(&pcsc_id, None)
                    .context_with("Failed to open card", ea!(card = pcsc_id))?
                    .into(),
                pcsc_id: pcsc_id,
                pin: pin,
            })));
        },
        #[cfg(not(feature = "card"))]
        Secret::Card { pcsc_id } => {
            return Err(
                loga::err_with(
                    "Identity secret references a card but this build has no card support",
                    ea!(card = pcsc_id),
                ),
            );
        },
    }
}

pub struct LocalIdentitySigner {
    public_key_chain: Option<IdentityPublicKeyChain>,
    secret: Ed25519LocalSecret,
}

impl LocalIdentitySigner {
    pub fn new(public_key_chain: Option<IdentityPublicKeyChain>, secret: Ed25519LocalSecret) -> Self {
        return Self {
            public_key_chain: public_key_chain,
            secret: secret,
        };
    }

    fn root_and_chain(&self) -> (IdentityPublicKey, Vec<ChainLink>) {
        match &self.public_key_chain {
            Some(c) => return (c.root, c.chain.clone()),
            None => return (
                IdentityPublicKey::V1(identity::v1::IdentityPublicKey::Ed25519(self.secret.public_key())),
                vec![],
            ),
        }
    }
}

impl IdentitySigner for LocalIdentitySigner {
    fn chain(&mut self) -> Result<Vec<ChainLink>, loga::Error> {
        return Ok(self.root_and_chain().1);
    }

    fn public_key_root(&mut self) -> Result<IdentityPublicKey, loga::Error> {
        return Ok(self.root_and_chain().0);
    }

    fn sign(&mut self, data: &[u8]) -> Result<(IdentityPublicKey, Vec<ChainLink>, Vec<u8>), loga::Error> {
        let (root, chain) = self.root_and_chain();
        return Ok((root, chain, self.secret.sign(data)));
    }
}

#[cfg(feature = "card")]
pub fn new_card_identity_secret(pcsc_id: String) -> Result<IdentitySecret, loga::Error> {
    use {
        crate::utils::pgp::card_to_ident,
        openpgp_card_sequoia::{
            Card,
            state::Open,
        },
    };

    let mut card: Card<Open> =
        openpgp_card_pcsc::PcscBackend::open_by_ident(&pcsc_id, None)
            .context_with("Failed to open card", ea!(card = pcsc_id))?
            .into();
    let mut transaction = card.transaction().context("Failed to start card transaction")?;
    let root = card_to_ident(&mut transaction)?.context("Card doesn't have an Ed25519 signing key")?;
    return Ok(IdentitySecret::V1(identity::v1::IdentitySecret {
        public_key_chain: Some(IdentityPublicKeyChain {
            root: root,
            chain: vec![],
        }),
        secret: Secret::Card { pcsc_id: pcsc_id },
    }));
}

pub fn new_local_identity_secret() -> IdentitySecret {
    let keypair = ed25519_dalek::SigningKey::generate(&mut OsRng {});
    return IdentitySecret::V1(identity::v1::IdentitySecret {
        public_key_chain: None,
        secret: Secret::Local(identity::v1::Ed25519LocalSecret(keypair)),
    });
}

pub fn new_subkey(parent: &mut dyn IdentitySigner, expires: Option<u64>) -> Result<IdentitySecret, loga::Error> {
    let keypair = ed25519_dalek::SigningKey::generate(&mut OsRng {});
    let new_pub =
        IdentityPublicKey::V1(
            identity::v1::IdentityPublicKey::Ed25519(identity::v1::Ed25519PublicKey(keypair.verifying_key())),
        );
    let new_secret = identity::v1::Ed25519LocalSecret(keypair);
    let content = ChainLink::serialize_content(new_pub, expires);
    let (root, mut chain, signature) = parent.sign(&content)?;
    chain.push(ChainLink {
        content: content,
        signature: signature,
    });
    return Ok(IdentitySecret::V1(identity::v1::IdentitySecret {
        public_key_chain: Some(IdentityPublicKeyChain {
            root: root,
            chain: chain,
        }),
        secret: Secret::Local(new_secret),
    }));
}

pub async fn read_identity_secret(path: &Path) -> Result<IdentitySecret, loga::Error> {
    let log = Log::new().fork(ea!(path = path.to_string_lossy()));
    return Ok(
        serde_json::from_slice::<IdentitySecret>(
            &read(path).await.stack_context(&log, "Error reading identity file")?,
        ).stack_context(&log, "Error parsing json in identity file")?,
    );
}

pub async fn write_identity_secret(path: &Path, identity: &IdentitySecret) -> Result<(), loga::Error> {
    write(path, serde_json::to_string_pretty(identity).unwrap().as_bytes())
        .await
        .context("Failed to write identity secret to file")?;
    return Ok(());
}
