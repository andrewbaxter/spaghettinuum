use std::fs::read;
use loga::{
    ResultContext,
    ea,
};
use crate::{
    interface::{
        identity::{
            Identity,
        },
        spagh_cli::{
            BackedIdentityLocal,
            BackedIdentityArg,
        },
    },
};
use super::blob::Blob;

pub trait IdentitySigner: Send {
    fn sign(&mut self, data: &[u8]) -> Result<(Identity, Blob), loga::Error>;
}

impl IdentitySigner for BackedIdentityLocal {
    fn sign(&mut self, data: &[u8]) -> Result<(Identity, Blob), loga::Error> {
        return Ok((self.identity(), BackedIdentityLocal::sign(&self, data)));
    }
}

#[cfg(feature = "card")]
mod card {
    use loga::{
        ea,
        ResultContext,
    };
    use openpgp_card_sequoia::{
        Card,
        state::Open,
    };
    use sequoia_openpgp::{
        types::HashAlgorithm,
        crypto::Signer,
    };
    use crate::{
        interface::identity::{
            Identity,
            self,
        },
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
    };
    use super::IdentitySigner;

    pub struct CardIdentitySigner {
        pub pcsc_id: String,
        pub pin: String,
        pub card: Card<Open>,
    }

    impl IdentitySigner for CardIdentitySigner {
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
                            .sign(HashAlgorithm::SHA512, &identity::hash_for_ed25519(data))
                            .map_err(|e| loga::err_with("Card signature failed", ea!(err = e)))?,
                    )
                        .to_bytes()
                        .blob(),
                ),
            );
        }
    }
}

pub fn get_identity_signer(ident: BackedIdentityArg) -> Result<Box<dyn IdentitySigner>, loga::Error> {
    match ident {
        BackedIdentityArg::Local(ident_config) => {
            let log = &loga::new().fork(ea!(path = ident_config.to_string_lossy()));
            let ident_data =
                serde_json::from_slice::<BackedIdentityLocal>(
                    &read(&ident_config).stack_context(log, "Error reading identity file")?,
                ).stack_context(log, "Error parsing json in identity file")?;
            return Ok(Box::new(ident_data));
        },
        #[cfg(feature = "card")]
        BackedIdentityArg::Card { pcsc_id, pin } => {
            let pin = if pin == "-" {
                rpassword::prompt_password(
                    "Enter your pin to sign announcement: ",
                ).context("Error securely reading pin")?
            } else {
                pin
            };
            return Ok(Box::new(card::CardIdentitySigner {
                card: openpgp_card_pcsc::PcscBackend::open_by_ident(&pcsc_id, None)
                    .context_with("Failed to open card", ea!(card = pcsc_id))?
                    .into(),
                pcsc_id: pcsc_id,
                pin: pin,
            }));
        },
    };
}
