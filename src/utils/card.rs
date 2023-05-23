use openpgp_card_pcsc::PcscBackend;
use openpgp_card_sequoia::{
    state::{
        Transaction,
        Open,
    },
    Card,
};
use crate::model::{
    identity::Identity,
    self,
};

pub fn card_to_ident(card: &mut Card<Transaction>) -> Result<Option<Identity>, loga::Error> {
    let card_pubkey = match card.public_key(openpgp_card_sequoia::types::KeyType::Signing)? {
        Some(pk) => pk,
        None => {
            return Ok(None);
        },
    };
    return Ok(Some(Identity::V1(match card_pubkey.mpis() {
        sequoia_openpgp::crypto::mpi::PublicKey::EdDSA { curve, q } => {
            match curve {
                sequoia_openpgp::types::Curve::Ed25519 => {
                    // GPG stores with standard (eddsa-paper-specified) encoding, prefixed with one
                    // 0x40 byte.  Strip that.
                    model::identity::v1::Identity::Ed25519(
                        model::identity::v1::Ed25519Identity(
                            ed25519_dalek::VerifyingKey::from_bytes(q.value()[1..].try_into().unwrap()).unwrap(),
                        ),
                    )
                },
                _ => {
                    return Ok(None);
                },
            }
        },
        _ => {
            return Ok(None);
        },
    })));
}

pub fn get_card<
    T,
>(gpg_id: &str, f: impl Fn(&mut Card<Transaction>) -> Result<T, loga::Error>) -> Result<T, loga::Error> {
    let mut card0 = <Card<Open>>::from(PcscBackend::open_by_ident(gpg_id, None)?);
    let mut card = card0.transaction()?;
    return Ok(f(&mut card)?);
}
