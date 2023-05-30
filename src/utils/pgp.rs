use std::mem::size_of;
use ed25519_dalek::ed25519::ComponentBytes;
use openpgp_card_pcsc::PcscBackend;
use openpgp_card_sequoia::{
    state::{
        Transaction,
        Open,
    },
    Card,
};
use sequoia_openpgp::{
    packet::{
        key::{
            PublicParts,
            UnspecifiedRole,
        },
    },
    crypto::mpi::Signature,
    types::Curve,
};
use crate::data::{
    identity::Identity,
};

pub fn pgp_pubkey_to_ident(pubkey: &sequoia_openpgp::packet::Key<PublicParts, UnspecifiedRole>) -> Option<Identity> {
    return Some(Identity::V1(match pubkey.mpis() {
        sequoia_openpgp::crypto::mpi::PublicKey::EdDSA { curve, q } => {
            match curve {
                sequoia_openpgp::types::Curve::Ed25519 => {
                    crate::data::identity::v1::Identity::Ed25519(
                        crate::data::identity::v1::Ed25519Identity(
                            ed25519_dalek::VerifyingKey::from_bytes(
                                q.decode_point(&Curve::Ed25519).unwrap().0.try_into().unwrap(),
                            ).unwrap(),
                        ),
                    )
                },
                _ => {
                    return None;
                },
            }
        },
        _ => {
            return None;
        },
    }));
}

pub fn card_to_ident(card: &mut Card<Transaction>) -> Result<Option<Identity>, loga::Error> {
    let card_pubkey = match card.public_key(openpgp_card_sequoia::types::KeyType::Signing)? {
        Some(pk) => pk,
        None => {
            return Ok(None);
        },
    };
    return Ok(pgp_pubkey_to_ident(&card_pubkey));
}

pub fn get_card<
    T,
>(gpg_id: &str, f: impl Fn(&mut Card<Transaction>) -> Result<T, loga::Error>) -> Result<T, loga::Error> {
    let mut card0 = <Card<Open>>::from(PcscBackend::open_by_ident(gpg_id, None)?);
    let mut card = card0.transaction()?;
    return Ok(f(&mut card)?);
}

pub fn extract_pgp_ed25519_sig(gpg_signature: &Signature) -> ed25519_dalek::Signature {
    match gpg_signature {
        sequoia_openpgp::crypto::mpi::Signature::EdDSA { r, s } => {
            let r = r.value_padded(size_of::<ComponentBytes>()).unwrap();
            let s = s.value_padded(size_of::<ComponentBytes>()).unwrap();
            ed25519_dalek::Signature::from_components(r.as_ref().try_into().unwrap(), s.as_ref().try_into().unwrap())
        },
        _ => panic!("signature type doesn't match key type"),
    }
}
