use {
    ed25519_dalek::ed25519::ComponentBytes,
    openpgp_card_pcsc::PcscBackend,
    openpgp_card_sequoia::{
        Card,
        state::{
            Open,
            Transaction,
        },
    },
    sequoia_openpgp::{
        crypto::mpi::{
            MPI,
            Signature,
        },
        packet::key::{
            PublicParts,
            UnspecifiedRole,
        },
        types::Curve,
    },
    spaghettinuum::interface::public_key::{
        IdentityPublicKey,
        self,
    },
    std::mem::size_of,
};

pub fn card_to_ident(card: &mut Card<Transaction>) -> Result<Option<IdentityPublicKey>, loga::Error> {
    let card_pubkey = match card.public_key(openpgp_card_sequoia::types::KeyType::Signing)? {
        Some(pk) => pk,
        None => {
            return Ok(None);
        },
    };
    return Ok(pgp_pubkey_to_ident(&card_pubkey));
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

pub fn get_card<
    T,
>(gpg_id: &str, f: impl Fn(&mut Card<Transaction>) -> Result<T, loga::Error>) -> Result<T, loga::Error> {
    let mut card0 = <Card<Open>>::from(PcscBackend::open_by_ident(gpg_id, None)?);
    let mut card = card0.transaction()?;
    return Ok(f(&mut card)?);
}

pub fn pgp_eddsa_to_identity(curve: &Curve, q: &MPI) -> Option<IdentityPublicKey> {
    match curve {
        sequoia_openpgp::types::Curve::Ed25519 => {
            Some(
                IdentityPublicKey::V1(
                    public_key::v1::IdentityPublicKey::Ed25519(
                        public_key::v1::Ed25519PublicKey(
                            ed25519_dalek::VerifyingKey::from_bytes(
                                q.decode_point(&Curve::Ed25519).unwrap().0.try_into().unwrap(),
                            ).unwrap(),
                        ),
                    ),
                ),
            )
        },
        _ => {
            return None;
        },
    }
}

pub fn pgp_pubkey_to_ident(
    pubkey: &sequoia_openpgp::packet::Key<PublicParts, UnspecifiedRole>,
) -> Option<IdentityPublicKey> {
    return Some(match pubkey.mpis() {
        sequoia_openpgp::crypto::mpi::PublicKey::EdDSA { curve, q } => {
            pgp_eddsa_to_identity(curve, q)?
        },
        _ => {
            return None;
        },
    });
}
