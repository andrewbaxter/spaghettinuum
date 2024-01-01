#[cfg(test)]
mod tests {
    use std::panic;
    use itertools::Itertools;
    use sequoia_openpgp::{
        packet::{
            prelude::Key4,
            key::{
                SecretParts,
                UnspecifiedRole,
            },
            Key,
        },
        crypto::{
            Signer,
        },
    };
    use crate::{
        utils::{
            pgp::{
                extract_pgp_ed25519_sig,
                pgp_pubkey_to_ident,
            },
        },
        interface::identity,
    };

    #[test]
    fn gpg_ed25519_to_dalek2() {
        let gpg_k: Key<SecretParts, UnspecifiedRole> =
            Key4::generate_ecc(true, sequoia_openpgp::types::Curve::Ed25519).unwrap().into();
        let mut gpg_k = gpg_k.into_keypair().unwrap();
        let message = "hello";
        let hash = identity::hash_for_ed25519(message.as_bytes());
        let gpg_sig = gpg_k.sign(sequoia_openpgp::types::HashAlgorithm::SHA512, &hash).unwrap();
        match gpg_k.public().verify(&gpg_sig, sequoia_openpgp::types::HashAlgorithm::SHA512, &hash) {
            Ok(_) => { },
            Err(e) => {
                panic!("gpg failed to verify: {:?}", e);
            },
        };
        let dalek_sig = extract_pgp_ed25519_sig(&gpg_sig);
        let ident = pgp_pubkey_to_ident(gpg_k.public()).unwrap();
        eprintln!("gpg pub {:?}", gpg_k.public());
        match &ident {
            identity::Identity::V1(v1) => match v1 {
                identity::v1::Identity::Ed25519(i) => eprintln!(
                    "dalek pub {:02x}",
                    i.0.as_bytes().iter().format(" ")
                ),
            },
        };
        eprintln!("gpg sig {:?}", gpg_sig);
        eprintln!(
            "dalek sig r {:02x} s {:02x}",
            dalek_sig.r_bytes().iter().format(" "),
            dalek_sig.s_bytes().iter().format(" ")
        );
        if ident.verify(message.as_bytes(), &dalek_sig.to_bytes()).is_err() {
            panic!("verify failed");
        }
    }
}
