use std::fmt::Display;
use good_ormning_runtime::sqlite::{
    GoodOrmningCustomString,
};
use loga::{
    ea,
};
use sha2::{
    Sha512,
    Digest,
};
use crate::{
    versioned,
};

pub mod v1;

/// For gpg-card compatibility we doubly hash the messages passed in for
/// signatures.  GPG takes a hash, passes it in as an ed25519 message, and the
/// ed25519 sign method hashes it again.
pub fn hash_for_ed25519(data: &[u8]) -> Vec<u8> {
    let mut hash = Sha512::new();
    hash.update(data);
    return hash.finalize().to_vec();
}

versioned!(
    Identity,
    PartialEq,
    Eq,
    Clone,
    Hash;
    (V1, 1, v1::Identity)
);

impl Display for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <dyn Display>::fmt(&zbase32::encode_full_bytes(&self.to_bytes()), f)
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <dyn std::fmt::Debug>::fmt(&<dyn Display>::to_string(self), f)
    }
}

impl GoodOrmningCustomString<Identity> for Identity {
    fn to_sql<'a>(value: &'a Identity) -> std::borrow::Cow<'a, str> {
        return value.to_string().into();
    }

    fn from_sql(value: String) -> Result<Identity, String> {
        return Self::from_str(&value).map_err(|e| e.to_string());
    }
}

impl Identity {
    pub fn from_str(data: &str) -> Result<Self, loga::Error> {
        return Ok(
            Self::from_bytes(
                &zbase32::decode_full_bytes_str(
                    data,
                ).map_err(|e| loga::err_with("Failed to decode zbase32 for identity", ea!(err = e)))?,
            )?,
        );
    }
}

pub trait IdentityVersionMethods {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), &'static str>;
}

impl Identity {
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), &'static str> {
        match self {
            Identity::V1(v) => v.verify(message, signature),
        }
    }
}
