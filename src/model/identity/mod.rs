use std::fmt::Display;
use loga::{
    ea,
};
use crate::{
    versioned,
};

pub mod v1;

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

impl Identity {
    pub fn from_str(data: &str) -> Result<Self, loga::Error> {
        return Ok(
            Self::from_bytes(
                &zbase32::decode_full_bytes_str(
                    data,
                ).map_err(|e| loga::Error::new("Failed to decode zbase32 for identity", ea!(err = e)))?,
            )?,
        );
    }

    pub fn to_sql(&self) -> Vec<u8> {
        return self.to_bytes();
    }

    pub fn from_sql(data: Vec<u8>) -> Result<Self, loga::Error> {
        return Self::from_bytes(&data);
    }

    pub fn new() -> (Self, IdentitySecret) {
        let (ident, secret) = v1::Ed25519Identity::new();
        return (
            Identity::V1(v1::Identity::Ed25519(ident)),
            IdentitySecret::V1(v1::IdentitySecret::Ed25519(secret)),
        );
    }
}

pub trait IdentityMethods {
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool;
}

impl IdentityMethods for Identity {
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        match self {
            Identity::V1(v) => v.verify(message, signature),
        }
    }
}

versioned!(
    IdentitySecret,
    Debug,
    Clone;
    (V1, 1, v1::IdentitySecret)
);

pub trait IdentitySecretMethods {
    fn sign(&self, data: &[u8]) -> Vec<u8>;
}

impl IdentitySecretMethods for IdentitySecret {
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        match self {
            IdentitySecret::V1(v) => v.sign(data),
        }
    }
}
