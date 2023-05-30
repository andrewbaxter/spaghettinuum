use loga::ea;
use crate::versioned;
use std::fmt::Display;

pub mod v1;

versioned!(
    NodeIdentity,
    PartialEq,
    Eq,
    Clone,
    Hash;
    (V1, 1, v1::NodeIdentity)
);

impl Display for NodeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <dyn Display>::fmt(&zbase32::encode_full_bytes(&self.to_bytes()), f)
    }
}

impl std::fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <dyn std::fmt::Debug>::fmt(&<dyn Display>::to_string(self), f)
    }
}

pub trait NodeIdentityMethods {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), loga::Error>;
}

impl NodeIdentityMethods for NodeIdentity {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), loga::Error> {
        match self {
            NodeIdentity::V1(v) => v.verify(message, signature),
        }
    }
}

impl NodeIdentity {
    pub fn new() -> (Self, NodeSecret) {
        let (ident, secret) = v1::Ed25519NodeIdentity::new();
        return (
            NodeIdentity::V1(v1::NodeIdentity::Ed25519(ident)),
            NodeSecret::V1(v1::NodeSecret::Ed25519(secret)),
        );
    }

    pub fn from_str(text: &str) -> Result<Self, loga::Error> {
        Ok(Self::from_bytes(&zbase32::decode_full_bytes_str(text).map_err(|e| {
            loga::Error::new("Unable to decode node identity zbase32", ea!(text = e))
        })?)?)
    }
}

versioned!(
    NodeSecret,
    Debug,
    Clone;
    (V1, 1, v1::NodeSecret)
);

impl NodeSecret {
    pub fn get_identity(&self) -> NodeIdentity {
        match self {
            NodeSecret::V1(v) => NodeIdentity::V1(v.get_identity()),
        }
    }
}

pub trait NodeSecretMethods {
    fn sign(&self, message: &[u8]) -> Box<[u8]>;
}

impl NodeSecretMethods for NodeSecret {
    fn sign(&self, message: &[u8]) -> Box<[u8]> {
        match self {
            NodeSecret::V1(v) => v.sign(message),
        }
    }
}
