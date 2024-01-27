use serde::{
    Deserialize,
    Serialize,
};
use crate::{
    interface::identity::Identity,
    utils::blob::Blob,
};

pub mod v1;

pub use v1 as latest;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackedIdentityLocal {
    V1(v1::LocalIdentitySecret),
}

impl BackedIdentityLocal {
    pub fn new() -> (Identity, Self) {
        let (ident, secret) = v1::LocalIdentitySecret::new();
        return (Identity::V1(ident), BackedIdentityLocal::V1(secret));
    }

    pub fn identity(&self) -> Identity {
        match self {
            BackedIdentityLocal::V1(s) => Identity::V1(s.identity()),
        }
    }

    pub fn sign(&self, message: &[u8]) -> Blob {
        match self {
            BackedIdentityLocal::V1(v) => v.sign(message).blob(),
        }
    }
}
