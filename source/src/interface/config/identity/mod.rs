use serde::{
    Deserialize,
    Serialize,
};
use crate::{
    interface::stored::identity::Identity,
    utils::blob::{
        Blob,
        ToBlob,
    },
};

pub mod v1;

pub use v1 as latest;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum LocalIdentitySecret {
    V1(v1::LocalIdentitySecret),
}

impl LocalIdentitySecret {
    pub fn new() -> (Identity, Self) {
        let (ident, secret) = v1::LocalIdentitySecret::new();
        return (Identity::V1(ident), LocalIdentitySecret::V1(secret));
    }

    pub fn identity(&self) -> Identity {
        match self {
            LocalIdentitySecret::V1(s) => Identity::V1(s.identity()),
        }
    }

    pub fn sign(&self, message: &[u8]) -> Blob {
        match self {
            LocalIdentitySecret::V1(v) => v.sign(message).blob(),
        }
    }
}
