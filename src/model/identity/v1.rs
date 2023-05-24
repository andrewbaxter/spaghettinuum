use std::{
    fmt::Display,
};
use rand::rngs::OsRng;
use serde::{
    Deserialize,
    Serialize,
};
use core::hash::Hash;
use std::fmt::Debug;
use ed25519_dalek::{
    VerifyingKey,
    Signature,
    SigningKey,
};
use crate::utils::hash_for_ed25519;
use super::{
    IdentityMethods,
    IdentitySecretMethods,
};

#[derive(Eq, PartialEq, Clone)]
pub struct Ed25519Identity(pub VerifyingKey);

impl Serialize for Ed25519Identity {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        return Serialize::serialize(self.0.as_bytes(), serializer);
    }
}

impl<'de> Deserialize<'de> for Ed25519Identity {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de> {
        return Ok(
            Ed25519Identity(
                VerifyingKey::from_bytes(
                    &<[u8; ed25519_dalek::PUBLIC_KEY_LENGTH]>::deserialize(deserializer)?,
                ).map_err(|e| serde::de::Error::custom(e.to_string()))?,
            ),
        );
    }
}

impl Hash for Ed25519Identity {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(self.0.as_bytes());
    }
}

impl Debug for Ed25519Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Ed25519IdentityId").field(&zbase32::encode_full_bytes(&self.0.to_bytes())).finish()
    }
}

impl Ed25519Identity {
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let hash = hash_for_ed25519(message);
        let sig_obj = match Signature::from_slice(signature) {
            Ok(s) => s,
            Err(_) => return false,
        };
        return self.0.verify_prehashed(hash, None, &sig_obj).is_ok();
    }

    pub fn new() -> (Self, Ed25519IdentitySecret) {
        let keypair = SigningKey::generate(&mut OsRng {});
        return (Self(keypair.verifying_key()), Ed25519IdentitySecret(keypair));
    }
}

#[derive(Debug, Clone)]
pub struct Ed25519IdentitySecret(SigningKey);

impl Serialize for Ed25519IdentitySecret {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        return Serialize::serialize(&self.0.to_bytes(), serializer);
    }
}

impl<'de> Deserialize<'de> for Ed25519IdentitySecret {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de> {
        return Ok(
            Ed25519IdentitySecret(
                SigningKey::from_bytes(&<[u8; ed25519_dalek::SECRET_KEY_LENGTH]>::deserialize(deserializer)?),
            ),
        );
    }
}

impl IdentitySecretMethods for Ed25519IdentitySecret {
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        let hash = hash_for_ed25519(data);
        return self.0.sign_prehashed(hash, None).unwrap().to_bytes().to_vec();
    }
}

// Aggregates
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Identity {
    Ed25519(Ed25519Identity),
}

impl Display for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&zbase32::encode_full_bytes(&bincode::serialize(self).unwrap()))
    }
}

impl IdentityMethods for Identity {
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        match self {
            Identity::Ed25519(i) => i.verify(message, signature),
        }
    }
}

impl Identity {
    pub fn from_bytes(data: &[u8]) -> Result<Self, loga::Error> {
        return Ok(bincode::deserialize(data)?);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        return bincode::serialize(self).unwrap();
    }

    pub fn from_bytes_unsafe(bytes: &[u8]) -> Self {
        bincode::deserialize(bytes).unwrap()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IdentitySecret {
    Ed25519(Ed25519IdentitySecret),
}

impl IdentitySecret {
    pub fn from_bytes(data: &[u8]) -> Result<Self, loga::Error> {
        return Ok(bincode::deserialize(data)?);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        return bincode::serialize(self).unwrap();
    }
}

impl IdentitySecretMethods for IdentitySecret {
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        match self {
            IdentitySecret::Ed25519(i) => i.sign(data),
        }
    }
}
