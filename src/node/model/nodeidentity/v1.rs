use core::fmt::Debug;
use std::fmt::Display;
use ed25519_dalek;
use ed25519_dalek::Signature;
use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use ed25519_dalek::Verifier;
use ed25519_dalek::VerifyingKey;
use loga::ResultContext;
use loga::ea;
use rand::rngs::OsRng;
use serde::{
    Deserialize,
    Serialize,
};
use super::NodeIdentityMethods;
use super::NodeSecretMethods;

// Ed25519
#[derive(PartialEq, Eq, Clone)]
pub struct Ed25519NodeIdentity(VerifyingKey);

impl Serialize for Ed25519NodeIdentity {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        return Serialize::serialize(self.0.as_bytes(), serializer);
    }
}

impl<'de> Deserialize<'de> for Ed25519NodeIdentity {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de> {
        return Ok(
            Ed25519NodeIdentity(
                VerifyingKey::from_bytes(
                    &<[u8; ed25519_dalek::PUBLIC_KEY_LENGTH]>::deserialize(deserializer)
                        .context("Failed to extract identity bytes", ea!())
                        .map_err(|e| serde::de::Error::custom(e.to_string()))?,
                ).map_err(|e| serde::de::Error::custom(format!("Failed to parse bytes as ed25519 key: {}", e)))?,
            ),
        );
    }
}

impl Debug for Ed25519NodeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Ed25519NodeId").field(&zbase32::encode_full_bytes(&self.0.to_bytes())).finish()
    }
}

impl core::hash::Hash for Ed25519NodeIdentity {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(&self.0.to_bytes());
    }
}

impl Ed25519NodeIdentity {
    pub fn new() -> (Self, Ed25519NodeSecret) {
        let keypair = SigningKey::generate(&mut OsRng {});
        return (Self(keypair.verifying_key()), Ed25519NodeSecret(keypair));
    }
}

impl NodeIdentityMethods for Ed25519NodeIdentity {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), loga::Error> {
        self.0.verify(message, &Signature::from_slice(signature)?)?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Ed25519NodeSecret(SigningKey);

impl Ed25519NodeSecret {
    pub fn get_identity(&self) -> Ed25519NodeIdentity {
        Ed25519NodeIdentity(self.0.verifying_key())
    }
}

impl Serialize for Ed25519NodeSecret {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        return Serialize::serialize(&self.0.to_bytes(), serializer);
    }
}

impl<'de> Deserialize<'de> for Ed25519NodeSecret {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de> {
        return Ok(
            Ed25519NodeSecret(
                SigningKey::from_bytes(
                    &<[u8; ed25519_dalek::SECRET_KEY_LENGTH]>::deserialize(deserializer)
                        .context("Failed to extract secret bytes", ea!())
                        .map_err(|e| serde::de::Error::custom(e.to_string()))?,
                ),
            ),
        );
    }
}

impl NodeSecretMethods for Ed25519NodeSecret {
    fn sign(&self, message: &[u8]) -> Box<[u8]> {
        return self.0.sign(message).to_bytes().to_vec().into_boxed_slice();
    }
}

// Aggregates
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub enum NodeIdentity {
    Ed25519(Ed25519NodeIdentity),
}

impl Display for NodeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", zbase32::encode_full_bytes(&bincode::serialize(self).unwrap()))
    }
}

impl NodeIdentity {
    pub fn from_bytes(message: &[u8]) -> Result<Self, loga::Error> {
        return Ok(bincode::deserialize(message).context("Bincode decode failed", ea!())?);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        return bincode::serialize(self).unwrap();
    }
}

impl NodeIdentityMethods for NodeIdentity {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), loga::Error> {
        match self {
            NodeIdentity::Ed25519(i) => i.verify(message, signature),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeSecret {
    Ed25519(Ed25519NodeSecret),
}

impl NodeSecret {
    pub fn from_bytes(message: &[u8]) -> Result<Self, loga::Error> {
        return Ok(bincode::deserialize(message).context("Bincode decode failed", ea!())?);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        return bincode::serialize(self).unwrap();
    }

    pub fn get_identity(&self) -> NodeIdentity {
        match self {
            NodeSecret::Ed25519(v) => NodeIdentity::Ed25519(v.get_identity()),
        }
    }
}

impl NodeSecretMethods for NodeSecret {
    fn sign(&self, message: &[u8]) -> Box<[u8]> {
        match self {
            NodeSecret::Ed25519(i) => i.sign(message),
        }
    }
}
