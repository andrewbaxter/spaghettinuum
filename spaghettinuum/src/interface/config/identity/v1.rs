use ed25519_dalek::{
    SigningKey,
    Signer,
};
use rand::rngs::OsRng;
use serde::{
    Serialize,
    Deserialize,
};
use crate::{
    interface::identity::{
        self,
        hash_for_ed25519,
    },
    utils::blob::{
        Blob,
        ToBlob,
    },
};

#[derive(Debug, Clone)]
pub struct Ed25519IdentitySecret(SigningKey);

impl Serialize for Ed25519IdentitySecret {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        return Serialize::serialize(&zbase32::encode_full_bytes(&self.0.to_bytes()), serializer);
    }
}

impl<'de> Deserialize<'de> for Ed25519IdentitySecret {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de> {
        let t = String::deserialize(deserializer)?;
        return Ok(
            Ed25519IdentitySecret(
                SigningKey::from_bytes(
                    &<[u8; ed25519_dalek::SECRET_KEY_LENGTH]>::try_from(
                        zbase32::decode_full_bytes_str(&t).map_err(|e| serde::de::Error::custom(&e.to_string()))?,
                    ).map_err(|_| serde::de::Error::custom("Wrong secret key length"))?,
                ),
            ),
        );
    }
}

impl Ed25519IdentitySecret {
    fn new() -> (identity::v1::Ed25519Identity, Self) {
        let keypair = SigningKey::generate(&mut OsRng {});
        return (identity::v1::Ed25519Identity(keypair.verifying_key()), Ed25519IdentitySecret(keypair));
    }

    pub fn identity(&self) -> identity::v1::Ed25519Identity {
        return identity::v1::Ed25519Identity(self.0.verifying_key());
    }

    pub fn sign(&self, message: &[u8]) -> Blob {
        return self.0.sign(&hash_for_ed25519(message)).to_bytes().blob();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalIdentitySecret {
    Ed25519(Ed25519IdentitySecret),
}

impl LocalIdentitySecret {
    pub fn from_bytes(data: &[u8]) -> Result<Self, loga::Error> {
        return Ok(bincode::deserialize(data)?);
    }

    pub fn to_bytes(&self) -> Blob {
        return bincode::serialize(self).unwrap().blob();
    }

    pub fn identity(&self) -> identity::v1::Identity {
        match self {
            LocalIdentitySecret::Ed25519(e) => {
                return identity::v1::Identity::Ed25519(e.identity());
            },
        }
    }
}

impl LocalIdentitySecret {
    pub fn new() -> (identity::v1::Identity, Self) {
        let (ident, sec) = Ed25519IdentitySecret::new();
        return (identity::v1::Identity::Ed25519(ident), Self::Ed25519(sec));
    }

    pub fn sign(&self, message: &[u8]) -> Blob {
        match self {
            LocalIdentitySecret::Ed25519(i) => i.sign(message),
        }
    }
}
