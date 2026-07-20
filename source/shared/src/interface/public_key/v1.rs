use {
    std::{
        fmt::Display,
    },
    serde::{
        Deserialize,
        Serialize,
    },
    core::hash::Hash,
    std::fmt::Debug,
    ed25519_dalek::{
        VerifyingKey,
        Signature,
        Verifier,
    },
    super::{
        hash_for_ed25519,
    },
    ed25519_dalek::{
        Signer,
        SigningKey,
    },
    schemars::JsonSchema,
};

#[derive(Eq, PartialEq, Clone, Copy)]
pub struct Ed25519PublicKey(pub VerifyingKey);

impl Serialize for Ed25519PublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        return Serialize::serialize(self.0.as_bytes(), serializer);
    }
}

impl<'de> Deserialize<'de> for Ed25519PublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de> {
        return Ok(
            Ed25519PublicKey(
                VerifyingKey::from_bytes(
                    &<[u8; ed25519_dalek::PUBLIC_KEY_LENGTH]>::deserialize(deserializer)?,
                ).map_err(|e| serde::de::Error::custom(e.to_string()))?,
            ),
        );
    }
}

impl Hash for Ed25519PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(self.0.as_bytes());
    }
}

impl Debug for Ed25519PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Ed25519PublicKey").field(&zbase32::encode_full_bytes(&self.0.to_bytes())).finish()
    }
}

impl PartialOrd for Ed25519PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        return self.0.as_bytes().partial_cmp(&other.0.as_bytes());
    }
}

impl Ord for Ed25519PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        return self.0.as_bytes().cmp(other.0.as_bytes());
    }
}

impl Ed25519PublicKey {
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), &'static str> {
        let sig_obj = match Signature::from_slice(signature) {
            Ok(s) => s,
            Err(_) => {
                return Err("Failed to parse signature");
            },
        };
        match self.0.verify(&hash_for_ed25519(message), &sig_obj) {
            Ok(_) => (),
            Err(_) => {
                return Err("Invalid signature");
            },
        };
        return Ok(());
    }
}

// Aggregates
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum PublicKey {
    Ed25519(Ed25519PublicKey),
}

impl Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&zbase32::encode_full_bytes(&bincode::serialize(self).unwrap()))
    }
}

impl PublicKey {
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), &'static str> {
        match self {
            PublicKey::Ed25519(i) => i.verify(message, signature),
        }
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        return Ok(bincode::deserialize(data).map_err(|e| e.to_string())?);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        return bincode::serialize(self).unwrap();
    }

    pub fn from_bytes_unsafe(bytes: &[u8]) -> Self {
        bincode::deserialize(bytes).unwrap()
    }
}

#[derive(Debug, Clone)]
pub struct Ed25519LocalSecret(pub SigningKey);

impl Serialize for Ed25519LocalSecret {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        return Serialize::serialize(&zbase32::encode_full_bytes(&self.0.to_bytes()), serializer);
    }
}

impl<'de> Deserialize<'de> for Ed25519LocalSecret {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de> {
        let t = String::deserialize(deserializer)?;
        return Ok(
            Ed25519LocalSecret(
                SigningKey::from_bytes(
                    &<[u8; ed25519_dalek::SECRET_KEY_LENGTH]>::try_from(
                        zbase32::decode_full_bytes_str(&t).map_err(|e| serde::de::Error::custom(&e.to_string()))?,
                    ).map_err(|_| serde::de::Error::custom("Wrong secret key length"))?,
                ),
            ),
        );
    }
}

impl JsonSchema for Ed25519LocalSecret {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        return std::any::type_name::<Ed25519LocalSecret>().to_string().into();
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        return String::json_schema(generator);
    }
}

impl Ed25519LocalSecret {
    pub fn public_key(&self) -> Ed25519PublicKey {
        return Ed25519PublicKey(self.0.verifying_key());
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        return self.0.sign(&hash_for_ed25519(message)).to_bytes().to_vec();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum LocalSecret {
    Ed25519(Ed25519LocalSecret),
}

impl LocalSecret {
    pub fn public_key(&self) -> PublicKey {
        match self {
            LocalSecret::Ed25519(e) => {
                return PublicKey::Ed25519(e.public_key());
            },
        }
    }
}

impl LocalSecret {
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self {
            LocalSecret::Ed25519(i) => i.sign(message),
        }
    }
}
