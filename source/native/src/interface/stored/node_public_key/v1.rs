use {
    core::fmt::Debug,
    ed25519_dalek,
    ed25519_dalek::{
        Signature as SSignature,
        Signer,
        SigningKey,
        Verifier,
        VerifyingKey,
    },
    loga::ResultContext,
    rand::rngs::OsRng,
    serde::{
        Deserialize,
        Serialize,
    },
    std::fmt::Display,
    super::{
        NodePublicKeyMethods,
        NodeSecretMethods,
    },
};

#[derive(PartialEq, Eq, Clone, Copy, Hash)]
pub struct Ed25519NodePublicKey(VerifyingKey);

impl Ed25519NodePublicKey {
    pub fn new() -> (Self, Ed25519NodeSecret) {
        let keypair = SigningKey::generate(&mut OsRng {});
        return (Self(keypair.verifying_key()), Ed25519NodeSecret(keypair));
    }
}

impl Debug for Ed25519NodePublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Ed25519NodeId").field(&zbase32::encode_full_bytes(&self.0.to_bytes())).finish()
    }
}

impl NodePublicKeyMethods for Ed25519NodePublicKey {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), loga::Error> {
        self.0.verify(message, &SSignature::from_slice(signature)?)?;
        Ok(())
    }
}

impl Serialize for Ed25519NodePublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        return Serialize::serialize(self.0.as_bytes(), serializer);
    }
}

impl<'de> Deserialize<'de> for Ed25519NodePublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de> {
        return Ok(
            Ed25519NodePublicKey(
                VerifyingKey::from_bytes(
                    &<[u8; ed25519_dalek::PUBLIC_KEY_LENGTH]>::deserialize(deserializer)
                        .context("Failed to extract identity bytes")
                        .map_err(|e| serde::de::Error::custom(e.to_string()))?,
                ).map_err(|e| serde::de::Error::custom(format!("Failed to parse bytes as ed25519 key: {}", e)))?,
            ),
        );
    }
}

#[derive(Debug, Clone)]
pub struct Ed25519NodeSecret(SigningKey);

impl Ed25519NodeSecret {
    pub fn get_identity(&self) -> Ed25519NodePublicKey {
        Ed25519NodePublicKey(self.0.verifying_key())
    }
}

impl NodeSecretMethods for Ed25519NodeSecret {
    fn sign(&self, message: &[u8]) -> Vec<u8> {
        return self.0.sign(message).to_bytes().to_vec();
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
                        .context("Failed to extract secret bytes")
                        .map_err(|e| serde::de::Error::custom(e.to_string()))?,
                ),
            ),
        );
    }
}

// Aggregates
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NodePublicKey {
    Ed25519(Ed25519NodePublicKey),
}

impl NodePublicKey {
    pub fn from_bytes(message: &[u8]) -> Result<Self, String> {
        return Ok(bincode::deserialize(message).map_err(|e| format!("Bincode decode failed: {}", e))?);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        return bincode::serialize(self).unwrap();
    }
}

impl Display for NodePublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", zbase32::encode_full_bytes(&bincode::serialize(self).unwrap()))
    }
}

impl NodePublicKeyMethods for NodePublicKey {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), loga::Error> {
        match self {
            NodePublicKey::Ed25519(i) => i.verify(message, signature),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NodeSecret {
    Ed25519(Ed25519NodeSecret),
}

impl NodeSecret {
    pub fn from_bytes(message: &[u8]) -> Result<Self, String> {
        return Ok(bincode::deserialize(message).map_err(|e| format!("Bincode decode failed: {}", e))?);
    }

    pub fn get_identity(&self) -> NodePublicKey {
        match self {
            NodeSecret::Ed25519(v) => NodePublicKey::Ed25519(v.get_identity()),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        return bincode::serialize(self).unwrap();
    }
}

impl NodeSecretMethods for NodeSecret {
    fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self {
            NodeSecret::Ed25519(i) => i.sign(message),
        }
    }
}
