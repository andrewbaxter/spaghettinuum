pub mod v1;

use {
    crate::versioned,
    schemars::{
        JsonSchema,
        json_schema,
    },
    serde::{
        Deserialize,
        Serialize,
    },
    sha2::{
        Digest,
        Sha256,
        Sha512,
    },
    std::{
        fmt::Display,
        str::FromStr,
    },
};

versioned!(
    Identity,
    PartialEq,
    Eq,
    Clone,
    Copy,
    Hash,
    PartialOrd,
    Ord;
    (V1, 1, v1::Identity)
);

versioned!(
    IdentityPublicKey,
    PartialEq,
    Eq,
    Clone,
    Copy,
    Hash,
    PartialOrd,
    Ord;
    (V1, 1, v1::IdentityPublicKey)
);

/// For gpg-card compatibility we doubly hash the messages passed in for
/// signatures.  GPG takes a hash, passes it in as an ed25519 message, and the
/// ed25519 sign method hashes it again.
pub fn hash_for_ed25519(data: &[u8]) -> Vec<u8> {
    return <Sha512 as Digest>::digest(data).to_vec();
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct IdentityPublicKeyChain {
    pub chain: Vec<crate::interface::signature_chain::ChainLink>,
    pub root: IdentityPublicKey,
}

#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum IdentitySecret {
    V1(v1::IdentitySecret),
}

impl IdentitySecret {
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        return Ok(bincode::deserialize(data).map_err(|e| e.to_string())?);
    }

    pub fn identity(&self) -> Option<Identity> {
        return Some(self.public_key()?.identity());
    }

    pub fn public_key(&self) -> Option<IdentityPublicKey> {
        match self {
            IdentitySecret::V1(s) => match &s.public_key_chain {
                Some(c) => return Some(c.root),
                None => match &s.secret {
                    v1::Secret::Local(k) => {
                        return Some(IdentityPublicKey::V1(v1::IdentityPublicKey::Ed25519(k.public_key())));
                    },
                    v1::Secret::Card { .. } => return None,
                },
            },
        }
    }

    pub fn public_key_chain(&self) -> Option<&IdentityPublicKeyChain> {
        match self {
            IdentitySecret::V1(s) => s.public_key_chain.as_ref(),
        }
    }

    pub fn secret(&self) -> &v1::Secret {
        match self {
            IdentitySecret::V1(s) => &s.secret,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        return bincode::serialize(self).unwrap().to_vec();
    }
}

impl Display for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <dyn Display>::fmt(&zbase32::encode_full_bytes(&self.to_bytes()), f)
    }
}

impl FromStr for Identity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        return Ok(
            Self::from_bytes(
                &zbase32::decode_full_bytes_str(s).map_err(|e| format!("Failed to decode zbase32 for id: {}", e))?,
            )?,
        );
    }
}

impl JsonSchema for Identity {
    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        return json_schema!({
            "type":["string"],
            "description": "An identity (zbase32 string), the fingerprint of a public key"
        });
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        return "Identity".into();
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <dyn std::fmt::Debug>::fmt(&<dyn Display>::to_string(self), f)
    }
}

impl IdentityPublicKey {
    pub fn identity(&self) -> Identity {
        return Identity::V1(v1::Identity::Sha256(<Sha256 as Digest>::digest(&self.to_bytes()).into()));
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), &'static str> {
        match self {
            IdentityPublicKey::V1(v) => v.verify(message, signature),
        }
    }
}

impl Display for IdentityPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <dyn Display>::fmt(&zbase32::encode_full_bytes(&self.to_bytes()), f)
    }
}

impl FromStr for IdentityPublicKey {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        return Ok(
            Self::from_bytes(
                &zbase32::decode_full_bytes_str(
                    s,
                ).map_err(|e| format!("Failed to decode zbase32 for public key: {}", e))?,
            )?,
        );
    }
}

impl JsonSchema for IdentityPublicKey {
    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        return json_schema!({
            "type":["string"],
            "description": "A public key (zbase32 string)"
        });
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        return "IdentityPublicKey".into();
    }
}

impl std::fmt::Debug for IdentityPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <dyn std::fmt::Debug>::fmt(&<dyn Display>::to_string(self), f)
    }
}
