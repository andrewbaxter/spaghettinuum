use {
    crate::versioned,
    schemars::{
        json_schema,
        JsonSchema,
    },
    serde::{
        Deserialize,
        Serialize,
    },
    sha2::{
        Digest,
        Sha512,
    },
    std::{
        fmt::Display,
        str::FromStr,
    },
};

pub mod v1;

/// For gpg-card compatibility we doubly hash the messages passed in for
/// signatures.  GPG takes a hash, passes it in as an ed25519 message, and the
/// ed25519 sign method hashes it again.
pub fn hash_for_ed25519(data: &[u8]) -> Vec<u8> {
    return <Sha512 as Digest>::digest(data).to_vec();
}

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

impl JsonSchema for Identity {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        return "Identity".into();
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        return json_schema!({
            "type":["string"],
            "description": "An identity (zbase32 string)"
        });
    }
}

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

impl FromStr for Identity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        return Ok(
            Self::from_bytes(
                &zbase32::decode_full_bytes_str(
                    s,
                ).map_err(|e| format!("Failed to decode zbase32 for identity: {}", e))?,
            )?,
        );
    }
}

impl Identity {
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), &'static str> {
        match self {
            Identity::V1(v) => v.verify(message, signature),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum LocalIdentitySecret {
    V1(v1::LocalIdentitySecret),
}

impl LocalIdentitySecret {
    pub fn identity(&self) -> Identity {
        match self {
            LocalIdentitySecret::V1(s) => Identity::V1(s.identity()),
        }
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self {
            LocalIdentitySecret::V1(v) => v.sign(message).to_vec(),
        }
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        return Ok(bincode::deserialize(data).map_err(|e| e.to_string())?);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        return bincode::serialize(self).unwrap().to_vec();
    }
}
