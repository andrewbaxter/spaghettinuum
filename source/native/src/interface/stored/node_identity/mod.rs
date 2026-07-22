pub mod v1;

pub use v1 as latest;
use {
    schemars::{
        JsonSchema,
        json_schema,
    },
    spaghettinuum::versioned,
    std::{
        fmt::Display,
        str::FromStr,
    },
};

versioned!(
    NodeIdentity,
    PartialEq,
    Eq,
    Clone,
    Hash,
    PartialOrd,
    Ord;
    (V1, 1, v1::NodeIdentity)
);

const NODE_ID_PREFIX: &'static str = "n_";

impl Display for NodeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <dyn Display>::fmt(&format!("{}{}", NODE_ID_PREFIX, zbase32::encode_full_bytes(&self.to_bytes())), f)
    }
}

impl FromStr for NodeIdentity {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let text =
            text
                .strip_prefix(NODE_ID_PREFIX)
                .ok_or_else(|| format!("Node id text [{}] missing [{}] prefix, invalid", text, NODE_ID_PREFIX))?;
        Ok(
            Self::from_bytes(
                &zbase32::decode_full_bytes_str(
                    text,
                ).map_err(|e| format!("Unable to decode node id zbase32: {}", e))?,
            )?,
        )
    }
}

impl JsonSchema for NodeIdentity {
    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        return json_schema!({
            "type":["string"],
            "description": "A node identity (fingerprint, zbase32 string)",
        });
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        return "NodeIdentity".into();
    }
}

impl std::fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <dyn std::fmt::Debug>::fmt(&<dyn Display>::to_string(self), f)
    }
}
