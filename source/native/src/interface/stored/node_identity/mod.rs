use {
    good_ormning_runtime::sqlite::GoodOrmningCustomString,
    schemars::{
        json_schema,
        JsonSchema,
    },
    spaghettinuum::versioned,
    std::fmt::Display,
};

pub mod v1;

pub use v1 as latest;

const NODE_IDENT_PREFIX: &'static str = "n_";

versioned!(
    NodeIdentity,
    PartialEq,
    Eq,
    Clone,
    Copy,
    Hash;
    (V1, 1, v1::NodeIdentity)
);

impl Display for NodeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <dyn Display>::fmt(&format!("{}{}", NODE_IDENT_PREFIX, zbase32::encode_full_bytes(&self.to_bytes())), f)
    }
}

impl std::fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <dyn std::fmt::Debug>::fmt(&<dyn Display>::to_string(self), f)
    }
}

impl JsonSchema for NodeIdentity {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        return "NodeIdentity".into();
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        return json_schema!({
            "type":["string"],
            "description": "A node identity (zbase32 string)",
        });
    }
}

pub trait NodeIdentityMethods {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), loga::Error>;
}

impl NodeIdentityMethods for NodeIdentity {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), loga::Error> {
        match self {
            NodeIdentity::V1(v) => v.verify(message, signature),
        }
    }
}

impl NodeIdentity {
    pub fn new() -> (Self, NodeSecret) {
        let (ident, secret) = v1::Ed25519NodeIdentity::new();
        return (
            NodeIdentity::V1(v1::NodeIdentity::Ed25519(ident)),
            NodeSecret::V1(v1::NodeSecret::Ed25519(secret)),
        );
    }

    pub fn from_str(text: &str) -> Result<Self, String> {
        let text =
            text
                .strip_prefix(NODE_IDENT_PREFIX)
                .ok_or_else(
                    || format!("Node identity text [{}] missing [{}] prefix, invalid", text, NODE_IDENT_PREFIX),
                )?;
        Ok(Self::from_bytes(&zbase32::decode_full_bytes_str(text).map_err(|e| {
            format!("Unable to decode node identity zbase32 [{}]: {}", text, e)
        })?)?)
    }
}

versioned!(
    NodeSecret,
    Debug,
    Clone;
    (V1, 1, v1::NodeSecret)
);

impl NodeSecret {
    pub fn get_identity(&self) -> NodeIdentity {
        match self {
            NodeSecret::V1(v) => NodeIdentity::V1(v.get_identity()),
        }
    }
}

pub trait NodeSecretMethods {
    fn sign(&self, message: &[u8]) -> Vec<u8>;
}

impl NodeSecretMethods for NodeSecret {
    fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self {
            NodeSecret::V1(v) => v.sign(message),
        }
    }
}

impl GoodOrmningCustomString<NodeSecret> for NodeSecret {
    fn to_sql<'a>(value: &'a NodeSecret) -> String {
        return zbase32::encode_full_bytes(&bincode::serialize(&value).unwrap()).into();
    }

    fn from_sql(value: String) -> Result<NodeSecret, String> {
        return Ok(
            bincode::deserialize(
                &zbase32::decode_full_bytes_str(&value).map_err(|e| e.to_string())?,
            ).map_err(|e| e.to_string())?,
        );
    }
}
