use {
    good_ormning::runtime::sqlite::GoodOrmningCustomString,
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
        Sha256,
    },
    spaghettinuum::versioned,
    std::{
        fmt::Display,
        str::FromStr,
    },
};

const NODE_ID_PREFIX: &'static str = "n_";

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum NodeIdInner {
    Sha256(Vec<u8>),
}

impl NodeIdInner {
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        return Ok(bincode::deserialize(data).map_err(|e| e.to_string())?);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        return bincode::serialize(self).unwrap();
    }
}

versioned!(
    NodeId,
    PartialEq,
    Eq,
    Clone,
    Hash,
    PartialOrd,
    Ord;
    (V1, 1, NodeIdInner)
);

impl Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <dyn Display>::fmt(&format!("{}{}", NODE_ID_PREFIX, zbase32::encode_full_bytes(&self.to_bytes())), f)
    }
}

impl std::fmt::Debug for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <dyn std::fmt::Debug>::fmt(&<dyn Display>::to_string(self), f)
    }
}

impl JsonSchema for NodeId {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        return "NodeId".into();
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        return json_schema!({
            "type": ["string"],
            "description": "A node identity (fingerprint, zbase32 string)",
        });
    }
}

impl FromStr for NodeId {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let text =
            text
                .strip_prefix(NODE_ID_PREFIX)
                .ok_or_else(|| format!("Node id text [{}] missing [{}] prefix, invalid", text, NODE_ID_PREFIX))?;
        Ok(
            Self::from_bytes(
                &zbase32::decode_full_bytes_str(text).map_err(|e| format!("Unable to decode node id zbase32: {}", e))?,
            )?,
        )
    }
}

pub mod v1;

pub use v1 as latest;

const NODE_IDENT_PREFIX: &'static str = "n_";

versioned!(
    NodePublicKey,
    PartialEq,
    Eq,
    Clone,
    Copy,
    Hash;
    (V1, 1, v1::NodePublicKey)
);

impl Display for NodePublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <dyn Display>::fmt(&format!("{}{}", NODE_IDENT_PREFIX, zbase32::encode_full_bytes(&self.to_bytes())), f)
    }
}

impl std::fmt::Debug for NodePublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <dyn std::fmt::Debug>::fmt(&<dyn Display>::to_string(self), f)
    }
}

impl JsonSchema for NodePublicKey {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        return "NodePublicKey".into();
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        return json_schema!({
            "type":["string"],
            "description": "A node identity (zbase32 string)",
        });
    }
}

pub trait NodePublicKeyMethods {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), loga::Error>;
}

impl NodePublicKeyMethods for NodePublicKey {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), loga::Error> {
        match self {
            NodePublicKey::V1(v) => v.verify(message, signature),
        }
    }
}

impl NodePublicKey {
    pub fn new() -> (Self, NodeSecret) {
        let (ident, secret) = v1::Ed25519NodePublicKey::new();
        return (
            NodePublicKey::V1(v1::NodePublicKey::Ed25519(ident)),
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

    pub fn id(&self) -> NodeId {
        return NodeId::V1(NodeIdInner::Sha256(<Sha256 as Digest>::digest(self.to_bytes()).to_vec()));
    }
}

versioned!(
    NodeSecret,
    Debug,
    Clone;
    (V1, 1, v1::NodeSecret)
);

impl NodeSecret {
    pub fn get_identity(&self) -> NodePublicKey {
        match self {
            NodeSecret::V1(v) => NodePublicKey::V1(v.get_identity()),
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
