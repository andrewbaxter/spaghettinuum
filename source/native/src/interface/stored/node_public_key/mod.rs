pub mod v1;

pub use v1 as latest;
use {
    good_ormning::runtime::sqlite::GoodOrmningCustomString,
    schemars::{
        JsonSchema,
        json_schema,
    },
    sha2::{
        Digest,
        Sha256,
    },
    spaghettinuum::versioned,
    std::fmt::Display,
    super::node_identity::{
        NodeIdentity,
        v1::NodeIdentity as NodeIdentityInner,
    },
};

versioned!(
    NodePublicKey,
    PartialEq,
    Eq,
    Clone,
    Copy,
    Hash;
    (V1, 1, v1::NodePublicKey)
);

versioned!(
    NodeSecret,
    Debug,
    Clone;
    (V1, 1, v1::NodeSecret)
);

const NODE_IDENT_PREFIX: &'static str = "n_";

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

impl NodePublicKey {
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

    pub fn id(&self) -> NodeIdentity {
        return NodeIdentity::V1(NodeIdentityInner::Sha256(<Sha256 as Digest>::digest(self.to_bytes()).to_vec()));
    }

    pub fn new() -> (Self, NodeSecret) {
        let (ident, secret) = v1::Ed25519NodePublicKey::new();
        return (
            NodePublicKey::V1(v1::NodePublicKey::Ed25519(ident)),
            NodeSecret::V1(v1::NodeSecret::Ed25519(secret)),
        );
    }
}

impl Display for NodePublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <dyn Display>::fmt(&format!("{}{}", NODE_IDENT_PREFIX, zbase32::encode_full_bytes(&self.to_bytes())), f)
    }
}

impl JsonSchema for NodePublicKey {
    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        return json_schema!({
            "type":["string"],
            "description": "A node identity (zbase32 string)",
        });
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        return "NodePublicKey".into();
    }
}

impl std::fmt::Debug for NodePublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <dyn std::fmt::Debug>::fmt(&<dyn Display>::to_string(self), f)
    }
}

impl NodeSecret {
    pub fn get_identity(&self) -> NodePublicKey {
        match self {
            NodeSecret::V1(v) => NodePublicKey::V1(v.get_identity()),
        }
    }
}

impl GoodOrmningCustomString<NodeSecret> for NodeSecret {
    fn from_sql(value: String) -> Result<NodeSecret, String> {
        return Ok(
            bincode::deserialize(
                &zbase32::decode_full_bytes_str(&value).map_err(|e| e.to_string())?,
            ).map_err(|e| e.to_string())?,
        );
    }

    fn to_sql<'a>(value: &'a NodeSecret) -> String {
        return zbase32::encode_full_bytes(&bincode::serialize(&value).unwrap()).into();
    }
}
