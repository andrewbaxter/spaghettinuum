use {
    crate::interface::stored::{
        record::{
            RecordValue,
            record_utils::RecordKey,
        },
        self,
    },
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
    },
    spaghettinuum::{
        interface::{
            id::Identity,
            public_key::IdentityPublicKey,
            signature_chain::ChainLink,
        },
        jsonsig::JsonSignature,
    },
    std::{
        collections::HashSet,
        net::SocketAddr,
    },
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct AnnounceRequest {
    pub announcement: stored::announcement::Announcement,
    pub identity: Identity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct DeleteAnnouncementRequest {
    #[serde(default)]
    pub chain: Vec<ChainLink>,
    pub challenge: JsonSignature<(), IdentityPublicKey>,
    pub identity: Identity,
    pub root_public_key: IdentityPublicKey,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct InfoResponse {
    pub advertise_addr: SocketAddr,
    pub cert_pub_hash: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PublishRequest {
    #[serde(default)]
    pub chain: Vec<ChainLink>,
    pub content: JsonSignature<PublishRequestContent, IdentityPublicKey>,
    pub identity: Identity,
    pub root_public_key: IdentityPublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PublishRequestContent {
    /// Stop publishing keys
    pub clear: HashSet<RecordKey>,
    /// Stop publishing all keys
    #[serde(default)]
    pub clear_all: bool,
    /// Update TTL for negative responses (in minutes). Defaults to 0 (don't cache
    /// missing responses).
    pub missing_ttl: Option<u32>,
    /// Start publishing values for keys
    pub set: Vec<(RecordKey, RecordValue)>,
}
