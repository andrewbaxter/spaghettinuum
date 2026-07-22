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
            identity::IdentityPublicKey,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct DeleteAnnouncementRequest {
    pub challenge: JsonSignature<(), IdentityPublicKey>,
    #[serde(default)]
    pub public_key_chain: Vec<ChainLink>,
    pub public_key_root: IdentityPublicKey,
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
    pub content: JsonSignature<PublishRequestContent, IdentityPublicKey>,
    #[serde(default)]
    pub public_key_chain: Vec<ChainLink>,
    pub public_key_root: IdentityPublicKey,
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
