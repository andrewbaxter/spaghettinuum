use {
    crate::interface::stored::{
        self,
        record::{
            RecordValue,
            record_utils::RecordKey,
        },
    },
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
    },
    spaghettinuum::{
        interface::identity::Identity,
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
    pub identity: Identity,
    pub announcement: stored::announcement::Announcement,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct DeleteAnnouncementRequest {
    pub identity: Identity,
    pub challenge: JsonSignature<(), Identity>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct InfoResponse {
    pub advertise_addr: SocketAddr,
    pub cert_pub_hash: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PublishRequestContent {
    /// Update TTL for negative responses (in minutes). Defaults to 0 (don't cache
    /// missing responses).
    pub missing_ttl: Option<u32>,
    /// Stop publishing all keys
    #[serde(default)]
    pub clear_all: bool,
    /// Stop publishing keys
    pub clear: HashSet<RecordKey>,
    /// Start publishing values for keys
    pub set: Vec<(RecordKey, RecordValue)>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PublishRequest {
    pub identity: Identity,
    pub content: JsonSignature<PublishRequestContent, Identity>,
}
