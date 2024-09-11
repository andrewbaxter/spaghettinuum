use std::{
    collections::{
        HashSet,
    },
    marker::PhantomData,
    net::SocketAddr,
};
use schemars::JsonSchema;
use serde::{
    de::DeserializeOwned,
    Deserialize,
    Serialize,
};
use crate::{
    interface::stored::{
        self,
        identity::Identity,
        record::{
            record_utils::RecordKey,
            RecordValue,
        },
    },
    utils::blob::Blob,
};

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "snake_case")]
pub struct JsonSignature<T: Serialize + DeserializeOwned, I> {
    pub message: String,
    pub signature: Blob,
    #[serde(skip)]
    pub _p: PhantomData<(T, I)>,
}

impl<T: Serialize + DeserializeOwned, I> std::fmt::Debug for JsonSignature<T, I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f
            .debug_struct("JsonSignature")
            .field("message", &self.message)
            .field("signature", &self.signature)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AnnounceRequest {
    pub identity: Identity,
    pub announcement: stored::announcement::Announcement,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DeleteAnnouncementRequest {
    pub identity: Identity,
    pub challenge: JsonSignature<(), Identity>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct InfoResponse {
    pub advertise_addr: SocketAddr,
    pub cert_pub_hash: Blob,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
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
#[serde(rename_all = "snake_case")]
pub struct PublishRequest {
    pub identity: Identity,
    pub content: JsonSignature<PublishRequestContent, Identity>,
}
