use std::{
    collections::HashMap,
    net::SocketAddr,
    marker::PhantomData,
};
use chrono::{
    Utc,
    DateTime,
};
use schemars::JsonSchema;
use serde::{
    Serialize,
    Deserialize,
    de::DeserializeOwned,
};
use crate::{
    interface::{
        identity::Identity,
        node_protocol::{
            self,
        },
    },
    utils::blob::{
        Blob,
        ToBlob,
    },
};

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "snake_case")]
pub struct JsonSignature<T: Serialize + DeserializeOwned, I> {
    pub message: String,
    pub signature: Blob,
    #[serde(skip)]
    pub _p: PhantomData<(T, I)>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct PublishValue {
    /// duration in minutes
    pub ttl: u32,
    pub data: serde_json::Value,
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct Publish {
    /// duration in minutes
    pub missing_ttl: u32,
    pub data: HashMap<String, PublishValue>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct InfoResponse {
    pub advertise_addr: SocketAddr,
    pub cert_pub_hash: Blob,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PublishRequestContent {
    pub announce: node_protocol::PublisherAnnouncement,
    pub keyvalues: Publish,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PublishRequest {
    pub identity: Identity,
    pub content: JsonSignature<PublishRequestContent, Identity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct UnpublishRequestContent {
    pub now: DateTime<Utc>,
}

impl UnpublishRequestContent {
    pub fn to_bytes(&self) -> Blob {
        return bincode::serialize(&self).unwrap().blob();
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, loga::Error> {
        return Ok(bincode::deserialize(bytes)?);
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct UnpublishRequest {
    pub identity: Identity,
    pub content: JsonSignature<UnpublishRequestContent, Identity>,
}
