use std::{
    collections::HashMap,
    net::SocketAddr,
};
use chrono::{
    Utc,
    DateTime,
};
use serde::{
    Serialize,
    Deserialize,
};
use crate::interface::{
    identity::Identity,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Announcement {
    #[serde(serialize_with = "crate::utils::as_zbase32", deserialize_with = "crate::utils::from_zbase32")]
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Announcement {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, loga::Error> {
        return Ok(bincode::deserialize(bytes)?);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PublishValue {
    /// duration in minutes
    pub ttl: u32,
    pub data: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
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
    /// zbase32
    pub cert_pub_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PublishRequestBody {
    pub announce: Announcement,
    pub keyvalues: Publish,
}

impl PublishRequestBody {
    pub fn to_bytes(&self) -> Vec<u8> {
        return bincode::serialize(&self).unwrap();
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, loga::Error> {
        return Ok(bincode::deserialize(bytes)?);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PublishRequestSigned {
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PublishRequest {
    pub identity: Identity,
    pub signed: PublishRequestSigned,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct UnpublishRequestBody {
    pub now: DateTime<Utc>,
}

impl UnpublishRequestBody {
    pub fn to_bytes(&self) -> Vec<u8> {
        return bincode::serialize(&self).unwrap();
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, loga::Error> {
        return Ok(bincode::deserialize(bytes)?);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct UnpublishRequestSigned {
    #[serde(serialize_with = "crate::utils::as_zbase32", deserialize_with = "crate::utils::from_zbase32")]
    pub message: Vec<u8>,
    #[serde(serialize_with = "crate::utils::as_zbase32", deserialize_with = "crate::utils::from_zbase32")]
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct UnpublishRequest {
    pub identity: Identity,
    pub signed: UnpublishRequestSigned,
}
