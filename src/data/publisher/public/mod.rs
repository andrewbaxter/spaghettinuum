use std::net::SocketAddr;
use chrono::{
    DateTime,
    Utc,
};
use serde::{
    Deserialize,
    Serialize,
};
use crate::data::identity::Identity;
use super::{
    announcement::v1::Announcement,
    v1::Publish,
};

#[derive(Serialize, Deserialize)]
pub struct InfoResponse {
    pub advertise_addr: SocketAddr,
    /// zbase32
    pub cert_pub_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
pub struct PublishRequestSigned {
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct PublishRequest {
    pub identity: Identity,
    pub signed: PublishRequestSigned,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
pub struct UnpublishRequestSigned {
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct UnpublishRequest {
    pub identity: Identity,
    pub signed: UnpublishRequestSigned,
}
