use std::net::SocketAddr;
use serde::{
    Deserialize,
    Serialize,
};
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

#[derive(Serialize, Deserialize)]
pub struct PublishRequest {
    pub announce: Announcement,
    pub keyvalues: Publish,
}
