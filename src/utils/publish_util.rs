use std::net::{
    SocketAddr,
};
use chrono::Utc;
use crate::interface::{
    node_protocol::{
        self,
        v1::SerialAddr,
    },
    identity::Identity,
};
use super::backed_identity::IdentitySigner;

pub fn generate_publish_announce(
    signer: &mut Box<dyn IdentitySigner>,
    publisher_advertise_addr: SocketAddr,
    publisher_cert_hash: &[u8],
) -> Result<(Identity, node_protocol::PublisherAnnouncement), String> {
    let announce_message = bincode::serialize(&node_protocol::latest::PublisherAnnouncementContent {
        addr: SerialAddr(publisher_advertise_addr),
        cert_hash: publisher_cert_hash.to_vec(),
        published: Utc::now(),
    }).unwrap();
    let (identity, request_message_sig) = signer.sign(&announce_message).map_err(|e| e.to_string())?;
    return Ok((identity, node_protocol::PublisherAnnouncement::V1(node_protocol::latest::PublisherAnnouncement {
        message: announce_message,
        signature: request_message_sig,
        _p: Default::default(),
    })));
}
