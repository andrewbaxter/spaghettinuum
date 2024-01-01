use std::net::{
    SocketAddr,
};
use chrono::Utc;
use crate::interface::{
    node_protocol::{
        self,
        v1::SerialAddr,
    },
    spagh_api::publish,
    identity::Identity,
};
use super::backed_identity::IdentitySigner;

pub fn generate_publish_announce(
    signer: &mut Box<dyn IdentitySigner>,
    publisher_advertise_addr: SocketAddr,
    publisher_cert_hash: &[u8],
) -> Result<(Identity, publish::latest::Announcement), String> {
    let announce_message = node_protocol::latest::ValueBody {
        addr: SerialAddr(publisher_advertise_addr),
        cert_hash: publisher_cert_hash.to_vec(),
        published: Utc::now(),
    }.to_bytes();
    let (identity, request_message_sig) = signer.sign(&announce_message).map_err(|e| e.to_string())?;
    return Ok((identity, publish::latest::Announcement {
        message: announce_message.clone(),
        signature: request_message_sig,
    }));
}
