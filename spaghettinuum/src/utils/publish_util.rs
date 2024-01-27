use std::{
    collections::HashMap,
    net::{
        SocketAddr,
    },
};
use chrono::Utc;
use hyper::Uri;
use loga::{
    ea,
    ResultContext,
};
use crate::{
    interface::{
        identity::Identity,
        node_protocol::{
            self,
            v1::SerialAddr,
        },
        spagh_api::publish::{
            self,
            latest::JsonSignature,
        },
    },
    node::IdentSignatureMethods,
    publisher::PublishIdentSignatureMethods,
};
use super::{
    backed_identity::IdentitySigner,
    blob::ToBlob,
    htreq,
    log::{
        Log,
        DEBUG_OTHER,
    },
};

pub fn generate_publish_announce(
    signer: &mut Box<dyn IdentitySigner>,
    publisher_advertise_addr: SocketAddr,
    publisher_cert_hash: &[u8],
) -> Result<(Identity, node_protocol::PublisherAnnouncement), String> {
    let announce_message = bincode::serialize(&node_protocol::latest::PublisherAnnouncementContent {
        addr: SerialAddr(publisher_advertise_addr),
        cert_hash: publisher_cert_hash.blob(),
        published: Utc::now(),
    }).unwrap().blob();
    let (identity, request_message_sig) = signer.sign(&announce_message).map_err(|e| e.to_string())?;
    return Ok((identity, node_protocol::PublisherAnnouncement::V1(node_protocol::latest::PublisherAnnouncement {
        message: announce_message,
        signature: request_message_sig,
        _p: Default::default(),
    })));
}

pub async fn publish(
    log: &Log,
    server: &Uri,
    identity_signer: &mut dyn IdentitySigner,
    keyvalues: publish::latest::Publish,
) -> Result<(), loga::Error> {
    let info_body =
        htreq::get(&format!("{}info", server), &HashMap::new(), 100 * 1024)
            .await
            .stack_context(log, "Error getting publisher info")?;
    let info: publish::latest::InfoResponse =
        serde_json::from_slice(
            &info_body,
        ).stack_context_with(
            log,
            "Error parsing info response from publisher as json",
            ea!(body = String::from_utf8_lossy(&info_body)),
        )?;
    log.log_with(
        DEBUG_OTHER,
        "Got publisher information",
        ea!(info = serde_json::to_string_pretty(&info_body).unwrap()),
    );
    let announcement_content = node_protocol::latest::PublisherAnnouncementContent {
        addr: SerialAddr(info.advertise_addr),
        cert_hash: info.cert_pub_hash,
        published: Utc::now(),
    };
    log.log_with(
        DEBUG_OTHER,
        "Unsigned publisher announcement",
        ea!(message = serde_json::to_string_pretty(&announcement_content).unwrap()),
    );
    let (identity, signed_announcement_content) =
        node_protocol::latest::PublisherAnnouncement::sign(
            identity_signer,
            announcement_content,
        ).stack_context(&log, "Failed to sign announcement")?;
    let request_content = publish::latest::PublishRequestContent {
        announce: node_protocol::PublisherAnnouncement::V1(signed_announcement_content),
        keyvalues: keyvalues,
    };
    log.log_with(
        DEBUG_OTHER,
        "Unsigned request message",
        ea!(message = serde_json::to_string_pretty(&request_content).unwrap()),
    );
    let (_, signed_request_content) =
        JsonSignature::sign(
            identity_signer,
            request_content,
        ).stack_context(&log, "Failed to sign publish request content")?;
    let request = publish::PublishRequest::V1(publish::latest::PublishRequest {
        identity: identity,
        content: signed_request_content,
    });
    let url = format!("{}publish/publish", server);
    log.log_with(
        DEBUG_OTHER,
        "Sending publish request",
        ea!(url = url, body = serde_json::to_string_pretty(&request).unwrap()),
    );
    htreq::post(&url, &HashMap::new(), serde_json::to_vec(&request).unwrap(), 100)
        .await
        .stack_context(log, "Error making publish request")?;
    return Ok(());
}
