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
        stored::{
            self,
            identity::Identity,
            shared::SerialAddr,
        },
        wire,
    },
};
use super::{
    backed_identity::IdentitySigner,
    blob::ToBlob,
    htreq,
    log::{
        Log,
        DEBUG_OTHER,
    },
    signed::IdentSignatureMethods,
};

pub fn generate_publish_announce(
    signer: &mut Box<dyn IdentitySigner>,
    publisher_advertise_addr: SocketAddr,
    publisher_cert_hash: &[u8],
) -> Result<(Identity, stored::announcement::Announcement), String> {
    let announce_message = bincode::serialize(&stored::announcement::latest::AnnouncementContent {
        addr: SerialAddr(publisher_advertise_addr),
        cert_hash: publisher_cert_hash.blob(),
        published: Utc::now(),
    }).unwrap().blob();
    let (identity, request_message_sig) = signer.sign(&announce_message).map_err(|e| e.to_string())?;
    return Ok((identity, stored::announcement::Announcement::V1(stored::announcement::latest::Announcement {
        message: announce_message,
        signature: request_message_sig,
        _p: Default::default(),
    })));
}

pub async fn announce(log: &Log, server: &Uri, identity_signer: &mut dyn IdentitySigner) -> Result<(), loga::Error> {
    let info_body =
        htreq::get(log, &format!("{}info", server), &HashMap::new(), 100 * 1024)
            .await
            .context("Error getting publisher info")?;
    let info: wire::api::publish::latest::InfoResponse =
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
    let announcement_content = stored::announcement::latest::AnnouncementContent {
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
        stored::announcement::latest::Announcement::sign(
            identity_signer,
            announcement_content,
        ).stack_context(&log, "Failed to sign announcement")?;
    let request = wire::api::publish::v1::AnnounceRequest {
        identity: identity,
        announcement: stored::announcement::Announcement::V1(signed_announcement_content),
    };
    let url = format!("{}publish/v1/announce", server);
    htreq::post(log, &url, &HashMap::new(), serde_json::to_vec(&request).unwrap(), 100)
        .await
        .context("Error making announce request")?;
    return Ok(());
}

pub async fn publish(
    log: &Log,
    server: &Uri,
    identity_signer: &mut dyn IdentitySigner,
    args: wire::api::publish::latest::PublishRequestContent,
) -> Result<(), loga::Error> {
    let (identity, signed_request_content) =
        wire::api::publish::v1::JsonSignature::sign(
            identity_signer,
            args,
        ).stack_context(&log, "Failed to sign publish request content")?;
    let request = wire::api::publish::latest::PublishRequest {
        identity: identity,
        content: signed_request_content,
    };
    let url = format!("{}publish/v1/publish", server);
    log.log_with(
        DEBUG_OTHER,
        "Sending publish request",
        ea!(url = url, body = serde_json::to_string_pretty(&request).unwrap()),
    );
    htreq::post(log, &url, &HashMap::new(), serde_json::to_vec(&request).unwrap(), 100)
        .await
        .context("Error making publish request")?;
    return Ok(());
}
