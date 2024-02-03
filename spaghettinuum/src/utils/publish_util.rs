use std::{
    collections::HashMap,
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
            announcement::latest::AnnouncementPublisher,
            identity::Identity,
            shared::SerialAddr,
        },
        wire::{
            self,
            api::publish::v1::InfoResponse,
        },
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
    signer: &mut dyn IdentitySigner,
    publishers_info: Vec<InfoResponse>,
) -> Result<(Identity, stored::announcement::Announcement), String> {
    let announce_message = bincode::serialize(&stored::announcement::latest::AnnouncementContent {
        publishers: publishers_info.into_iter().map(|info| AnnouncementPublisher {
            addr: SerialAddr(info.advertise_addr),
            cert_hash: info.cert_pub_hash,
        }).collect(),
        announced: Utc::now(),
    }).unwrap().blob();
    let (identity, request_message_sig) = signer.sign(&announce_message).map_err(|e| e.to_string())?;
    return Ok((identity, stored::announcement::Announcement::V1(stored::announcement::latest::Announcement {
        message: announce_message,
        signature: request_message_sig,
        _p: Default::default(),
    })));
}

pub async fn announce(
    log: &Log,
    identity_signer: &mut dyn IdentitySigner,
    publishers: &[Uri],
) -> Result<(), loga::Error> {
    let mut publishers_info = vec![];
    for s in publishers {
        let info_body =
            htreq::get(log, &format!("{}info", s), &HashMap::new(), 100 * 1024)
                .await
                .context("Error getting publisher info")?;
        let info =
            serde_json::from_slice::<wire::api::publish::latest::InfoResponse>(
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
        publishers_info.push(info);
    }
    let (identity, announcement) =
        generate_publish_announce(
            identity_signer,
            publishers_info,
        ).map_err(|e| log.err_with("Error generating publisher announcement", ea!(err = e)))?;
    let request = wire::api::publish::v1::AnnounceRequest {
        identity: identity,
        announcement: announcement,
    };
    for s in publishers {
        let url = format!("{}publish/v1/announce", s);
        htreq::post(log, &url, &HashMap::new(), serde_json::to_vec(&request).unwrap(), 100)
            .await
            .context("Error making announce request")?;
    }
    return Ok(());
}

pub async fn publish(
    log: &Log,
    publishers: &[Uri],
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
    for s in publishers {
        let url = format!("{}publish/v1/publish", s);
        log.log_with(
            DEBUG_OTHER,
            "Sending publish request",
            ea!(url = url, body = serde_json::to_string_pretty(&request).unwrap()),
        );
        htreq::post(log, &url, &HashMap::new(), serde_json::to_vec(&request).unwrap(), 100)
            .await
            .context("Error making publish request")?;
    }
    return Ok(());
}
