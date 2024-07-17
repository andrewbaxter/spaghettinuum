use {
    super::{
        blob::ToBlob,
        fs_util,
        identity_secret::IdentitySigner,
        signed::IdentSignatureMethods,
    },
    crate::interface::{
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
    chrono::Utc,
    htwrap::{
        htreq,
        UriJoin,
    },
    hyper::Uri,
    loga::{
        ea,
        Log,
        ResultContext,
    },
    std::{
        collections::HashMap,
        path::PathBuf,
        str::FromStr,
        sync::{
            Arc,
            Mutex,
        },
    },
};

pub fn generate_publish_announce(
    signer: &Arc<Mutex<dyn IdentitySigner>>,
    publishers_info: Vec<InfoResponse>,
) -> Result<(Identity, stored::announcement::Announcement), String> {
    let announce_message = bincode::serialize(&stored::announcement::latest::AnnouncementContent {
        publishers: publishers_info.into_iter().map(|info| AnnouncementPublisher {
            addr: SerialAddr(info.advertise_addr),
            cert_hash: info.cert_pub_hash,
        }).collect(),
        announced: Utc::now(),
    }).unwrap().blob();
    let (identity, request_message_sig) =
        signer.lock().unwrap().sign(&announce_message).map_err(|e| e.to_string())?;
    return Ok((identity, stored::announcement::Announcement::V1(stored::announcement::latest::Announcement {
        message: announce_message,
        signature: request_message_sig,
        _p: Default::default(),
    })));
}

pub async fn announce(
    log: &Log,
    identity_signer: Arc<Mutex<dyn IdentitySigner>>,
    publishers: &[Uri],
) -> Result<(), loga::Error> {
    let mut publishers_info = vec![];
    for s in publishers {
        let url = s.join("publish/v1/info");
        let info_body =
            htreq::get(
                &log,
                &mut htreq::connect(&url).await.context("Error connecting to publisher")?,
                &url,
                &HashMap::new(),
                100 * 1024,
            )
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
            loga::DEBUG,
            "Got publisher information",
            ea!(info = serde_json::to_string_pretty(&info).unwrap()),
        );
        publishers_info.push(info);
    }
    let (identity, announcement) =
        generate_publish_announce(
            &identity_signer,
            publishers_info,
        ).map_err(|e| log.err_with("Error generating publisher announcement", ea!(err = e)))?;
    let request = wire::api::publish::v1::AnnounceRequest {
        identity: identity,
        announcement: announcement,
    };
    for s in publishers {
        let url = Uri::from_str(&format!("{}publish/v1/announce", s)).unwrap();
        htreq::post(
            log,
            &mut htreq::connect(&url).await.context("Error connecting to publisher")?,
            &url,
            &HashMap::new(),
            serde_json::to_vec(&request).unwrap(),
            100,
        )
            .await
            .context("Error making announce request")?;
    }
    return Ok(());
}

pub async fn publish(
    log: &Log,
    publishers: &[Uri],
    identity_signer: Arc<Mutex<dyn IdentitySigner>>,
    args: wire::api::publish::latest::PublishRequestContent,
) -> Result<(), loga::Error> {
    let (identity, signed_request_content) =
        wire::api::publish::v1::JsonSignature::sign(
            &mut *identity_signer.lock().unwrap(),
            args,
        ).stack_context(&log, "Failed to sign publish request content")?;
    let request = wire::api::publish::latest::PublishRequest {
        identity: identity,
        content: signed_request_content,
    };
    for s in publishers {
        let url = s.join("publish/v1/publish");
        log.log_with(
            loga::DEBUG,
            "Sending publish request",
            ea!(url = url, body = serde_json::to_string_pretty(&request).unwrap()),
        );
        htreq::post(
            log,
            &mut htreq::connect(&url).await.context("Error connecting to publisher")?,
            &url,
            &HashMap::new(),
            serde_json::to_vec(&request).unwrap(),
            100,
        )
            .await
            .context("Error making publish request")?;
    }
    return Ok(());
}

/// Scan system for ssh host keys and add them to a record set to publish.
///
/// * `paths` - if empty, search the system for default host key paths
pub async fn add_ssh_host_key_records(
    publish_data: &mut HashMap<String, stored::record::RecordValue>,
    mut paths: Vec<PathBuf>,
) -> Result<(), loga::Error> {
    if paths.is_empty() {
        for algo in ["rsa", "ed25519", "dsa", "ecdsa"] {
            paths.push(PathBuf::from(format!("/etc/ssh/ssh_host_{}_key.pub", algo)));
        }
    }
    let mut host_keys = vec![];
    for key_path in paths {
        let Some(key) = fs_util:: maybe_read(&key_path).await ? else {
            break;
        };
        let key =
            String::from_utf8(
                key,
            ).context_with("Host key isn't valid utf-8", ea!(path = key_path.to_string_lossy()))?;
        host_keys.push(key);
    }
    if !host_keys.is_empty() {
        publish_data.insert(
            stored::record::tls_record::KEY.to_string(),
            stored::record::RecordValue::latest(stored::record::latest::RecordValue {
                ttl: 60,
                data: Some(
                    serde_json::to_value(
                        &stored::record::tls_record::TlsCerts::latest(
                            stored::record::tls_record::latest::TlsCerts(host_keys),
                        ),
                    ).unwrap(),
                ),
            }),
        );
    }
    return Ok(());
}
