use {
    super::{
        blob::ToBlob,
        fs_util,
        identity_secret::IdentitySigner,
        signed::IdentSignatureMethods,
        time_util::UtcSecs,
    },
    crate::{
        interface::{
            stored::{
                self,
                announcement::latest::AnnouncementPublisher,
                identity::Identity,
                record::{
                    dns_record::{
                        build_dns_key,
                        RecordType,
                    },
                    record_utils::RecordKey,
                    RecordValue,
                },
                shared::SerialAddr,
            },
            wire::{
                self,
                api::publish::v1::InfoResponse,
            },
        },
        resolving::{
            connect_publisher_node,
            UrlPair,
        },
        service::publisher::API_ROUTE_PUBLISH,
    },
    htwrap::htreq,
    loga::{
        ea,
        DebugDisplay,
        Log,
        ResultContext,
    },
    std::{
        collections::{
            HashMap,
            HashSet,
        },
        path::PathBuf,
        sync::{
            Arc,
            Mutex,
        },
        time::SystemTime,
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
        announced: UtcSecs::from(SystemTime::now()),
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
    resolvers: &[UrlPair],
    publishers: &[UrlPair],
    identity_signer: &Arc<Mutex<dyn IdentitySigner>>,
) -> Result<(), loga::Error> {
    let mut publishers_info = vec![];
    for s in publishers {
        let url = s.join("publish/v1/info");
        let info_body =
            htreq::get(
                &log,
                &mut connect_publisher_node(&log, resolvers, &url).await.context("Error connecting to publisher")?,
                &url.url,
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
            identity_signer,
            publishers_info,
        ).map_err(|e| log.err_with("Error generating publisher announcement", ea!(err = e)))?;
    let request = wire::api::publish::v1::AnnounceRequest {
        identity: identity,
        announcement: announcement,
    };
    for s in publishers {
        let url = s.join("publish/v1/announce");
        htreq::post(
            log,
            &mut connect_publisher_node(log, resolvers, &url).await.context("Error connecting to publisher")?,
            &url.url,
            &HashMap::new(),
            serde_json::to_vec(&request).unwrap(),
            100,
        )
            .await
            .context("Error making announce request")?;
    }
    return Ok(());
}

#[derive(Default, Clone)]
pub struct PublishArgs {
    /// Update TTL for negative responses (in minutes). Defaults to 0 (don't cache
    /// missing responses).
    pub missing_ttl: Option<u32>,
    /// Stop publishing all keys
    pub clear_all: bool,
    /// Stop publishing keys
    pub clear: HashSet<RecordKey>,
    /// Start publishing values for keys
    pub set: HashMap<RecordKey, RecordValue>,
}

pub async fn remote_publish(
    log: &Log,
    resolvers: &[UrlPair],
    publishers: &[UrlPair],
    identity_signer: &Arc<Mutex<dyn IdentitySigner>>,
    args: PublishArgs,
) -> Result<(), loga::Error> {
    let (identity, signed_request_content) =
        wire::api::publish::v1::JsonSignature::sign(
            &mut *identity_signer.lock().unwrap(),
            wire::api::publish::latest::PublishRequestContent {
                missing_ttl: args.missing_ttl,
                clear_all: args.clear_all,
                clear: args.clear,
                set: args.set.into_iter().collect(),
            },
        ).stack_context(&log, "Failed to sign publish request content")?;
    let request = wire::api::publish::latest::PublishRequest {
        identity: identity,
        content: signed_request_content,
    };
    for s in publishers {
        let url = s.join(format!("{}/v1/publish", API_ROUTE_PUBLISH));
        log.log_with(
            loga::DEBUG,
            "Sending publish request",
            ea!(url = url, body = serde_json::to_string_pretty(&request).unwrap()),
        );
        htreq::post(
            log,
            &mut connect_publisher_node(&log, resolvers, &url).await.context("Error connecting to publisher")?,
            &url.url,
            &HashMap::new(),
            serde_json::to_vec(&request).unwrap(),
            100,
        )
            .await
            .context("Error making publish request")?;
    }
    return Ok(());
}

/// Add an ip address record to a set to publish
pub fn add_ip_record(
    publish_data: &mut HashMap<RecordKey, stored::record::RecordValue>,
    head: Vec<String>,
    ttl: u64,
    ip: std::net::IpAddr,
) {
    let key;
    let data;
    match ip {
        std::net::IpAddr::V4(ip) => {
            key = RecordType::A;
            data =
                serde_json::to_value(
                    &stored::record::dns_record::DnsA::V1(stored::record::dns_record::latest::DnsA(vec![ip])),
                ).unwrap();
        },
        std::net::IpAddr::V6(ip) => {
            key = RecordType::Aaaa;
            data =
                serde_json::to_value(
                    &stored::record::dns_record::DnsAaaa::V1(stored::record::dns_record::latest::DnsAaaa(vec![ip])),
                ).unwrap();
        },
    }
    let key = build_dns_key(head, key);
    publish_data.insert(key, stored::record::RecordValue::latest(stored::record::latest::RecordValue {
        ttl: ttl,
        data: Some(data),
    }));
}

/// Scan system for ssh host keys and add them to a record set to publish.
///
/// * `paths` - if empty, search the system for default host key paths
pub async fn add_ssh_host_key_records(
    publish_data: &mut HashMap<RecordKey, stored::record::RecordValue>,
    head: RecordKey,
    ttl: u64,
    paths: &Vec<PathBuf>,
) -> Result<(), loga::Error> {
    let mut paths = paths.clone();
    if paths.is_empty() {
        for algo in ["rsa", "ed25519", "dsa", "ecdsa"] {
            paths.push(PathBuf::from(format!("/etc/ssh/ssh_host_{}_key.pub", algo)));
        }
    }
    let mut host_keys = vec![];
    for key_path in &paths {
        let Some(key) = fs_util::maybe_read(&key_path).await? else {
            break;
        };
        let key =
            String::from_utf8(
                key,
            ).context_with("Host key isn't valid utf-8", ea!(path = key_path.to_string_lossy()))?;
        host_keys.push(key);
    }
    if host_keys.is_empty() {
        return Err(loga::err_with("No ssh host keys could be located", ea!(paths = paths.dbg_str())));
    }
    let mut key = head;
    key.push(stored::record::ssh_record::KEY_SUFFIX_SSH_HOSTKEYS.to_string());
    publish_data.insert(key, stored::record::RecordValue::latest(stored::record::latest::RecordValue {
        ttl: ttl,
        data: Some(
            serde_json::to_value(
                &stored::record::ssh_record::SshHostKeys::latest(
                    stored::record::ssh_record::latest::SshHostKeys(host_keys),
                ),
            ).unwrap(),
        ),
    }));
    return Ok(());
}
