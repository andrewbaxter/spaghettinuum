use {
    aargvark::{
        Aargvark,
        AargvarkJson,
    },
    chrono::Duration,
    hyper::Uri,
    loga::{
        ea,
        ErrContext,
        Log,
        ResultContext,
    },
    spaghettinuum::{
        bb,
        cap_fn,
        content::serve_content,
        interface::{
            config::{
                auto::Config,
                DebugFlag,
                ENV_CONFIG,
            },
            stored::{
                self,
                dns_record::{
                    format_dns_key,
                    RecordType,
                },
            },
            wire,
        },
        self_tls::{
            request_cert,
            request_cert_stream,
            CertPair,
        },
        ta_res,
        utils::{
            backed_identity::get_identity_signer,
            ip_util::resolve_global_ip,
            publish_util,
            tls_util::load_certified_key,
        },
    },
    std::{
        collections::HashMap,
        str::FromStr,
        sync::{
            Arc,
            RwLock,
        },
    },
    taskmanager::TaskManager,
    tokio::{
        fs::{
            create_dir_all,
            read,
            write,
        },
        select,
        time::sleep,
    },
    tokio_stream::wrappers::WatchStream,
};

#[derive(Aargvark)]
struct Args {
    /// Config - json.  See the reference documentation and jsonschema for details.
    pub config: Option<AargvarkJson<Config>>,
    /// Enable debug logging
    #[vark(break)]
    pub debug: Option<Vec<DebugFlag>>,
}

async fn inner(log: &Log, tm: &TaskManager, args: Args) -> Result<(), loga::Error> {
    let config = if let Some(p) = args.config {
        p.value
    } else if let Some(c) = match std::env::var(ENV_CONFIG) {
        Ok(c) => Some(c),
        Err(e) => match e {
            std::env::VarError::NotPresent => None,
            std::env::VarError::NotUnicode(_) => {
                return Err(loga::err_with("Error parsing env var as unicode", ea!(env = ENV_CONFIG)))
            },
        },
    } {
        let log = log.fork(ea!(source = "env"));
        serde_json::from_str::<Config>(&c).stack_context(&log, "Parsing config")?
    } else {
        return Err(
            log.err_with("No config passed on command line, and no config set in env var", ea!(env = ENV_CONFIG)),
        );
    };
    let identity_signer = get_identity_signer(config.identity.clone()).stack_context(log, "Error loading identity")?;

    // Publish global ips
    let async_publish_ips = {
        let identity_signer = identity_signer.clone();
        let log = log.fork(ea!(sys = "publish_ips"));
        async move {
            ta_res!(());
            let log = &log;
            let mut global_ips = vec![];
            for a in config.global_addrs {
                global_ips.push(resolve_global_ip(log, a).await?);
            };
            loop {
                match async {
                    ta_res!(());
                    let mut publisher_urls = vec![];
                    for p in &config.publishers {
                        publisher_urls.push(Uri::from_str(&p).stack_context(log, "Invalid publisher URI")?);
                    }
                    publish_util::announce(log, identity_signer.clone(), &publisher_urls).await?;
                    publish_util::publish(
                        log,
                        &publisher_urls,
                        identity_signer.clone(),
                        wire::api::publish::v1::PublishRequestContent {
                            clear_all: true,
                            set: {
                                let mut out = HashMap::new();
                                for ip in &global_ips {
                                    let key;
                                    let data;
                                    match ip {
                                        std::net::IpAddr::V4(ip) => {
                                            key = RecordType::A;
                                            data =
                                                serde_json::to_value(
                                                    &stored::dns_record::DnsA::V1(
                                                        stored::dns_record::latest::DnsA(vec![ip.to_string()]),
                                                    ),
                                                ).unwrap();
                                        },
                                        std::net::IpAddr::V6(ip) => {
                                            key = RecordType::Aaaa;
                                            data =
                                                serde_json::to_value(
                                                    &stored::dns_record::DnsAaaa::V1(
                                                        stored::dns_record::latest::DnsAaaa(vec![ip.to_string()]),
                                                    ),
                                                ).unwrap();
                                        },
                                    }
                                    let key = format_dns_key(".", key);
                                    if !out.contains_key(&key) {
                                        out.insert(
                                            key,
                                            stored::record::RecordValue::latest(stored::record::latest::RecordValue {
                                                ttl: 60,
                                                data: Some(data),
                                            }),
                                        );
                                    }
                                }
                                out
                            },
                            ..Default::default()
                        },
                    ).await?;
                    return Ok(());
                }.await {
                    Ok(_) => break,
                    Err(e) => {
                        log.log_err(loga::INFO, e.context("Error reaching publisher, retrying"));
                        sleep(Duration::seconds(60).to_std().unwrap()).await;
                    },
                }
            }
            return Ok(());
        }
    };

    // Start server or just tls renewal
    if let Some(serve) = config.serve {
        let cert_path = serve.cert_dir;
        create_dir_all(&cert_path)
            .await
            .stack_context_with(log, "Error creating cert dir", ea!(path = cert_path.to_string_lossy()))?;
        let pub_path = cert_path.join("pub.pem");
        let pub_pem = bb!{
            'pub_done _;
            let raw = match read(&pub_path).await {
                Ok(v) => {
                    v
                },
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        break 'pub_done None;
                    }
                    return Err(
                        e.stack_context_with(log, "Error reading file", ea!(path = pub_path.to_string_lossy())),
                    );
                },
            };
            Some(
                String::from_utf8(
                    raw,
                ).stack_context_with(log, "Couldn't parse PEM as utf-8", ea!(path = pub_path.to_string_lossy()))?,
            )
        };
        let priv_path = cert_path.join("priv.pem");
        let priv_pem = bb!{
            'priv_done _;
            let raw = match read(&priv_path).await {
                Ok(v) => {
                    v
                },
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        break 'priv_done None;
                    }
                    return Err(
                        e.stack_context_with(log, "Error reading file", ea!(path = priv_path.to_string_lossy())),
                    );
                },
            };
            Some(
                String::from_utf8(
                    raw,
                ).stack_context_with(log, "Couldn't parse PEM as utf-8", ea!(path = priv_path.to_string_lossy()))?,
            )
        };
        let initial_certs = match pub_pem.zip(priv_pem) {
            Some((pub_pem, priv_pem)) => CertPair {
                pub_pem: pub_pem,
                priv_pem: priv_pem,
            },
            None => loop {
                match request_cert(&log, identity_signer.clone()).await {
                    Ok(p) => break p,
                    Err(e) => {
                        log.log_err(
                            loga::WARN,
                            e.context_with("Error fetching initial certificates, retrying", ea!(subsys = "self_tls")),
                        );
                        sleep(Duration::seconds(60).to_std().unwrap()).await;
                    },
                }
            },
        };
        let certs =
            Arc::new(
                RwLock::new(
                    load_certified_key(
                        &initial_certs.pub_pem,
                        &initial_certs.priv_pem,
                    ).context("Error reading initial certs")?,
                ),
            );
        let certs_stream = request_cert_stream(&log, &tm, identity_signer.clone(), initial_certs).await?;
        tm.stream(
            "Serve - handle cert changes",
            WatchStream::new(certs_stream.clone()),
            cap_fn!((p)(certs, pub_path, priv_path, log) {
                match load_certified_key(&p.pub_pem, &p.priv_pem) {
                    Ok(v) => {
                        *certs.write().unwrap() = v;
                    },
                    Err(e) => {
                        log.log_err(loga::WARN, e.context("Received invalid certs, dropping"));
                        return;
                    },
                };
                write(&pub_path, p.pub_pem.as_bytes())
                    .await
                    .log_with(
                        &log,
                        loga::WARN,
                        "Error writing pub pem to disk",
                        ea!(path = pub_path.to_string_lossy(), pem = p.pub_pem),
                    );
                write(&priv_path, p.priv_pem.as_bytes())
                    .await
                    .log_with(
                        &log,
                        loga::WARN,
                        "Error writing priv pem to disk",
                        ea!(path = priv_path.to_string_lossy(), pem = p.priv_pem),
                    );
            }),
        );
        for content in serve.content {
            serve_content(log, tm, &certs, content).await?;
        }
    } else {
        tm.terminate();
    }

    select!{
        r = async_publish_ips => {
            r?;
        }
    }

    return Ok(());
}

#[tokio::main]
async fn main() {
    let args = aargvark::vark::<Args>();
    let log = &Log::new_root(if args.debug.is_some() {
        loga::DEBUG
    } else {
        loga::INFO
    });
    let tm = taskmanager::TaskManager::new();
    match inner(log, &tm, args).await.map_err(|e| {
        tm.terminate();
        return e;
    }).also({
        tm.join(log).await.context("Critical services failed")
    }) {
        Ok(_) => { },
        Err(e) => {
            loga::fatal(e);
        },
    }
}
