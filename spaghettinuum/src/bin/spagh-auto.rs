use {
    aargvark::{
        Aargvark,
        AargvarkJson,
    },
    chrono::Duration,
    loga::{
        ea,
        Log,
        ResultContext,
    },
    spaghettinuum::{
        interface::{
            config::{
                auto::Config,
                shared::GlobalAddrConfig,
                DebugFlag,
                ENV_CONFIG,
            },
            stored::{
                self,
                record::dns_record::{
                    format_dns_key,
                    RecordType,
                },
            },
            wire,
        },
        publishing::{
            system_publisher_url_pairs,
            Publisher,
            RemotePublisher,
        },
        resolving::system_resolver_url_pairs,
        self_tls::{
            self,
            RequestCertOptions,
        },
        service::content::start_serving_content,
        ta_res,
        utils::{
            fs_util::cache_dir,
            identity_secret::get_identity_signer,
            publish_util::{
                self,
                add_ssh_host_key_records,
            },
            system_addr::resolve_global_ip,
        },
    },
    std::{
        collections::HashMap,
        sync::Arc,
    },
    taskmanager::TaskManager,
    tokio::{
        fs::create_dir_all,
        time::sleep,
    },
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
    let identity_signer =
        get_identity_signer(config.identity.clone()).await.stack_context(log, "Error loading identity")?;
    let resolvers = system_resolver_url_pairs(&log)?;
    let publishers = system_publisher_url_pairs(&log)?;

    // Publish global ips, ssh certs
    {
        let identity_signer = identity_signer.clone();
        let log = log.fork(ea!(sys = "publish_ips"));
        ta_res!(());
        let log = &log;
        let mut publish_data = HashMap::new();
        let mut global_addrs = config.global_addrs;
        if global_addrs.is_empty() {
            global_addrs.push(GlobalAddrConfig::FromInterface {
                name: None,
                ip_version: None,
            });
        }
        for a in global_addrs {
            let ip = resolve_global_ip(log, a).await?;
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
                            &stored::record::dns_record::DnsAaaa::V1(
                                stored::record::dns_record::latest::DnsAaaa(vec![ip]),
                            ),
                        ).unwrap();
                },
            }
            let key = format_dns_key(".", key);
            if !publish_data.contains_key(&key) {
                publish_data.insert(key, stored::record::RecordValue::latest(stored::record::latest::RecordValue {
                    ttl: 60,
                    data: Some(data),
                }));
            }
        }
        add_ssh_host_key_records(&mut publish_data, config.ssh_host_keys).await?;
        loop {
            match async {
                ta_res!(());
                publish_util::announce(log, identity_signer.clone(), &resolvers, &publishers).await?;
                publish_util::publish(
                    log,
                    &resolvers,
                    &publishers,
                    identity_signer.clone(),
                    wire::api::publish::v1::PublishRequestContent {
                        clear_all: true,
                        set: publish_data.clone(),
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
    }

    // Start server or just tls renewal
    if config.cert_dir.is_some() || !config.content.is_empty() {
        let publisher = Arc::new(RemotePublisher {
            resolver_urls: resolvers,
            publisher_urls: publishers,
        }) as Arc<dyn Publisher>;
        let Some((certs, _)) = self_tls:: htserve_certs(log, &cache_dir(), if let Some(cert_dir) = config.cert_dir {
            create_dir_all(&cert_dir)
                .await
                .stack_context_with(log, "Error creating cert dir", ea!(path = cert_dir.to_string_lossy()))?;
            true
        } else {
            false
        }, tm, &publisher, &identity_signer, RequestCertOptions {
            certifier: true,
            signature: false,
        }).await ? else {
            return Ok(());
        };
        for content in config.content {
            start_serving_content(log, tm, certs.clone(), content).await?;
        }
    } else {
        tm.terminate();
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
