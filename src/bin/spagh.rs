//! The server executable.  This takes a json config with the schema:
#![doc= "```"]
#![doc= include_str !("../../server_config.schema.json")]
#![doc= "```"]

use std::{
    net::SocketAddr,
    collections::HashMap,
};
use aargvark::{
    Aargvark,
    AargvarkJson,
};
use chrono::Duration;
use futures::FutureExt;
use loga::{
    ea,
    ResultContext,
};
use poem::{
    Route,
    Server,
    listener::{
        TcpListener,
        Listener,
        RustlsConfig,
        RustlsCertificate,
    },
};
use spaghettinuum::{
    config::{
        Config,
        self,
    },
    node::Node,
    publisher::{
        self,
        Publisher,
        DbAdmin,
    },
    resolver::{
        self,
        Resolver,
    },
    interface::{
        node_protocol::{
            latest::{
                NodeInfo,
                SerialAddr,
            },
        },
        spagh_cli::{
            self,
            DEFAULT_CERTIFIER_URL,
        },
        spagh_api::{
            publish,
            resolve::{
                KEY_DNS_A,
                KEY_DNS_AAAA,
            },
        },
    },
    utils::{
        publish_util::generate_publish_announce,
        ip_util::{
            local_resolve_global_ip,
            remote_resolve_global_ip,
        },
        backed_identity::get_identity_signer,
    },
    bb,
    self_tls::request_cert_stream,
};
use tokio::{
    fs::create_dir_all,
    time::sleep,
};
use tokio_stream::{
    StreamExt,
    wrappers::WatchStream,
};

#[derive(Aargvark)]
struct Args {
    pub config: Option<AargvarkJson<Config>>,
    pub debug: Option<()>,
}

#[tokio::main]
async fn main() {
    async fn inner() -> Result<(), loga::Error> {
        let args = aargvark::vark::<Args>();
        let log = &loga::new().with_level(if args.debug.is_some() {
            loga::Level::Debug
        } else {
            loga::Level::Info
        });
        let config = if let Some(p) = args.config {
            p.value
        } else if let Some(c) = match std::env::var(spagh_cli::ENV_CONFIG) {
            Ok(c) => Some(c),
            Err(e) => match e {
                std::env::VarError::NotPresent => None,
                std::env::VarError::NotUnicode(_) => {
                    return Err(
                        loga::new_err_with("Error parsing env var as unicode", ea!(env = spagh_cli::ENV_CONFIG)),
                    )
                },
            },
        } {
            let log = log.fork(ea!(source = "env"));
            serde_json::from_str::<Config>(&c).log_context(&log, "Parsing config")?
        } else {
            return Err(
                log.new_err_with(
                    "No config passed on command line, and no config set in env var",
                    ea!(env = spagh_cli::ENV_CONFIG),
                ),
            );
        };
        create_dir_all(&config.persistent_dir)
            .await
            .log_context_with(
                log,
                "Error creating persistent dir",
                ea!(path = config.persistent_dir.to_string_lossy()),
            )?;
        let mut global_ips = vec![];
        for a in config.global_addrs {
            global_ips.push(match a {
                config::GlobalAddrConfig::Fixed(s) => {
                    log.info("Identified fixed public ip address from config", ea!(addr = s));
                    s
                },
                config::GlobalAddrConfig::FromInterface { name, ip_version } => {
                    let res = loop {
                        if let Some(res) = local_resolve_global_ip(&name, &ip_version).await? {
                            break res;
                        }
                        log.info("Waiting for public ip address on interface", ea!());
                        sleep(Duration::seconds(10).to_std().unwrap()).await;
                    };
                    log.info("Identified public ip address via interface", ea!(addr = res));
                    res
                },
                config::GlobalAddrConfig::Lookup(lookup) => {
                    let res = loop {
                        match remote_resolve_global_ip(&lookup.lookup, lookup.contact_ip_ver).await {
                            Ok(r) => break r,
                            Err(e) => {
                                log.info_e(
                                    e,
                                    "Error looking up public ip through external service, retrying",
                                    ea!(),
                                );
                            },
                        }
                        sleep(Duration::seconds(10).to_std().unwrap()).await;
                    };
                    log.info("Identified public ip address via external lookup", ea!(addr = res));
                    res
                },
            })
        };
        let mut identity;
        if let Some(identity_config) = &config.identity {
            identity =
                Some(
                    get_identity_signer(identity_config.identity.clone()).log_context(log, "Error loading identity")?,
                );
            if identity_config.self_publish && config.publisher.is_none() {
                return Err(
                    log.new_err("Config has self_publish enabled but the publisher must be enabled for this to work"),
                );
            }
        } else {
            identity = None;
        }
        let tm = taskmanager::TaskManager::new();
        let node = {
            let mut bootstrap = vec![];
            for e in config.node.bootstrap {
                bootstrap.push(NodeInfo {
                    id: e.id,
                    address: SerialAddr(
                        e.addr.resolve().log_context(log, "Error resolving bootstrap node address")?,
                    ),
                });
            }
            Node::new(log, tm.clone(), config.node.bind_addr, &bootstrap, &config.persistent_dir).await?
        };
        let mut has_api_endpoints = false;
        let publisher = match config.publisher {
            Some(publisher_config) => {
                let bind_addr =
                    publisher_config.bind_addr.resolve().log_context(log, "Error resolving publisher bind address")?;
                has_api_endpoints = true;
                let advertise_ip =
                    *global_ips
                        .get(0)
                        .log_context(log, "Running a publisher requires at least one configured global IP")?;
                let advertise_port = publisher_config.advertise_port.unwrap_or(bind_addr.port());
                let advertise_addr = SocketAddr::new(advertise_ip, advertise_port);
                let publisher =
                    Publisher::new(
                        log,
                        &tm,
                        node.clone(),
                        publisher_config.bind_addr,
                        advertise_addr,
                        DbAdmin::new(&config.persistent_dir)
                            .await
                            .log_context(log, "Error setting up publisher db-admin")?,
                    )
                        .await
                        .log_context(log, "Error setting up publisher")?;
                if let Some(identity_config) = &config.identity {
                    if identity_config.self_publish {
                        let (identity, announcement) =
                            generate_publish_announce(
                                identity.as_mut().unwrap(),
                                advertise_addr,
                                &publisher.pub_cert_hash(),
                            ).map_err(
                                |e| log.new_err_with(
                                    "Failed to generate announcement for self publication",
                                    ea!(err = e),
                                ),
                            )?;
                        publisher.publish(&identity, announcement, publish::latest::Publish {
                            missing_ttl: 60 * 24,
                            data: {
                                let mut out = HashMap::new();
                                match advertise_ip {
                                    std::net::IpAddr::V4(ip) => {
                                        out.insert(KEY_DNS_A.to_string(), publish::latest::PublishValue {
                                            ttl: 60,
                                            data: ip.to_string(),
                                        });
                                    },
                                    std::net::IpAddr::V6(ip) => {
                                        out.insert(KEY_DNS_AAAA.to_string(), publish::latest::PublishValue {
                                            ttl: 60,
                                            data: ip.to_string(),
                                        });
                                    },
                                }
                                out
                            },
                        }).await?;
                    }
                }
                Some(publisher)
            },
            None => None,
        };
        let resolver = match config.resolver {
            Some(resolver_config) => {
                let resolver =
                    Resolver::new(log, &tm, node.clone(), resolver_config.max_cache, &config.persistent_dir)
                        .await
                        .log_context(log, "Error setting up resolver")?;
                if let Some(dns_config) = resolver_config.dns_bridge {
                    resolver::dns::start_dns_bridge(
                        log,
                        &tm,
                        &resolver,
                        &global_ips,
                        dns_config,
                        &config.persistent_dir,
                    )
                        .await
                        .log_context(log, "Error setting up resolver DNS bridge")?;
                } else {
                    has_api_endpoints = true;
                }
                Some(resolver)
            },
            None => None,
        };
        if has_api_endpoints {
            if config.api_bind_addrs.is_empty() {
                return Err(
                    log.new_err(
                        "Configuration defines api http endpoints but no api http bind address present in config",
                    ),
                );
            }
            let mut certs_stream_rx = None;

            bb!{
                let Some(identity) = identity else {
                    break;
                };
                let certifier_url = match &config.identity.as_ref().unwrap().self_tls {
                    false => {
                        break;
                    },
                    true => DEFAULT_CERTIFIER_URL.to_string(),
                };
                certs_stream_rx =
                    Some(request_cert_stream(log, &tm, &certifier_url, identity, &config.persistent_dir).await?);
            };

            for bind_addr in config.api_bind_addrs {
                let bind_addr = bind_addr.resolve().log_context(log, "Error resolving api bind address")?;
                let mut api_endpoints = Route::new();
                if let Some(resolver) = &resolver {
                    api_endpoints = api_endpoints.nest("/resolve", resolver::build_api_endpoints(&log, resolver).0);
                }
                if let Some(publisher) = &publisher {
                    api_endpoints = api_endpoints.nest("/publish", publisher::build_api_endpoints(publisher).0);
                }
                let server = match &certs_stream_rx {
                    Some(certs_stream_rx) => {
                        Server::new(
                            TcpListener::bind(
                                bind_addr,
                            ).rustls(
                                WatchStream::new(
                                    certs_stream_rx.clone(),
                                ).map(
                                    |p| RustlsConfig
                                    ::new().fallback(RustlsCertificate::new().cert(p.pub_pem).key(p.priv_pem)),
                                ),
                            ),
                        )
                            .run(api_endpoints)
                            .boxed()
                    },
                    None => {
                        Server::new(TcpListener::bind(bind_addr)).run(api_endpoints).boxed()
                    },
                };
                tm.critical_task({
                    let log = log.fork(ea!(subsys = "api_http"));
                    let tm1 = tm.clone();
                    async move {
                        match tm1.if_alive(server).await {
                            Some(r) => {
                                return r.log_context_with(&log, "Exited with error", ea!(addr = bind_addr));
                            },
                            None => {
                                return Ok(());
                            },
                        }
                    }
                });
            }
        }
        tm.join().await?;
        return Ok(());
    }

    match inner().await {
        Ok(_) => { },
        Err(e) => {
            loga::fatal(e);
        },
    }
}
