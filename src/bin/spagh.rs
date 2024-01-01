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
use futures::FutureExt;
use itertools::Itertools;
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
            self,
        },
        spagh_cli,
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
use tokio::fs::create_dir_all;
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
        let log = &loga::new(if args.debug.is_some() {
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
                    return Err(loga::err_with("Error parsing env var as unicode", ea!(env = spagh_cli::ENV_CONFIG)))
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
        let global_ip = match config.global_addr {
            config::GlobalAddrConfig::Fixed(s) => s,
            config::GlobalAddrConfig::FromInterface { name, ip_version } => {
                local_resolve_global_ip(name, ip_version).await?
            },
            config::GlobalAddrConfig::Lookup(lookup) => {
                remote_resolve_global_ip(&lookup.lookup, lookup.contact_ip_ver).await?
            },
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
        let node =
            Node::new(log, tm.clone(), config.node.bind_addr, &config.node.bootstrap.into_iter().map(|e| NodeInfo {
                id: match e.id {
                    node_protocol::NodeIdentity::V1(i) => i,
                },
                address: SerialAddr(e.addr.1),
            }).collect_vec(), &config.persistent_dir).await?;
        let mut api_endpoints = Route::new();
        let mut has_api_endpoints = false;
        if let Some(publisher_config) = config.publisher {
            let publisher =
                Publisher::new(
                    log,
                    &tm,
                    node.clone(),
                    publisher_config.bind_addr,
                    SocketAddr::new(global_ip, publisher_config.advertise_port),
                    DbAdmin::new(&config.persistent_dir)
                        .await
                        .log_context(log, "Error setting up publisher db-admin")?,
                )
                    .await
                    .log_context(log, "Error setting up publisher")?;
            has_api_endpoints = true;
            api_endpoints = api_endpoints.nest("/publish", publisher::build_api_endpoints(&publisher).0);
            if let Some(identity_config) = &config.identity {
                if identity_config.self_publish {
                    let (identity, announcement) =
                        generate_publish_announce(
                            identity.as_mut().unwrap(),
                            SocketAddr::new(global_ip, publisher_config.advertise_port),
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
                            match global_ip {
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
        }
        if let Some(resolver_config) = config.resolver {
            let resolver =
                Resolver::new(log, &tm, node.clone(), resolver_config.max_cache, &config.persistent_dir)
                    .await
                    .log_context(log, "Error setting up resolver")?;
            has_api_endpoints = true;
            api_endpoints = api_endpoints.nest("/resolve", resolver::build_api_endpoints(&log, &resolver).0);
            if let Some(dns_config) = resolver_config.dns_bridge {
                resolver::start_dns_bridge(log, &tm, &resolver, dns_config);
            }
        }
        if has_api_endpoints {
            let bind_addr =
                config
                    .api_bind_addr
                    .log_context(
                        log,
                        "Configuration defines api http endpoints but no api http bind address present in config",
                    )?;
            let server;

            bb!{
                'prepared_server _;
                // Certs from spagh certifier
                bb!{
                    let Some(identity) = identity else {
                        break;
                    };
                    let Some(certifier_url) = config.identity.unwrap().self_tls else {
                        break;
                    };
                    let certs_stream_rx =
                        request_cert_stream(log, &tm, &certifier_url, identity, &config.persistent_dir).await?;
                    server =
                        Server::new(
                            TcpListener::bind(
                                bind_addr.1,
                            ).rustls(
                                WatchStream::new(
                                    certs_stream_rx,
                                ).map(
                                    |p| RustlsConfig
                                    ::new().fallback(RustlsCertificate::new().cert(p.pub_pem).key(p.priv_pem)),
                                ),
                            ),
                        )
                            .run(api_endpoints)
                            .boxed();
                    break 'prepared_server;
                };
                // Default http server
                server = Server::new(TcpListener::bind(bind_addr.1)).run(api_endpoints).boxed();
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
