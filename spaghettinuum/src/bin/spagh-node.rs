use {
    aargvark::{
        Aargvark,
        AargvarkJson,
    },
    chrono::Duration,
    loga::{
        ea,
        ErrContext,
        Log,
        ResultContext,
    },
    spaghettinuum::{
        cap_fn,
        content::serve_content,
        interface::{
            config::{
                node::Config,
                DebugFlag,
                ENV_CONFIG,
            },
            stored::{
                self,
                dns_record::{
                    format_dns_key,
                    RecordType,
                },
                shared::SerialAddr,
            },
            wire::{
                self,
                api::publish::latest::InfoResponse,
                node::latest::NodeInfo,
            },
        },
        node::Node,
        publisher::{
            self,
            Publisher,
        },
        resolver::{
            self,
            Resolver,
        },
        self_tls::{
            self,
            request_cert,
            request_cert_stream,
            CertPair,
        },
        ta_res,
        utils::{
            backed_identity::get_identity_signer,
            db_util,
            htserve::{
                self,
                auth,
                auth_hash,
                Routes,
            },
            ip_util::resolve_global_ip,
            publish_util::generate_publish_announce,
            tls_util::{
                load_certified_key,
                SingleCertResolver,
            },
        },
    },
    std::{
        collections::{
            HashMap,
            HashSet,
        },
        net::SocketAddr,
        sync::{
            Arc,
            RwLock,
        },
    },
    taskmanager::TaskManager,
    tokio::{
        fs::create_dir_all,
        task::spawn_blocking,
        time::sleep,
    },
    tokio_stream::wrappers::WatchStream,
};

#[derive(Aargvark)]
struct Args {
    /// Refer to the readme for the json schema
    pub config: Option<AargvarkJson<Config>>,
    /// Enable default debug logging, or specific log levels
    #[vark(break)]
    pub debug: Option<Vec<DebugFlag>>,
}

async fn inner(log: &Log, tm: &TaskManager, args: Args) -> Result<(), loga::Error> {
    // Load and parse config, prep environment
    let mut debug_flags = HashSet::<DebugFlag>::new();
    if let Some(f) = &args.debug {
        debug_flags.extend(f);
    }
    let debug_level = move |flag: DebugFlag| {
        if debug_flags.contains(&flag) {
            return loga::DEBUG;
        } else {
            return loga::INFO;
        }
    };
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
    create_dir_all(&config.persistent_dir)
        .await
        .stack_context_with(
            log,
            "Error creating persistent dir",
            ea!(path = config.persistent_dir.to_string_lossy()),
        )?;

    // Resolve public ips
    let mut global_ips = vec![];
    for a in config.global_addrs {
        global_ips.push(resolve_global_ip(log, a).await?);
    };

    // Get identity signer for self-publish and getting ssl certs
    let identity = get_identity_signer(config.identity.clone()).stack_context(log, "Error loading identity")?;

    // Start node
    let node = {
        let log = log.fork_with_log_from(debug_level(DebugFlag::Node), ea!(sys = "node"));
        let mut bootstrap = vec![];
        for e in config.node.bootstrap {
            bootstrap.push(NodeInfo {
                ident: e.ident,
                address: SerialAddr(
                    e.addr.resolve().stack_context(&log, "Error resolving bootstrap node address")?,
                ),
            });
        }
        Node::new(log, tm.clone(), config.node.bind_addr, &bootstrap, &config.persistent_dir).await?
    };

    // Start publisher
    let publisher = {
        let publisher_config = config.publisher;
        let log = &log.fork_with_log_from(debug_level(DebugFlag::Publish), ea!(sys = "publisher"));
        let bind_addr =
            publisher_config.bind_addr.resolve().stack_context(log, "Error resolving publisher bind address")?;
        let advertise_ip =
            *global_ips
                .get(0)
                .stack_context(log, "Running a publisher requires at least one configured global IP")?;
        let advertise_port = publisher_config.advertise_port.unwrap_or(bind_addr.port());
        let advertise_addr = SocketAddr::new(advertise_ip, advertise_port);
        let publisher =
            Publisher::new(log, &tm, node.clone(), publisher_config.bind_addr, advertise_addr, &config.persistent_dir)
                .await
                .stack_context(log, "Error setting up publisher")?;

        // Publish self
        let (identity, announcement) = generate_publish_announce(&identity, vec![InfoResponse {
            advertise_addr: advertise_addr,
            cert_pub_hash: publisher.pub_cert_hash(),
        }]).map_err(|e| log.err_with("Failed to generate announcement for self publication", ea!(err = e)))?;
        publisher.announce(&identity, announcement).await?;
        publisher.modify_values(&identity, wire::api::publish::v1::PublishRequestContent {
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
                        out.insert(key, stored::record::RecordValue::latest(stored::record::latest::RecordValue {
                            ttl: 60,
                            data: Some(data),
                        }));
                    }
                }
                out
            },
            ..Default::default()
        }).await?;
        publisher
    };

    // Start resolver
    let resolver = match config.resolver {
        Some(resolver_config) => {
            let log = &log.fork_with_log_from(debug_level(DebugFlag::Resolve), ea!(sys = "resolver"));
            let resolver =
                Resolver::new(
                    log,
                    &tm,
                    node.clone(),
                    resolver_config.max_cache,
                    &config.persistent_dir,
                    publisher.clone(),
                    global_ips.clone(),
                )
                    .await
                    .stack_context(log, "Error setting up resolver")?;
            if let Some(dns_config) = resolver_config.dns_bridge {
                resolver::dns::start_dns_bridge(log, &tm, &resolver, dns_config, &config.persistent_dir)
                    .await
                    .stack_context(log, "Error setting up resolver DNS bridge")?;
            }
            Some(resolver)
        },
        None => None,
    };

    // Get own tls cert
    let latest_certs = {
        let db_pool =
            db_util::setup_db(&config.persistent_dir.join("self_tls.sqlite3"), self_tls::db::migrate).await?;
        db_pool.get().await?.interact(|conn| self_tls::db::api_certs_setup(conn)).await??;
        let initial_pair = db_pool.get().await?.interact(|conn| self_tls::db::api_certs_get(conn)).await??;
        let initial_pair = match (initial_pair.pub_pem, initial_pair.priv_pem) {
            (Some(pub_pem), Some(priv_pem)) => CertPair {
                pub_pem: pub_pem,
                priv_pem: priv_pem,
            },
            _ => {
                loop {
                    match request_cert(&log, identity.clone()).await {
                        Ok(p) => break p,
                        Err(e) => {
                            log.log_err(
                                loga::WARN,
                                e.context_with(
                                    "Error fetching initial certificates, retrying",
                                    ea!(subsys = "self_tls"),
                                ),
                            );
                            sleep(Duration::seconds(60).to_std().unwrap()).await;
                        },
                    }
                }
            },
        };
        let latest_certs =
            Arc::new(
                RwLock::new(
                    load_certified_key(
                        &initial_pair.pub_pem,
                        &initial_pair.priv_pem,
                    ).context("Initial certs are invalid")?,
                ),
            );
        let certs_stream = request_cert_stream(&log, &tm, identity, initial_pair).await?;
        tm.stream(
            "API - process new certs",
            WatchStream::new(certs_stream.clone()),
            cap_fn!((pair)(db_pool, log, latest_certs) {
                match async {
                    ta_res!(());
                    match load_certified_key(&pair.pub_pem, &pair.priv_pem) {
                        Ok(p) => {
                            spawn_blocking({
                                let latest_certs = latest_certs.clone();
                                move || {
                                    *latest_certs.write().unwrap() = p;
                                }
                            }).await.unwrap();
                        },
                        Err(e) => {
                            log.log_err(loga::WARN, e.context("New certs are invalid"));
                            return Ok(());
                        },
                    };
                    db_pool
                        .get()
                        .await?
                        .interact(
                            move |conn| self_tls::db::api_certs_set(
                                conn,
                                Some(&pair.pub_pem),
                                Some(&pair.priv_pem),
                            ),
                        )
                        .await??;
                    return Ok(());
                }.await {
                    Ok(_) => (),
                    Err(e) => {
                        log.log_err(loga::DEBUG, e.context("Error persisting new certs"));
                    },
                }
            }),
        );
        latest_certs
    };

    // Start http api
    let log = log.fork_with_log_from(debug_level(DebugFlag::Htserve), ea!(sys = "api_http"));
    if config.api_bind_addrs.is_empty() {
        return Err(
            log.err("Configuration enables resolver or publisher but no api http bind address present in config"),
        );
    }
    let mut routes = Routes::new();
    routes.add("health", htserve::Leaf::new().get(cap_fn!((_r)() {
        return htserve::Response::Ok;
    })));
    if let Some(admin_token) = &config.admin_token {
        let admin_token = auth_hash(admin_token);
        routes.add("admin/health", htserve::Leaf::new().get(cap_fn!((r)(node, admin_token) {
            // Auth
            if !auth(&admin_token, &r.auth_bearer) {
                return htserve::Response::AuthErr;
            }

            // Process + respond
            return htserve::Response::json(node.health_detail());
        })));
    }
    if let Some(resolver) = &resolver {
        let log = log.fork_with_log_from(debug_level(DebugFlag::Resolve), ea!(sys = "resolver"));
        routes.nest("resolve", resolver::build_api_endpoints(log, resolver));
    }
    {
        let log = log.fork_with_log_from(debug_level(DebugFlag::Publish), ea!(sys = "publisher"));
        routes.nest(
            "publish",
            publisher::build_api_endpoints(
                log.clone(),
                &publisher,
                config.admin_token.as_ref(),
                &config.persistent_dir,
            )
                .await
                .stack_context(&log, "Error building publisher endpoints")?,
        );
    }
    let routes = routes.build(log.fork(ea!(subsys = "router")));
    for bind_addr in config.api_bind_addrs {
        let bind_addr = bind_addr.resolve().stack_context(&log, "Error resolving api bind address")?;
        let log = log.clone();
        let routes = routes.clone();
        let tls_acceptor = {
            let mut server_config =
                rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_cert_resolver(Arc::new(SingleCertResolver(latest_certs.clone())));
            server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
            tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
        };
        tm.stream(
            format!("API - Server ({})", bind_addr),
            tokio_stream::wrappers::TcpListenerStream::new(
                tokio::net::TcpListener::bind(&bind_addr).await.stack_context(&log, "Error binding to address")?,
            ),
            move |stream| {
                let log = log.clone();
                let tls_acceptor = tls_acceptor.clone();
                let routes = routes.clone();
                async move {
                    let stream = match stream {
                        Ok(s) => s,
                        Err(e) => {
                            log.log_err(loga::DEBUG, e.context("Error opening peer stream"));
                            return;
                        },
                    };
                    let peer_addr = match stream.peer_addr() {
                        Ok(a) => a,
                        Err(e) => {
                            log.log_err(loga::DEBUG, e.context("Error getting connection peer address"));
                            return;
                        },
                    };
                    let stream = match tls_acceptor.accept(stream).await {
                        Ok(a) => a,
                        Err(e) => {
                            log.log_err(loga::DEBUG, e.context("Error setting up tls stream"));
                            return;
                        },
                    };
                    tokio::task::spawn(async move {
                        match async move {
                            hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                                .serve_connection(
                                    hyper_util::rt::TokioIo::new(stream),
                                    hyper::service::service_fn(move |req| htserve::handle(routes.clone(), req)),
                                )
                                .await
                                .map_err(
                                    |e| loga::err_with("Error serving HTTP on connection", ea!(err = e.to_string())),
                                )?;
                            return Ok(()) as Result<(), loga::Error>;
                        }.await {
                            Ok(_) => (),
                            Err(e) => {
                                log.log_err(
                                    loga::DEBUG,
                                    e.context_with("Error serving connection", ea!(peer = peer_addr)),
                                );
                            },
                        }
                    });
                }
            },
        );
    }

    // Start additional content serving
    for content in config.content {
        let log = log.fork_with_log_from(debug_level(DebugFlag::Htserve), ea!(sys = "content"));
        serve_content(&log, tm, &latest_certs, content).await?;
    }

    // Done
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
