use {
    aargvark::{
        Aargvark,
        AargvarkJson,
    },
    htwrap::htserve::{
        self,
        check_auth_token_hash,
        get_auth_token,
        hash_auth_token,
        response_200,
        response_200_json,
        response_400,
        response_401,
        response_503,
        AuthTokenHash,
    },
    loga::{
        ea,
        Log,
        ResultContext,
    },
    spaghettinuum::{
        interface::{
            config::{
                self,
                node::Config,
                DebugFlag,
                ENV_CONFIG,
            },
            stored::{
                self,
                record::dns_record::{
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
        self_tls,
        service::{
            content::serve_content,
            node::Node,
            publisher::{
                self,
                Publisher,
            },
            resolver::{
                self,
                Resolver,
            },
        },
        ta_res,
        ta_vis_res,
        utils::{
            identity_secret::get_identity_signer,
            ip_util::resolve_global_ip,
            publish_util::{
                add_ssh_host_key_records,
                generate_publish_announce,
            },
            ResultVisErr,
            VisErr,
        },
    },
    std::{
        collections::{
            HashMap,
            HashSet,
        },
        fs,
        net::{
            IpAddr,
            SocketAddr,
        },
        sync::Arc,
    },
    taskmanager::TaskManager,
    tokio::{
        fs::create_dir_all,
        select,
    },
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
    let data_dir = fs_util::data_dir();
    let cache_dir = fs_util::cache_dir();
    let config_path = fs_util::config_path();
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
    create_dir_all(&data_dir)
        .await
        .stack_context_with(log, "Error creating persistent data dir", ea!(path = data_dir.to_string_lossy()))?;

    // Resolve public ips
    let resolve_public_ips = async {
        ta_res!(Vec < IpAddr >);
        let mut ips = vec![];
        for a in config.global_addrs {
            ips.push(resolve_global_ip(log, a).await?);
        };
        return Ok(ips);
    };
    let public_ips = select!{
        x = resolve_public_ips => x ?,
        _ = tm.until_terminate() => return Ok(()),
    };

    // Get identity signer for self-publish and getting ssl certs
    let identity = get_identity_signer(config.identity.clone()).await.stack_context(log, "Error loading identity")?;

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
        Node::new(&log, &tm, config.node.bind_addr, &bootstrap, &config.persistent_dir).await?
    };

    // Start publisher
    let publisher = {
        let publisher_config = config.publisher;
        let log = &log.fork_with_log_from(debug_level(DebugFlag::Publish), ea!(sys = "publisher"));
        let bind_addr =
            publisher_config.bind_addr.resolve().stack_context(log, "Error resolving publisher bind address")?;
        let advertise_ip =
            *public_ips
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
        let mut publish_data = HashMap::new();
        for ip in &public_ips {
            let key;
            let data;
            match ip {
                std::net::IpAddr::V4(ip) => {
                    key = RecordType::A;
                    data =
                        serde_json::to_value(
                            &stored::record::dns_record::DnsA::V1(
                                stored::record::dns_record::latest::DnsA(vec![*ip]),
                            ),
                        ).unwrap();
                },
                std::net::IpAddr::V6(ip) => {
                    key = RecordType::Aaaa;
                    data =
                        serde_json::to_value(
                            &stored::record::dns_record::DnsAaaa::V1(
                                stored::record::dns_record::latest::DnsAaaa(vec![*ip]),
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
        publisher.modify_values(&identity, wire::api::publish::v1::PublishRequestContent {
            clear_all: true,
            set: publish_data,
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
                    public_ips.clone(),
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
    let Some(
        latest_certs
    ) = self_tls:: htserve_tls_resolves(
        log,
        &config.persistent_dir,
        false,
        tm,
        &(publisher.clone() as Arc<dyn spaghettinuum::publishing::Publisher>),
        &identity
    ).await ? else {
        return Ok(());
    };

    // Start http api
    let log = log.fork_with_log_from(debug_level(DebugFlag::Htserve), ea!(sys = "api_http"));
    if config.api_bind_addrs.is_empty() {
        return Err(
            log.err("Configuration enables resolver or publisher but no api http bind address present in config"),
        );
    }
    let mut router = htserve::PathRouter::default();
    router.insert("/health", Box::new(htwrap::handler!(()(_r -> htserve:: Body) {
        return response_200();
    })));
    if let Some(admin_token) = config.admin_token {
        let admin_token = hash_auth_token(&match admin_token {
            config::node::AdminToken::File(p) => String::from_utf8(
                fs::read(&p).context_with("Error reading admin token file", ea!(path = p.to_string_lossy()))?,
            ).map_err(|_| loga::err_with("Admin token isn't valid utf8", ea!(path = p.to_string_lossy())))?,
            config::node::AdminToken::Inline(p) => p,
        });
        router.insert(
            "/admin/health",
            Box::new(htwrap::handler!((log: Log, node: Node, admin_token: AuthTokenHash)(r -> htserve:: Body) {
                match async {
                    ta_vis_res!(http:: Response < htserve:: Body >);
                    if !check_auth_token_hash(&admin_token, &get_auth_token(&r.head.headers).err_external()?) {
                        return Ok(response_401());
                    }
                    return Ok(response_200_json(node.health_detail()));
                }.await {
                    Ok(r) => return r,
                    Err(VisErr::External(e)) => {
                        return response_400(e);
                    },
                    Err(VisErr::Internal(e)) => {
                        log.log_err(loga::DEBUG, e.context("Error serving admin health endpoint"));
                        return response_503();
                    },
                }
            })),
        );
        router.insert(
            "/publish",
            Box::new(
                publisher::build_api_endpoints(
                    &log.fork_with_log_from(debug_level(DebugFlag::Publish), ea!(sys = "publisher")),
                    &publisher,
                    &admin_token,
                    &config.persistent_dir,
                )
                    .await
                    .stack_context(&log, "Error building publisher endpoints")?,
            ),
        );
    }
    if let Some(resolver) = &resolver {
        let log = log.fork_with_log_from(debug_level(DebugFlag::Resolve), ea!(sys = "resolver"));
        router.insert("/resolve", Box::new(resolver::build_api_endpoints(log, resolver)));
    }
    let router = Arc::new(router);
    for bind_addr in config.api_bind_addrs {
        let bind_addr = bind_addr.resolve().stack_context(&log, "Error resolving api bind address")?;
        let log = log.clone();
        let routes = router.clone();
        let tls_acceptor = {
            let mut server_config =
                rustls::ServerConfig::builder().with_no_client_auth().with_cert_resolver(latest_certs.clone());
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
                    match async {
                        ta_res!(());
                        htserve::root_handle_https(&log, tls_acceptor, routes, stream?).await?;
                        return Ok(());
                    }.await {
                        Ok(_) => (),
                        Err(e) => {
                            log.log_err(loga::DEBUG, e.context("Error serving request"));
                            return;
                        },
                    }
                }
            },
        );
    }

    // Start additional content serving
    for content in config.content {
        let log = log.fork_with_log_from(debug_level(DebugFlag::Htserve), ea!(sys = "content"));
        serve_content(&log, tm, latest_certs.clone(), content).await?;
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
