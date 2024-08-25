use {
    aargvark::{
        Aargvark,
        AargvarkJson,
    },
    flowcontrol::shed,
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
        tls_acceptor,
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
                identity::LocalIdentitySecret,
                node::{
                    api_config::DEFAULT_API_PORT,
                    node_config::DEFAULT_NODE_PORT,
                    publisher_config::DEFAULT_PUBLISHER_PORT,
                    Config,
                },
                shared::{
                    IdentitySecretArg,
                    StrSocketAddr,
                },
                DebugFlag,
                ENV_CONFIG,
            },
            stored::shared::SerialAddr,
            wire::{
                self,
                api::publish::latest::InfoResponse,
                node::latest::NodeInfo,
            },
        },
        self_tls::{
            self,
            RequestCertOptions,
        },
        service::{
            content::start_serving_content,
            node::{
                default_bootstrap,
                Node,
            },
            publisher::{
                self,
                Publisher,
                API_ROUTE_PUBLISH,
            },
            resolver::{
                self,
                Resolver,
                API_ROUTE_RESOLVE,
            },
        },
        ta_res,
        ta_vis_res,
        utils::{
            fs_util::{
                self,
                maybe_read_json,
            },
            identity_secret::get_identity_signer,
            publish_util::{
                add_ip_record,
                add_ssh_host_key_records,
                generate_publish_announce,
            },
            system_addr::resolve_global_ip,
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
            Ipv4Addr,
            Ipv6Addr,
            SocketAddr,
            SocketAddrV4,
            SocketAddrV6,
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
    #[vark(break_help)]
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
    } else if let Some(config) = maybe_read_json(fs_util::config_path()).await? {
        config
    } else {
        return Err(
            log.err_with(
                "No config passed on command line, no config set in env var, and no config at default path",
                ea!(env = ENV_CONFIG, default_path = fs_util::config_path().to_string_lossy()),
            ),
        );
    };
    let data_dir = config.persistent_dir.unwrap_or_else(|| fs_util::data_dir());
    let cache_dir = config.cache_dir.unwrap_or_else(|| fs_util::cache_dir());
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
    let identity_secret = shed!{
        if let Some(i) = config.identity {
            break i;
        }
        let ident_path = data_dir.join("host.ident");
        if ident_path.exists() {
            break IdentitySecretArg::Local(ident_path);
        }
        let (_, s) = LocalIdentitySecret::new();
        fs_util::write(&ident_path, &serde_json::to_vec_pretty(&s).unwrap()).await?;
        break IdentitySecretArg::Local(ident_path);
    };
    let identity_signer =
        get_identity_signer(identity_secret.clone()).await.stack_context(log, "Error loading identity")?;

    // Prep for api
    let mut router = htserve::PathRouter::default();
    router.insert("/health", Box::new(htwrap::handler!(()(_r -> htserve:: Body) {
        return response_200();
    })));

    // Start node
    let node = {
        let log = log.fork_with_log_from(debug_level(DebugFlag::Node), ea!(sys = "node"));
        let mut bootstrap = vec![];
        match config.node.bootstrap {
            Some(bootstrap1) => {
                for e in bootstrap1 {
                    bootstrap.push(NodeInfo {
                        ident: e.ident,
                        address: SerialAddr(
                            e.addr.resolve().stack_context(&log, "Error resolving bootstrap node address")?,
                        ),
                    });
                }
            },
            None => {
                bootstrap = default_bootstrap();
            },
        }
        Node::new(
            &log,
            &tm,
            config
                .node
                .bind_addr
                .unwrap_or_else(
                    || StrSocketAddr::from(
                        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, DEFAULT_NODE_PORT, 0, 0)),
                    ),
                ),
            &bootstrap,
            &cache_dir,
        ).await?
    };

    // Start publisher
    let publisher;
    if let Some(publisher_config) = config.publisher {
        let log = &log.fork_with_log_from(debug_level(DebugFlag::Publish), ea!(sys = "publisher"));
        let bind_addr =
            publisher_config
                .bind_addr
                .unwrap_or_else(
                    || StrSocketAddr::from(
                        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, DEFAULT_PUBLISHER_PORT, 0, 0)),
                    ),
                )
                .resolve()
                .stack_context(log, "Error resolving publisher bind address")?;
        let advertise_ip =
            *public_ips
                .get(0)
                .stack_context(log, "Running a publisher requires at least one configured global IP")?;
        let advertise_port = publisher_config.advertise_port.unwrap_or(bind_addr.port());
        let advertise_addr = SocketAddr::new(advertise_ip, advertise_port);
        let publisher1 =
            Publisher::new(log, &tm, node.clone(), bind_addr, advertise_addr, &data_dir)
                .await
                .stack_context(log, "Error setting up publisher")?;

        // Publish self
        let (identity, announcement) = generate_publish_announce(&identity_signer, vec![InfoResponse {
            advertise_addr: advertise_addr,
            cert_pub_hash: publisher1.pub_cert_hash(),
        }]).map_err(|e| log.err_with("Failed to generate announcement for self publication", ea!(err = e)))?;
        publisher1.announce(&identity, announcement).await?;
        let mut publish_data = HashMap::new();
        for ip in &public_ips {
            add_ip_record(&mut publish_data, *ip);
        }
        add_ssh_host_key_records(&mut publish_data, publisher_config.ssh_host_keys).await?;
        publisher1.modify_values(&identity, wire::api::publish::v1::PublishRequestContent {
            clear_all: true,
            set: publish_data,
            ..Default::default()
        }).await?;
        publisher = Some(publisher1);
    } else {
        publisher = None;
    }

    // Get own tls cert
    let Some((certs, r21_certs)) =
        self_tls::htserve_certs(
            log,
            &cache_dir,
            None,
            tm,
            publisher
                .as_ref()
                .map(|publisher| publisher.clone() as Arc<dyn spaghettinuum::publishing::Publisher>)
                .as_ref(),
            &identity_signer,
            RequestCertOptions {
                certifier: false,
                signature: true,
            },
        ).await? else {
            return Ok(());
        };

    // Start resolver
    if let Some(resolver_config) = config.resolver {
        let resolver =
            Resolver::new(
                &log.fork_with_log_from(debug_level(DebugFlag::Resolve), ea!(sys = "resolver")),
                &tm,
                node.clone(),
                resolver_config.max_cache,
                &cache_dir,
                publisher.clone(),
                public_ips.clone(),
            )
                .await
                .stack_context(log, "Error setting up resolver")?;
        if let Some(dns_config) = resolver_config.dns_bridge {
            resolver::dns::start_dns_bridge(
                &log.fork_with_log_from(debug_level(DebugFlag::Resolve), ea!(sys = "resolver_dns")),
                &tm,
                &resolver,
                r21_certs,
                dns_config,
            )
                .await
                .stack_context(log, "Error setting up resolver DNS bridge")?;
        }
        {
            let log = log.fork_with_log_from(debug_level(DebugFlag::Resolve), ea!(sys = "resolver"));
            router.insert(
                format!("/{}", API_ROUTE_RESOLVE),
                Box::new(resolver::build_api_endpoints(log, &resolver)),
            );
        }
    }

    // Start http api
    let log = log.fork_with_log_from(debug_level(DebugFlag::Htserve), ea!(sys = "api_http"));
    if let Some(api) = config.api {
        if let Some(admin_token) = api.admin_token {
            let admin_token = hash_auth_token(&match admin_token {
                config::node::api_config::AdminToken::File(p) => String::from_utf8(
                    fs::read(&p).context_with("Error reading admin token file", ea!(path = p.to_string_lossy()))?,
                ).map_err(|_| loga::err_with("Admin token isn't valid utf8", ea!(path = p.to_string_lossy())))?,
                config::node::api_config::AdminToken::Inline(p) => p,
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
            if let Some(publisher) = &publisher {
                router.insert(
                    format!("/{}", API_ROUTE_PUBLISH),
                    Box::new(
                        publisher::build_api_endpoints(
                            &log.fork_with_log_from(debug_level(DebugFlag::Publish), ea!(sys = "publisher")),
                            &publisher,
                            &admin_token,
                            &data_dir,
                        )
                            .await
                            .stack_context(&log, "Error building publisher endpoints")?,
                    ),
                );
            }
        }
        let router = Arc::new(router);
        let mut api_bind_addrs = api.bind_addrs;
        if api_bind_addrs.is_empty() {
            api_bind_addrs.push(
                StrSocketAddr::from(
                    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, DEFAULT_API_PORT, 0, 0)),
                ),
            );
            api_bind_addrs.push(
                StrSocketAddr::from(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, DEFAULT_API_PORT))),
            );
        }
        for bind_addr in api_bind_addrs {
            let bind_addr = bind_addr.resolve().stack_context(&log, "Error resolving api bind address")?;
            let log = log.clone();
            let routes = router.clone();
            let tls_acceptor = tls_acceptor(certs.clone());
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
    }

    // Serve content
    if let Some(content) = config.content {
        for content in content {
            start_serving_content(&log, tm, certs.clone(), content).await?;
        }
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
