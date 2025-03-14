use {
    aargvark::{
        traits_impls::AargvarkJson,
        Aargvark,
    },
    flowcontrol::{
        ta_return,
    },
    htwrap::htserve::{
        self,
        auth::{
            check_auth_token_hash,
            get_auth_token,
            hash_auth_token,
            AuthTokenHash,
        },
        handler::{
            tls_acceptor,
            Handler,
        },
        responses::{
            response_200,
            response_200_json,
            response_400,
            response_401,
            response_503,
            Body,
        },
    },
    loga::{
        ea,
        DebugDisplay,
        Log,
        ResultContext,
    },
    rustls::server::ResolvesServerCert,
    spaghettinuum::{
        interface::{
            config::{
                self,
                shared::{
                    StrSocketAddr,
                },
                spagh::{
                    Config,
                    DEFAULT_API_PORT,
                    DEFAULT_NODE_PORT,
                    DEFAULT_PUBLISHER_PORT,
                },
                DebugFlag,
                ENV_CONFIG,
            },
            stored::{
                record::{
                    record_utils::RecordKey,
                    RecordValue,
                },
                self_tls::latest::RefreshTlsState,
                shared::SerialAddr,
            },
            wire::{
                api::publish::latest::InfoResponse,
                node::latest::NodeInfo,
            },
        },
        publishing,
        self_tls::{
            self,
            publish_tls_certs,
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
                write,
            },
            identity_secret::{
                get_identity_signer,
                IdentitySigner,
            },
            publish_util::{
                add_ip_record,
                add_ssh_host_key_records,
                generate_publish_announce,
                PublishArgs,
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
        sync::{
            Arc,
            Mutex,
        },
    },
    taskmanager::TaskManager,
    tokio::{
        fs::create_dir_all,
        select,
        sync::watch,
    },
    tokio_stream::wrappers::WatchStream,
};

#[derive(Aargvark)]
pub struct Args {
    /// Refer to the readme for the json schema
    pub config: Option<AargvarkJson<Config>>,
    /// Enable default debug logging, or specific log levels
    #[vark(break_help)]
    pub debug: Option<Vec<DebugFlag>>,
    /// Validate config then exit (with error code if config is invalid).
    pub validate: Option<()>,
}

fn debug_level(flags: &HashSet<DebugFlag>, want: DebugFlag) -> loga::Level {
    if flags.contains(&want) {
        return loga::DEBUG;
    } else {
        return loga::INFO;
    }
}

pub async fn run(log: &Log, args: Args) -> Result<(), loga::Error> {
    let tm = taskmanager::TaskManager::new();

    // Load and parse config, prep environment
    let mut debug_flags = HashSet::<DebugFlag>::new();
    if let Some(f) = &args.debug {
        debug_flags.extend(f);
    }
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
        serde_json::from_str::<Config>(&c).context("Parsing config")?
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
    if args.validate.is_some() {
        return Ok(());
    }
    create_dir_all(&config.persistent_dir)
        .await
        .context_with("Error creating persistent data dir", ea!(path = config.persistent_dir.to_string_lossy()))?;

    // Resolve public ips
    let resolve_public_ips = async {
        ta_res!(Vec < IpAddr >);
        let mut ips = vec![];
        for a in &config.global_addrs {
            ips.push(resolve_global_ip(log, a).await?);
        };
        return Ok(ips);
    };
    let global_ips = select!{
        x = resolve_public_ips => x ?,
        _ = tm.until_terminate() => return Ok(()),
    };

    // Start node
    let node = {
        let log = log.fork_with_log_from(debug_level(&debug_flags, DebugFlag::Node), ea!(sys = "node"));
        let mut bootstrap = vec![];
        match &config.node.bootstrap {
            Some(bootstrap1) => {
                for e in bootstrap1 {
                    bootstrap.push(NodeInfo {
                        ident: e.ident.clone(),
                        address: SerialAddr(e.addr.resolve().context("Error resolving bootstrap node address")?),
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
                .clone()
                .unwrap_or_else(
                    || StrSocketAddr::from(
                        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, DEFAULT_NODE_PORT, 0, 0)),
                    ),
                ),
            &bootstrap,
            &config.cache_dir,
        ).await?
    };

    struct SetupState {
        // Inputs
        tm: TaskManager,
        config: Config,
        node: Node,
        log: Log,
        global_ips: Vec<IpAddr>,
        debug_flags: HashSet<DebugFlag>,
        // Outputs
        publisher: Option<Result<(SocketAddr, Arc<Publisher>), loga::Error>>,
        resolver: Option<Result<Arc<Resolver>, loga::Error>>,
        tls: Option<Result<Option<watch::Receiver<RefreshTlsState>>, loga::Error>>,
        htserve_tls: Option<
            Result<
                Option<(Arc<dyn ResolvesServerCert>, Arc<dyn rustls_21::server::ResolvesServerCert>)>,
                loga::Error,
            >,
        >,
        admin: Option<Result<AuthTokenHash, loga::Error>>,
        identity: Option<Result<Arc<Mutex<dyn IdentitySigner>>, loga::Error>>,
        api_routes: HashMap<String, Box<dyn Handler<Body>>>,
        self_publish: HashMap<RecordKey, RecordValue>,
    }

    impl SetupState {
        async fn setup_admin(&mut self) -> Result<AuthTokenHash, loga::Error> {
            if let Some(x) = self.admin.as_ref() {
                return x.clone();
            };
            let res = async {
                let Some(admin_config) = &self.config.enable_admin else {
                    return Err(loga::err("Missing `enable_admin` configuration"));
                };
                let admin_token = hash_auth_token(&match &admin_config.admin_token {
                    config::spagh::AdminToken::File(p) => String::from_utf8(
                        fs::read(&p).context_with("Error reading admin token file", ea!(path = p.to_string_lossy()))?,
                    ).map_err(|_| loga::err_with("Admin token isn't valid utf8", ea!(path = p.to_string_lossy())))?,
                    config::spagh::AdminToken::Inline(p) => p.clone(),
                });
                let node = self.node.clone();
                let log =
                    self
                        .log
                        .fork_with_log_from(debug_level(&self.debug_flags, DebugFlag::Admin), ea!(sys = "admin"));
                self
                    .api_routes
                    .insert(
                        "/admin/health".to_string(),
                        Box::new(
                            htwrap::handler!(
                                (log: Log, node: Node, admin_token: AuthTokenHash)(r -> htserve:: responses:: Body) {
                                    match async {
                                        ta_vis_res!(http:: Response < htserve:: responses:: Body >);
                                        if !check_auth_token_hash(
                                            &admin_token,
                                            &get_auth_token(&r.head.headers).err_external()?,
                                        ) {
                                            return Ok(response_401());
                                        }
                                        return Ok(response_200_json(node.health_detail()));
                                    }.await {
                                        Ok(r) => return r,
                                        Err(VisErr::External(e)) => {
                                            return response_400(e);
                                        },
                                        Err(VisErr::Internal(e)) => {
                                            log.log_err(
                                                loga::DEBUG,
                                                e.context("Error serving admin health endpoint"),
                                            );
                                            return response_503();
                                        },
                                    }
                                }
                            ),
                        ),
                    );
                return Ok(admin_token);
            }.await.context("Error setting up admin endpoint");
            self.admin = Some(res.clone());
            return res;
        }

        async fn setup_identity(&mut self) -> Result<Arc<Mutex<dyn IdentitySigner>>, loga::Error> {
            if let Some(x) = self.identity.as_ref() {
                return x.clone();
            };
            let res = async {
                let Some(identity_secret) = &self.config.identity else {
                    return Err(loga::err("No identity supplied in config - please create an identity first"));
                };
                let identity_signer =
                    get_identity_signer(identity_secret.clone()).await.context("Error loading identity")?;
                return Ok(identity_signer) as Result<_, loga::Error>;
            }.await.context("Error setting up self identity");
            self.identity = Some(res.clone());
            return res;
        }

        async fn setup_publisher(&mut self) -> Result<(SocketAddr, Arc<Publisher>), loga::Error> {
            if let Some(x) = self.publisher.as_ref() {
                return x.clone();
            };
            let res = async {
                let log =
                    &self
                        .log
                        .fork_with_log_from(
                            debug_level(&self.debug_flags, DebugFlag::Publish),
                            ea!(sys = "publisher"),
                        );
                let bind_addr =
                    self
                        .config
                        .publisher
                        .bind_addr
                        .clone()
                        .unwrap_or_else(
                            || StrSocketAddr::from(
                                SocketAddr::V6(
                                    SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, DEFAULT_PUBLISHER_PORT, 0, 0),
                                ),
                            ),
                        )
                        .resolve()
                        .context("Error resolving publisher bind address")?;
                let advertise_ip =
                    *self
                        .global_ips
                        .get(0)
                        .context("Running a publisher requires at least one configured global IP")?;
                let advertise_port = self.config.publisher.advertise_port.unwrap_or(bind_addr.port());
                let advertise_addr = SocketAddr::new(advertise_ip, advertise_port);
                let publisher1 =
                    Publisher::new(
                        log,
                        &self.tm,
                        self.node.clone(),
                        bind_addr,
                        advertise_addr,
                        &self.config.persistent_dir,
                    ).await?;
                return Ok((advertise_addr, publisher1)) as Result<_, loga::Error>;
            }.await.context("Error setting up publisher service");
            self.publisher = Some(res.clone());
            return res;
        }

        async fn setup_resolver(&mut self) -> Result<Arc<Resolver>, loga::Error> {
            if let Some(res) = self.resolver.as_ref() {
                return res.clone();
            }
            let res = async {
                let log =
                    self
                        .log
                        .fork_with_log_from(
                            debug_level(&self.debug_flags, DebugFlag::Resolve),
                            ea!(sys = "resolver"),
                        );
                let publisher;
                if self.config.enable_external_publish || self.config.enable_self_publish_ip ||
                    self.config.enable_self_publish_ssh_key.is_some() ||
                    self.config.enable_self_publish_tls {
                    publisher = Some(self.setup_publisher().await?.1);
                } else {
                    publisher = None;
                }
                let resolver =
                    Arc::new(
                        Resolver::new(
                            &log,
                            &self.tm,
                            self.node.clone(),
                            self.config.resolver.max_cache,
                            &self.config.cache_dir,
                            publisher,
                            self.global_ips.clone(),
                        ).await?,
                    );
                return Ok(resolver) as Result<_, loga::Error>;
            }.await.context("Error setting up resolver");
            self.resolver = Some(res.clone());
            return res;
        }

        async fn setup_tls(&mut self) -> Result<Option<watch::Receiver<RefreshTlsState>>, loga::Error> {
            if let Some(res) = self.tls.as_ref() {
                return res.clone();
            }
            let res = async {
                let log =
                    self
                        .log
                        .fork_with_log_from(
                            debug_level(&self.debug_flags, DebugFlag::SelfTls),
                            ea!(sys = "tls_refresh"),
                        );
                let identity = self.setup_identity().await?;
                return Ok(
                    self_tls::stream_persistent_certs(
                        &log,
                        &self.tm,
                        &self.config.cache_dir,
                        &identity,
                        RequestCertOptions {
                            certifier: !self.config.tls.no_certifier,
                            signature: true,
                        },
                    ).await?,
                ) as Result<_, loga::Error>;
            }.await.context("Error setting up the tls certificate stream");
            self.tls = Some(res.clone());
            return res;
        }

        async fn setup_htserve_tls(
            &mut self,
        ) -> Result<
            Option<(Arc<dyn ResolvesServerCert>, Arc<dyn rustls_21::server::ResolvesServerCert>)>,
            loga::Error,
        > {
            if let Some(res) = self.htserve_tls.as_ref() {
                return res.clone();
            }
            let res = async {
                let log =
                    self
                        .log
                        .fork_with_log_from(
                            debug_level(&self.debug_flags, DebugFlag::SelfTls),
                            ea!(sys = "htserve_tls_refresh"),
                        );
                let Some(certs) = self.setup_tls().await? else {
                    return Ok(None);
                };
                return Ok(self_tls::stream_htserve_certs(&log, &self.tm, WatchStream::new(certs)).await?) as
                    Result<_, loga::Error>;
            }.await.context("Error setting up tls certs for http endpoints");
            self.htserve_tls = Some(res.clone());
            return res;
        }
    }

    let mut setup_state = SetupState {
        tm: tm,
        config: config,
        node: node,
        log: log.clone(),
        global_ips: global_ips,
        publisher: Default::default(),
        resolver: Default::default(),
        api_routes: Default::default(),
        self_publish: Default::default(),
        admin: Default::default(),
        tls: Default::default(),
        htserve_tls: Default::default(),
        identity: Default::default(),
        debug_flags: debug_flags,
    };

    // # Set up REST API admin routes
    if setup_state.config.enable_admin.is_some() {
        setup_state.setup_admin().await?;
    }

    // # Set up REST API external publishing route
    if setup_state.config.enable_external_publish {
        async {
            ta_return!((), loga::Error);
            let admin_token = setup_state.setup_admin().await?;
            let publisher = setup_state.setup_publisher().await?.1;
            let log =
                log.fork_with_log_from(
                    debug_level(&setup_state.debug_flags, DebugFlag::Publish),
                    ea!(sys = "external_publish"),
                );
            setup_state
                .api_routes
                .insert(
                    format!("/{}", API_ROUTE_PUBLISH),
                    Box::new(
                        publisher::build_api_publish_external_endpoints(
                            &log,
                            &publisher,
                            &admin_token,
                            &setup_state.config.persistent_dir,
                        ).await?,
                    ),
                );
            return Ok(()) as Result<_, loga::Error>;
        }.await.context("Error setting up external publishing")?;
    }

    // # Prep to publish ip
    if setup_state.config.enable_self_publish_ip {
        for ip in &setup_state.global_ips {
            add_ip_record(&mut setup_state.self_publish, vec![], 5, *ip);
        }
    }

    // # Prep to publish ssh host keys
    if let Some(publish_ssh_config) = &setup_state.config.enable_self_publish_ssh_key {
        add_ssh_host_key_records(&mut setup_state.self_publish, vec![], 1, &publish_ssh_config.ssh_host_keys).await?;
    }

    // # Publish dynamic tls certs
    if setup_state.config.enable_self_publish_tls {
        async {
            ta_return!((), loga::Error);
            let Some(tls_stream) = setup_state.setup_tls().await? else {
                return Ok(());
            };
            let publisher = setup_state.setup_publisher().await?.1;
            let identity = setup_state.setup_identity().await?;
            let log =
                setup_state
                    .log
                    .fork_with_log_from(
                        debug_level(&setup_state.debug_flags, DebugFlag::SelfTls),
                        ea!(sys = "self_publish_tls"),
                    );
            setup_state.tm.stream("Self-publish TLS certs", WatchStream::new(tls_stream), move |current| {
                let publisher = publisher.clone();
                let log = log.clone();
                let identity = identity.clone();
                async move {
                    if let Err(e) =
                        publish_tls_certs(
                            &log,
                            &(publisher as Arc<dyn publishing::Publisher>),
                            &identity,
                            &current,
                        ).await {
                        log.log_err(loga::WARN, e.context("Error publishing self tls cert record"));
                    }
                }
            });
            return Ok(());
        }.await.context("Error self-publishing tls cert records")?;
    }

    // # Write TLS certs to disk
    if let Some(write_tls_config) = setup_state.config.enable_write_tls.clone() {
        async {
            ta_return!((), loga::Error);
            let Some(tls_stream) = setup_state.setup_tls().await? else {
                return Ok(());
            };
            let log =
                setup_state
                    .log
                    .fork_with_log_from(
                        debug_level(&setup_state.debug_flags, DebugFlag::SelfTls),
                        ea!(sys = "dir_write_tls"),
                    );
            setup_state.tm.stream("Write TLS certs", WatchStream::new(tls_stream), move |current| {
                let log = log.clone();
                let write_tls_config = write_tls_config.clone();
                async move {
                    match async {
                        write(write_tls_config.write_certs_dir.join("pub.pem"), current.current.pub_pem.as_bytes())
                            .await
                            .context("Error writing new pub.pem")?;
                        write(write_tls_config.write_certs_dir.join("priv.pem"), current.current.priv_pem.as_bytes())
                            .await
                            .context("Error writing new priv.pem")?;
                        return Ok(()) as Result<_, loga::Error>;
                    }.await {
                        Ok(_) => { },
                        Err(e) => {
                            log.log_err(
                                loga::WARN,
                                e.context_with(
                                    "Error writing new TLS certs to disk",
                                    ea!(path = write_tls_config.write_certs_dir.dbg_str()),
                                ),
                            );
                        },
                    }
                }
            });
            return Ok(());
        }.await.context("Error setting up `enable_write_tls`")?;
    }

    // # Setup REST resolver
    if setup_state.config.enable_resolver_rest {
        async {
            ta_return!((), loga::Error);
            let resolver = setup_state.setup_resolver().await?;
            let log =
                log.fork_with_log_from(
                    debug_level(&setup_state.debug_flags, DebugFlag::Resolve),
                    ea!(sys = "resolver_rest"),
                );
            setup_state
                .api_routes
                .insert(format!("/{}", API_ROUTE_RESOLVE), Box::new(resolver::build_api_endpoints(log, &resolver)));
            return Ok(());
        }.await.context("Error setting up `enable_resolver_rest`")?;
    }

    // # Setup DNS resolver
    if let Some(dns_config) = setup_state.config.enable_resolver_dns.clone() {
        async {
            ta_return!((), loga::Error);
            let resolver = setup_state.setup_resolver().await?;
            let Some((_, r21_certs)) = setup_state.setup_htserve_tls().await? else {
                return Ok(());
            };
            let log =
                log.fork_with_log_from(
                    debug_level(&setup_state.debug_flags, DebugFlag::Dns),
                    ea!(sys = "resolver_dns"),
                );
            resolver::dns::start_dns_bridge(
                &log,
                &setup_state.tm,
                &resolver,
                r21_certs,
                &setup_state.global_ips,
                dns_config,
            ).await?;
            return Ok(());
        }.await.context("Error setting up `enable_resolver_dns`")?;
    }

    // # Start serving content
    if !setup_state.config.enable_serve_content.is_empty() {
        async {
            ta_return!((), loga::Error);
            let log =
                log.fork_with_log_from(
                    debug_level(&setup_state.debug_flags, DebugFlag::Content),
                    ea!(sys = "content"),
                );
            let Some((certs, _)) = setup_state.setup_htserve_tls().await? else {
                return Ok(());
            };
            start_serving_content(
                &log,
                &setup_state.tm,
                certs,
                setup_state.config.enable_serve_content.drain().collect::<HashMap<_, _>>(),
            ).await?;
            return Ok(());
        }.await.context("Error setting up `enable_serve_content`")?;
    }

    // # Self-publish fixed records
    if !setup_state.self_publish.is_empty() {
        async {
            ta_return!((), loga::Error);
            let (advertise_addr, publisher) = setup_state.setup_publisher().await?;
            let identity = setup_state.setup_identity().await?;
            let (identity, announcement) = generate_publish_announce(&identity, vec![InfoResponse {
                advertise_addr: advertise_addr,
                cert_pub_hash: publisher.pub_cert_hash(),
            }]).map_err(|e| loga::err_with("Failed to generate announcement for self publication", ea!(err = e)))?;
            publisher.announce(&identity, announcement).await?;
            publisher.modify_values(&identity, PublishArgs {
                clear_all: true,
                set: setup_state.self_publish.drain().collect::<HashMap<_, _>>(),
                ..Default::default()
            }).await?;
            return Ok(());
        }.await.context("Error self-publishing initial records")?;
    }

    // # Rest API
    if !setup_state.api_routes.is_empty() {
        let log =
            log.fork_with_log_from(debug_level(&setup_state.debug_flags, DebugFlag::Api), ea!(sys = "api_http"));
        let mut router = htserve::handler::PathRouter::default();
        router.insert("/health", Box::new(htwrap::handler!(()(_r -> htserve:: responses:: Body) {
            return response_200();
        }))).unwrap();
        let router = Arc::new(router);
        let mut api_bind_addrs = setup_state.config.api.bind_addrs.clone();
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
            let bind_addr = bind_addr.resolve().context("Error resolving api bind address")?;
            let log = log.clone();
            let routes = router.clone();
            let Some((certs, _)) = setup_state.setup_htserve_tls().await.context("Error setting up API")? else {
                return Ok(());
            };
            let tls_acceptor = tls_acceptor(certs.clone());
            setup_state
                .tm
                .stream(
                    format!("API - Server ({})", bind_addr),
                    tokio_stream::wrappers::TcpListenerStream::new(
                        tokio::net::TcpListener::bind(&bind_addr).await.context("Error binding to address for api")?,
                    ),
                    move |stream| {
                        let log = log.clone();
                        let tls_acceptor = tls_acceptor.clone();
                        let routes = routes.clone();
                        async move {
                            match async {
                                ta_res!(());
                                htserve::handler::root_handle_https(&log, tls_acceptor, routes, stream?).await?;
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

    // Done
    let tm = setup_state.tm.clone();
    drop(setup_state);
    tm.join(log).await.context("Critical services failed")?;
    return Ok(());
}
