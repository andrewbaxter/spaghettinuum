use {
    crate::{
        cap_fn,
        interface::{
            stored::{
                self,
                announcement::Announcement,
                identity::Identity,
            },
            wire::{
                self,
                api::admin::v1::{
                    AdminAllowIdentityBody,
                    AdminIdentity,
                },
            },
        },
        service::node::Node,
        ta_res,
        ta_vis_res,
        utils::{
            blob::{
                Blob,
                ToBlob,
            },
            db_util::{
                setup_db,
                DbTx,
            },
            identity_secret::IdentitySigner,
            signed::IdentSignatureMethods,
            tls_util::{
                cert_der_hash,
                create_leaf_cert_der_local,
            },
            ResultVisErr,
            VisErr,
        },
    },
    async_trait::async_trait,
    chrono::{
        DateTime,
        Duration,
        NaiveDate,
        NaiveDateTime,
        Utc,
    },
    deadpool_sqlite::Pool,
    good_ormning_runtime::GoodError,
    http::{
        Method,
        Response,
    },
    http_body_util::BodyExt,
    htwrap::htserve::{
        self,
        check_auth_token_hash,
        response_200,
        response_200_json,
        response_400,
        response_401,
        response_404,
        response_503,
        AuthTokenHash,
    },
    loga::{
        ea,
        Log,
        ResultContext,
    },
    p256::pkcs8::EncodePrivateKey,
    rustls::pki_types::{
        CertificateDer,
        PrivateKeyDer,
        PrivatePkcs8KeyDer,
    },
    serde::Deserialize,
    std::{
        collections::HashMap,
        net::SocketAddr,
        path::Path,
        sync::{
            Arc,
            Mutex,
            RwLock,
        },
    },
    taskmanager::TaskManager,
};

pub mod db;
pub mod admin_db;

pub struct SingleCertResolver(pub Arc<RwLock<Arc<rustls::sign::CertifiedKey>>>);

impl std::fmt::Debug for SingleCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SingleCertResolver").field(&self.0.read().unwrap()).finish()
    }
}

impl rustls::server::ResolvesServerCert for SingleCertResolver {
    fn resolve(&self, _client_hello: rustls::server::ClientHello) -> Option<Arc<rustls::sign::CertifiedKey>> {
        return Some(self.0.read().unwrap().clone());
    }
}

/// A publisher is basically an http server that responds to resolver queries with
/// record values.
pub struct Publisher {
    log: Log,
    node: Node,
    cert_pub_hash: Blob,
    advertise_addr: SocketAddr,
    db_pool: Pool,
}

impl Publisher {
    /// Launch a new dynamic publisher in task manager.
    ///
    /// * `advertise_addr`: The address to use in announcements to the network. This should
    ///   be the internet-routable address of this instance (your public ip, plus the port
    ///   you're forwarding to the host)
    pub async fn new(
        log: &Log,
        tm: &TaskManager,
        node: Node,
        bind_addr: SocketAddr,
        advertise_addr: SocketAddr,
        persistent_dir: &Path,
    ) -> Result<Arc<Publisher>, loga::Error> {
        let db_pool =
            setup_db(&persistent_dir.join("publisher.sqlite3"), db::migrate)
                .await
                .stack_context(log, "Error initializing database")?;

        // Prepare publisher certs for publisher-resolver communication
        let certs = {
            match db_pool
                .tx(|conn| Ok(db::get_certs(conn)?))
                .await
                .stack_context(log, "Error looking up certs")? {
                Some(c) => match c {
                    stored::publisher::Certs::V1(v1) => {
                        v1
                    },
                },
                None => {
                    let priv_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
                    let pub_cert_der =
                        create_leaf_cert_der_local(
                            priv_key.clone(),
                            "unused",
                            DateTime::UNIX_EPOCH,
                            NaiveDateTime::from(NaiveDate::from_ymd_opt(9999, 12, 31).unwrap()).and_utc(),
                            None,
                            "unused",
                        ).await?;
                    let certs = stored::publisher::latest::Certs {
                        pub_der: pub_cert_der,
                        priv_der: priv_key.to_pkcs8_der().unwrap().as_bytes().blob(),
                    };
                    db_pool.tx({
                        let certs = certs.clone();
                        move |conn| Ok(db::ensure_certs(conn, &stored::publisher::Certs::V1(certs.clone()))?)
                    }).await.stack_context(log, "Error persisting generated certs")?;
                    certs
                },
            }
        };
        let publisher = Arc::new(Publisher {
            node: node.clone(),
            log: log.clone(),
            cert_pub_hash: cert_der_hash(&certs.pub_der).unwrap(),
            advertise_addr: advertise_addr,
            db_pool: db_pool,
        });
        tm.stream(
            "Publisher - network server",
            tokio_stream::wrappers::TcpListenerStream::new(
                tokio::net::TcpListener::bind(bind_addr).await.stack_context(&log, "Error binding to address")?,
            ),
            {
                let log = log.fork(ea!(subsys = "protocol"));
                let handler = {
                    let log = log.clone();
                    let publisher = publisher.clone();
                    Arc::new(htwrap::handler!((publisher: Arc < Publisher >, log: Log)(r -> htserve:: Body) {
                        match async {
                            ta_vis_res!(Response < htserve:: Body >);
                            log.log_with(loga::DEBUG, "Recieved request", ea!(path = r.head.uri));
                            let Some(ident) = r.subpath.strip_prefix("/") else {
                                return Ok(response_400("Missing identity in path"));
                            };
                            let ident =
                                Identity::from_str(&ident).context("Couldn't parse identity").err_external()?;
                            let mut keys = vec![];
                            for raw_key in r.query.split(",") {
                                keys.push(
                                    urlencoding::decode(raw_key)
                                        .map(|x| x.to_string())
                                        .unwrap_or_else(|_| raw_key.to_string()),
                                );
                            }
                            return Ok(response_200_json(publisher.get_values(&ident, keys).await.err_internal()?));
                        }.await {
                            Ok(r) => return r,
                            Err(VisErr::Internal(e)) => {
                                log.log_err(loga::WARN, e.context("Error processing request"));
                                return response_503();
                            },
                            Err(VisErr::External(e)) => {
                                return response_400(e);
                            },
                        }
                    }))
                };
                let tls_acceptor = {
                    let mut server_config =
                        rustls::ServerConfig::builder()
                            .with_no_client_auth()
                            .with_single_cert(
                                vec![CertificateDer::from(certs.pub_der.clone().to_vec())],
                                PrivateKeyDer::from(PrivatePkcs8KeyDer::from(certs.priv_der.clone().to_vec())),
                            )
                            .context("Error setting up tls listener")?;
                    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
                    tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
                };
                move |stream| {
                    let log = log.clone();
                    let tls_acceptor = tls_acceptor.clone();
                    let handler = handler.clone();
                    async move {
                        match async {
                            ta_res!(());
                            htserve::root_handle_https(&log, tls_acceptor, handler, stream?).await?;
                            return Ok(());
                        }.await {
                            Ok(_) => { },
                            Err(e) => {
                                log.log_err(loga::DEBUG, e.context("Error handling request"));
                            },
                        }
                    }
                }
            },
        );
        tm.periodic("Publisher - periodic announce", Duration::try_hours(4).unwrap().to_std().unwrap(), {
            let log = log.fork(ea!(subsys = "periodic_announce"));
            cap_fn!(()(log, publisher, node) {
                match async {
                    ta_res!(());
                    let mut after = None;
                    loop {
                        let announce_pairs = publisher.list_announcements(after.as_ref()).await?;
                        let count = announce_pairs.len();
                        if count == 0 {
                            break;
                        }
                        for (i, (identity, announcement)) in announce_pairs.into_iter().enumerate() {
                            let accepted = node.put(identity.clone(), announcement.clone()).await;
                            if let Some(accepted) = accepted {
                                match accepted {
                                    Announcement::V1(accepted) => {
                                        let have_announced = match &announcement {
                                            Announcement::V1(a) => a.parse_unwrap().announced,
                                        };
                                        if accepted.parse_unwrap().announced > have_announced {
                                            // Newer announcement elsewhere, delete this announcement to save some network
                                            // effort
                                            publisher.clear_identity(&identity).await.log(&log, loga::WARN, "Error deleting obsolete announcement");
                                        }
                                    },
                                }
                            }
                            if i + 1 == count {
                                after = Some(identity);
                            }
                        }
                    }
                    return Ok(());
                }.await {
                    Ok(_) => { },
                    Err(e) => {
                        log.log_err(loga::WARN, e.context("Error while re-announcing publishers"));
                    },
                }
            })
        });
        return Ok(publisher);
    }

    pub fn pub_cert_hash(&self) -> Blob {
        return self.cert_pub_hash.clone();
    }

    pub async fn announce(
        &self,
        identity: &Identity,
        announcement: stored::announcement::Announcement,
    ) -> Result<(), loga::Error> {
        let accepted = self.node.put(identity.clone(), announcement.clone()).await;
        match accepted {
            Some(accepted) => {
                let new_published = match &announcement {
                    Announcement::V1(a) => a.parse_unwrap().announced,
                };
                let accepted_published = match accepted {
                    Announcement::V1(a) => a.parse_unwrap().announced,
                };
                if accepted_published > new_published {
                    return Ok(());
                }
            },
            None => (),
        }
        self.db_pool.tx({
            let identity = identity.clone();
            let announcement = announcement.clone();
            move |db| Ok(db::set_announce(db, &identity, &announcement)?)
        }).await?;
        return Ok(())
    }

    pub async fn clear_identity(&self, identity: &Identity) -> Result<(), loga::Error> {
        self.db_pool.tx({
            let identity = identity.clone();
            move |db| {
                db::delete_announce(db, &identity)?;
                db::values_delete_all(db, &identity)?;
                return Ok(());
            }
        }).await?;
        return Ok(());
    }

    pub async fn list_announcements(
        &self,
        after: Option<&Identity>,
    ) -> Result<Vec<(Identity, Announcement)>, loga::Error> {
        let after = after.cloned();
        return Ok(match after {
            None => {
                let res =
                    self
                        .db_pool
                        .tx(move |db| Ok(db::list_announce_start(db)?))
                        .await?
                        .into_iter()
                        .map(|p| (p.identity, p.value))
                        .collect();
                res
            },
            Some(a) => {
                self
                    .db_pool
                    .tx(move |db| Ok(db::list_announce_after(db, &a)?))
                    .await?
                    .into_iter()
                    .map(|p| (p.identity, p.value))
                    .collect()
            },
        });
    }

    pub async fn modify_values(
        &self,
        identity: &Identity,
        args: wire::api::publish::latest::PublishRequestContent,
    ) -> Result<(), loga::Error> {
        self.db_pool.tx({
            let identity = identity.clone();
            move |db| {
                if let Some(missing_ttl) = args.missing_ttl {
                    db::ident_set(db, &identity, missing_ttl as i64)?;
                }
                if args.clear_all {
                    db::values_delete_all(db, &identity)?;
                }
                for k in args.clear {
                    db::values_delete(db, &identity, &k)?;
                }
                for (k, v) in args.set {
                    db::values_set(db, &identity, &k, &v)?;
                }
                return Ok(());
            }
        }).await?;
        return Ok(());
    }

    pub async fn get_values(
        &self,
        identity: &Identity,
        keys: Vec<String>,
    ) -> Result<wire::resolve::ResolveKeyValues, loga::Error> {
        let identity = identity.clone();
        return Ok(self.db_pool.tx(move |db| {
            let mut out = HashMap::new();
            let missing_ttl = db::ident_get(db, &identity)?.unwrap_or_else(|| 5);
            let now = Utc::now();
            for k in keys {
                let expires;
                let data;
                match db::values_get(db, &identity, &k)? {
                    Some(v) => match v {
                        stored::record::RecordValue::V1(v) => {
                            expires = now + Duration::try_minutes(v.ttl as i64).context("TTL out of range")?;
                            data = v.data;
                        },
                    },
                    None => {
                        expires =
                            now + Duration::try_minutes(missing_ttl as i64).context("Missing-TTL out of range")?;
                        data = None;
                    },
                }
                out.insert(k, wire::resolve::v1::ResolveValue {
                    expires: expires,
                    data: data,
                });
            }
            return Ok(wire::resolve::ResolveKeyValues::V1(out));
        }).await?);
    }

    pub async fn list_value_keys(
        &self,
        identity: &Identity,
        after: Option<String>,
    ) -> Result<Vec<String>, loga::Error> {
        let identity = identity.clone();
        return Ok(self.db_pool.tx(move |conn| match after {
            Some(v) => {
                return Ok(db::values_keys_list_after(conn, &identity, &v)?);
            },
            None => {
                return Ok(db::values_keys_list_start(conn, &identity)?);
            },
        }).await?);
    }
}

#[async_trait]
impl crate::publishing::Publisher for Publisher {
    async fn publish(
        &self,
        _log: &Log,
        identity_signer: &Arc<Mutex<dyn IdentitySigner>>,
        content: wire::api::publish::latest::PublishRequestContent,
    ) -> Result<(), loga::Error> {
        let identity = identity_signer.lock().unwrap().identity()?;
        self.modify_values(&identity, content).await?;
        return Ok(());
    }
}

#[async_trait]
pub trait PublisherAuthorizer: Sync + Send {
    async fn is_identity_allowed(&self, identity: &Identity) -> Result<bool, loga::Error>;
}

pub async fn build_api_endpoints_with_authorizer(
    log: &Log,
    publisher: &Arc<Publisher>,
    authorizer: Arc<dyn PublisherAuthorizer>,
) -> Result<htserve::PathRouter<htserve::Body>, loga::Error> {
    struct State {
        log: Log,
        publisher: Arc<Publisher>,
        authorizer: Arc<dyn PublisherAuthorizer>,
    }

    let state = Arc::new(State {
        log: log.clone(),
        publisher: publisher.clone(),
        authorizer: authorizer,
    });
    let mut routes = htserve::PathRouter::default();
    routes.insert("/v1", {
        let mut routes = htserve::PathRouter::default();
        routes.insert("/announce", {
            let state = state.clone();
            Box::new(htwrap::handler!((state: Arc < State >)(r -> htserve:: Body) {
                match async {
                    ta_res!(Response < htserve:: Body >);

                    // Params
                    let req =
                        match serde_json::from_slice::<wire::api::publish::v1::AnnounceRequest>(
                            &r.body.collect().await?.to_bytes(),
                        ) {
                            Ok(r) => r,
                            Err(e) => {
                                return Ok(response_400(format!("Invalid json: {}", e))) as Result<_, loga::Error>;
                            },
                        };
                    match &req.announcement {
                        Announcement::V1(a) => {
                            let Ok(_) = a.verify(&req.identity) else {
                                return Ok(response_400("Couldn't verify payload"));
                            };
                        },
                    };

                    // Auth
                    if !state.authorizer.is_identity_allowed(&req.identity).await? {
                        return Ok(response_401());
                    }

                    // Publish it
                    state.publisher.announce(&req.identity, req.announcement).await?;
                    return Ok(response_200());
                }.await {
                    Ok(r) => {
                        return r;
                    },
                    Err(e) => {
                        state.log.log_err(loga::WARN, e.context("Error publishing key values"));
                        return response_503();
                    },
                }
            }))
        });
        routes.insert("/clear_identity", {
            let state = state.clone();
            Box::new(htwrap::handler!((state: Arc < State >)(r -> htserve:: Body) {
                match async {
                    ta_res!(Response < htserve:: Body >);

                    // Params
                    let req =
                        match serde_json::from_slice::<wire::api::publish::v1::DeleteAnnouncementRequest>(
                            &r.body.collect().await?.to_bytes(),
                        ) {
                            Ok(r) => r,
                            Err(e) => {
                                return Ok(response_400(format!("Invalid json: {}", e))) as Result<_, loga::Error>;
                            },
                        };
                    let Ok(_) = req.challenge.verify(&req.identity) else {
                        return Ok(response_400("Couldn't verify payload"));
                    };

                    // Auth
                    if !state.authorizer.is_identity_allowed(&req.identity).await? {
                        return Ok(response_401());
                    }

                    // Respond
                    state.publisher.clear_identity(&req.identity).await?;
                    return Ok(response_200());
                }.await {
                    Ok(r) => {
                        return r;
                    },
                    Err(e) => {
                        state.log.log_err(loga::WARN, e.context("Error unpublishing key values"));
                        return response_503();
                    },
                }
            }))
        });
        routes.insert("/publish", {
            let state = state.clone();
            Box::new(htwrap::handler!((state: Arc < State >)(r -> htserve:: Body) {
                match async {
                    ta_res!(Response < htserve:: Body >);

                    // Params
                    let req =
                        match serde_json::from_slice::<wire::api::publish::v1::PublishRequest>(
                            &r.body.collect().await?.to_bytes(),
                        ) {
                            Ok(r) => r,
                            Err(e) => {
                                return Ok(response_400(format!("Invalid json: {}", e))) as Result<_, loga::Error>;
                            },
                        };
                    let Ok(body) = req.content.verify(&req.identity) else {
                        return Ok(response_400("Couldn't verify payload"));
                    };

                    // Auth
                    if !state.authorizer.is_identity_allowed(&req.identity).await? {
                        return Ok(response_401());
                    }

                    // Publish it
                    state.publisher.modify_values(&req.identity, body).await?;
                    return Ok(response_200());
                }.await {
                    Ok(r) => {
                        return r;
                    },
                    Err(e) => {
                        state.log.log_err(loga::WARN, e.context("Error publishing key values"));
                        return response_503();
                    },
                }
            }))
        });
        routes.insert("/info", {
            let state = state.clone();
            Box::new(htwrap::handler!((state: Arc < State >)(_r -> htserve:: Body) {
                return response_200_json(wire::api::publish::v1::InfoResponse {
                    advertise_addr: state.publisher.advertise_addr,
                    cert_pub_hash: state.publisher.cert_pub_hash.clone(),
                });
            }))
        });
        Box::new(routes)
    });
    return Ok(routes);
}

pub async fn build_api_endpoints(
    log: &Log,
    publisher: &Arc<Publisher>,
    admin_token: &AuthTokenHash,
    persist_dir: &Path,
) -> Result<htserve::PathRouter<htserve::Body>, loga::Error> {
    let db_pool =
        setup_db(&persist_dir.join("publisher_admin.sqlite3"), admin_db::migrate)
            .await
            .context("Error initializing database")?;

    struct State {
        log: Log,
        db_pool: Pool,
        publisher: Arc<Publisher>,
    }

    impl State {
        async fn allow_identity(&self, identity: &Identity, group: String) -> Result<(), loga::Error> {
            let identity = identity.clone();
            self.db_pool.get().await?.interact(move |db| {
                admin_db::allow_identity(db, &identity, &group)?;
                return Ok(()) as Result<(), GoodError>;
            }).await??;
            return Ok(());
        }

        async fn disallow_identity(&self, identity: &Identity) -> Result<(), loga::Error> {
            let identity = identity.clone();
            self.db_pool.get().await?.interact(move |db| {
                admin_db::disallow_identity(db, &identity)?;
                return Ok(()) as Result<(), GoodError>;
            }).await??;
            return Ok(());
        }

        async fn list_allowed_identities(
            &self,
            after: Option<&Identity>,
        ) -> Result<Vec<AdminIdentity>, loga::Error> {
            let after = after.cloned();
            return Ok(match after {
                None => {
                    self.db_pool.get().await?.interact(|db| admin_db::list_allowed_identities_start(db)).await??
                },
                Some(a) => {
                    self
                        .db_pool
                        .get()
                        .await?
                        .interact(move |db| admin_db::list_allowed_identities_after(db, &a))
                        .await??
                },
            }.into_iter().map(|r| AdminIdentity {
                identity: r.identity,
                group: r.group,
            }).collect());
        }
    }

    #[async_trait]
    impl PublisherAuthorizer for State {
        async fn is_identity_allowed(&self, identity: &Identity) -> Result<bool, loga::Error> {
            let identity = identity.clone();
            return Ok(self.db_pool.get().await?.interact(move |db| {
                return Ok(admin_db::is_identity_allowed(db, &identity)?.is_some()) as Result<bool, GoodError>;
            }).await??);
        }
    }

    let state = Arc::new(State {
        log: log.clone(),
        db_pool: db_pool,
        publisher: publisher.clone(),
    });
    let mut routes = build_api_endpoints_with_authorizer(log, publisher, state.clone()).await?;
    let admin_token = admin_token.clone();
    routes.insert("/admin", {
        let mut routes = htserve::PathRouter::default();
        routes.insert("/allowed_identities", {
            let state = state.clone();
            let admin_token = admin_token.clone();
            Box::new(htwrap::handler!((state: Arc < State >, admin_token: AuthTokenHash)(r -> htserve:: Body) {
                match async {
                    ta_vis_res!(Response < htserve:: Body >);
                    if !check_auth_token_hash(
                        &admin_token,
                        &htserve::get_auth_token(&r.head.headers).err_external()?,
                    ) {
                        return Ok(response_401());
                    }
                    match r.head.method {
                        Method::GET => {
                            #[derive(Debug, Deserialize)]
                            struct Params {
                                after: Option<String>,
                            }

                            let query = match serde_urlencoded::from_str::<Params>(&r.query) {
                                Ok(q) => q,
                                Err(e) => {
                                    return Ok(response_400(format!("Invalid query parameters: {}", e)));
                                },
                            };
                            let after = match &query.after {
                                Some(i) => {
                                    Some(Identity::from_str(i).err_external()?)
                                },
                                None => None,
                            };
                            return Ok(
                                response_200_json(
                                    state.list_allowed_identities(after.as_ref()).await.err_internal()?,
                                ),
                            );
                        },
                        Method::POST => {
                            let Some(identity) = r.subpath.strip_prefix("/") else {
                                return Ok(response_400("Missing identity in path"));
                            };
                            let identity = Identity::from_str(&identity).err_external()?;
                            let body =
                                serde_json::from_slice::<AdminAllowIdentityBody>(
                                    &r.body.collect().await.err_external()?.to_bytes(),
                                )
                                    .context("Bad request body")
                                    .err_external()?;
                            return Ok(
                                response_200_json(state.allow_identity(&identity, body.group).await.err_internal()?),
                            );
                        },
                        Method::DELETE => {
                            let Some(identity) = r.subpath.strip_prefix("/") else {
                                return Ok(response_400("Missing identity in path"));
                            };
                            let identity = Identity::from_str(&identity).err_external()?;
                            state.disallow_identity(&identity).await.err_internal()?;
                            state.publisher.clear_identity(&identity).await.err_internal()?;
                            return Ok(response_200());
                        },
                        _ => return Ok(response_404()),
                    }
                }.await {
                    Ok(d) => {
                        return d;
                    },
                    Err(e) => match e {
                        VisErr::Internal(e) => {
                            state.log.log_err(loga::WARN, e.context("Error getting published identities"));
                            return response_503();
                        },
                        VisErr::External(e) => {
                            return response_400(e);
                        },
                    },
                }
            }))
        });
        routes.insert("/keys", {
            let state = state.clone();
            let admin_token = admin_token.clone();
            Box::new(htwrap::handler!((state: Arc < State >, admin_token: AuthTokenHash)(r -> htserve:: Body) {
                match async {
                    ta_res!(Response < htserve:: Body >);
                    if !check_auth_token_hash(&admin_token, &htserve::get_auth_token(&r.head.headers)?) {
                        return Ok(response_401());
                    }
                    let Some(identity) = r.subpath.strip_prefix("/") else {
                        return Ok(response_400("Missing identity in path"));
                    };
                    let identity = Identity::from_str(&identity)?;

                    #[derive(Debug, Deserialize)]
                    struct Params {
                        after: Option<String>,
                    }

                    let query = match serde_urlencoded::from_str::<Params>(&r.query) {
                        Ok(q) => q,
                        Err(e) => {
                            return Ok(response_400(format!("Invalid query parameters: {}", e)));
                        },
                    };

                    // Respond
                    return Ok(response_200_json(state.publisher.list_value_keys(&identity, query.after).await?));
                }.await {
                    Ok(d) => {
                        return d;
                    },
                    Err(e) => {
                        state
                            .publisher
                            .log
                            .log_err(loga::WARN, e.context("Error getting published keys for identity"));
                        return response_503();
                    },
                }
            }))
        });
        routes.insert("/announcements", {
            let state = state.clone();
            let admin_token = admin_token.clone();
            Box::new(htwrap::handler!((state: Arc < State >, admin_token: AuthTokenHash)(r -> htserve:: Body) {
                match async {
                    ta_res!(Response < htserve:: Body >);
                    if !check_auth_token_hash(&admin_token, &htserve::get_auth_token(&r.head.headers)?) {
                        return Ok(response_401());
                    }

                    #[derive(Debug, Deserialize)]
                    struct Params {
                        after: Option<String>,
                    }

                    let query = match serde_urlencoded::from_str::<Params>(&r.query) {
                        Ok(q) => q,
                        Err(e) => {
                            return Ok(response_400(format!("Invalid query parameters: {}", e)));
                        },
                    };
                    let after = match query.after {
                        Some(i) => {
                            Some(Identity::from_str(&i)?)
                        },
                        None => None,
                    };

                    // Respond
                    return Ok(
                        response_200_json(
                            state
                                .publisher
                                .list_announcements(after.as_ref())
                                .await?
                                .into_iter()
                                .map(|e| e.0)
                                .collect::<Vec<_>>(),
                        ),
                    );
                }.await {
                    Ok(d) => {
                        return d;
                    },
                    Err(e) => {
                        state.log.log_err(loga::WARN, e.context("Error getting published identities"));
                        return response_503();
                    },
                }
            }))
        });
        Box::new(routes)
    });
    return Ok(routes);
}
