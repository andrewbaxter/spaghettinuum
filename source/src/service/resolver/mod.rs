use {
    crate::{
        interface::{
            stored::{
                self,
                identity::Identity,
                record::record_utils::{
                    join_record_key,
                    split_query_record_keys,
                    split_record_key,
                    RecordKey,
                },
            },
            wire::{
                self,
            },
        },
        service::{
            node::Node,
            publisher::Publisher,
        },
        ta_res,
        ta_vis_res,
        utils::{
            blob::Blob,
            db_util::setup_db,
            signed::IdentSignatureMethods,
            tls_util::cert_der_hash,
            ResultVisErr,
            VisErr,
        },
    },
    flowcontrol::shed,
    htwrap::{
        htreq::{
            self,
            Conn,
        },
        htserve::{
            self,
            responses::{
                response_200_json,
                response_400,
                response_503,
            },
        },
    },
    hyper::Uri,
    hyper_rustls::HttpsConnectorBuilder,
    loga::{
        ea,
        DebugDisplay,
        ErrContext,
        Log,
        ResultContext,
    },
    moka::future::Cache,
    rand::{
        seq::SliceRandom,
        thread_rng,
    },
    rustls::ClientConfig,
    std::{
        collections::HashMap,
        net::IpAddr,
        path::Path,
        str::FromStr,
        sync::Arc,
        time::{
            Duration,
            SystemTime,
        },
    },
    taskmanager::TaskManager,
    tokio::{
        select,
        spawn,
        time::sleep,
    },
    tower_service::Service,
};

pub mod db;
pub mod dns;

#[derive(Debug)]
pub struct SingleKeyVerifier {
    hash: Blob,
}

impl SingleKeyVerifier {
    pub fn new(hash: Blob) -> Arc<dyn rustls::client::danger::ServerCertVerifier> {
        return Arc::new(SingleKeyVerifier { hash });
    }
}

impl rustls::client::danger::ServerCertVerifier for SingleKeyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if cert_der_hash(
            end_entity.as_ref(),
        ).map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))? !=
            self.hash {
            return Err(rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding));
        }
        return Ok(rustls::client::danger::ServerCertVerified::assertion());
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        return Ok(rustls::client::danger::HandshakeSignatureValid::assertion());
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        return Ok(rustls::client::danger::HandshakeSignatureValid::assertion());
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        return vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448
        ];
    }
}

struct Resolver_ {
    node: Node,
    log: Log,
    cache: Cache<(Identity, RecordKey), (SystemTime, Option<String>)>,
    publisher: Option<Arc<Publisher>>,
    global_addrs: Vec<IpAddr>,
}

/// This is the core of the resolver; it does lookups using a local node. If you
/// don't have a local node, you can do lookups with a simple http client against a
/// remote resolver.
#[derive(Clone)]
pub struct Resolver(Arc<Resolver_>);

impl Resolver {
    /// Start a new resolver core in the task manager.
    ///
    /// * `max_cache`: The maximum data to store in the cache (bytes, roughly). Defaults to
    ///   about 64MiB.
    ///
    /// * `cache_path`: If a cache path is provided the cache will be persisted there when
    ///   shutting down, and initialized from that data when starting up.
    pub async fn new(
        log: &Log,
        tm: &TaskManager,
        node: Node,
        max_cache: Option<u64>,
        cache_dir: &Path,
        publisher: Option<Arc<Publisher>>,
        global_addrs: Vec<IpAddr>,
    ) -> Result<Resolver, loga::Error> {
        let db_pool =
            setup_db(&cache_dir.join("resolver.sqlite3"), db::migrate)
                .await
                .stack_context(log, "Error initializing database")?;
        let cache = Cache::builder().weigher(|_key, pair: &(SystemTime, Option<String>)| -> u32 {
            match &pair.1 {
                Some(v) => v.len().try_into().unwrap_or(u32::MAX),
                None => 1,
            }
        }).max_capacity(max_cache.unwrap_or(64 * 1024 * 1024)).build();

        // Seed with stored cache data
        {
            let log = &log.fork(ea!(subsys = "restore_cache"));
            let db_pool = db_pool.clone();
            match async {
                let mut edge = Some(i64::MAX);
                while let Some(e) = edge.take() {
                    for row in db_pool
                        .get()
                        .await
                        .stack_context(log, "Error gettting db connection")?
                        .interact(move |db| db::cache_list(db, e))
                        .await?? {
                        edge = Some(row.rowid);
                        cache
                            .insert(
                                (row.identity.clone(), split_record_key(&row.key)),
                                (row.expires.into(), row.value),
                            )
                            .await;
                    }
                }
                return Ok(()) as Result<(), loga::Error>;
            }.await {
                Err(e) => {
                    log.log_err(loga::WARN, e.context("Error seeding cache with persisted data"));
                },
                _ => { },
            }
        }
        let core = Resolver(Arc::new(Resolver_ {
            node: node,
            log: log.clone(),
            cache: cache.clone(),
            publisher: publisher,
            global_addrs: global_addrs,
        }));

        // Bg core cleanup
        tm.task("Resolver - cache persister", {
            let tm1 = tm.clone();
            let db_pool = db_pool.clone();
            let log = log.fork(ea!(subsys = "persist_cache"));
            let cache = cache.clone();
            async move {
                let log = &log;
                match async {
                    ta_res!(());
                    tm1.until_terminate().await;
                    db_pool.get().await.stack_context(log, "Error gettting db connection")?.interact({
                        let cache = cache.clone();
                        move |db| {
                            db::cache_clear(db)?;
                            for (k, v) in cache.iter() {
                                db::cache_push(
                                    db,
                                    &k.0,
                                    &join_record_key(&k.1),
                                    &v.0.into(),
                                    v.1.as_ref().map(|v| v.as_str()),
                                )?;
                            }
                            return Ok(()) as Result<_, loga::Error>;
                        }
                    }).await??;
                    return Ok(());
                }.await {
                    Ok(_) => { },
                    Err(e) => {
                        log.log_err(loga::WARN, e.context("Failed to persist cache at shutdown"));
                    },
                }
            }
        });
        Ok(core)
    }

    pub async fn get(
        &self,
        ident: &Identity,
        request_keys: Vec<RecordKey>,
    ) -> Result<wire::resolve::v1::ResolveKeyValues, loga::Error> {
        // First check cache. Only respond with cache answers if all keys are in cache
        // (will be making a request anyway, might as well get fresh data).
        let now = SystemTime::now();
        shed!{
            'missing _;
            let mut kvs = HashMap::new();
            for k in &request_keys {
                if let Some(found) = self.0.cache.get(&(ident.clone(), k.clone())) {
                    let (expiry, v) = found;
                    if expiry < now {
                        break 'missing;
                    }
                    let v = match v {
                        Some(v) => {
                            match serde_json::from_str::<serde_json::Value>(&v) {
                                Ok(v) => Some(v),
                                Err(e) => {
                                    self
                                        .0
                                        .log
                                        .log_err(
                                            loga::WARN,
                                            e.context_with(
                                                "Couldn't parse cache value as json",
                                                ea!(key = k.dbg_str()),
                                            ),
                                        );
                                    break 'missing;
                                },
                            }
                        },
                        None => None,
                    };
                    kvs.insert(k.clone(), wire::resolve::v1::ResolveValue {
                        expires: expiry.into(),
                        data: v,
                    });
                } else {
                    self.0.log.log_with(loga::DEBUG, "Cache miss", ea!(ident = ident, key = k.dbg_str()));
                    break 'missing;
                }
            }
            return Ok(kvs);
        };

        // Not in cache, find publisher via nodes
        let resp = match self.0.node.get(ident.clone()).await {
            Some(v) => v,
            None => {
                self
                    .0
                    .log
                    .log_with(loga::DEBUG, "No announcement found, returning empty result", ea!(ident = ident));
                return Ok(HashMap::new());
            },
        };
        let mut publishers;
        match resp {
            stored::announcement::Announcement::V1(a) => {
                let a = a.parse_unwrap();
                publishers = a.publishers;
            },
        };
        publishers.shuffle(&mut thread_rng());
        let mut values = None;
        let mut errs = vec![];
        let resp_max_size = request_keys.len() * 128 * 1024;
        for publisher in publishers {
            let log = self.0.log.fork(ea!(publisher = publisher.addr));
            let log = &log;
            match async {
                ta_res!(wire::resolve::v1::ResolveKeyValues);

                // Request values from publisher
                shed!{
                    // Check if publisher is us, short circuit network
                    if !self.0.global_addrs.iter().any(|i| *i == publisher.addr.0.ip()) {
                        break;
                    }
                    let Some(publisher) = &self.0.publisher else {
                        break;
                    };
                    return Ok(publisher.get_values(&ident, request_keys.clone()).await?);
                }

                // Request values via publisher over internet
                let url = Uri::from_str(&format!("https://{}", publisher.addr)).unwrap();
                let connect = async {
                    return Ok(
                        HttpsConnectorBuilder::new()
                            .with_tls_config(
                                ClientConfig::builder()
                                    .dangerous()
                                    .with_custom_certificate_verifier(SingleKeyVerifier::new(publisher.cert_hash))
                                    .with_no_client_auth(),
                            )
                            .https_only()
                            .enable_http1()
                            .build()
                            .call(url.clone())
                            .await
                            .map_err(|e| loga::err_with("Connection failed", ea!(err = e.to_string(), url = url)))?,
                    );
                };
                let mut conn =
                    Conn::new(
                        hyper::client::conn::http1::handshake(select!{
                            _ = sleep(Duration::from_secs(10)) => Err(loga::err("Timeout connecting")),
                            res = connect => res,
                        }.context_with("Error connecting to publisher", ea!(url = url))?)
                            .await
                            .context("Error completing http handshake")?,
                    );
                let resp =
                    htreq::post_json::<wire::resolve::v1::ResolveResp>(
                        log,
                        &mut conn,
                        &url,
                        &HashMap::new(),
                        &wire::resolve::ResolveRequest::V1(wire::resolve::v1::ResolveRequest {
                            ident: ident.clone(),
                            keys: request_keys.clone(),
                        }),
                        resp_max_size,
                    )
                        .await
                        .context("Error getting response from publisher")?
                        .into_iter()
                        .collect::<wire::resolve::v1::ResolveKeyValues>();
                return Ok(resp);
            }.await {
                Ok(v) => {
                    values = Some(v);
                    break;
                },
                Err(e) => {
                    errs.push(e.stack_context(log, "Error retrieving response from publisher"));
                },
            }
        }
        let Some(values) = values else {
            if errs.is_empty() {
                return Err(loga::err("Publisher announcement listed no publishers"));
            }
            return Err(loga::agg_err("Value lookup failed on all announced publishers", errs));
        };

        // Store found values
        spawn({
            let resp_kvs = values.clone();
            let cache = self.0.cache.clone();
            let identity = ident.clone();
            let log = self.0.log.clone();
            let ident = ident.clone();
            async move {
                let log = &log;
                for (k, v) in resp_kvs {
                    log.log_with(loga::DEBUG, "Cache store", ea!(ident = ident, key = k.dbg_str()));
                    cache
                        .insert(
                            (identity.clone(), k.to_owned()),
                            (v.expires.into(), v.data.as_ref().map(|v| serde_json::to_string(v).unwrap())),
                        )
                        .await;
                }
            }
        });
        return Ok(values);
    }
}

pub const API_ROUTE_RESOLVE: &str = "resolve";

/// Launch a publisher into the task manager and return the API endpoints for
/// attaching to the user-facing HTTP servers.
pub fn build_api_endpoints(log: Log, resolver: &Resolver) -> htserve::handler::PathRouter<htserve::responses::Body> {
    struct Inner {
        resolver: Resolver,
        log: Log,
    }

    let state = Arc::new(Inner {
        resolver: resolver.clone(),
        log: log,
    });
    let mut r = htserve::handler::PathRouter::default();
    r.insert("/v1", Box::new(htwrap::handler!((state: Arc < Inner >)(args -> htserve:: responses:: Body) {
        match async {
            ta_vis_res!(wire::api::resolve::v1::ResolveResp);
            let ident_src =
                args.subpath.strip_prefix("/").context("Missing identity final path element").err_external()?;
            let keys = split_query_record_keys(&args.query);
            let kvs =
                state
                    .resolver
                    .get(
                        &Identity::from_str(&ident_src)
                            .context_with("Failed to parse identity", ea!(identity = ident_src))
                            .err_external()?,
                        keys,
                    )
                    .await
                    .err_internal()?;
            return Ok(kvs.into_iter().collect::<Vec<_>>());
        }.await {
            Ok(r) => response_200_json(r),
            Err(VisErr::External(e)) => {
                return response_400(e);
            },
            Err(VisErr::Internal(e)) => {
                state.log.log_err(loga::WARN, e.context("Error responding to query"));
                return response_503();
            },
        }
    }))).unwrap();
    return r;
}
