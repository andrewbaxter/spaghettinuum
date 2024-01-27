use crate::{
    utils::{
        db_util::setup_db,
        blob::Blob,
        htserve::{
            Routes,
            self,
            Response,
        },
        log::{
            Log,
            WARN,
            DEBUG_RESOLVE,
        },
        ResultVisErr,
        VisErr,
        htreq,
    },
    interface::{
        identity::Identity,
    },
    publisher::publisher_cert_hash,
    ta_res,
    cap_fn,
    ta_vis_res,
};
use crate::node::Node;
use chrono::{
    DateTime,
    Duration,
    Utc,
};
use http_body_util::Empty;
use hyper::{
    Request,
    body::Bytes,
    Uri,
};
use hyper_rustls::HttpsConnectorBuilder;
use itertools::Itertools;
use loga::{
    ea,
    ErrContext,
    ResultContext,
};
use moka::future::Cache;
use tower_service::Service;
use std::{
    collections::HashMap,
    sync::Arc,
    path::Path,
    str::FromStr,
};
use taskmanager::TaskManager;
use tokio::spawn;

pub mod db;
pub mod dns;

struct Resolver_ {
    node: Node,
    log: Log,
    cache: Cache<(Identity, String), (DateTime<Utc>, Option<String>)>,
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
        persistent_dir: &Path,
    ) -> Result<Resolver, loga::Error> {
        let log = &log.fork(ea!(sys = "resolver"));
        let db_pool =
            setup_db(&persistent_dir.join("resolver.sqlite3"), db::migrate)
                .await
                .stack_context(log, "Error initializing database")?;
        let cache = Cache::builder().weigher(|_key, pair: &(DateTime<Utc>, Option<String>)| -> u32 {
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
                        cache.insert((row.identity.clone(), row.key), (row.expires, row.value)).await;
                    }
                }
                return Ok(()) as Result<(), loga::Error>;
            }.await {
                Err(e) => {
                    log.log_err(WARN, e.context("Error seeding cache with persisted data"));
                },
                _ => { },
            }
        }
        let core = Resolver(Arc::new(Resolver_ {
            node: node,
            log: log.clone(),
            cache: cache.clone(),
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
                                db::cache_push(db, &k.0, &k.1, v.0, v.1.as_ref().map(|v| v.as_str()))?;
                            }
                            return Ok(()) as Result<_, loga::Error>;
                        }
                    }).await??;
                    return Ok(());
                }.await {
                    Ok(_) => { },
                    Err(e) => {
                        log.log_err(WARN, e.context("Failed to persist cache at shutdown"));
                    },
                }
            }
        });
        Ok(core)
    }

    pub async fn get(
        &self,
        ident: &Identity,
        request_keys: &[&str],
    ) -> Result<HashMap<String, resolve::latest::ResolveValue>, loga::Error> {
        // First check cache
        let now = Utc::now();
        'missing : loop {
            let mut kvs = HashMap::new();
            for k in request_keys {
                if let Some(found) = self.0.cache.get(&(ident.clone(), k.to_string())) {
                    let (expiry, v) = found;
                    if expiry + Duration::minutes(5) < now {
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
                                            WARN,
                                            e.context_with("Couldn't parse cache value as json", ea!(key = k)),
                                        );
                                    break 'missing;
                                },
                            }
                        },
                        None => None,
                    };
                    kvs.insert(k.to_string(), resolve::latest::ResolveValue {
                        expires: expiry,
                        data: v,
                    });
                } else {
                    self.0.log.log_with(DEBUG_RESOLVE, "Cache miss", ea!(ident = ident, key = k));
                    break 'missing;
                }
            }
            return Ok(kvs);
        }

        // Not in cache, find publisher via nodes
        let resp = match self.0.node.get(ident.clone()).await {
            Some(v) => v,
            None => return Ok(HashMap::new()),
        };

        // Request values via publisher
        let log = self.0.log.fork(ea!(publisher = resp.addr, action = "publisher_request"));
        let log = &log;

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
                if publisher_cert_hash(
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

        let uri = Uri::from_str(&format!("https://{}/{}?{}", resp.addr, ident, request_keys.join(","))).unwrap();
        let pub_resp_bytes =
            htreq::send(
                HttpsConnectorBuilder::new()
                    .with_tls_config(
                        rustls::ClientConfig::builder()
                            .dangerous()
                            .with_custom_certificate_verifier(SingleKeyVerifier::new(resp.cert_hash))
                            .with_no_client_auth(),
                    )
                    .https_only()
                    .enable_http1()
                    .build()
                    .call(uri.clone())
                    .await
                    .map_err(|e| log.err_with("Error connecting to publisher", ea!(err = e.to_string())))?,
                128 * 1024 * request_keys.len(),
                Duration::seconds(10),
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .header(hyper::header::HOST, resp.addr.to_string())
                    .body(Empty::<Bytes>::new())
                    .unwrap(),
            )
                .await
                .stack_context(log, "Error getting response from publisher")?;
        let resp_kvs: resolve::ResolveKeyValues =
            serde_json::from_slice(&pub_resp_bytes).stack_context(&log, "Couldn't parse response")?;

        // Store found values
        spawn({
            let resp_kvs = resp_kvs.clone();
            let cache = self.0.cache.clone();
            let identity = ident.clone();
            let log = log.clone();
            let ident = ident.clone();
            async move {
                let log = &log;
                match &resp_kvs {
                    resolve::ResolveKeyValues::V1(resp_kvs) => {
                        for (k, v) in &resp_kvs.0 {
                            log.log_with(DEBUG_RESOLVE, "Cache store", ea!(ident = ident, key = k));
                            cache
                                .insert(
                                    (identity.clone(), k.to_owned()),
                                    (v.expires, v.data.as_ref().map(|v| serde_json::to_string(v).unwrap())),
                                )
                                .await;
                        }
                    },
                }
            }
        });

        // Respond with found values
        match resp_kvs {
            resolve::ResolveKeyValues::V1(kvs) => {
                return Ok(kvs.0);
            },
        }
    }
}

/// Launch a publisher into the task manager and return the API endpoints for
/// attaching to the user-facing HTTP servers.
pub fn build_api_endpoints(log: &Log, resolver: &Resolver) -> Routes {
    struct Inner {
        resolver: Resolver,
        log: Log,
    }

    let state = Arc::new(Inner {
        resolver: resolver.clone(),
        log: log.fork(ea!(sys = "resolver")),
    });
    let mut r = Routes::new();
    r.add("v1", htserve::Leaf::new().get(cap_fn!((mut req)(state) {
        match async {
            ta_vis_res!(resolve::latest::ResolveKeyValues);
            let ident_src = req.path.pop().context("Missing identity final path element").err_external()?;
            let kvs =
                state
                    .resolver
                    .get(
                        &Identity::from_str(&ident_src)
                            .context_with("Failed to parse identity", ea!(identity = ident_src))
                            .err_external()?,
                        &req.query.split(",").collect_vec(),
                    )
                    .await
                    .err_internal()?;
            return Ok(resolve::latest::ResolveKeyValues(kvs));
        }.await {
            Ok(r) => Response::json(r),
            Err(e) => match e {
                VisErr::External(e) => {
                    return Response::ExternalErr(e.to_string());
                },
                VisErr::Internal(e) => {
                    state.log.log_err(WARN, e.context("Error responding to query"));
                    return Response::InternalErr;
                },
            },
        }
    })));
    return r;
}
