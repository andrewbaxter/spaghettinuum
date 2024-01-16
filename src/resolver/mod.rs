use crate::{
    utils::{
        reqwest_get,
        SystemEndpoints,
        db_util::setup_db,
    },
    interface::{
        identity::Identity,
        spagh_api::resolve::self,
    },
    publisher::publisher_cert_hash,
};
use crate::node::Node;
use chrono::{
    DateTime,
    Duration,
    Utc,
};
use itertools::Itertools;
use loga::{
    ea,
    Log,
    ResultContext,
};
use moka::future::Cache;
use poem::{
    async_trait,
    get,
    http::StatusCode,
    Endpoint,
    IntoResponse,
    Request,
    Response,
    IntoEndpoint,
    EndpointExt,
};
use std::{
    collections::HashMap,
    sync::Arc,
    path::Path,
};
use taskmanager::TaskManager;
use tokio::spawn;

pub mod db;
pub mod config;
pub mod dns;

// Workaround for unqualified anyhow usage issue
mod parse_path {
    use structre::structre;

    #[structre("/v1/(?P<identity>.*)")]
    pub struct V1Path {
        pub identity: String,
    }
}

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
        let log = &log.fork(ea!(subsys = "core"));
        let db_pool =
            setup_db(&persistent_dir.join("resolver.sqlite3"), db::migrate)
                .await
                .log_context(log, "Error initializing database")?;
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
                        .log_context(log, "Error gettting db connection")?
                        .interact(move |db| db::cache_list(db, e))
                        .await?? {
                        edge = Some(row.rowid);
                        cache.insert((row.identity.clone(), row.key), (row.expires, row.value)).await;
                    }
                }
                return Ok(()) as Result<(), loga::Error>;
            }.await {
                Err(e) => {
                    log.warn_e(e, "Error seeding cache with persisted data", ea!());
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
        {
            tm.task({
                let tm1 = tm.clone();
                let db_pool = db_pool.clone();
                let log = log.fork(ea!(subsys = "persist_cache"));
                let cache = cache.clone();
                async move {
                    let log = &log;
                    match async {
                        tm1.until_terminate().await;
                        db_pool.get().await.log_context(log, "Error gettting db connection")?.interact({
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
                            log.warn_e(e, "Failed to persist cache at shutdown", ea!());
                        },
                    }
                }
            });
        }
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
                    kvs.insert(k.to_string(), resolve::latest::ResolveValue {
                        expires: expiry,
                        data: v,
                    });
                } else {
                    eprintln!("DEBUG resolver cache miss {} {}", ident, k);
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
        let log = self.0.log.fork(ea!(url = resp.addr, action = "publisher_request"));

        #[derive(Debug)]
        pub struct SingleKeyVerifier {
            hash: Vec<u8>,
        }

        impl SingleKeyVerifier {
            pub fn new(hash: Vec<u8>) -> Arc<dyn reqwest::rustls::client::ServerCertVerifier> {
                return Arc::new(SingleKeyVerifier { hash });
            }
        }

        impl reqwest::rustls::client::ServerCertVerifier for SingleKeyVerifier {
            fn verify_server_cert(
                &self,
                end_entity: &reqwest::rustls::Certificate,
                _intermediates: &[reqwest::rustls::Certificate],
                _server_name: &reqwest::rustls::ServerName,
                _scts: &mut dyn Iterator<Item = &[u8]>,
                _ocsp_response: &[u8],
                _now: std::time::SystemTime,
            ) -> Result<reqwest::rustls::client::ServerCertVerified, reqwest::rustls::Error> {
                if publisher_cert_hash(
                    end_entity.as_ref(),
                ).map_err(
                    |_| reqwest::rustls::Error::InvalidCertificate(reqwest::rustls::CertificateError::BadEncoding),
                )? !=
                    self.hash {
                    return Err(
                        reqwest::rustls::Error::InvalidCertificate(reqwest::rustls::CertificateError::BadEncoding),
                    );
                }
                return Ok(reqwest::rustls::client::ServerCertVerified::assertion());
            }
        }

        let pub_resp_bytes =
            reqwest_get(
                reqwest::ClientBuilder::new()
                    .use_preconfigured_rustls(
                        reqwest::rustls::ClientConfig::builder()
                            .with_safe_defaults()
                            .with_custom_certificate_verifier(SingleKeyVerifier::new(resp.cert_hash))
                            .with_no_client_auth(),
                    )
                    .build()
                    .unwrap()
                    .get(format!("https://{}/{}?{}", resp.addr, ident, request_keys.join(",")))
                    .send()
                    .await
                    .log_context(&log, "Error sending request")?,
                128 * 1024 * request_keys.len(),
            )
                .await
                .log_context(&log, "Error getting response from publisher")?;
        let resp_kvs: resolve::ResolveKeyValues =
            serde_json::from_slice(&pub_resp_bytes).log_context(&log, "Couldn't parse response")?;

        // Store found values
        spawn({
            let resp_kvs = resp_kvs.clone();
            let cache = self.0.cache.clone();
            let identity = ident.clone();
            async move {
                match &resp_kvs {
                    resolve::ResolveKeyValues::V1(resp_kvs) => {
                        for (k, v) in &resp_kvs.0 {
                            eprintln!("DEBUG cache store {} {}", identity, k);
                            cache.insert((identity.clone(), k.to_owned()), (v.expires, v.data.clone())).await;
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
pub fn build_api_endpoints(log: &loga::Log, resolver: &Resolver) -> SystemEndpoints {
    struct Inner {
        resolver: Resolver,
        log: Log,
    }

    struct Outer(Arc<Inner>);

    #[async_trait]
    impl Endpoint for Outer {
        type Output = Response;

        async fn call(&self, req: Request) -> poem::Result<Self::Output> {
            self.0.log.debug("Request", ea!(path = req.uri().path()));
            if req.uri().path() == "/health" {
                return Ok(StatusCode::OK.into_response());
            }
            match async {
                let ident_src =
                    parse_path::V1Path::parser().parse(req.uri().path()).map_err(|e| loga::Error::from(e))?;
                let kvs =
                    self
                        .0
                        .resolver
                        .get(
                            &Identity::from_str(
                                &ident_src.identity,
                            ).context_with("Failed to parse identity", ea!(identity = ident_src.identity))?,
                            &req.uri().query().unwrap_or("").split(",").collect_vec(),
                        )
                        .await?;
                return Ok(resolve::ResolveKeyValues::V1(resolve::latest::ResolveKeyValues(kvs))) as
                    Result<resolve::ResolveKeyValues, loga::Error>;
            }.await {
                Ok(kvs) => Ok(poem::web::Json(kvs).into_response()),
                Err(e) => {
                    return Ok(
                        <String as IntoResponse>::with_status(e.to_string(), StatusCode::BAD_REQUEST).into_response(),
                    );
                },
            }
        }
    }

    return SystemEndpoints(get(Outer(Arc::new(Inner {
        resolver: resolver.clone(),
        log: log.fork(ea!(sys = "resolver")),
    }))).into_endpoint().boxed());
}
