use self::config::ResolverConfig;
use crate::{
    data::{
        dns::DnsRecordsetJson,
        identity::Identity,
        publisher::{
            self,
            v1::ResolveValue,
            ResolveKeyValues,
        },
        standard::{
            COMMON_KEYS_DNS,
            KEY_DNS_A,
            KEY_DNS_AAAA,
            KEY_DNS_CNAME,
            KEY_DNS_MX,
            KEY_DNS_NS,
            KEY_DNS_PTR,
            KEY_DNS_SOA,
            KEY_DNS_TXT,
        },
    },
    utils::reqwest_get,
};
use crate::{
    aes,
    aes2,
    node::Node,
    publisher::publisher_cert_hash,
    utils::{
        ResultVisErr,
        VisErr,
    },
};
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
    DebugDisplay,
};
use moka::future::Cache;
use poem::{
    async_trait,
    get,
    http::StatusCode,
    listener::TcpListener,
    Endpoint,
    IntoResponse,
    Request,
    Response,
    Server,
};
use rusqlite::Connection;
use rustls::{
    client::{
        ServerCertVerified,
        ServerCertVerifier,
    },
    Certificate,
};
use std::{
    collections::HashMap,
    fs,
    io::ErrorKind,
    net::{
        Ipv4Addr,
        Ipv6Addr,
    },
    path::PathBuf,
    str::FromStr,
    sync::{
        Arc,
        Mutex,
    },
};
use taskmanager::TaskManager;
use tokio::{
    net::UdpSocket,
    spawn,
};
use trust_dns_client::{
    client::{
        AsyncClient,
        ClientHandle,
    },
    op::{
        Header,
        ResponseCode,
    },
    rr::{
        rdata::{
            MX,
            TXT,
        },
        DNSClass,
        Label,
        LowerName,
        Name,
        Record,
    },
    udp::UdpClientStream,
};
use trust_dns_server::{
    authority::MessageResponseBuilder,
    server::ResponseInfo,
};

pub mod config;
mod db;

// Workaround for unqualified anyhow usage issue
mod parse_path {
    use structre::structre;

    #[structre("/v1/(?P<identity>.*)")]
    pub struct V1Path {
        pub identity: String,
    }
}

struct CoreInner {
    node: Node,
    log: Log,
    cache: Cache<(Identity, String), (DateTime<Utc>, Option<String>)>,
}

/// This is the core of the resolver; it does lookups using a local node. If you
/// don't have a local node, you can do lookups with a simple http client against a
/// remote resolver.
#[derive(Clone)]
pub struct Core(Arc<CoreInner>);

impl Core {
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
        cache_path: Option<PathBuf>,
    ) -> Result<Core, loga::Error> {
        let log = log.fork(ea!(subsys = "core"));
        let cache = Cache::builder().weigher(|_key, pair: &(DateTime<Utc>, Option<String>)| -> u32 {
            match &pair.1 {
                Some(v) => v.len().try_into().unwrap_or(u32::MAX),
                None => 1,
            }
        }).max_capacity(max_cache.unwrap_or(64 * 1024 * 1024)).build();

        // Seed with stored cache data
        if let Some(p) = &cache_path {
            let log = log.fork(ea!(path = p.to_string_lossy()));
            match aes!({
                if !p.exists() {
                    return Ok(());
                }
                let db = &mut Connection::open(p)?;
                db::migrate(db)?;
                let mut edge = Some(i64::MAX);
                while let Some(e) = edge.take() {
                    for row in db::list(db, e)? {
                        edge = Some(row.rowid);
                        cache.insert((row.identity.clone(), row.key), (row.expires, row.value)).await;
                    }
                }
                return Ok(()) as Result<(), loga::Error>;
            }).await {
                Err(e) => {
                    log.warn_e(e, "Error seeding cache with persisted data", ea!());
                },
                _ => { },
            }
        }
        let core = Core(Arc::new(CoreInner {
            node: node,
            log: log.clone(),
            cache: cache.clone(),
        }));

        // Bg core cleanup
        if let Some(p) = &cache_path {
            let p = p.clone();
            tm.task({
                let tm1 = tm.clone();
                async move {
                    match aes!({
                        tm1.until_terminate().await;
                        match fs::remove_file(&p) {
                            Err(e) if e.kind() != ErrorKind::NotFound => {
                                Err(e)?;
                            },
                            _ => { },
                        };
                        let db = &mut Connection::open(&p)?;
                        db::migrate(db)?;
                        for (k, v) in cache.iter() {
                            db::push(db, &k.0, &k.1, v.0, v.1.as_ref().map(|v| v.as_str()))?;
                        }
                        return Ok(());
                    }).await {
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
    ) -> Result<HashMap<String, ResolveValue>, loga::Error> {
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
                    kvs.insert(k.to_string(), ResolveValue {
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

        pub struct SingleKeyVerifier {
            hash: Vec<u8>,
        }

        impl SingleKeyVerifier {
            pub fn new(hash: Vec<u8>) -> Arc<dyn ServerCertVerifier> {
                return Arc::new(SingleKeyVerifier { hash });
            }
        }

        impl ServerCertVerifier for SingleKeyVerifier {
            fn verify_server_cert(
                &self,
                end_entity: &Certificate,
                _intermediates: &[Certificate],
                _server_name: &rustls::ServerName,
                _scts: &mut dyn Iterator<Item = &[u8]>,
                _ocsp_response: &[u8],
                _now: std::time::SystemTime,
            ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
                let cert = match x509_parser::parse_x509_certificate(&end_entity.0) {
                    Ok(c) => c.1,
                    Err(_) => return Err(rustls::Error::InvalidCertificateEncoding),
                };
                if publisher_cert_hash(&cert) != self.hash {
                    return Err(rustls::Error::InvalidCertificateSignature);
                }
                return Ok(ServerCertVerified::assertion());
            }
        }

        let pub_resp_bytes =
            reqwest_get(
                reqwest::ClientBuilder::new()
                    .use_preconfigured_tls(
                        rustls::ClientConfig::builder()
                            .with_safe_defaults()
                            .with_custom_certificate_verifier(SingleKeyVerifier::new(resp.cert_hash))
                            .with_no_client_auth(),
                    )
                    .build()
                    .unwrap()
                    .get(format!("https://{}/{}?{}", resp.addr, ident, request_keys.join(",")))
                    .send()
                    .await
                    .log_context(&log, "Error sending request", ea!())?,
                128 * 1024 * request_keys.len(),
            )
                .await
                .log_context(&log, "Error getting response from publisher", ea!())?;
        let resp_kvs: publisher::ResolveKeyValues =
            serde_json::from_slice(&pub_resp_bytes).log_context(&log, "Couldn't parse response", ea!())?;

        // Store found values
        spawn({
            let resp_kvs = resp_kvs.clone();
            let cache = self.0.cache.clone();
            let identity = ident.clone();
            async move {
                match &resp_kvs {
                    publisher::ResolveKeyValues::V1(resp_kvs) => {
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
            ResolveKeyValues::V1(kvs) => {
                return Ok(kvs.0);
            },
        }
    }
}

#[doc(hidden)]
pub async fn start(tm: &TaskManager, log: &Log, config: ResolverConfig, node: Node) -> Result<(), loga::Error> {
    let log = log.fork(ea!(sys = "resolver"));
    let core = Core::new(&log, tm, node, config.max_cache, config.cache_persist_path).await?;

    // Launch resolver server
    if let Some(bind_addr) = config.bind_addr {
        struct Inner {
            core: Core,
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
                match aes!({
                    let ident_src =
                        parse_path::V1PathFromRegex::new()
                            .parse(req.uri().path())
                            .map_err(|e| loga::Error::from(e))?;
                    let kvs =
                        self
                            .0
                            .core
                            .get(
                                &Identity::from_str(
                                    &ident_src.identity,
                                ).context("Failed to parse identity", ea!(identity = ident_src.identity))?,
                                &req.uri().query().unwrap_or("").split(",").collect_vec(),
                            )
                            .await?;
                    return Ok(ResolveKeyValues::V1(crate::data::publisher::v1::ResolveKeyValues(kvs)));
                }).await {
                    Ok(kvs) => Ok(poem::web::Json(kvs).into_response()),
                    Err(e) => {
                        return Ok(
                            <String as IntoResponse>::with_status(
                                e.to_string(),
                                StatusCode::BAD_REQUEST,
                            ).into_response(),
                        );
                    },
                }
            }
        }

        tm.critical_task::<_, loga::Error>({
            let tm1 = tm.clone();
            let core1 = core.clone();
            let log = log.fork(ea!(subsys = "endpoint"));
            async move {
                match tm1.if_alive(Server::new(TcpListener::bind(bind_addr.1)).run(get(Outer(Arc::new(Inner {
                    core: core1,
                    log: log,
                }))))).await {
                    Some(r) => {
                        r?;
                    },
                    None => { },
                };
                return Ok(());
            }
        });
    }

    // Launch dns bridge
    if let Some(dns_config) = config.dns_bridge {
        struct HandlerInner {
            log: Log,
            core: Core,
            upstream: Mutex<AsyncClient>,
            expect_suffix: LowerName,
        }

        struct Handler(Arc<HandlerInner>);

        #[async_trait]
        impl trust_dns_server::server::RequestHandler for Handler {
            async fn handle_request<
                R: trust_dns_server::server::ResponseHandler,
            >(
                &self,
                request: &trust_dns_server::server::Request,
                mut response_handle: R,
            ) -> trust_dns_server::server::ResponseInfo {
                self.0.log.debug("Received", ea!(request = request.dbg_str()));
                let self1 = self.0.clone();
                match aes!({
                    match aes2!({
                        if request.query().query_class() != DNSClass::IN {
                            return Ok(None);
                        }
                        if request.query().name().base_name() != self1.expect_suffix {
                            return Ok(None);
                        }
                        if request.query().name().num_labels() != 2 {
                            return Err(
                                loga::Error::new(
                                    "Expected two parts in request (id., s.) but got different number",
                                    ea!(name = request.query().name(), count = request.query().name().num_labels()),
                                ),
                            ).err_external();
                        }
                        let query_name = Name::from(request.query().name());
                        let ident_part = query_name.iter().next().unwrap();
                        let ident =
                            Identity::from_bytes(&zbase32::decode_full_bytes(ident_part).map_err(|e| {
                                loga::Error::new("Wrong number of parts in request", ea!(ident = e))
                            }).err_external()?)
                                .context(
                                    "Couldn't parse ident in request",
                                    ea!(ident = String::from_utf8_lossy(&ident_part)),
                                )
                                .err_external()?;
                        let (lookup_key, batch_keys) = match request.query().query_type() {
                            trust_dns_client::rr::RecordType::A => (KEY_DNS_A, COMMON_KEYS_DNS),
                            trust_dns_client::rr::RecordType::AAAA => {
                                (KEY_DNS_AAAA, COMMON_KEYS_DNS)
                            },
                            trust_dns_client::rr::RecordType::CNAME => {
                                (KEY_DNS_CNAME, COMMON_KEYS_DNS)
                            },
                            trust_dns_client::rr::RecordType::NS => (KEY_DNS_NS, COMMON_KEYS_DNS),
                            trust_dns_client::rr::RecordType::PTR => (KEY_DNS_PTR, COMMON_KEYS_DNS),
                            trust_dns_client::rr::RecordType::SOA => (KEY_DNS_SOA, COMMON_KEYS_DNS),
                            trust_dns_client::rr::RecordType::TXT => (KEY_DNS_TXT, COMMON_KEYS_DNS),
                            trust_dns_client::rr::RecordType::MX => (KEY_DNS_MX, COMMON_KEYS_DNS),
                            _ => {
                                return Ok(
                                    Some(
                                        response_handle
                                            .send_response(
                                                MessageResponseBuilder::from_message_request(
                                                    request,
                                                ).build_no_records(Header::response_from_request(request.header())),
                                            )
                                            .await
                                            .context("Error sending response", ea!()),
                                    ),
                                );
                            },
                        };
                        let mut res = self1.core.get(&ident, batch_keys).await.err_internal()?;
                        let mut answers = vec![];
                        let filter_some = |v: ResolveValue| match v.data {
                            Some(v1) => Some((v.expires, v1)),
                            None => None,
                        };
                        if let Some((expires, data)) =
                            res
                                .remove(KEY_DNS_CNAME)
                                .map(filter_some)
                                .flatten()
                                .or_else(|| res.remove(lookup_key).map(filter_some).flatten()) {
                            match serde_json::from_str::<DnsRecordsetJson>(&data)
                                .context("Failed to parse received record json", ea!())
                                .err_internal()? {
                                DnsRecordsetJson::V1(v) => match v {
                                    crate::data::dns::v1::DnsRecordsetJson::A(n) => {
                                        for n in n {
                                            let n = match Ipv4Addr::from_str(&n) {
                                                Err(e) => {
                                                    self1
                                                        .log
                                                        .debug_e(
                                                            e.into(),
                                                            "A addr in record invalid for DNS",
                                                            ea!(name = n),
                                                        );
                                                    continue;
                                                },
                                                Ok(n) => n,
                                            };
                                            answers.push(
                                                Record::from_rdata(
                                                    request.query().name().into(),
                                                    expires
                                                        .signed_duration_since(Utc::now())
                                                        .num_seconds()
                                                        .try_into()
                                                        .unwrap_or(i32::MAX as u32),
                                                    trust_dns_client::rr::RData::A(n),
                                                ),
                                            );
                                        }
                                    },
                                    crate::data::dns::v1::DnsRecordsetJson::Aaaa(n) => {
                                        for n in n {
                                            let n = match Ipv6Addr::from_str(&n) {
                                                Err(e) => {
                                                    self1
                                                        .log
                                                        .debug_e(
                                                            e.into(),
                                                            "AAAA addr in record invalid for DNS",
                                                            ea!(name = n),
                                                        );
                                                    continue;
                                                },
                                                Ok(n) => n,
                                            };
                                            answers.push(
                                                Record::from_rdata(
                                                    request.query().name().into(),
                                                    expires
                                                        .signed_duration_since(Utc::now())
                                                        .num_seconds()
                                                        .try_into()
                                                        .unwrap_or(i32::MAX as u32),
                                                    trust_dns_client::rr::RData::AAAA(n),
                                                ),
                                            );
                                        }
                                    },
                                    crate::data::dns::v1::DnsRecordsetJson::Cname(n) => {
                                        for n in n {
                                            let n = match Name::from_utf8(&n) {
                                                Err(e) => {
                                                    self1
                                                        .log
                                                        .debug_e(
                                                            e.into(),
                                                            "Cname name in record invalid for DNS",
                                                            ea!(name = n),
                                                        );
                                                    continue;
                                                },
                                                Ok(n) => n,
                                            };
                                            answers.push(
                                                Record::from_rdata(
                                                    request.query().name().into(),
                                                    expires
                                                        .signed_duration_since(Utc::now())
                                                        .num_seconds()
                                                        .try_into()
                                                        .unwrap_or(i32::MAX as u32),
                                                    trust_dns_client::rr::RData::CNAME(n),
                                                ),
                                            );
                                        }
                                    },
                                    crate::data::dns::v1::DnsRecordsetJson::Txt(n) => {
                                        for n in n {
                                            answers.push(
                                                Record::from_rdata(
                                                    request.query().name().into(),
                                                    expires
                                                        .signed_duration_since(Utc::now())
                                                        .num_seconds()
                                                        .try_into()
                                                        .unwrap_or(i32::MAX as u32),
                                                    trust_dns_client::rr::RData::TXT(TXT::new(vec![n])),
                                                ),
                                            );
                                        }
                                    },
                                    crate::data::dns::v1::DnsRecordsetJson::Mx(n) => {
                                        for n in n {
                                            let exchange = match Name::from_utf8(&n.1) {
                                                Err(e) => {
                                                    self1
                                                        .log
                                                        .debug_e(
                                                            e.into(),
                                                            "Mx name in record invalid for DNS",
                                                            ea!(name = n.1),
                                                        );
                                                    continue;
                                                },
                                                Ok(n) => n,
                                            };
                                            answers.push(
                                                Record::from_rdata(
                                                    request.query().name().into(),
                                                    expires
                                                        .signed_duration_since(Utc::now())
                                                        .num_seconds()
                                                        .try_into()
                                                        .unwrap_or(i32::MAX as u32),
                                                    trust_dns_client::rr::RData::MX(MX::new(n.0, exchange)),
                                                ),
                                            );
                                        }
                                    },
                                },
                            }
                        }
                        return Ok(
                            Some(
                                response_handle
                                    .send_response(
                                        MessageResponseBuilder::from_message_request(
                                            request,
                                        ).build(
                                            Header::response_from_request(request.header()),
                                            answers.iter().map(|r| r),
                                            &[],
                                            &[],
                                            &[],
                                        ),
                                    )
                                    .await
                                    .context("Error sending response", ea!()),
                            ),
                        );
                    }).await as Result<Option<Result<ResponseInfo, loga::Error>>, VisErr> {
                        Ok(r) => match r {
                            Some(resp) => {
                                return Ok(resp?);
                            },
                            None => {
                                let query =
                                    self1
                                        .upstream
                                        .lock()
                                        .unwrap()
                                        .query(
                                            Name::from(request.query().name()),
                                            request.query().query_class(),
                                            request.query().query_type(),
                                        );
                                let resp = match query.await {
                                    Ok(r) => r,
                                    Err(e) => {
                                        self1.log.debug_e(e.into(), "Request failed due to upstream issue", ea!());
                                        return Ok(
                                            response_handle
                                                .send_response(
                                                    MessageResponseBuilder::from_message_request(
                                                        request,
                                                    ).error_msg(request.header(), ResponseCode::FormErr),
                                                )
                                                .await?,
                                        );
                                    },
                                };
                                return Ok(
                                    response_handle
                                        .send_response(
                                            MessageResponseBuilder::from_message_request(
                                                request,
                                            ).build(
                                                Header::response_from_request(request.header()),
                                                resp.answers(),
                                                resp.name_servers(),
                                                resp.soa(),
                                                resp.additionals(),
                                            ),
                                        )
                                        .await?,
                                );
                            },
                        },
                        Err(e) => match e {
                            VisErr::External(e) => {
                                self1.log.debug_e(e, "Request failed due to requester issue", ea!());
                                return Ok(
                                    response_handle
                                        .send_response(
                                            MessageResponseBuilder::from_message_request(
                                                request,
                                            ).error_msg(request.header(), ResponseCode::FormErr),
                                        )
                                        .await?,
                                );
                            },
                            VisErr::Internal(e) => {
                                self1.log.warn_e(e, "Request failed due to internal issue", ea!());
                                return Ok(
                                    response_handle
                                        .send_response(
                                            MessageResponseBuilder::from_message_request(
                                                request,
                                            ).error_msg(request.header(), ResponseCode::ServFail),
                                        )
                                        .await?,
                                );
                            },
                        },
                    }
                }).await as Result<ResponseInfo, loga::Error> {
                    Err(e) => {
                        self1.log.warn_e(e, "Request failed due to internal issue", ea!());
                        let mut header = Header::new();
                        header.set_response_code(ResponseCode::ServFail);
                        return header.into();
                    },
                    Ok(info) => {
                        return info;
                    },
                }
            }
        }

        tm.critical_task::<_, loga::Error>({
            let log = log.fork(ea!(subsys = "dns"));
            let tm1 = tm.clone();
            async move {
                let (upstream, upstream_bg) =
                    AsyncClient::connect(UdpClientStream::<UdpSocket>::new(dns_config.upstream.1))
                        .await
                        .log_context(&log, "Failed to open upstream client", ea!())?;
                spawn(upstream_bg);
                let mut server = trust_dns_server::ServerFuture::new(Handler(Arc::new(HandlerInner {
                    log: log.clone(),
                    core,
                    upstream: Mutex::new(upstream),
                    expect_suffix: LowerName::new(&Name::from_labels(&[Label::from_utf8("s").unwrap()]).unwrap()),
                })));
                server.register_socket(
                    UdpSocket::bind(&dns_config.bind_addr.1)
                        .await
                        .log_context(&log, "Opening UDP listener failed", ea!(socket = dns_config.bind_addr.1))?,
                );
                match tm1.if_alive(server.block_until_done()).await {
                    Some(r) => {
                        r.log_context(&log, "Server exited with error", ea!())?;
                    },
                    None => { },
                };
                return Ok(());
            }
        });
    }
    return Ok(());
}
