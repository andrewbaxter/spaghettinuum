use std::{
    sync::{
        Arc,
        Mutex,
    },
    net::{
        SocketAddr,
    },
    path::PathBuf,
    collections::HashMap,
    fs,
    io::ErrorKind,
};
use chrono::{
    Utc,
    DateTime,
    Duration,
};
use itertools::Itertools;
use loga::{
    Log,
    ResultContext,
    ea,
};
use moka::future::Cache;
use poem::{
    Server,
    Endpoint,
    Response,
    async_trait,
    Request,
    http::StatusCode,
    get,
    listener::TcpListener,
    IntoResponse,
};
use rusqlite::{
    Connection,
};
use rustls::{
    client::{
        ServerCertVerifier,
        ServerCertVerified,
    },
    Certificate,
};
use serde::{
    Deserialize,
    Serialize,
};
use taskmanager::TaskManager;
use tokio::{
    spawn,
    net::UdpSocket,
};
use trust_dns_client::{
    rr::{
        DNSClass,
        LowerName,
        Name,
        Record,
        Label,
    },
    op::{
        Header,
        ResponseCode,
    },
    client::{
        AsyncClient,
        ClientHandle,
    },
    udp::UdpClientStream,
};
use trust_dns_server::{
    authority::MessageResponseBuilder,
    server::ResponseInfo,
};
use crate::{
    node::{
        Node,
    },
    model::{
        identity::{
            Identity,
        },
        publish::{
            v1::{
                Value,
            },
            self,
            ResolveKeyValues,
        },
        self,
    },
    aes,
    publisher::publisher_cert_hash,
    utils::{
        ResultVisErr,
        VisErr,
    },
    aes2,
};

pub mod db;

const KEY_DNS_A: &'static str = "dsf9oyfz83fatqpscp9yt8wkuw";
const KEY_DNS_AAAA: &'static str = "wwfukygd6tykiqrmi3jp6qnoiw";
const KEY_DNS_CNAME: &'static str = "gi3saqn8pfn7tmwbd4pxj3tour";
const KEY_DNS_MX: &'static str = "zm5zzaotiib4bbqg9befbr1kro";
const KEY_DNS_NS: &'static str = "ic6hcun6zjnqtxe5ft8i6wox4w";
const KEY_DNS_PTR: &'static str = "t7ou17qiefnozbe1uef7ym5hih";
const KEY_DNS_SOA: &'static str = "371z1qxg5jnftcjr3g9x7ihzdo";
const KEY_DNS_SRV: &'static str = "pyte8mamfbgijefzc8a47gcq4h";
const KEY_DNS_TXT: &'static str = "rht6tfoc4pnbipesgjejkzeeta";
const KEY_DNS_NSEC: &'static str = "o5qooyyh4pfo7pm8j8z5aaxtwo";
const KEY_DNS_NSEC3: &'static str = "x18s8kzedpgy9k9yhm46gxjdky";
const KEY_DNS_NSEC3PARAM: &'static str = "k1qkz4rn5p8gp8qmurt7ohijuy";
const KEY_DNS_RRSIG: &'static str = "xdgo9zk4p7ntxjuk1tomoqpfja";
const KEY_DNS_TLSA: &'static str = "75raif7nhtf87gxqf7h4binmdr";
const KEY_DNS_DNSKEY: &'static str = "wngk1zrw4p8ojbkbpxzdqk6wwy";
const KEY_DNS_DS: &'static str = "wjfjjd8ysiyb5xdgmmm514e64c";
const KEY_DNS_CDNSKEY: &'static str = "5m9p4wwsjprtxpzkp7s4ctk3hh";
const COMMON_KEYS_DNS: &[&'static str] =
    &[
        KEY_DNS_A,
        KEY_DNS_AAAA,
        KEY_DNS_CNAME,
        KEY_DNS_MX,
        KEY_DNS_NS,
        KEY_DNS_PTR,
        KEY_DNS_SOA,
        KEY_DNS_SRV,
        KEY_DNS_TXT,
        KEY_DNS_NSEC,
        KEY_DNS_NSEC3,
        KEY_DNS_NSEC3PARAM,
        KEY_DNS_RRSIG,
        KEY_DNS_TLSA,
        KEY_DNS_DNSKEY,
        KEY_DNS_DS,
        KEY_DNS_CDNSKEY,
    ];

#[derive(Deserialize, Serialize, Clone, Debug)]
pub enum DnsRecordJson {
    Cname(String),
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct DnsRecordsetJson(Vec<DnsRecordJson>);

//. Unsupported
//. const KEY_DNS_AFSDB: &'static str = "3dmm7eocsjbnmy1jokcban5bre";
//. const KEY_DNS_APL: &'static str = "74yih9nx63gd5e5ea9u77bswjc";
//. const KEY_DNS_CAA: &'static str = "mkt18be4ebyzjd9ushujkdgd3w";
//. const KEY_DNS_CDS: &'static str = "yfp769ynsfneubrsya773f9ubr";
//. const KEY_DNS_CERT: &'static str = "xtby1psjtff1me44w3wnrdwfdw";
//. const KEY_DNS_CSYNC: &'static str = "px8ana558tbyubn11by9ju7xue";
//. const KEY_DNS_DHCID: &'static str = "6bn6oyeertbizy3bd6eiim8xxh";
//. const KEY_DNS_DLV: &'static str = "xbuh5zkc87rktgpbux8mx7adeh";
//. const KEY_DNS_DNAME: &'static str = "39b73zajj3bwx8h9x3c9fzxkxc";
//. const KEY_DNS_EUI48: &'static str = "yzaykod1utd3xy5mm31niktoew";
//. const KEY_DNS_EUI64: &'static str = "bobfkaefs3ywzecfx6kwc7q8ye";
//. const KEY_DNS_HINFO: &'static str = "wijsunu9hidqipabhdosj1ryor";
//. const KEY_DNS_HIP: &'static str = "ir4mz7q7jjrumr8io5x1rmxb7o";
//. const KEY_DNS_HTTPS: &'static str = "af9ggtncy7gk5qrg7e1qrka4he";
//. const KEY_DNS_IPSECKEY: &'static str = "oz181b9dhff4mgsahcqwf3o84o";
//. const KEY_DNS_KEY: &'static str = "d6n1q796ntfef8w4xhfdd8e3ih";
//. const KEY_DNS_KX: &'static str = "7tsx91qyu3rwmdgsdscbc448py";
//. const KEY_DNS_LOC: &'static str = "41ciwyocmtyxxecagfau633wqo";
//. const KEY_DNS_NAPTR: &'static str = "edncym8jgjgctjagghc81n4r7e";
//. const KEY_DNS_OPENPGPKEY: &'static str = "bus8bas8jfbh9g4wi13s5cix9h";
//. const KEY_DNS_RP: &'static str = "n3za9djpr3bbjkfw7xp5ynb5dy";
//. const KEY_DNS_SIG: &'static str = "kbq5umit1i8bmng3dmmkkwdujo";
//. const KEY_DNS_SMIMEA: &'static str = "744jqnambfnnbmr8ww68syxncw";
//. const KEY_DNS_SSHFP: &'static str = "631mu91517b6ugosuwdqc8yxde";
//. const KEY_DNS_SVCB: &'static str = "rr6834nx5tnfup7rz44anpoe7r";
//. const KEY_DNS_TA: &'static str = "o8wt8bc9g7fhzyf5fyjnx4w6or";
//. const KEY_DNS_TKEY: &'static str = "ebygsh9ce3dk5met8e4ute9uoo";
//. const KEY_DNS_TSIG: &'static str = "1rqocmfbnpg8dg4rp54ucggqoa";
//. const KEY_DNS_URI: &'static str = "rskkuenpmffbbpqxfo5kkwueqy";
//. const KEY_DNS_ZONEMD: &'static str = "yar9fu1px7f3pygrfuxjejm61a";
#[derive(Deserialize, Serialize)]
pub struct ResolverConfig {
    pub bind_addr: Option<SocketAddr>,
    pub cache_path: Option<PathBuf>,
    pub max_cache: Option<u64>,
    pub dns_bridge: Option<DnsBridgerConfig>,
}

#[derive(Deserialize, Serialize)]
pub struct DnsBridgerConfig {
    pub upstream: SocketAddr,
    pub bind_addr: SocketAddr,
}

struct CoreInner {
    node: Node,
    log: Log,
    cache: Cache<(Identity, String), (DateTime<Utc>, String)>,
}

#[derive(Clone)]
struct Core(Arc<CoreInner>);

impl Core {
    async fn get(&self, ident: &Identity, keys: &[&str]) -> Result<HashMap<String, Value>, loga::Error> {
        //. let ident = Identity::from_str(req.uri().path().get(1..).unwrap_or(""))?;
        //. let keys = req.uri().query().unwrap_or("").split(",").collect_vec();
        // First check cache
        let now = Utc::now();
        'missing : loop {
            let mut kvs = HashMap::new();
            for k in keys {
                if let Some(found) = self.0.cache.get(&(ident.clone(), k.to_string())) {
                    let (expiry, v) = found;
                    if expiry + Duration::minutes(5) < now {
                        break 'missing;
                    }
                    kvs.insert(k.to_string(), Value {
                        expires: expiry,
                        data: v,
                    });
                } else {
                    break 'missing;
                }
            }
            return Ok(kvs);
        };

        // Not in cache, find publisher via nodes
        let resp = match self.0.node.get(ident.clone()).await {
            Some(v) => v,
            None => return Ok(HashMap::new()),
        };

        // Request values via publisher
        let log = self.0.log.fork(ea!(addr = resp.addr, action = "publisher_request"));

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
                if publisher_cert_hash(cert.public_key().raw) != self.hash {
                    return Err(rustls::Error::InvalidCertificateSignature);
                }
                return Ok(ServerCertVerified::assertion());
            }
        }

        let pub_resp =
            reqwest::ClientBuilder::new()
                .use_preconfigured_tls(
                    rustls::ClientConfig::builder()
                        .with_safe_defaults()
                        .with_custom_certificate_verifier(SingleKeyVerifier::new(resp.cert_hash))
                        .with_no_client_auth(),
                )
                .build()
                .unwrap()
                .get(format!("https://{}/{}?{}", resp.addr, ident, keys.join(",")))
                .send()
                .await
                .log_context(&log, "Error sending request", ea!())?;
        let status = pub_resp.status();
        let pub_resp_bytes = pub_resp.bytes().await.log_context(&log, "Error reading response body", ea!())?.to_vec();
        if status.is_client_error() || status.is_server_error() {
            return Err(
                log.new_err(
                    "Publisher responded with error code",
                    ea!(status = status, body = String::from_utf8_lossy(&pub_resp_bytes)),
                ),
            );
        }
        let kvs: publish::ResolveKeyValues =
            serde_json::from_slice(&pub_resp_bytes).log_context(&log, "Couldn't parse response", ea!())?;

        // Store found values
        spawn({
            let kvs = kvs.clone();
            let cache = self.0.cache.clone();
            let identity = ident.clone();
            async move {
                match &kvs {
                    publish::ResolveKeyValues::V1(kvs) => {
                        for (k, v) in &kvs.0 {
                            cache.insert((identity.clone(), k.to_owned()), (v.expires, v.data.clone())).await;
                        }
                    },
                }
            }
        });

        // Respond with found values
        match kvs {
            ResolveKeyValues::V1(kvs) => {
                return Ok(kvs.0);
            },
        }
    }
}

pub async fn start(tm: &TaskManager, log: &Log, config: ResolverConfig, node: Node) -> Result<(), loga::Error> {
    let cache = Cache::builder().weigher(|_key, pair: &(DateTime<Utc>, String)| -> u32 {
        pair.1.len().try_into().unwrap_or(u32::MAX)
    }).max_capacity(config.max_cache.unwrap_or(64 * 1024 * 1024)).build();

    // Seed with stored cache data
    if let Some(p) = &config.cache_path {
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

    // Launch core
    let core = {
        let log = log.fork(ea!(subsys = "core"));
        let core = Core(Arc::new(CoreInner {
            node: node,
            log: log.clone(),
            cache: cache.clone(),
        }));

        // Bg core cleanup
        if let Some(p) = &config.cache_path {
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
                            db::push(db, &k.0, &k.1, v.0, &v.1)?;
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
        core
    };

    // Launch resolver server
    if let Some(bind_addr) = config.bind_addr {
        struct ResolverEndpoint(Core);

        #[async_trait]
        impl Endpoint for ResolverEndpoint {
            type Output = Response;

            async fn call(&self, req: Request) -> poem::Result<Self::Output> {
                match aes!({
                    let kvs =
                        self
                            .0
                            .get(
                                &Identity::from_str(req.uri().path().get(1..).unwrap_or(""))?,
                                &req.uri().query().unwrap_or("").split(",").collect_vec(),
                            )
                            .await?;
                    return Ok(ResolveKeyValues::V1(model::publish::v1::ResolveKeyValues(kvs)));
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

        let tm1 = tm.clone();
        let core1 = core.clone();
        tm.critical_task::<_, loga::Error>(async move {
            match tm1
                .if_alive(Server::new(TcpListener::bind(bind_addr)).run(get(ResolverEndpoint(core1))))
                .await {
                Some(r) => {
                    r?;
                },
                None => { },
            };
            return Ok(());
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
                let self1 = self.0.clone();
                match aes!({
                    match aes2!({
                        if request.query().query_class() != DNSClass::IN {
                            return Ok(None);
                        }
                        if request.query().name().base_name() != self1.expect_suffix {
                            return Ok(None);
                        }
                        if request.query().name().len() != 2 {
                            return Err(
                                loga::Error::new(
                                    "Wrong number of parts in request",
                                    ea!(name = request.query().name()),
                                ),
                            ).err_external();
                        }
                        let query_name = Name::from(request.query().name());
                        let ident_part = query_name.iter().next().unwrap();
                        let ident =
                            Identity::from_bytes(
                                &zbase32::decode_full_bytes(ident_part)
                                    .map_err(
                                        |e| loga::Error::new("Wrong number of parts in request", ea!(ident = e)),
                                    )
                                    .err_external()?,
                            )
                                .context(
                                    "Couldn't parse ident in request",
                                    ea!(ident = String::from_utf8_lossy(&ident_part)),
                                )
                                .err_external()?;
                        let (lookup_key, batch_keys) = match request.query().query_type() {
                            trust_dns_client::rr::RecordType::A => (KEY_DNS_A, COMMON_KEYS_DNS),
                            trust_dns_client::rr::RecordType::AAAA => (KEY_DNS_AAAA, COMMON_KEYS_DNS),
                            trust_dns_client::rr::RecordType::CNAME => (KEY_DNS_CNAME, COMMON_KEYS_DNS),
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
                        let res = self1.core.get(&ident, batch_keys).await.err_internal()?;
                        let mut answers = vec![];
                        if let Some(res) = res.get(KEY_DNS_CNAME).or_else(|| res.get(lookup_key)) {
                            for rec in serde_json::from_str::<DnsRecordsetJson>(&res.data)
                                .context("Failed to parse received record json", ea!())
                                .err_external()?
                                .0 {
                                match rec {
                                    DnsRecordJson::Cname(n) => {
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
                                                res
                                                    .expires
                                                    .signed_duration_since(Utc::now())
                                                    .num_seconds()
                                                    .try_into()
                                                    .unwrap_or(i32::MAX as u32),
                                                trust_dns_client::rr::RData::CNAME(n),
                                            ),
                                        );
                                    },
                                }
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
                        Err(e) => {
                            match e {
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
                            }
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
                    AsyncClient::connect(UdpClientStream::<UdpSocket>::new(dns_config.upstream))
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
                    UdpSocket::bind(&dns_config.bind_addr)
                        .await
                        .log_context(&log, "Opening UDP listener failed", ea!(socket = dns_config.bind_addr))?,
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
