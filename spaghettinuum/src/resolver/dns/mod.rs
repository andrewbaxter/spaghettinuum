use crate::{
    bb,
    interface::{
        config::node::resolver_config::DnsBridgeConfig,
        stored::{
            self,
            dns_record::{
                format_dns_key,
                COMMON_HTTP_RECORD_TYPES,
            },
            identity::Identity,
        },
        wire,
    },
    ta_res,
    ta_vis_res,
    utils::{
        db_util::{
            setup_db,
            DbTx,
        },
        tls_util::{
            rustls21_load_certified_key,
            extract_expiry,
            encode_priv_pem,
        },
        log::{
            Log,
            DEBUG_DNS_S,
            DEBUG_DNS_NONS,
            DEBUG_DNS,
            WARN,
            INFO,
        },
        time_util::ToInstant,
    },
};
use crate::utils::{
    ResultVisErr,
    VisErr,
};
use chrono::{
    Duration,
    Utc,
    DateTime,
};
use futures::StreamExt;
use hickory_proto::{
    rr::{
        rdata::{
            A,
            AAAA,
            CNAME,
            MX,
            TXT,
        },
        RData,
        RecordType,
        DNSClass,
        Record,
    },
    xfer::{
        DnsHandle,
        DnsRequest,
        DnsRequestOptions,
    },
    op::{
        Message,
        Query,
        MessageParts,
        Header,
        ResponseCode,
    },
};
use hickory_resolver::{
    config::{
        NameServerConfigGroup,
    },
    name_server::{
        TokioConnectionProvider,
        NameServerPool,
        TokioRuntimeProvider,
        GenericConnector,
    },
    Name,
};
use loga::{
    ea,
    ResultContext,
    DebugDisplay,
    ErrContext,
};
use poem::{
    async_trait,
    listener::acme::{
        EABCreds,
        ACME_KEY_ALG,
        AcmeClient,
        create_acme_account,
        Http01Endpoint,
        ChallengeTypeParameters,
        Http01TokensMap,
    },
    RouteScheme,
    Server,
};
use std::{
    net::{
        Ipv4Addr,
        Ipv6Addr,
        IpAddr,
        SocketAddr,
        SocketAddrV4,
        SocketAddrV6,
    },
    str::FromStr,
    sync::{
        Arc,
        Mutex,
    },
    path::Path,
};
use taskmanager::TaskManager;
use tokio::{
    net::{
        UdpSocket,
        TcpListener,
    },
    select,
    time::{
        sleep,
        sleep_until,
    },
};
use hickory_server::{
    authority::MessageResponseBuilder,
    server::{
        Request,
        ResponseInfo,
    },
};
use super::{
    Resolver,
};

pub mod db;

struct DotCertHandler(Arc<Mutex<Option<Arc<rustls_21::sign::CertifiedKey>>>>);

impl rustls_21::server::ResolvesServerCert for DotCertHandler {
    fn resolve(&self, _client_hello: rustls_21::server::ClientHello) -> Option<Arc<rustls_21::sign::CertifiedKey>> {
        return self.0.lock().unwrap().clone();
    }
}

pub async fn start_dns_bridge(
    log: &Log,
    tm: &TaskManager,
    resolver: &Resolver,
    global_addrs: &[IpAddr],
    dns_config: DnsBridgeConfig,
    persistent_dir: &Path,
) -> Result<(), loga::Error> {
    let log = log.fork(ea!(sys = "dns"));
    let log = &log;
    let db_pool =
        setup_db(&persistent_dir.join("resolver_dns_bridge.sqlite3"), db::migrate)
            .await
            .stack_context(log, "Error initializing database")?;
    db_pool.get().await?.interact(|conn| db::dot_certs_setup(conn)).await??;

    struct HandlerInner {
        log: Log,
        resolver: Resolver,
        upstream: NameServerPool<TokioConnectionProvider>,
    }

    struct Handler(Arc<HandlerInner>);

    #[async_trait]
    impl hickory_server::server::RequestHandler for Handler {
        async fn handle_request<
            R: hickory_server::server::ResponseHandler,
        >(
            &self,
            request: &hickory_server::server::Request,
            mut response_handle: R,
        ) -> hickory_server::server::ResponseInfo {
            let self1 = self.0.clone();
            match async {
                ta_vis_res!(ResponseInfo);
                let query_name = Name::from(request.query().name());
                let mut query_name_parts = query_name.iter().collect::<Vec<_>>();
                query_name_parts.reverse();
                let mut query_name_iter = query_name_parts.iter().map(|x| *x);
                let root = query_name_iter.next();
                if request.query().query_class() == DNSClass::IN && (match root {
                    Some(b"s") | Some(b"s.") => true,
                    _ => false,
                }) {
                    self.0.log.log_with(DEBUG_DNS_S, "Received spagh request", ea!(request = request.dbg_str()));
                    let Some(ident_part) = query_name_iter.next() else {
                        return Err(
                            loga::err_with(
                                "Expected at least two parts in request (ident, .s) but got different number",
                                ea!(name = request.query().name(), count = request.query().name().num_labels()),
                            ),
                        ).err_external();
                    };
                    let ident =
                        Identity::from_bytes(&zbase32::decode_full_bytes(ident_part).map_err(|e| {
                            loga::err_with("Wrong number of parts in request", ea!(ident = e))
                        }).err_external()?)
                            .context_with(
                                "Couldn't parse ident in request",
                                ea!(ident = String::from_utf8_lossy(&ident_part)),
                            )
                            .err_external()?;
                    let mut subdomain =
                        query_name_iter.map(|x| format!("{}.", String::from_utf8_lossy(x))).collect::<Vec<_>>();
                    if subdomain.is_empty() {
                        subdomain.push(".".to_string());
                    }
                    subdomain.reverse();
                    let subdomain = subdomain.join("");
                    let record_type_key;
                    let batch_record_type_keys;
                    let record_type_handler:
                        fn(
                            log: &Log,
                            request: &Request,
                            answers: &mut Vec<Record>,
                            expires: u32,
                            data: serde_json::Value,
                        ) -> Result<(), VisErr>;
                    match request.query().query_type() {
                        RecordType::CNAME => {
                            record_type_key = stored::dns_record::RecordType::Cname;
                            batch_record_type_keys = COMMON_HTTP_RECORD_TYPES;

                            fn handler(
                                _log: &Log,
                                _request: &Request,
                                _answers: &mut Vec<Record>,
                                _expires: u32,
                                _data: serde_json::Value,
                            ) -> Result<(), VisErr> {
                                unreachable!();
                            }

                            record_type_handler = handler;
                        },
                        RecordType::A => {
                            record_type_key = stored::dns_record::RecordType::A;
                            batch_record_type_keys = COMMON_HTTP_RECORD_TYPES;

                            fn handler(
                                log: &Log,
                                request: &Request,
                                answers: &mut Vec<Record>,
                                expires: u32,
                                data: serde_json::Value,
                            ) -> Result<(), VisErr> {
                                match serde_json::from_value::<stored::dns_record::DnsA>(data.clone())
                                    .context_with("Failed to parse received record json", ea!(json = data))
                                    .err_external()? {
                                    stored::dns_record::DnsA::V1(n) => {
                                        for n in n.0 {
                                            let n = match Ipv4Addr::from_str(&n) {
                                                Err(e) => {
                                                    log.log_err(
                                                        DEBUG_DNS_S,
                                                        e.context_with("Ipv4 addr in record invalid", ea!(name = n)),
                                                    );
                                                    continue;
                                                },
                                                Ok(n) => n,
                                            };
                                            answers.push(
                                                Record::from_rdata(
                                                    request.query().name().into(),
                                                    expires,
                                                    RData::A(A(n)),
                                                ),
                                            );
                                        }
                                    },
                                }
                                return Ok(());
                            }

                            record_type_handler = handler;
                        },
                        RecordType::AAAA => {
                            record_type_key = stored::dns_record::RecordType::Aaaa;
                            batch_record_type_keys = COMMON_HTTP_RECORD_TYPES;

                            fn handler(
                                log: &Log,
                                request: &Request,
                                answers: &mut Vec<Record>,
                                expires: u32,
                                data: serde_json::Value,
                            ) -> Result<(), VisErr> {
                                match serde_json::from_value::<stored::dns_record::DnsAaaa>(data.clone())
                                    .context_with("Failed to parse received record json", ea!(json = data))
                                    .err_external()? {
                                    stored::dns_record::DnsAaaa::V1(n) => {
                                        for n in n.0 {
                                            let n = match Ipv6Addr::from_str(&n) {
                                                Err(e) => {
                                                    log.log_err(
                                                        DEBUG_DNS_S,
                                                        e.context_with(
                                                            "Ipv6 addr in AAAA record invalid",
                                                            ea!(name = n),
                                                        ),
                                                    );
                                                    continue;
                                                },
                                                Ok(n) => n,
                                            };
                                            answers.push(
                                                Record::from_rdata(
                                                    request.query().name().into(),
                                                    expires,
                                                    RData::AAAA(AAAA(n)),
                                                ),
                                            );
                                        }
                                    },
                                }
                                return Ok(());
                            }

                            record_type_handler = handler;
                        },
                        RecordType::TXT => {
                            record_type_key = stored::dns_record::RecordType::Txt;
                            batch_record_type_keys = COMMON_HTTP_RECORD_TYPES;

                            fn handler(
                                _log: &Log,
                                request: &Request,
                                answers: &mut Vec<Record>,
                                expires: u32,
                                data: serde_json::Value,
                            ) -> Result<(), VisErr> {
                                match serde_json::from_value::<stored::dns_record::DnsA>(data.clone())
                                    .context_with("Failed to parse received record json", ea!(json = data))
                                    .err_external()? {
                                    stored::dns_record::DnsA::V1(n) => {
                                        for n in n.0 {
                                            answers.push(
                                                Record::from_rdata(
                                                    request.query().name().into(),
                                                    expires,
                                                    RData::TXT(TXT::new(vec![n])),
                                                ),
                                            );
                                        }
                                    },
                                }
                                return Ok(());
                            }

                            record_type_handler = handler;
                        },
                        RecordType::MX => {
                            record_type_key = stored::dns_record::RecordType::Mx;
                            batch_record_type_keys = COMMON_HTTP_RECORD_TYPES;

                            fn handler(
                                log: &Log,
                                request: &Request,
                                answers: &mut Vec<Record>,
                                expires: u32,
                                data: serde_json::Value,
                            ) -> Result<(), VisErr> {
                                match serde_json::from_value::<stored::dns_record::DnsMx>(data.clone())
                                    .context_with("Failed to parse received record json", ea!(json = data))
                                    .err_external()? {
                                    stored::dns_record::DnsMx::V1(n) => {
                                        for (i, n) in n.0.into_iter().enumerate() {
                                            let n = match Name::from_utf8(&n) {
                                                Err(e) => {
                                                    log.log_err(
                                                        DEBUG_DNS_S,
                                                        e.context_with(
                                                            "Mx name in record invalid for DNS",
                                                            ea!(name = n),
                                                        ),
                                                    );
                                                    continue;
                                                },
                                                Ok(n) => n,
                                            };
                                            answers.push(
                                                Record::from_rdata(
                                                    request.query().name().into(),
                                                    expires,
                                                    RData::MX(MX::new(i as u16, n)),
                                                ),
                                            );
                                        }
                                    },
                                }
                                return Ok(());
                            }

                            record_type_handler = handler;
                        },
                        _ => {
                            // Unsupported key pairs
                            return Ok(
                                response_handle
                                    .send_response(
                                        MessageResponseBuilder::from_message_request(
                                            request,
                                        ).build_no_records(Header::response_from_request(request.header())),
                                    )
                                    .await
                                    .context("Error sending response")
                                    .err_internal()?,
                            );
                        },
                    };
                    let mut res =
                        match self1
                            .resolver
                            .get(
                                &ident,
                                &batch_record_type_keys
                                    .iter()
                                    .map(|k| format_dns_key(&subdomain, *k))
                                    .collect::<Vec<_>>(),
                            )
                            .await
                            .err_internal()? {
                            wire::resolve::ResolveKeyValues::V1(v) => v,
                        };
                    let mut answers = vec![];
                    let filter_some = |v: wire::resolve::latest::ResolveValue| match v.data {
                        Some(d) => Some((v.expires, d)),
                        None => None,
                    };
                    if let Some((expires, data)) =
                        res
                            .remove(&format_dns_key(&subdomain, stored::dns_record::RecordType::Cname))
                            .and_then(filter_some) {
                        match serde_json::from_value::<stored::dns_record::DnsCname>(data.clone())
                            .context_with("Failed to parse received record json", ea!(json = data))
                            .err_external()? {
                            stored::dns_record::DnsCname::V1(n) => {
                                for n in n.0 {
                                    let n = match Name::from_utf8(&n) {
                                        Err(e) => {
                                            self1
                                                .log
                                                .log_err(
                                                    DEBUG_DNS_S,
                                                    e.context_with(
                                                        "Cname name in record invalid for DNS",
                                                        ea!(name = n),
                                                    ),
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
                                            RData::CNAME(CNAME(n)),
                                        ),
                                    );
                                }
                            },
                        }
                    } else if let Some((expires, data)) =
                        res.remove(&format_dns_key(&subdomain, record_type_key)).and_then(filter_some) {
                        record_type_handler(
                            &self1.log,
                            &request,
                            &mut answers,
                            expires
                                .signed_duration_since(Utc::now())
                                .num_seconds()
                                .try_into()
                                .unwrap_or(i32::MAX as u32),
                            data,
                        )?;
                    }
                    return Ok(
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
                            .context("Error sending response")
                            .err_internal()?,
                    );
                } else {
                    self
                        .0
                        .log
                        .log_with(DEBUG_DNS_NONS, "Received non-spagh request", ea!(request = request.dbg_str()));
                    let resp = self1.upstream.send(DnsRequest::new(Message::from(MessageParts {
                        header: *request.header(),
                        queries: vec![{
                            let mut q =
                                Query::query(Name::from(request.query().name()), request.query().query_type());
                            q.set_query_class(request.query().query_class());
                            q
                        }],
                        answers: vec![],
                        name_servers: vec![],
                        additionals: vec![],
                        sig0: vec![],
                        edns: request.edns().cloned(),
                    }), DnsRequestOptions::default())).next().await;
                    match resp {
                        Some(resp) => {
                            let resp = match resp {
                                Ok(r) => r,
                                Err(e) => match e.kind() {
                                    hickory_resolver::error::ResolveErrorKind::NoRecordsFound { soa, .. } => {
                                        return Ok(
                                            response_handle
                                                .send_response(
                                                    MessageResponseBuilder::from_message_request(
                                                        request,
                                                    ).build(
                                                        Header::response_from_request(request.header()),
                                                        &[],
                                                        &[],
                                                        soa
                                                            .as_ref()
                                                            .map(|r| r.clone().into_record_of_rdata())
                                                            .as_ref(),
                                                        &[],
                                                    ),
                                                )
                                                .await
                                                .context("Error returning empty results")
                                                .err_internal()?,
                                        );
                                    },
                                    _ => {
                                        return Err(e).context("Upstream DNS server returned error").err_external();
                                    },
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
                                            resp.soa().map(|r| r.to_owned().into_record_of_rdata()).as_ref(),
                                            resp.additionals(),
                                        ),
                                    )
                                    .await
                                    .context("Error forwarding DNS response")
                                    .err_internal()?,
                            );
                        },
                        None => {
                            return Ok(
                                response_handle
                                    .send_response(
                                        MessageResponseBuilder::from_message_request(
                                            request,
                                        ).build(Header::response_from_request(request.header()), &[], &[], &[], &[]),
                                    )
                                    .await
                                    .context("Error sending empty response")
                                    .err_internal()?,
                            );
                        },
                    };
                }
            }.await {
                Err(e) => {
                    match e {
                        VisErr::External(e) => {
                            self1.log.log_err(DEBUG_DNS_S, e.context("Request failed due to external issue"));
                            match response_handle
                                .send_response(
                                    MessageResponseBuilder::from_message_request(
                                        request,
                                    ).error_msg(request.header(), ResponseCode::FormErr),
                                )
                                .await {
                                Ok(r) => return r,
                                Err(e) => {
                                    self1.log.log_err(WARN, e.context("Failed to send error response"));
                                    return ResponseInfo::from(*request.header());
                                },
                            };
                        },
                        VisErr::Internal(e) => {
                            self1.log.log_err(WARN, e.context("Request failed due to internal issue"));
                            match response_handle
                                .send_response(
                                    MessageResponseBuilder::from_message_request(
                                        request,
                                    ).error_msg(request.header(), ResponseCode::ServFail),
                                )
                                .await {
                                Ok(r) => return r,
                                Err(e) => {
                                    self1.log.log_err(WARN, e.context("Failed to send error response"));
                                    return ResponseInfo::from(*request.header());
                                },
                            };
                        },
                    }
                },
                Ok(info) => {
                    return info;
                },
            }
        }
    }

    let upstream = {
        let (config, options) =
            hickory_resolver
            ::system_conf
            ::read_system_conf().stack_context(
                log,
                "Error reading system dns resolver config for dns bridge upstream",
            )?;
        let mut name_servers = NameServerConfigGroup::new();
        for n in config.name_servers() {
            name_servers.push(n.clone());
        }
        if let Some(client_config) = config.client_config() {
            name_servers = name_servers.with_client_config(client_config.0.clone());
        }
        NameServerPool::from_config(name_servers, options, GenericConnector::new(TokioRuntimeProvider::new()))
    };
    let mut server = hickory_server::ServerFuture::new(Handler(Arc::new(HandlerInner {
        log: log.clone(),
        resolver: resolver.clone(),
        upstream: upstream,
    })));
    for bind_addr in &dns_config.udp_bind_addrs {
        let bind_addr = bind_addr.resolve()?;
        server.register_socket(
            UdpSocket::bind(&bind_addr)
                .await
                .stack_context_with(&log, "Opening UDP listener failed", ea!(socket = bind_addr))?,
        );
    }
    if let Some(tls) = dns_config.tls {
        let log = log.fork(ea!(subsys = "dot-tls-acme", names = global_addrs.dbg_str()));
        let log = &log;
        let cert = Arc::new(Mutex::new(None));
        let cert_expiry = Arc::new(Mutex::new(None));
        let eab = tls.eab.map(|config| EABCreds {
            kid: config.kid,
            hmac_b64: config.hmac_b64,
        });

        // Retrieve stored certs
        let initial_certs = db_pool.tx(|txn| {
            return Ok(db::dot_certs_get(txn)?);
        }).await.stack_context(log, "Error looking up initial certs")?;
        if let Some((pub_pem, priv_pem)) = initial_certs.pub_pem.zip(initial_certs.priv_pem) {
            let expires_at = extract_expiry(pub_pem.as_bytes()).context("Error reading expiry from initial certs")?;
            log.log_with(
                DEBUG_DNS,
                "Loaded existing cert",
                ea!(expiry = <DateTime<Utc>>::from(expires_at).to_rfc3339()),
            );
            (*cert.lock().unwrap()) = Some(rustls21_load_certified_key(pub_pem.as_bytes(), priv_pem.as_bytes())?);
            (*cert_expiry.lock().unwrap()) = Some(expires_at);
        }

        // Start cert refreshing task
        let near_expiry_thresh = Duration::hours(7 * 24);
        tm.critical_task("DNS bridge - DoT cert refresher", {
            let tm = tm.clone();
            let cert = cert.clone();
            let db_pool = db_pool.clone();
            let names = vec![tls.name.clone()];
            let mut acme_client0 = None;
            let mut kid0 = None;
            let log = log.clone();
            async move {
                let log = &log;
                loop {
                    let near_expiry;
                    if let Some(cert_expiry) = cert_expiry.lock().unwrap().clone() {
                        near_expiry = <DateTime<Utc>>::from(cert_expiry) - near_expiry_thresh;
                    } else {
                        near_expiry = Utc::now();
                    }
                    log.log_with(
                        DEBUG_DNS,
                        "Sleeping until time to refresh cert",
                        ea!(deadline = near_expiry.to_rfc3339()),
                    );

                    select!{
                        _ = sleep_until(near_expiry.to_instant()) =>(),
                        _ = tm.until_terminate() => {
                            break;
                        }
                    }

                    log.log(DEBUG_DNS, "Refreshing cert");
                    match async {
                        // Retrieve or create a new key for acme communication
                        let acme_key_pem;
                        match db_pool.tx(move |txn| Ok(db::acme_key_get(txn)?)).await? {
                            Some(key) => {
                                acme_key_pem = key;
                            },
                            None => {
                                let key1 =
                                    poem::listener::acme::EcdsaKeyPair::generate_pkcs8(
                                        ACME_KEY_ALG,
                                        &mut poem::listener::acme::SystemRandom::new(),
                                    ).unwrap();
                                acme_key_pem = encode_priv_pem(key1.as_ref());
                                db_pool.tx({
                                    let acme_key = acme_key_pem.clone();
                                    move |txn| Ok(db::acme_key_set(txn, Some(&acme_key))?)
                                }).await?;
                            },
                        }
                        let acme_key =
                            poem::listener::acme::EncodingKey::from_ec_pem(
                                acme_key_pem.as_bytes(),
                            ).stack_context(log, "Error loading stored acme key")?;

                        // Create acme client with key
                        let acme_client;
                        match acme_client0.as_mut() {
                            Some(c) => {
                                acme_client = c;
                            },
                            None => {
                                acme_client0 =
                                    Some(
                                        AcmeClient::try_new_with_key(
                                            &tls.acme_directory_url,
                                            tls.contacts.clone(),
                                            acme_key,
                                        ).await?,
                                    );
                                acme_client = acme_client0.as_mut().unwrap();
                            },
                        }

                        // Retrieve or get a new kid from the acme provider
                        let kid = bb!{
                            if let Some(k) = &kid0 {
                                break k;
                            }
                            let kid_dir_pair = db_pool.tx(move |txn| Ok(db::acme_key_kid_get(txn)?)).await?;
                            if let (Some(d), Some(k)) = (kid_dir_pair.acme_dir, kid_dir_pair.acme_api_key_kid) {
                                if d == tls.acme_directory_url {
                                    kid0 = Some(k);
                                    break kid0.as_ref().unwrap();
                                }
                            }
                            let k = create_acme_account(&acme_client, eab.as_ref()).await?;
                            db_pool.tx({
                                let k = k.clone();
                                let dir = tls.acme_directory_url.clone();
                                move |txn| Ok(db::acme_key_kid_set(txn, Some(&dir), Some(&k))?)
                            }).await?;
                            kid0 = Some(k);
                            break kid0.as_ref().unwrap();
                        };

                        // Start challenge listener
                        let tokens = Http01TokensMap::new();
                        let subtm = tm.sub("DNS bridge - DoT cert refresher ACME listener");
                        for bind_addr in [
                            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 80)),
                            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 80, 0, 0)),
                        ] {
                            subtm.critical_task(format!("Listener ({})", bind_addr), {
                                let tokens = tokens.clone();
                                let subtm = subtm.clone();
                                async move {
                                    ta_res!(());
                                    Server::new(poem::listener::TcpListener::bind(bind_addr))
                                        .run_with_graceful_shutdown(
                                            RouteScheme::new().http(Http01Endpoint { keys: tokens }),
                                            subtm.until_terminate(),
                                            Some(Duration::seconds(60).to_std().unwrap().into()),
                                        )
                                        .await?;
                                    return Ok(());
                                }
                            });
                        }
                        sleep(Duration::seconds(1).to_std().unwrap()).await;

                        // Initiate verification
                        let res =
                            poem::listener::acme::issue_cert(
                                acme_client,
                                &kid,
                                &names,
                                ChallengeTypeParameters::Http01 { keys_for_http01: &tokens },
                            )
                                .await
                                .context("Error issuing new cert")?;
                        subtm.terminate();
                        if let Err(e) = subtm.join(log, INFO).await {
                            log.log_err(WARN, e.context("Error in one of the ACME challenge listeners"));
                        }
                        (*cert.lock().unwrap()) =
                            Some(
                                rustls21_load_certified_key(
                                    &res.public_pem,
                                    &res.private_pem,
                                ).stack_context(log, "Error loading received new certs")?,
                            );
                        (*cert_expiry.lock().unwrap()) =
                            Some(extract_expiry(&res.public_pem).context("Error reading expiry from new certs")?);
                        let pub_pem =
                            String::from_utf8(res.public_pem).context("Issued public cert PEM is invalid utf-8")?;
                        log.log_with(DEBUG_DNS, "Successfully refreshed certificate", ea!(pub_pem = pub_pem));
                        db_pool.tx(move |txn| {
                            db::dot_certs_set(
                                txn,
                                Some(&pub_pem),
                                Some(
                                    &String::from_utf8(
                                        res.private_pem,
                                    ).context("Issued private key PEM is invalid utf-8")?,
                                ),
                            )?;
                            return Ok(());
                        }).await?;
                        return Ok(()) as Result<_, loga::Error>;
                    }.await {
                        Err(e) => {
                            log.log_err(WARN, e.context("Error getting new TLS cert"));

                            select!{
                                _ = sleep(Duration::minutes(10).to_std().unwrap()) =>(),
                                _ = tm.until_terminate() => {
                                    break;
                                }
                            }
                        },
                        Ok(_) => { },
                    };
                }
                return Ok(()) as Result<_, loga::Error>;
            }
        });
        for bind_addr in &dns_config.tcp_bind_addrs {
            let bind_addr = bind_addr.resolve()?;
            server
                .register_tls_listener_with_tls_config(
                    TcpListener::bind(&bind_addr)
                        .await
                        .stack_context_with(&log, "Opening TCP listener failed", ea!(socket = bind_addr))?,
                    Duration::seconds(10).to_std().unwrap(),
                    Arc::new(
                        rustls_21::ServerConfig::builder()
                            .with_safe_defaults()
                            .with_no_client_auth()
                            .with_cert_resolver(Arc::new(DotCertHandler(cert.clone()))),
                    ),
                )
                .stack_context_with(log, "Error registering TLS listener", ea!(bind_addr = bind_addr))?;
        }
    } else {
        for bind_addr in &dns_config.tcp_bind_addrs {
            let bind_addr = bind_addr.resolve()?;
            server.register_listener(
                TcpListener::bind(&bind_addr)
                    .await
                    .stack_context_with(&log, "Opening TCP listener failed", ea!(socket = bind_addr))?,
                Duration::seconds(10).to_std().unwrap(),
            );
        }
    }
    tm.critical_task("DNS bridge - server", {
        let log = log.clone();
        let tm = tm.clone();
        async move {
            ta_res!(());

            select!{
                _ = tm.until_terminate() => {
                    return Ok(());
                }
                r = server.block_until_done() => {
                    r.stack_context(&log, "Server exited with error")?;
                    return Err(log.err("Server unexpectedly exited"));
                }
            }
        }
    });
    return Ok(());
}
