use crate::{
    interface::{
        identity::Identity,
        spagh_api::{
            resolve::{
                self,
                KEY_DNS_CNAME,
                KEY_DNS_TXT,
                KEY_DNS_MX,
                COMMON_KEYS_DNS,
                KEY_DNS_A,
                KEY_DNS_AAAA,
            },
        },
    },
    resolver::{
        config::DnsType,
    },
};
use crate::utils::{
    ResultVisErr,
    VisErr,
};
use chrono::{
    Duration,
    Utc,
};
use futures::StreamExt;
use hickory_proto::{
    rr::{
        rdata::{
            CNAME,
            AAAA,
            A,
            TXT,
            MX,
        },
        LowerName,
        RData,
        RecordType,
        DNSClass,
        Record,
        domain::Label,
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
        NameServerConfig,
        NameServerConfigGroup,
        ResolverOpts,
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
    Log,
    ResultContext,
    DebugDisplay,
};
use poem::async_trait;
use rustls::{
    Certificate,
    PrivateKey,
};
use std::{
    net::{
        Ipv4Addr,
        Ipv6Addr,
        IpAddr,
    },
    str::FromStr,
    sync::Arc,
};
use taskmanager::TaskManager;
use tokio::{
    net::{
        UdpSocket,
        TcpListener,
    },
    fs::read,
};
use hickory_server::{
    authority::MessageResponseBuilder,
    server::ResponseInfo,
};
use super::{
    Resolver,
    config::DnsBridgeConfig,
};

pub async fn start_dns_bridge(
    log: &loga::Log,
    tm: &TaskManager,
    resolver: &Resolver,
    global_addrs: &[IpAddr],
    dns_config: DnsBridgeConfig,
) -> Result<(), loga::Error> {
    struct HandlerInner {
        log: Log,
        resolver: Resolver,
        upstream: NameServerPool<TokioConnectionProvider>,
        expect_suffix: LowerName,
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
                if false {
                    // Type assertion
                    return Err(loga::new_err("")).err_internal() as Result<ResponseInfo, VisErr>;
                }
                if request.query().query_class() == DNSClass::IN &&
                    request.query().name().base_name() == self1.expect_suffix {
                    self.0.log.debug("Received spagh request", ea!(request = request.dbg_str()));
                    if request.query().name().num_labels() != 2 {
                        return Err(
                            loga::new_err_with(
                                "Expected two parts in request (id., s.) but got different number",
                                ea!(name = request.query().name(), count = request.query().name().num_labels()),
                            ),
                        ).err_external();
                    }
                    let query_name = Name::from(request.query().name());
                    let ident_part = query_name.iter().next().unwrap();
                    let ident =
                        Identity::from_bytes(&zbase32::decode_full_bytes(ident_part).map_err(|e| {
                            loga::new_err_with("Wrong number of parts in request", ea!(ident = e))
                        }).err_external()?)
                            .context_with(
                                "Couldn't parse ident in request",
                                ea!(ident = String::from_utf8_lossy(&ident_part)),
                            )
                            .err_external()?;
                    let (lookup_key, batch_keys) = match request.query().query_type() {
                        RecordType::A => (KEY_DNS_A, COMMON_KEYS_DNS),
                        RecordType::AAAA => {
                            (KEY_DNS_AAAA, COMMON_KEYS_DNS)
                        },
                        RecordType::CNAME => {
                            (KEY_DNS_CNAME, COMMON_KEYS_DNS)
                        },
                        RecordType::TXT => (KEY_DNS_TXT, COMMON_KEYS_DNS),
                        RecordType::MX => (KEY_DNS_MX, COMMON_KEYS_DNS),
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
                    let mut res = self1.resolver.get(&ident, batch_keys).await.err_internal()?;
                    let mut answers = vec![];
                    let filter_some = |v: resolve::latest::ResolveValue| match v.data {
                        Some(v1) => Some((v.expires, v1)),
                        None => None,
                    };
                    if let Some((expires, data)) =
                        res
                            .remove(KEY_DNS_CNAME)
                            .map(filter_some)
                            .flatten()
                            .or_else(|| res.remove(lookup_key).map(filter_some).flatten()) {
                        match serde_json::from_str::<resolve::DnsRecordsetJson>(&data)
                            .context("Failed to parse received record json")
                            .err_external()? {
                            resolve::DnsRecordsetJson::V1(v) => match v {
                                resolve::latest::DnsRecordsetJson::A(n) => {
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
                                                RData::A(A(n)),
                                            ),
                                        );
                                    }
                                },
                                resolve::latest::DnsRecordsetJson::Aaaa(n) => {
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
                                                RData::AAAA(AAAA(n)),
                                            ),
                                        );
                                    }
                                },
                                resolve::latest::DnsRecordsetJson::Cname(n) => {
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
                                                RData::CNAME(CNAME(n)),
                                            ),
                                        );
                                    }
                                },
                                resolve::latest::DnsRecordsetJson::Txt(n) => {
                                    for n in n {
                                        answers.push(
                                            Record::from_rdata(
                                                request.query().name().into(),
                                                expires
                                                    .signed_duration_since(Utc::now())
                                                    .num_seconds()
                                                    .try_into()
                                                    .unwrap_or(i32::MAX as u32),
                                                RData::TXT(TXT::new(vec![n])),
                                            ),
                                        );
                                    }
                                },
                                resolve::latest::DnsRecordsetJson::Mx(n) => {
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
                                                RData::MX(MX::new(n.0, exchange)),
                                            ),
                                        );
                                    }
                                },
                            },
                        }
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
                        .debug("Received non-spagh request, forwarding upstream", ea!(request = request.dbg_str()));
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
                            let resp = resp.err_external()?;
                            let soa = match resp.soa() {
                                Some(r) => {
                                    let mut r2 = Record::new();
                                    r2
                                        .set_name(r.name().clone())
                                        .set_rr_type(r.record_type())
                                        .set_dns_class(r.dns_class())
                                        .set_ttl(r.ttl())
                                        .set_data(r.data().map(|x| hickory_proto::rr::RData::SOA(x.clone())));
                                    Some(r2)
                                },
                                None => None,
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
                                            soa.as_ref(),
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
                            self1.log.debug_e(e, "Request failed due to requester issue", ea!());
                            match response_handle
                                .send_response(
                                    MessageResponseBuilder::from_message_request(
                                        request,
                                    ).error_msg(request.header(), ResponseCode::FormErr),
                                )
                                .await {
                                Ok(r) => return r,
                                Err(e) => {
                                    self1.log.warn_e(e.into(), "Failed to send error response", ea!());
                                    return ResponseInfo::from(*request.header());
                                },
                            };
                        },
                        VisErr::Internal(e) => {
                            self1.log.warn_e(e, "Request failed due to internal issue", ea!());
                            match response_handle
                                .send_response(
                                    MessageResponseBuilder::from_message_request(
                                        request,
                                    ).error_msg(request.header(), ResponseCode::ServFail),
                                )
                                .await {
                                Ok(r) => return r,
                                Err(e) => {
                                    self1.log.warn_e(e.into(), "Failed to send error response", ea!());
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
        let mut name_servers = NameServerConfigGroup::new();
        name_servers.push({
            let mut c =
                NameServerConfig::new(
                    dns_config.upstream.1,
                    match (dns_config.upstream_type, dns_config.upstream.1.port()) {
                        (Some(DnsType::Udp), _) | (None, 53) => {
                            hickory_resolver::config::Protocol::Udp
                        },
                        (Some(DnsType::Tls), _) | (None, 853) => {
                            hickory_resolver::config::Protocol::Tls
                        },
                        _ => {
                            return Err(
                                log.new_err_with(
                                    "Unable to guess upstream DNS protocol from port number, please specify explicitly with `upstream_type`",
                                    ea!(port = dns_config.upstream.1.port()),
                                ),
                            );
                        },
                    },
                );
            c.tls_dns_name = Some(dns_config.upstream.1.ip().to_string());
            c
        });
        NameServerPool::from_config(
            name_servers,
            ResolverOpts::default(),
            GenericConnector::new(TokioRuntimeProvider::new()),
        )
    };
    let mut server = hickory_server::ServerFuture::new(Handler(Arc::new(HandlerInner {
        log: log.clone(),
        resolver: resolver.clone(),
        upstream: upstream,
        expect_suffix: LowerName::new(&Name::from_labels(&[Label::from_utf8("s").unwrap()]).unwrap()),
    })));
    for bind_addr in &dns_config.udp_bind_addrs {
        server.register_socket(
            UdpSocket::bind(&bind_addr.1)
                .await
                .log_context_with(&log, "Opening UDP listener failed", ea!(socket = bind_addr.1))?,
        );
    }
    for bind_addr in &dns_config.tcp_bind_addrs {
        server.register_listener(
            TcpListener::bind(&bind_addr.1)
                .await
                .log_context_with(&log, "Opening TCP listener failed", ea!(socket = bind_addr.1))?,
            Duration::seconds(10).to_std().unwrap(),
        );
    }
    if let Some(tls) = dns_config.tls {
        let log = log.fork(ea!(subsys = "dot-tls-acme", names = global_addrs.dbg_str()));
        let log = &log;
        for bind_addr in &tls.bind_addrs {
            server
                .register_tls_listener_with_tls_config(
                    TcpListener::bind(&bind_addr.1)
                        .await
                        .log_context_with(&log, "Opening TCP listener failed", ea!(socket = bind_addr.1))?,
                    Duration::seconds(10).to_std().unwrap(),
                    Arc::new(
                        rustls::ServerConfig::builder()
                            .with_safe_defaults()
                            .with_no_client_auth()
                            .with_single_cert(
                                rustls_pemfile::certs(
                                    &mut read(&tls.pub_pem_path)
                                        .await
                                        .log_context_with(
                                            log,
                                            "Unable to read public cert PEM file at",
                                            ea!(path = tls.pub_pem_path.to_string_lossy()),
                                        )?
                                        .as_ref(),
                                )
                                    .log_context(log, "Error reading public certs from PEM")?
                                    .into_iter()
                                    .map(Certificate)
                                    .collect(),
                                rustls_pemfile::pkcs8_private_keys(
                                    &mut read(&tls.priv_pem_path)
                                        .await
                                        .log_context_with(
                                            log,
                                            "Unable to read private key PEM file",
                                            ea!(path = tls.priv_pem_path.to_string_lossy()),
                                        )?
                                        .as_ref(),
                                )
                                    .log_context(log, "Error reading private certs from PEM")?
                                    .into_iter()
                                    .map(PrivateKey)
                                    .next()
                                    .log_context(log, "No private key found in private key PEM file")?,
                            )
                            .log_context(log, "Error setting up cert for DoT server")?,
                    ),
                )
                .log_context_with(log, "Error registering TLS listener", ea!(bind_addr = bind_addr))?;
        }
    }
    tm.critical_task::<_, loga::Error>({
        let log = log.fork(ea!(subsys = "dns"));
        let tm1 = tm.clone();
        async move {
            match tm1.if_alive(server.block_until_done()).await {
                Some(r) => {
                    r.log_context(&log, "Server exited with error")?;
                },
                None => { },
            };
            return Ok(());
        }
    });
    return Ok(());
}
