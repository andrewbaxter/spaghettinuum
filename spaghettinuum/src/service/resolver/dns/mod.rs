use {
    super::Resolver,
    crate::{
        interface::{
            config::node::resolver_config::DnsBridgeConfig,
            stored::{
                self,
                record::{
                    dns_record::{
                        format_dns_key,
                        COMMON_HTTP_RECORD_TYPES,
                    },
                },
                identity::Identity,
            },
            wire,
        },
        ta_res,
        ta_vis_res,
        utils::{
            db_util::setup_db,
            ResultVisErr,
            VisErr,
        },
    },
    async_trait::async_trait,
    chrono::{
        Duration,
        Utc,
    },
    futures::StreamExt,
    hickory_proto::{
        op::{
            Header,
            Message,
            MessageParts,
            Query,
            ResponseCode,
        },
        rr::{
            rdata::{
                A,
                AAAA,
                CNAME,
                MX,
                TXT,
            },
            DNSClass,
            RData,
            Record,
            RecordType,
        },
        xfer::{
            DnsHandle,
            DnsRequest,
            DnsRequestOptions,
        },
    },
    hickory_resolver::{
        config::NameServerConfigGroup,
        name_server::{
            GenericConnector,
            NameServerPool,
            TokioConnectionProvider,
            TokioRuntimeProvider,
        },
        Name,
    },
    hickory_server::{
        authority::MessageResponseBuilder,
        server::{
            Request,
            ResponseInfo,
        },
    },
    loga::{
        ea,
        DebugDisplay,
        ErrContext,
        Log,
        ResultContext,
    },
    std::{
        path::Path,
        sync::{
            Arc,
        },
    },
    taskmanager::TaskManager,
    tokio::{
        net::{
            TcpListener,
            UdpSocket,
        },
        select,
    },
};

pub mod db;

pub async fn start_dns_bridge(
    log: &Log,
    tm: &TaskManager,
    resolver: &Resolver,
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
                    self.0.log.log_with(loga::DEBUG, "Received spagh request", ea!(request = request.dbg_str()));
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
                            record_type_key = stored::record::dns_record::RecordType::Cname;
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
                            record_type_key = stored::record::dns_record::RecordType::A;
                            batch_record_type_keys = COMMON_HTTP_RECORD_TYPES;

                            fn handler(
                                _log: &Log,
                                request: &Request,
                                answers: &mut Vec<Record>,
                                expires: u32,
                                data: serde_json::Value,
                            ) -> Result<(), VisErr> {
                                match serde_json::from_value::<stored::record::dns_record::DnsA>(data.clone())
                                    .context_with("Failed to parse received record json", ea!(json = data))
                                    .err_external()? {
                                    stored::record::dns_record::DnsA::V1(n) => {
                                        for n in n.0 {
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
                            record_type_key = stored::record::dns_record::RecordType::Aaaa;
                            batch_record_type_keys = COMMON_HTTP_RECORD_TYPES;

                            fn handler(
                                _log: &Log,
                                request: &Request,
                                answers: &mut Vec<Record>,
                                expires: u32,
                                data: serde_json::Value,
                            ) -> Result<(), VisErr> {
                                match serde_json::from_value::<stored::record::dns_record::DnsAaaa>(data.clone())
                                    .context_with("Failed to parse received record json", ea!(json = data))
                                    .err_external()? {
                                    stored::record::dns_record::DnsAaaa::V1(n) => {
                                        for n in n.0 {
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
                            record_type_key = stored::record::dns_record::RecordType::Txt;
                            batch_record_type_keys = COMMON_HTTP_RECORD_TYPES;

                            fn handler(
                                _log: &Log,
                                request: &Request,
                                answers: &mut Vec<Record>,
                                expires: u32,
                                data: serde_json::Value,
                            ) -> Result<(), VisErr> {
                                match serde_json::from_value::<stored::record::dns_record::DnsTxt>(data.clone())
                                    .context_with("Failed to parse received record json", ea!(json = data))
                                    .err_external()? {
                                    stored::record::dns_record::DnsTxt::V1(n) => {
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
                            record_type_key = stored::record::dns_record::RecordType::Mx;
                            batch_record_type_keys = COMMON_HTTP_RECORD_TYPES;

                            fn handler(
                                log: &Log,
                                request: &Request,
                                answers: &mut Vec<Record>,
                                expires: u32,
                                data: serde_json::Value,
                            ) -> Result<(), VisErr> {
                                match serde_json::from_value::<stored::record::dns_record::DnsMx>(data.clone())
                                    .context_with("Failed to parse received record json", ea!(json = data))
                                    .err_external()? {
                                    stored::record::dns_record::DnsMx::V1(n) => {
                                        for (i, n) in n.0.into_iter().enumerate() {
                                            let n = match Name::from_utf8(&n) {
                                                Err(e) => {
                                                    log.log_err(
                                                        loga::DEBUG,
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
                            .remove(&format_dns_key(&subdomain, stored::record::dns_record::RecordType::Cname))
                            .and_then(filter_some) {
                        match serde_json::from_value::<stored::record::dns_record::DnsCname>(data.clone())
                            .context_with("Failed to parse received record json", ea!(json = data))
                            .err_external()? {
                            stored::record::dns_record::DnsCname::V1(n) => {
                                for n in n.0 {
                                    let n = match Name::from_utf8(&n) {
                                        Err(e) => {
                                            self1
                                                .log
                                                .log_err(
                                                    loga::DEBUG,
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
                    self.0.log.log_with(loga::DEBUG, "Received non-spagh request", ea!(request = request.dbg_str()));
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
                            self1.log.log_err(loga::DEBUG, e.context("Request failed due to external issue"));
                            match response_handle
                                .send_response(
                                    MessageResponseBuilder::from_message_request(
                                        request,
                                    ).error_msg(request.header(), ResponseCode::FormErr),
                                )
                                .await {
                                Ok(r) => return r,
                                Err(e) => {
                                    self1.log.log_err(loga::WARN, e.context("Failed to send error response"));
                                    return ResponseInfo::from(*request.header());
                                },
                            };
                        },
                        VisErr::Internal(e) => {
                            self1.log.log_err(loga::WARN, e.context("Request failed due to internal issue"));
                            match response_handle
                                .send_response(
                                    MessageResponseBuilder::from_message_request(
                                        request,
                                    ).error_msg(request.header(), ResponseCode::ServFail),
                                )
                                .await {
                                Ok(r) => return r,
                                Err(e) => {
                                    self1.log.log_err(loga::WARN, e.context("Failed to send error response"));
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
    for bind_addr in &dns_config.tcp_bind_addrs {
        let bind_addr = bind_addr.resolve()?;
        server.register_listener(
            TcpListener::bind(&bind_addr)
                .await
                .stack_context_with(&log, "Opening TCP listener failed", ea!(socket = bind_addr))?,
            Duration::seconds(10).to_std().unwrap(),
        );
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
