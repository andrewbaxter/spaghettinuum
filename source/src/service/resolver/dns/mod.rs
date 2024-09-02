use {
    super::Resolver,
    crate::{
        interface::{
            config::{
                node::resolver_config::DnsBridgeConfig,
            },
            stored::{
                self,
                identity::Identity,
                record::{
                    delegate_record::build_delegate_key,
                    dns_record::{
                        build_dns_key,
                        RecordType,
                    },
                    record_utils::{
                        join_dns_name,
                        split_dns_name,
                        RecordKey,
                    },
                },
            },
            wire::{
                self,
            },
        },
        ta_res,
        ta_vis_res,
        utils::{
            ResultVisErr,
            VisErr,
        },
    },
    async_trait::async_trait,
    chrono::{
        Duration,
        Utc,
    },
    flowcontrol::shed,
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
            LowerName,
            RData,
            Record,
        },
        xfer::{
            DnsHandle,
            DnsRequest,
            DnsRequestOptions,
        },
    },
    hickory_resolver::{
        config::{
            NameServerConfig,
            NameServerConfigGroup,
            ResolverOpts,
        },
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
        server::ResponseInfo,
    },
    loga::{
        ea,
        DebugDisplay,
        ErrContext,
        Log,
        ResultContext,
    },
    rand::{
        seq::SliceRandom,
        thread_rng,
    },
    std::{
        collections::HashMap,
        net::{
            IpAddr,
            Ipv4Addr,
            Ipv6Addr,
            SocketAddr,
        },
        str::FromStr,
        sync::Arc,
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

pub async fn start_dns_bridge(
    log: &Log,
    tm: &TaskManager,
    resolver: &Resolver,
    certs: Arc<dyn rustls_21::server::ResolvesServerCert>,
    global_ips: &[IpAddr],
    dns_config: DnsBridgeConfig,
) -> Result<(), loga::Error> {
    struct HandlerInner {
        log: Log,
        resolver: Resolver,
        upstream: NameServerPool<TokioConnectionProvider>,
        synthetic_self_record: Option<LowerName>,
        global_ipv4: Vec<Ipv4Addr>,
        global_ipv6: Vec<Ipv6Addr>,
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
                let name = request.query().name();

                // First check + handle the syntetic name
                shed!{
                    let Some(synthetic_name) = self1.synthetic_self_record.as_ref() else {
                        break;
                    };
                    if name != synthetic_name {
                        break;
                    }
                    let mut answers = vec![];
                    match request.query().query_type() {
                        hickory_proto::rr::RecordType::A => {
                            for n in &self1.global_ipv4 {
                                answers.push(
                                    Record::from_rdata(request.query().name().into(), 60, RData::A(A(*n))),
                                );
                            }
                        },
                        hickory_proto::rr::RecordType::AAAA => {
                            for n in &self1.global_ipv6 {
                                answers.push(
                                    Record::from_rdata(request.query().name().into(), 60, RData::AAAA(AAAA(*n))),
                                );
                            }
                        },
                        _ => { },
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
                }

                // Spagh + upstream DNS
                let (root, path) = split_dns_name(name).err_external()?;
                match root {
                    stored::record::record_utils::RecordRoot::S(ident) => {
                        self.0.log.log_with(loga::DEBUG, "Received spagh request", ea!(request = request.dbg_str()));

                        enum DoResolveRes {
                            Cname(Record),
                            Other(HashMap<RecordKey, (u32, serde_json::Value)>),
                        }

                        async fn do_resolve(
                            self1: &Arc<HandlerInner>,
                            original_name: &LowerName,
                            ident: &Identity,
                            path: RecordKey,
                            explicit_request_keys: Vec<RecordKey>,
                        ) -> Result<DoResolveRes, VisErr> {
                            let mut path = path;

                            // Always automatically request delegation (-> CNAME)
                            let mut delegate_keys = vec![];
                            for i in 1 ..= path.len() {
                                delegate_keys.push(build_delegate_key(path[..i].to_vec()));
                            }
                            let mut request_keys = delegate_keys.clone();
                            request_keys.extend(explicit_request_keys);

                            // Make request, filter out empty results
                            let mut res = match self1.resolver.get(&ident, request_keys).await.err_internal()? {
                                wire::resolve::ResolveKeyValues::V1(v) => v,
                            }.into_iter().filter_map(|(k, v)| {
                                return match v.data {
                                    Some(d) => Some(
                                        (
                                            k,
                                            (
                                                v
                                                    .expires
                                                    .signed_duration_since(Utc::now())
                                                    .num_seconds()
                                                    .try_into()
                                                    .unwrap_or(i32::MAX as u32),
                                                d,
                                            ),
                                        ),
                                    ),
                                    None => None,
                                };
                            }).collect::<HashMap<_, _>>();

                            // Delegation (->CNAME) is automatic preempts all other requests
                            for delegate_key in delegate_keys {
                                let Some((expires, data)) = res.remove(&delegate_key) else {
                                    continue;
                                };
                                match serde_json::from_value::<stored::record::delegate_record::Delegate>(
                                    data.clone(),
                                )
                                    .context_with("Failed to parse received delegate record json", ea!(json = data))
                                    .err_external()? {
                                    stored::record::delegate_record::Delegate::V1(n) => {
                                        let Some((choose_root, mut choose_path)) =
                                            n.0.as_slice().choose(&mut thread_rng()).cloned() else {
                                                continue;
                                            };
                                        choose_path.extend(path.split_off(delegate_key.len()));
                                        return Ok(
                                            DoResolveRes::Cname(
                                                Record::from_rdata(
                                                    original_name.into(),
                                                    expires,
                                                    RData::CNAME(
                                                        CNAME(
                                                            Name::from_ascii(
                                                                &join_dns_name(
                                                                    choose_root,
                                                                    choose_path,
                                                                ).err_external()?,
                                                            ).unwrap(),
                                                        ),
                                                    ),
                                                ),
                                            ),
                                        );
                                    },
                                }
                            }

                            // Otherwise return the normal results
                            return Ok(DoResolveRes::Other(res));
                        }

                        let mut answers = vec![];
                        match request.query().query_type() {
                            hickory_proto::rr::RecordType::CNAME => {
                                match do_resolve(&self1, request.query().name(), &ident, path, vec![]).await? {
                                    DoResolveRes::Cname(r) => {
                                        answers.push(r);
                                    },
                                    // No values
                                    DoResolveRes::Other(_) => (),
                                }
                            },
                            hickory_proto::rr::RecordType::A => {
                                let primary_request_key = build_dns_key(path.clone(), RecordType::A);
                                let mut request_keys = vec![primary_request_key.clone()];
                                for t in [RecordType::Aaaa, RecordType::Txt] {
                                    request_keys.push(build_dns_key(path.clone(), t));
                                }
                                match do_resolve(&self1, request.query().name(), &ident, path, request_keys).await? {
                                    DoResolveRes::Cname(r) => {
                                        answers.push(r);
                                    },
                                    DoResolveRes::Other(mut res) => {
                                        if let Some((expires, data)) = res.remove(&primary_request_key) {
                                            match serde_json::from_value::<stored::record::dns_record::DnsA>(
                                                data.clone(),
                                            )
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
                                        }
                                    },
                                }
                            },
                            hickory_proto::rr::RecordType::AAAA => {
                                let primary_request_key = build_dns_key(path.clone(), RecordType::Aaaa);
                                let mut request_keys = vec![primary_request_key.clone()];
                                for t in [RecordType::A, RecordType::Txt] {
                                    request_keys.push(build_dns_key(path.clone(), t));
                                }
                                match do_resolve(&self1, request.query().name(), &ident, path, request_keys).await? {
                                    DoResolveRes::Cname(r) => {
                                        answers.push(r);
                                    },
                                    DoResolveRes::Other(mut res) => {
                                        if let Some((expires, data)) = res.remove(&primary_request_key) {
                                            match serde_json::from_value::<stored::record::dns_record::DnsAaaa>(
                                                data.clone(),
                                            )
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
                                        }
                                    },
                                }
                            },
                            hickory_proto::rr::RecordType::TXT => {
                                let primary_request_key = build_dns_key(path.clone(), RecordType::Txt);
                                let mut request_keys = vec![primary_request_key.clone()];
                                for t in [RecordType::A, RecordType::Aaaa] {
                                    request_keys.push(build_dns_key(path.clone(), t));
                                }
                                match do_resolve(&self1, request.query().name(), &ident, path, request_keys).await? {
                                    DoResolveRes::Cname(r) => {
                                        answers.push(r);
                                    },
                                    DoResolveRes::Other(mut res) => {
                                        if let Some((expires, data)) = res.remove(&primary_request_key) {
                                            match serde_json::from_value::<stored::record::dns_record::DnsTxt>(
                                                data.clone(),
                                            )
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
                                        }
                                    },
                                }
                            },
                            hickory_proto::rr::RecordType::MX => {
                                let primary_request_key = build_dns_key(path.clone(), RecordType::Mx);
                                let request_keys = vec![primary_request_key.clone()];
                                match do_resolve(&self1, request.query().name(), &ident, path, request_keys).await? {
                                    DoResolveRes::Cname(r) => {
                                        answers.push(r);
                                    },
                                    DoResolveRes::Other(mut res) => {
                                        if let Some((expires, data)) = res.remove(&primary_request_key) {
                                            match serde_json::from_value::<stored::record::dns_record::DnsMx>(
                                                data.clone(),
                                            )
                                                .context_with("Failed to parse received record json", ea!(json = data))
                                                .err_external()? {
                                                stored::record::dns_record::DnsMx::V1(n) => {
                                                    for (i, n) in n.0.into_iter().enumerate() {
                                                        let n = match Name::from_utf8(&n) {
                                                            Err(e) => {
                                                                self1
                                                                    .log
                                                                    .log_err(
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
                                        }
                                    },
                                }
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
                    },
                    stored::record::record_utils::RecordRoot::Dns(_name) => {
                        self
                            .0
                            .log
                            .log_with(loga::DEBUG, "Received non-spagh request", ea!(request = request.dbg_str()));
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
                                            return Err(e)
                                                .context("Upstream DNS server returned error")
                                                .err_external();
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
                                            ).build(
                                                Header::response_from_request(request.header()),
                                                &[],
                                                &[],
                                                &[],
                                                &[],
                                            ),
                                        )
                                        .await
                                        .context("Error sending empty response")
                                        .err_internal()?,
                                );
                            },
                        };
                    },
                    stored::record::record_utils::RecordRoot::Ip(_) => unreachable!(),
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
        let mut upstream_servers = NameServerConfigGroup::new();
        let mut upstream_opts;
        if let Some(dns_config_upstream) = &dns_config.upstream {
            for n in dns_config_upstream {
                let mut upstream;
                match &n.adn {
                    Some(adn) => {
                        upstream =
                            NameServerConfig::new(
                                SocketAddr::new(n.ip, n.port.unwrap_or(853)),
                                hickory_resolver::config::Protocol::Tls,
                            );
                        upstream.tls_dns_name = Some(adn.clone());
                    },
                    None => {
                        upstream =
                            NameServerConfig::new(
                                SocketAddr::new(n.ip, n.port.unwrap_or(53)),
                                hickory_resolver::config::Protocol::Udp,
                            );
                    },
                }
                upstream_servers.push(upstream);
            }
            upstream_opts = ResolverOpts::default();
            upstream_opts.shuffle_dns_servers = true;
        } else {
            let (config, options) =
                hickory_resolver
                ::system_conf
                ::read_system_conf().stack_context(
                    log,
                    "Error reading system dns resolver config for DNS bridge upstream",
                )?;
            for n in config.name_servers() {
                upstream_servers.push(n.clone());
            }
            upstream_opts = options;
        }
        NameServerPool::from_config(
            upstream_servers,
            upstream_opts,
            GenericConnector::new(TokioRuntimeProvider::new()),
        )
    };
    let mut global_ipv4 = vec![];
    let mut global_ipv6 = vec![];
    for ip in global_ips {
        match ip {
            IpAddr::V4(n) => {
                global_ipv4.push(*n);
            },
            IpAddr::V6(n) => {
                global_ipv6.push(*n);
            },
        }
    }
    let mut server = hickory_server::ServerFuture::new(Handler(Arc::new(HandlerInner {
        log: log.clone(),
        resolver: resolver.clone(),
        upstream: upstream,
        synthetic_self_record: if let Some(name) = dns_config.synthetic_self_record {
            Some(
                LowerName::from_str(
                    &name,
                ).context_with("Synthetic record name isn't a valid DNS name", ea!(name = name))?,
            )
        } else {
            None
        },
        global_ipv4: global_ipv4,
        global_ipv6: global_ipv6,
    })));
    let udp_bind_addrs = if let Some(bind_addrs) = dns_config.udp_bind_addrs {
        let mut out = vec![];
        for bind_addr in bind_addrs {
            out.push(bind_addr.resolve()?);
        }
        out
    } else {
        vec![
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 53),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 53)
        ]
    };
    let tcp_bind_addrs = if let Some(bind_addrs) = dns_config.tcp_bind_addrs {
        let mut out = vec![];
        for bind_addr in bind_addrs {
            out.push(bind_addr.resolve()?);
        }
        out
    } else {
        vec![
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 853),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 853)
        ]
    };
    let mut registered = false;
    for bind_addr in udp_bind_addrs {
        server.register_socket(
            UdpSocket::bind(&bind_addr)
                .await
                .stack_context_with(&log, "Opening UDP listener failed", ea!(socket = bind_addr))?,
        );
        registered = true;
    }
    for bind_addr in tcp_bind_addrs {
        server
            .register_tls_listener_with_tls_config(
                TcpListener::bind(&bind_addr)
                    .await
                    .stack_context_with(&log, "Opening TCP listener failed", ea!(socket = bind_addr))?,
                Duration::try_seconds(10).unwrap().to_std().unwrap(),
                Arc::new(
                    rustls_21::ServerConfig::builder()
                        .with_safe_defaults()
                        .with_no_client_auth()
                        .with_cert_resolver(certs.clone()),
                ),
            )
            .context_with("Error starting DoT server", ea!(socket = bind_addr))?;
        registered = true;
    }
    if !registered {
        return Err(loga::err("No UDP or TCP bind addresses defined for DNS resolver"));
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
