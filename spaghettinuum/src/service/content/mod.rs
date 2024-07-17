use {
    crate::{
        bb,
        cap_block,
        cap_fn,
        interface::config::{
            content::{
                ContentConfig,
                ServeMode,
            },
            shared::StrSocketAddr,
        },
        ta_res,
        utils::fs_util::{
            maybe_read,
        },
    },
    futures::Future,
    http::{
        uri::PathAndQuery,
        Method,
        Request,
        Response,
        Uri,
    },
    http_body::Body,
    http_body_util::{
        combinators::BoxBody,
        BodyExt,
        Full,
    },
    htwrap::htreq,
    hyper::{
        body::{
            Bytes,
            Incoming,
        },
        service::service_fn,
    },
    hyper_util::rt::{
        TokioExecutor,
        TokioIo,
    },
    loga::{
        ea,
        ErrContext,
        Log,
        ResultContext,
    },
    path_absolutize::Absolutize,
    rustls::{
        server::ResolvesServerCert,
        ServerConfig,
    },
    std::{
        convert::Infallible,
        net::SocketAddr,
        str::FromStr,
        sync::Arc,
    },
    taskmanager::TaskManager,
    tokio::{
        net::TcpListener,
        spawn,
    },
    tokio_rustls::TlsAcceptor,
    tokio_stream::wrappers::TcpListenerStream,
};

pub async fn serve_content(
    log: &Log,
    tm: &TaskManager,
    resolves_cert: Arc<dyn ResolvesServerCert>,
    content: ContentConfig,
) -> Result<(), loga::Error> {
    let tls_acceptor = TlsAcceptor::from(Arc::new({
        let mut server_config = ServerConfig::builder().with_no_client_auth().with_cert_resolver(resolves_cert);
        server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
        server_config
    }));

    #[derive(Debug)]
    struct RespErr(String);

    impl std::fmt::Display for RespErr {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            return self.0.fmt(f);
        }
    }

    impl std::error::Error for RespErr { }

    async fn serve<
        E: 'static + Send + Sync + std::error::Error,
        B: 'static + Send + hyper::body::Buf,
        R: 'static + Send + Body<Data = B, Error = E>,
        T: 'static + Send + Future<Output = Result<Response<R>, Infallible>>,
        F: 'static + Clone + Send + Sync + Fn(SocketAddr, Request<Incoming>) -> T,
    >(
        log: &Log,
        tm: &TaskManager,
        tls_acceptor: &TlsAcceptor,
        bind_addrs: &[StrSocketAddr],
        handler: F,
    ) -> Result<(), loga::Error> {
        ta_res!(());
        for addr in bind_addrs {
            let log = log.fork(ea!(sys = "serve", bind_addr = addr));
            tm.stream(
                format!("Serve - content ({})", addr),
                TcpListenerStream::new(
                    TcpListener::bind(addr.resolve().stack_context(&log, "Error resolving bind address for server")?)
                        .await
                        .stack_context(&log, "Error binding to address")?,
                ),
                cap_fn!((stream)(log, tls_acceptor, handler) {
                    let stream = match stream {
                        Ok(s) => s,
                        Err(e) => {
                            log.log_err(loga::DEBUG, e.context("Error opening peer stream"));
                            return;
                        },
                    };
                    let peer_addr = match stream.peer_addr() {
                        Ok(a) => a,
                        Err(e) => {
                            log.log_err(loga::DEBUG, e.context("Error getting connection peer address"));
                            return;
                        },
                    };
                    tokio::task::spawn(async move {
                        match async {
                            ta_res!(());
                            hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                                .serve_connection(
                                    TokioIo::new(
                                        tls_acceptor
                                            .accept(stream)
                                            .await
                                            .context("Error establishing TLS connection")?,
                                    ),
                                    service_fn(cap_fn!((req)(peer_addr, handler) {
                                        handler(peer_addr, req).await
                                    })),
                                )
                                .await
                                .map_err(
                                    |e| loga::err_with("Error serving HTTP on connection", ea!(err = e.to_string())),
                                )?;
                            return Ok(());
                        }.await {
                            Ok(_) => (),
                            Err(e) => {
                                log.log_err(loga::DEBUG, e.context("Error serving connection"));
                            },
                        }
                    });
                }),
            );
        }
        return Ok(());
    }

    match content.mode {
        None => (),
        Some(c) => match c {
            ServeMode::StaticFiles { content_dir } => {
                serve(&log, &tm, &tls_acceptor, &content.bind_addrs, cap_fn!((_peer_addr, req)(log, content_dir) {
                    match async {
                        ta_res!(Response < Full < Bytes >>);

                        bb!{
                            if req.method() != Method::GET {
                                break;
                            }
                            let mut path =
                                content_dir
                                    .join(req.uri().path().trim_start_matches('/'))
                                    .absolutize()?
                                    .to_path_buf();
                            if !path.starts_with(&content_dir) {
                                break;
                            }
                            if path.is_dir() {
                                path = path.join("index.html").to_path_buf();
                            }
                            let body = match maybe_read(&path).await? {
                                Some(b) => b,
                                None => break,
                            };
                            return Ok(
                                Response::builder()
                                    .status(200)
                                    .header(
                                        "Content-type",
                                        mime_guess::from_path(&path).first_or_text_plain().to_string(),
                                    )
                                    .body(http_body_util::Full::new(Bytes::from(body)))
                                    .unwrap(),
                            );
                        };

                        return Ok(
                            Response::builder().status(404).body(http_body_util::Full::new(Bytes::new())).unwrap(),
                        );
                    }.await {
                        Ok(r) => Ok(r),
                        Err(e) => {
                            log.log_err(loga::WARN, e.context_with("Error serving response", ea!(url = req.uri())));
                            return Ok(
                                Response::builder()
                                    .status(503)
                                    .body(http_body_util::Full::new(Bytes::new()))
                                    .unwrap(),
                            );
                        },
                    }
                })).await?;
            },
            ServeMode::ReverseProxy { upstream_url } => {
                let upstream_url =
                    Uri::from_str(&upstream_url).stack_context(log, "Unable to parse upstream address as url")?;
                serve(&log, &tm, &tls_acceptor, &content.bind_addrs, cap_fn!((peer_addr, req)(log, upstream_url) {
                    match async {
                        ta_res!(Response < BoxBody < Bytes, RespErr >>);
                        let (mut sender, conn) = htreq::connect(&upstream_url).await?.inner.unwrap();

                        // Adjust request - merge base path, forwarding headers
                        let req = {
                            let (mut req_parts, req_body) = req.into_parts();
                            let mut uri_parts = req_parts.uri.into_parts();
                            let base_path = upstream_url.path().trim_start_matches('/');
                            match uri_parts.path_and_query {
                                Some(path_and_query) => {
                                    uri_parts.path_and_query =
                                        Some(
                                            PathAndQuery::try_from(
                                                format!("{}{}", base_path, path_and_query.to_string()),
                                            ).unwrap(),
                                        );
                                },
                                None => {
                                    uri_parts.path_and_query = Some(PathAndQuery::try_from(base_path).unwrap());
                                },
                            }
                            req_parts.uri = Uri::from_parts(uri_parts).unwrap();
                            let mut forwarded_for = vec![];
                            const HEADER_FORWARDED_FOR: &'static str = "X-Forwarded-For";

                            bb!{
                                let Some(old_forwarded_for) = req_parts.headers.get(HEADER_FORWARDED_FOR) else {
                                    break;
                                };
                                let old_forwarded_for = match old_forwarded_for.to_str() {
                                    Ok(f) => f,
                                    Err(e) => {
                                        log.log(
                                            loga::DEBUG,
                                            e.context_with(
                                                "Couldn't parse received header as utf-8",
                                                ea!(header = HEADER_FORWARDED_FOR),
                                            ),
                                        );
                                        break;
                                    },
                                };
                                forwarded_for.extend(old_forwarded_for.split("/").map(|x| x.to_string()));
                            }

                            forwarded_for.push(peer_addr.to_string());
                            req_parts
                                .headers
                                .insert(HEADER_FORWARDED_FOR, forwarded_for.join(", ").try_into().unwrap());
                            Request::from_parts(req_parts, req_body)
                        };

                        // Send req
                        spawn(cap_block!((log, upstream_url) {
                            conn
                                .await
                                .log_with(
                                    &log,
                                    loga::DEBUG,
                                    "Error in background thread for connection",
                                    ea!(upstream = upstream_url),
                                );
                        }));

                        // Forward body back
                        let resp = sender.send_request(req).await?;
                        let (parts, body) = resp.into_parts();
                        return Ok(Response::from_parts(parts, body.map_err(|e| RespErr(e.to_string())).boxed()));
                    }.await {
                        Ok(r) => {
                            return Ok(r);
                        },
                        Err(e) => {
                            log.log_err(loga::WARN, e.context("Encountered error talking with upstream"));
                            return Ok(
                                Response::builder()
                                    .status(503)
                                    .body(
                                        BoxBody::new(
                                            http_body_util::Full::new(
                                                Bytes::new(),
                                            ).map_err(|e| RespErr(e.to_string())),
                                        ),
                                    )
                                    .unwrap(),
                            );
                        },
                    }
                })).await?;
            },
        },
    }
    return Ok(());
}
