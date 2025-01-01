use {
    crate::{
        cap_block,
        cap_fn,
        interface::config::content::{
            ContentConfig,
            ServeMode,
        },
        ta_res,
        utils::fs_util::maybe_read,
    },
    async_trait::async_trait,
    flowcontrol::shed,
    http::{
        uri::PathAndQuery,
        Method,
        Request,
        Response,
        Uri,
    },
    http_body_util::{
        combinators::BoxBody,
        BodyExt,
    },
    htwrap::{
        htreq,
        htserve::{
            self,
            handler::Handler,
        },
    },
    hyper::body::Bytes,
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
        collections::BTreeMap,
        path::PathBuf,
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

struct StaticFilesHandler {
    log: Log,
    content_dir: PathBuf,
}

#[async_trait]
impl htserve::handler::Handler<BoxBody<Bytes, RespErr>> for StaticFilesHandler {
    async fn handle(&self, args: htserve::handler::HandlerArgs<'_>) -> Response<BoxBody<Bytes, RespErr>> {
        match async {
            ta_res!(Response < BoxBody < Bytes, RespErr >>);
            shed!{
                if args.head.method != Method::GET {
                    break;
                }
                let mut path = self.content_dir.join(args.subpath).absolutize()?.to_path_buf();
                if !path.starts_with(&self.content_dir) {
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
                        .header("Content-type", mime_guess::from_path(&path).first_or_text_plain().to_string())
                        .body(
                            BoxBody::new(
                                http_body_util::Full::new(Bytes::from(body)).map_err(|e| RespErr(e.to_string())),
                            ),
                        )
                        .unwrap(),
                );
            };
            return Ok(
                Response::builder()
                    .status(404)
                    .body(
                        BoxBody::new(http_body_util::Full::new(Bytes::new()).map_err(|e| RespErr(e.to_string()))),
                    )
                    .unwrap(),
            );
        }.await {
            Ok(r) => r,
            Err(e) => {
                self.log.log_err(loga::WARN, e.context_with("Error serving response", ea!(url = args.head.uri)));
                return Response::builder()
                    .status(503)
                    .body(
                        BoxBody::new(http_body_util::Full::new(Bytes::new()).map_err(|e| RespErr(e.to_string()))),
                    )
                    .unwrap();
            },
        }
    }
}

struct ReverseProxyHandler {
    log: Log,
    upstream_url: Uri,
}

#[async_trait]
impl htserve::handler::Handler<BoxBody<Bytes, RespErr>> for ReverseProxyHandler {
    async fn handle(&self, args: htserve::handler::HandlerArgs<'_>) -> Response<BoxBody<Bytes, RespErr>> {
        match async {
            ta_res!(Response < BoxBody < Bytes, RespErr >>);
            let (mut sender, conn) = htreq::connect(&self.upstream_url).await?.inner.unwrap();

            // Adjust request - merge base path, forwarding headers
            let req = {
                let mut req_parts = args.head.clone();
                let mut uri_parts = req_parts.uri.into_parts();
                let base_path = self.upstream_url.path();
                if args.subpath.is_empty() {
                    uri_parts.path_and_query = Some(PathAndQuery::try_from(base_path).unwrap());
                } else {
                    uri_parts.path_and_query =
                        Some(
                            PathAndQuery::try_from(
                                format!("{}{}{}{}", base_path, args.subpath, if args.query.is_empty() {
                                    ""
                                } else {
                                    "?"
                                }, args.query),
                            ).unwrap(),
                        );
                }
                req_parts.uri = Uri::from_parts(uri_parts).unwrap();
                let mut forwarded =
                    htserve::forwarded::parse_all_forwarded(&mut req_parts.headers)
                        .unwrap_or_default()
                        .into_iter()
                        .map(|x| x.to_owned())
                        .collect::<Vec<_>>();
                forwarded.push(htserve::forwarded::parse_forwarded_current(&req_parts.uri, args.peer_addr));
                if let Err(e) = htserve::forwarded::add_forwarded(&mut req_parts.headers, &forwarded) {
                    self.log.log_err(loga::DEBUG, loga::err(e));
                }
                if let Err(e) = htserve::forwarded::add_x_forwarded(&mut req_parts.headers, &forwarded) {
                    self.log.log_err(loga::DEBUG, loga::err(e));
                }
                Request::from_parts(req_parts, args.body)
            };

            // Send req
            {
                let log = &self.log;
                let upstream_url = &self.upstream_url;
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
            }

            // Forward body back
            let resp = sender.send_request(req).await?;
            let (parts, body) = resp.into_parts();
            return Ok(Response::from_parts(parts, body.map_err(|e| RespErr(e.to_string())).boxed()));
        }.await {
            Ok(r) => {
                return r;
            },
            Err(e) => {
                self.log.log_err(loga::WARN, e.context("Encountered error talking with upstream"));
                return Response::builder()
                    .status(503)
                    .body(
                        BoxBody::new(http_body_util::Full::new(Bytes::new()).map_err(|e| RespErr(e.to_string()))),
                    )
                    .unwrap();
            },
        }
    }
}

#[derive(Debug)]
struct RespErr(String);

impl std::fmt::Display for RespErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return self.0.fmt(f);
    }
}

impl std::error::Error for RespErr { }

pub async fn start_serving_content(
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
    for (addr, subpaths) in content.items {
        let mut routes = BTreeMap::new();
        for (subpath, mode) in subpaths {
            let handler: Box<dyn Handler<BoxBody<Bytes, RespErr>>>;
            match mode {
                ServeMode::StaticFiles { content_dir } => {
                    handler = Box::new(StaticFilesHandler {
                        log: log.clone(),
                        content_dir: content_dir,
                    });
                },
                ServeMode::ReverseProxy { upstream_url } => {
                    handler = Box::new(ReverseProxyHandler {
                        log: log.clone(),
                        upstream_url: Uri::from_str(
                            &upstream_url,
                        ).stack_context(log, "Unable to parse upstream address as url")?,
                    });
                },
            }
            routes.insert(subpath, handler);
        }
        let log = log.fork(ea!(sys = "serve", bind_addr = addr));
        let handler =
            Arc::new(
                htserve::handler::PathRouter::new(
                    routes,
                ).map_err(
                    |e| loga::agg_err(
                        "One or more errors setting up content router",
                        e.into_iter().map(loga::err).collect(),
                    ),
                )?,
            );
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
                htserve::handler::root_handle_https(&log, tls_acceptor, handler, stream)
                    .await
                    .log(&log, loga::DEBUG, "Error initiating request handling");
            }),
        );
    }
    return Ok(());
}
