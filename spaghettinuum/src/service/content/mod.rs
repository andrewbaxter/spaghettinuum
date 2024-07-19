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
        utils::fs_util::maybe_read,
    },
    async_trait::async_trait,
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
    htwrap::{
        htreq,
        htserve,
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
impl htserve::Handler<Full<Bytes>> for StaticFilesHandler {
    async fn handle(&self, args: htserve::HandlerArgs<'_>) -> Response<Full<Bytes>> {
        match async {
            ta_res!(Response < Full < Bytes >>);

            bb!{
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
                        .body(http_body_util::Full::new(Bytes::from(body)))
                        .unwrap(),
                );
            };

            return Ok(Response::builder().status(404).body(http_body_util::Full::new(Bytes::new())).unwrap());
        }.await {
            Ok(r) => r,
            Err(e) => {
                self.log.log_err(loga::WARN, e.context_with("Error serving response", ea!(url = args.head.uri)));
                return Response::builder().status(503).body(http_body_util::Full::new(Bytes::new())).unwrap();
            },
        }
    }
}

struct ReverseProxyHandler {
    log: Log,
    upstream_url: Uri,
}

#[async_trait]
impl htserve::Handler<BoxBody<Bytes, RespErr>> for ReverseProxyHandler {
    async fn handle(&self, args: htserve::HandlerArgs<'_>) -> Response<BoxBody<Bytes, RespErr>> {
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
                let mut forwarded_for = vec![];
                const HEADER_FORWARDED_FOR: &'static str = "X-Forwarded-For";

                bb!{
                    let Some(old_forwarded_for) = req_parts.headers.get(HEADER_FORWARDED_FOR) else {
                        break;
                    };
                    let old_forwarded_for = match old_forwarded_for.to_str() {
                        Ok(f) => f,
                        Err(e) => {
                            self
                                .log
                                .log(
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

                forwarded_for.push(args.peer_addr.to_string());
                req_parts.headers.insert(HEADER_FORWARDED_FOR, forwarded_for.join(", ").try_into().unwrap());
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

async fn serve<
    E: 'static + Send + Sync + std::error::Error,
    B: 'static + Send + hyper::body::Buf,
    R: 'static + Send + Body<Data = B, Error = E>,
>(
    log: &Log,
    tm: &TaskManager,
    tls_acceptor: &TlsAcceptor,
    bind_addrs: &[StrSocketAddr],
    handler: Arc<dyn htserve::Handler<R>>,
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
                htserve::root_handle_https(&log, tls_acceptor, handler, stream)
                    .await
                    .log(&log, loga::DEBUG, "Error initiating request handling");
            }),
        );
    }
    return Ok(());
}

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
    match content.mode {
        None => (),
        Some(c) => match c {
            ServeMode::StaticFiles { content_dir } => {
                serve(&log, &tm, &tls_acceptor, &content.bind_addrs, Arc::new(StaticFilesHandler {
                    log: log.clone(),
                    content_dir: content_dir,
                })).await?;
            },
            ServeMode::ReverseProxy { upstream_url } => {
                serve(&log, &tm, &tls_acceptor, &content.bind_addrs, Arc::new(ReverseProxyHandler {
                    log: log.clone(),
                    upstream_url: Uri::from_str(
                        &upstream_url,
                    ).stack_context(log, "Unable to parse upstream address as url")?,
                })).await?;
            },
        },
    }
    return Ok(());
}
