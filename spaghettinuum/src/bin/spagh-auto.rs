use std::{
    collections::HashMap,
    convert::Infallible,
    net::SocketAddr,
    str::FromStr,
    sync::{
        Arc,
        Mutex,
    },
};
use http_body::Body;
use http_body_util::{
    combinators::BoxBody,
    BodyExt,
    Full,
};
use path_absolutize::Absolutize;
use aargvark::{
    Aargvark,
    AargvarkJson,
};
use futures::Future;
use hyper::{
    body::{
        Bytes,
        Incoming,
    },
    service::service_fn,
    Method,
    Request,
    Response,
    Uri,
};
use hyper_util::{
    rt::{
        TokioExecutor,
        TokioIo,
    },
    server::conn::auto::Builder,
};
use loga::{
    ea,
    ErrContext,
    ResultContext,
};
use poem::http::uri::PathAndQuery;
use rustls::ServerConfig;
use spaghettinuum::{
    bb,
    cap_block,
    cap_fn,
    interface::{
        config::{
            auto::{
                Config,
                ServeMode,
            },
            shared::StrSocketAddr,
            DebugFlag,
            Flag,
            ENV_CONFIG,
        },
        stored::{
            self,
            dns_record::{
                format_dns_key,
                RecordType,
            },
        },
        wire,
    },
    self_tls::{
        request_cert_stream,
        CertPair,
        SimpleResolvesServerCert,
    },
    ta_res,
    utils::{
        publish_util,
        log::{
            Log,
            DEBUG_HTSERVE,
            DEBUG_OTHER,
            DEBUG_SELF_TLS,
            INFO,
            NON_DEBUG_FLAGS,
            WARN,
        },
        tls_util::load_certified_key,
        htreq,
        backed_identity::get_identity_signer,
        ip_util::resolve_global_ip,
    },
};
use taskmanager::TaskManager;
use tokio::{
    fs::{
        create_dir_all,
        read,
        write,
    },
    net::TcpListener,
    spawn,
};
use tokio_rustls::TlsAcceptor;
use tokio_stream::wrappers::{
    WatchStream,
    TcpListenerStream,
};

#[derive(Aargvark)]
struct Args {
    /// Config - json.  See the reference documentation and jsonschema for details.
    pub config: Option<AargvarkJson<Config>>,
    /// Enable debug logging
    #[vark(break)]
    pub debug: Option<Vec<DebugFlag>>,
}

async fn inner(log: &Log, tm: &TaskManager, args: Args) -> Result<(), loga::Error> {
    let config = if let Some(p) = args.config {
        p.value
    } else if let Some(c) = match std::env::var(ENV_CONFIG) {
        Ok(c) => Some(c),
        Err(e) => match e {
            std::env::VarError::NotPresent => None,
            std::env::VarError::NotUnicode(_) => {
                return Err(loga::err_with("Error parsing env var as unicode", ea!(env = ENV_CONFIG)))
            },
        },
    } {
        let log = log.fork(ea!(source = "env"));
        serde_json::from_str::<Config>(&c).stack_context(&log, "Parsing config")?
    } else {
        return Err(
            log.err_with("No config passed on command line, and no config set in env var", ea!(env = ENV_CONFIG)),
        );
    };
    let mut identity_signer =
        get_identity_signer(config.identity.clone()).stack_context(log, "Error loading identity")?;
    let mut global_ips = vec![];
    for a in config.global_addrs {
        global_ips.push(resolve_global_ip(log, a).await?);
    };

    // Publish global ips
    let mut publisher_urls = vec![];
    for p in &config.publishers {
        publisher_urls.push(Uri::from_str(&p).stack_context(log, "Invalid publisher URI")?);
    }
    publish_util::announce(log, identity_signer.as_mut(), &publisher_urls).await?;
    publish_util::publish(
        log,
        &publisher_urls,
        identity_signer.as_mut(),
        wire::api::publish::v1::PublishRequestContent {
            clear_all: true,
            set: {
                let mut out = HashMap::new();
                for ip in global_ips {
                    let key;
                    let data;
                    match ip {
                        std::net::IpAddr::V4(ip) => {
                            key = RecordType::A;
                            data =
                                serde_json::to_value(
                                    &stored::dns_record::DnsA::V1(
                                        stored::dns_record::latest::DnsA(vec![ip.to_string()]),
                                    ),
                                ).unwrap();
                        },
                        std::net::IpAddr::V6(ip) => {
                            key = RecordType::Aaaa;
                            data =
                                serde_json::to_value(
                                    &stored::dns_record::DnsAaaa::V1(
                                        stored::dns_record::latest::DnsAaaa(vec![ip.to_string()]),
                                    ),
                                ).unwrap();
                        },
                    }
                    let key = format_dns_key(".", key);
                    if !out.contains_key(&key) {
                        out.insert(key, stored::record::RecordValue::latest(stored::record::latest::RecordValue {
                            ttl: 60,
                            data: Some(data),
                        }));
                    }
                }
                out
            },
            ..Default::default()
        },
    ).await?;

    // Start server or just tls renewal
    if let Some(serve) = config.serve {
        let cert_path = serve.cert_dir;
        create_dir_all(&cert_path)
            .await
            .stack_context_with(log, "Error creating cert dir", ea!(path = cert_path.to_string_lossy()))?;
        let pub_path = cert_path.join("pub.pem");
        let pub_pem = bb!{
            'pub_done _;
            let raw = match read(&pub_path).await {
                Ok(v) => {
                    v
                },
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        break 'pub_done None;
                    }
                    return Err(
                        e.stack_context_with(log, "Error reading file", ea!(path = pub_path.to_string_lossy())),
                    );
                },
            };
            Some(
                String::from_utf8(
                    raw,
                ).stack_context_with(log, "Couldn't parse PEM as utf-8", ea!(path = pub_path.to_string_lossy()))?,
            )
        };
        let priv_path = cert_path.join("priv.pem");
        let priv_pem = bb!{
            'priv_done _;
            let raw = match read(&priv_path).await {
                Ok(v) => {
                    v
                },
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        break 'priv_done None;
                    }
                    return Err(
                        e.stack_context_with(log, "Error reading file", ea!(path = priv_path.to_string_lossy())),
                    );
                },
            };
            Some(
                String::from_utf8(
                    raw,
                ).stack_context_with(log, "Couldn't parse PEM as utf-8", ea!(path = priv_path.to_string_lossy()))?,
            )
        };
        let certs_stream =
            request_cert_stream(
                &log,
                &tm,
                identity_signer,
                pub_pem.zip(priv_pem).map(|(pub_pem, priv_pem)| CertPair {
                    pub_pem: pub_pem,
                    priv_pem: priv_pem,
                }),
            ).await?;
        let certs = Arc::new(Mutex::new(None));
        tm.stream(
            "Serve - handle cert changes",
            WatchStream::new(certs_stream.clone()),
            cap_fn!((p)(certs, pub_path, priv_path, log) {
                *certs.lock().unwrap() = match load_certified_key(p.pub_pem.as_bytes(), p.priv_pem.as_bytes()) {
                    Ok(v) => Some(v),
                    Err(e) => {
                        log.log_err(WARN, e.context("Error reading received certs"));
                        None
                    },
                };
                write(&pub_path, p.pub_pem.as_bytes())
                    .await
                    .log_with(
                        &log,
                        WARN,
                        "Error writing pub pem to disk",
                        ea!(path = pub_path.to_string_lossy(), pem = p.pub_pem),
                    );
                write(&priv_path, p.priv_pem.as_bytes())
                    .await
                    .log_with(
                        &log,
                        WARN,
                        "Error writing priv pem to disk",
                        ea!(path = priv_path.to_string_lossy(), pem = p.priv_pem),
                    );
            }),
        );
        if let Some(content) = serve.content {
            let tls_acceptor = TlsAcceptor::from(Arc::new({
                let mut server_config =
                    ServerConfig::builder()
                        .with_no_client_auth()
                        .with_cert_resolver(Arc::new(SimpleResolvesServerCert(certs)));
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
                            TcpListener::bind(
                                addr.resolve().stack_context(&log, "Error resolving bind address for server")?,
                            )
                                .await
                                .stack_context(&log, "Error binding to address")?,
                        ),
                        cap_fn!((stream)(log, tls_acceptor, handler) {
                            let stream = match stream {
                                Ok(s) => s,
                                Err(e) => {
                                    log.log_err(DEBUG_OTHER, e.context("Error opening peer stream"));
                                    return;
                                },
                            };
                            let peer_addr = match stream.peer_addr() {
                                Ok(a) => a,
                                Err(e) => {
                                    log.log_err(DEBUG_OTHER, e.context("Error getting connection peer address"));
                                    return;
                                },
                            };
                            tokio::task::spawn(async move {
                                match async {
                                    ta_res!(());
                                    Builder::new(TokioExecutor::new())
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
                                            |e| loga::err_with(
                                                "Error serving HTTP on connection",
                                                ea!(err = e.to_string()),
                                            ),
                                        )?;
                                    return Ok(());
                                }.await {
                                    Ok(_) => (),
                                    Err(e) => {
                                        log.log_err(DEBUG_OTHER, e.context("Error serving connection"));
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
                        serve(
                            &log,
                            &tm,
                            &tls_acceptor,
                            &content.bind_addrs,
                            cap_fn!((_peer_addr, req)(log, content_dir) {
                                match async {
                                    ta_res!(Response < Full < Bytes >>);

                                    bb!{
                                        if req.method() != Method::GET {
                                            break;
                                        }
                                        let mut path = content_dir.join(req.uri().path()).absolutize()?.to_path_buf();
                                        if !path.starts_with(content_dir) {
                                            break;
                                        }
                                        if path.is_dir() {
                                            path = path.join("index.html").to_path_buf();
                                        }
                                        let body = match read(&path).await {
                                            Ok(b) => b,
                                            Err(e) => match e.kind() {
                                                std::io::ErrorKind::NotFound => {
                                                    break;
                                                },
                                                _ => {
                                                    return Err(e.into());
                                                },
                                            },
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
                                        Response::builder()
                                            .status(404)
                                            .body(http_body_util::Full::new(Bytes::new()))
                                            .unwrap(),
                                    );
                                }.await {
                                    Ok(r) => Ok(r),
                                    Err(e) => {
                                        log.log_err(
                                            WARN,
                                            e.context_with("Error serving response", ea!(url = req.uri())),
                                        );
                                        return Ok(
                                            Response::builder()
                                                .status(503)
                                                .body(http_body_util::Full::new(Bytes::new()))
                                                .unwrap(),
                                        );
                                    },
                                }
                            }),
                        ).await?;
                    },
                    ServeMode::ReverseProxy { upstream_url } => {
                        let upstream_url =
                            Uri::from_str(
                                &upstream_url,
                            ).stack_context(log, "Unable to parse upstream address as url")?;
                        serve(
                            &log,
                            &tm,
                            &tls_acceptor,
                            &content.bind_addrs,
                            cap_fn!((peer_addr, req)(log, upstream_url) {
                                match async {
                                    ta_res!(Response < BoxBody < Bytes, RespErr >>);
                                    let conn = htreq::new_conn(&upstream_url).await?;
                                    let (mut sender, conn) =
                                        hyper::client::conn::http1::handshake(conn)
                                            .await
                                            .context("Error completing http handshake")?;

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
                                                uri_parts.path_and_query =
                                                    Some(PathAndQuery::try_from(base_path).unwrap());
                                            },
                                        }
                                        req_parts.uri = Uri::from_parts(uri_parts).unwrap();
                                        let mut forwarded_for = vec![];
                                        const HEADER_FORWARDED_FOR: &'static str = "X-Forwarded-For";

                                        bb!{
                                            let Some(
                                                old_forwarded_for
                                            ) = req_parts.headers.get(HEADER_FORWARDED_FOR) else {
                                                break;
                                            };
                                            let old_forwarded_for = match old_forwarded_for.to_str() {
                                                Ok(f) => f,
                                                Err(e) => {
                                                    log.log(
                                                        DEBUG_HTSERVE,
                                                        e.context_with(
                                                            "Couldn't parse received header as utf-8",
                                                            ea!(header = HEADER_FORWARDED_FOR),
                                                        ),
                                                    );
                                                    break;
                                                },
                                            };
                                            forwarded_for.extend(
                                                old_forwarded_for.split("/").map(|x| x.to_string()),
                                            );
                                        }

                                        forwarded_for.push(peer_addr.to_string());
                                        req_parts
                                            .headers
                                            .insert(
                                                HEADER_FORWARDED_FOR,
                                                forwarded_for.join(", ").try_into().unwrap(),
                                            );
                                        Request::from_parts(req_parts, req_body)
                                    };

                                    // Send req
                                    spawn(cap_block!((log, upstream_url) {
                                        conn
                                            .await
                                            .log_with(
                                                &log,
                                                DEBUG_OTHER,
                                                "Error in background thread for connection",
                                                ea!(upstream = upstream_url),
                                            );
                                    }));

                                    // Forward body back
                                    let resp = sender.send_request(req).await?;
                                    let (parts, body) = resp.into_parts();
                                    return Ok(
                                        Response::from_parts(
                                            parts,
                                            body.map_err(|e| RespErr(e.to_string())).boxed(),
                                        ),
                                    );
                                }.await {
                                    Ok(r) => {
                                        return Ok(r);
                                    },
                                    Err(e) => {
                                        log.log_err(WARN, e.context("Encountered error talking with upstream"));
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
                            }),
                        ).await?;
                    },
                },
            }
        }
    } else {
        tm.terminate();
    }
    return Ok(());
}

#[tokio::main]
async fn main() {
    let args = aargvark::vark::<Args>();
    let mut flags = NON_DEBUG_FLAGS.to_vec();
    if let Some(f) = &args.debug {
        if f.is_empty() {
            flags.push(DEBUG_HTSERVE);
            flags.push(DEBUG_SELF_TLS);
            flags.push(DEBUG_OTHER);
        } else {
            flags.extend(f.into_iter().map(|x| Flag::Debug(*x)));
        }
    }
    let log = &Log::new().with_flags(&flags);
    let tm = taskmanager::TaskManager::new();
    match inner(log, &tm, args).await.map_err(|e| {
        tm.terminate();
        return e;
    }).also({
        tm.join(log, INFO).await.context("Critical services failed")
    }) {
        Ok(_) => { },
        Err(e) => {
            loga::fatal(e);
        },
    }
}
