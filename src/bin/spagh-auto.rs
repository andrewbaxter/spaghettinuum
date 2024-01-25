use std::{
    collections::HashMap,
    convert::Infallible,
    path::PathBuf,
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
use rustls::ServerConfig;
use serde::{
    Deserialize,
    Serialize,
};
use spaghettinuum::{
    bb,
    cap_block,
    cap_fn,
    config::GlobalAddrConfig,
    interface::{
        spagh_api::{
            publish,
            resolve::{
                self,
                KEY_DNS_A,
                KEY_DNS_AAAA,
            },
        },
        spagh_cli::{
            self,
            BackedIdentityArg,
            StrSocketAddr,
        },
    },
    self_tls::{
        certifier_url,
        request_cert_stream,
        CertPair,
        SimpleResolvesServerCert,
    },
    ta_res,
    utils::{
        publish_util,
        log::{
            DEBUG_OTHER,
            DEBUG_SELF_TLS,
            DEBUG_API,
            NON_DEBUG,
            WARN,
            INFO,
            Log,
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

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServeMode {
    StaticFiles {
        /// Where files to serve are
        content_dir: PathBuf,
    },
    ReverseProxy {
        /// Url of upstream HTTP server
        upstream_addr: String,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ContentConfig {
    /// Interface IPs and ports to bind to
    bind_addrs: Vec<StrSocketAddr>,
    /// What content to serve
    #[serde(default)]
    pub mode: Option<ServeMode>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ServeConfig {
    /// Where to store TLS certs.  This directory and its parents will be created if
    /// they don't already exist.  The certs will be named `pub.pem` and `priv.pem`.
    pub cert_dir: PathBuf,
    /// How to serve content.  If not specified, just keeps certificates in the cert
    /// dir up to date.
    #[serde(default)]
    pub content: Option<ContentConfig>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Config {
    /// How to identify and select globally routable IP addresses for this host
    pub global_addrs: Vec<GlobalAddrConfig>,
    /// Identity to use for publishing
    pub identity: BackedIdentityArg,
    /// Url of publisher where this identity is authorized to publish
    pub publisher: String,
    /// Configure HTTPS serving using certipasta certs
    #[serde(default)]
    pub serve: Option<ServeConfig>,
}

#[derive(Aargvark)]
struct Args {
    /// Config - json.  See the reference documentation and jsonschema for details.
    pub config: Option<AargvarkJson<Config>>,
    /// Enable debug logging
    pub debug: Option<()>,
}

async fn inner(log: &Log, tm: &TaskManager, args: Args) -> Result<(), loga::Error> {
    let config = if let Some(p) = args.config {
        p.value
    } else if let Some(c) = match std::env::var(spagh_cli::ENV_CONFIG) {
        Ok(c) => Some(c),
        Err(e) => match e {
            std::env::VarError::NotPresent => None,
            std::env::VarError::NotUnicode(_) => {
                return Err(loga::err_with("Error parsing env var as unicode", ea!(env = spagh_cli::ENV_CONFIG)))
            },
        },
    } {
        let log = log.fork(ea!(source = "env"));
        serde_json::from_str::<Config>(&c).stack_context(&log, "Parsing config")?
    } else {
        return Err(
            log.err_with(
                "No config passed on command line, and no config set in env var",
                ea!(env = spagh_cli::ENV_CONFIG),
            ),
        );
    };
    let mut identity_signer =
        get_identity_signer(config.identity.clone()).stack_context(log, "Error loading identity")?;
    let mut global_ips = vec![];
    for a in config.global_addrs {
        global_ips.push(resolve_global_ip(log, a).await?);
    };

    // Publish global ips
    publish_util::publish(
        log,
        &Uri::from_str(&config.publisher).stack_context(log, "Invalid publisher URI")?,
        identity_signer.as_mut(),
        publish::latest::Publish {
            missing_ttl: 60 * 24,
            data: {
                let mut out = HashMap::new();
                for ip in global_ips {
                    match ip {
                        std::net::IpAddr::V4(ip) => {
                            let key = KEY_DNS_A.to_string();
                            if !out.contains_key(&key) {
                                out.insert(key, publish::latest::PublishValue {
                                    ttl: 60,
                                    data: serde_json::to_value(
                                        &resolve::DnsA::V1(resolve::v1::DnsA(vec![ip.to_string()])),
                                    ).unwrap(),
                                });
                            }
                        },
                        std::net::IpAddr::V6(ip) => {
                            let key = KEY_DNS_AAAA.to_string();
                            if !out.contains_key(&key) {
                                out.insert(key, publish::latest::PublishValue {
                                    ttl: 60,
                                    data: serde_json::to_value(
                                        &resolve::DnsAaaa::V1(resolve::v1::DnsAaaa(vec![ip.to_string()])),
                                    ).unwrap(),
                                });
                            }
                        },
                    }
                }
                out
            },
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
                &certifier_url(),
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
                F: 'static + Clone + Send + Sync + Fn(Request<Incoming>) -> T,
            >(
                log: &Log,
                tm: &TaskManager,
                tls_acceptor: &TlsAcceptor,
                bind_addrs: &[StrSocketAddr],
                handler: F,
            ) -> Result<(), loga::Error> {
                ta_res!(());
                let handler = service_fn(handler);
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
                                            handler.clone(),
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
                        serve(&log, &tm, &tls_acceptor, &content.bind_addrs, cap_fn!((req)(log, content_dir) {
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
                        })).await?;
                    },
                    ServeMode::ReverseProxy { upstream_addr } => {
                        let upstream_addr =
                            Uri::from_str(
                                &upstream_addr,
                            ).stack_context(log, "Unable to parse upstream address as uri")?;
                        serve(&log, &tm, &tls_acceptor, &content.bind_addrs, cap_fn!((req)(log, upstream_addr) {
                            match async {
                                ta_res!(Response < BoxBody < Bytes, RespErr >>);
                                let conn = htreq::new_conn(&upstream_addr).await?;
                                let (mut sender, conn) =
                                    hyper::client::conn::http1::handshake(conn)
                                        .await
                                        .context("Error completing http handshake")?;
                                let uri = req.uri().clone();
                                spawn(cap_block!((log, uri) {
                                    conn
                                        .await
                                        .log_with(
                                            &log,
                                            DEBUG_OTHER,
                                            "Error in background thread for connection",
                                            ea!(uri = uri),
                                        );
                                }));
                                let resp = sender.send_request(req).await?;
                                let (parts, body) = resp.into_parts();
                                return Ok(
                                    Response::from_parts(parts, body.map_err(|e| RespErr(e.to_string())).boxed()),
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
                        })).await?;
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
    let mut flags = NON_DEBUG;
    if args.debug.is_some() {
        flags |= DEBUG_API;
        flags |= DEBUG_SELF_TLS;
        flags |= DEBUG_OTHER;
    }
    let log = &Log::new().with_flags(flags);
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
