use {
    http::Method,
    http_body_util::Full,
    htwrap::htreq,
    hyper::body::Bytes,
    loga::{
        ea,
        DebugDisplay,
        Log,
        ResultContext,
    },
    serde_json::json,
    spaghettinuum::{
        resolving::{
            default_resolver_url_pairs,
            resolve_for_tls,
            ResolveTlsRes,
        },
        utils::tls_util::{
            cert_pem_hash,
            SpaghTlsClientVerifier,
        },
    },
    std::{
        collections::{
            HashMap,
            HashSet,
        },
        time::Duration,
    },
    tokio::{
        fs::File,
        io::stdout,
    },
};

pub mod args {
    use {
        aargvark::{
            traits_impls::AargvarkFile,
            Aargvark,
        },
        http::Uri,
        std::{
            collections::HashMap,
            path::PathBuf,
        },
    };

    #[derive(Aargvark)]
    pub enum HttpMethod {
        Head,
        Options,
        Get,
        Put,
        Post,
        Patch,
        Delete,
    }

    #[derive(Aargvark)]
    pub struct Http {
        pub method: HttpMethod,
        pub url: Uri,
        pub headers: Option<HashMap<String, String>>,
        pub params: Option<HashMap<String, String>>,
        pub body: Option<String>,
        /// Like `body` but read from a file.
        pub body_file: Option<AargvarkFile>,
        /// Output to file instead of stdout.
        pub output: Option<PathBuf>,
        /// Write output metadata as json. If output is not a file, output will be a field
        /// in the JSON.
        pub json: Option<()>,
    }
}

pub async fn run(log: &Log, config: args::Http) -> Result<(), loga::Error> {
    let (scheme, host, port) = htreq::uri_parts(&config.url)?;

    // Prepare request
    let final_req;
    {
        let mut req = http::Request::builder();

        // Method
        req = req.method(match config.method {
            args::HttpMethod::Head => Method::HEAD,
            args::HttpMethod::Options => Method::OPTIONS,
            args::HttpMethod::Get => Method::GET,
            args::HttpMethod::Put => Method::PUT,
            args::HttpMethod::Post => Method::POST,
            args::HttpMethod::Patch => Method::PATCH,
            args::HttpMethod::Delete => Method::DELETE,
        });

        // Headers
        for (k, v) in config.headers.into_iter().flatten() {
            req = req.header(k, v);
        }

        // Query parameters + url
        let mut query_params = vec![];
        if let Some(q) = config.url.query() {
            query_params.push(q.to_string());
        }
        for (k, v) in config.params.into_iter().flatten() {
            query_params.push(format!("{}={}", urlencoding::encode(&k), urlencoding::encode(&v)));
        }
        req = req.uri(format!("{}://{}:{}{}{}", scheme, host, port, config.url.path(), if query_params.is_empty() {
            "".to_string()
        } else {
            format!("?{}", query_params.join("&"))
        }));

        // Body
        if config.body.is_some() && config.body_file.is_some() {
            return Err(loga::err("Must specify only one body parameter"));
        }
        final_req = if let Some(b) = config.body {
            req.body(Full::new(Bytes::from(b.into_bytes())))
        } else if let Some(b) = config.body_file {
            req.body(Full::new(Bytes::from(b.value)))
        } else {
            req.body(Full::new(Bytes::new()))
        }.unwrap();
    }

    // Resolve destination
    let ResolveTlsRes { ips, certs: certs0 } = resolve_for_tls(log, &default_resolver_url_pairs(log)?, &host).await?;
    let mut certs = HashSet::new();
    for c in certs0 {
        match cert_pem_hash(&c) {
            Ok(c) => {
                certs.insert(c);
            },
            Err(e) => {
                log.log_err(
                    loga::DEBUG,
                    e.context("Couldn't parse TLS record into expected JSON format, not using for verification"),
                );
            },
        }
    }

    // Now make the actual request
    let mut conn =
        htreq::connect_ips(
            ips,
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(SpaghTlsClientVerifier::with_root_cas(certs)?)
                .with_no_client_auth(),
            scheme,
            host,
            port,
        ).await?;
    let (status, headers, continue_send) = htreq::send(log, &mut conn, Duration::MAX, final_req).await?;
    log.log_with(loga::DEBUG, "Received header", ea!(status = status, headers = headers.dbg_str()));
    match config.output {
        Some(p) => {
            htreq::receive_stream(
                continue_send,
                File::create(&p).await.context_with("Error opening output file", ea!(path = p.to_string_lossy()))?,
            ).await?;
            if config.json.is_some() {
                let headers =
                    headers.into_iter().map(|(k, v)| (k.dbg_str(), v.dbg_str())).collect::<HashMap<_, _>>();
                println!("{}", serde_json::to_string_pretty(&json!({
                    "status": status.dbg_str(),
                    "headers": headers,
                })).unwrap());
            } else {
                if !status.is_success() {
                    return Err(loga::err_with("Received non-success status code", ea!(status = status)));
                }
            }
        },
        None => {
            if config.json.is_some() {
                let mut buf = vec![];
                htreq::receive_stream(continue_send, &mut buf).await?;
                let body_valid_utf8;
                let body_str;
                match String::from_utf8(buf) {
                    Ok(b) => {
                        body_str = b;
                        body_valid_utf8 = true;
                    },
                    Err(e) => {
                        body_str = String::from_utf8_lossy(e.as_bytes()).to_string();
                        body_valid_utf8 = false;
                    },
                }
                let headers =
                    headers.into_iter().map(|(k, v)| (k.dbg_str(), v.dbg_str())).collect::<HashMap<_, _>>();
                println!("{}", serde_json::to_string_pretty(&json!({
                    "status": status.dbg_str(),
                    "headers": headers,
                    "body": body_str,
                    "body_valid_utf8": body_valid_utf8,
                })).unwrap());
            } else {
                htreq::receive_stream(continue_send, stdout()).await?;
                if !status.is_success() {
                    return Err(loga::err_with("Received non-success status code", ea!(status = status)));
                }
            }
        },
    };
    return Ok(());
}
