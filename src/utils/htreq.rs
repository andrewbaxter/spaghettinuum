use std::{
    collections::HashMap,
    str::FromStr,
    net::{
        IpAddr,
        Ipv6Addr,
        Ipv4Addr,
    },
    sync::OnceLock,
};
use chrono::{
    Duration,
};
use futures::future::join_all;
use http_body_util::{
    Limited,
    BodyExt,
    Full,
    Empty,
};
use hyper::{
    Request,
    StatusCode,
    Uri,
    body::Bytes,
};
use hyper_rustls::{
    HttpsConnectorBuilder,
    ConfigBuilderExt,
};
use loga::{
    ea,
    ResultContext,
};
use rand::{
    seq::SliceRandom,
    thread_rng,
};
use rustls::ClientConfig;
use tokio::{
    select,
    time::sleep,
    sync::{
        mpsc,
    },
};
use tower_service::Service;
use crate::{
    ta_res,
};

pub fn rustls_client_config() -> rustls::ClientConfig {
    static S: OnceLock<rustls::ClientConfig> = OnceLock::new();
    return S.get_or_init(move || {
        ClientConfig::builder()
            .with_native_roots()
            .context("Error loading native roots")
            .unwrap()
            .with_no_client_auth()
    }).clone();
}

pub type Conn = hyper_rustls::MaybeHttpsStream<hyper_util::rt::tokio::TokioIo<tokio::net::TcpStream>>;

pub enum HostPart {
    Ip(IpAddr),
    Name(String),
}

pub fn uri_parts(uri: &Uri) -> Result<(String, HostPart, u16), loga::Error> {
    let host = uri.host().context("Url is missing host")?;
    if host.is_empty() {
        return Err(loga::err("Host portion of url is empty"));
    }
    let host = if host.as_bytes()[0] as char == '[' {
        HostPart::Ip(
            IpAddr::V6(
                Ipv6Addr::from_str(
                    &String::from_utf8(
                        host.as_bytes()[1..]
                            .split_last()
                            .context("URL ipv6 missing ending ]")?
                            .1
                            .iter()
                            .cloned()
                            .collect(),
                    ).unwrap(),
                ).context("Invalid ipv6 address in URL")?,
            ),
        )
    } else if host.as_bytes().iter().all(|b| ('0' ..= '9').contains(&(*b as char))) {
        HostPart::Ip(IpAddr::V4(Ipv4Addr::from_str(host).context("Invalid ipv4 address in URL")?))
    } else {
        HostPart::Name(host.to_string())
    };
    let scheme = uri.scheme().context("Url is missing scheme")?.to_string();
    let port = match uri.port_u16() {
        Some(p) => p,
        None => match scheme.as_str() {
            "http" => 80,
            "https" => 443,
            _ => return Err(loga::err("Only http/https urls are supported")),
        },
    };
    return Ok((scheme, host, port));
}

pub async fn send<
    ID: Send,
    IE: std::error::Error + Send + Sync + 'static,
    I: http_body::Body<Data = ID, Error = IE> + 'static,
>(conn: Conn, max_size: usize, max_time: Duration, req: Request<I>) -> Result<Vec<u8>, loga::Error> {
    let read = async move {
        ta_res!((Vec < u8 >, StatusCode));
        let (mut sender, mut conn) =
            hyper::client::conn::http1::handshake(conn).await.context("Error completing http handshake")?;
        let work = sender.send_request(req);
        let resp = select!{
            _ =& mut conn => {
                return Err(loga::err("Connection failed while sending request"));
            }
            r = work => r,
        }.context("Error sending request")?;
        let status = resp.status();
        let work = Limited::new(resp.into_body(), max_size).collect();
        let resp = select!{
            _ =& mut conn => {
                return Err(loga::err("Connection failed while reading body"));
            }
            r = work => r,
        }.map_err(|e| loga::err_with("Error reading response", ea!(err = e)))?.to_bytes().to_vec();
        return Ok((resp, status));
    };
    let (resp, status) = select!{
        _ = sleep(max_time.to_std().unwrap()) => {
            return Err(loga::err("Timeout waiting for response from server"));
        }
        x = read => x ?,
    };
    if !status.is_success() {
        return Err(
            loga::err_with(
                "Server returned error response",
                ea!(status = status, body = String::from_utf8_lossy(&resp)),
            ),
        );
    }
    return Ok(resp);
}

/// Creates a new HTTPS/HTTP connection with default settings.  `base_uri` is just
/// used for schema, host, and port.
pub async fn new_conn(base_uri: &Uri) -> Result<Conn, loga::Error> {
    let (scheme, host, port) = uri_parts(base_uri).context("Incomplete url")?;
    let (try_ips, host) = match host {
        HostPart::Ip(i) => (vec![i], i.to_string()),
        HostPart::Name(host) => {
            let mut ipv4s = vec![];
            let mut ipv6s = vec![];
            for ip in hickory_resolver::TokioAsyncResolver::tokio_from_system_conf()
                .context("Error reading resolv.conf")?
                .lookup_ip(&format!("{}.", host))
                .await
                .context("Failed to look up lookup host ip addresses")? {
                match ip {
                    std::net::IpAddr::V4(_) => {
                        ipv4s.push(ip);
                    },
                    std::net::IpAddr::V6(_) => {
                        ipv6s.push(ip);
                    },
                }
            }
            let mut try_ips = vec![];
            {
                let mut r = thread_rng();
                try_ips.extend(ipv4s.choose(&mut r));
                try_ips.extend(ipv6s.choose(&mut r));
            }
            (try_ips, host)
        },
    };
    let mut bg = vec![];
    let (found_tx, mut found_rx) = mpsc::channel(1);
    for ip in try_ips {
        bg.push({
            let found_tx = found_tx.clone();
            let scheme = &scheme;
            let host = &host;
            async move {
                ta_res!(());
                let conn =
                    HttpsConnectorBuilder::new()
                        .with_tls_config(rustls_client_config())
                        .https_or_http()
                        .with_server_name(host.to_string())
                        .enable_http1()
                        .build()
                        .call(Uri::from_str(&format!("{}://{}:{}", scheme, match ip {
                            IpAddr::V4(i) => i.to_string(),
                            IpAddr::V6(i) => format!("[{}]", i),
                        }, port)).unwrap())
                        .await
                        .map_err(
                            |e| loga::err_with(
                                "Error connecting to host",
                                ea!(err = e.to_string(), dest_addr = ip, host = host, port = port),
                            ),
                        )?;
                _ = found_tx.send(conn);
                return Ok(());
            }
        });
    }

    select!{
        failed = join_all(bg) => {
            if failed.is_empty() {
                return Err(loga::err("No addresses found when looking up host"));
            }
            if let Ok(found) = found_rx.try_recv() {
                return Ok(found);
            }
            return Err(
                loga::agg_err("Unable to connect to host", failed.into_iter().map(|e| e.unwrap_err()).collect()),
            );
        }
        found = found_rx.recv() => {
            return Ok(found.unwrap());
        }
    }
}

pub async fn post(
    uri: impl AsRef<str>,
    headers: &HashMap<String, String>,
    body: Vec<u8>,
    max_size: usize,
) -> Result<Vec<u8>, loga::Error> {
    let uri = uri.as_ref();
    let uri = Uri::from_str(uri).context_with("URI couldn't be parsed", ea!(uri = uri))?;
    let req = Request::builder();
    let mut req = req.method("POST").uri(uri.clone());
    for (k, v) in headers.iter() {
        req = req.header(k, v);
    }
    return Ok(
        send(
            new_conn(&uri).await?,
            max_size,
            Duration::seconds(10),
            req.body(Full::new(Bytes::from(body))).unwrap(),
        )
            .await
            .context_with("Error sending POST", ea!(uri = uri))?,
    );
}

pub async fn get(
    uri: impl AsRef<str>,
    headers: &HashMap<String, String>,
    max_size: usize,
) -> Result<Vec<u8>, loga::Error> {
    let uri = uri.as_ref();
    let uri = Uri::from_str(uri).context_with("URI couldn't be parsed", ea!(uri = uri))?;
    let req = Request::builder();
    let mut req = req.method("GET").uri(uri.clone());
    for (k, v) in headers.iter() {
        req = req.header(k, v);
    }
    return Ok(
        send(new_conn(&uri).await?, max_size, Duration::seconds(10), req.body(Empty::<Bytes>::new()).unwrap())
            .await
            .context_with("Error sending GET", ea!(uri = uri))?,
    );
}

pub async fn get_text(
    uri: impl AsRef<str>,
    headers: &HashMap<String, String>,
    max_size: usize,
) -> Result<String, loga::Error> {
    let body = get(uri, headers, max_size).await?;
    return Ok(
        String::from_utf8(
            body,
        ).map_err(
            |e| loga::err_with(
                "Received data isn't valid utf-8",
                ea!(err = e.to_string(), body = String::from_utf8_lossy(e.as_bytes())),
            ),
        )?,
    );
}

pub async fn delete(
    uri: impl AsRef<str>,
    headers: &HashMap<String, String>,
    max_size: usize,
) -> Result<Vec<u8>, loga::Error> {
    let uri = uri.as_ref();
    let uri = Uri::from_str(uri).context_with("URI couldn't be parsed", ea!(uri = uri))?;
    let req = Request::builder();
    let mut req = req.method("DELETE").uri(uri.clone());
    for (k, v) in headers.iter() {
        req = req.header(k, v);
    }
    return Ok(
        send(new_conn(&uri).await?, max_size, Duration::seconds(10), req.body(Empty::<Bytes>::new()).unwrap())
            .await
            .context_with("Error sending DELETE", ea!(uri = uri))?,
    );
}
