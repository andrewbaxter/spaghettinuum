use std::{
    io::Write,
    sync::{
        Arc,
        Mutex,
    },
    net::{
        IpAddr,
        ToSocketAddrs,
    },
    str::FromStr,
};
use futures::{
    stream,
    FutureExt,
    Stream,
    Future,
};
use itertools::Itertools;
use loga::{
    ea,
    ResultContext,
};
use manual_future::{
    ManualFuture,
    ManualFutureCompleter,
};
use reqwest::{
    Response,
    Url,
};
use serde::Serialize;

#[cfg(feature = "card")]
pub mod pgp;
pub mod versioned;
pub mod misctests;

pub trait BincodeSerializable {
    fn serialize(&self) -> Box<[u8]>;
    fn serialize_into(&self, w: &mut dyn Write);
}

impl<T: Serialize> BincodeSerializable for T {
    fn serialize(&self) -> Box<[u8]> {
        return bincode::serialize(self).unwrap().into_boxed_slice();
    }

    fn serialize_into(&self, w: &mut dyn Write) {
        bincode::serialize_into(w, self).unwrap();
    }
}

#[derive(Clone)]
pub struct AsyncBus<T: Clone + Unpin>(Arc<Mutex<Vec<ManualFutureCompleter<T>>>>);

impl<T: Clone + Unpin> AsyncBus<T> {
    pub fn new() -> AsyncBus<T> {
        return AsyncBus(Arc::new(Mutex::new(vec![])));
    }

    pub async fn send(&self, value: T) {
        let mut v = {
            let mut v = self.0.lock().unwrap();
            if v.is_empty() {
                return;
            }
            v.drain(..).collect_vec()
        };
        match v.pop() {
            Some(last) => {
                for f in v.drain(..) {
                    f.complete(value.clone()).await;
                }
                v.clear();
                last.complete(value).await;
            },
            None => { },
        };
    }

    pub fn recv(&self) -> ManualFuture<T> {
        let (f, c) = ManualFuture::new();
        let mut v = self.0.lock().unwrap();
        v.push(c);
        return f;
    }

    pub fn stream(self) -> impl Stream<Item = T> {
        stream::unfold(self, |b| b.recv().map(|v| Some((v, b))))
    }
}

#[inline(always)]
pub fn err_stop<R, F: FnOnce() -> Result<R, loga::Error>>(f: F) -> Result<R, loga::Error> {
    f()
}

#[macro_export]
macro_rules! es{
    ($b: expr) => {
        $crate:: utils:: err_stop(|| $b)
    };
}

#[inline(always)]
pub async fn async_err_stop<
    R,
    T: Future<Output = Result<R, loga::Error>>,
    F: FnOnce() -> T,
>(f: F) -> Result<R, loga::Error> {
    f().await
}

#[macro_export]
macro_rules! aes{
    ($b: expr) => {
        $crate:: utils:: async_err_stop(|| async {
            $b
        })
    };
}

pub enum VisErr {
    Internal(loga::Error),
    External(loga::Error),
}

pub trait ResultVisErr<O> {
    fn err_internal(self) -> Result<O, VisErr>;
    fn err_external(self) -> Result<O, VisErr>;
}

impl<O, E: Into<loga::Error>> ResultVisErr<O> for Result<O, E> {
    fn err_internal(self) -> Result<O, VisErr> {
        match self {
            Ok(v) => Ok(v),
            Err(e) => Err(VisErr::Internal(e.into())),
        }
    }

    fn err_external(self) -> Result<O, VisErr> {
        match self {
            Ok(v) => Ok(v),
            Err(e) => Err(VisErr::External(e.into())),
        }
    }
}

#[inline(always)]
pub async fn async_err_stop2<
    R,
    T: Future<Output = Result<R, VisErr>>,
    F: FnOnce() -> T,
>(f: F) -> Result<R, VisErr> {
    f().await
}

#[macro_export]
macro_rules! aes2{
    ($b: expr) => {
        $crate:: utils:: async_err_stop2(|| async {
            $b
        })
    };
}

pub async fn reqwest_get(r: Response, limit: usize) -> Result<Vec<u8>, loga::Error> {
    let status = r.status();
    let mut resp_bytes = r.bytes().await.context("Error reading response body")?;
    resp_bytes.truncate(limit);
    let resp_bytes = resp_bytes.to_vec();
    if status.is_client_error() || status.is_server_error() {
        return Err(
            loga::err_with(
                "Got response with error code",
                ea!(status = status, body = String::from_utf8_lossy(&resp_bytes)),
            ),
        );
    }
    return Ok(resp_bytes);
}

pub async fn lookup_ip(lookup: &str, ipv4_only: bool, ipv6_only: bool) -> Result<IpAddr, loga::Error> {
    let lookup =
        Url::parse(&lookup).context_with("Couldn't parse `advertise_addr` lookup as URL", ea!(lookup = lookup))?;
    let lookup_host =
        lookup.host().ok_or_else(|| loga::err("Missing host portion in `advertise_addr` url"))?.to_string();
    let lookup_port = lookup.port().unwrap_or(match lookup.scheme() {
        "http" => 80,
        "https" => 443,
        _ => return Err(loga::err("Only http/https are supported for ip lookups")),
    });
    let ip =
        reqwest_get(
            reqwest::ClientBuilder::new()
                .resolve(
                    &lookup_host,
                    format!("{}:{}", lookup_host, lookup_port)
                        .to_socket_addrs()
                        .context_with("Failed to look up lookup host", ea!(host = lookup_host))?
                        .into_iter()
                        .filter(|a| {
                            if ipv4_only && !a.is_ipv4() {
                                return false;
                            }
                            if ipv6_only && !a.is_ipv6() {
                                return false;
                            }
                            return true;
                        })
                        .next()
                        .ok_or_else(
                            || loga::err_with(
                                "Unable to resolve any addresses (matching ipv4/6 requirements) via lookup",
                                ea!(lookup = lookup),
                            ),
                        )?,
                )
                .build()
                .unwrap()
                .get(lookup)
                .send()
                .await?,
            10 * 1024,
        ).await?;
    let ip =
        String::from_utf8(
            ip.clone(),
        ).context_with("Failed to parse response as utf8", ea!(resp = String::from_utf8_lossy(&ip)))?;
    let ip = IpAddr::from_str(&ip).context_with("Failed to parse response as socket addr", ea!(ip = ip))?;
    return Ok(ip);
}
