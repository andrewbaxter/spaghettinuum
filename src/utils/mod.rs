use std::{
    sync::{
        Arc,
        Mutex,
    },
};
use futures::{
    stream,
    FutureExt,
    Stream,
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
use poem::{
    endpoint::BoxEndpoint,
};
use reqwest::{
    Response,
};
use self::blob::{
    Blob,
    ToBlob,
};

#[cfg(feature = "card")]
pub mod pgp;
pub mod versioned;
pub mod misc_tests;
pub mod ip_util;
pub mod unstable_ip;
pub mod local_identity;
pub mod backed_identity;
pub mod tls_util;
pub mod publish_util;
pub mod db_util;
pub mod poem_util;
pub mod time_util;
pub mod blob;

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

pub async fn reqwest_get(r: Response, limit: usize) -> Result<Blob, loga::Error> {
    let status = r.status();
    let mut resp_bytes = r.bytes().await.context("Error reading response body")?;
    resp_bytes.truncate(limit);
    let resp_bytes = resp_bytes.blob();
    if status.is_client_error() || status.is_server_error() {
        return Err(
            loga::new_err_with(
                "Got response with error code",
                ea!(status = status, body = String::from_utf8_lossy(&resp_bytes)),
            ),
        );
    }
    return Ok(resp_bytes);
}

pub struct SystemEndpoints(pub BoxEndpoint<'static, poem::Response>);

// Break barrier - remove the footgunishness of using loop for this directly
#[macro_export]
macro_rules! bb{
    ($l: lifetime _; $($t: tt) *) => {
        $l: loop {
            #[allow(unreachable_code)] break {
                $($t) *
            };
        }
    };
    ($($t: tt) *) => {
        loop {
            #[allow(unreachable_code)] break {
                $($t) *
            };
        }
    };
}
