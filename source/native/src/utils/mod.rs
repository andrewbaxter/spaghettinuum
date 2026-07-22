//! Other assorted methods and tools.
pub mod db_util;
pub mod dns_util;
pub mod fs_util;
pub mod identity_secret;
pub mod misc_tests;
#[cfg(feature = "card")]
pub mod pgp;
pub mod publish_util;
pub mod signed;
pub mod ssh_util;
pub mod system_addr;
pub mod time_util;
pub mod tls_util;
pub mod unstable_ip;

use {
    futures::{
        FutureExt,
        Stream,
        stream,
    },
    itertools::Itertools,
    manual_future::{
        ManualFuture,
        ManualFutureCompleter,
    },
    std::sync::{
        Arc,
        Mutex,
    },
};

/// Explicitly capturing async block - clones elements in the second parens into
/// the closure. Anything else will be moved.
#[macro_export]
macro_rules! cap_block{
    (($($cap: ident), *) {
        $($t: tt) *
    }) => {
        {
            $(let $cap = $cap.clone();) * async move {
                $($t) *
            }
        }
    };
}

/// Explicitly capturing async closure - clones elements in the second parens into
/// the closure. Anything else will be moved.
#[macro_export]
macro_rules! cap_fn{
    (($($a: pat_param), *)($($cap: ident), *) {
        $($t: tt) *
    }) => {
        {
            $(let $cap = $cap.clone();) * move | $($a),
            *| {
                $(let $cap = $cap.clone();) * async move {
                    $($t) *
                }
            }
        }
    };
}

/// Explicitly communicate the async block return type to the compiler via
/// unexecuting code.
#[macro_export]
macro_rules! ta_res{
    ($t: ty) => {
        flowcontrol::ta_return!($t, loga::Error);
    }
}

/// Explicitly communicate the async block return type to the compiler via
/// unexecuting code (`VisErr` error type).
#[macro_export]
macro_rules! ta_vis_res{
    ($t: ty) => {
        flowcontrol::ta_return!($t, $crate:: utils:: VisErr);
    }
}

pub trait ResultVisErr<O> {
    fn err_external(self) -> Result<O, VisErr>;
    fn err_internal(self) -> Result<O, VisErr>;
}

impl<O, E: Into<loga::Error>> ResultVisErr<O> for Result<O, E> {
    fn err_external(self) -> Result<O, VisErr> {
        match self {
            Ok(v) => Ok(v),
            Err(e) => Err(VisErr::External(e.into())),
        }
    }

    fn err_internal(self) -> Result<O, VisErr> {
        match self {
            Ok(v) => Ok(v),
            Err(e) => Err(VisErr::Internal(e.into())),
        }
    }
}

#[derive(Clone)]
pub struct AsyncBus<T: Clone + Unpin>(Arc<Mutex<Vec<ManualFutureCompleter<T>>>>);

impl<T: Clone + Unpin> AsyncBus<T> {
    pub fn new() -> AsyncBus<T> {
        return AsyncBus(Arc::new(Mutex::new(vec![])));
    }

    pub fn recv(&self) -> ManualFuture<T> {
        let (f, c) = ManualFuture::new();
        let mut v = self.0.lock().unwrap();
        v.push(c);
        return f;
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

    pub fn stream(self) -> impl Stream<Item = T> {
        stream::unfold(self, |b| b.recv().map(|v| Some((v, b))))
    }
}

pub enum VisErr {
    External(loga::Error),
    Internal(loga::Error),
}
