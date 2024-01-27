use std::sync::{
    Arc,
    Mutex,
};
use futures::{
    stream,
    FutureExt,
    Stream,
};
use itertools::Itertools;
use manual_future::{
    ManualFuture,
    ManualFutureCompleter,
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
pub mod htserve;
pub mod htreq;
pub mod log;
pub mod signed;

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

/// Break barrier - remove the footgunishness of using loop for this directly
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

/// Explicitly communicate the async block return type to the compiler via
/// unexecuting code.
#[macro_export]
macro_rules! ta_res{
    ($t: ty) => {
        if false {
            fn unreachable_value<T>() -> T {
                panic!();
            }
            return std:: result:: Result::< $t,
            loga::Error > ::Ok(unreachable_value());
        }
    }
}

/// Explicitly communicate the async block return type to the compiler via
/// unexecuting code (`VisErr` error type).
#[macro_export]
macro_rules! ta_vis_res{
    ($t: ty) => {
        if false {
            fn unreachable_value<T>() -> T {
                panic!();
            }
            return std:: result:: Result::< $t,
            crate::utils::VisErr > ::Ok(unreachable_value());
        }
    }
}
