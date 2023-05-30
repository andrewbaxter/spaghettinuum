use std::{
    io::Write,
    sync::{
        Arc,
        Mutex,
    },
};
use futures::{
    stream,
    FutureExt,
    Stream,
    Future,
};
use itertools::Itertools;
use manual_future::{
    ManualFuture,
    ManualFutureCompleter,
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
