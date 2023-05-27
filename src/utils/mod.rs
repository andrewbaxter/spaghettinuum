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

pub mod card;
pub mod standard;
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

pub type VerInt = u16;

#[macro_export]
macro_rules! ver_int_len{
    () => {
        2
    };
}

#[macro_export]
macro_rules! versioned{
    ($et: ident $(, $dv: ident) *; $(($var: ident, $ver: literal, $t: ty)), *) => {
        #[derive($($dv), *)] 
        // hack to use default serialization for human readable
        pub enum $et {
            $($var($t),) *
        }
        impl $et {
            pub fn from_bytes(data: &[u8]) -> Result < $et,
            loga:: Error > {
                let version = $crate:: utils:: VerInt:: from_le_bytes(
                    <[
                        u8;
                        $crate:: ver_int_len !()
                    ] >:: try_from(
                        data.get(
                            0..$crate:: ver_int_len !()
                        ).ok_or_else(
                            || loga::Error::new(
                                "Data length is less than version header size",
                                loga::ea!(got_len = data.len(), expected_len = $crate:: ver_int_len !()),
                            )
                        ) ?
                    ).unwrap()
                );
                match version {
                    $($ver => {
                        return Ok(Self:: $var(< $t >:: from_bytes(& data[$crate:: ver_int_len !()..]) ?));
                    },) * v => {
                        return Err(loga::Error::new("Unsupported version", loga::ea!(version = v)));
                    }
                }
            }
            pub fn to_bytes(&self) -> Vec < u8 > {
                let mut out = vec![];
                match self {
                    $(Self:: $var(d) => {
                        std:: io:: Write:: write(&mut out, &($ver as $crate:: utils:: VerInt).to_le_bytes()).unwrap();
                        std::io::Write::write(&mut out, &d.to_bytes()).unwrap();
                    }),
                    *
                }
                return out;
            }
        }
        impl serde:: Serialize for $et {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: serde::Serializer {
                if serializer.is_human_readable() {
                    return serializer.serialize_str(&zbase32::encode_full_bytes(&self.to_bytes()));
                } else {
                    return serde::Serialize::serialize(&self.to_bytes(), serializer);
                }
            }
        }
        impl < 'de > serde:: Deserialize < 'de > for $et {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: serde::Deserializer<'de> {
                if deserializer.is_human_readable() {
                    let s = String::deserialize(deserializer)?;
                    Self::from_bytes(
                        &zbase32::decode_full_bytes_str(&s).map_err(serde::de::Error::custom)?,
                    ).map_err(
                        |e| serde::de::Error::custom(
                            format!("Error deserializing {} zbase32: {}", stringify!($et), e.to_string()),
                        ),
                    )
                } else {
                    let bytes = Vec::deserialize(deserializer)?;
                    return Ok(
                        Self::from_bytes(
                            &bytes,
                        ).map_err(
                            |e| serde::de::Error::custom(
                                format!("Error deserializing {}: {}", stringify!($et), e.to_string()),
                            ),
                        )?,
                    );
                }
            }
        }
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
