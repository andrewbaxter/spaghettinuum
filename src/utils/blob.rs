use std::ops::{
    Deref,
    DerefMut,
};
use serde::{
    Serialize,
    Deserialize,
    Serializer,
    Deserializer,
};

#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct Blob(Box<[u8]>);

impl Blob {
    pub fn new(len: usize) -> Blob {
        let mut out = Vec::new();
        out.resize(len, 0u8);
        return Blob(out.into_boxed_slice());
    }
}

impl Deref for Blob {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        return self.0.as_ref();
    }
}

impl DerefMut for Blob {
    fn deref_mut(&mut self) -> &mut Self::Target {
        return self.0.as_mut();
    }
}

impl AsRef<[u8]> for Blob {
    fn as_ref(&self) -> &[u8] {
        return self.0.as_ref();
    }
}

impl AsMut<[u8]> for Blob {
    fn as_mut(&mut self) -> &mut [u8] {
        return self.0.as_mut();
    }
}

impl std::fmt::Display for Blob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return format!("b({})", zbase32::encode_full_bytes(&self.0)).fmt(f);
    }
}

impl std::fmt::Debug for Blob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return std::fmt::Display::fmt(self, f);
    }
}

impl From<&[u8]> for Blob {
    fn from(value: &[u8]) -> Self {
        return Blob(Box::from(value));
    }
}

impl From<Vec<u8>> for Blob {
    fn from(value: Vec<u8>) -> Self {
        return Blob(value.into_boxed_slice());
    }
}

impl Serialize for Blob {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer {
        if serializer.is_human_readable() {
            return zbase32::encode_full_bytes(&self.0).serialize(serializer);
        } else {
            return self.0.serialize(serializer);
        }
    }
}

impl<'d> Deserialize<'d> for Blob {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d> {
        let v;
        if deserializer.is_human_readable() {
            v =
                zbase32::decode_full_bytes_str(
                    &String::deserialize(deserializer)?,
                ).map_err(|_| serde::de::Error::custom(format!("Bytes are not valid zbase32")))?;
        } else {
            v = <Vec<u8>>::deserialize(deserializer)?;
        }
        return Ok(Blob(v.into_boxed_slice()));
    }
}

pub trait ToBlob {
    fn blob(self) -> Blob;
}

impl ToBlob for Vec<u8> {
    fn blob(self) -> Blob {
        return Blob::from(self);
    }
}

impl ToBlob for &[u8] {
    fn blob(self) -> Blob {
        return Blob::from(self);
    }
}
