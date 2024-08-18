use std::{
    marker::PhantomData,
};
use serde::{
    de::DeserializeOwned,
    Deserialize,
    Serialize,
};
use crate::interface::stored::identity::Identity;
use crate::interface::stored::shared::SerialAddr;
use crate::utils::blob::Blob;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct AnnouncementPublisher {
    pub addr: SerialAddr,
    pub cert_hash: Blob,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct AnnouncementContent {
    pub publishers: Vec<AnnouncementPublisher>,
    pub announced: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "snake_case")]
pub struct BincodeSignature<T: Serialize + DeserializeOwned, I> {
    pub message: Blob,
    pub signature: Blob,
    #[serde(skip)]
    pub _p: PhantomData<(T, I)>,
}

impl<T: Serialize + DeserializeOwned + std::fmt::Debug, I> std::fmt::Debug for BincodeSignature<T, I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        format_args!("(sig: {}) ", &zbase32::encode_full_bytes(&self.signature)[..8]).fmt(f)?;
        if let Ok(v) = bincode::deserialize::<T>(&self.message) {
            v.fmt(f)?;
        } else {
            self.message.fmt(f)?;
        }
        return Ok(());
    }
}

pub type Announcement = BincodeSignature<AnnouncementContent, Identity>;
