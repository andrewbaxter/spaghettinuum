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

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct AnnouncementContent {
    pub addr: SerialAddr,
    pub cert_hash: Blob,
    pub published: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "snake_case")]
pub struct BincodeSignature<T: Serialize + DeserializeOwned, I> {
    pub message: Blob,
    pub signature: Blob,
    #[serde(skip)]
    pub _p: PhantomData<(T, I)>,
}

pub type Announcement = BincodeSignature<AnnouncementContent, Identity>;
