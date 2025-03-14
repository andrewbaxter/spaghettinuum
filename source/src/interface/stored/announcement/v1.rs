use {
    std::{
        marker::PhantomData,
    },
    serde::{
        de::DeserializeOwned,
        Deserialize,
        Serialize,
    },
    crate::interface::stored::identity::Identity,
    crate::interface::stored::shared::SerialAddr,
    crate::utils::blob::Blob,
    crate::utils::time_util::UtcSecs,
};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct AnnouncementPublisher {
    pub addr: SerialAddr,
    pub cert_hash: Blob,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct AnnouncementContent {
    pub publishers: Vec<AnnouncementPublisher>,
    pub announced: UtcSecs,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
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
