use {
    crate::{
        interface::stored::shared::SerialAddr,
        utils::time_util::UtcSecs,
    },
    serde::{
        de::DeserializeOwned,
        Deserialize,
        Serialize,
    },
    spaghettinuum::interface::public_key::PublicKey,
    std::marker::PhantomData,
};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct AnnouncementPublisher {
    pub addr: SerialAddr,
    pub cert_hash: Vec<u8>,
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
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
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

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Announcement {
    pub public_key: PublicKey,
    pub signed: BincodeSignature<AnnouncementContent, PublicKey>,
}

impl Announcement {
    pub fn verify(&self) -> Result<AnnouncementContent, ()> {
        self.public_key.verify(&self.signed.message, &self.signed.signature).map_err(|_| ())?;
        return Ok(bincode::deserialize(&self.signed.message).map_err(|_| ())?);
    }

    pub fn parse_unwrap(&self) -> AnnouncementContent {
        return bincode::deserialize(&self.signed.message).unwrap();
    }

    pub fn id(&self) -> spaghettinuum::interface::id::Id {
        return self.public_key.id();
    }
}
