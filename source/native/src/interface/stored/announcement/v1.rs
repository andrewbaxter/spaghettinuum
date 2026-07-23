use {
    crate::{
        interface::stored::shared::SerialAddr,
        utils::time_util::UtcSecs,
    },
    serde::{
        Deserialize,
        Serialize,
        de::DeserializeOwned,
    },
    spaghettinuum::interface::{
        identity::IdentityPublicKey,
        signature_chain::{
            ChainLink,
            verify_chain,
        },
    },
    std::marker::PhantomData,
};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Announcement {
    #[serde(default)]
    pub public_key_chain: Vec<ChainLink>,
    pub public_key_root: IdentityPublicKey,
    pub signed: BincodeSignature<AnnouncementContent, IdentityPublicKey>,
}

impl Announcement {
    pub fn identity(&self) -> spaghettinuum::interface::identity::Identity {
        return self.public_key_root.identity();
    }

    pub fn parse_unwrap(&self) -> AnnouncementContent {
        return bincode::deserialize(&self.signed.message).unwrap();
    }

    pub fn verify(&self, identity: &spaghettinuum::interface::identity::Identity) -> Result<AnnouncementContent, ()> {
        if self.public_key_root.identity() != *identity {
            return Err(());
        }
        let content = bincode::deserialize::<AnnouncementContent>(&self.signed.message).map_err(|_| ())?;
        let leaf = verify_chain(&self.public_key_root, &self.public_key_chain, content.announced.0)?;
        leaf.verify(&self.signed.message, &self.signed.signature).map_err(|_| ())?;
        return Ok(content);
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct AnnouncementContent {
    pub announced: UtcSecs,
    pub publishers: Vec<AnnouncementPublisher>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct AnnouncementPublisher {
    pub addr: SerialAddr,
    pub cert_hash: Vec<u8>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct BincodeSignature<T: Serialize + DeserializeOwned, I> {
    #[serde(skip)]
    pub _p: PhantomData<(T, I)>,
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
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
