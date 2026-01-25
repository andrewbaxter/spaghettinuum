use {
    crate::interface::stored::{
        announcement::Announcement,
        node_identity::NodeIdentity,
        shared::SerialAddr,
    },
    core::fmt::Debug,
    generic_array::GenericArray,
    serde::{
        de::DeserializeOwned,
        Deserialize,
        Serialize,
        Serializer,
    },
    spaghettinuum::interface::identity::Identity,
    std::marker::PhantomData,
};

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct BincodeSignature<T: Serialize + DeserializeOwned, I> {
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
    #[serde(skip)]
    pub _p: PhantomData<(T, I)>,
}

impl<T: Serialize + DeserializeOwned, I> BincodeSignature<T, I> {
    pub fn parse_unwrap(&self) -> T {
        return bincode::deserialize(&self.message).unwrap();
    }
}

impl<T: Serialize + DeserializeOwned + Debug, I> std::fmt::Debug for BincodeSignature<T, I> {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct DhtCoord(pub GenericArray<u8, generic_array::typenum::U32>);

impl Serialize for DhtCoord {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer {
        return self.0.as_slice().serialize(serializer);
    }
}

impl<'a> Deserialize<'a> for DhtCoord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'a> {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        return Ok(
            Self(
                <GenericArray<u8, generic_array::typenum::U32>>::from_exact_iter(
                    bytes.into_iter(),
                ).ok_or_else(|| serde::de::Error::custom("DhtCoord has the wrong number of bytes"))?,
            ),
        );
    }
}

pub trait Req {
    fn into_req(self) -> Message;
}

pub trait ReqResp {
    type Resp: DeserializeOwned;

    fn into_req(self) -> Message;
}

// Find
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FindGoal {
    Coord(DhtCoord),
    Identity(Identity),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindRequest {
    pub sender: NodeIdentity,
    pub challenge: Vec<u8>,
    pub goal: FindGoal,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct NodeInfo {
    pub ident: NodeIdentity,
    pub address: SerialAddr,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindResponseContent {
    pub goal: FindGoal,
    pub challenge: Vec<u8>,
    pub nodes: Vec<NodeInfo>,
    pub value: Option<Announcement>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindResponse {
    pub sender: NodeIdentity,
    pub content: BincodeSignature<FindResponseContent, NodeIdentity>,
}

impl ReqResp for FindRequest {
    type Resp = FindResponse;

    fn into_req(self) -> Message {
        return Message::Find(self);
    }
}

// # Store
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct StoreRequest {
    pub key: Identity,
    pub value: Announcement,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct StoreResponse {
    pub key: Identity,
    pub value: Announcement,
}

impl Req for StoreRequest {
    fn into_req(self) -> Message {
        return Message::Store(self);
    }
}

// # Ping
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PingRequest;

impl ReqResp for PingRequest {
    type Resp = NodeIdentity;

    fn into_req(self) -> Message {
        return Message::Ping(self);
    }
}

// # Challenge
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Challenge(pub Vec<u8>);

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ChallengeResponse {
    pub sender: NodeIdentity,
    pub signature: Vec<u8>,
}

impl ReqResp for Challenge {
    type Resp = ChallengeResponse;

    fn into_req(self) -> Message {
        return Message::Challenge(self);
    }
}

// # Assembly
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Message {
    Find(FindRequest),
    Store(StoreRequest),
    Ping(PingRequest),
    Challenge(Challenge),
}

impl Message {
    pub fn from_bytes(bytes: &[u8]) -> Result<Message, String> {
        return Ok(bincode::deserialize(bytes).map_err(|e| e.to_string())?);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        return bincode::serialize(self).unwrap();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct NodeState {
    pub node: NodeInfo,
    pub unresponsive: bool,
}
