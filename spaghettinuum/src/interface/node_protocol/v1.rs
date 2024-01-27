use serde::Serializer;
use serde::de::DeserializeOwned;
use serde::{
    Serialize,
    Deserialize,
};
use core::fmt::Debug;
use std::fmt::Display;
use std::marker::PhantomData;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use sha2::Digest;
use crate::interface::identity::Identity;
use crate::interface::node_identity::NodeIdentity;
use crate::utils::blob::{
    Blob,
    ToBlob,
};

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "snake_case")]
pub struct BincodeSignature<T: Serialize + DeserializeOwned, I> {
    pub message: Blob,
    pub signature: Blob,
    #[serde(skip)]
    pub _p: PhantomData<(T, I)>,
}

// Ed25519
pub struct Hash(Blob);

impl Hash {
    pub fn new(data: &[u8]) -> Self {
        return Self(<sha2::Sha256 as Digest>::digest(data).blob());
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Hash)]
#[serde(rename_all = "snake_case")]
pub enum FindMode {
    Nodes(NodeIdentity),
    Put(Identity),
    Get(Identity),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FindRequest {
    pub sender: NodeIdentity,
    pub challenge: Blob,
    pub mode: FindMode,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SerialAddrInner {
    V4(SerialIpv4),
    V6(SerialIpv6),
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
struct SerialIpv4 {
    addr: [u8; 4],
    port: u16,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
struct SerialIpv6 {
    addr: [u16; 8],
    port: u16,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SerialAddr(pub SocketAddr);

impl Display for SerialAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <dyn Display>::fmt(&self.0, f)
    }
}

impl Serialize for SerialAddr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer {
        Serialize::serialize(&match self.0.ip() {
            IpAddr::V4(ip) => SerialAddrInner::V4(SerialIpv4 {
                addr: ip.octets(),
                port: self.0.port(),
            }),
            IpAddr::V6(ip) => SerialAddrInner::V6(SerialIpv6 {
                addr: ip.segments(),
                port: self.0.port(),
            }),
        }, serializer)
    }
}

impl<'a> Deserialize<'a> for SerialAddr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'a> {
        Ok(match SerialAddrInner::deserialize(deserializer)? {
            SerialAddrInner::V4(addr) => SerialAddr(
                SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(addr.addr[0], addr.addr[1], addr.addr[2], addr.addr[3])),
                    addr.port,
                ),
            ),
            SerialAddrInner::V6(addr) => SerialAddr(
                SocketAddr::new(
                    IpAddr::V6(
                        Ipv6Addr::new(
                            addr.addr[0],
                            addr.addr[1],
                            addr.addr[2],
                            addr.addr[3],
                            addr.addr[4],
                            addr.addr[5],
                            addr.addr[6],
                            addr.addr[7],
                        ),
                    ),
                    addr.port,
                ),
            ),
        })
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct NodeInfo {
    pub ident: NodeIdentity,
    pub address: SerialAddr,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct PublisherAnnouncementContent {
    pub addr: SerialAddr,
    pub cert_hash: Blob,
    pub published: chrono::DateTime<chrono::Utc>,
}

pub type PublisherAnnouncement = BincodeSignature<PublisherAnnouncementContent, Identity>;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum FindResponseModeContent {
    Nodes(Vec<NodeInfo>),
    Value(PublisherAnnouncement),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct FindResponseContent {
    pub challenge: Blob,
    pub sender: NodeIdentity,
    pub mode: FindMode,
    pub inner: FindResponseModeContent,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct FindResponse {
    pub sender: NodeIdentity,
    pub content: BincodeSignature<FindResponseContent, NodeIdentity>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct StoreRequest {
    pub key: Identity,
    pub value: PublisherAnnouncement,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ChallengeResponse {
    pub sender: NodeIdentity,
    pub signature: Blob,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Message {
    FindRequest(FindRequest),
    FindResponse(FindResponse),
    Store(StoreRequest),
    Ping,
    Pung(NodeIdentity),
    Challenge(Blob),
    ChallengeResponse(ChallengeResponse),
}

impl Message {
    pub fn from_bytes(bytes: &[u8]) -> Result<Message, loga::Error> {
        return Ok(bincode::deserialize(bytes)?);
    }

    pub fn to_bytes(&self) -> Blob {
        return bincode::serialize(self).unwrap().blob();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct NodeState {
    pub node: NodeInfo,
    pub unresponsive: bool,
}
