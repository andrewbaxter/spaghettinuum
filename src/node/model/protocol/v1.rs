use crate::{
    model::{
        identity::Identity,
    },
    node::model::nodeidentity::NodeIdentity,
};
use serde::{
    Deserialize,
    Serialize,
    Serializer,
};
use std::{
    net::{
        IpAddr,
        Ipv4Addr,
        SocketAddr,
        Ipv6Addr,
    },
    fmt::Display,
};
use sha2::Digest;

pub struct Hash(Vec<u8>);

impl Hash {
    pub fn new(data: &[u8]) -> Self {
        let mut hash = sha2::Sha256::new();
        hash.update(data);
        return Self(hash.finalize().to_vec());
    }
}

#[derive(Debug, Serialize)]
pub struct TempChallengeSigBody<'a, B: Serialize> {
    pub challenge: &'a [u8],
    pub body: &'a B,
}

impl<'a, B: Serialize> TempChallengeSigBody<'a, B> {
    pub fn to_bytes(&self) -> Vec<u8> {
        return bincode::serialize(self).unwrap();
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
pub struct FindRequest {
    pub sender: NodeIdentity,
    pub challenge: Box<[u8]>,
    pub mode: FindMode,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SerialAddr {
    V4(SerialIpv4),
    V6(SerialIpv6),
}

#[derive(Serialize, Deserialize)]
struct SerialIpv4 {
    addr: [u8; 4],
    port: u16,
}

#[derive(Serialize, Deserialize)]
struct SerialIpv6 {
    addr: [u16; 8],
    port: u16,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Addr(pub SocketAddr);

impl Display for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <dyn Display>::fmt(&self.0, f)
    }
}

impl Serialize for Addr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer {
        Serialize::serialize(&match self.0.ip() {
            IpAddr::V4(ip) => SerialAddr::V4(SerialIpv4 {
                addr: ip.octets(),
                port: self.0.port(),
            }),
            IpAddr::V6(ip) => SerialAddr::V6(SerialIpv6 {
                addr: ip.segments(),
                port: self.0.port(),
            }),
        }, serializer)
    }
}

impl<'a> Deserialize<'a> for Addr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'a> {
        Ok(match SerialAddr::deserialize(deserializer)? {
            SerialAddr::V4(addr) => Addr(
                SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(addr.addr[0], addr.addr[1], addr.addr[2], addr.addr[3])),
                    addr.port,
                ),
            ),
            SerialAddr::V6(addr) => Addr(
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
pub struct NodeInfo {
    pub id: NodeIdentity,
    pub address: Addr,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ValueBody {
    pub addr: Addr,
    pub cert_hash: Vec<u8>,
    // Max 24h
    pub expires: chrono::DateTime<chrono::Utc>,
}

impl ValueBody {
    pub fn to_bytes(&self) -> Vec<u8> {
        return bincode::serialize(self).unwrap();
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Value {
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Value {
    pub fn parse(&self) -> Result<ValueBody, loga::Error> {
        return Ok(bincode::deserialize(&self.message)?);
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum FindResponseModeBody {
    Nodes(Vec<NodeInfo>),
    Value(Value),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FindResponseBody {
    pub sender: NodeIdentity,
    pub mode: FindMode,
    pub inner: FindResponseModeBody,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FindResponse {
    pub body: FindResponseBody,
    pub sig: Box<[u8]>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StoreRequest {
    pub key: Identity,
    pub value: Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub sender: NodeIdentity,
    pub signature: Box<[u8]>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Message {
    FindRequest(FindRequest),
    FindResponse(FindResponse),
    Store(StoreRequest),
    Ping,
    Pung(NodeIdentity),
    Challenge(Box<[u8]>),
    ChallengeResponse(ChallengeResponse),
}

impl Message {
    pub fn from_bytes(bytes: &[u8]) -> Result<Message, loga::Error> {
        return Ok(bincode::deserialize(bytes)?);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }
}
