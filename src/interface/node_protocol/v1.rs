use serde::Serializer;
use serde::{
    Serialize,
    Deserialize,
};
use core::fmt::Debug;
use std::fmt::Display;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use ed25519_dalek;
use ed25519_dalek::Signature;
use sha2::Digest;
use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use ed25519_dalek::Verifier;
use ed25519_dalek::VerifyingKey;
use loga::ResultContext;
use rand::rngs::OsRng;
use crate::interface::identity::Identity;
use super::NodeIdentityMethods;
use super::NodeSecretMethods;

// Ed25519
#[derive(PartialEq, Eq, Clone)]
pub struct Ed25519NodeIdentity(VerifyingKey);

impl Serialize for Ed25519NodeIdentity {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        return Serialize::serialize(self.0.as_bytes(), serializer);
    }
}

impl<'de> Deserialize<'de> for Ed25519NodeIdentity {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de> {
        return Ok(
            Ed25519NodeIdentity(
                VerifyingKey::from_bytes(
                    &<[u8; ed25519_dalek::PUBLIC_KEY_LENGTH]>::deserialize(deserializer)
                        .context("Failed to extract identity bytes")
                        .map_err(|e| serde::de::Error::custom(e.to_string()))?,
                ).map_err(|e| serde::de::Error::custom(format!("Failed to parse bytes as ed25519 key: {}", e)))?,
            ),
        );
    }
}

impl Debug for Ed25519NodeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Ed25519NodeId").field(&zbase32::encode_full_bytes(&self.0.to_bytes())).finish()
    }
}

impl core::hash::Hash for Ed25519NodeIdentity {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(&self.0.to_bytes());
    }
}

impl Ed25519NodeIdentity {
    pub fn new() -> (Self, Ed25519NodeSecret) {
        let keypair = SigningKey::generate(&mut OsRng {});
        return (Self(keypair.verifying_key()), Ed25519NodeSecret(keypair));
    }
}

impl NodeIdentityMethods for Ed25519NodeIdentity {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), loga::Error> {
        self.0.verify(message, &Signature::from_slice(signature)?)?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Ed25519NodeSecret(SigningKey);

impl Ed25519NodeSecret {
    pub fn get_identity(&self) -> Ed25519NodeIdentity {
        Ed25519NodeIdentity(self.0.verifying_key())
    }
}

impl Serialize for Ed25519NodeSecret {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        return Serialize::serialize(&self.0.to_bytes(), serializer);
    }
}

impl<'de> Deserialize<'de> for Ed25519NodeSecret {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de> {
        return Ok(
            Ed25519NodeSecret(
                SigningKey::from_bytes(
                    &<[u8; ed25519_dalek::SECRET_KEY_LENGTH]>::deserialize(deserializer)
                        .context("Failed to extract secret bytes")
                        .map_err(|e| serde::de::Error::custom(e.to_string()))?,
                ),
            ),
        );
    }
}

impl NodeSecretMethods for Ed25519NodeSecret {
    fn sign(&self, message: &[u8]) -> Box<[u8]> {
        return self.0.sign(message).to_bytes().to_vec().into_boxed_slice();
    }
}

// Aggregates
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "snake_case")]
pub enum NodeIdentity {
    Ed25519(Ed25519NodeIdentity),
}

impl Display for NodeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", zbase32::encode_full_bytes(&bincode::serialize(self).unwrap()))
    }
}

impl NodeIdentity {
    pub fn from_bytes(message: &[u8]) -> Result<Self, loga::Error> {
        return Ok(bincode::deserialize(message).context("Bincode decode failed")?);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        return bincode::serialize(self).unwrap();
    }
}

impl NodeIdentityMethods for NodeIdentity {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), loga::Error> {
        match self {
            NodeIdentity::Ed25519(i) => i.verify(message, signature),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeSecret {
    Ed25519(Ed25519NodeSecret),
}

impl NodeSecret {
    pub fn from_bytes(message: &[u8]) -> Result<Self, loga::Error> {
        return Ok(bincode::deserialize(message).context("Bincode decode failed")?);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        return bincode::serialize(self).unwrap();
    }

    pub fn get_identity(&self) -> NodeIdentity {
        match self {
            NodeSecret::Ed25519(v) => NodeIdentity::Ed25519(v.get_identity()),
        }
    }
}

impl NodeSecretMethods for NodeSecret {
    fn sign(&self, message: &[u8]) -> Box<[u8]> {
        match self {
            NodeSecret::Ed25519(i) => i.sign(message),
        }
    }
}

pub struct Hash(Vec<u8>);

impl Hash {
    pub fn new(data: &[u8]) -> Self {
        let mut hash = sha2::Sha256::new();
        hash.update(data);
        return Self(hash.finalize().to_vec());
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
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
#[serde(rename_all = "snake_case")]
pub struct FindRequest {
    pub sender: NodeIdentity,
    pub challenge: Box<[u8]>,
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
    pub id: NodeIdentity,
    pub address: SerialAddr,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct ValueBody {
    pub addr: SerialAddr,
    pub cert_hash: Vec<u8>,
    pub published: chrono::DateTime<chrono::Utc>,
}

impl ValueBody {
    pub fn to_bytes(&self) -> Vec<u8> {
        return bincode::serialize(self).unwrap();
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, loga::Error> {
        return Ok(bincode::deserialize(data)?);
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Value {
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
    // Max 24h
    pub expires: chrono::DateTime<chrono::Utc>,
}

impl Value {
    pub fn parse(&self) -> Result<ValueBody, loga::Error> {
        return ValueBody::from_bytes(&self.message);
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum FindResponseModeBody {
    Nodes(Vec<NodeInfo>),
    Value(Value),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct FindResponseBody {
    pub sender: NodeIdentity,
    pub mode: FindMode,
    pub inner: FindResponseModeBody,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct FindResponse {
    pub body: FindResponseBody,
    pub sig: Box<[u8]>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct StoreRequest {
    pub key: Identity,
    pub value: Value,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct NodeState {
    pub node: NodeInfo,
    pub unresponsive: bool,
}
