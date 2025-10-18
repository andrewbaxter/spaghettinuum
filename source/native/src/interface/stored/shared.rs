use std::net::{
    IpAddr,
    Ipv4Addr,
    Ipv6Addr,
    SocketAddr,
};
use serde::{
    Deserialize,
    Serialize,
    Serializer,
};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum SerialAddrInner {
    V4(SerialIpv4),
    V6(SerialIpv6),
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct SerialIpv4 {
    addr: [u8; 4],
    port: u16,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct SerialIpv6 {
    addr: [u16; 8],
    port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerialAddr(pub SocketAddr);

impl std::fmt::Display for SerialAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <dyn std::fmt::Display>::fmt(&self.0, f)
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
