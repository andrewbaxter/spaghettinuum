use std::{
    path::PathBuf,
    net::SocketAddr,
};
use schemars::JsonSchema;
use serde::{
    Serialize,
    Deserialize,
};
use crate::data::{
    utils::StrSocketAddr,
};

#[derive(JsonSchema)]
#[derive(Deserialize, Serialize)]
pub struct AdvertiseAddrLookupConfig {
    /// Host to look up address on.
    pub lookup: String,
    /// Port to use for the generated socket address (not related to lookup).
    pub port: u16,
    /// Use IPv4 to contact lookup in order to get an IPv4 address back
    pub ipv4_only: bool,
    /// Use IPv6 to contact lookup in order to get an IPv6 address back
    pub ipv6_only: bool,
}

#[derive(JsonSchema)]
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdvertiseAddrConfigIpVer {
    /// Look for an interface with a public Ipv4 address
    V4,
    /// Look for an interface with a public Ipv6 address
    V6,
}

#[derive(JsonSchema)]
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdvertiseAddrConfig {
    /// Use this if you know the IP address beforehand (ex: in terraform, if you
    /// allocate a floating ip before provisioning this host) and it's not the address
    /// of any local interface.
    Fixed(SocketAddr),
    /// If your server is directly on the internet (with an externally reachable IP
    /// configured on an interface) this will cause that IP to be used. Specify an
    /// interface name (ex: `eth0`) or leave blank to scan all interfaces for a public
    /// IP.  All ipv6 addresses are considered public.
    FromInterface {
        /// Interface name, like `eth0`.
        name: Option<String>,
        /// Which address version to look for, or any if empty.
        ip_version: Option<AdvertiseAddrConfigIpVer>,
        /// Port to attach to the output socket address.
        port: u16,
    },
    /// Look up a socket address via a remote service (ex: whatismyip). The service
    /// must reply with the ip address as plain text.
    Lookup(AdvertiseAddrLookupConfig),
}

#[derive(JsonSchema)]
#[derive(Deserialize, Serialize)]
pub struct PublisherConfig {
    /// Port to bind for serving published data to other nodes, secured with announced
    /// ssl cert
    pub bind_addr: StrSocketAddr,
    /// A cert will be generated and stored here if one doesn't already exist. Custom
    /// format (not pem). This is a filename, not directory name.
    pub cert_path: PathBuf,
    /// URL other nodes will connect to to retrieve data - your external address.
    pub advertise_addr: AdvertiseAddrConfig,
    /// The database will be created and stored here. This is a filename, not directory
    /// name.
    pub db_path: PathBuf,
}
