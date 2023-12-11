use std::{
    path::PathBuf,
    net::SocketAddr,
};
use serde::{
    Serialize,
    Deserialize,
};
use crate::data::{
    utils::StrSocketAddr,
};

#[derive(Deserialize, Serialize)]
pub struct AdvertiseAddrLookupConfig {
    pub lookup: String,
    pub port: u16,
    /// Use IPv4 to contact lookup in order to get an IPv4 address back
    pub ipv4_only: bool,
    /// Use IPv6 to contact lookup in order to get an IPv6 address back
    pub ipv6_only: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdvertiseAddrConfigIpVer {
    // Look for an interface with a public Ipv4 address
    V4,
    // Look for an interface with a public Ipv6 address
    V6,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdvertiseAddrConfig {
    /// Use this if you know the IP address beforehand (ex: in terraform, if you
    /// allocate a floating ip before provisioning this host) and it's not the address
    /// of any local interface.
    Fixed(SocketAddr),
    /// If your server is directly on the internet, with an externally reachable IP
    /// configured on an interface, this will cause that IP to be used. Specify an
    /// interface name (ex: `eth0`) or leave blank to scan all interfaces for a public
    /// IP.  All ipv6 addresses are considered public.
    FromInterface {
        name: Option<String>,
        ip_version: Option<AdvertiseAddrConfigIpVer>,
        port: u16,
    },
    /// Curl this URL, use the response body as the IP address
    Lookup(AdvertiseAddrLookupConfig),
}

#[derive(Deserialize, Serialize)]
pub struct Config {
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
