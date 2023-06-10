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
pub enum AdvertiseAddrConfig {
    Fixed(SocketAddr),
    /// Curl this URL, use the response body as the IP address
    Lookup(AdvertiseAddrLookupConfig),
}

#[derive(Deserialize, Serialize)]
pub struct Config {
    /// Port to bind for serving published data to other nodes
    pub bind_addr: StrSocketAddr,
    /// A cert will be generated and stored here if one doesn't already exist. Custom
    /// format (not pem).
    pub cert_path: PathBuf,
    /// URL other nodes will connect to to retrieve data - should match however to
    /// reach bind_addr externally (i.e. http/https, public instead of local ip)
    pub advertise_addr: AdvertiseAddrConfig,
    pub db_path: PathBuf,
    /// Port to bind to for admin api
    pub admin_bind_addr: StrSocketAddr,
}
