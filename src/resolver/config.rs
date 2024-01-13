use std::path::PathBuf;
use schemars::JsonSchema;
use serde::{
    Deserialize,
    Serialize,
};
use crate::interface::spagh_cli::StrSocketAddr;

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DnsType {
    Udp,
    Tls,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct TlsConfig {
    /// DNS over TLS (DoT) socket addresses to bind to.
    pub bind_addrs: Vec<StrSocketAddr>,
    /// Path to public cert PEM file.
    pub pub_pem_path: PathBuf,
    /// Path to private cert PEM file.
    pub priv_pem_path: PathBuf,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct DnsBridgeConfig {
    /// Upstream DNS server, where non-spaghettinuum requests will be sent.
    pub upstream: StrSocketAddr,
    /// If not specified, guess the upstream protocol based on the port.
    #[serde(default)]
    pub upstream_type: Option<DnsType>,
    /// Normal DNS - typically port 53.
    #[serde(default)]
    pub udp_bind_addrs: Vec<StrSocketAddr>,
    /// TCP for DNS over TLS, but you need to proxy the TLS connection. Can be whatever
    /// (proxy's external port is normally 853).
    #[serde(default)]
    pub tcp_bind_addrs: Vec<StrSocketAddr>,
    /// Self managed DNS over TLS.
    #[serde(default)]
    pub tls: Option<TlsConfig>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct ResolverConfig {
    /// Maximum number of entries (identity, key pairs) in resolver cache.
    #[serde(default)]
    pub max_cache: Option<u64>,
    /// Specify to enable the DNS bridge.
    #[serde(default)]
    pub dns_bridge: Option<DnsBridgeConfig>,
}
