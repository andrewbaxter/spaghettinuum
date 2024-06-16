use schemars::JsonSchema;
use serde::{
    Deserialize,
    Serialize,
};
use crate::interface::config::shared::StrSocketAddr;

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct DnsBridgeConfig {
    /// Normal DNS - typically port 53.
    #[serde(default)]
    pub udp_bind_addrs: Vec<StrSocketAddr>,
    /// TCP for DNS over TLS. Please set up your own TLS reverse proxy.
    #[serde(default)]
    pub tcp_bind_addrs: Vec<StrSocketAddr>,
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
