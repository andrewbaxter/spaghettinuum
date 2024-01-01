use schemars::JsonSchema;
use serde::{
    Deserialize,
    Serialize,
};
use crate::interface::spagh_cli::StrSocketAddr;

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct ResolverConfig {
    /// Maximum number of entries (identity, key pairs) in resolver cache.
    pub max_cache: Option<u64>,
    /// Specify to enable the DNS bridge.
    pub dns_bridge: Option<DnsBridgeConfig>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct DnsBridgeConfig {
    /// Upstream DNS server.
    pub upstream: StrSocketAddr,
    /// UDP bind address - typically port 53.
    pub bind_addr: StrSocketAddr,
}
