use schemars::JsonSchema;
use serde::{
    Deserialize,
    Serialize,
};
use crate::interface::config::shared::StrSocketAddr;

#[derive(Deserialize, Serialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub struct DnsBridgeConfig {
    /// DNS is on by default, specify this to disable.
    #[serde(default)]
    pub disable: bool,
    /// Normal UDP DNS (Do53).
    ///
    /// Defaults to `[::]:53` and `0:53`.
    #[serde(default)]
    pub udp_bind_addrs: Vec<StrSocketAddr>,
    /// DNS over TLS. Uses a self-provisioned spaghettinuum certificate.
    ///
    /// Defaults to `[::]:853` and `0:853`.
    #[serde(default)]
    pub tcp_bind_addrs: Vec<StrSocketAddr>,
}

#[derive(Deserialize, Serialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub struct ResolverConfig {
    /// Maximum number of entries (identity, key pairs) in resolver cache.
    #[serde(default)]
    pub max_cache: Option<u64>,
    /// The DNS bridge exposes specific spaghettinuum `dns/` records over DNS.
    #[serde(default)]
    pub dns_bridge: DnsBridgeConfig,
}
