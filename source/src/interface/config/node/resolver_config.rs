use {
    crate::interface::config::shared::{
        AdnSocketAddr,
        StrSocketAddr,
    },
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
    },
};

#[derive(Deserialize, Serialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub struct DnsBridgeConfig {
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
    /// Upstream resolvers, such as for non-`.s` names. Each address port defaults to
    /// port 53 if no ADN, otherwise 853. If not specified, uses system resolvers.
    #[serde(default)]
    pub upstream: Option<Vec<AdnSocketAddr>>,
}

#[derive(Deserialize, Serialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub struct ResolverConfig {
    /// Maximum number of entries (identity, key pairs) in resolver cache.
    #[serde(default)]
    pub max_cache: Option<u64>,
    /// The DNS bridge exposes specific spaghettinuum `dns/` records over DNS.
    #[serde(default)]
    pub dns_bridge: Option<DnsBridgeConfig>,
}
