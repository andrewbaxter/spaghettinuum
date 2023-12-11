use std::{
    path::PathBuf,
};
use schemars::JsonSchema;
use serde::{
    Deserialize,
    Serialize,
};
use crate::data::utils::StrSocketAddr;

#[derive(JsonSchema)]
#[derive(Deserialize, Serialize)]
pub struct ResolverConfig {
    /// Where to persist the resolver cache. This is a sqlite filename.
    pub cache_persist_path: Option<PathBuf>,
    /// Maximum number of entries (identity, key pairs) in resolver cache.
    pub max_cache: Option<u64>,
    /// Specify to enable the DNS bridge.
    pub dns_bridge: Option<DnsBridgeConfig>,
}

#[derive(JsonSchema)]
#[derive(Deserialize, Serialize)]
pub struct DnsBridgeConfig {
    /// Upstream DNS server.
    pub upstream: StrSocketAddr,
    /// UDP bind address - typically port 53.
    pub bind_addr: StrSocketAddr,
}
