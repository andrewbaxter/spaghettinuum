use std::{
    net::SocketAddr,
    path::PathBuf,
};
use serde::{
    Deserialize,
    Serialize,
};

#[derive(Deserialize, Serialize)]
pub struct ResolverConfig {
    pub bind_addr: Option<SocketAddr>,
    pub cache_persist_path: Option<PathBuf>,
    pub max_cache: Option<u64>,
    pub dns_bridge: Option<DnsBridgerConfig>,
}

#[derive(Deserialize, Serialize)]
pub struct DnsBridgerConfig {
    pub upstream: SocketAddr,
    pub bind_addr: SocketAddr,
}
