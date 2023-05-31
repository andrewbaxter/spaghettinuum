use std::{
    path::PathBuf,
};
use serde::{
    Deserialize,
    Serialize,
};
use crate::data::utils::StrSocketAddr;

#[derive(Deserialize, Serialize)]
pub struct ResolverConfig {
    pub bind_addr: Option<StrSocketAddr>,
    pub cache_persist_path: Option<PathBuf>,
    pub max_cache: Option<u64>,
    pub dns_bridge: Option<DnsBridgerConfig>,
}

#[derive(Deserialize, Serialize)]
pub struct DnsBridgerConfig {
    pub upstream: StrSocketAddr,
    pub bind_addr: StrSocketAddr,
}
