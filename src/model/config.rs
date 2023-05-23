use std::{
    net::SocketAddr,
    path::PathBuf,
};
use serde::{
    Deserialize,
    Serialize,
};
use crate::{
    node::model::nodeidentity::NodeIdentity,
    resolver,
    publisher,
};

#[derive(Deserialize, Serialize)]
pub struct BootstrapConfig {
    pub addr: SocketAddr,
    pub id: NodeIdentity,
}

#[derive(Deserialize, Serialize)]
pub struct NodeConfig {
    pub bind_addr: SocketAddr,
    pub bootstrap: Vec<BootstrapConfig>,
    pub persist_path: Option<PathBuf>,
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub node: NodeConfig,
    pub resolver: Option<resolver::ResolverConfig>,
    pub publisher: Option<publisher::model::config::Config>,
}
