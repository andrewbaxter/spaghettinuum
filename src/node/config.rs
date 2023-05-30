use std::{
    net::SocketAddr,
    path::PathBuf,
};
use serde::{
    Deserialize,
    Serialize,
};
use crate::data::node::nodeidentity::NodeIdentity;

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
