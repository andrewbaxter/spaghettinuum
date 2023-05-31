use std::{
    path::PathBuf,
};
use serde::{
    Deserialize,
    Serialize,
};
use crate::data::{
    node::nodeidentity::NodeIdentity,
    utils::StrSocketAddr,
};

#[derive(Deserialize, Serialize)]
pub struct BootstrapConfig {
    pub addr: StrSocketAddr,
    pub id: NodeIdentity,
}

#[derive(Deserialize, Serialize)]
pub struct NodeConfig {
    pub bind_addr: StrSocketAddr,
    pub bootstrap: Vec<BootstrapConfig>,
    pub persist_path: Option<PathBuf>,
}
