use std::{
    path::PathBuf,
};
use schemars::JsonSchema;
use serde::{
    Deserialize,
    Serialize,
};
use crate::data::{
    node::nodeidentity::NodeIdentity,
    utils::StrSocketAddr,
};

#[derive(JsonSchema)]
#[derive(Deserialize, Serialize)]
pub struct BootstrapConfig {
    /// Peer address.
    pub addr: StrSocketAddr,
    /// Node ID at that address.
    pub id: NodeIdentity,
}

#[derive(JsonSchema)]
#[derive(Deserialize, Serialize)]
pub struct NodeConfig {
    /// The address the node will listen on (UDP).
    pub bind_addr: StrSocketAddr,
    /// A list of peers to use to bootstrap the connection.
    pub bootstrap: Vec<BootstrapConfig>,
    /// Where to persist peers across startups.
    pub persist_path: Option<PathBuf>,
}
