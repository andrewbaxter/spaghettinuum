use schemars::JsonSchema;
use serde::{
    Deserialize,
    Serialize,
};
use crate::interface::{
    config::shared::StrSocketAddr,
    stored::node_identity::NodeIdentity,
};

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct BootstrapConfig {
    /// Peer address.
    pub addr: StrSocketAddr,
    /// Node ID at that address.
    pub ident: NodeIdentity,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct NodeConfig {
    /// The address the node will listen on (UDP).
    pub bind_addr: StrSocketAddr,
    /// A list of peers to use to bootstrap the connection.
    #[serde(default)]
    pub bootstrap: Vec<BootstrapConfig>,
}
