use {
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
    },
    crate::interface::{
        config::shared::StrSocketAddr,
        stored::node_identity::NodeIdentity,
    },
};

pub const DEFAULT_NODE_PORT: u16 = 48390;

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct BootstrapConfig {
    /// Peer address.
    pub addr: StrSocketAddr,
    /// Node ID at that address.
    pub ident: NodeIdentity,
}

#[derive(Deserialize, Serialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub struct NodeConfig {
    /// The address the node will listen on (UDP).
    ///
    /// Defaults to `[::]:48390` - any open port on any IPv6 interface.
    #[serde(default)]
    pub bind_addr: Option<StrSocketAddr>,
    /// A list of peers to use to bootstrap the connection.
    ///
    /// Defaults to the current `antipasta` node at time of build.
    #[serde(default)]
    pub bootstrap: Option<Vec<BootstrapConfig>>,
}
