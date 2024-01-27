use schemars::JsonSchema;
use serde::{
    Serialize,
    Deserialize,
};
use crate::interface::config::shared::StrSocketAddr;

pub const PORT_PUBLISHER: u16 = 43891;

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct PublisherConfig {
    /// Port to bind for serving published data to other nodes
    pub bind_addr: StrSocketAddr,
    /// Port the publisher is externally reachable on, for advertisements (if different
    /// from bind port).
    pub advertise_port: Option<u16>,
}
