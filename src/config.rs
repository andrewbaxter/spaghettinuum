use schemars::JsonSchema;
use serde::{
    Deserialize,
    Serialize,
};
use crate::{
    node::{
        config::NodeConfig,
    },
    resolver,
    publisher,
    data::utils::StrSocketAddr,
};

#[derive(JsonSchema)]
#[derive(Serialize, Deserialize)]
pub struct Config {
    /// Core DHT node config, for publishing and looking up addresses
    pub node: NodeConfig,
    /// Address for client interaction - resolver lookups, publishing. Required for
    /// publisher and resolver.  This must be externally accessible.
    pub public_http_addr: Option<StrSocketAddr>,
    /// Address for administration - listing published data, registering identities,
    /// etc. Required for publisher.  This is unauthenticated - it should not be opened
    /// to the world (if you need to access it, do it via a SSH tunnel).
    pub private_http_addr: Option<StrSocketAddr>,
    /// Specify to enable resolver functionality.
    pub resolver: Option<resolver::config::ResolverConfig>,
    /// Specify to enable publisher functionality.
    pub publisher: Option<publisher::config::PublisherConfig>,
}
