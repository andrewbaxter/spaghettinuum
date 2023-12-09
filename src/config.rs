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

#[derive(Serialize, Deserialize)]
pub struct Config {
    /// Core DHT node config, for publishing and looking up addresses
    pub node: NodeConfig,
    /// Address for client interaction - resolver lookups, publishing. Required for
    /// publisher and resolver.
    pub public_http_addr: Option<StrSocketAddr>,
    /// Address for administration - listing published data, registering identities,
    /// etc. Required for publisher.
    pub private_http_addr: Option<StrSocketAddr>,
    pub resolver: Option<resolver::config::ResolverConfig>,
    pub publisher: Option<publisher::config::Config>,
}
