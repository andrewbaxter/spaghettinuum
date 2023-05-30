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
};

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub node: NodeConfig,
    pub resolver: Option<resolver::config::ResolverConfig>,
    pub publisher: Option<publisher::config::Config>,
}
