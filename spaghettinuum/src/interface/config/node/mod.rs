use std::{
    path::PathBuf,
};
use schemars::JsonSchema;
use serde::{
    Deserialize,
    Serialize,
};
use super::{
    content::ContentConfig,
    shared::{
        IdentitySecretArg,
        GlobalAddrConfig,
    },
};

pub mod publisher_config;
pub mod resolver_config;
pub mod node_config;
pub mod api_config;

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct Config {
    /// An identity secret this server will use for generating a TLS cert for the api,
    /// and for self-publication if the publisher is enabled.
    ///
    /// If not specified, an identity will be generated at `host.ident` in the data
    /// directory.
    #[serde(default)]
    pub identity: Option<IdentitySecretArg>,
    /// How to determine the public ip for publisher announcements and self-publishing.
    /// Publisher announcements always use the first address.
    ///
    /// If empty, defaults to using a gobal IPv6 address found on any interface.
    #[serde(default)]
    pub global_addrs: Vec<GlobalAddrConfig>,
    /// Configuration for the core node. The core node is the DHT participant, used by
    /// the publisher and resolver (always enabled).
    #[serde(default)]
    pub node: node_config::NodeConfig,
    /// The publisher (as named) allows publishing records.
    #[serde(default)]
    pub publisher: publisher_config::PublisherConfig,
    /// The resolver (as named) resolves records for clients. It is exposed on the API
    /// server along with other APIs.
    #[serde(default)]
    pub resolver: resolver_config::ResolverConfig,
    /// An HTTPS server for all client interaction: resolving, publishing, and
    /// administration.
    #[serde(default)]
    pub api: api_config::ApiConfig,
    /// Additionally act as a server for HTTP content (static files or reverse proxy).
    /// Uses the same certificate as the API server.
    #[serde(default)]
    pub content: Vec<ContentConfig>,
}
