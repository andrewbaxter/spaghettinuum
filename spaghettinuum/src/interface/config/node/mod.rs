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
        BackedIdentityArg,
        GlobalAddrConfig,
        StrSocketAddr,
    },
};

pub mod publisher_config;
pub mod resolver_config;
pub mod node_config;

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AdminToken {
    File(PathBuf),
    Inline(String),
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct Config {
    /// Path to a dir for subsystems to store persistent data (mostly sqlite
    /// databases). Will be created if it doesn't exist.
    pub persistent_dir: PathBuf,
    /// A backed identity (by file or card) this server will use for generating a tls
    /// cert for the api, and for self-publication if the publisher is enabled.
    pub identity: BackedIdentityArg,
    /// How to determine the public ip for publisher announcements and self-publishing.
    /// Publisher announcements always use the first address.
    #[serde(default)]
    pub global_addrs: Vec<GlobalAddrConfig>,
    /// Core DHT node config, for publishing and looking up addresses
    pub node: node_config::NodeConfig,
    /// Configure publisher - must be enabled because api tls certs refer to the node's
    /// address and so the node must self-publish.
    pub publisher: publisher_config::PublisherConfig,
    /// Specify to enable resolver functionality.
    #[serde(default)]
    pub resolver: Option<resolver_config::ResolverConfig>,
    /// Addresses for client interaction - resolver lookups, publishing, and admin.
    /// Required for publisher and resolver.  This serves both token-protected and
    /// public endpoints.
    #[serde(default)]
    pub api_bind_addrs: Vec<StrSocketAddr>,
    /// HTTP authorization bearer token for accessing publisher admin endpoints. If
    /// None, remote admin operations will be disabled (only self-publish on this node
    /// will work since there will be no way to register publishing identities).
    #[serde(default)]
    pub admin_token: Option<AdminToken>,
    /// Additionally act as a server for http content (static files or reverse proxy)
    /// with a `.s` tls cert.
    #[serde(default)]
    pub content: Vec<ContentConfig>,
}
