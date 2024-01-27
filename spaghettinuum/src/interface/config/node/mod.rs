use std::{
    path::PathBuf,
};
use schemars::JsonSchema;
use serde::{
    Deserialize,
    Serialize,
};
use super::shared::{
    BackedIdentityArg,
    GlobalAddrConfig,
    StrSocketAddr,
};

pub mod publisher_config;
pub mod resolver_config;
pub mod node_config;

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct SelfIdentityConfig {
    pub identity: BackedIdentityArg,
    /// Retrieve a TLS cert for the identity's domain (`.s`) and configure TLS on the
    /// public endpoint (https instead of http) via `certipasta.isandrew.com`.
    pub self_tls: bool,
    /// Wait for a local interface configured with a public ip and publish it using
    /// this server's identity.
    pub self_publish: bool,
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct Config {
    /// Path to a dir for subsystems to store persistent data (mostly sqlite
    /// databases). Will be created if it doesn't exist.
    pub persistent_dir: PathBuf,
    /// How to determine the public ip for publisher advertisements and
    /// self-publishing. Publisher advertisements always use the first address.
    #[serde(default)]
    pub global_addrs: Vec<GlobalAddrConfig>,
    /// Core DHT node config, for publishing and looking up addresses
    pub node: node_config::NodeConfig,
    /// Specify to enable resolver functionality.
    #[serde(default)]
    pub resolver: Option<resolver_config::ResolverConfig>,
    /// Specify to enable publisher functionality.
    #[serde(default)]
    pub publisher: Option<publisher_config::PublisherConfig>,
    /// Addresses for client interaction - resolver lookups, publishing, and admin.
    /// Required for publisher and resolver.  This serves both token-protected and
    /// public endpoints.
    #[serde(default)]
    pub api_bind_addrs: Vec<StrSocketAddr>,
    /// When configuring the publisher, admin endpoints must be accessed with this as a
    /// bearer http authorization token.  Required for publisher.
    #[serde(default)]
    pub admin_token: Option<String>,
    /// An backed identity (by file or card) this server can use as its own.  See the
    /// structure fields for more information on what this provides.
    #[serde(default)]
    pub identity: Option<SelfIdentityConfig>,
}
