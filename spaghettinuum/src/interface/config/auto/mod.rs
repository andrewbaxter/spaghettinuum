use std::path::PathBuf;
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

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ServeMode {
    StaticFiles {
        /// Where files to serve are
        content_dir: PathBuf,
    },
    ReverseProxy {
        /// Base url of upstream HTTP server. The request path is appended.
        upstream_url: String,
    },
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct ContentConfig {
    /// Interface IPs and ports to bind to
    pub bind_addrs: Vec<StrSocketAddr>,
    /// What content to serve
    #[serde(default)]
    pub mode: Option<ServeMode>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct ServeConfig {
    /// Where to store TLS certs.  This directory and its parents will be created if
    /// they don't already exist.  The certs will be named `pub.pem` and `priv.pem`.
    pub cert_dir: PathBuf,
    /// How to serve content.  If not specified, just keeps certificates in the cert
    /// dir up to date.
    #[serde(default)]
    pub content: Option<ContentConfig>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct Config {
    /// How to identify and select globally routable IP addresses for this host
    pub global_addrs: Vec<GlobalAddrConfig>,
    /// Identity to use for publishing
    pub identity: BackedIdentityArg,
    /// Url of publisher where this identity is authorized to publish
    pub publishers: Vec<String>,
    /// Configure HTTPS serving using certipasta certs
    #[serde(default)]
    pub serve: Option<ServeConfig>,
}
