use {
    super::{
        content::ContentConfig,
        shared::{
            BackedIdentityArg,
            GlobalAddrConfig,
        },
    },
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
    },
    std::path::PathBuf,
};

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct ServeConfig {
    /// Where to store TLS certs.  This directory and its parents will be created if
    /// they don't already exist.  The certs will be named `pub.pem` and `priv.pem`.
    pub cert_dir: PathBuf,
    /// How to serve content.  If not specified, just keeps certificates in the cert
    /// dir up to date.
    #[serde(default)]
    pub content: Vec<ContentConfig>,
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
