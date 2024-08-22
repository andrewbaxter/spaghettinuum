use {
    super::{
        content::ContentConfig,
        shared::{
            IdentitySecretArg,
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
pub struct Config {
    /// Where to put cache files.  If not specified, uses the `CACHE_DIR` environment
    /// variable.
    pub cache_dir: Option<PathBuf>,
    /// How to identify and select globally routable IP addresses for this host
    #[serde(default)]
    pub global_addrs: Vec<GlobalAddrConfig>,
    /// Identity to use for publishing
    pub identity: IdentitySecretArg,
    /// A list of paths to host keys to publish for this host. If not specified, a
    /// default SSH host key location will be used, otherwise no SSH host keys will be
    /// published.
    #[serde(default)]
    pub ssh_host_keys: Option<Vec<PathBuf>>,
    /// Where to store TLS certs.  This directory and its parents will be created if
    /// they don't already exist.  The certs will be named `pub.pem` and `priv.pem`.
    #[serde(default)]
    pub cert_dir: Option<PathBuf>,
    /// Content to serve, in addition to keeping certs up to date.
    #[serde(default)]
    pub content: Vec<ContentConfig>,
}
