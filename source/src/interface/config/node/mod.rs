use {
    super::{
        content::ContentConfig,
        shared::{
            GlobalAddrConfig,
            IdentitySecretArg,
        },
    },
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
    },
    std::path::PathBuf,
};

pub mod publisher_config;
pub mod resolver_config;
pub mod node_config;
pub mod api_config;

#[derive(Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub struct Config {
    /// Where persistent files will be placed. You may want to back this up
    /// periodically. If not specified, uses a default directory based on the
    /// `DATA_DIRECTORY` environment variable.
    pub persistent_dir: Option<PathBuf>,
    /// Where cache files will be placed. If not specified, uses a default directory
    /// based on the `CACHE_DIRECTORY` environment variable.
    pub cache_dir: Option<PathBuf>,
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
    pub publisher: Option<publisher_config::PublisherConfig>,
    /// The resolver (as named) resolves records for clients. It is exposed on the API
    /// server along with other APIs.
    #[serde(default)]
    pub resolver: Option<resolver_config::ResolverConfig>,
    /// An HTTPS server for all client interaction except DNS: resolving, publishing,
    /// and administration. It is disabled if not present or null, but to enable it
    /// with defaults you can provide an empty config.
    #[serde(default)]
    pub api: Option<api_config::ApiConfig>,
    /// Additionally serve more HTTP content, using the host cert.
    #[serde(default)]
    pub content: Option<Vec<ContentConfig>>,
    /// Disable certifier signature of certs (still verifiable via spagh record)
    #[serde(default)]
    pub no_certifier: bool,
}
