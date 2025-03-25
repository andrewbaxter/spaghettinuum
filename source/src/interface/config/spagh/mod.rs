use {
    super::shared::{
        AdnSocketAddr,
        GlobalAddrConfig,
        IdentitySecretArg,
        StrSocketAddr,
    },
    crate::interface::stored::node_identity::NodeIdentity,
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
    },
    std::{
        collections::HashMap,
        path::PathBuf,
    },
};

pub const DEFAULT_NODE_PORT: u16 = 48390;

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct BootstrapConfig {
    /// Peer address.
    pub addr: StrSocketAddr,
    /// Node ID at that address.
    pub ident: NodeIdentity,
}

#[derive(Deserialize, Serialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct TlsConfig {
    /// Disable certifier signature of certs.
    ///
    /// The certs will still be published in spaghettinuum and therefore verifiable via
    /// spaghettinuum lookup.
    ///
    /// Certifier signature is important for general http clients that don't support
    /// spaghettinuum natively as well as systems that don't have spaghettinuum access
    /// yet (like DNS clients). If you're just using service discovery or non-http
    /// protocols, or you're running on a host with no persistent storage to store
    /// certificates disabling certifier usage may avoid rate limit issues.
    #[serde(default)]
    pub no_certifier: bool,
}

#[derive(Deserialize, Serialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct NodeConfig {
    /// The address the node will listen on (UDP).
    ///
    /// Defaults to `[::]:48390` - any open port on any IPv6 interface.
    #[serde(default)]
    pub bind_addr: Option<StrSocketAddr>,
    /// A list of peers to use to bootstrap the connection.
    ///
    /// Defaults to the current `antipasta` node at time of build.
    #[serde(default)]
    pub bootstrap: Option<Vec<BootstrapConfig>>,
}

pub const DEFAULT_API_PORT: u16 = 12434;

#[derive(Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ApiConfig {
    /// Addresses for the server to listen on for client interaction.
    ///
    /// If empty or not specified, defaults to `[::]:12434` and `0:12434`.
    #[serde(default)]
    pub bind_addrs: Vec<StrSocketAddr>,
}

pub const DEFAULT_PUBLISHER_PORT: u16 = 48391;

#[derive(Deserialize, Serialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct PublisherConfig {
    /// Port to bind for serving published data to other nodes
    ///
    /// Defaults to `[::]:48391` - any open port on any IPv6 interface.
    #[serde(default)]
    pub bind_addr: Option<StrSocketAddr>,
    /// Port the publisher is externally reachable on, for advertisements (if different
    /// from bind port).
    #[serde(default)]
    pub advertise_port: Option<u16>,
}

#[derive(Deserialize, Serialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ResolverConfig {
    /// Maximum number of entries in resolver cache.
    #[serde(default)]
    pub max_cache: Option<u64>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AdminToken {
    File(PathBuf),
    Inline(String),
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FunctionAdmin {
    /// HTTP authorization `Bearer` token for accessing publisher admin endpoints.
    ///
    /// If not specified, remote admin operations will be disabled (only self-publish
    /// on this node will work since there will be no way to register publishing
    /// identities).
    pub admin_token: AdminToken,
}

#[derive(Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FunctionPublishSelfSshKeys {
    /// A list of paths to SSH host keys to self-publish for this host.
    ///
    /// If empty or not specified default SSH host key locations will be used.
    #[serde(default)]
    pub ssh_host_keys: Vec<PathBuf>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FunctionWriteTls {
    /// The location to write the certificates to whenever they're refreshed. The
    /// certificates will be named `pub.pem` and `priv.pem`.
    pub write_certs_dir: PathBuf,
}

#[derive(Deserialize, Serialize, JsonSchema, Default, Clone)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FunctionResolverDns {
    /// Normal UDP DNS (Do53).
    ///
    /// Defaults to `[::]:53` and `0:53` if not specified; set to an empty list to
    /// disable.
    #[serde(default)]
    pub udp_bind_addrs: Option<Vec<StrSocketAddr>>,
    /// DNS over TLS. Uses a self-provisioned spaghettinuum certificate.
    ///
    /// Defaults to `[::]:853` and `0:853` if not specified; set to an empty list to
    /// disable.
    #[serde(default)]
    pub tcp_bind_addrs: Option<Vec<StrSocketAddr>>,
    /// Create a synthetic A/AAAA record with this name pointing to this host. This
    /// uses the global addresses specified in the root config.
    #[serde(default)]
    pub synthetic_self_record: Option<String>,
}

#[derive(Serialize, Deserialize, JsonSchema, Clone)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ContentSource {
    StaticFiles {
        /// Where files to serve are.
        content_dir: PathBuf,
    },
    ReverseProxy {
        /// Base url of upstream HTTP server. The request path is appended.
        upstream_url: String,
    },
}

/// Map of socket address -> route (empty path with no slash, or slash-prefixed
/// path) -> content to serve.
pub type FunctionServeContent = HashMap<StrSocketAddr, HashMap<String, ContentSource>>;

#[derive(Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Config {
    // # External inputs
    //
    // ---
    /// Where persistent files will be placed, such as published records. You may want
    /// to back this up periodically.
    pub persistent_dir: PathBuf,
    /// Where cache files will be placed.
    pub cache_dir: PathBuf,
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
    /// If empty, defaults to using the first gobal IPv6 address found on any interface.
    #[serde(default)]
    pub global_addrs: Vec<GlobalAddrConfig>,
    /// Upstream resolvers. These are used for any dns resolution needed internally
    /// (namely, contacting the certifier for self-tls), as well  as resolving non-`.s`
    /// names in the dns bridge. Each address port defaults to port 53 if no ADN,
    /// otherwise 853. If not specified, uses system resolvers.
    #[serde(default)]
    pub upstream_dns: Option<Vec<AdnSocketAddr>>,
    // # Core internal service override config
    //
    // ---
    #[serde(default)]
    pub tls: TlsConfig,
    /// Override default configuration for the node (DHT participant).
    #[serde(default)]
    pub node: NodeConfig,
    /// Override default configuration for the publisher.
    #[serde(default)]
    pub publisher: PublisherConfig,
    /// The resolver (as named) resolves records for clients. It is exposed on the API
    /// server along with other APIs.
    #[serde(default)]
    pub resolver: ResolverConfig,
    /// An HTTPS server for all client interaction except DNS: resolving, publishing,
    /// and administration. It is disabled if not present or null, but to enable it
    /// with defaults you can provide an empty config.
    #[serde(default)]
    pub api: ApiConfig,
    // # Opt-in functionality
    //
    // ---
    /// Function: enable the admin rest endpoints.
    ///
    /// This is required if `enable_external_publish` is on.
    #[serde(default)]
    pub enable_admin: Option<FunctionAdmin>,
    /// Function: publish the detected global IP address under the configured self
    /// identity.
    ///
    /// This is automatically enabled if `enable_serve_content` is on.
    #[serde(default)]
    pub enable_self_publish_ip: bool,
    /// Function: publish the current host's ssh host public key.
    ///
    /// This allows the spagh ssh client to resolve the host key via the host identity.
    #[serde(default)]
    pub enable_self_publish_ssh_key: Option<FunctionPublishSelfSshKeys>,
    /// Function: generate and publish tls certificates, automatically refreshing
    /// before they expire.
    #[serde(default)]
    pub enable_self_publish_tls: bool,
    /// Function: generate and write tls certificates to a directory
    ///
    /// A service like nginx can be configured to use the certs in the directory for
    /// publishing content if this demon's publishing functionality isn't used directly.
    ///
    /// The certs are written with a delay of the published tls record ttl (plus a bit)
    /// if `enable_self_publish_tls` is on so that clients have a chance to refresh
    /// their expected certs before opening a new connection.
    #[serde(default)]
    pub enable_write_tls: Option<FunctionWriteTls>,
    /// Function: enable external publishers to publish records via the rest api.
    ///
    /// The identities to publish must be registered via the admin api beforehand.
    #[serde(default)]
    pub enable_external_publish: bool,
    /// Function: enable resolver queries via the rest api.
    #[serde(default)]
    pub enable_resolver_rest: bool,
    /// Function: enable resolver queries via dns (via `IDENTITY.s` names).
    #[serde(default)]
    pub enable_resolver_dns: Option<FunctionResolverDns>,
    /// Function: serve http content (static files or reverse proxy) using a
    /// spaghettinuum TLS certificate.
    ///
    /// This is a mapping of interface IPs and ports to bind, to subpaths, to content
    /// sources.
    #[serde(default)]
    pub enable_serve_content: FunctionServeContent,
}
