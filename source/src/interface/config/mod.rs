use {
    aargvark::Aargvark,
};

/// URLs of resolver for `spagh` CLI, if not getting them from system resolver
/// information. In the form `IP=URL`. Comma separated if providing multiple.
///
/// Both the IP and the URL with the `.s` domain name must be specified in order to
/// use the server identity to validate the TLS certificate.
pub const ENV_RESOLVER_PAIRS: &'static str = "SPAGH_RESOLVERS";
pub const ENV_PUBLISHER_URLS: &'static str = "SPAGH_PUBLISHERS";

/// The token for making admin requests, for `spagh` CLI.
pub const ENV_API_ADMIN_TOKEN: &'static str = "SPAGH_TOKEN";

/// The JSON config (itself, not a path), for `spagh-node` and `spagh-auto`.
pub const ENV_CONFIG: &'static str = "SPAGH_CONFIG";

/// Persisted identity types
pub mod identity;

/// Configs for running a `spagh` demon
pub mod spagh;

/// Common config structures
pub mod shared;

#[derive(Clone, Hash, PartialEq, Eq, Copy, Aargvark)]
pub enum DebugFlag {
    Admin,
    Node,
    Publish,
    Resolve,
    Dns,
    SelfTls,
    Api,
    Content,
}
