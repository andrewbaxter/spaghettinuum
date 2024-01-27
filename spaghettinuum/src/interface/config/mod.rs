/// URL of resolver/publisher, for `spagh` CLI.
pub const ENV_API_ADDR: &'static str = "SPAGH";

/// The token for making admin requests, for `spagh` CLI.
pub const ENV_API_ADMIN_TOKEN: &'static str = "SPAGH_TOKEN";

/// The JSON config (itself, not a path), for `spagh-node` and `spagh-auto`.
pub const ENV_CONFIG: &'static str = "SPAGH_CONFIG";

/// Persisted identity types
pub mod identity;

/// Configs for `spagh-auto`
pub mod auto;

/// Configs for `spagh-node`
pub mod node;

/// Common config structures
pub mod shared;
