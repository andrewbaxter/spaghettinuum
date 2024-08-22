use {
    crate::interface::config::shared::StrSocketAddr,
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
    },
    std::path::PathBuf,
};

pub const DEFAULT_PUBLISHER_PORT: u16 = 48391;

#[derive(Deserialize, Serialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
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
    /// A list of paths to SSH host keys to self-publish for this host.
    ///
    /// If not specified, a default SSH host key location will be used, otherwise no
    /// SSH host keys will be published.
    #[serde(default)]
    pub ssh_host_keys: Option<Vec<PathBuf>>,
}
