use {
    super::shared::StrSocketAddr,
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
    },
    std::path::PathBuf,
};

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ServeMode {
    StaticFiles {
        /// Where files to serve are.
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
    /// Interface IPs and ports to bind to. These always serve HTTPS, regardless of the
    /// port. For HTTP traffic you can use some other static file server.
    pub bind_addrs: Vec<StrSocketAddr>,
    /// What content to serve.
    pub mode: ServeMode,
}
