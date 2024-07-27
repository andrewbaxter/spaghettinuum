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
