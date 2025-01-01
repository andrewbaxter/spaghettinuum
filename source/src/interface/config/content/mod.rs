use {
    super::shared::StrSocketAddr,
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

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
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
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct ContentConfig {
    /// Mapping of interface IPs and ports to bind to to subpaths to content to serve.
    ///
    /// Regardless of port this always serves HTTPS. For HTTP traffic you can use some
    /// other static file server.
    pub items: HashMap<StrSocketAddr, HashMap<String, ServeMode>>,
}
