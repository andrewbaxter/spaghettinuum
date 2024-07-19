use {
    crate::interface::config::shared::StrSocketAddr,
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
    },
    std::path::PathBuf,
};
pub const DEFAULT_API_PORT: u16 = 12434;

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AdminToken {
    File(PathBuf),
    Inline(String),
}

#[derive(Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub struct ApiConfig {
    /// Addresses for the server to listen on for client interaction.
    ///
    /// Defaults to `[::]:12434` and `0:12434`.
    #[serde(default)]
    pub bind_addrs: Vec<StrSocketAddr>,
    /// HTTP authorization bearer token for accessing publisher admin endpoints.
    ///
    /// If not specified, remote admin operations will be disabled (only self-publish
    /// on this node will work since there will be no way to register publishing
    /// identities).
    #[serde(default)]
    pub admin_token: Option<AdminToken>,
}
