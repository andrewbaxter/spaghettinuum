use {
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
    },
};

pub mod v1;

pub use v1 as latest;

pub const KEY_SUFFIX_TLS: &'static str = "tls";

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TlsCerts {
    V1(v1::TlsCerts),
}

impl TlsCerts {
    pub fn latest(data: latest::TlsCerts) -> Self {
        return Self::V1(data);
    }
}
