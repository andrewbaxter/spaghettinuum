use {
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
    },
};

pub const KEY_HOST_KEYS: &'static str = "ssh_host_keys";

pub mod v1;

pub use v1 as latest;

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SshHostKeys {
    V1(v1::SshHostKeys),
}
