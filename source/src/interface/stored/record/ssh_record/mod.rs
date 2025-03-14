use {
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
    },
};

pub mod v1;

pub use v1 as latest;

pub const KEY_SUFFIX_SSH_HOSTKEYS: &'static str = "ssh_hostkeys";

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SshHostKeys {
    V1(v1::SshHostKeys),
}

impl SshHostKeys {
    pub fn latest(data: latest::SshHostKeys) -> Self {
        return Self::V1(data);
    }
}
