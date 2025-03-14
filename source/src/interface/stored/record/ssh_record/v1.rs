use {
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
    },
};

/// A list of possible host keys a server could serve.
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SshHostKeys(pub Vec<String>);
