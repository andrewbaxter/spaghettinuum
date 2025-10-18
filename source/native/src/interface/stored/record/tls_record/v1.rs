use {
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
    },
};

/// A list of possible public certs (PEM format) a server could serve. These certs
/// should be accepted regardless of all other properties (including signer status
/// and significant dates within the certificate).
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct TlsCerts(pub Vec<String>);
