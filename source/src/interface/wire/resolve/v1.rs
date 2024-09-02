use {
    crate::interface::stored::{
        identity::Identity,
        record::record_utils::RecordKey,
    },
    chrono::{
        DateTime,
        Utc,
    },
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
    },
    std::collections::HashMap,
};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct ResolveValue {
    /// The expiration time per the time on the publisher when the value was retrieved.
    /// This should be far enough in the future to ignore when not storing the results.
    pub expires: DateTime<Utc>,
    pub data: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct ResolveRequest {
    pub ident: Identity,
    pub keys: Vec<RecordKey>,
}

pub type ResolveResp = Vec<(RecordKey, ResolveValue)>;
pub type ResolveKeyValues = HashMap<RecordKey, ResolveValue>;
