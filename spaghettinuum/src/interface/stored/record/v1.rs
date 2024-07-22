use schemars::JsonSchema;
use serde::{
    Deserialize,
    Serialize,
};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct RecordValue {
    /// Time record can be cached (in minutes)
    pub ttl: i32,
    /// Data, or nothing for explicitly removed data (to override previously published
    /// data).
    pub data: Option<serde_json::Value>,
}
