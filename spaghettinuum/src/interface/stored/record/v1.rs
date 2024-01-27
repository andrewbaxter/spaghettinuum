use schemars::JsonSchema;
use serde::{
    Deserialize,
    Serialize,
};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct RecordValue {
    pub ttl: i32,
    pub data: Option<serde_json::Value>,
}
