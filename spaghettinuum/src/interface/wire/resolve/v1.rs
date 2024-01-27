use chrono::{
    DateTime,
    Utc,
};
use schemars::JsonSchema;
use serde::{
    Deserialize,
    Serialize,
};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct ResolveValue {
    pub expires: DateTime<Utc>,
    pub data: Option<serde_json::Value>,
}
