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
    /// The expiration time per the time on the publisher when the value was retrieved.
    /// This should be far enough in the future to ignore when not storing the results.
    pub expires: DateTime<Utc>,
    pub data: Option<serde_json::Value>,
}
