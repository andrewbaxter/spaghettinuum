use std::collections::HashMap;
use chrono::{
    Utc,
    DateTime,
};
use schemars::JsonSchema;
use serde::{
    Serialize,
    Deserialize,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ResolveValue {
    pub expires: DateTime<Utc>,
    pub data: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ResolveKeyValues(pub HashMap<String, ResolveValue>);

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct DnsA(pub Vec<String>);

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct DnsAaaa(pub Vec<String>);

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct DnsCname(pub Vec<String>);

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct DnsTxt(pub Vec<String>);
