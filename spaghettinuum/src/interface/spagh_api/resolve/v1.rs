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

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct ResolveValue {
    pub expires: DateTime<Utc>,
    pub data: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct ResolveKeyValues(pub HashMap<String, ResolveValue>);

/// A list of Ipv4 addresses
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct DnsA(pub Vec<String>);

/// A list of Ipv6 addresses
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct DnsAaaa(pub Vec<String>);

/// A list of DNS names
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct DnsCname(pub Vec<String>);

/// A list of TXT record strings
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct DnsTxt(pub Vec<String>);

/// A list of mail server domain names.  The first will have priority 0, the second
/// 1, etc.
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct DnsMx(pub Vec<String>);
