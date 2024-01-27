use std::collections::HashMap;
use chrono::{
    DateTime,
    Utc,
};
use schemars::JsonSchema;
use serde::{
    Deserialize,
    Serialize,
};
use crate::utils::blob::Blob;

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct PublisherCerts {
    #[serde(rename = "pub")]
    pub pub_der: Blob,
    #[serde(rename = "priv")]
    pub priv_der: Blob,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct RecordValue {
    pub expires: DateTime<Utc>,
    pub data: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct ResolveKeyValues(pub HashMap<String, RecordValue>);
