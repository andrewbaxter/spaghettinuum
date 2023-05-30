use std::collections::HashMap;
use chrono::{
    Utc,
    DateTime,
};
use serde::{
    Serialize,
    Deserialize,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolveValue {
    pub expires: DateTime<Utc>,
    pub data: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolveKeyValues(pub HashMap<String, ResolveValue>);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublishValue {
    /// duration in minutes
    pub ttl: u32,
    pub data: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Publish {
    /// duration in minutes
    pub missing_ttl: u32,
    pub data: HashMap<String, PublishValue>,
}
