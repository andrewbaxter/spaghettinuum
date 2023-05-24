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
    pub data: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolveKeyValues(pub HashMap<String, ResolveValue>);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Value {
    /// duration in minutes
    pub ttl: u32,
    pub data: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyValues(pub HashMap<String, Value>);
