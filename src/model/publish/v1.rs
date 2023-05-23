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
pub struct Value {
    pub expires: DateTime<Utc>,
    pub data: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolveKeyValues(pub HashMap<String, Value>);

// u32 is duration in minutes
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyValues(pub HashMap<String, (u32, String)>);
