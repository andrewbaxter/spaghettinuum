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
#[serde(rename_all = "snake_case")]
pub struct ResolveValue {
    pub expires: DateTime<Utc>,
    pub data: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ResolveKeyValues(pub HashMap<String, ResolveValue>);

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum DnsRecordsetJson {
    Cname(Vec<String>),
    A(Vec<String>),
    Aaaa(Vec<String>),
    Txt(Vec<String>),
    Mx(Vec<(u16, String)>),
}
