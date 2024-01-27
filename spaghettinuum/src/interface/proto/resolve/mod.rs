//! Interface across time, no non-self users.
use good_ormning_runtime::sqlite::GoodOrmningCustomString;
use serde::{
    Deserialize,
    Serialize,
};

pub mod v1;

pub use v1 as latest;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublisherCerts {
    V1(v1::PublisherCerts),
}

impl GoodOrmningCustomString<PublisherCerts> for PublisherCerts {
    fn to_sql<'a>(value: &'a PublisherCerts) -> std::borrow::Cow<'a, str> {
        return serde_json::to_string(value).unwrap().into();
    }

    fn from_sql(value: String) -> Result<PublisherCerts, String> {
        return Ok(serde_json::from_str(&value).map_err(|e| e.to_string())?);
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordValue {
    V1(v1::RecordValue),
}

impl RecordValue {
    pub fn latest(v: latest::RecordValue) -> Self {
        return Self::V1(v);
    }
}

impl GoodOrmningCustomString<RecordValue> for RecordValue {
    fn to_sql<'a>(value: &'a RecordValue) -> std::borrow::Cow<'a, str> {
        return serde_json::to_string(value).unwrap().into();
    }

    fn from_sql(value: String) -> Result<RecordValue, String> {
        return Ok(serde_json::from_str(&value).map_err(|e| e.to_string())?);
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolveKeyValues {
    V1(v1::ResolveKeyValues),
}
