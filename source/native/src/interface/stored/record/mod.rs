pub mod delegate_record;
pub mod dns_record;
pub mod record_utils;
pub mod ssh_record;
pub mod tls_record;
pub mod v1;

pub use v1 as latest;
use {
    good_ormning::runtime::sqlite::GoodOrmningCustomString,
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
    },
};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RecordValue {
    V1(v1::RecordValue),
}

impl RecordValue {
    pub fn latest(v: latest::RecordValue) -> Self {
        return Self::V1(v);
    }
}

impl GoodOrmningCustomString<RecordValue> for RecordValue {
    fn from_sql(value: String) -> Result<RecordValue, String> {
        return Ok(serde_json::from_str(&value).map_err(|e| e.to_string())?);
    }

    fn to_sql<'a>(value: &'a RecordValue) -> String {
        return serde_json::to_string(value).unwrap().into();
    }
}
