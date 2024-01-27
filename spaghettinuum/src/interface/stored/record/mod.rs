use good_ormning_runtime::sqlite::GoodOrmningCustomString;
use schemars::JsonSchema;
use serde::{
    Deserialize,
    Serialize,
};

pub mod v1;

pub use v1 as latest;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
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
