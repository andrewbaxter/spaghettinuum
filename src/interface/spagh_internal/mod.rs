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
pub enum PublishCerts {
    V1(v1::PublishCerts),
}

impl GoodOrmningCustomString<PublishCerts> for PublishCerts {
    fn to_sql<'a>(value: &'a PublishCerts) -> std::borrow::Cow<'a, str> {
        return serde_json::to_string(value).unwrap().into();
    }

    fn from_sql(value: String) -> Result<PublishCerts, String> {
        return Ok(serde_json::from_str(&value).map_err(|e| e.to_string())?);
    }
}
