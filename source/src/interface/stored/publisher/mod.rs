use good_ormning_runtime::sqlite::GoodOrmningCustomString;
use serde::{
    Deserialize,
    Serialize,
};

pub mod v1;

pub use v1 as latest;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Certs {
    V1(v1::Certs),
}

impl GoodOrmningCustomString<Certs> for Certs {
    fn to_sql<'a>(value: &'a Certs) -> String {
        return serde_json::to_string(value).unwrap().into();
    }

    fn from_sql(value: String) -> Result<Certs, String> {
        return Ok(serde_json::from_str(&value).map_err(|e| e.to_string())?);
    }
}
