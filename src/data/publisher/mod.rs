pub mod admin;
pub mod announcement;

use good_ormning_runtime::sqlite::GoodOrmningCustomBytes;
use serde::{
    Serialize,
    Deserialize,
};

pub mod v1;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolveKeyValues {
    V1(v1::ResolveKeyValues),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Publish {
    V1(v1::Publish),
}

impl GoodOrmningCustomBytes<Publish> for Publish {
    fn to_sql<'a>(value: &'a Publish) -> std::borrow::Cow<'a, [u8]> {
        return bincode::serialize(value).unwrap().into();
    }

    fn from_sql(value: Vec<u8>) -> Result<Publish, String> {
        return bincode::deserialize(&value).map_err(|e| e.to_string());
    }
}
