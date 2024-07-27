use good_ormning_runtime::sqlite::GoodOrmningCustomString;
use serde::{
    Deserialize,
    Serialize,
};

pub mod v1;

pub use v1 as latest;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Announcement {
    V1(v1::Announcement),
}

impl GoodOrmningCustomString<Announcement> for Announcement {
    fn to_sql<'a>(value: &'a Announcement) -> std::borrow::Cow<'a, str> {
        return serde_json::to_string(value).unwrap().into();
    }

    fn from_sql(value: String) -> Result<Announcement, String> {
        return serde_json::from_str(&value).map_err(|e| e.to_string());
    }
}
