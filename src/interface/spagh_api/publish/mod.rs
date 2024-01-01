pub mod v1;

use good_ormning_runtime::sqlite::{
    GoodOrmningCustomString,
};
pub use v1 as latest;
use serde::{
    Deserialize,
    Serialize,
};
use crate::versioned;

versioned!(
    Announcement,
    Debug,
    Clone;
    (V1, 1, v1::Announcement)
);

impl GoodOrmningCustomString<Announcement> for Announcement {
    fn to_sql<'a>(value: &'a Announcement) -> std::borrow::Cow<'a, str> {
        return serde_json::to_string(value).unwrap().into();
    }

    fn from_sql(value: String) -> Result<Announcement, String> {
        return serde_json::from_str(&value).map_err(|e| e.to_string());
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Publish {
    V1(v1::Publish),
}

impl GoodOrmningCustomString<Publish> for Publish {
    fn to_sql<'a>(value: &'a Publish) -> std::borrow::Cow<'a, str> {
        return serde_json::to_string(value).unwrap().into();
    }

    fn from_sql(value: String) -> Result<Publish, String> {
        return serde_json::from_str(&value).map_err(|e| e.to_string());
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublishRequest {
    V1(v1::PublishRequest),
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnpublishRequest {
    V1(v1::UnpublishRequest),
}
