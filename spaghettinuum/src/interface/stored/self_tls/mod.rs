use {
    good_ormning_runtime::sqlite::GoodOrmningCustomString,
    serde::{
        Deserialize,
        Serialize,
    },
};

pub mod v1;

pub use v1 as latest;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfTlsState {
    V1(v1::SelfTlsState),
}

impl SelfTlsState {
    pub fn latest(v: latest::SelfTlsState) -> Self {
        return Self::V1(v);
    }
}

impl GoodOrmningCustomString<SelfTlsState> for SelfTlsState {
    fn to_sql<'a>(value: &'a SelfTlsState) -> std::borrow::Cow<'a, str> {
        return serde_json::to_string(value).unwrap().into();
    }

    fn from_sql(value: String) -> Result<SelfTlsState, String> {
        return Ok(serde_json::from_str(&value).map_err(|e| e.to_string())?);
    }
}
