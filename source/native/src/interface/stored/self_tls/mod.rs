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
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RefreshTlsState {
    V1(v1::RefreshTlsState),
}

impl RefreshTlsState {
    pub fn latest(v: latest::RefreshTlsState) -> Self {
        return Self::V1(v);
    }
}

impl GoodOrmningCustomString<RefreshTlsState> for RefreshTlsState {
    fn to_sql<'a>(value: &'a RefreshTlsState) -> String {
        return serde_json::to_string(value).unwrap().into();
    }

    fn from_sql(value: String) -> Result<RefreshTlsState, String> {
        return Ok(serde_json::from_str(&value).map_err(|e| e.to_string())?);
    }
}
