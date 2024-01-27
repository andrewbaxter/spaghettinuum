use good_ormning_runtime::sqlite::GoodOrmningCustomString;
use serde::{
    Deserialize,
    Serialize,
};
use crate::versioned;

pub mod v1;

pub use v1 as latest;

versioned!(
    Protocol,
    Debug;
    (V1, 1, v1::Message)
);

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeState {
    V1(v1::NodeState),
}

impl GoodOrmningCustomString<NodeState> for NodeState {
    fn to_sql<'a>(value: &'a NodeState) -> std::borrow::Cow<'a, str> {
        return serde_json::to_string(value).unwrap().into();
    }

    fn from_sql(value: String) -> Result<NodeState, String> {
        return Ok(serde_json::from_str(&value).map_err(|e| e.to_string())?);
    }
}
