//! Interface across time, no non-self users.
use std::collections::HashMap;
use serde::{
    Deserialize,
    Serialize,
};

pub mod v1;

pub use v1 as latest;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolveKeyValues {
    V1(HashMap<String, v1::ResolveValue>),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolveValue {
    V1(v1::ResolveValue),
}
