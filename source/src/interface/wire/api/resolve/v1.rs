use std::collections::HashMap;
use schemars::JsonSchema;
use serde::{
    Deserialize,
    Serialize,
};
use crate::interface::{
    stored::record::record_utils::RecordKey,
    wire,
};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ResolveValues(pub HashMap<RecordKey, wire::resolve::v1::ResolveValue>);
