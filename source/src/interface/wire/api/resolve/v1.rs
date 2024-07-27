use std::collections::HashMap;
use schemars::JsonSchema;
use serde::{
    Deserialize,
    Serialize,
};
use crate::interface::{
    wire,
};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ResolveValues(pub HashMap<String, wire::resolve::v1::ResolveValue>);
