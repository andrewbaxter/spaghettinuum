use {
    serde::{
        Deserialize,
        Serialize,
    },
};

pub const DNS_SUFFIX: &str = "s";
pub const DNS_DOT_SUFFIX: &str = ".s";

pub mod v1;

pub use v1 as latest;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ResolveRequest {
    V1(v1::ResolveRequest),
}
