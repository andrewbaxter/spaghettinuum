use serde::{
    Serialize,
    Deserialize,
};

pub mod v1;

pub use v1 as latest;

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum CertRequest {
    V1(v1::CertRequest),
}
