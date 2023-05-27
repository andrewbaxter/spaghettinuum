use serde::{
    Deserialize,
    Serialize,
};

pub mod v1;

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum DnsRecordsetJson {
    V1(v1::DnsRecordsetJson),
}
