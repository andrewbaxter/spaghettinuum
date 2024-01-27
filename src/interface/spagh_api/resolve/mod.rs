pub mod v1;

use schemars::JsonSchema;
pub use v1 as latest;
use serde::{
    Deserialize,
    Serialize,
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolveKeyValues {
    V1(v1::ResolveKeyValues),
}

pub const KEY_DNS_CNAME: &'static str = "a6ff2372-e325-443f-a15f-dcefb6aee864";
pub const KEY_DNS_A: &'static str = "dff50392-a569-4de4-9e66-e086af040f30";
pub const KEY_DNS_AAAA: &'static str = "a793cc93-cc06-4369-ba47-5a9e8d2a23dd";
pub const KEY_DNS_TXT: &'static str = "630e1d90-845a-470f-95f3-14253a6c269c";
pub const KEY_DNS_MX: &'static str = "f665bd5f-6da7-4fa7-8ef9-51dd9a53ff60";
pub const COMMON_KEYS_DNS: &[&'static str] = &[KEY_DNS_A, KEY_DNS_AAAA, KEY_DNS_CNAME, KEY_DNS_TXT];

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DnsA {
    V1(v1::DnsA),
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DnsAaaa {
    V1(v1::DnsAaaa),
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DnsCname {
    V1(v1::DnsCname),
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DnsTxt {
    V1(v1::DnsTxt),
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DnsMx {
    V1(v1::DnsMx),
}
