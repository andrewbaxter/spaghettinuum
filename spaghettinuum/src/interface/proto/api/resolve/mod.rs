pub mod v1;

use schemars::JsonSchema;
pub use v1 as latest;
use serde::{
    Deserialize,
    Serialize,
};

pub const KEY_DNS_PREFIX: &'static str = "dns";
pub const KEY_DNS_CNAME: &'static str = "cname";
pub const KEY_DNS_A: &'static str = "a";
pub const KEY_DNS_AAAA: &'static str = "aaaa";
pub const KEY_DNS_TXT: &'static str = "txt";
pub const KEY_DNS_MX: &'static str = "mx";
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
