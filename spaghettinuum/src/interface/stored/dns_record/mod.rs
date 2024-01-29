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

#[derive(Clone, Copy)]
pub enum RecordType {
    Cname,
    A,
    Aaaa,
    Txt,
    Mx,
}

pub const COMMON_HTTP_RECORD_TYPES: &[RecordType] =
    &[RecordType::Cname, RecordType::A, RecordType::Aaaa, RecordType::Txt];

pub fn format_dns_key(subdomain: &str, record_type: RecordType) -> String {
    return format!("{}/{}/{}", KEY_DNS_PREFIX, subdomain, match record_type {
        RecordType::Cname => KEY_DNS_CNAME,
        RecordType::A => KEY_DNS_A,
        RecordType::Aaaa => KEY_DNS_AAAA,
        RecordType::Txt => KEY_DNS_TXT,
        RecordType::Mx => KEY_DNS_MX,
    });
}

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
