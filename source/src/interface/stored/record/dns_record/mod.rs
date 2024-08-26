use {
    super::record_utils::{
        RecordKey,
    },
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
    },
};

pub mod v1;

pub use v1 as latest;

pub const KEY_SUFFIX_DNS_A: &'static str = "dns/a";
pub const KEY_SUFFIX_DNS_AAAA: &'static str = "dns/aaaa";
pub const KEY_SUFFIX_DNS_TXT: &'static str = "dns/txt";
pub const KEY_SUFFIX_DNS_MX: &'static str = "dns/mx";

#[derive(Clone, Copy)]
pub enum RecordType {
    A,
    Aaaa,
    Txt,
    Mx,
}

pub fn build_dns_key(head: RecordKey, record_type: RecordType) -> RecordKey {
    let mut out = head;
    out.push(match record_type {
        RecordType::A => KEY_SUFFIX_DNS_A,
        RecordType::Aaaa => KEY_SUFFIX_DNS_AAAA,
        RecordType::Txt => KEY_SUFFIX_DNS_TXT,
        RecordType::Mx => KEY_SUFFIX_DNS_MX,
    }.to_string());
    return out;
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
pub enum DnsTxt {
    V1(v1::DnsTxt),
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DnsMx {
    V1(v1::DnsMx),
}
