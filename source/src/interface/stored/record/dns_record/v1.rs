use {
    std::net::{
        Ipv4Addr,
        Ipv6Addr,
    },
    schemars::JsonSchema,
    serde::{
        Serialize,
        Deserialize,
    },
};

/// A list of Ipv4 addresses
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct DnsA(pub Vec<Ipv4Addr>);

/// A list of Ipv6 addresses
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct DnsAaaa(pub Vec<Ipv6Addr>);

/// A list of DNS names
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct DnsCname(pub Vec<String>);

/// A list of TXT record strings. Each entry is a separate TXT record, there can be
/// no multi-string single-record values.
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct DnsTxt(pub Vec<String>);

/// A list of mail server domain names.  The first will have priority 0, the second
/// 1, etc.
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct DnsMx(pub Vec<String>);
