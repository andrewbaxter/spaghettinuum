use serde::{
    Deserialize,
    Serialize,
};

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum DnsRecordsetJson {
    Cname(Vec<String>),
    A(Vec<String>),
    Aaaa(Vec<String>),
    Txt(Vec<String>),
    Mx(Vec<(u16, String)>),
}
