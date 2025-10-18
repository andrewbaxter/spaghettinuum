use {
    super::record_utils::RecordKey,
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
    },
};

pub mod v1;

pub use v1 as latest;

pub const KEY_SUFFIX_DELEGATE: &'static str = "delegate";

pub fn build_delegate_key(head: RecordKey) -> RecordKey {
    let mut out = head;
    out.push(KEY_SUFFIX_DELEGATE.to_string());
    return out;
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Delegate {
    V1(v1::Delegate),
}

impl Delegate {
    pub fn latest(data: latest::Delegate) -> Self {
        return Self::V1(data);
    }
}
