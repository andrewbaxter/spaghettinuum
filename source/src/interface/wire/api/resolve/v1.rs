use {
    crate::interface::{
        stored::record::record_utils::RecordKey,
        wire,
    },
    std::collections::HashMap,
};

pub type ResolveResp = Vec<(RecordKey, wire::resolve::v1::ResolveValue)>;
pub type ResolveKeyValues = HashMap<RecordKey, wire::resolve::v1::ResolveValue>;
