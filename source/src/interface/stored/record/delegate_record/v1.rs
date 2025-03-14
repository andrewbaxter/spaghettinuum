use {
    crate::interface::stored::{
        record::record_utils::{
            RecordKey,
            RecordRoot,
        },
    },
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
    },
};

/// A list of other key paths. Delegate records for all prefixes of a query path
/// should be queried as well, with the shortest prefix that has a delegate used.
/// When a delegate record is used, the matched prefix from the delegate record is
/// replaced by the value of the delegate record.
///
/// Multiple values are all valid and any single value should be used. They can be
/// used for client-side load balancing (by using a random member) and failover (by
/// trying another value when one value is unusable).
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Delegate(pub Vec<(RecordRoot, RecordKey)>);
