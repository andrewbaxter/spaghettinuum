use {
    std::time::Duration,
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
    },
};

#[derive(Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Debug)]
struct Minutes(pub u64);

impl From<Duration> for Minutes {
    fn from(value: Duration) -> Self {
        return Self(value.as_secs() / 60);
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RecordValue {
    /// Time record can be cached (in minutes)
    pub ttl: u64,
    /// Data, or nothing for explicitly removed data (to override previously published
    /// data).
    pub data: Option<serde_json::Value>,
}
