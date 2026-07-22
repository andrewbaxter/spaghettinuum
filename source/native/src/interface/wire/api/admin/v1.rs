use {
    serde::{
        Deserialize,
        Serialize,
    },
    spaghettinuum::interface::id::Identity,
};

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct AdminAllowIdentityBody {
    pub group: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct AdminIdentity {
    pub group: String,
    pub identity: Identity,
}
