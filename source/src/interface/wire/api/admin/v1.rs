use {
    crate::interface::stored::identity::Identity,
    serde::{
        Deserialize,
        Serialize,
    },
};

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct AdminAllowIdentityBody {
    pub group: String,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct AdminIdentity {
    pub identity: Identity,
    pub group: String,
}
