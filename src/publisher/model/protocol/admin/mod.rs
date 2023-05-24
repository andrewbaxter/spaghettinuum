use serde::{
    Deserialize,
    Serialize,
};
use crate::model::identity::{
    Identity,
    IdentitySecret,
};

#[derive(Serialize, Deserialize)]
pub struct RegisterIdentityRequestLocal {
    pub identity: Identity,
    pub secret: IdentitySecret,
}

#[derive(Serialize, Deserialize)]
pub struct RegisteryIdentityRequestCard {
    pub gpg_id: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegisterIdentityRequest {
    Local(RegisterIdentityRequestLocal),
    Card(RegisteryIdentityRequestCard),
}
