use {
    crate::interface::identity::Identity,
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
    },
    std::marker::PhantomData,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord, JsonSchema)]
pub struct Signature<T> {
    pub identity: Identity,
    pub signature: Vec<u8>,
    #[serde(skip, default)]
    pub _t: PhantomData<T>,
}
