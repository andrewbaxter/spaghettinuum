use {
    crate::interface::identity::Identity,
    schemars::JsonSchema,
    serde::{
        de::DeserializeOwned,
        Deserialize,
        Serialize,
    },
    std::marker::PhantomData,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord, JsonSchema)]
pub struct Signature<T> {
    pub identity: Identity,
    pub data: Vec<u8>,
    pub signature: Vec<u8>,
    #[serde(skip, default)]
    pub _t: PhantomData<T>,
}

impl<T: DeserializeOwned> Signature<T> {
    pub fn verify(&self) -> Result<T, String> {
        if let Err(e) = self.identity.verify(&self.data, &self.signature) {
            return Err(e.to_string());
        };
        return self.get_no_verify();
    }

    pub fn get_no_verify(&self) -> Result<T, String> {
        return Ok(serde_json::from_slice(&self.data).map_err(|e| e.to_string())?);
    }
}
