use {
    crate::interface::{
        id::Id,
        public_key::PublicKey,
    },
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
    pub public_key: PublicKey,
    pub data: Vec<u8>,
    pub signature: Vec<u8>,
    #[serde(skip, default)]
    pub _t: PhantomData<T>,
}

impl<T: DeserializeOwned> Signature<T> {
    pub fn verify(&self) -> Result<T, String> {
        if let Err(e) = self.public_key.verify(&self.data, &self.signature) {
            return Err(e.to_string());
        };
        return self.get_no_verify();
    }

    pub fn id(&self) -> Id {
        return self.public_key.id();
    }

    pub fn get_no_verify(&self) -> Result<T, String> {
        return Ok(serde_json::from_slice(&self.data).map_err(|e| e.to_string())?);
    }
}
