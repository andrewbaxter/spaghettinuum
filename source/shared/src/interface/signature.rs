use {
    crate::interface::{
        id::Identity,
        public_key::IdentityPublicKey,
    },
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
        de::DeserializeOwned,
    },
    std::marker::PhantomData,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord, JsonSchema)]
pub struct Signature<T> {
    #[serde(skip, default)]
    pub _t: PhantomData<T>,
    pub data: Vec<u8>,
    pub public_key: IdentityPublicKey,
    pub signature: Vec<u8>,
}

impl<T: DeserializeOwned> Signature<T> {
    pub fn get_no_verify(&self) -> Result<T, String> {
        return Ok(serde_json::from_slice(&self.data).map_err(|e| e.to_string())?);
    }

    pub fn identity(&self) -> Identity {
        return self.public_key.identity();
    }

    pub fn verify(&self) -> Result<T, String> {
        if let Err(e) = self.public_key.verify(&self.data, &self.signature) {
            return Err(e.to_string());
        };
        return self.get_no_verify();
    }
}
