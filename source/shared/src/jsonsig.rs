use {
    crate::{
        byteszb32::BytesZb32,
        interface::identity::Identity,
    },
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
        de::DeserializeOwned,
    },
    std::marker::PhantomData,
};

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct JsonSignature<T: Serialize + DeserializeOwned, I> {
    pub message: String,
    pub signature: BytesZb32,
    #[serde(skip)]
    pub _p: PhantomData<(T, I)>,
}

impl<T: Serialize + DeserializeOwned, I> std::fmt::Debug for JsonSignature<T, I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f
            .debug_struct("JsonSignature")
            .field("message", &self.message)
            .field("signature", &self.signature)
            .finish()
    }
}

impl<T: Serialize + DeserializeOwned> JsonSignature<T, Identity> {
    pub fn verify(&self, identity: &Identity) -> Result<T, String> {
        identity.verify(&self.message.as_bytes(), &self.signature.0).map_err(|e| e.to_string())?;
        return Ok(
            serde_json::from_str(
                &self.message,
            ).map_err(|e| format!("Invalid signed json or json doesn't match version request spec: {}", e))?,
        );
    }
}
