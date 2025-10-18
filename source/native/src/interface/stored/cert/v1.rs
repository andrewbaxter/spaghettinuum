use {
    serde::{
        Deserialize,
        Serialize,
    },
};

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct X509ExtSpagh {
    /// Signature of the X509 SPKI
    pub signature: Vec<u8>,
}

impl X509ExtSpagh {
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        return Ok(bincode::deserialize(data).map_err(|e| e.to_string())?);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        return bincode::serialize(self).unwrap();
    }

    pub fn from_bytes_unsafe(bytes: &[u8]) -> Self {
        bincode::deserialize(bytes).unwrap()
    }
}
