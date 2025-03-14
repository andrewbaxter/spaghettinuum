use {
    crate::utils::blob::{
        Blob,
        ToBlob,
    },
    serde::{
        Deserialize,
        Serialize,
    },
};

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct X509ExtSpagh {
    /// Signature of the X509 SPKI
    pub signature: Blob,
}

impl X509ExtSpagh {
    pub fn from_bytes(data: &[u8]) -> Result<Self, loga::Error> {
        return Ok(bincode::deserialize(data)?);
    }

    pub fn to_bytes(&self) -> Blob {
        return bincode::serialize(self).unwrap().blob();
    }

    pub fn from_bytes_unsafe(bytes: &[u8]) -> Self {
        bincode::deserialize(bytes).unwrap()
    }
}
