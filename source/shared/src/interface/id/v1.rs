use {
    serde::{
        Deserialize,
        Serialize,
    },
};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum Id {
    Sha256(Vec<u8>),
}

impl Id {
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        return Ok(bincode::deserialize(data).map_err(|e| e.to_string())?);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        return bincode::serialize(self).unwrap();
    }
}
