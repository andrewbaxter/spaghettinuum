use serde::{
    Serialize,
    Deserialize,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Announcement {
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Announcement {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, loga::Error> {
        return Ok(bincode::deserialize(bytes)?);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }
}
