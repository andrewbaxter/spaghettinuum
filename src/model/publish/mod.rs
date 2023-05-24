use serde::{
    Serialize,
    Deserialize,
};

pub mod v1;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolveKeyValues {
    V1(v1::ResolveKeyValues),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyValues {
    V1(v1::KeyValues),
}

impl KeyValues {
    pub fn to_sql(&self) -> Vec<u8> {
        return bincode::serialize(self).unwrap();
    }

    pub fn from_sql(data: Vec<u8>) -> Result<Self, loga::Error> {
        return Ok(bincode::deserialize(&data)?);
    }
}
