use std::{
    path::PathBuf,
    net::SocketAddr,
    collections::HashMap,
};
use serde::{
    Serialize,
    Deserialize,
};
use crate::model::{
    self,
    identity::{
        Identity,
        IdentitySecret,
    },
};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretType {
    Local(IdentitySecret),
    Card(String),
}

impl SecretType {
    pub fn to_sql(&self) -> Vec<u8> {
        return bincode::serialize(self).unwrap();
    }

    pub fn from_sql(data: Vec<u8>) -> Result<Self, loga::Error> {
        return Ok(bincode::deserialize(&data)?);
    }
}

#[derive(Deserialize, Serialize)]
pub struct IdentityData {
    pub secret: SecretType,
    pub kvs: model::publish::v1::KeyValues,
}

#[derive(Deserialize, Serialize)]
pub struct DynamicDataConfig {
    pub db: PathBuf,
    pub bind_addr: SocketAddr,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DataConfig {
    Static(HashMap<Identity, IdentityData>),
    Dynamic(DynamicDataConfig),
}

#[derive(Deserialize, Serialize)]
pub struct Config {
    pub bind_addr: SocketAddr,
    /// A cert will be generated and stored here if one doesn't already exist. Custom
    /// format (not pem).
    pub cert_path: PathBuf,
    /// URL other nodes will connect to to retrieve data - should match however to
    /// reach bind_addr externally (i.e. http/https, public instead of local ip)
    pub advertise_addr: SocketAddr,
    pub data: DataConfig,
}
