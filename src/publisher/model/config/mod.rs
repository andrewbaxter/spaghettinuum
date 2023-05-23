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
    /// Address other nodes will connect to to retrieve data.  Use this if this doesn't
    /// match the bind address (ex: binding to private ip, but forwarded from public
    /// ip) - defaults to `bind_addr`.
    pub advertise_addr: Option<SocketAddr>,
    pub data: DataConfig,
}
