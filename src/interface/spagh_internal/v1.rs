use serde::{
    Deserialize,
    Serialize,
};

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct PublishCerts {
    #[serde(rename = "pub")]
    pub pub_der: Vec<u8>,
    #[serde(rename = "priv")]
    pub priv_der: Vec<u8>,
}
