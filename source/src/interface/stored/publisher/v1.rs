use serde::{
    Deserialize,
    Serialize,
};
use crate::utils::blob::Blob;

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Certs {
    #[serde(rename = "pub")]
    pub pub_der: Blob,
    // PKCS8 der
    #[serde(rename = "priv")]
    pub priv_der: Blob,
}
