use {
    serde::{
        Deserialize,
        Serialize,
    },
};

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Certs {
    #[serde(rename = "pub")]
    pub pub_der: Vec<u8>,
    // PKCS8 der
    #[serde(rename = "priv")]
    pub priv_der: Vec<u8>,
}
