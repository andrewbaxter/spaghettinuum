use {
    chrono::{
        DateTime,
        Utc,
    },
    serde::{
        Deserialize,
        Serialize,
    },
};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub struct CertPair {
    /// X509 public cert, signed by certipasta CA key
    pub pub_pem: String,
    /// PKCS8 private key
    pub priv_pem: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub struct SelfTlsState {
    pub pending: Option<(DateTime<Utc>, CertPair)>,
    pub current: CertPair,
}
