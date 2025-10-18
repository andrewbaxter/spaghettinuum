use {
    serde::{
        Deserialize,
        Serialize,
    },
};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct CertPair {
    /// X509 public cert, signed by certipasta CA key
    pub pub_pem: String,
    /// PKCS8 private key
    pub priv_pem: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RefreshTlsState {
    pub pending: Option<CertPair>,
    pub current: CertPair,
}
