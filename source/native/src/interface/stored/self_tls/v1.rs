use serde::{
    Deserialize,
    Serialize,
};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct CertPair {
    /// PKCS8 private key
    pub priv_pem: String,
    /// X509 public cert, signed by certipasta CA key
    pub pub_pem: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct RefreshTlsState {
    pub current: CertPair,
    pub pending: Option<CertPair>,
}
