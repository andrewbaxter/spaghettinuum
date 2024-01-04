use chrono::{
    DateTime,
    Utc,
};
use serde::{
    Serialize,
    Deserialize,
};
use crate::interface::identity::Identity;

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct CertRequest {
    pub identity: Identity,
    pub params: SignedCertRequestParams,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct SignedCertRequestParams {
    #[serde(serialize_with = "crate::utils::as_zbase32", deserialize_with = "crate::utils::from_zbase32")]
    pub sig: Vec<u8>,
    #[serde(serialize_with = "crate::utils::as_zbase32", deserialize_with = "crate::utils::from_zbase32")]
    pub text: Vec<u8>,
}

impl SignedCertRequestParams {
    pub fn verify(&self, identity: &Identity) -> Result<CertRequestParams, String> {
        identity.verify(&self.text, &self.sig).map_err(|e| e.to_string())?;
        return Ok(
            serde_json::from_slice(
                &self.text,
            ).map_err(|e| format!("Invalid signed json or json doesn't match version request spec: {}", e))?,
        );
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct CertRequestParams {
    pub stamp: DateTime<Utc>,
    #[serde(serialize_with = "crate::utils::as_zbase32", deserialize_with = "crate::utils::from_zbase32")]
    pub spki_der: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CertResponse {
    pub pub_pem: String,
}
