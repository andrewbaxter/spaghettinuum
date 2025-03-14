use {
    serde::{
        Serialize,
        Deserialize,
    },
    crate::{
        interface::stored::{
            cert::v1::X509ExtSpagh,
            identity::Identity,
        },
        utils::{
            blob::Blob,
            time_util::UtcSecs,
        },
    },
};

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct CertRequest {
    pub identity: Identity,
    pub params: SignedCertRequestParams,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SignedCertRequestParams {
    pub sig: Blob,
    pub text: Blob,
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
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct CertRequestParams {
    pub stamp: UtcSecs,
    pub spki_der: Blob,
    pub sig_ext: Option<X509ExtSpagh>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct CertResponse {
    pub pub_pem: String,
}
