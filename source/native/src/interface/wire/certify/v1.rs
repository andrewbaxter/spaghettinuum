use {
    crate::{
        interface::stored::cert::v1::X509ExtSpagh,
        utils::time_util::UtcSecs,
    },
    serde::{
        Deserialize,
        Serialize,
    },
    spaghettinuum::{
        byteszb32::BytesZb32,
        interface::identity::Identity,
        jsonsig::JsonSignature,
    },
};

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct CertRequestParams {
    pub stamp: UtcSecs,
    pub spki_der: BytesZb32,
    pub sig_ext: Option<X509ExtSpagh>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct CertRequest {
    pub identity: Identity,
    pub params: JsonSignature<CertRequestParams, Identity>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct CertResponse {
    pub pub_pem: String,
}
