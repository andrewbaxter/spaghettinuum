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
        interface::{
            identity::IdentityPublicKey,
            signature_chain::ChainLink,
        },
        jsonsig::JsonSignature,
    },
};

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct CertRequest {
    pub params: JsonSignature<CertRequestParams, IdentityPublicKey>,
    #[serde(default)]
    pub public_key_chain: Vec<ChainLink>,
    pub public_key_root: IdentityPublicKey,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct CertRequestParams {
    pub sig_ext: Option<X509ExtSpagh>,
    pub spki_der: BytesZb32,
    pub stamp: UtcSecs,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct CertResponse {
    pub pub_pem: String,
}
