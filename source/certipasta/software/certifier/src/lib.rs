use {
    chrono::{
        Duration,
    },
    const_oid::db::rfc5912::{
        ID_EC_PUBLIC_KEY,
        SECP_256_R_1,
        SECP_384_R_1,
        ECDSA_WITH_SHA_256,
        ECDSA_WITH_SHA_384,
    },
    der::{
        Decode,
        Encode,
    },
    loga::{
        ea,
        ResultContext,
    },
    sec1::EcParameters,
    serde::{
        Serialize,
        Deserialize,
    },
    sha2::{
        Digest,
        Sha256,
        Sha384,
    },
    signature::Keypair,
    x509_cert::{
        spki::{
            SubjectPublicKeyInfoOwned,
            EncodePublicKey,
            DynSignatureAlgorithmIdentifier,
        },
    },
};

pub const ENV_ROTATE_CONFIG: &'static str = "CERTIPASTA_ROTATE_CONFIG";
pub const ENV_SERVER_CONFIG: &'static str = "CERTIPASTA_CONFIG";
pub const VERSION_STATE_ENABLED: &'static str = "ENABLED";
pub const VERSION_STATE_DISABLED: &'static str = "DISABLED";
pub const VERSION_STATE_DESTROY_SCHEDULED: &'static str = "DESTROY_SCHEDULED";
pub const VERSION_STATE_DESTROYED: &'static str = "DESTROYED";

#[derive(Serialize, Deserialize)]
pub struct RotateConfig {
    pub bucket: String,
    pub key_gcpid: String,
}

#[derive(Serialize, Deserialize)]
pub struct ServerConfig {
    pub key_gcpid: String,
    pub cert_bucket: String,
    pub log_bucket: String,
}

pub fn sign_duration() -> Duration {
    return Duration::days(90);
}

pub fn rotation_period() -> Duration {
    return Duration::days(365);
}

pub fn rotation_buffer() -> Duration {
    return Duration::days(7);
}

pub const CA_FQDN: &'static str = "certipasta.isandrew.com";

#[derive(Clone)]
pub struct BuilderPubKey(pub SubjectPublicKeyInfoOwned);

impl EncodePublicKey for BuilderPubKey {
    fn to_public_key_der(&self) -> x509_cert::spki::Result<x509_cert::spki::Document> {
        return Ok(der::Document::from_der(&self.0.to_der().unwrap()).unwrap());
    }
}

pub struct BuilderSigner {
    pub key: BuilderPubKey,
    pub alg: x509_cert::spki::AlgorithmIdentifierOwned,
}

impl Keypair for BuilderSigner {
    type VerifyingKey = BuilderPubKey;

    fn verifying_key(&self) -> Self::VerifyingKey {
        return self.key.clone();
    }
}

impl DynSignatureAlgorithmIdentifier for BuilderSigner {
    fn signature_algorithm_identifier(&self) -> x509_cert::spki::Result<x509_cert::spki::AlgorithmIdentifierOwned> {
        return Ok(self.alg.clone());
    }
}

pub fn decide_sig(
    signer_keyinfo: &SubjectPublicKeyInfoOwned,
) -> Result<(fn(&[u8]) -> google_cloudkms1::api::Digest, x509_cert::spki::AlgorithmIdentifierOwned), loga::Error> {
    let digest_fn: fn(&[u8]) -> google_cloudkms1::api::Digest;
    let signature_algorithm;
    match signer_keyinfo.algorithm.oid {
        // ecPublicKey
        ID_EC_PUBLIC_KEY => {
            let curve =
                EcParameters::from_der(
                    &signer_keyinfo
                        .algorithm
                        .parameters
                        .as_ref()
                        .context("Missing ecPublicKey parameters")?
                        .to_der()
                        .unwrap(),
                )
                    .context("Error parsing ecPublicKey params")?
                    .named_curve()
                    .context("ecPublicKey params missing curve name")?;
            match curve {
                SECP_256_R_1 => {
                    fn f(csr_der: &[u8]) -> google_cloudkms1::api::Digest {
                        return google_cloudkms1::api::Digest {
                            sha256: Some(<Sha256 as Digest>::digest(csr_der).to_vec()),
                            ..Default::default()
                        };
                    }

                    digest_fn = f;
                    signature_algorithm = x509_cert::spki::AlgorithmIdentifierOwned {
                        oid: ECDSA_WITH_SHA_256,
                        parameters: None,
                    };
                },
                SECP_384_R_1 => {
                    fn f(csr_der: &[u8]) -> google_cloudkms1::api::Digest {
                        return google_cloudkms1::api::Digest {
                            sha384: Some(<Sha384 as Digest>::digest(csr_der).to_vec()),
                            ..Default::default()
                        };
                    }

                    digest_fn = f;
                    signature_algorithm = x509_cert::spki::AlgorithmIdentifierOwned {
                        oid: ECDSA_WITH_SHA_384,
                        parameters: None,
                    };
                },
                _ => {
                    return Err(loga::err_with("ecPublicKey has unsupported curve", ea!(curve = curve)));
                },
            }
        },
        _ => {
            return Err(
                loga::err_with("Configured key has unsupported algorithm", ea!(oid = signer_keyinfo.algorithm.oid)),
            );
        },
    }
    return Ok((digest_fn, signature_algorithm));
}
