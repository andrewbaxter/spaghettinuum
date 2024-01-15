use std::{
    time::SystemTime,
    sync::Arc,
};
use loga::ResultContext;
use pem::Pem;
use x509_cert::Certificate;

pub fn encode_pub_pem(der: &[u8]) -> String {
    return Pem::new("CERTIFICATE", der).to_string();
}

pub fn encode_priv_pem(der: &[u8]) -> String {
    return Pem::new("PRIVATE KEY", der).to_string();
}

pub fn extract_expiry(pub_pem: &[u8]) -> Result<SystemTime, loga::Error> {
    return Ok(
        Certificate::load_pem_chain(pub_pem)
            .context("Received invalid pub cert pem from certifier")?
            .first()
            .context("No certs in received pem")?
            .tbs_certificate
            .validity
            .not_after
            .to_system_time(),
    );
}

pub fn load_certified_key(
    mut pub_pem: &[u8],
    mut priv_pem: &[u8],
) -> Result<Arc<rustls_21::sign::CertifiedKey>, loga::Error> {
    let mut certs = vec![];
    for cert in rustls_pemfile::certs(&mut pub_pem) {
        let cert = cert.context("Invalid cert in public cert PEM")?;
        certs.push(rustls_21::Certificate(cert.to_vec()));
    }
    let key =
        rustls_pemfile::pkcs8_private_keys(&mut priv_pem)
            .next()
            .context("Private key PEM has no private certs in it")?
            .context("Error reading private key PEM")?;
    return Ok(
        Arc::new(
            rustls_21::sign::CertifiedKey::new(
                certs,
                rustls_21::sign::any_ecdsa_type(&rustls_21::PrivateKey(key.secret_pkcs8_der().to_vec())).unwrap(),
            ),
        ),
    );
}
