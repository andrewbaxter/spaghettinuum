use std::time::SystemTime;
use loga::ResultContext;
use pem::Pem;
use x509_cert::Certificate;

pub fn encode_pub_pem(der: &[u8]) -> String {
    return Pem::new("CERTIFICATE", der).to_string();
}

pub fn encode_priv_pem(der: &[u8]) -> String {
    return Pem::new("PRIVATE KEY", der).to_string();
}

pub fn extract_expiry(pub_pem: &str) -> Result<SystemTime, loga::Error> {
    return Ok(
        Certificate::load_pem_chain(pub_pem.as_bytes())
            .context("Received invalid pub cert pem from certifier")?
            .first()
            .context("No certs in received pem")?
            .tbs_certificate
            .validity
            .not_after
            .to_system_time(),
    );
}
