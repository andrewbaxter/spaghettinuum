use {
    std::sync::{
        Arc,
        RwLock,
    },
    chrono::{
        DateTime,
        Duration,
        Utc,
    },
    loga::ResultContext,
    pem::Pem,
    rustls::{
        server::ResolvesServerCert,
    },
    x509_cert::Certificate,
};

pub fn encode_priv_pem(der: &[u8]) -> String {
    return Pem::new("PRIVATE KEY", der).to_string();
}

pub fn extract_expiry(pub_pem: &[u8]) -> Result<DateTime<Utc>, loga::Error> {
    return Ok(
        DateTime::<Utc>::UNIX_EPOCH +
            Duration::seconds(
                Certificate::load_pem_chain(pub_pem)
                    .context("Received invalid pub cert pem from certifier")?
                    .first()
                    .context("No certs in received pem")?
                    .tbs_certificate
                    .validity
                    .not_after
                    .to_system_time()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as
                    i64,
            ),
    );
}

pub fn load_certified_key(pub_pem: &str, priv_pem: &str) -> Result<Arc<rustls::sign::CertifiedKey>, loga::Error> {
    let mut certs = vec![];
    for cert in rustls_pemfile::certs(&mut pub_pem.as_bytes()) {
        let cert = cert.context("Invalid cert in public cert PEM")?;
        certs.push(rustls::pki_types::CertificateDer::from(cert.to_vec()));
    }
    let key =
        rustls_pemfile::pkcs8_private_keys(&mut priv_pem.as_bytes())
            .next()
            .context("Private key PEM has no private certs in it")?
            .context("Error reading private key PEM")?;
    return Ok(
        Arc::new(
            rustls::sign::CertifiedKey::new(
                certs,
                rustls::crypto::ring::sign::any_ecdsa_type(
                    &rustls::pki_types::PrivateKeyDer::Pkcs8(
                        rustls::pki_types::PrivatePkcs8KeyDer::from(key.secret_pkcs8_der().to_vec()),
                    ),
                ).unwrap(),
            ),
        ),
    );
}

pub fn rustls21_load_certified_key(
    pub_pem: &str,
    priv_pem: &str,
) -> Result<Arc<rustls_21::sign::CertifiedKey>, loga::Error> {
    let mut certs = vec![];
    for cert in rustls_pemfile::certs(&mut pub_pem.as_bytes()) {
        let cert = cert.context("Invalid cert in public cert PEM")?;
        certs.push(rustls_21::Certificate(cert.to_vec()));
    }
    let key =
        rustls_pemfile::pkcs8_private_keys(&mut priv_pem.as_bytes())
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

pub struct SingleCertResolver(pub Arc<RwLock<Arc<rustls::sign::CertifiedKey>>>);

impl std::fmt::Debug for SingleCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SingleCertResolver").field(&self.0.read().unwrap()).finish()
    }
}

impl ResolvesServerCert for SingleCertResolver {
    fn resolve(&self, _client_hello: rustls::server::ClientHello) -> Option<Arc<rustls::sign::CertifiedKey>> {
        return Some(self.0.read().unwrap().clone());
    }
}
