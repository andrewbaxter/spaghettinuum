use {
    super::blob::{
        Blob,
        ToBlob,
    },
    chrono::{
        DateTime,
        Duration,
        Utc,
    },
    der::{
        Decode,
        Encode,
    },
    loga::ResultContext,
    pem::Pem,
    rustls::server::ResolvesServerCert,
    sha2::{
        Digest,
        Sha256,
    },
    std::sync::{
        Arc,
        RwLock,
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

pub fn publisher_cert_hash(cert_der: &[u8]) -> Result<Blob, ()> {
    return Ok(
        <Sha256 as Digest>::digest(
            Certificate::from_der(&cert_der)
                .map_err(|_| ())?
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .map_err(|_| ())?,
        ).blob(),
    );
}

#[derive(Debug)]
pub struct SingleKeyVerifier {
    hash: Blob,
}

impl SingleKeyVerifier {
    pub fn new(hash: Blob) -> Arc<dyn rustls::client::danger::ServerCertVerifier> {
        return Arc::new(SingleKeyVerifier { hash });
    }
}

impl rustls::client::danger::ServerCertVerifier for SingleKeyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if publisher_cert_hash(
            end_entity.as_ref(),
        ).map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))? !=
            self.hash {
            return Err(rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding));
        }
        return Ok(rustls::client::danger::ServerCertVerified::assertion());
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        return Ok(rustls::client::danger::HandshakeSignatureValid::assertion());
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        return Ok(rustls::client::danger::HandshakeSignatureValid::assertion());
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        return vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448
        ];
    }
}
