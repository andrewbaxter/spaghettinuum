use {
    super::blob::{
        Blob,
        ToBlob,
    },
    crate::{
        bb,
        interface::stored::{
            self,
            identity::Identity,
        },
    },
    chrono::{
        DateTime,
        Duration,
        Utc,
    },
    der::{
        Decode,
        DecodePem,
        Encode,
    },
    loga::ResultContext,
    pem::Pem,
    rustls::client::WebPkiServerVerifier,
    sha2::{
        Digest,
        Sha256,
    },
    std::{
        collections::HashSet,
        sync::Arc,
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

/// Produce a hash of a public cert used for out-of-band cert verification.
pub fn cert_der_hash(cert_der: &[u8]) -> Result<Blob, loga::Error> {
    return Ok(
        <Sha256 as Digest>::digest(
            Certificate::from_der(&cert_der)
                .context("Error parsing cert DER for hashing")?
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .context("Error retrieving cert SPKI DER for hashing")?,
        ).blob(),
    );
}

pub fn cert_pem_hash(cert_pem: &str) -> Result<Blob, loga::Error> {
    return Ok(
        <Sha256 as Digest>::digest(
            Certificate::from_pem(&cert_pem)
                .context("Error parsing cert PEM for hashing")?
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .context("Error retrieving cert SPKI DER for hashing")?,
        ).blob(),
    );
}

fn default_verify_schemes() -> Vec<rustls::SignatureScheme> {
    // All enum values, in reverse order since it looks like newer ones are last on
    // the list?
    return vec![
        rustls::SignatureScheme::ED448,
        rustls::SignatureScheme::ED25519,
        rustls::SignatureScheme::RSA_PSS_SHA512,
        rustls::SignatureScheme::RSA_PSS_SHA384,
        rustls::SignatureScheme::RSA_PSS_SHA256,
        rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
        rustls::SignatureScheme::RSA_PKCS1_SHA512,
        rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
        rustls::SignatureScheme::RSA_PKCS1_SHA384,
        rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
        rustls::SignatureScheme::RSA_PKCS1_SHA256,
        rustls::SignatureScheme::ECDSA_SHA1_Legacy,
        rustls::SignatureScheme::RSA_PKCS1_SHA1
    ];
}

/// An http client cert verifier that doesn't verify anything, for situations where
/// the server name can't be known (DoT or resolver via DHCP where name isn't
/// provided separately).
#[derive(Debug)]
pub struct UnverifyingVerifier;

impl rustls::client::danger::ServerCertVerifier for UnverifyingVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
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
        return default_verify_schemes();
    }
}

/// A http client verifier that allows certs signed by an identity or provided
/// out-of-band.
#[derive(Debug)]
pub struct SpaghTlsClientVerifier {
    /// Any cert whose DER (SHA256) hash matches one of these is considered verified.
    pub hashes: HashSet<Blob>,
    /// Any cert with extension data containing a signature of the public key via this
    /// identity is considered verified.
    // TODO
    pub identity: Option<Identity>,
    pub inner: Arc<dyn rustls::client::danger::ServerCertVerifier>,
}

impl SpaghTlsClientVerifier {
    pub fn new(
        hashes: HashSet<Blob>,
        identity: Option<Identity>,
    ) -> Result<Arc<dyn rustls::client::danger::ServerCertVerifier>, loga::Error> {
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().expect("could not load platform certs") {
            roots.add(cert).ignore();
        }
        let inner = WebPkiServerVerifier::builder(Arc::new(roots)).build()?;
        return Ok(Arc::new(Self {
            hashes: hashes,
            identity: identity,
            inner: inner,
        }));
    }
}

impl rustls::client::danger::ServerCertVerifier for SpaghTlsClientVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Validate via out of band info
        if self
            .hashes
            .contains(
                &cert_der_hash(
                    end_entity.as_ref(),
                ).map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?,
            ) {
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }

        // Validate based on signature extension
        bb!{
            // Get signature
            let Ok(cert) = x509_cert:: Certificate:: from_der(&end_entity) else {
                break;
            };
            let Some(
                ext
            ) = cert.tbs_certificate.extensions.iter(
            ).flatten().find(|x| x.extn_id == stored::cert::x509_ext_pagh_oid()) else {
                break;
            };
            let Ok(ext) = stored:: cert:: X509ExtSpagh:: from_bytes(&ext.extn_value.as_bytes()) else {
                break;
            };
            let signature = match ext {
                stored::cert::X509ExtSpagh::V1(ext) => {
                    ext.signature
                },
            };

            // Get id
            let rustls:: pki_types:: ServerName:: DnsName(server_name) = server_name else {
                break;
            };
            let Some((prefix, suffix)) = server_name.as_ref().trim_matches('.').rsplit_once('.') else {
                break;
            };
            if suffix != ".s" {
                break;
            }
            let Some((_, raw_id_id)) = prefix.rsplit_once('.') else {
                break;
            };
            let Ok(id) = Identity:: from_str(raw_id_id) else {
                break;
            };

            // Check sig
            if id.verify(&cert.tbs_certificate.subject_public_key_info.to_der().unwrap(), &signature).is_ok() {
                return Ok(rustls::client::danger::ServerCertVerified::assertion());
            }
        }

        // Fall back to centralized methods
        return self.inner.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now);
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
        return default_verify_schemes();
    }
}
