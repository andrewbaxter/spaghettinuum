use {
    super::{
        blob::{
            Blob,
            ToBlob,
        },
    },
    crate::interface::{
        stored::{
            self,
            cert::X509_EXT_SPAGH_OID,
            identity::Identity,
        },
        wire::resolve::DNS_SUFFIX,
    },
    der::{
        oid::AssociatedOid,
        Decode,
        DecodePem,
        Encode,
    },
    flowcontrol::shed,
    futures::Future,
    loga::{
        conversion::ResultIgnore,
        ResultContext,
    },
    p256::ecdsa::DerSignature,
    pem::Pem,
    rand::RngCore,
    rustls::client::WebPkiServerVerifier,
    sha2::{
        Digest,
        Sha256,
    },
    signature::SignerMut,
    std::{
        collections::HashSet,
        str::FromStr,
        sync::Arc,
        time::{
            SystemTime,
        },
    },
    x509_cert::{
        builder::Builder,
        ext::AsExtension,
        Certificate,
    },
};

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
    pub inner: Option<Arc<dyn rustls::client::danger::ServerCertVerifier>>,
}

impl SpaghTlsClientVerifier {
    pub fn with_root_cas(
        hashes: HashSet<Blob>,
    ) -> Result<Arc<dyn rustls::client::danger::ServerCertVerifier>, loga::Error> {
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().expect("could not load platform certs") {
            roots.add(cert).ignore();
        }
        let inner = WebPkiServerVerifier::builder(Arc::new(roots)).build()?;
        return Ok(Arc::new(Self {
            hashes: hashes,
            inner: Some(inner),
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
        // Validate via out of band info - this is hashes provided by records for the
        // identity (retrieved via spaghettinuum). Zero conf. Can be revoked, but requires
        // network access + setup.
        if self
            .hashes
            .contains(
                &cert_der_hash(
                    end_entity.as_ref(),
                ).map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?,
            ) {
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }

        // Validate based on signature extension - the extension contains the SPKI signed
        // by the identity itself. Zero conf. This is not revokable.
        shed!{
            // Get signature
            let Ok(cert) = x509_cert::Certificate::from_der(&end_entity) else {
                break;
            };
            let Some(ext) =
                cert.tbs_certificate.extensions.iter().flatten().find(|x| x.extn_id == X509_EXT_SPAGH_OID) else {
                    break;
                };
            let Ok(ext) = stored::cert::X509ExtSpagh::from_bytes(&ext.extn_value.as_bytes()) else {
                break;
            };
            let signature = match ext {
                stored::cert::X509ExtSpagh::V1(ext) => {
                    ext.signature
                },
            };

            // Get id
            let rustls::pki_types::ServerName::DnsName(server_name) = server_name else {
                break;
            };
            let Some((prefix, suffix)) = server_name.as_ref().trim_matches('.').rsplit_once('.') else {
                break;
            };
            if suffix != DNS_SUFFIX {
                break;
            }
            let raw_id_id;
            match prefix.rsplit_once('.') {
                Some((_, r)) => {
                    raw_id_id = r;
                },
                None => {
                    raw_id_id = prefix;
                },
            }
            let Ok(id) = Identity::from_str(raw_id_id) else {
                break;
            };

            // Check sig
            if id.verify(&cert.tbs_certificate.subject_public_key_info.to_der().unwrap(), &signature).is_ok() {
                return Ok(rustls::client::danger::ServerCertVerified::assertion());
            }
        }

        // Verify via chain/local CA certs - centralized and requires client configuration
        // for extra certs.
        if let Some(inner) = &self.inner {
            return inner.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now);
        }

        // Default reject
        return Err(rustls::Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure));
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

/// Produce a random serial number for a certificate
pub fn rand_serial() -> x509_cert::serial_number::SerialNumber {
    let mut data = [0u8; 20];
    rand::thread_rng().fill_bytes(&mut data);

    // Big-endian positive, for whatever meaning the spec has remaining
    data[0] &= 0x7F;
    return x509_cert::serial_number::SerialNumber::new(&data).unwrap();
}

/// Convert time from chrono into x509 time format (day granularity)
pub fn to_x509_time(t: SystemTime) -> x509_cert::time::Time {
    return x509_cert::time::Time::GeneralTime(der::asn1::GeneralizedTime::from_system_time(t).unwrap());
}

pub async fn create_leaf_cert_der<
    S,
    S2,
    S2F,
>(
    requester_key_info: x509_cert::spki::SubjectPublicKeyInfoOwned,
    fqdn: &str,
    signature_ext: Option<stored::cert::v1::X509ExtSpagh>,
    start: SystemTime,
    end: SystemTime,
    issuer_signer: S,
    issuer_signer2: S2,
    issuer_fqdn: &str,
) -> Result<Blob, loga::Error>
where
    S: signature::Keypair + x509_cert::spki::DynSignatureAlgorithmIdentifier,
    S::VerifyingKey: p256::pkcs8::EncodePublicKey,
    S2F: Future<Output = Result<Blob, loga::Error>>,
    S2: FnOnce(Blob) -> S2F {
    let mut cert_builder =
        x509_cert::builder::CertificateBuilder::new(
            x509_cert::builder::Profile::Leaf {
                issuer: x509_cert::name::RdnSequence::from_str(&format!("CN={}", issuer_fqdn)).unwrap(),
                enable_key_agreement: true,
                enable_key_encipherment: true,
            },
            rand_serial(),
            x509_cert::time::Validity {
                not_before: to_x509_time(start),
                not_after: to_x509_time(end),
            },
            x509_cert::name::RdnSequence::from_str(&format!("CN={}", fqdn)).unwrap(),
            requester_key_info,
            &issuer_signer,
        ).unwrap();
    cert_builder
        .add_extension(
            &x509_cert::ext::pkix::SubjectAltName(
                vec![x509_cert::ext::pkix::name::GeneralName::DnsName(der::asn1::Ia5String::new(&fqdn).unwrap())],
            ),
        )
        .unwrap();
    if let Some(signature_ext) = signature_ext {
        struct SigExt(Vec<u8>);

        impl AssociatedOid for SigExt {
            const OID: der::oid::ObjectIdentifier = X509_EXT_SPAGH_OID;
        }

        impl der::Encode for SigExt {
            fn encoded_len(&self) -> der::Result<der::Length> {
                return Ok(der::Length::new(self.0.len() as u16));
            }

            fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
                return Ok(encoder.write(&self.0)?);
            }
        }

        impl AsExtension for SigExt {
            fn critical(&self, _subject: &x509_cert::name::Name, _extensions: &[x509_cert::ext::Extension]) -> bool {
                return false;
            }
        }

        cert_builder.add_extension(&SigExt(stored::cert::X509ExtSpagh::V1(signature_ext).to_bytes())).unwrap();
    }
    let csr_der = cert_builder.finalize().unwrap();
    let signature = issuer_signer2(Blob::from(csr_der)).await?;
    return Ok(
        cert_builder
            .assemble(der::asn1::BitString::from_bytes(&signature).context("Error building signature bitstring")?)
            .context("Error assembling cert")?
            .to_der()
            .context("Error building PEM for cert")?
            .blob(),
    );
}

pub async fn create_leaf_cert_der_local(
    key: p256::ecdsa::SigningKey,
    fqdn: &str,
    start: SystemTime,
    end: SystemTime,
    signature_ext: Option<stored::cert::v1::X509ExtSpagh>,
    issuer_fqdn: &str,
) -> Result<Blob, loga::Error> {
    return Ok(
        create_leaf_cert_der(
            x509_cert::spki::SubjectPublicKeyInfoOwned::from_key(*key.verifying_key()).unwrap(),
            fqdn,
            signature_ext,
            start,
            end,
            key.clone(),
            {
                let mut key = key;
                move |csr| async move {
                    return Ok(SignerMut::<DerSignature>::try_sign(&mut key, &csr)?.to_bytes().blob());
                }
            },
            issuer_fqdn,
        ).await?.blob(),
    );
}
