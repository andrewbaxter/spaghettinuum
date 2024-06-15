use std::{
    collections::HashMap,
    str::FromStr,
    sync::{
        Arc,
        Mutex,
        RwLock,
    },
};
use chrono::{
    Utc,
    Duration,
    DateTime,
};
use der::{
    Encode,
};
use http::Uri;
use htwrap::htreq;
use loga::{
    ea,
    Log,
    ResultContext,
};
use p256::pkcs8::EncodePrivateKey;
use rustls::server::ResolvesServerCert;
use taskmanager::TaskManager;
use tokio::{
    select,
    sync::watch::{
        self,
        channel,
    },
    time::{
        sleep,
        sleep_until,
    },
};
use x509_cert::{
    spki::{
        SubjectPublicKeyInfoOwned,
    },
};
use crate::{
    bb,
    interface::wire,
    ta_res,
    utils::{
        backed_identity::IdentitySigner,
        tls_util::{
            encode_priv_pem,
            extract_expiry,
        },
        blob::ToBlob,
        time_util::ToInstant,
    },
};

pub mod db;

pub const CERTIFIER_URL: &'static str = "https://certipasta.isandrew.com";

/// Requests a TLS public cert from the certifier for the `.s` domain associated
/// with the provided identity and returns the result as PEM. This function
/// generates a new private/public key pair for the cert.
pub async fn request_cert(
    log: &Log,
    message_signer: Arc<Mutex<dyn IdentitySigner>>,
) -> Result<CertPair, loga::Error> {
    let priv_key = p256::SecretKey::random(&mut rand::thread_rng());
    let pub_pem =
        request_cert_with_key(
            log,
            &SubjectPublicKeyInfoOwned::from_key(priv_key.public_key()).unwrap(),
            message_signer,
        )
            .await
            .context("Error requesting api server tls cert from certifier")?
            .pub_pem;
    let priv_pem = encode_priv_pem(priv_key.to_pkcs8_der().unwrap().as_bytes());
    log.log_with(loga::DEBUG, "Received cert", ea!(pub_pem = pub_pem));
    return Ok(CertPair {
        priv_pem: priv_pem,
        pub_pem: pub_pem,
    });
}

/// Requests a TLS public cert from the certifier for the `.s` domain associated
/// with the provided identity and private key and returns the result as PEM.
pub async fn request_cert_with_key(
    log: &Log,
    requester_spki: &SubjectPublicKeyInfoOwned,
    message_signer: Arc<Mutex<dyn IdentitySigner>>,
) -> Result<wire::certify::latest::CertResponse, loga::Error> {
    let text = serde_json::to_vec(&wire::certify::latest::CertRequestParams {
        stamp: Utc::now(),
        spki_der: requester_spki.to_der().unwrap().blob(),
    }).unwrap().blob();
    log.log_with(loga::DEBUG, "Unsigned cert request params", ea!(params = String::from_utf8_lossy(&text)));
    let (ident, signature) =
        message_signer.lock().unwrap().sign(&text).context("Error signing cert request params")?;
    let body = serde_json::to_vec(&wire::certify::CertRequest::V1(wire::certify::latest::CertRequest {
        identity: ident,
        params: wire::certify::latest::SignedCertRequestParams {
            sig: signature,
            text: text,
        },
    })).unwrap();
    let url = Uri::from_str(CERTIFIER_URL).unwrap();
    let log = log.fork(ea!(url = url));
    log.log_with(loga::DEBUG, "Sending cert request body", ea!(body = String::from_utf8_lossy(&body)));
    let body =
        htreq::post(
            &log,
            &mut htreq::connect(&url).await.stack_context(&log, "Error connecting to certifier url")?,
            &url,
            &HashMap::new(),
            body,
            100 * 1024,
        ).await?;
    return Ok(serde_json::from_slice(&body).context("Error parsing cert request response body as json")?);
}

#[derive(Clone)]
pub struct CertPair {
    /// X509 public cert, signed by certipasta CA key
    pub pub_pem: String,
    /// PKCS8 private key
    pub priv_pem: String,
}

pub async fn request_cert_stream(
    log: &Log,
    tm: &TaskManager,
    signer: Arc<Mutex<dyn IdentitySigner>>,
    initial_pair: CertPair,
) -> Result<watch::Receiver<CertPair>, loga::Error> {
    let log = &log.fork(ea!(sys = "self_tls"));

    fn decide_refresh_at(pub_pem: &str) -> Result<DateTime<Utc>, loga::Error> {
        let not_after = extract_expiry(pub_pem.as_bytes())?;
        return Ok(not_after - Duration::hours(24 * 7));
    }

    let refresh_at =
        decide_refresh_at(&initial_pair.pub_pem).context("Error extracting expiration time from cert pem")?;
    let (certs_stream_tx, certs_stream_rx) = channel(initial_pair);
    tm.critical_task("API - Self-TLS refresher", {
        let tm = tm.clone();
        let log = log.clone();
        async move {
            ta_res!(());
            let mut refresh_at = refresh_at;
            let log = &log;
            loop {
                log.log_with(loga::DEBUG, "Sleeping until cert needs refresh", ea!(deadline = refresh_at));

                select!{
                    _ = tm.until_terminate() => {
                        break;
                    }
                    _ = sleep_until(refresh_at.to_instant()) =>(),
                }

                let mut backoff = std::time::Duration::from_secs(30);
                let max_tries = 5;
                let certs = bb!{
                    'ok _;
                    for _ in 0 .. max_tries {
                        match request_cert(log, signer.clone()).await {
                            Ok(certs) => {
                                break 'ok Some(certs);
                            },
                            Err(e) => {
                                log.log_err(loga::WARN, e.context("Error getting new certs"));
                                sleep(backoff).await;
                                backoff = backoff * 2;
                            },
                        }
                    }
                    break 'ok None;
                }.stack_context_with(log, "Failed to get new cert after retrying", ea!(tries = max_tries))?;
                refresh_at =
                    decide_refresh_at(&certs.pub_pem).context("Error extracting expiration time from cert pem")?;
                _ = certs_stream_tx.send(certs);
            }
            return Ok(());
        }
    });
    return Ok(certs_stream_rx);
}

pub struct SimpleResolvesServerCert(pub Arc<RwLock<Arc<rustls::sign::CertifiedKey>>>);

impl std::fmt::Debug for SimpleResolvesServerCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return self.0.read().unwrap().fmt(f);
    }
}

impl ResolvesServerCert for SimpleResolvesServerCert {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello,
    ) -> Option<std::sync::Arc<rustls::sign::CertifiedKey>> {
        return Some(self.0.read().unwrap().clone());
    }
}
