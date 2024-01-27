use std::{
    collections::HashMap,
    env,
    sync::{
        Arc,
        Mutex,
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
use loga::{
    ea,
    ResultContext,
};
use p256::pkcs8::EncodePrivateKey;
use rustls::server::ResolvesServerCert;
use taskmanager::TaskManager;
use tokio::{
    sync::watch::{
        Receiver,
        channel,
    },
    select,
    time::{
        sleep_until,
        sleep,
    },
};
use x509_cert::{
    spki::{
        SubjectPublicKeyInfoOwned,
    },
};
use crate::{
    utils::{
        backed_identity::IdentitySigner,
        tls_util::{
            encode_priv_pem,
            extract_expiry,
        },
        blob::ToBlob,
        log::{
            Log,
            DEBUG_SELF_TLS,
            WARN,
        },
        htreq,
        time_util::ToInstant,
    },
    interface::{
        certify_protocol::{
            latest,
            CertRequest,
        },
        spagh_cli::{
            DEFAULT_CERTIFIER_URL,
            ENV_CERTIFIER,
        },
    },
    bb,
    ta_res,
};

pub mod db;

pub fn certifier_url() -> String {
    return env::var(ENV_CERTIFIER).unwrap_or(DEFAULT_CERTIFIER_URL.to_string());
}

/// Requests a TLS public cert from the certifier for the `.s` domain associated
/// with the provided identity and returns the result as PEM.
pub async fn request_cert(
    log: &Log,
    certifier_url: &str,
    requester_spki: &SubjectPublicKeyInfoOwned,
    message_signer: &mut Box<dyn IdentitySigner>,
) -> Result<latest::CertResponse, loga::Error> {
    let text = serde_json::to_vec(&latest::CertRequestParams {
        stamp: Utc::now(),
        spki_der: requester_spki.to_der().unwrap().blob(),
    }).unwrap().blob();
    log.log_with(DEBUG_SELF_TLS, "Unsigned cert request params", ea!(params = String::from_utf8_lossy(&text)));
    let (ident, signature) = message_signer.sign(&text).context("Error signing cert request params")?;
    let body = serde_json::to_vec(&CertRequest::V1(latest::CertRequest {
        identity: ident,
        params: latest::SignedCertRequestParams {
            sig: signature,
            text: text,
        },
    })).unwrap();
    log.log_with(
        DEBUG_SELF_TLS,
        "Sending cert request body",
        ea!(url = certifier_url, body = String::from_utf8_lossy(&body)),
    );
    let body = htreq::post(certifier_url, &HashMap::new(), body, 100 * 1024).await?;
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
    certifier_url: &str,
    mut signer: Box<dyn IdentitySigner>,
    initial_pair: Option<CertPair>,
) -> Result<Receiver<CertPair>, loga::Error> {
    let log = &log.fork(ea!(sys = "self_tls"));

    fn decide_refresh_at(pub_pem: &str) -> Result<DateTime<Utc>, loga::Error> {
        let not_after = extract_expiry(pub_pem.as_bytes())?;
        return Ok(not_after - Duration::hours(24 * 7));
    }

    async fn update_cert(
        log: &Log,
        certifier_url: &str,
        identity: &mut Box<dyn IdentitySigner>,
    ) -> Result<CertPair, loga::Error> {
        let priv_key = p256::SecretKey::random(&mut rand::thread_rng());
        let pub_pem =
            request_cert(
                log,
                &certifier_url,
                &SubjectPublicKeyInfoOwned::from_key(priv_key.public_key()).unwrap(),
                identity,
            )
                .await
                .context("Error requesting api server tls cert from certifier")?
                .pub_pem;
        let priv_pem = encode_priv_pem(priv_key.to_pkcs8_der().unwrap().as_bytes());
        log.log_with(DEBUG_SELF_TLS, "Received cert", ea!(pub_pem = pub_pem));
        return Ok(CertPair {
            priv_pem: priv_pem,
            pub_pem: pub_pem,
        });
    }

    let initial_pair = match initial_pair {
        Some(p) => p,
        _ => {
            update_cert(log, certifier_url, &mut signer)
                .await
                .stack_context(log, "Error retrieving initial certificates")?
        },
    };
    let refresh_at =
        decide_refresh_at(&initial_pair.pub_pem).context("Error extracting expiration time from cert pem")?;
    let (certs_stream_tx, certs_stream_rx) = channel(initial_pair);
    tm.critical_task("API - Self-TLS refresher", {
        let tm = tm.clone();
        let certifier_url = certifier_url.to_string();
        let log = log.clone();
        async move {
            ta_res!(());
            let mut refresh_at = refresh_at;
            let log = &log;
            loop {
                log.log_with(DEBUG_SELF_TLS, "Sleeping until cert needs refresh", ea!(deadline = refresh_at));

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
                        match update_cert(log, &certifier_url, &mut signer).await {
                            Ok(certs) => {
                                break 'ok Some(certs);
                            },
                            Err(e) => {
                                log.log_err(WARN, e.context("Error getting new certs"));
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

pub struct SimpleResolvesServerCert(pub Arc<Mutex<Option<Arc<rustls::sign::CertifiedKey>>>>);

impl std::fmt::Debug for SimpleResolvesServerCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return self.0.lock().unwrap().fmt(f);
    }
}

impl ResolvesServerCert for SimpleResolvesServerCert {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello,
    ) -> Option<std::sync::Arc<rustls::sign::CertifiedKey>> {
        return self.0.lock().unwrap().clone();
    }
}
