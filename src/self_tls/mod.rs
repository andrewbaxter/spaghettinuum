use std::{
    env,
    path::Path,
    time::{
        SystemTime,
    },
};
use chrono::{
    Utc,
};
use deadpool_sqlite::Pool;
use der::{
    Decode,
    Encode,
};
use loga::{
    ea,
    ResultContext,
};
use ring::{
    rand::{
        SystemRandom,
    },
    signature::{
        ECDSA_P256_SHA256_ASN1_SIGNING,
        EcdsaKeyPair,
    },
};
use taskmanager::TaskManager;
use tokio::{
    sync::watch::{
        Receiver,
        channel,
    },
    select,
    time::{
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
        db_util::setup_db,
        tls_util::{
            encode_priv_pem,
            extract_expiry,
        },
    },
    interface::{
        certify_protocol::{
            latest,
            CertRequest,
        },
        spagh_cli::DEFAULT_CERTIFIER_URL,
    },
    bb,
};

pub mod db;

pub fn certifier_url() -> String {
    return env::var("CERTIPASTA").unwrap_or(DEFAULT_CERTIFIER_URL.to_string());
}

/// Generates a key pair DER which can be serialized as PEM for a SSL server or
/// from which SPKI can be extracted for a certifier cert request.
pub fn default_generate_cert_keys(random: &SystemRandom) -> Vec<u8> {
    let alg = &ECDSA_P256_SHA256_ASN1_SIGNING;
    return EcdsaKeyPair::generate_pkcs8(alg, random).unwrap().as_ref().to_vec();
}

/// Requests a TLS public cert from the certifier for the `.s` domain associated
/// with the provided identity and returns the result as PEM.
pub async fn request_cert(
    certifier_url: &str,
    signer: &mut Box<dyn IdentitySigner>,
    cert_priv_key_pkcs8_der: &[u8],
) -> Result<latest::CertResponse, String> {
    let requester_spki = SubjectPublicKeyInfoOwned::from_der(&cert_priv_key_pkcs8_der).unwrap();
    let text = serde_json::to_vec(&latest::CertRequestParams {
        stamp: Utc::now(),
        spki_der: requester_spki.to_der().unwrap(),
    }).unwrap();
    let (ident, signature) = signer.sign(&text).map_err(|e| format!("Error signing payload: {:?}", e))?;
    let resp =
        reqwest::Client::builder()
            .build()
            .unwrap()
            .post(certifier_url)
            .body(serde_json::to_vec(&CertRequest::V1(latest::CertRequest {
                identity: ident,
                params: latest::SignedCertRequestParams {
                    sig: signature,
                    text: text,
                },
            })).unwrap())
            .send()
            .await
            .map_err(|e| format!("Error sending cert request: {}", e))?;
    let resp_status = resp.status();
    let body = resp.bytes().await.map_err(|e| format!("Error reading response: {:?}", e))?;
    if !resp_status.is_success() {
        return Err(
            format!("Received {:?} from server with body: [[{}]]", resp_status, String::from_utf8_lossy(&body)),
        );
    }
    return Ok(
        serde_json::from_slice(&body).map_err(|e| format!("Error reading cert request response body: {}", e))?,
    );
}

#[derive(Clone)]
pub struct CertPair {
    pub pub_pem: String,
    pub priv_pem: String,
}

pub async fn request_cert_stream(
    log: &loga::Log,
    tm: &TaskManager,
    certifier_url: &str,
    mut signer: Box<dyn IdentitySigner>,
    persistent_dir: &Path,
) -> Result<Receiver<CertPair>, loga::Error> {
    let log = &log.fork(ea!(subsys = "self_cert"));
    let db_pool = setup_db(&persistent_dir.join("self_tls.sqlite3"), db::migrate).await?;
    db_pool.get().await?.interact(|conn| db::ensure(conn)).await??;

    fn decide_refresh_at(pub_pem: &str) -> Result<SystemTime, loga::Error> {
        let not_after = extract_expiry(pub_pem)?;
        return Ok(not_after - std::time::Duration::from_secs(60 * 60 * 24 * 7));
    }

    async fn update_cert(
        db_pool: &Pool,
        certifier_url: &str,
        identity: &mut Box<dyn IdentitySigner>,
    ) -> Result<CertPair, loga::Error> {
        let priv_der = default_generate_cert_keys(&SystemRandom::new());
        let pub_pem =
            request_cert(&certifier_url, identity, &priv_der)
                .await
                .map_err(|e| loga::err_with("Error requesting api server tls cert from certifier", ea!(err = e)))?
                .pub_pem;
        let priv_pem = encode_priv_pem(&priv_der);
        db_pool.get().await?.interact({
            let pub_pem = pub_pem.clone();
            let priv_pem = priv_pem.clone();
            move |conn| db::set_cert(conn, Some(&pub_pem), Some(&priv_pem))
        }).await??;
        return Ok(CertPair {
            priv_pem: priv_pem,
            pub_pem: pub_pem,
        });
    }

    let initial_pair = db_pool.get().await?.interact(|conn| db::get_cert(conn)).await??;
    let initial_pair = match (initial_pair.pub_pem, initial_pair.priv_pem) {
        (Some(pub_pem), Some(priv_pem)) => CertPair {
            pub_pem: pub_pem,
            priv_pem: priv_pem,
        },
        _ => {
            update_cert(&db_pool, certifier_url, &mut signer).await?
        },
    };
    let refresh_at =
        decide_refresh_at(&initial_pair.pub_pem).context("Error extracting expiration time from cert pem")?;
    let (certs_stream_tx, certs_stream_rx) = channel(initial_pair);
    tm.critical_task({
        let db_pool = db_pool.clone();
        let tm = tm.clone();
        let certifier_url = certifier_url.to_string();
        let log = log.clone();
        async move {
            let mut refresh_at = refresh_at;
            let log = &log;
            loop {
                select!{
                    _ = sleep(refresh_at.duration_since(SystemTime::now()).unwrap()) =>(),
                    _ = tm.until_terminate() => {
                        break;
                    }
                }

                let mut backoff = std::time::Duration::from_secs(30);
                let max_tries = 5;
                let certs = bb!{
                    'ok _;
                    for _ in 0 .. max_tries {
                        match update_cert(&db_pool, &certifier_url, &mut signer).await {
                            Ok(certs) => {
                                break 'ok Some(certs);
                            },
                            Err(e) => {
                                log.warn_e(e, "Error getting new certs", ea!());
                                sleep(backoff).await;
                                backoff = backoff * 2;
                            },
                        }
                    }
                    break 'ok None;
                }.log_context_with(log, "Failed to get new cert after retrying", ea!(tries = max_tries))?;
                refresh_at =
                    decide_refresh_at(&certs.pub_pem).context("Error extracting expiration time from cert pem")?;
                certs_stream_tx.send(certs).unwrap();
            }
            return Ok(()) as Result<_, loga::Error>;
        }
    });
    return Ok(certs_stream_rx);
}
