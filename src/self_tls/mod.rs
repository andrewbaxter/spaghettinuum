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
    Encode,
};
use loga::{
    ea,
    ResultContext,
    DebugDisplay,
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
        blob::ToBlob,
        log::{
            Log,
            DEBUG_OTHER,
            WARN,
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
    ta_res,
};

pub mod db;

pub fn certifier_url() -> String {
    return env::var("CERTIPASTA").unwrap_or(DEFAULT_CERTIFIER_URL.to_string());
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
    log.log_with(DEBUG_OTHER, "Unsigned cert request params", ea!(params = String::from_utf8_lossy(&text)));
    let (ident, signature) = message_signer.sign(&text).context("Error signing cert request params")?;
    let body = serde_json::to_vec(&CertRequest::V1(latest::CertRequest {
        identity: ident,
        params: latest::SignedCertRequestParams {
            sig: signature,
            text: text,
        },
    })).unwrap();
    log.log_with(
        DEBUG_OTHER,
        "Sending cert request body",
        ea!(url = certifier_url, body = String::from_utf8_lossy(&body)),
    );
    let resp =
        reqwest::Client::builder()
            .build()
            .unwrap()
            .post(certifier_url)
            .body(body)
            .send()
            .await
            .context("Error sending cert request")?;
    let resp_status = resp.status();
    let body = resp.bytes().await.context("Error reading cert request response")?;
    if !resp_status.is_success() {
        return Err(
            loga::err_with(
                "Received error response",
                ea!(status = resp_status.dbg_str(), body = String::from_utf8_lossy(&body)),
            ),
        );
    }
    return Ok(serde_json::from_slice(&body).context("Error reading cert request response body")?);
}

#[derive(Clone)]
pub struct CertPair {
    pub pub_pem: String,
    pub priv_pem: String,
}

pub async fn request_cert_stream(
    log: &Log,
    tm: &TaskManager,
    certifier_url: &str,
    mut signer: Box<dyn IdentitySigner>,
    persistent_dir: &Path,
) -> Result<Receiver<CertPair>, loga::Error> {
    let log = &log.fork(ea!(subsys = "self_cert"));
    let db_pool = setup_db(&persistent_dir.join("self_tls.sqlite3"), db::migrate).await?;
    db_pool.get().await?.interact(|conn| db::api_certs_setup(conn)).await??;

    fn decide_refresh_at(pub_pem: &str) -> Result<SystemTime, loga::Error> {
        let not_after = extract_expiry(pub_pem.as_bytes())?;
        return Ok(not_after - std::time::Duration::from_secs(60 * 60 * 24 * 7));
    }

    async fn update_cert(
        log: &Log,
        db_pool: &Pool,
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
        let priv_pem = encode_priv_pem(&priv_key.to_sec1_der().unwrap());
        db_pool.get().await?.interact({
            let pub_pem = pub_pem.clone();
            let priv_pem = priv_pem.clone();
            move |conn| db::api_certs_set(conn, Some(&pub_pem), Some(&priv_pem))
        }).await??;
        return Ok(CertPair {
            priv_pem: priv_pem,
            pub_pem: pub_pem,
        });
    }

    let initial_pair = db_pool.get().await?.interact(|conn| db::api_certs_get(conn)).await??;
    let initial_pair = match (initial_pair.pub_pem, initial_pair.priv_pem) {
        (Some(pub_pem), Some(priv_pem)) => CertPair {
            pub_pem: pub_pem,
            priv_pem: priv_pem,
        },
        _ => {
            update_cert(log, &db_pool, certifier_url, &mut signer).await?
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
            ta_res!(());
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
                        match update_cert(log, &db_pool, &certifier_url, &mut signer).await {
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
                certs_stream_tx.send(certs).unwrap();
            }
            return Ok(());
        }
    });
    return Ok(certs_stream_rx);
}
