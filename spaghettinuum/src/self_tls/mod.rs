//! Methods for obtaining a `.s` TLS cert
use {
    std::{
        collections::HashMap,
        path::Path,
        str::FromStr,
        sync::{
            Arc,
            Mutex,
            RwLock,
        },
    },
    chrono::{
        Utc,
        Duration,
        DateTime,
    },
    der::{
        Encode,
    },
    http::Uri,
    htwrap::htreq,
    loga::{
        ea,
        Log,
        ResultContext,
    },
    p256::pkcs8::EncodePrivateKey,
    rustls::{
        server::ResolvesServerCert,
    },
    taskmanager::TaskManager,
    tokio::{
        select,
        sync::watch::{
            self,
            channel,
        },
        task::spawn_blocking,
        time::{
            sleep,
            sleep_until,
        },
    },
    tokio_stream::{
        wrappers::WatchStream,
        StreamExt,
    },
    x509_cert::{
        spki::{
            SubjectPublicKeyInfoOwned,
        },
    },
    crate::{
        bb,
        interface::{
            stored::{
                self,
                self_tls::{
                    latest::CertPair,
                },
            },
            wire::{
                self,
                api::publish::v1::PublishRequestContent,
            },
        },
        publishing::Publisher,
        ta_res,
        utils::{
            identity_secret::IdentitySigner,
            blob::ToBlob,
            db_util::{
                self,
                DbTx,
            },
            fs_util::write,
            time_util::ToInstant,
            tls_util::{
                encode_priv_pem,
                extract_expiry,
                load_certified_key,
            },
        },
    },
};

pub mod db;

pub const CERTIFIER_URL: &'static str = "https://certipasta.isandrew.com";

pub fn publish_ssl_ttl() -> Duration {
    return Duration::try_minutes(60).unwrap();
}

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

/// Produces a stream of TLS cert pairs, with a new pair some time before the
/// previous pair expires.
pub async fn request_cert_stream(
    log: &Log,
    tm: &TaskManager,
    signer: Arc<Mutex<dyn IdentitySigner>>,
    initial_pair: CertPair,
) -> Result<watch::Receiver<CertPair>, loga::Error> {
    let log = &log.fork(ea!(sys = "self_tls"));

    fn decide_refresh_at(pub_pem: &str) -> Result<DateTime<Utc>, loga::Error> {
        let not_after = extract_expiry(pub_pem.as_bytes())?;
        return Ok(not_after - Duration::try_hours(24 * 7).unwrap() - (publish_ssl_ttl() * 2));
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

/// Produce a rustls-compatible server cert resolver with an automatically updated
/// cert.  This is a managed task that maintains state using a database at the
/// provided location.
///
/// Returns `None` if the task manager is shut down before initial setup completes.
pub async fn htserve_tls_resolves(
    log: &Log,
    persistent_dir: &Path,
    write_certs: bool,
    tm: &TaskManager,
    publisher: &Arc<dyn Publisher>,
    identity_signer: &Arc<Mutex<dyn IdentitySigner>>,
) -> Result<Option<Arc<dyn ResolvesServerCert>>, loga::Error> {
    async fn publish_tls_certs(
        log: &Log,
        publisher: &Arc<dyn Publisher>,
        identity_signer: &Arc<Mutex<dyn IdentitySigner>>,
        state: &stored::self_tls::latest::SelfTlsState,
    ) -> Result<(), loga::Error> {
        publisher.publish(log, identity_signer.clone(), PublishRequestContent {
            set: {
                let mut m = HashMap::new();
                let mut certs = vec![state.current.pub_pem.clone()];
                if let Some((_, new)) = &state.pending {
                    certs.push(new.pub_pem.clone());
                }
                m.insert(
                    stored::record::tls_record::KEY.to_string(),
                    stored::record::RecordValue::V1(stored::record::latest::RecordValue {
                        ttl: publish_ssl_ttl().num_minutes() as i32,
                        data: Some(
                            serde_json::to_value(
                                &stored::record::tls_record::TlsCerts::V1(
                                    stored::record::tls_record::latest::TlsCerts(certs),
                                ),
                            ).unwrap(),
                        ),
                    }),
                );
                m
            },
            ..Default::default()
        }).await?;
        return Ok(());
    }

    let db_pool = db_util::setup_db(&persistent_dir.join("self_tls.sqlite3"), db::migrate).await?;
    db_pool.tx(|conn| Ok(db::api_certs_setup(conn)?)).await?;

    // Prepare initial state, either restoring or getting from scratch
    let mut state = match db_pool.tx(|conn| Ok(db::api_certs_get(conn)?)).await? {
        Some(s) => match s {
            stored::self_tls::SelfTlsState::V1(mut s) => {
                bb!({
                    let Some((after, _)) =& s.pending else {
                        break;
                    };
                    if Utc::now() < *after {
                        break;
                    }
                    let (_, new) = s.pending.take().unwrap();
                    s.current = new;
                });
                s
            },
        },
        None => {
            let pair = loop {
                match select!{
                    c = request_cert(&log, identity_signer.clone()) => c,
                    _ = tm.until_terminate() => {
                        return Ok(None);
                    }
                } {
                    Ok(p) => break p,
                    Err(e) => {
                        log.log_err(
                            loga::WARN,
                            e.context_with("Error fetching initial certificates, retrying", ea!(subsys = "self_tls")),
                        );
                        sleep(Duration::try_seconds(60).unwrap().to_std().unwrap()).await;
                    },
                }
            };
            let state = stored::self_tls::latest::SelfTlsState {
                pending: None,
                current: pair,
            };
            db_pool.tx({
                let state = state.clone();
                move |conn| Ok(db::api_certs_set(conn, Some(&stored::self_tls::SelfTlsState::V1(state)))?)
            }).await.context("Error storing fresh initial state")?;
            state
        },
    };

    // Set initial certs
    let latest_certs =
        Arc::new(
            RwLock::new(
                load_certified_key(
                    &state.current.pub_pem,
                    &state.current.priv_pem,
                ).context("Initial certs are invalid")?,
            ),
        );
    publish_tls_certs(&log, publisher, &identity_signer, &state).await?;
    if write_certs {
        write(persistent_dir.join("pub.pem"), state.current.pub_pem.as_bytes())
            .await
            .context("Error writing new pub.pem")?;
        write(persistent_dir.join("priv.pem"), state.current.priv_pem.as_bytes())
            .await
            .context("Error writing new priv.pem")?;
    }

    // Start refresh loop
    tm.critical_task("API - process new certs", {
        let persistent_dir = persistent_dir.to_path_buf();
        let tm = tm.clone();
        let log = log.clone();
        let publisher = publisher.clone();
        let identity_signer = identity_signer.clone();
        let latest_certs = latest_certs.clone();
        async move {
            let mut cert_stream =
                WatchStream::new(
                    request_cert_stream(&log, &tm, identity_signer.clone(), state.current.clone()).await?,
                );
            loop {
                // Wait for pending certs and swap
                if let Some((after, pair)) = state.pending.take() {
                    select!{
                        _ = sleep_until(after.to_instant()) => {
                        },
                        _ = tm.until_terminate() => {
                            return Ok(());
                        }
                    }

                    match load_certified_key(&pair.pub_pem, &pair.priv_pem) {
                        Ok(p) => {
                            spawn_blocking({
                                let latest_certs = latest_certs.clone();
                                move || {
                                    *latest_certs.write().unwrap() = p;
                                }
                            }).await.unwrap();
                        },
                        Err(e) => {
                            log.log_err(loga::WARN, e.context("New certs are invalid"));
                            return Ok(());
                        },
                    };
                    publish_tls_certs(&log, &publisher, &identity_signer, &state).await?;
                    state.current = pair;
                    write(persistent_dir.join("pub.pem"), state.current.pub_pem.as_bytes())
                        .await
                        .context("Error writing new pub.pem")?;
                    write(persistent_dir.join("priv.pem"), state.current.priv_pem.as_bytes())
                        .await
                        .context("Error writing new priv.pem")?;
                }

                // Wait for next refresh
                let new_pair = match cert_stream.next().await {
                    Some(c) => c,
                    None => {
                        return Ok(());
                    },
                };
                db_pool.tx({
                    let state = state.clone();
                    move |conn| Ok(db::api_certs_set(conn, Some(&stored::self_tls::SelfTlsState::V1(state)))?)
                }).await.context("Error storing updated state")?;
                state.pending = Some((Utc::now() + publish_ssl_ttl(), new_pair));
                publish_tls_certs(&log, &publisher, &identity_signer, &state).await?;
            }
        }
    });
    return Ok(Some(Arc::new(SimpleResolvesServerCert(latest_certs))));
}
