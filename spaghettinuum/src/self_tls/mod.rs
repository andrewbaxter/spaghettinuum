//! Methods for obtaining a `.s` TLS cert. Certs can be authenticated in three ways:
//!
//! * Out of band, in a separate spaghettinuum record published alongside address
//!   records
//!
//!   This is most flexible, and can be revoked within the time of the TTL of the
//!   record by publishing a new record, but requires a secured connection to a
//!   resolver (i.e. can't be done for the resolver API itself). This requires client
//!   support.
//!
//!   Any cert, with any signature (self signed, etc) can be used since any cert
//!   published in a record is treated as valid.
//!
//! * Signed by the `certipasta` `.s` CA, with the CA cert installed on the local system
//!
//!   This is centralized but doesn't require client support as long as the CA cert is
//!   installed (which is a common procedure).
//!
//! * With a spaghettinuum extension signing the cert SPKI with the identity
//!
//!   This is also decentralized, and validation can be done without resolver access,
//!   but revocation is more difficult. This is used for resolvers, whose own
//!   identities are not important and can be discarded/replaced if compromised. This
//!   requires client support.
use {
    crate::{
        bb,
        interface::{
            stored::{
                self,
                self_tls::latest::CertPair,
            },
            wire::{
                self,
                api::publish::v1::PublishRequestContent,
            },
        },
        publishing::Publisher,
        ta_res,
        utils::{
            blob::{
                ToBlob,
            },
            db_util::{
                self,
                DbTx,
            },
            fs_util::write,
            identity_secret::IdentitySigner,
            time_util::ToInstant,
            tls_util::{
                create_leaf_cert_der_local,
                encode_priv_pem,
                encode_pub_pem,
                extract_expiry,
                load_certified_key,
                rustls21_load_certified_key,
            },
        },
    },
    chrono::{
        DateTime,
        Duration,
        Utc,
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
    rustls::server::ResolvesServerCert,
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
        spki::SubjectPublicKeyInfoOwned,
    },
};

pub mod db;

pub const CERTIFIER_URL: &'static str = "https://certipasta.isandrew.com";

pub fn publish_ssl_ttl() -> Duration {
    return Duration::try_minutes(60).unwrap();
}

#[derive(Clone, Copy)]
pub struct RequestCertOptions {
    /// Get a certificate signed by the `certipasta` CA cert.
    pub certifier: bool,
    /// Add the spaghettinuum identity signature extension to the cert.
    pub signature: bool,
}

/// Requests a TLS public cert from the certifier for the `.s` domain associated
/// with the provided identity and returns the result as PEM. This function
/// generates a new private/public key pair for the cert.
pub async fn request_cert(
    log: &Log,
    message_signer: Arc<Mutex<dyn IdentitySigner>>,
    options: RequestCertOptions,
) -> Result<CertPair, loga::Error> {
    let priv_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
    let requester_spki_der =
        SubjectPublicKeyInfoOwned::from_key(priv_key.verifying_key().clone()).unwrap().to_der().unwrap().blob();
    let sig_ext = if options.signature {
        Some(
            message_signer
                .lock()
                .unwrap()
                .sign(&requester_spki_der)
                .context("Error signing SPKI der for spaghettinuum extension")?
                .1,
        )
    } else {
        None
    };
    let priv_pem = encode_priv_pem(priv_key.to_pkcs8_der().unwrap().as_bytes());
    let pub_pem;
    if options.certifier {
        let text = serde_json::to_vec(&wire::certify::latest::CertRequestParams {
            stamp: Utc::now(),
            sig_ext: sig_ext,
            spki_der: requester_spki_der,
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
        let resp =
            serde_json::from_slice::<wire::certify::latest::CertResponse>(
                &body,
            ).context("Error parsing cert request response body as json")?;
        pub_pem = resp.pub_pem;
        log.log_with(loga::DEBUG, "Received cert", ea!(pub_pem = pub_pem));
    } else {
        let identity = message_signer.lock().unwrap().identity()?;
        let now = Utc::now();
        let fqdn = format!("{}.s", identity);
        let pub_der =
            create_leaf_cert_der_local(priv_key, &fqdn, now, now + Duration::days(90), sig_ext, &fqdn).await?;
        pub_pem = encode_pub_pem(&pub_der);
    }
    return Ok(CertPair {
        priv_pem: priv_pem,
        pub_pem: pub_pem,
    });
}

/// Produces a stream of TLS cert pairs, with a new pair some time before the
/// previous pair expires.
pub async fn request_cert_stream(
    log: &Log,
    tm: &TaskManager,
    signer: Arc<Mutex<dyn IdentitySigner>>,
    options: RequestCertOptions,
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
                        match request_cert(log, signer.clone(), options).await {
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

pub struct SimpleResolvesServerCert(RwLock<Arc<rustls::sign::CertifiedKey>>);

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

pub struct Rustls21SimpleResolvesServerCert(RwLock<Arc<rustls_21::sign::CertifiedKey>>);

impl std::fmt::Debug for Rustls21SimpleResolvesServerCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return self.0.read().unwrap().cert.fmt(f);
    }
}

impl rustls_21::server::ResolvesServerCert for Rustls21SimpleResolvesServerCert {
    fn resolve(&self, _client_hello: rustls_21::server::ClientHello) -> Option<Arc<rustls_21::sign::CertifiedKey>> {
        return Some(self.0.read().unwrap().clone());
    }
}

/// Produce a rustls-compatible server cert resolver with an automatically updated
/// cert.  This is a managed task that maintains state using a database at the
/// provided location.
///
/// Returns `None` if the task manager is shut down before initial setup completes.
pub async fn htserve_certs(
    log: &Log,
    cache_dir: &Path,
    write_certs: bool,
    tm: &TaskManager,
    publisher: &Arc<dyn Publisher>,
    identity_signer: &Arc<Mutex<dyn IdentitySigner>>,
    options: RequestCertOptions,
) -> Result<Option<(Arc<dyn ResolvesServerCert>, Arc<dyn rustls_21::server::ResolvesServerCert>)>, loga::Error> {
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

    let db_pool = db_util::setup_db(&cache_dir.join("self_tls.sqlite3"), db::migrate).await?;
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
                    c = request_cert(&log, identity_signer.clone(), options) => c,
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
            SimpleResolvesServerCert(
                RwLock::new(
                    load_certified_key(
                        &state.current.pub_pem,
                        &state.current.priv_pem,
                    ).context("Initial certs are invalid")?,
                ),
            ),
        );
    let r21_latest_certs =
        Arc::new(
            Rustls21SimpleResolvesServerCert(
                RwLock::new(
                    rustls21_load_certified_key(
                        &state.current.pub_pem,
                        &state.current.priv_pem,
                    ).context("Initial certs are invalid")?,
                ),
            ),
        );
    publish_tls_certs(&log, publisher, &identity_signer, &state).await?;
    if write_certs {
        write(cache_dir.join("pub.pem"), state.current.pub_pem.as_bytes())
            .await
            .context("Error writing new pub.pem")?;
        write(cache_dir.join("priv.pem"), state.current.priv_pem.as_bytes())
            .await
            .context("Error writing new priv.pem")?;
    }

    // Start refresh loop
    tm.critical_task("API - process new certs", {
        let persistent_dir = cache_dir.to_path_buf();
        let tm = tm.clone();
        let log = log.clone();
        let publisher = publisher.clone();
        let identity_signer = identity_signer.clone();
        let latest_certs = latest_certs.clone();
        let r21_latest_certs = r21_latest_certs.clone();
        async move {
            let mut cert_stream =
                WatchStream::new(
                    request_cert_stream(&log, &tm, identity_signer.clone(), options, state.current.clone()).await?,
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
                                    *latest_certs.0.write().unwrap() = p;
                                }
                            }).await.unwrap();
                        },
                        Err(e) => {
                            log.log_err(loga::WARN, e.context("New certs are invalid"));
                            return Ok(());
                        },
                    };
                    match rustls21_load_certified_key(&pair.pub_pem, &pair.priv_pem) {
                        Ok(p) => {
                            spawn_blocking({
                                let latest_certs = r21_latest_certs.clone();
                                move || {
                                    *latest_certs.0.write().unwrap() = p;
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
    return Ok(Some((latest_certs, r21_latest_certs as Arc<dyn rustls_21::server::ResolvesServerCert>)));
}
