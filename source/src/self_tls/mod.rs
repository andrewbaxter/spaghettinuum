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
        interface::{
            stored::{
                self,
                cert::v1::X509ExtSpagh,
                self_tls::{
                    latest::{
                        CertPair,
                        RefreshTlsState,
                    },
                },
            },
            wire::{
                self,
                resolve::DNS_DOT_SUFFIX,
            },
        },
        publishing::Publisher,
        ta_res,
        utils::{
            blob::ToBlob,
            db_util::{
                self,
                DbTx,
            },
            identity_secret::IdentitySigner,
            publish_util,
            time_util::{
                ToInstant,
            },
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
    der::Encode,
    flowcontrol::shed,
    http::Uri,
    htwrap::htreq,
    loga::{
        conversion::ResultIgnore,
        ea,
        DebugDisplay,
        Log,
        ResultContext,
    },
    p256::{
        pkcs8::EncodePrivateKey,
    },
    rustls::server::ResolvesServerCert,
    std::{
        collections::HashMap,
        path::{
            Path,
        },
        str::FromStr,
        sync::{
            Arc,
            Mutex,
            RwLock,
        },
        time::{
            Duration,
            Instant,
            SystemTime,
        },
    },
    taskmanager::TaskManager,
    tokio::{
        fs::create_dir_all,
        select,
        sync::watch::{
            self,
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
    x509_cert::spki::SubjectPublicKeyInfoOwned,
};

pub mod db;

pub const CERTIFIER_URL: &'static str = "https://certipasta.isandrew.com";

pub fn publish_ssl_ttl() -> Duration {
    return Duration::from_secs(60 * 60);
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
            X509ExtSpagh {
                signature: message_signer
                    .lock()
                    .unwrap()
                    .sign(&requester_spki_der)
                    .context("Error signing SPKI der for spaghettinuum extension")?
                    .1,
            },
        )
    } else {
        None
    };
    let priv_pem = encode_priv_pem(priv_key.to_pkcs8_der().unwrap().as_bytes());
    let pub_pem;
    if options.certifier {
        let text = serde_json::to_vec(&wire::certify::latest::CertRequestParams {
            stamp: SystemTime::now().into(),
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
        let now = SystemTime::now();
        let fqdn = format!("{}{}", identity, DNS_DOT_SUFFIX);
        let pub_der =
            create_leaf_cert_der_local(
                priv_key,
                &fqdn,
                now,
                now + Duration::from_secs(60 * 60 * 24 * 90),
                sig_ext,
                &fqdn,
            ).await?;
        pub_pem = encode_pub_pem(&pub_der);
    }
    return Ok(CertPair {
        priv_pem: priv_pem,
        pub_pem: pub_pem,
    });
}

/// Produces a stream of TLS cert pairs, with a new pair some time before the
/// previous pair expires.
pub async fn stream_certs(
    log: &Log,
    tm: &TaskManager,
    signer: Arc<Mutex<dyn IdentitySigner>>,
    options: RequestCertOptions,
    initial_state: RefreshTlsState,
) -> Result<watch::Receiver<RefreshTlsState>, loga::Error> {
    let mut state = initial_state;
    let log = &log.fork(ea!(sys = "self_tls"));

    fn refresh_buffer() -> Duration {
        return Duration::from_secs(60 * 60 * 24 * 7);
    }

    fn decide_refresh_at(pub_pem: &str) -> Result<Instant, loga::Error> {
        let expiry = extract_expiry(pub_pem.as_bytes())?.to_instant();
        return Ok(expiry - refresh_buffer() - (publish_ssl_ttl() * 2));
    }

    fn decide_swap_at(pub_pem: &str) -> Result<Instant, loga::Error> {
        let expiry = extract_expiry(pub_pem.as_bytes())?.to_instant();
        return Ok(expiry - refresh_buffer());
    }

    let (certs_stream_tx, certs_stream_rx) = watch::channel(state.clone());
    tm.critical_task("API - TLS cert refresher", {
        let tm: TaskManager = tm.clone();
        let log = log.clone();
        async move {
            ta_res!(());
            loop {
                if let Some(pending) = state.pending {
                    let swap_at = decide_swap_at(&state.current.pub_pem)?;
                    log.log_with(
                        loga::DEBUG,
                        "Sleeping until time to start using pending cert",
                        ea!(deadline = swap_at.duration_since(Instant::now()).dbg_str()),
                    );
                    select!{
                        _ = tm.until_terminate() => {
                            break;
                        }
                        _ = sleep_until(swap_at.into()) =>(),
                    }
                    state.pending = None;
                    state.current = pending;
                    certs_stream_tx.send(state.clone()).ignore();
                } else {
                    let refresh_at = decide_refresh_at(&state.current.pub_pem)?;
                    log.log_with(
                        loga::DEBUG,
                        "Sleeping until cert needs refresh",
                        ea!(deadline = refresh_at.duration_since(Instant::now()).dbg_str()),
                    );
                    select!{
                        _ = tm.until_terminate() => {
                            break;
                        }
                        _ = sleep_until(refresh_at.into()) =>(),
                    }
                    let mut backoff = std::time::Duration::from_secs(30);
                    let max_tries = 5;
                    let next_certs = shed!{
                        'ok _;
                        for _ in 0 .. max_tries {
                            match request_cert(&log, signer.clone(), options).await {
                                Ok(certs) => {
                                    break 'ok Some(certs);
                                },
                                Err(e) => {
                                    log.log_err(loga::WARN, e.context("Error refreshing cert"));
                                    sleep(backoff).await;
                                    backoff = backoff * 2;
                                },
                            }
                        }
                        break 'ok None;
                    }.stack_context_with(&log, "Failed to get new cert after retrying", ea!(tries = max_tries))?;
                    state.pending = Some(next_certs);
                    certs_stream_tx.send(state.clone()).ignore();
                }
            }
            return Ok(());
        }
    });
    return Ok(certs_stream_rx);
}

pub async fn stream_persistent_certs(
    log: &Log,
    tm: &TaskManager,
    cache_dir: &Path,
    identity_signer: &Arc<Mutex<dyn IdentitySigner>>,
    options: RequestCertOptions,
) -> Result<Option<watch::Receiver<RefreshTlsState>>, loga::Error> {
    create_dir_all(cache_dir)
        .await
        .context_with("Error creating htserve cache dir", ea!(path = cache_dir.to_string_lossy()))?;
    let db_pool = db_util::setup_db(&cache_dir.join("self_tls.sqlite3"), db::migrate).await?;
    db_pool.tx(|conn| Ok(db::api_certs_setup(conn)?)).await?;

    // Prepare initial state, either restoring or getting from scratch
    let state = match db_pool.tx(|conn| Ok(db::api_certs_get(conn)?)).await? {
        Some(s) => match s {
            stored::self_tls::RefreshTlsState::V1(s) => {
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
                        sleep(Duration::from_secs(60).into()).await;
                    },
                }
            };
            let state = RefreshTlsState {
                pending: None,
                current: pair,
            };
            db_pool.tx({
                let state = state.clone();
                move |conn| Ok(db::api_certs_set(conn, Some(&stored::self_tls::RefreshTlsState::V1(state)))?)
            }).await.context("Error storing fresh initial state")?;
            state
        },
    };
    return Ok(Some(stream_certs(&log, &tm, identity_signer.clone(), options, state).await?));
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
pub async fn stream_htserve_certs(
    log: &Log,
    tm: &TaskManager,
    mut certs: WatchStream<RefreshTlsState>,
) -> Result<Option<(Arc<dyn ResolvesServerCert>, Arc<dyn rustls_21::server::ResolvesServerCert>)>, loga::Error> {
    let Some(first) = certs.next().await else {
        return Ok(None);
    };
    let latest_certs =
        Arc::new(
            SimpleResolvesServerCert(
                RwLock::new(
                    load_certified_key(
                        &first.current.pub_pem,
                        &first.current.priv_pem,
                    ).context("Initial certs are invalid")?,
                ),
            ),
        );
    let r21_latest_certs =
        Arc::new(
            Rustls21SimpleResolvesServerCert(
                RwLock::new(
                    rustls21_load_certified_key(
                        &first.current.pub_pem,
                        &first.current.priv_pem,
                    ).context("Initial certs are invalid")?,
                ),
            ),
        );
    tm.critical_task("API - Process new certs", {
        let tm = tm.clone();
        let log = log.clone();
        let latest_certs = latest_certs.clone();
        let r21_latest_certs = r21_latest_certs.clone();
        async move {
            loop {
                let Some(next) = (select!{
                    next = certs.next() => next,
                    _ = tm.until_terminate() => {
                        return Ok(());
                    }
                }) else {
                    return Ok(());
                };
                match load_certified_key(&next.current.pub_pem, &next.current.priv_pem) {
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
                match rustls21_load_certified_key(&next.current.pub_pem, &next.current.priv_pem) {
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
            }
        }
    });
    return Ok(Some((latest_certs, r21_latest_certs as Arc<dyn rustls_21::server::ResolvesServerCert>)));
}

pub async fn publish_tls_certs(
    log: &Log,
    publisher: &Arc<dyn Publisher>,
    identity_signer: &Arc<Mutex<dyn IdentitySigner>>,
    state: &RefreshTlsState,
) -> Result<(), loga::Error> {
    publisher.publish(log, identity_signer, publish_util::PublishArgs {
        set: {
            let mut m = HashMap::new();
            let mut certs = vec![state.current.pub_pem.clone()];
            if let Some(pending) = &state.pending {
                certs.push(pending.pub_pem.clone());
            }
            m.insert(
                vec![stored::record::tls_record::KEY_SUFFIX_TLS.to_string()],
                stored::record::RecordValue::V1(stored::record::latest::RecordValue {
                    ttl: publish_ssl_ttl().as_secs() / 60,
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
