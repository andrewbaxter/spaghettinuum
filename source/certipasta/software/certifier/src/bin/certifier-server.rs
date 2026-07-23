use {
    aargvark::{
        Aargvark,
        traits_impls::AargvarkJson,
    },
    async_trait::async_trait,
    certifier::{
        BuilderPubKey,
        BuilderSigner,
        CA_FQDN,
        ENV_SERVER_CONFIG,
        ServerConfig,
        VERSION_STATE_ENABLED,
        decide_sig,
        sign_duration,
    },
    http::header::CONTENT_TYPE,
    chrono::{
        DateTime,
        Duration,
        Utc,
    },
    der::{
        Decode,
        DecodePem,
    },
    flowcontrol::ta_return,
    google_cloudkms1::{
        CloudKMS,
        api::AsymmetricSignRequest,
    },
    governor::{
        Quota,
        RateLimiter,
    },
    http::{
        Response,
        StatusCode,
    },
    http_body_util::BodyExt,
    htwrap::htserve::{
        self,
        responses::{
            response_200_json,
            response_400,
            response_503,
        },
    },
    loga::{
        Log,
        ResultContext,
        ea,
    },
    spaghettinuum::interface::identity::Identity,
    spaghettinuum_native::{
        interface::{
            stored::cert::v1::X509ExtSpagh,
            wire::certify::{
                CertRequest,
                v1::CertResponse,
            },
        },
        utils::{
            time_util::UtcSecs,
            tls_util::{
                create_leaf_cert_der,
                encode_pub_pem,
            },
        },
    },
    std::{
        net::{
            IpAddr,
            Ipv4Addr,
            SocketAddr,
            SocketAddrV4,
        },
        num::NonZeroU32,
        sync::Arc,
        time::SystemTime,
    },
    x509_cert::spki::SubjectPublicKeyInfoOwned,
    yup_oauth2::{
        ApplicationDefaultCredentialsAuthenticator,
        ApplicationDefaultCredentialsFlowOpts,
        authenticator::ApplicationDefaultCredentialsTypes,
    },
};

async fn generate_cert(
    now: DateTime<Utc>,
    identity: &Identity,
    spki_der: &[u8],
    signature_ext: Option<X509ExtSpagh>,
    kms_key_gcpid: &str,
    kms_client: &CloudKMS<yup_oauth2::hyper_rustls::HttpsConnector<yup_oauth2::hyper::client::HttpConnector>>,
) -> Result<CertResponse, loga::Error> {
    let log = &Log::new().fork(ea!(id = identity.to_string()));
    let requester_keyinfo =
        SubjectPublicKeyInfoOwned::from_der(spki_der).stack_context(log, "Unable to parse SPKI DER")?;
    let (_, ca_keylist) =
        kms_client
            .projects()
            .locations_key_rings_crypto_keys_crypto_key_versions_list(kms_key_gcpid)
            .filter(&format!("state={}", VERSION_STATE_ENABLED))
            .page_size(2)
            .doit()
            .await
            .stack_context(log, "Failed to get keys info")?;
    let mut ca_keylist =
        ca_keylist
            .crypto_key_versions
            .stack_context(log, "Missing items in crypto key version list response")?
            .into_iter()
            .filter_map(|k| match (k.create_time, k.name) {
                (Some(t), Some(n)) => Some((t, n)),
                _ => None,
            })
            .collect::<Vec<_>>();
    ca_keylist.sort_by_cached_key(|k| k.0);
    let ca_current_privkey_full_id =
        ca_keylist
            .pop()
            .stack_context(
                log,
                "No primary key set in keys, can't sign (keys missing critical fields in response may have been filtered)",
            )?
            .1;
    let (_, ca_pubkey) =
        kms_client
            .projects()
            .locations_key_rings_crypto_keys_crypto_key_versions_get_public_key(&ca_current_privkey_full_id)
            .doit()
            .await
            .stack_context(log, "Failed to get public key")?;
    let ca_keyinfo = SubjectPublicKeyInfoOwned::from_pem(&ca_pubkey.pem.unwrap()).unwrap();
    let (sig_digest_fn, sig_algorithm) = decide_sig(&ca_keyinfo)?;
    let pub_der =
        create_leaf_cert_der(
            requester_keyinfo,
            &format!("{}.s", identity.to_string()),
            signature_ext,
            now.into(),
            (now + sign_duration()).into(),
            BuilderSigner {
                key: BuilderPubKey(ca_keyinfo.clone()),
                alg: sig_algorithm,
            },
            move |csr_der| async move {
                return Ok(
                    kms_client
                        .projects()
                        .locations_key_rings_crypto_keys_crypto_key_versions_asymmetric_sign(AsymmetricSignRequest {
                            digest: Some(sig_digest_fn(&csr_der)),
                            ..Default::default()
                        }, &ca_current_privkey_full_id)
                        .doit()
                        .await
                        .stack_context(log, "Error signing new CA cert CSR")?
                        .1
                        .signature
                        .stack_context(log, "Signing request response missing signature data")?,
                )
            },
            CA_FQDN,
        ).await?;
    return Ok(CertResponse { pub_pem: encode_pub_pem(&pub_der) });
}

#[derive(Aargvark)]
struct Args {
    pub config: Option<AargvarkJson<ServerConfig>>,
}

#[tokio::main]
async fn main() {
    async fn inner() -> Result<(), loga::Error> {
        let args = aargvark::vark::<Args>();
        let log = loga::Log::new_root(loga::INFO);
        let config = if let Some(p) = args.config {
            p.value
        } else if let Some(c) = match std::env::var(ENV_SERVER_CONFIG) {
            Ok(c) => Some(c),
            Err(e) => match e {
                std::env::VarError::NotPresent => None,
                std::env::VarError::NotUnicode(_) => {
                    return Err(loga::err_with("Error parsing env var as unicode", ea!(env = ENV_SERVER_CONFIG)))
                },
            },
        } {
            let log = log.fork(ea!(source = "env"));
            serde_json::from_str::<ServerConfig>(&c).stack_context(&log, "Parsing config")?
        } else {
            return Err(
                log.err_with(
                    "No config passed on command line, and no config set in env var",
                    ea!(env = ENV_SERVER_CONFIG),
                ),
            );
        };
        let tm = taskmanager::TaskManager::new();
        {
            let hyper_client =
                yup_oauth2
                ::hyper
                ::Client
                ::builder().build(
                    yup_oauth2::hyper_rustls::HttpsConnectorBuilder::new()
                        .with_webpki_roots()
                        .https_or_http()
                        .enable_http1()
                        .build(),
                );
            let kms_client =
                CloudKMS::new(
                    hyper_client.clone(),
                    match ApplicationDefaultCredentialsAuthenticator::with_client(
                        ApplicationDefaultCredentialsFlowOpts::default(),
                        hyper_client,
                    ).await {
                        ApplicationDefaultCredentialsTypes::InstanceMetadata(auth) => auth
                            .build()
                            .await
                            .expect("Unable to create instance metadata authenticator"),
                        ApplicationDefaultCredentialsTypes::ServiceAccount(auth) => auth
                            .build()
                            .await
                            .expect("Unable to create service account authenticator"),
                    },
                );

            struct State {
                log: Log,
                kms_key_gcpid: String,
                cert_bucket: String,
                log_bucket: String,
                kms_client: CloudKMS<
                    yup_oauth2::hyper_rustls::HttpsConnector<yup_oauth2::hyper::client::HttpConnector>,
                >,
                ip_limit: RateLimiter<
                    IpAddr,
                    governor::state::keyed::DefaultKeyedStateStore<IpAddr>,
                    governor::clock::DefaultClock,
                >,
                ident_limit: RateLimiter<
                    Identity,
                    governor::state::keyed::DefaultKeyedStateStore<Identity>,
                    governor::clock::DefaultClock,
                >,
            }

            #[async_trait]
            impl htserve::handler::Handler<htserve::responses::Body> for State {
                async fn handle(
                    &self,
                    args: htserve::handler::HandlerArgs<'_>,
                ) -> Response<htserve::responses::Body> {
                    match async {
                        ta_return!(Response < htserve:: responses:: Body >, loga::Error);
                        if args.head.method == http::Method::GET {
                            let html = format!(
                                concat!(
                                    "<!DOCTYPE html>\n",
                                    "<html>\n",
                                    "<head><title>Certipasta</title>",
                                    "<style>body{{font-family:sans-serif;max-width:800px;margin:40px auto;padding:0 20px}}</style>",
                                    "</head>\n",
                                    "<body>\n",
                                    "<h1>Certipasta</h1>\n",
                                    "<p>TLS certificate authority for Spaghettinuum <code>.s</code> domains. ",
                                    "See the <a href=\"https://github.com/andrewbaxter/certipasta\">GitHub repository</a> for details.</p>\n",
                                    "<h2>Root Certificate Bundle</h2>\n",
                                    "<p>Download and install to trust certipasta-issued certificates:</p>\n",
                                    "<p><a href=\"https://storage.googleapis.com/{cert_bucket}/spaghettinuum_s.crt\">spaghettinuum_s.crt</a></p>\n",
                                    "<h2>Certificate Rotation Logs</h2>\n",
                                    "<p>Logs from annual certificate rotation runs:</p>\n",
                                    "<p><a href=\"https://storage.googleapis.com/storage/v1/b/{log_bucket}/o\">Browse rotation logs (JSON)</a></p>\n",
                                    "</body>\n",
                                    "</html>\n",
                                ),
                                cert_bucket = self.cert_bucket,
                                log_bucket = self.log_bucket,
                            );
                            return Ok(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .header(CONTENT_TYPE, "text/html; charset=utf-8")
                                    .body(htserve::responses::body_full(html.into_bytes()))
                                    .unwrap(),
                            );
                        }
                        let body =
                            match serde_json::from_slice::<CertRequest>(&args.body.collect().await?.to_bytes()) {
                                Ok(b) => b,
                                Err(e) => {
                                    return Ok(response_400(e));
                                },
                            };
                        if self.ip_limit.check_key(&args.peer_addr.ip()).is_err() {
                            return Ok(
                                Response::builder()
                                    .status(StatusCode::TOO_MANY_REQUESTS)
                                    .body(
                                        htserve::responses::body_full(
                                            "Per-ip request rate too high".to_string().into_bytes(),
                                        ),
                                    )
                                    .unwrap(),
                            );
                        }
                        let now = Utc::now();
                        match body {
                            CertRequest::V1(req) => {
                                let identity = req.public_key_root.identity();
                                let Ok(req_params) =
                                    req.params.verify(&identity, &req.public_key_root, &req.public_key_chain) else {
                                    return Ok(response_400("Invalid signature by identity"));
                                };
                                let stamp = <UtcSecs as Into<SystemTime>>::into(req_params.stamp);
                                let stamp = <SystemTime as Into<DateTime<Utc>>>::into(stamp);
                                if now.signed_duration_since(stamp) > Duration::seconds(60) {
                                    return Ok(response_400("Request arrived long after timestamp"));
                                }
                                if self.ident_limit.check_key(&identity).is_err() {
                                    return Ok(
                                        Response::builder()
                                            .status(StatusCode::TOO_MANY_REQUESTS)
                                            .body(
                                                htserve::responses::body_full(
                                                    "Per-identity request rate too high".to_string().into_bytes(),
                                                ),
                                            )
                                            .unwrap(),
                                    );
                                }
                                return Ok(
                                    response_200_json(
                                        &generate_cert(
                                            now,
                                            &identity,
                                            &req_params.spki_der.0,
                                            req_params.sig_ext,
                                            &self.kms_key_gcpid,
                                            &self.kms_client,
                                        ).await?,
                                    ),
                                );
                            },
                        }
                    }.await {
                        Ok(r) => return r,
                        Err(e) => {
                            self.log.log_err(loga::WARN, e.context("Error processing cert request"));
                            return response_503();
                        },
                    }
                }
            }

            let state = Arc::new(State {
                log: log.fork(ea!(sys = "http")),
                kms_key_gcpid: config.key_gcpid,
                cert_bucket: config.cert_bucket,
                log_bucket: config.log_bucket,
                kms_client: kms_client,
                ip_limit: RateLimiter::keyed(
                    Quota::with_period(Duration::hours(24).to_std().unwrap())
                        .unwrap()
                        .allow_burst(NonZeroU32::new(10).unwrap()),
                ),
                ident_limit: RateLimiter::keyed(
                    Quota::with_period(Duration::hours(24).to_std().unwrap())
                        .unwrap()
                        .allow_burst(NonZeroU32::new(10).unwrap()),
                ),
            });
            let bind_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 80));
            let log = log.clone();
            tm.critical_stream(
                format!("API - Server ({})", bind_addr),
                tokio_stream::wrappers::TcpListenerStream::new(
                    tokio::net::TcpListener::bind(&bind_addr).await.stack_context(&log, "Error binding to address")?,
                ),
                move |stream| {
                    let log = log.clone();
                    let state = state.clone();
                    async move {
                        match async {
                            ta_return!((), loga::Error);
                            htserve::handler::root_handle_http(&log, state, stream?).await?;
                            return Ok(());
                        }.await {
                            Ok(_) => (),
                            Err(e) => {
                                log.log_err(loga::DEBUG, e.context("Error serving request"));
                            },
                        }
                        return Ok(());
                    }
                },
            );
        }
        tm.join(&log).await?;
        return Ok(());
    }

    match inner().await {
        Ok(_) => { },
        Err(e) => {
            loga::fatal(e);
        },
    }
}
