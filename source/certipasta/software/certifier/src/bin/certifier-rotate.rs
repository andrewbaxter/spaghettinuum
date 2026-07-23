use {
    aargvark::{
        Aargvark,
        traits_impls::AargvarkJson,
    },
    certifier::{
        decide_sig,
        rotation_buffer,
        rotation_period,
        sign_duration,
        BuilderPubKey,
        BuilderSigner,
        RotateConfig,
        CA_FQDN,
        ENV_ROTATE_CONFIG,
        VERSION_STATE_DESTROYED,
        VERSION_STATE_DESTROY_SCHEDULED,
        VERSION_STATE_DISABLED,
        VERSION_STATE_ENABLED,
    },
    chrono::{
        DateTime,
        Duration,
        Utc,
    },
    der::{
        DecodePem,
        EncodePem,
    },
    google_cloudkms1::{
        api::{
            AsymmetricSignRequest,
            CryptoKeyVersion,
            DestroyCryptoKeyVersionRequest,
        },
        CloudKMS,
        FieldMask,
    },
    google_storage1::{
        api::Object,
        Storage,
    },
    loga::{
        ea,
        DebugDisplay,
        ErrContext,
        Log,
        ResultContext,
    },
    mime::Mime,
    spaghettinuum_native::utils::tls_util::{
        rand_serial,
        to_x509_time,
    },
    std::{
        cell::RefCell,
        collections::{
            HashMap,
            HashSet,
        },
        io::Cursor,
        rc::Rc,
        str::FromStr,
    },
    tokio::time::sleep,
    x509_cert::{
        builder::{
            Builder,
            CertificateBuilder,
            Profile,
        },
        der::asn1::{
            BitString,
            Ia5String,
        },
        ext::pkix::{
            constraints::name::GeneralSubtree,
            name::GeneralName,
            NameConstraints,
        },
        spki::SubjectPublicKeyInfoOwned,
    },
    yup_oauth2::{
        authenticator::ApplicationDefaultCredentialsTypes,
        ApplicationDefaultCredentialsAuthenticator,
        ApplicationDefaultCredentialsFlowOpts,
    },
};

#[derive(Aargvark)]
struct Args {
    pub config: Option<AargvarkJson<RotateConfig>>,
}

const TAG_ISSUE_START: &'static str = "start";
const TAG_ISSUE_END: &'static str = "end";
const BUCKET_PREFIX_VERSION: &'static str = "generations";

fn get_ver_short_id(full_id: &str) -> Result<String, loga::Error> {
    return Ok(
        full_id
            .rsplit_once("/")
            .map(|(_, r)| r.to_string())
            .context_with("Error parsing id from version full id", ea!(id = full_id))?,
    );
}

struct ViewObject_ {
    object_key: String,
    version_short_id: String,
    create_time: DateTime<Utc>,
    issue_start: Option<DateTime<Utc>>,
    issue_end: Option<DateTime<Utc>>,
}

#[derive(Clone)]
struct ViewObject(Rc<RefCell<ViewObject_>>);

struct ViewVersion_ {
    full_id: String,
    short_id: String,
}

#[derive(Clone)]
struct ViewVersion(Rc<RefCell<ViewVersion_>>);

struct View {
    objects: Vec<ViewObject>,
    versions: HashMap<String, ViewVersion>,
}

async fn generate_version(
    log: &Log,
    kms_client: &CloudKMS<yup_oauth2::hyper_rustls::HttpsConnector<yup_oauth2::hyper::client::HttpConnector>>,
    storage_client: &Storage<yup_oauth2::hyper_rustls::HttpsConnector<yup_oauth2::hyper::client::HttpConnector>>,
    key_gcpid: &str,
    bucket_gcpid: &str,
    view: &mut View,
) -> Result<ViewObject, loga::Error> {
    let now = Utc::now();

    // Generate new keypair version + get public key
    let (_, version) = kms_client.projects().locations_key_rings_crypto_keys_crypto_key_versions_create(CryptoKeyVersion {
        state: Some(VERSION_STATE_DISABLED.to_string()),
        ..Default::default()
    }, key_gcpid).doit().await.stack_context(log, "Error rotating key")?;
    let ver_full_id = version.name.unwrap();
    let ver_short_id = get_ver_short_id(&ver_full_id)?;
    let (_, ca_pubkey) =
        kms_client
            .projects()
            .locations_key_rings_crypto_keys_crypto_key_versions_get_public_key(&ver_full_id)
            .doit()
            .await
            .stack_context(log, "Failed to get new public key")?;

    // Build CA cert
    let ca_keyinfo = SubjectPublicKeyInfoOwned::from_pem(&ca_pubkey.pem.unwrap()).unwrap();
    let (sig_digest_fn, sig_algorithm) = decide_sig(&ca_keyinfo)?;
    let ca_signer = BuilderSigner {
        key: BuilderPubKey(ca_keyinfo.clone()),
        alg: sig_algorithm,
    };
    let mut cert_builder = CertificateBuilder::new(
        Profile::Root,
        // Timestamp, 1h granularity (don't publish two issued within an hour/don't issue
        // two within an hour)
        rand_serial(),
        x509_cert::time::Validity {
            not_before: to_x509_time((now - Duration::hours(24)).into()),
            not_after: to_x509_time((now + rotation_period() * 2 + rotation_buffer() + sign_duration()).into()),
        },
        x509_cert::name::RdnSequence::from_str(&format!("CN={}", CA_FQDN)).unwrap(),
        ca_keyinfo.clone(),
        &ca_signer,
    ).unwrap();
    cert_builder.add_extension(&NameConstraints {
        permitted_subtrees: Some(vec![GeneralSubtree {
            base: GeneralName::DnsName(Ia5String::new(".s").unwrap()),
            minimum: 0,
            maximum: None,
        }]),
        excluded_subtrees: None,
    }).unwrap();
    let cert_csr_der = cert_builder.finalize().unwrap();
    let signature =
        kms_client
            .projects()
            .locations_key_rings_crypto_keys_crypto_key_versions_asymmetric_sign(AsymmetricSignRequest {
                digest: Some(sig_digest_fn(&cert_csr_der)),
                ..Default::default()
            }, &ver_full_id)
            .doit()
            .await
            .stack_context(log, "Error signing new CA cert CSR")?
            .1
            .signature
            .stack_context(log, "Signing request response missing signature data")?;
    let cert_pem =
        cert_builder
            .assemble(BitString::from_bytes(&signature).stack_context(log, "Error building signature bitstring")?)
            .stack_context(log, "Error assembling cert")?
            .to_pem(der::pem::LineEnding::LF)
            .stack_context(log, "Error building PEM for cert")?;

    // Log and store
    let object_key = format!("{}/{}", BUCKET_PREFIX_VERSION, ver_short_id);
    storage_client
        .objects()
        .insert(Object {
            name: Some(object_key.clone()),
            ..Default::default()
        }, &bucket_gcpid)
        .upload_resumable(Cursor::new(cert_pem.as_bytes()), Mime::from_str("application/x-pem-file").unwrap())
        .await
        .stack_context_with(log, "Error uploading new cert", ea!(bucket = bucket_gcpid, object = object_key))?;
    eprintln!("\nNew root cert is:\n{}", cert_pem);

    // Update view + return
    let version = ViewVersion(Rc::new(RefCell::new(ViewVersion_ {
        full_id: ver_full_id,
        short_id: ver_short_id.clone(),
    })));
    let object = ViewObject(Rc::new(RefCell::new(ViewObject_ {
        object_key: object_key,
        version_short_id: ver_short_id.clone(),
        create_time: now,
        issue_start: None,
        issue_end: None,
    })));
    view.versions.insert(ver_short_id, version);
    view.objects.push(object.clone());
    return Ok(object);
}

#[tokio::main]
async fn main() {
    async fn inner() -> Result<(), loga::Error> {
        let args = aargvark::vark::<Args>();
        let log = Log::new_root(loga::INFO);
        let log = &log;
        let config = if let Some(p) = args.config {
            p.value
        } else if let Some(c) = match std::env::var(ENV_ROTATE_CONFIG) {
            Ok(c) => Some(c),
            Err(e) => match e {
                std::env::VarError::NotPresent => None,
                std::env::VarError::NotUnicode(_) => {
                    return Err(loga::err_with("Error parsing env var as unicode", ea!(env = ENV_ROTATE_CONFIG)))
                },
            },
        } {
            let log = log.fork(ea!(source = "env"));
            serde_json::from_str::<RotateConfig>(&c).stack_context(&log, "Parsing config")?
        } else {
            return Err(
                log.err_with(
                    "No config passed on command line, and no config set in env var",
                    ea!(env = ENV_ROTATE_CONFIG),
                ),
            );
        };
        let hc =
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
        let auth =
            match ApplicationDefaultCredentialsAuthenticator::with_client(
                ApplicationDefaultCredentialsFlowOpts::default(),
                hc.clone(),
            ).await {
                ApplicationDefaultCredentialsTypes::InstanceMetadata(auth) => auth
                    .build()
                    .await
                    .expect("Unable to create instance metadata authenticator"),
                ApplicationDefaultCredentialsTypes::ServiceAccount(auth) => auth
                    .build()
                    .await
                    .expect("Unable to create service account authenticator"),
            };
        let kms_client = CloudKMS::new(hc.clone(), auth.clone());
        let storage_client = Storage::new(hc, auth);

        // # 1. Gather all obj + version info
        let mut view = View {
            objects: vec![],
            versions: HashMap::new(),
        };
        {
            let mut after = <Option<String>>::None;
            loop {
                let mut req = storage_client.objects().list(&config.bucket);
                if let Some(after) = after {
                    req = req.page_token(&after);
                }
                let (_, page) = req.doit().await.stack_context(log, "Failed to retrieve cert bucket page")?;
                let Some(new_objects) = page.items else {
                    break;
                };
                for v in new_objects {
                    let Some(object_key) = v.name else {
                        log.log(loga::WARN, "Received obj missing name/id! Skipping...");
                        continue;
                    };
                    let Some(version_short_id) =
                        object_key
                            .strip_suffix("/")
                            .unwrap_or(&object_key)
                            .strip_prefix(&format!("{}/", BUCKET_PREFIX_VERSION)) else {
                            continue;
                        };
                    let metadata = v.metadata.unwrap_or_default();
                    let create_time =
                        v.time_created.stack_context(log, "Missing created time for object from gcp api")?;
                    let issue_start = match metadata.get(TAG_ISSUE_START) {
                        Some(tag_value) => {
                            match DateTime::parse_from_rfc3339(tag_value.as_str()) {
                                Ok(stamp) => Some(<DateTime<Utc>>::from(stamp)),
                                Err(e) => {
                                    log.log_err(
                                        loga::WARN,
                                        e.context_with("Error parsing tag", ea!(tag = TAG_ISSUE_START)),
                                    );
                                    continue;
                                },
                            }
                        },
                        None => {
                            None
                        },
                    };
                    let issue_end = match metadata.get(TAG_ISSUE_END) {
                        Some(tag_value) => {
                            match DateTime::parse_from_rfc3339(tag_value.as_str()) {
                                Ok(stamp) => Some(<DateTime<Utc>>::from(stamp)),
                                Err(e) => {
                                    log.log_err(
                                        loga::WARN,
                                        e.context_with("Error parsing tag", ea!(tag = TAG_ISSUE_END)),
                                    );
                                    continue;
                                },
                            }
                        },
                        None => {
                            None
                        },
                    };
                    log.log_with(
                        loga::INFO,
                        "Surveying, found cert",
                        ea!(id = object_key, issue_start = issue_start.dbg_str(), issue_end = issue_end.dbg_str()),
                    );
                    view.objects.push(ViewObject(Rc::new(RefCell::new(ViewObject_ {
                        object_key: object_key.clone(),
                        version_short_id: version_short_id.to_string(),
                        create_time: create_time,
                        issue_start: issue_start,
                        issue_end: issue_end,
                    }))));
                }
                after = page.next_page_token.map(|x| x.to_string());
                if after.is_none() {
                    break;
                }
            }
        }
        view.objects.sort_by_cached_key(|e| e.0.borrow().create_time);
        {
            let mut after = <Option<String>>::None;
            loop {
                let mut req =
                    kms_client
                        .projects()
                        .locations_key_rings_crypto_keys_crypto_key_versions_list(&config.key_gcpid);
                if let Some(after) = after {
                    req = req.page_token(&after);
                }
                let (_, page) =
                    req.doit().await.stack_context(log, "Failed to retrieve key versions to update to semi-latest")?;
                let Some(new_versions) = page.crypto_key_versions else {
                    break;
                };
                for v in new_versions {
                    let Some(state) = v.state else {
                        log.log(loga::WARN, "Received version missing state! Skipping...");
                        continue;
                    };
                    if state == VERSION_STATE_DESTROY_SCHEDULED || state == VERSION_STATE_DESTROYED {
                        continue;
                    }
                    let Some(full_id) = v.name else {
                        log.log(loga::WARN, "Received version missing name/id! Skipping...");
                        continue;
                    };
                    let short_id = get_ver_short_id(&full_id)?;
                    log.log_with(loga::INFO, "Surveying, found key version", ea!(id = short_id, state = state));
                    view.versions.insert(short_id.clone(), ViewVersion(Rc::new(RefCell::new(ViewVersion_ {
                        full_id: full_id,
                        short_id: short_id,
                    }))));
                }
                after = page.next_page_token.map(|x| x.to_string());
                if after.is_none() {
                    break;
                }
            }
        }

        // # Decide/identiy new active, pending, and old active objects
        let mut old_current = None;
        let mut current = None;
        let mut next = None;
        {
            let mut offset = 0usize;
            for (i, o) in view.objects.iter().enumerate() {
                let o1 = o.0.borrow();
                if o1.issue_start.is_some() && o1.issue_end.is_none() &&
                    view.versions.contains_key(&o1.version_short_id) {
                    old_current = Some(o.clone());
                    log.log_with(loga::INFO, "Selected old current key version", ea!(id = o1.version_short_id));
                    offset = i + 1;
                    break;
                }
            }
            for o in view.objects.iter().skip(offset) {
                offset += 1;
                let o1 = o.0.borrow();
                if o1.issue_start.is_none() && o1.issue_end.is_none() &&
                    view.versions.contains_key(&o1.version_short_id) {
                    log.log_with(loga::INFO, "Selected current key version", ea!(id = o1.version_short_id));
                    current = Some(o.clone());
                    break;
                }
            }
            for o in view.objects.iter().skip(offset) {
                let o1 = o.0.borrow();
                if !o1.issue_start.is_some() && !o1.issue_end.is_some() &&
                    view.versions.contains_key(&o1.version_short_id) {
                    log.log_with(loga::INFO, "Selected next key version", ea!(id = o1.version_short_id));
                    next = Some(o.clone());
                    break;
                }
            }
        }

        // # Ensure a current version, enable the key and mark it as having started use
        let current = match current {
            None => {
                log.log(loga::INFO, "No available current key version, creating");
                generate_version(
                    log,
                    &kms_client,
                    &storage_client,
                    &config.key_gcpid,
                    &config.bucket,
                    &mut view,
                ).await?
            },
            Some(current) => {
                if next.is_none() {
                    log.log(loga::INFO, "No available next key version, creating");
                    generate_version(
                        log,
                        &kms_client,
                        &storage_client,
                        &config.key_gcpid,
                        &config.bucket,
                        &mut view,
                    ).await?;
                }
                current
            },
        };
        log.log_with(
            loga::INFO,
            "Activating selected current key version",
            ea!(id = current.0.borrow().version_short_id),
        );
        kms_client
            .projects()
            .locations_key_rings_crypto_keys_crypto_key_versions_patch(CryptoKeyVersion {
                state: Some(VERSION_STATE_ENABLED.to_string()),
                ..Default::default()
            }, &view.versions[&current.0.borrow().version_short_id].0.borrow().full_id)
            .update_mask(FieldMask::new(&["state"]))
            .doit()
            .await
            .stack_context(log, "Error disabling old current key version")?;
        storage_client
            .objects()
            .update(Object {
                metadata: Some({
                    let mut new_tags = HashMap::new();
                    new_tags.insert(TAG_ISSUE_START.to_string(), Utc::now().to_rfc3339());
                    new_tags
                }),
                ..Default::default()
            }, &config.bucket, &urlencoding::encode(&current.0.borrow().object_key))
            .doit()
            .await
            .stack_context_with(
                log,
                "Failed to set new current version issue start tag",
                ea!(object = current.0.borrow().object_key),
            )?;

        // # Disable the old current
        //
        // Wait for transactions with the old current key to finish...
        if let Some(old_current) = old_current {
            log.log_with(
                loga::INFO,
                "Waiting for a fixed period to allow outstanding requests to finish before deactivating old current version",
                ea!(id = old_current.0.borrow().version_short_id),
            );
            sleep(Duration::minutes(1).to_std().unwrap()).await;
            kms_client
                .projects()
                .locations_key_rings_crypto_keys_crypto_key_versions_patch(CryptoKeyVersion {
                    state: Some(VERSION_STATE_DISABLED.to_string()),
                    ..Default::default()
                }, &view.versions[&old_current.0.borrow().version_short_id].0.borrow().full_id)
                .update_mask(FieldMask::new(&["state"]))
                .doit()
                .await
                .stack_context(log, "Error disabling old current key version")?;
            let end_time = Utc::now();
            storage_client
                .objects()
                .update(Object {
                    metadata: Some({
                        let mut new_tags = HashMap::new();
                        new_tags.insert(TAG_ISSUE_END.to_string(), end_time.to_rfc3339());
                        new_tags
                    }),
                    ..Default::default()
                }, &config.bucket, &urlencoding::encode(&old_current.0.borrow().object_key))
                .doit()
                .await
                .stack_context_with(
                    log,
                    "Failed to set old current version issue end tag",
                    ea!(object = old_current.0.borrow().object_key),
                )?;
            old_current.0.borrow_mut().issue_end = Some(end_time);
        }

        // # Clean up objects and versions
        let epoch = Utc::now() - sign_duration();
        let mut keep_objects = vec![];
        for o in view.objects.drain(..) {
            let o1 = o.0.borrow();
            let Some(issue_end) = o1.issue_end else {
                drop(o1);
                keep_objects.push(o);
                continue;
            };
            if issue_end >= epoch {
                drop(o1);
                keep_objects.push(o);
                continue;
            }
            log.log_with(loga::INFO, "Deleting obsolete cert", ea!(id = o.0.borrow().version_short_id));
            storage_client
                .objects()
                .delete(&config.bucket, &urlencoding::encode(&o1.object_key))
                .doit()
                .await
                .stack_context_with(log, "Error deleting expired cert object", ea!(object = o1.object_key))?;
        }
        view.objects = keep_objects;
        let mut active_versions = HashSet::new();
        for o in &view.objects {
            let o1 = o.0.borrow();
            active_versions.insert(o1.version_short_id.clone());
        }
        for v in view.versions.values() {
            let v0 = v.0.borrow();
            if active_versions.contains(&v0.short_id) {
                continue;
            }
            log.log_with(loga::INFO, "Deleting unrooted key version", ea!(id = v.0.borrow().short_id));
            kms_client
                .projects()
                .locations_key_rings_crypto_keys_crypto_key_versions_destroy(
                    DestroyCryptoKeyVersionRequest::default(),
                    &v0.full_id,
                )
                .doit()
                .await
                .stack_context_with(log, "Failed to destroy old key", ea!(id = v0.short_id))?;
        }

        // Build CA bundle artifact
        let mut certs = vec![];
        for o in view.objects {
            let o0 = o.0.borrow();
            let log = &log.fork(ea!(id = o0.object_key));
            log.log(loga::INFO, "Adding cert to artifact bundle");
            let resp =
                storage_client
                    .objects()
                    .get(&config.bucket, &urlencoding::encode(&o0.object_key))
                    .param("alt", "media")
                    .doit()
                    .await
                    .stack_context_with(log, "Error requesting cert from bucket", ea!(object = o0.object_key))?
                    .0;
            if !resp.status().is_success() {
                return Err(log.err("Received error response to request for cert"))
            }
            let mut body =
                String::from_utf8(
                    yup_oauth2::hyper::body::to_bytes(resp.into_body())
                        .await
                        .stack_context(log, "Error downloading cert body")?
                        .to_vec(),
                ).stack_context(log, "Downloaded cert PEM has invalid utf-8")?;
            if body.is_empty() {
                return Err(log.err("Got empty cert body from server"));
            }
            if *body.as_bytes().last().unwrap() != '\n' as u8 {
                body.push('\n');
            }
            if o.0.as_ptr() == current.0.as_ptr() {
                eprintln!("\nActive signing cert is:\n{}", body);
            }
            certs.extend(body.as_bytes());
        }
        let artifact_name = "spaghettinuum_s.crt";
        let url = format!("https://storage.googleapis.com/{}/{}", config.bucket, artifact_name);
        storage_client
            .objects()
            .insert(Object {
                name: Some(artifact_name.to_string()),
                ..Default::default()
            }, &config.bucket)
            .upload_resumable(Cursor::new(&certs), Mime::from_str("application/pem-certificate-chain").unwrap())
            .await
            .stack_context_with(log, "Error uploading bundle", ea!(object = url))?;
        eprintln!("Bundle was uploaded to {}", url);
        return Ok(());
    }

    match inner().await {
        Ok(_) => { },
        Err(e) => {
            loga::fatal(e);
        },
    }
}
