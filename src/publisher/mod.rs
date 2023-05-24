use std::{
    sync::Arc,
    collections::HashMap,
    mem::size_of,
    fs,
    io::ErrorKind,
    net::SocketAddr,
};
use chrono::{
    Utc,
    Duration,
};
use deadpool_sqlite::{
    Pool,
    Runtime,
};
use pem::Pem;
use sha2::{
    Digest,
};
use ed25519_dalek::ed25519::ComponentBytes;
use loga::{
    Log,
    ea,
    ResultContext,
};
use openpgp_card_pcsc::PcscBackend;
use openpgp_card_sequoia::{
    Card,
    state::Open,
};
use poem::{
    Server,
    Endpoint,
    Response,
    async_trait,
    Request,
    http::StatusCode,
    get,
    listener::{
        TcpListener,
        Listener,
        RustlsConfig,
        RustlsCertificate,
    },
    IntoResponse,
    Route,
    post,
    delete,
    middleware::AddData,
    EndpointExt,
    web::{
        Json,
        Data,
        Path,
    },
    handler,
};
use sequoia_openpgp::{
    types::HashAlgorithm,
    crypto::Signer,
};
use serde::{
    Deserialize,
    Serialize,
};
use sha2::Sha256;
use taskmanager::TaskManager;
use x509_parser::prelude::X509Certificate;
use crate::{
    model::{
        identity::{
            Identity,
            IdentitySecretMethods,
        },
        publish::{
            ResolveKeyValues,
            self,
        },
    },
    aes,
    node::{
        self,
        Node,
        model::protocol::Addr,
    },
    es,
    utils::{
        hash_for_ed25519,
        VisErr,
        ResultVisErr,
        card,
    },
    aes2,
    publisher::model::{
        config::IdentityData,
        protocol::admin::RegisterIdentityRequest,
    },
};
use self::model::config::{
    SecretType,
    DataConfig,
    Config,
};

pub mod db;
pub mod model;

#[derive(Serialize, Deserialize)]
struct SerialTlsCert {
    pub_der: Vec<u8>,
    priv_der: Vec<u8>,
}

pub fn publisher_cert_hash(cert: &X509Certificate) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(cert.public_key().raw);
    return hash.finalize().to_vec();
}

async fn announce(log: &Log, message: &Vec<u8>, node: &Node, ident: &Identity, secret: &SecretType) {
    let value = match secret {
        SecretType::Local(secret) => {
            node::model::protocol::v1::Value {
                message: message.clone(),
                signature: secret.sign(message.as_ref()),
            }
        },
        SecretType::Card(fingerprint) => {
            match es!({
                let mut card: Card<Open> = PcscBackend::open_by_ident(&fingerprint, None)?.into();
                let mut transaction = card.transaction()?;
                let mut user = transaction.signing_card().unwrap();
                let signer_panic =
                    || panic!("Card {} needs human interaction, automatic republishing won't work", fingerprint);
                let mut signer = user.signer(&signer_panic)?;
                match signer.public() {
                    sequoia_openpgp::packet::Key::V4(k) => match k.mpis() {
                        sequoia_openpgp::crypto::mpi::PublicKey::EdDSA { .. } => {
                            let gpg_signature =
                                signer
                                    .sign(HashAlgorithm::SHA512, &hash_for_ed25519(&message).finalize().to_vec())
                                    .map_err(|e| loga::Error::new("Card signature failed", ea!(err = e)))?;
                            let sig = match gpg_signature {
                                sequoia_openpgp::crypto::mpi::Signature::EdDSA { r, s } => ed25519_dalek
                                ::Signature
                                ::from_components(
                                    r.value_padded(size_of::<ComponentBytes>()).unwrap().to_vec().try_into().unwrap(),
                                    s
                                        .value_padded(size_of::<ComponentBytes>())
                                        .unwrap()
                                        .to_vec()
                                        .try_into()
                                        .unwrap(),
                                ),
                                _ => panic!("signature type doesn't match key type"),
                            };
                            return Ok(node::model::protocol::v1::Value {
                                message: message.clone(),
                                signature: sig.to_vec(),
                            });
                        },
                        _ => { },
                    },
                    _ => { },
                };
                return Err(loga::Error::new("Unsupported key type - must be Ed25519", ea!()));
            }) {
                Ok(v) => v,
                Err(e) => {
                    log.warn_e(e, "Failed to sign publisher advertisement for card secret", ea!(card = fingerprint));
                    return;
                },
            }
        },
    };
    node.put(ident.clone(), value).await;
}

pub async fn start(tm: &TaskManager, log: &Log, config: Config, node: Node) -> Result<(), loga::Error> {
    let log = log.fork(ea!(sys = "publisher"));

    // Prepare publish server cert
    let (pub_der, priv_der) = 'got_certs : loop {
        match es!({
            let bytes = match fs::read(&config.cert_path) {
                Err(e) => {
                    if e.kind() == ErrorKind::NotFound {
                        return Ok(None);
                    } else {
                        return Err(e.into());
                    }
                },
                Ok(b) => b,
            };
            let serial_cert: SerialTlsCert = bincode::deserialize(&bytes)?;
            return Ok(Some((serial_cert.pub_der, serial_cert.priv_der)));
        }) {
            Ok(c) => match c {
                Some(c) => break 'got_certs c,
                None => { },
            },
            Err(e) => {
                log.warn_e(e, "Error loading serialized publisher cert", ea!());
            },
        }
        let cert = rcgen::generate_simple_self_signed([config.advertise_addr.ip().to_string()]).unwrap();
        let pub_der = &(&cert).serialize_der().unwrap();
        let priv_der = &(&cert).serialize_private_key_der();
        match fs::write(&config.cert_path, &bincode::serialize(&SerialTlsCert {
            pub_der: pub_der.clone(),
            priv_der: priv_der.clone(),
        }).unwrap()) {
            Err(e) => {
                log.warn_e(e.into(), "Failed to serialize new publisher cert", ea!());
            },
            Ok(_) => { },
        };
        break (pub_der.clone(), priv_der.clone());
    };
    let pub_pem = {
        let p = Pem::new("CERTIFICATE".to_string(), pub_der.clone());
        pem::encode(&p)
    };
    let priv_pem = {
        let p = Pem::new("PRIVATE KEY".to_string(), priv_der);
        pem::encode(&p)
    };
    let pub_hash = publisher_cert_hash(&x509_parser::parse_x509_certificate(&pub_der).unwrap().1);

    // Serve
    match config.data {
        DataConfig::Static(base) => {
            struct Inner {
                data: Arc<HashMap<Identity, IdentityData>>,
            }

            struct Outer(Arc<Inner>);

            #[async_trait]
            impl Endpoint for Outer {
                type Output = Response;

                async fn call(&self, req: Request) -> poem::Result<Self::Output> {
                    match aes!({
                        let ident =
                            Identity::from_str(
                                req.uri().path().get(1..).unwrap_or(""),
                            ).context("Couldn't parse identity", ea!())?;
                        let mut kvs = publish::v1::ResolveKeyValues(HashMap::new());
                        if let Some(d) = self.0.data.get(&ident) {
                            let now = Utc::now();
                            for k in req.uri().query().unwrap_or("").split(",") {
                                if let Some(v) = d.kvs.0.get(k) {
                                    kvs.0.insert(k.to_string(), publish::v1::ResolveValue {
                                        expires: now + Duration::minutes(v.ttl as i64),
                                        data: v.data.clone(),
                                    });
                                }
                            }
                        }
                        return Ok(ResolveKeyValues::V1(kvs));
                    }).await {
                        Ok(kvs) => Ok(
                            <poem::web::Json<ResolveKeyValues> as IntoResponse>::into_response(poem::web::Json(kvs)),
                        ),
                        Err(e) => {
                            return Ok(
                                <String as IntoResponse>::with_status(
                                    e.to_string(),
                                    StatusCode::BAD_REQUEST,
                                ).into_response(),
                            );
                        },
                    }
                }
            }

            let base = Arc::new(base);
            {
                let base = base.clone();
                let log = log.fork(ea!(subsys = "server"));
                let tm1 = tm.clone();
                tm.critical_task(async move {
                    match tm1
                        .if_alive(
                            Server::new(
                                TcpListener::bind(
                                    config.bind_addr,
                                ).rustls(
                                    RustlsConfig
                                    ::new().fallback(RustlsCertificate::new().key(priv_pem).cert(pub_pem)),
                                ),
                            ).run(get(Outer(Arc::new(Inner { data: base.clone() })))),
                        )
                        .await {
                        Some(r) => {
                            return r.log_context(&log, "Exited with error", ea!());
                        },
                        None => {
                            return Ok(())
                        },
                    }
                });
            }
            {
                let base = base.clone();
                let node = node.clone();
                let log = log.fork(ea!(sys = "periodic_announce"));
                let advertise_addr = config.advertise_addr.clone();
                tm.periodic(Duration::hours(4).to_std().unwrap(), move || {
                    let pub_hash = pub_hash.clone();
                    let node = node.clone();
                    let log = log.clone();
                    let base = base.clone();
                    let advertise_addr = advertise_addr.clone();
                    return async move {
                        let message = node::model::protocol::v1::ValueBody {
                            addr: Addr(advertise_addr),
                            cert_hash: pub_hash,
                            expires: Utc::now() + Duration::hours(12),
                        }.to_bytes();
                        for (ident, data) in base.as_ref() {
                            announce(&log, &message, &node, ident, &data.secret).await;
                        }
                    };
                });
            }
        },
        DataConfig::Dynamic(base) => {
            let db = deadpool_sqlite::Config::new(base.db).create_pool(Runtime::Tokio1).unwrap();
            {
                let log = log.fork(ea!(action = "db_init"));
                db
                    .get()
                    .await
                    .log_context(&log, "Error getting db instance", ea!())?
                    .interact(|db| {
                        db::migrate(db)
                    })
                    .await
                    .log_context(&log, "Pool interaction error", ea!())?
                    .log_context(&log, "Migration failed", ea!())?;
            }
            tm.critical_task({
                let log = log.fork(ea!(subsys = "server"));
                let tm1 = tm.clone();
                let db = db.clone();
                async move {
                    struct Inner {
                        db: Pool,
                        log: Log,
                    }

                    struct Outer(Arc<Inner>);

                    #[async_trait]
                    impl Endpoint for Outer {
                        type Output = Response;

                        async fn call(&self, req: Request) -> poem::Result<Self::Output> {
                            match aes2!({
                                let ident =
                                    Identity::from_str(req.uri().path().get(1..).unwrap_or(""))
                                        .context("Couldn't parse identity", ea!())
                                        .err_external()?;
                                let mut kvs = publish::v1::ResolveKeyValues(HashMap::new());
                                if let Some(found_kvs) = self.0.db.get().await.err_internal()?.interact(move |db| {
                                    db::get_keyvalues(db, &ident)
                                }).await.err_internal()?.err_internal()? {
                                    let now = Utc::now();
                                    match found_kvs {
                                        publish::KeyValues::V1(mut found_kvs) => {
                                            for k in req.uri().query().unwrap_or("").split(",") {
                                                if let Some(v) = found_kvs.0.remove(k) {
                                                    kvs.0.insert(k.to_string(), publish::v1::ResolveValue {
                                                        expires: now + Duration::minutes(v.ttl as i64),
                                                        data: v.data,
                                                    });
                                                }
                                            }
                                        },
                                    }
                                }
                                return Ok(ResolveKeyValues::V1(kvs));
                            }).await {
                                Ok(kvs) => Ok(
                                    <poem::web::Json<ResolveKeyValues> as IntoResponse>::into_response(
                                        poem::web::Json(kvs),
                                    ),
                                ),
                                Err(e) => {
                                    match e {
                                        VisErr::Internal(e) => {
                                            self.0.log.warn_e(e, "Error processing request", ea!());
                                            return Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response());
                                        },
                                        VisErr::External(e) => {
                                            return Ok(
                                                <String as IntoResponse>::with_status(
                                                    e.to_string(),
                                                    StatusCode::BAD_REQUEST,
                                                ).into_response(),
                                            );
                                        },
                                    }
                                },
                            }
                        }
                    }

                    match tm1
                        .if_alive(
                            Server::new(
                                TcpListener::bind(
                                    config.bind_addr,
                                ).rustls(
                                    RustlsConfig
                                    ::new().fallback(RustlsCertificate::new().key(priv_pem).cert(pub_pem)),
                                ),
                            ).run(get(Outer(Arc::new(Inner {
                                db: db.clone(),
                                log: log.clone(),
                            })))),
                        )
                        .await {
                        Some(r) => {
                            return r.log_context(&log, "Exited with error", ea!());
                        },
                        None => {
                            return Ok(());
                        },
                    }
                }
            });
            tm.periodic(Duration::hours(4).to_std().unwrap(), {
                let log = log.fork(ea!(sys = "periodic_announce"));
                let db = db.clone();
                let node = node.clone();
                let pub_hash = pub_hash.clone();
                let advertise_url = config.advertise_addr.clone();
                move || {
                    let node = node.clone();
                    let pub_hash = pub_hash.clone();
                    let log = log.clone();
                    let db = db.clone();
                    let advertise_url = advertise_url.clone();
                    return async move {
                        match aes!({
                            let message = node::model::protocol::v1::ValueBody {
                                addr: Addr(advertise_url),
                                cert_hash: pub_hash,
                                expires: Utc::now() + Duration::hours(12),
                            }.to_bytes();
                            let db = db.get().await.context("Error getting db connection", ea!())?;
                            let ident_pairs = db.interact(|db| db::list_idents_start(db)).await??;
                            for ident_pair in &ident_pairs {
                                announce(&log, &message, &node, &ident_pair.identity, &ident_pair.secret).await;
                            }
                            let mut prev_ident = ident_pairs.last().map(|i| i.identity.clone());
                            while let Some(edge) = prev_ident {
                                let ident_pairs = db.interact(move |db| db::list_idents_after(db, &edge)).await??;
                                for ident_pair in &ident_pairs {
                                    announce(&log, &message, &node, &ident_pair.identity, &ident_pair.secret).await;
                                }
                                prev_ident = ident_pairs.last().map(|i| i.identity.clone());
                            }
                            return Ok(());
                        }).await {
                            Ok(_) => { },
                            Err(e) => {
                                log.warn_e(e, "Error while re-announcing publishers", ea!());
                            },
                        }
                    };
                }
            });
            tm.critical_task({
                let log = log.fork(ea!(subsys = "admin"));
                let tm1 = tm.clone();
                let db = db.clone();
                async move {
                    struct Inner {
                        db: Pool,
                        log: Log,
                        publisher_advertise_url: SocketAddr,
                        publisher_pub_cert_hash: Vec<u8>,
                        node: Node,
                    }

                    struct Outer(Arc<Inner>);

                    match tm1
                        .if_alive(
                            Server::new(TcpListener::bind(base.bind_addr)).run(Route::new().at("/identity", post({
                                #[handler]
                                async fn ep(service: Data<&Arc<Inner>>, body: Json<RegisterIdentityRequest>) -> Response {
                                    match aes!({
                                        match body.0 {
                                            RegisterIdentityRequest::Local(l) => {
                                                service.0.db.get().await?.interact(move |db| {
                                                    db::add_ident(db, &l.identity, &SecretType::Local(l.secret))
                                                }).await??;
                                            },
                                            RegisterIdentityRequest::Card(c) => {
                                                let identity =
                                                    card::get_card(
                                                        &c.gpg_id,
                                                        |card| card::card_to_ident(card),
                                                    )?.ok_or_else(
                                                        || loga::Error::new("Card key type not supported", ea!()),
                                                    )?;
                                                service.0.db.get().await?.interact(move |db| {
                                                    db::add_ident(db, &identity, &SecretType::Card(c.gpg_id))
                                                }).await??;
                                            },
                                        }
                                        return Ok(());
                                    }).await {
                                        Ok(()) => {
                                            return StatusCode::OK.into_response();
                                        },
                                        Err(e) => {
                                            service.log.warn_e(e, "Error registering identity", ea!());
                                            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                                        },
                                    }
                                }

                                ep
                            })).at("/identity/:identity", delete({
                                #[handler]
                                async fn ep(service: Data<&Arc<Inner>>, Path(identity): Path<String>) -> Response {
                                    match aes!({
                                        let identity = Identity::from_str(&identity)?;
                                        service.0.db.get().await?.interact(move |db| {
                                            db::delete_ident(db, &identity)
                                        }).await??;
                                        return Ok(());
                                    }).await {
                                        Ok(()) => {
                                            return StatusCode::OK.into_response();
                                        },
                                        Err(e) => {
                                            service
                                                .log
                                                .warn_e(e, "Error deleting identity", ea!(identity = identity));
                                            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                                        },
                                    }
                                }

                                ep
                            })).at("/publish/:identity", post({
                                #[handler]
                                async fn ep(
                                    service: Data<&Arc<Inner>>,
                                    Path(identity): Path<String>,
                                    body: Json<crate::model::publish::v1::KeyValues>,
                                ) -> Response {
                                    match aes!({
                                        let identity = Identity::from_str(&identity)?;
                                        {
                                            let identity = identity.clone();
                                            service.0.db.get().await?.interact(move |db| {
                                                db::set_keyvalues(
                                                    db,
                                                    &identity,
                                                    &crate::model::publish::KeyValues::V1(body.0),
                                                )
                                            }).await??;
                                        }
                                        {
                                            let announce_message = node::model::protocol::v1::ValueBody {
                                                addr: Addr(service.publisher_advertise_url.clone()),
                                                cert_hash: service.publisher_pub_cert_hash.clone(),
                                                expires: Utc::now() + Duration::hours(12),
                                            }.to_bytes();
                                            let secret = {
                                                let identity = identity.clone();
                                                service.0.db.get().await?.interact(move |db| {
                                                    db::get_ident(db, &identity)
                                                }).await??
                                            };
                                            announce(
                                                &service.log,
                                                &announce_message,
                                                &service.node,
                                                &identity,
                                                &secret,
                                            ).await;
                                        }
                                        return Ok(());
                                    }).await {
                                        Ok(()) => {
                                            return StatusCode::OK.into_response();
                                        },
                                        Err(e) => {
                                            service.log.warn_e(e, "Error publishing key values", ea!());
                                            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                                        },
                                    }
                                }

                                ep
                            })).with(AddData::new(Arc::new(Inner {
                                db: db.clone(),
                                log: log.clone(),
                                publisher_advertise_url: config.advertise_addr.clone(),
                                publisher_pub_cert_hash: pub_hash.clone(),
                                node: node.clone(),
                            })))),
                        )
                        .await {
                        Some(r) => {
                            return r.log_context(&log, "Exited with error", ea!(addr = base.bind_addr));
                        },
                        None => {
                            return Ok(());
                        },
                    }
                }
            });
        },
    }
    return Ok(());
}
