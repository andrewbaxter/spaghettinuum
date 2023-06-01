use std::{
    sync::Arc,
    collections::HashMap,
    fs,
    io::ErrorKind,
    path::PathBuf,
    net::{
        SocketAddr,
    },
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
use loga::{
    Log,
    ea,
    ResultContext,
};
#[cfg(feature = "card")]
use openpgp_card_pcsc::PcscBackend;
#[cfg(feature = "card")]
use openpgp_card_sequoia::{
    Card,
    state::Open,
};
#[cfg(feature = "card")]
use sequoia_openpgp::{
    types::HashAlgorithm,
    crypto::Signer,
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
        RustlsConfig,
        RustlsCertificate,
        Listener,
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
use serde::{
    Deserialize,
    Serialize,
};
use sha2::Sha256;
use taskmanager::TaskManager;
use x509_parser::prelude::X509Certificate;
use crate::{
    data::{
        identity::{
            Identity,
            IdentitySecretVersionMethods,
            IdentitySecret,
        },
        publisher::{
            ResolveKeyValues,
            self,
            admin::RegisterIdentityRequest,
        },
        node::protocol::SerialAddr,
        utils::StrSocketAddr,
    },
    utils::{
        lookup_ip,
    },
};
use crate::{
    aes,
    node::{
        Node,
    },
    es,
    utils::{
        VisErr,
        ResultVisErr,
    },
    aes2,
};
#[cfg(feature = "card")]
use crate::utils::pgp::{
    self,
    extract_pgp_ed25519_sig,
};
use crate::publisher::config::{
    SecretType,
    DataConfig,
    Config,
};
use self::config::{
    IdentityData,
    AdvertiseAddrConfig,
};
#[cfg(feature = "card")]
use self::config::SecretTypeCard;

pub mod config;
mod db;

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
            crate::data::node::protocol::v1::Value {
                message: message.clone(),
                signature: secret.sign(message.as_ref()),
            }
        },
        #[cfg(feature = "card")]
        SecretType::Card(card_desc) => {
            match es!({
                let mut card: Card<Open> = PcscBackend::open_by_ident(&card_desc.pcsc_id, None)?.into();
                let mut transaction = card.transaction()?;
                transaction
                    .verify_user_for_signing(card_desc.pin.as_bytes())
                    .log_context(log, "Error unlocking card with pin", ea!(card = card_desc.pcsc_id))?;
                let mut user = transaction.signing_card().unwrap();
                let signer_panic =
                    || panic!(
                        "Card {} needs human interaction, automatic republishing won't work",
                        card_desc.pcsc_id
                    );
                let mut signer = user.signer(&signer_panic)?;
                match signer.public() {
                    sequoia_openpgp::packet::Key::V4(k) => match k.mpis() {
                        sequoia_openpgp::crypto::mpi::PublicKey::EdDSA { .. } => {
                            let hash = crate::data::identity::hash_for_ed25519(&message);
                            return Ok(crate::data::node::protocol::v1::Value {
                                message: message.clone(),
                                signature: extract_pgp_ed25519_sig(
                                    &signer
                                        .sign(HashAlgorithm::SHA512, &hash)
                                        .map_err(|e| loga::Error::new("Card signature failed", ea!(err = e)))?,
                                ).to_vec(),
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
                    log.warn_e(
                        e,
                        "Failed to sign publisher advertisement for card secret",
                        ea!(card = card_desc.pcsc_id),
                    );
                    return;
                },
            }
        },
    };
    node.put(ident.clone(), value).await;
}

/// Start a static publisher in the task manager. In a static publisher, all data
/// to publish is part of the config.
pub async fn new_static_publisher(
    log: &Log,
    tm: &TaskManager,
    node: Node,
    bind_addr: StrSocketAddr,
    advertise_addr: SocketAddr,
    cert_path: PathBuf,
    data: HashMap<Identity, IdentityData>,
) -> Result<(), loga::Error> {
    let certs = get_certs(log, advertise_addr, cert_path)?;

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
                let mut kvs = publisher::v1::ResolveKeyValues(HashMap::new());
                if let Some(d) = self.0.data.get(&ident) {
                    let now = Utc::now();
                    for k in req.uri().query().unwrap_or("").split(",") {
                        if let Some(v) = d.kvs.data.get(k) {
                            kvs.0.insert(k.to_string(), publisher::v1::ResolveValue {
                                expires: now + Duration::minutes(v.ttl as i64),
                                data: Some(v.data.clone()),
                            });
                        } else {
                            kvs.0.insert(k.to_string(), publisher::v1::ResolveValue {
                                expires: now + Duration::minutes(d.kvs.missing_ttl as i64),
                                data: None,
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
                        <String as IntoResponse>::with_status(e.to_string(), StatusCode::BAD_REQUEST).into_response(),
                    );
                },
            }
        }
    }

    let base = Arc::new(data);
    {
        let base = base.clone();
        let log = log.fork(ea!(subsys = "server"));
        let tm1 = tm.clone();
        tm.critical_task(async move {
            match tm1
                .if_alive(
                    Server::new(
                        TcpListener::bind(
                            bind_addr.1,
                        ).rustls(
                            RustlsConfig
                            ::new().fallback(RustlsCertificate::new().key(certs.priv_pem).cert(certs.pub_pem)),
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
        let advertise_addr = advertise_addr.clone();
        tm.periodic(Duration::hours(4).to_std().unwrap(), move || {
            let pub_hash = certs.pub_hash.clone();
            let node = node.clone();
            let log = log.clone();
            let base = base.clone();
            let advertise_addr = advertise_addr.clone();
            return async move {
                let message = crate::data::node::protocol::v1::ValueBody {
                    addr: SerialAddr(advertise_addr),
                    cert_hash: pub_hash,
                    expires: Utc::now() + Duration::hours(12),
                }.to_bytes();
                for (ident, data) in base.as_ref() {
                    announce(&log, &message, &node, ident, &data.secret).await;
                }
            };
        });
    }
    return Ok(());
}

struct DynamicPublisherInner {
    db: Pool,
    log: Log,
    node: Node,
    cert_pub_hash: Vec<u8>,
    advertise_addr: SocketAddr,
}

/// A publisher that stores data it publishes in a sqlite database, with methods
/// for maintaining this data.
#[derive(Clone)]
pub struct DynamicPublisher(Arc<DynamicPublisherInner>);

#[async_trait]
impl Endpoint for DynamicPublisher {
    type Output = Response;

    async fn call(&self, req: Request) -> poem::Result<Self::Output> {
        match aes2!({
            let ident =
                Identity::from_str(req.uri().path().get(1..).unwrap_or(""))
                    .context("Couldn't parse identity", ea!())
                    .err_external()?;
            let mut kvs = publisher::v1::ResolveKeyValues(HashMap::new());
            if let Some(found_kvs) = self.0.db.get().await.err_internal()?.interact(move |db| {
                db::get_keyvalues(db, &ident)
            }).await.err_internal()?.err_internal()? {
                let now = Utc::now();
                match found_kvs {
                    publisher::Publish::V1(mut found) => {
                        for k in req.uri().query().unwrap_or("").split(",") {
                            if let Some(v) = found.data.remove(k) {
                                kvs.0.insert(k.to_string(), publisher::v1::ResolveValue {
                                    expires: now + Duration::minutes(v.ttl as i64),
                                    data: Some(v.data),
                                });
                            } else {
                                kvs.0.insert(k.to_string(), publisher::v1::ResolveValue {
                                    expires: now + Duration::minutes(found.missing_ttl as i64),
                                    data: None,
                                });
                            }
                        }
                    },
                }
            }
            return Ok(ResolveKeyValues::V1(kvs));
        }).await {
            Ok(kvs) => Ok(
                <poem::web::Json<ResolveKeyValues> as IntoResponse>::into_response(poem::web::Json(kvs)),
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

impl DynamicPublisher {
    /// Launch a new dynamic publisher in task manager.
    ///
    /// * `advertise_addr`: The address to use in announcements to the network. This should
    ///   be the internet-routable address of this instance (your public ip, plus the port
    ///   you're forwarding to the host)
    ///
    /// * `cert_path`: where to persist certs; generated if doesn't exist, otherwise loaded
    ///
    /// * `db_path`: path to file to store sqlite database
    pub async fn new(
        log: &Log,
        tm: &TaskManager,
        node: Node,
        bind_addr: StrSocketAddr,
        advertise_addr: SocketAddr,
        cert_path: PathBuf,
        db_path: PathBuf,
    ) -> Result<DynamicPublisher, loga::Error> {
        let certs = get_certs(log, advertise_addr, cert_path)?;
        let db = deadpool_sqlite::Config::new(db_path).create_pool(Runtime::Tokio1).unwrap();
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
        let core_log = log.fork(ea!(subsys = "server"));
        let core = DynamicPublisher(Arc::new(DynamicPublisherInner {
            db: db.clone(),
            node: node.clone(),
            log: core_log.clone(),
            cert_pub_hash: certs.pub_hash.clone(),
            advertise_addr: advertise_addr,
        }));
        tm.critical_task({
            let tm1 = tm.clone();
            let core = core.clone();
            async move {
                match tm1
                    .if_alive(
                        Server::new(
                            TcpListener::bind(
                                bind_addr.1,
                            ).rustls(
                                RustlsConfig
                                ::new().fallback(RustlsCertificate::new().key(certs.priv_pem).cert(certs.pub_pem)),
                            ),
                        ).run(get(core.clone())),
                    )
                    .await {
                    Some(r) => {
                        return r.log_context(&core_log, "Exited with error", ea!());
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
            let pub_hash = certs.pub_hash.clone();
            let advertise_url = advertise_addr.clone();
            move || {
                let node = node.clone();
                let pub_hash = pub_hash.clone();
                let log = log.clone();
                let db = db.clone();
                let advertise_url = advertise_url.clone();
                return async move {
                    match aes!({
                        let message = crate::data::node::protocol::v1::ValueBody {
                            addr: SerialAddr(advertise_url),
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
        return Ok(core);
    }

    /// Enable publishing with identity by storing identity information required for
    /// publishing. You must subsequently call `publish` to publish something.
    #[cfg(feature = "card")]
    pub async fn register_card_identity(&self, pcsc_id: String, pin: String) -> Result<Identity, loga::Error> {
        let identity =
            pgp::get_card(
                &pcsc_id,
                |card| pgp::card_to_ident(card),
            )?.ok_or_else(|| loga::Error::new("Card key type not supported", ea!()))?;
        self.0.db.get().await?.interact({
            let identity = identity.clone();
            move |db| {
                db::add_ident(db, &identity, &SecretType::Card(SecretTypeCard {
                    pcsc_id: pcsc_id,
                    pin: pin,
                }))
            }
        }).await??;
        return Ok(identity);
    }

    /// Enable publishing with identity by storing identity information required for
    /// publishing. You must subsequently call `publish` to publish something.
    pub async fn register_local_identity(&self, identity: Identity, secret: IdentitySecret) -> Result<(), loga::Error> {
        self.0.db.get().await?.interact(move |db| {
            db::add_ident(db, &identity, &SecretType::Local(secret))
        }).await??;
        return Ok(());
    }

    /// Disable publishing with identity, wiping info from database including published
    /// values.  Any published data will be unavailable to resolvers.
    pub async fn unregister_identity(&self, identity: Identity) -> Result<(), loga::Error> {
        self.0.db.get().await?.interact(move |db| {
            db::delete_keyvalues(db, &identity)?;
            db::delete_ident(db, &identity)
        }).await??;
        return Ok(());
    }

    /// Make data available to resolvers. This does two things: add it to the database,
    /// and trigger an initial announcement that this publisher is authoritative for
    /// the identity.
    pub async fn publish(
        &self,
        identity: Identity,
        data: crate::data::publisher::v1::Publish,
    ) -> Result<(), loga::Error> {
        {
            let identity = identity.clone();
            self.0.db.get().await?.interact(move |db| {
                db::set_keyvalues(db, &identity, &crate::data::publisher::Publish::V1(data))
            }).await??;
        }
        {
            let announce_message = crate::data::node::protocol::v1::ValueBody {
                addr: SerialAddr(self.0.advertise_addr),
                cert_hash: self.0.cert_pub_hash.clone(),
                expires: Utc::now() + Duration::hours(12),
            }.to_bytes();
            let secret = {
                let identity = identity.clone();
                self.0.db.get().await?.interact(move |db| {
                    db::get_ident(db, &identity)
                }).await??
            };
            announce(&self.0.log, &announce_message, &self.0.node, &identity, &secret).await;
        }
        return Ok(());
    }

    /// Make data unavailable to publishers and stop announcing authority for this
    /// identity.
    pub async fn unpublish(&self, identity: Identity) -> Result<(), loga::Error> {
        self.0.db.get().await?.interact(move |db| {
            db::delete_keyvalues(db, &identity)
        }).await??;
        return Ok(());
    }
}

struct PublisherCerts {
    pub_pem: String,
    priv_pem: String,
    pub_hash: Vec<u8>,
}

fn get_certs(log: &Log, advertise_addr: SocketAddr, cert_path: PathBuf) -> Result<PublisherCerts, loga::Error> {
    let (pub_der, priv_der) = 'got_certs : loop {
        match es!({
            let bytes = match fs::read(&cert_path) {
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
        let cert = rcgen::generate_simple_self_signed([advertise_addr.ip().to_string()]).unwrap();
        let pub_der = &(&cert).serialize_der().unwrap();
        let priv_der = &(&cert).serialize_private_key_der();
        match fs::write(&cert_path, &bincode::serialize(&SerialTlsCert {
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
    return Ok(PublisherCerts {
        pub_pem: pub_pem,
        priv_pem: priv_pem,
        pub_hash: pub_hash,
    });
}

async fn resolve_advertise_addr(a: AdvertiseAddrConfig) -> Result<SocketAddr, loga::Error> {
    match a {
        AdvertiseAddrConfig::Fixed(a) => return Ok(a),
        AdvertiseAddrConfig::Lookup(l) => {
            return Ok(SocketAddr::new(lookup_ip(&l.lookup, l.ipv4_only, l.ipv6_only).await?, l.port));
        },
    }
}

#[doc(hidden)]
pub async fn start(tm: &TaskManager, log: &Log, config: Config, node: Node) -> Result<(), loga::Error> {
    let log = log.fork(ea!(sys = "publisher"));

    // Serve
    match config.data {
        DataConfig::Static(base) => {
            new_static_publisher(
                &log,
                tm,
                node,
                config.bind_addr,
                resolve_advertise_addr(config.advertise_addr).await?,
                config.cert_path,
                base,
            ).await?;
        },
        DataConfig::Dynamic(base) => {
            let core =
                DynamicPublisher::new(
                    &log,
                    tm,
                    node,
                    config.bind_addr,
                    resolve_advertise_addr(config.advertise_addr).await?,
                    config.cert_path,
                    base.db_path,
                ).await?;
            tm.critical_task({
                let log = log.fork(ea!(subsys = "admin"));
                let tm1 = tm.clone();
                async move {
                    struct Inner {
                        core: DynamicPublisher,
                        log: Log,
                    }

                    match tm1
                        .if_alive(
                            Server::new(TcpListener::bind(base.bind_addr.1)).run(Route::new().at("/identity", post({
                                #[handler]
                                async fn ep(service: Data<&Arc<Inner>>, body: Json<RegisterIdentityRequest>) -> Response {
                                    match aes!({
                                        match body.0 {
                                            RegisterIdentityRequest::Local(l) => {
                                                service.core.register_local_identity(l.identity, l.secret).await?;
                                            },
                                            #[cfg(feature = "card")]
                                            RegisterIdentityRequest::Card(c) => {
                                                service.core.register_card_identity(c.pcsc_id, c.pin).await?;
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
                                        service.core.unregister_identity(identity).await?;
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
                                    body: Json<crate::data::publisher::v1::Publish>,
                                ) -> Response {
                                    match aes!({
                                        let identity = Identity::from_str(&identity)?;
                                        service.core.publish(identity, body.0).await?;
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
                                core: core,
                                log: log.clone(),
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
