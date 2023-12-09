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
    middleware::AddData,
    EndpointExt,
    web::{
        Json,
        Data,
        Path,
        Query,
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
        },
        publisher::{
            ResolveKeyValues,
            self,
            admin::{
                InfoResponse,
            },
            Publish,
        },
        utils::StrSocketAddr,
    },
    utils::{
        lookup_ip,
    },
    node::ValueArgs,
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
use crate::publisher::config::{
    Config,
};
use self::{
    config::{
        AdvertiseAddrConfig,
    },
};

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

/// Start a static publisher in the task manager. In a static publisher, all data
/// to publish is part of the config.
pub async fn new_static_publisher(
    log: &Log,
    tm: &TaskManager,
    node: Node,
    bind_addr: StrSocketAddr,
    advertise_addr: SocketAddr,
    cert_path: PathBuf,
    announcements: HashMap<Identity, crate::data::publisher::announcement::v1::Announcement>,
    keyvalues: HashMap<Identity, crate::data::publisher::v1::Publish>,
) -> Result<(), loga::Error> {
    let certs = get_certs(log, advertise_addr, cert_path)?;

    struct Inner {
        keyvalues: HashMap<Identity, crate::data::publisher::v1::Publish>,
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
                    ).context("Couldn't parse identity")?;
                let mut kvs = publisher::v1::ResolveKeyValues(HashMap::new());
                if let Some(d) = self.0.keyvalues.get(&ident) {
                    let now = Utc::now();
                    for k in req.uri().query().unwrap_or("").split(",") {
                        if let Some(v) = d.data.get(k) {
                            kvs.0.insert(k.to_string(), publisher::v1::ResolveValue {
                                expires: now + Duration::minutes(v.ttl as i64),
                                data: Some(v.data.clone()),
                            });
                        } else {
                            kvs.0.insert(k.to_string(), publisher::v1::ResolveValue {
                                expires: now + Duration::minutes(d.missing_ttl as i64),
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

    {
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
                    ).run(get(Outer(Arc::new(Inner { keyvalues: keyvalues })))),
                )
                .await {
                Some(r) => {
                    return r.log_context(&log, "Exited with error");
                },
                None => {
                    return Ok(())
                },
            }
        });
    }
    {
        let announcements = Arc::new(announcements);
        let node = node.clone();
        tm.periodic(Duration::hours(4).to_std().unwrap(), move || {
            let node = node.clone();
            let announcements = announcements.clone();
            return async move {
                for (ident, data) in announcements.as_ref() {
                    node.put(ident.clone(), crate::node::ValueArgs {
                        message: data.message.clone(),
                        signature: data.signature.clone(),
                    }).await;
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
                    .context("Couldn't parse identity")
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
            db.get().await.log_context(&log, "Error getting db instance")?.interact(|db| {
                db::migrate(db)
            }).await.log_context(&log, "Pool interaction error")?.log_context(&log, "Migration failed")?;
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
                        return r.log_context(&core_log, "Exited with error");
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
            move || {
                let node = node.clone();
                let log = log.clone();
                let db = db.clone();
                return async move {
                    match aes!({
                        let db = db.get().await.context("Error getting db connection")?;

                        // easier than lambda...
                        macro_rules! announce{
                            ($pair: expr) => {
                                let value = match & $pair.value {
                                    publisher:: announcement:: Announcement:: V1(v) => ValueArgs {
                                        message: v.message.clone(),
                                        signature: v.signature.clone(),
                                    },
                                };
                                node.put($pair.identity.clone(), value).await;
                            };
                        }

                        let announce_pairs = db.interact(|db| db::list_announce_start(db)).await??;
                        for announce_pair in &announce_pairs {
                            announce!(announce_pair);
                        }
                        let mut prev_ident = announce_pairs.last().map(|i| i.identity.clone());
                        while let Some(edge) = prev_ident {
                            let announce_pairs = db.interact(move |db| db::list_announce_after(db, &edge)).await??;
                            for announce_pair in &announce_pairs {
                                announce!(announce_pair);
                            }
                            prev_ident = announce_pairs.last().map(|i| i.identity.clone());
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

    /// Make data available to resolvers. This does two things: add it to the database,
    /// and trigger an initial announcement that this publisher is authoritative for
    /// the identity.
    pub async fn publish(
        &self,
        identity: Identity,
        announcement: crate::data::publisher::announcement::v1::Announcement,
        keyvalues: crate::data::publisher::v1::Publish,
    ) -> Result<(), loga::Error> {
        {
            let identity = identity.clone();
            let announcement = announcement.clone();
            self.0.db.get().await?.interact(move |db| {
                db::set_announce(db, &identity, &publisher::announcement::Announcement::V1(announcement))?;
                db::set_keyvalues(db, &identity, &crate::data::publisher::Publish::V1(keyvalues))
            }).await??;
        }
        self.0.node.put(identity, ValueArgs {
            message: announcement.message,
            signature: announcement.signature,
        }).await;
        return Ok(());
    }

    /// Make data unavailable to publishers and stop announcing authority for this
    /// identity.
    pub async fn unpublish(&self, identity: Identity) -> Result<(), loga::Error> {
        self.0.db.get().await?.interact(move |db| {
            db::delete_announce(db, &identity)?;
            db::delete_keyvalues(db, &identity)
        }).await??;
        return Ok(());
    }

    pub async fn list_identities(&self, after: Option<Identity>) -> Result<Vec<Identity>, loga::Error> {
        return Ok(match after {
            None => {
                self
                    .0
                    .db
                    .get()
                    .await?
                    .interact(|db| db::list_announce_start(db))
                    .await??
                    .into_iter()
                    .map(|p| p.identity)
                    .collect()
            },
            Some(a) => {
                self
                    .0
                    .db
                    .get()
                    .await?
                    .interact(move |db| db::list_announce_after(db, &a))
                    .await??
                    .into_iter()
                    .map(|p| p.identity)
                    .collect()
            },
        });
    }

    pub async fn get_published_data(&self, identity: Identity) -> Result<Option<Publish>, loga::Error> {
        return Ok(self.0.db.get().await?.interact(move |db| {
            db::get_keyvalues(db, &identity)
        }).await??);
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
    let core =
        DynamicPublisher::new(
            &log,
            tm,
            node,
            config.bind_addr,
            resolve_advertise_addr(config.advertise_addr).await?,
            config.cert_path,
            config.db_path,
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
                .if_alive(Server::new(TcpListener::bind(config.admin_bind_addr.1)).run(Route::new().at("/info", get({
                    #[handler]
                    async fn ep(service: Data<&Arc<Inner>>) -> Response {
                        return Json(InfoResponse {
                            advertise_addr: service.core.0.advertise_addr,
                            cert_pub_hash: zbase32::encode_full_bytes(&service.core.0.cert_pub_hash).to_string(),
                        }).into_response();
                    }

                    ep
                })).at("/publish", get({
                    #[derive(Debug, Deserialize)]
                    struct Params {
                        after: Option<String>,
                    }

                    #[handler]
                    async fn ep(service: Data<&Arc<Inner>>, query: Query<Params>) -> Response {
                        match aes!({
                            match &query.after {
                                Some(i) => {
                                    let identity = Identity::from_str(i)?;
                                    return Ok(service.core.list_identities(Some(identity)).await?);
                                },
                                None => {
                                    return Ok(service.core.list_identities(None).await?);
                                },
                            }
                        }).await {
                            Ok(d) => {
                                return Json(d).into_response();
                            },
                            Err(e) => {
                                service.log.warn_e(e, "Error getting published identities", ea!());
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
                        body: Json<crate::data::publisher::admin::PublishRequest>,
                    ) -> Response {
                        match aes!({
                            let identity = Identity::from_str(&identity)?;
                            service.core.publish(identity, body.0.announce, body.0.keyvalues).await?;
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
                }).delete({
                    #[handler]
                    async fn ep(service: Data<&Arc<Inner>>, Path(identity): Path<String>) -> Response {
                        match aes!({
                            let identity = Identity::from_str(&identity)?;
                            service.core.unpublish(identity).await?;
                            return Ok(());
                        }).await {
                            Ok(()) => {
                                return StatusCode::OK.into_response();
                            },
                            Err(e) => {
                                service.log.warn_e(e, "Error deleting published data", ea!(identity = identity));
                                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                            },
                        }
                    }

                    ep
                }).get({
                    #[handler]
                    async fn ep(service: Data<&Arc<Inner>>, Path(identity): Path<String>) -> Response {
                        match aes!({
                            let identity = Identity::from_str(&identity)?;
                            return Ok(service.core.get_published_data(identity).await?);
                        }).await {
                            Ok(d) => {
                                return Json(d).into_response();
                            },
                            Err(e) => {
                                service.log.warn_e(e, "Error getting published identity data", ea!());
                                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                            },
                        }
                    }

                    ep
                })).with(AddData::new(Arc::new(Inner {
                    core: core,
                    log: log.clone(),
                })))))
                .await {
                Some(r) => {
                    return r.log_context_with(&log, "Exited with error", ea!(addr = config.admin_bind_addr));
                },
                None => {
                    return Ok(());
                },
            }
        }
    });
    return Ok(());
}
