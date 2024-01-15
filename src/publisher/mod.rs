use std::{
    sync::Arc,
    collections::HashMap,
    path::Path,
    net::{
        SocketAddr,
    },
    str::FromStr,
};
use chrono::{
    Utc,
    Duration,
};
use deadpool_sqlite::{
    Pool,
};
use der::{
    Decode,
    asn1::{
        GeneralizedTime,
    },
    Encode,
};
use good_ormning_runtime::GoodError;
use p256::{
    pkcs8::EncodePrivateKey,
    ecdsa::{
        DerSignature,
    },
};
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
    Response,
    async_trait,
    http::{
        StatusCode,
        Uri,
    },
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
        Query,
        self,
    },
    handler,
};
use serde::{
    Deserialize,
    Serialize,
    de::DeserializeOwned,
};
use sha2::Sha256;
use taskmanager::TaskManager;
use x509_cert::{
    spki::{
        SubjectPublicKeyInfoOwned,
    },
    builder::{
        CertificateBuilder,
        Profile,
        Builder,
    },
    name::RdnSequence,
    serial_number::SerialNumber,
    time::Time,
    Certificate,
};
use crate::{
    utils::{
        SystemEndpoints,
        VisErr,
        ResultVisErr,
        db_util::setup_db,
        tls_util::{
            encode_priv_pem,
            encode_pub_pem,
        },
        backed_identity::IdentitySigner,
    },
    node::{
        Node,
    },
    interface::{
        identity::Identity,
        spagh_cli::StrSocketAddr,
        spagh_api::{
            resolve::{
                ResolveKeyValues,
                self,
            },
            publish::{
                self,
                latest::{
                    InfoResponse,
                    JsonSignature,
                },
            },
        },
        spagh_internal,
        node_protocol,
    },
};

pub mod admin_db;
pub mod config;

pub trait PublishIdentSignatureMethods<B, I>
where
    Self: Sized {
    fn sign(signer: &mut dyn IdentitySigner, body: B) -> Result<(I, Self), loga::Error>;
    fn verify(&self, identity: &Identity) -> Result<B, ()>;
}

impl<B: Serialize + DeserializeOwned> PublishIdentSignatureMethods<B, Identity> for JsonSignature<B, Identity> {
    fn verify(&self, identity: &Identity) -> Result<B, ()> {
        identity.verify(self.message.as_bytes(), &self.signature).map_err(|_| ())?;
        return Ok(serde_json::from_str(&self.message).map_err(|_| ())?);
    }

    fn sign(signer: &mut dyn IdentitySigner, body: B) -> Result<(Identity, Self), loga::Error> {
        let message = serde_json::to_string(&body).unwrap();
        let (ident, signature) = signer.sign(message.as_bytes())?;
        return Ok((ident, Self {
            message: message,
            signature: signature,
            _p: Default::default(),
        }));
    }
}

#[derive(Serialize, Deserialize)]
struct SerialTlsCert {
    pub_der: Vec<u8>,
    priv_der: Vec<u8>,
}

pub fn publisher_cert_hash(cert_der: &[u8]) -> Result<Vec<u8>, ()> {
    return Ok(
        <Sha256 as Digest>::digest(
            Certificate::from_der(&cert_der)
                .map_err(|_| ())?
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .map_err(|_| ())?,
        ).to_vec(),
    );
}

/// This manages identities/published values for the publisher.  The `DbAdmin`
/// trait manages them in a persistent database, but you can implement your own if
/// you want to control them fully programmatically.
#[async_trait]
pub trait Admin: Send + Sync {
    async fn retrieve_certs(&self) -> Result<Option<spagh_internal::latest::PublishCerts>, loga::Error>;
    async fn store_certs(&self, certs: &spagh_internal::latest::PublishCerts) -> Result<(), loga::Error>;

    /// Allow publishing with this identity via the public publish endpoint.
    async fn allow_identity(&self, identity: &Identity) -> Result<(), loga::Error>;
    async fn disallow_identity(&self, identity: &Identity) -> Result<(), loga::Error>;
    async fn is_identity_allowed(&self, identity: &Identity) -> Result<bool, loga::Error>;
    async fn list_allowed_identities(&self, after: Option<&Identity>) -> Result<Vec<Identity>, loga::Error>;

    /// Make data available to resolvers. This does two things: add it to the database,
    /// and trigger an initial announcement that this publisher is authoritative for
    /// the identity.
    async fn publish(
        &self,
        identity: &Identity,
        announcement: &node_protocol::PublisherAnnouncement,
        keyvalues: publish::latest::Publish,
    ) -> Result<(), loga::Error>;

    /// Make data unavailable to publishers and stop announcing authority for this
    /// identity.
    async fn unpublish(&self, identity: &Identity) -> Result<(), loga::Error>;
    async fn list_announcements(
        &self,
        after: Option<&Identity>,
    ) -> Result<Vec<(Identity, node_protocol::PublisherAnnouncement)>, loga::Error>;
    async fn get_published_data(&self, identity: &Identity) -> Result<Option<publish::Publish>, loga::Error>;
}

pub struct DbAdmin {
    db_pool: Pool,
}

impl DbAdmin {
    pub async fn new(db_path: &Path) -> Result<DbAdmin, loga::Error> {
        let db_pool =
            setup_db(&db_path.join("publisher_admin.sqlite3"), admin_db::migrate)
                .await
                .context("Error initializing database")?;
        return Ok(DbAdmin { db_pool: db_pool });
    }
}

#[async_trait]
impl Admin for DbAdmin {
    async fn retrieve_certs(&self) -> Result<Option<spagh_internal::latest::PublishCerts>, loga::Error> {
        let Some(found) = self.db_pool.get().await ?.interact(|conn| admin_db::get_certs(conn)).await ?? else {
            return Ok(None);
        };
        match found {
            crate::interface::spagh_internal::PublishCerts::V1(v1) => {
                return Ok(Some(v1));
            },
        }
    }

    async fn store_certs(&self, certs: &spagh_internal::latest::PublishCerts) -> Result<(), loga::Error> {
        let certs = certs.clone();
        return Ok(
            self
                .db_pool
                .get()
                .await?
                .interact(
                    move |conn| admin_db::ensure_certs(conn, &spagh_internal::PublishCerts::V1(certs.clone())),
                )
                .await??,
        );
    }

    async fn allow_identity(&self, identity: &Identity) -> Result<(), loga::Error> {
        let identity = identity.clone();
        self.db_pool.get().await?.interact(move |db| {
            admin_db::allow_identity(db, &identity)?;
            return Ok(()) as Result<(), GoodError>;
        }).await??;
        return Ok(());
    }

    async fn disallow_identity(&self, identity: &Identity) -> Result<(), loga::Error> {
        let identity = identity.clone();
        self.db_pool.get().await?.interact(move |db| {
            admin_db::disallow_identity(db, &identity)?;
            return Ok(()) as Result<(), GoodError>;
        }).await??;
        return Ok(());
    }

    async fn is_identity_allowed(&self, identity: &Identity) -> Result<bool, loga::Error> {
        let identity = identity.clone();
        return Ok(self.db_pool.get().await?.interact(move |db| {
            return Ok(admin_db::is_identity_allowed(db, &identity)?.is_some()) as Result<bool, GoodError>;
        }).await??);
    }

    async fn list_allowed_identities(&self, after: Option<&Identity>) -> Result<Vec<Identity>, loga::Error> {
        let after = after.cloned();
        return Ok(match after {
            None => {
                self.db_pool.get().await?.interact(|db| admin_db::list_allowed_identities_start(db)).await??
            },
            Some(a) => {
                self
                    .db_pool
                    .get()
                    .await?
                    .interact(move |db| admin_db::list_allowed_identities_after(db, &a))
                    .await??
            },
        });
    }

    async fn publish(
        &self,
        identity: &Identity,
        announcement: &node_protocol::PublisherAnnouncement,
        keyvalues: publish::latest::Publish,
    ) -> Result<(), loga::Error> {
        let identity = identity.clone();
        let announcement = announcement.clone();
        self.db_pool.get().await?.interact(move |db| {
            admin_db::set_announce(db, &identity, &announcement)?;
            admin_db::set_keyvalues(db, &identity, &publish::Publish::V1(keyvalues))
        }).await??;
        return Ok(());
    }

    async fn unpublish(&self, identity: &Identity) -> Result<(), loga::Error> {
        let identity = identity.clone();
        self.db_pool.get().await?.interact(move |db| {
            admin_db::delete_announce(db, &identity)?;
            admin_db::delete_keyvalues(db, &identity)
        }).await??;
        return Ok(());
    }

    async fn list_announcements(
        &self,
        after: Option<&Identity>,
    ) -> Result<Vec<(Identity, node_protocol::PublisherAnnouncement)>, loga::Error> {
        let after = after.cloned();
        return Ok(match after {
            None => {
                self
                    .db_pool
                    .get()
                    .await?
                    .interact(|db| admin_db::list_announce_start(db))
                    .await??
                    .into_iter()
                    .map(|p| (p.identity, p.value))
                    .collect()
            },
            Some(a) => {
                self
                    .db_pool
                    .get()
                    .await?
                    .interact(move |db| admin_db::list_announce_after(db, &a))
                    .await??
                    .into_iter()
                    .map(|p| (p.identity, p.value))
                    .collect()
            },
        });
    }

    async fn get_published_data(&self, identity: &Identity) -> Result<Option<publish::Publish>, loga::Error> {
        let identity = identity.clone();
        return Ok(self.db_pool.get().await?.interact(move |db| {
            admin_db::get_keyvalues(db, &identity)
        }).await??);
    }
}

struct PublisherInner<A: Admin> {
    log: Log,
    node: Node,
    cert_pub_hash: Vec<u8>,
    advertise_addr: SocketAddr,
    admin: A,
}

/// A publisher that stores data it publishes in a sqlite database, with methods
/// for maintaining this data.
pub struct Publisher<A: Admin = DbAdmin>(Arc<PublisherInner<A>>);

impl<A: Admin> Clone for Publisher<A> {
    fn clone(&self) -> Self {
        return Self(self.0.clone());
    }
}

impl<A: Admin + 'static> Publisher<A> {
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
        admin: A,
    ) -> Result<Publisher<A>, loga::Error> {
        let log = &log.fork(ea!(sys = "publisher"));

        // Prepare publisher certs for publisher-resolver communication
        let certs = match admin.retrieve_certs().await.log_context(log, "Error looking up certs")? {
            Some(c) => c,
            None => {
                let priv_key = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
                let self_spki = SubjectPublicKeyInfoOwned::from_key(*priv_key.verifying_key()).unwrap();
                let pub_key_der = CertificateBuilder::new(
                    Profile::Leaf {
                        issuer: RdnSequence::from_str(&"CN=unused").unwrap(),
                        enable_key_agreement: true,
                        enable_key_encipherment: true,
                    },
                    // Timestamp, 1h granularity (don't publish two issued within an hour/don't issue
                    // two within an hour)
                    SerialNumber::new(&[1u8]).unwrap(),
                    x509_cert::time::Validity {
                        not_before: Time::GeneralTime(
                            GeneralizedTime::from_date_time(der::DateTime::new(1970, 1, 1, 0, 0, 0).unwrap()),
                        ),
                        not_after: Time::GeneralTime(GeneralizedTime::from_date_time(der::DateTime::INFINITY)),
                    },
                    RdnSequence::from_str(&"CN=unused").unwrap(),
                    self_spki.clone(),
                    &priv_key,
                ).unwrap().build::<DerSignature>().unwrap().to_der().unwrap();
                let certs = spagh_internal::latest::PublishCerts {
                    pub_der: pub_key_der,
                    priv_der: priv_key.to_pkcs8_der().unwrap().as_bytes().to_vec(),
                };
                admin.store_certs(&certs).await.log_context(log, "Error persisting generated certs")?;
                certs
            },
        };
        let core = Publisher(Arc::new(PublisherInner {
            node: node.clone(),
            log: log.clone(),
            cert_pub_hash: publisher_cert_hash(&certs.pub_der).unwrap(),
            advertise_addr: advertise_addr,
            admin: admin,
        }));
        tm.critical_task({
            let tm1 = tm.clone();
            let log = log.fork(ea!(subsys = "protocol"));
            async move {
                let log = &log;
                match tm1
                    .if_alive(
                        Server::new(
                            TcpListener::bind(
                                bind_addr.resolve()?,
                            ).rustls(
                                RustlsConfig
                                ::new().fallback(
                                    RustlsCertificate::new()
                                        .key(encode_priv_pem(&certs.priv_der))
                                        .cert(encode_pub_pem(&certs.pub_der)),
                                ),
                            ),
                        ).run(get({
                            #[handler]
                            async fn ep(service: Data<&Publisher>, uri: &Uri) -> Response {
                                match async {
                                    let ident =
                                        Identity::from_str(uri.path().get(1..).unwrap_or(""))
                                            .context("Couldn't parse identity")
                                            .err_external()?;
                                    let mut kvs = resolve::latest::ResolveKeyValues(HashMap::new());
                                    if let Some(found_kvs) =
                                        service.0.0.admin.get_published_data(&ident).await.err_internal()? {
                                        let now = Utc::now();
                                        match found_kvs {
                                            publish::Publish::V1(mut found) => {
                                                for k in uri.query().unwrap_or("").split(",") {
                                                    if let Some(v) = found.data.remove(k) {
                                                        kvs.0.insert(k.to_string(), resolve::latest::ResolveValue {
                                                            expires: now + Duration::minutes(v.ttl as i64),
                                                            data: Some(v.data),
                                                        });
                                                    } else {
                                                        kvs.0.insert(k.to_string(), resolve::latest::ResolveValue {
                                                            expires: now + Duration::minutes(found.missing_ttl as i64),
                                                            data: None,
                                                        });
                                                    }
                                                }
                                            },
                                        }
                                    }
                                    return Ok(ResolveKeyValues::V1(kvs));
                                }.await {
                                    Ok(kvs) => poem::web::Json(kvs).into_response(),
                                    Err(e) => {
                                        match e {
                                            VisErr::Internal(e) => {
                                                service.0.0.log.warn_e(e, "Error processing request", ea!());
                                                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                                            },
                                            VisErr::External(e) => {
                                                return <String as IntoResponse>::with_status(
                                                    e.to_string(),
                                                    StatusCode::BAD_REQUEST,
                                                ).into_response();
                                            },
                                        }
                                    },
                                }
                            }

                            ep
                        })),
                    )
                    .await {
                    Some(r) => {
                        return r.log_context(log, "Exited with error");
                    },
                    None => {
                        return Ok(());
                    },
                }
            }
        });
        tm.periodic(Duration::hours(4).to_std().unwrap(), {
            let log = log.fork(ea!(subsys = "periodic_announce"));
            let core = core.clone();
            let node = node.clone();
            move || {
                let core = core.clone();
                let node = node.clone();
                let log = log.clone();
                return async move {
                    match async {
                        let mut after = None;
                        loop {
                            let announce_pairs = core.0.admin.list_announcements(after.as_ref()).await?;
                            let count = announce_pairs.len();
                            if count == 0 {
                                break;
                            }
                            for (i, (identity, announcement)) in announce_pairs.into_iter().enumerate() {
                                let value = match announcement {
                                    node_protocol::PublisherAnnouncement::V1(v) => v,
                                };
                                node.put(identity.clone(), value).await;
                                if i + 1 == count {
                                    after = Some(identity);
                                }
                            }
                        }
                        return Ok(());
                    }.await {
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

    pub async fn publish(
        &self,
        identity: &Identity,
        announcement: node_protocol::PublisherAnnouncement,
        keyvalues: publish::latest::Publish,
    ) -> Result<(), loga::Error> {
        self.0.admin.publish(identity, &announcement, keyvalues).await?;
        self.0.node.put(identity.clone(), match announcement {
            node_protocol::PublisherAnnouncement::V1(v) => v,
        }).await;
        return Ok(())
    }

    pub fn pub_cert_hash(&self) -> Vec<u8> {
        return self.0.cert_pub_hash.clone();
    }
}

pub fn build_api_endpoints(publisher: &Publisher) -> SystemEndpoints {
    return SystemEndpoints(Route::new().at("/publish", post({
        #[handler]
        async fn ep(Data(service): Data<&Publisher>, Json(req): Json<publish::PublishRequest>) -> Response {
            let req = match req {
                publish::PublishRequest::V1(r) => r,
            };
            match async {
                // Before db access, make sure the stated identity actually created the message
                let Ok(body) = req.content.verify(&req.identity) else {
                    return Ok(StatusCode::BAD_REQUEST.into_response());
                };

                // Check the identity is in the list of allowed to publish
                if !service.0.admin.is_identity_allowed(&req.identity).await? {
                    return Ok(StatusCode::UNAUTHORIZED.into_response());
                }

                // Publish it
                service.publish(&req.identity, body.announce, body.keyvalues).await?;
                return Ok(StatusCode::OK.into_response());
            }.await {
                Ok(r) => {
                    return r;
                },
                Err(e) => {
                    service.0.log.warn_e(e, "Error publishing key values", ea!(identity = req.identity));
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                },
            }
        }

        ep
    })).at("/unpublish", post({
        #[handler]
        async fn ep(Data(service): Data<&Publisher>, Json(body): Json<publish::UnpublishRequest>) -> Response {
            let req = match body {
                publish::UnpublishRequest::V1(body) => body,
            };
            match async {
                // Before db access, make sure the stated identity actually created the message
                let Ok(content) = req.content.verify(&req.identity) else {
                    return Ok(StatusCode::BAD_REQUEST.into_response());
                };

                // Check the identity is in the list of allowed to (un)publish
                if !service.0.admin.is_identity_allowed(&req.identity).await? {
                    return Ok(StatusCode::UNAUTHORIZED.into_response());
                }

                // Check that the message is recent to discourage repeat attacks
                if content.now + Duration::seconds(10) < Utc::now() {
                    return Ok(StatusCode::BAD_REQUEST.into_response());
                }

                // The request is by the identity and the identity recently made the request - do
                // the unpublish.
                service.0.admin.unpublish(&req.identity).await?;
                return Ok(StatusCode::OK.into_response());
            }.await {
                Ok(r) => {
                    return r;
                },
                Err(e) => {
                    service.0.log.warn_e(e, "Error deleting published data", ea!(identity = req.identity));
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                },
            }
        }

        ep
    })).at("/info", get({
        #[handler]
        async fn ep(service: Data<&Publisher>) -> Response {
            return Json(InfoResponse {
                advertise_addr: service.0.0.advertise_addr,
                cert_pub_hash: service.0.0.cert_pub_hash.clone(),
            }).into_response();
        }

        ep
    })).nest("/admin", Route::new().at("/admin/allowed_identities", get({
            #[derive(Debug, Deserialize)]
            struct Params {
                after: Option<String>,
            }

            #[handler]
            async fn ep(Data(service): Data<&Publisher>, query: Query<Params>) -> Response {
                match async {
                    let after = match &query.after {
                        Some(i) => {
                            Some(Identity::from_str(i)?)
                        },
                        None => None,
                    };
                    return Ok(service.0.admin.list_allowed_identities(after.as_ref()).await?);
                }.await {
                    Ok(d) => {
                        return Json(d).into_response();
                    },
                    Err(e) => {
                        service.0.log.warn_e(e, "Error getting published identities", ea!());
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    },
                }
            }

            ep
        })).at("/admin/allowed_identities/:identity", post({
            #[handler]
            async fn ep(Data(service): Data<&Publisher>, web::Path(identity): web::Path<String>) -> Response {
                match async {
                    let identity = Identity::from_str(&identity)?;
                    return Ok(service.0.admin.allow_identity(&identity).await?);
                }.await {
                    Ok(d) => {
                        return Json(d).into_response();
                    },
                    Err(e) => {
                        service.0.log.warn_e(e, "Error registering identity for publishing", ea!());
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    },
                }
            }

            ep
        }).delete({
            #[handler]
            async fn ep(Data(service): Data<&Publisher>, web::Path(identity): web::Path<String>) -> Response {
                match async {
                    let identity = Identity::from_str(&identity)?;
                    return Ok(service.0.admin.disallow_identity(&identity).await?);
                }.await {
                    Ok(d) => {
                        return Json(d).into_response();
                    },
                    Err(e) => {
                        service.0.log.warn_e(e, "Error unregistering identity for publishing", ea!());
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    },
                }
            }

            ep
        }))
        // Announced identities
        .at("/admin/announcements", get({
            #[derive(Debug, Deserialize)]
            struct Params {
                after: Option<String>,
            }

            #[handler]
            async fn ep(Data(service): Data<&Publisher>, Query(query): Query<Params>) -> Response {
                match async {
                    let after = match query.after {
                        Some(i) => {
                            Some(Identity::from_str(&i)?)
                        },
                        None => None,
                    };
                    return Ok(
                        service
                            .0
                            .admin
                            .list_announcements(after.as_ref())
                            .await?
                            .into_iter()
                            .map(|e| e.0)
                            .collect::<Vec<_>>(),
                    );
                }.await {
                    Ok(d) => {
                        return Json(d).into_response();
                    },
                    Err(e) => {
                        service.0.log.warn_e(e, "Error getting published identities", ea!());
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    },
                }
            }

            ep
        })).at("/admin/announcements/:identity", get({
            #[handler]
            async fn ep(Data(service): Data<&Publisher>, web::Path(identity): web::Path<String>) -> Response {
                match async {
                    let identity = Identity::from_str(&identity)?;
                    return Ok(service.0.admin.get_published_data(&identity).await?);
                }.await {
                    Ok(d) => {
                        return Json(d).into_response();
                    },
                    Err(e) => {
                        service.0.log.warn_e(e, "Error getting published identity data", ea!());
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    },
                }
            }

            ep
        }))).with(AddData::new(publisher.clone())).boxed());
}
