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
    ea,
    ResultContext,
};
use poem::{
    async_trait,
    Server,
    listener::{
        TcpListener,
        RustlsConfig,
        RustlsCertificate,
        Listener,
    },
};
use serde::{
    Deserialize,
    Serialize,
    de::DeserializeOwned,
};
use sha2::Sha256;
use taskmanager::TaskManager;
use tokio::select;
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
        VisErr,
        ResultVisErr,
        db_util::setup_db,
        tls_util::{
            encode_priv_pem,
            encode_pub_pem,
        },
        backed_identity::IdentitySigner,
        blob::{
            Blob,
            ToBlob,
        },
        log::{
            Log,
            WARN,
        },
        htserve::{
            Routes,
            Leaf,
            Response,
        },
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
    ta_res,
    ta_vis_res,
    cap_fn,
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
    pub_der: Blob,
    priv_der: Blob,
}

pub fn publisher_cert_hash(cert_der: &[u8]) -> Result<Blob, ()> {
    return Ok(
        <Sha256 as Digest>::digest(
            Certificate::from_der(&cert_der)
                .map_err(|_| ())?
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .map_err(|_| ())?,
        ).blob(),
    );
}

pub fn auth_hash(s: &str) -> Blob {
    return <Sha256 as Digest>::digest(s.as_bytes()).blob();
}

pub fn auth(want: &[u8], got: &Option<String>) -> bool {
    let Some(got) = got.as_ref() else {
        return false;
    };
    return auth_hash(got).as_ref() == want;
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
                let outer = self.db_pool.get().await?;
                let res = outer.interact(|db| {
                    let out = admin_db::list_announce_start(db);
                    out
                }).await??.into_iter().map(|p| (p.identity, p.value)).collect();
                res
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
    cert_pub_hash: Blob,
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
        let certs = match admin.retrieve_certs().await.stack_context(log, "Error looking up certs")? {
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
                ).unwrap().build::<DerSignature>().unwrap().to_der().unwrap().blob();
                let certs = spagh_internal::latest::PublishCerts {
                    pub_der: pub_key_der,
                    priv_der: priv_key.to_pkcs8_der().unwrap().as_bytes().blob(),
                };
                admin.store_certs(&certs).await.stack_context(log, "Error persisting generated certs")?;
                certs
            },
        };
        let publisher = Publisher(Arc::new(PublisherInner {
            node: node.clone(),
            log: log.clone(),
            cert_pub_hash: publisher_cert_hash(&certs.pub_der).unwrap(),
            advertise_addr: advertise_addr,
            admin: admin,
        }));
        tm.critical_task("Publisher - network server", {
            let log = log.fork(ea!(subsys = "protocol"));
            let mut routes = Routes::new();
            let tm = tm.clone();
            routes.add("", Leaf::new().get(cap_fn!((mut r)(publisher) {
                match async {
                    ta_vis_res!(Response);

                    // Params
                    let Some(ident) = r.path.pop() else {
                        return Ok(Response::user_err("Missing identity in path"));
                    };
                    let ident = Identity::from_str(&ident).context("Couldn't parse identity").err_external()?;

                    // Respond
                    let mut kvs = resolve::latest::ResolveKeyValues(HashMap::new());
                    if let Some(found_kvs) = publisher.0.admin.get_published_data(&ident).await.err_internal()? {
                        let now = Utc::now();
                        match found_kvs {
                            publish::Publish::V1(mut found) => {
                                for k in r.query.split(",") {
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
                    return Ok(Response::json(ResolveKeyValues::V1(kvs)));
                }.await {
                    Ok(r) => r,
                    Err(e) => {
                        match e {
                            VisErr::Internal(e) => {
                                publisher.0.log.log_err(WARN, e.context("Error processing request"));
                                return Response::InternalErr;
                            },
                            VisErr::External(e) => {
                                return Response::external_err(e.to_string());
                            },
                        }
                    },
                }
            })));
            async move {
                let server =
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
                    ).run(routes.build(log.fork(ea!(subsys = "router"))));

                select!{
                    _ = tm.until_terminate() => {
                        return Ok(());
                    }
                    r = server => {
                        return r.stack_context(&log, "Exited with error");
                    }
                }
            }
        });
        tm.periodic("Publisher - periodic announce", Duration::hours(4).to_std().unwrap(), {
            let log = log.fork(ea!(subsys = "periodic_announce"));
            cap_fn!(()(log, publisher, node) {
                match async {
                    ta_res!(());
                    let mut after = None;
                    loop {
                        let announce_pairs = publisher.0.admin.list_announcements(after.as_ref()).await?;
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
                        log.log_err(WARN, e.context("Error while re-announcing publishers"));
                    },
                }
            })
        });
        return Ok(publisher);
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

    pub fn pub_cert_hash(&self) -> Blob {
        return self.0.cert_pub_hash.clone();
    }
}

pub fn build_api_endpoints(publisher: &Publisher, admin_token: &str) -> Result<Routes, loga::Error> {
    let mut routes = Routes::new();
    routes.add("publish", Leaf::new().post(cap_fn!((r)(publisher) {
        match async {
            ta_res!(Response);

            // Params
            let req = match serde_json::from_slice(&r.body) {
                Ok(r) => r,
                Err(e) => {
                    return Ok(Response::user_err(format!("Invalid json: {}", e))) as Result<_, loga::Error>;
                },
            };
            let req = match req {
                publish::PublishRequest::V1(r) => r,
            };
            let Ok(body) = req.content.verify(&req.identity) else {
                return Ok(Response::user_err("Couldn't verify payload"));
            };

            // Auth
            if !publisher.0.admin.is_identity_allowed(&req.identity).await? {
                return Ok(Response::AuthErr);
            }

            // Publish it
            publisher.publish(&req.identity, body.announce, body.keyvalues).await?;
            return Ok(Response::Ok);
        }.await {
            Ok(r) => {
                return r;
            },
            Err(e) => {
                publisher.0.log.log_err(WARN, e.context("Error publishing key values"));
                return Response::InternalErr;
            },
        }
    })));
    routes.add("unpublish", Leaf::new().post(cap_fn!((r)(publisher) {
        match async {
            ta_res!(Response);

            // Params
            let req = match serde_json::from_slice(&r.body) {
                Ok(r) => r,
                Err(e) => {
                    return Ok(Response::user_err(format!("Invalid json: {}", e))) as Result<_, loga::Error>;
                },
            };
            let req = match req {
                publish::UnpublishRequest::V1(body) => body,
            };
            let Ok(content) = req.content.verify(&req.identity) else {
                return Ok(Response::user_err("Couldn't verify payload"));
            };
            if content.now + Duration::seconds(10) < Utc::now() {
                return Ok(Response::user_err("Expired request"));
            }

            // Auth
            if !publisher.0.admin.is_identity_allowed(&req.identity).await? {
                return Ok(Response::AuthErr);
            }

            // Respond
            publisher.0.admin.unpublish(&req.identity).await?;
            return Ok(Response::Ok);
        }.await {
            Ok(r) => {
                return r;
            },
            Err(e) => {
                publisher.0.log.log_err(WARN, e.context("Error unpublishing key values"));
                return Response::InternalErr;
            },
        }
    })));
    routes.add("info", Leaf::new().get(cap_fn!((_r)(publisher) {
        // Respond
        return Response::json(InfoResponse {
            advertise_addr: publisher.0.advertise_addr,
            cert_pub_hash: publisher.0.cert_pub_hash.clone(),
        });
    })));
    routes.nest("admin", {
        let admin_token = auth_hash(admin_token);
        let mut routes = Routes::new();
        routes.add("allowed_identities", Leaf::new().get(cap_fn!((r)(publisher, admin_token) {
            match async {
                ta_res!(Response);

                // Auth
                if !auth(&admin_token, &r.auth_bearer) {
                    return Ok(Response::AuthErr);
                }

                // Check params
                #[derive(Debug, Deserialize)]
                struct Params {
                    after: Option<String>,
                }

                let query = match serde_urlencoded::from_str::<Params>(&r.query) {
                    Ok(q) => q,
                    Err(e) => {
                        return Ok(Response::user_err(format!("Invalid query parameters: {}", e)));
                    },
                };
                let after = match &query.after {
                    Some(i) => {
                        Some(Identity::from_str(i)?)
                    },
                    None => None,
                };

                // Respond
                return Ok(Response::json(publisher.0.admin.list_allowed_identities(after.as_ref()).await?));
            }.await {
                Ok(d) => {
                    return d;
                },
                Err(e) => {
                    publisher.0.log.log_err(WARN, e.context("Error getting published identities"));
                    return Response::InternalErr;
                },
            }
        })).post(cap_fn!((mut r)(publisher, admin_token) {
            match async {
                ta_res!(Response);

                // Auth
                if !auth(&admin_token, &r.auth_bearer) {
                    return Ok(Response::AuthErr);
                }

                // Check params
                ta_res!(Response);
                let Some(identity) = r.path.pop() else {
                    return Ok(Response::user_err("Missing identity in path"));
                };
                let identity = Identity::from_str(&identity)?;

                // Respond
                return Ok(Response::json(publisher.0.admin.allow_identity(&identity).await?));
            }.await {
                Ok(d) => {
                    return d;
                },
                Err(e) => {
                    publisher.0.log.log_err(WARN, e.context("Error registering identity for publishing"));
                    return Response::InternalErr;
                },
            }
        })).delete(cap_fn!((mut r)(publisher, admin_token) {
            match async {
                ta_res!(Response);

                // Auth
                if !auth(&admin_token, &r.auth_bearer) {
                    return Ok(Response::AuthErr);
                }

                // Check params
                ta_res!(Response);
                let Some(identity) = r.path.pop() else {
                    return Ok(Response::user_err("Missing identity in path"));
                };
                let identity = Identity::from_str(&identity)?;

                // Respond
                return Ok(Response::json(publisher.0.admin.disallow_identity(&identity).await?));
            }.await {
                Ok(d) => {
                    return d;
                },
                Err(e) => {
                    publisher.0.log.log_err(WARN, e.context("Error unregistering identity for publishing"));
                    return Response::InternalErr;
                },
            }
        })));
        routes.add("announcements", Leaf::new().get(cap_fn!((mut r)(publisher, admin_token) {
            // Auth
            if !auth(&admin_token, &r.auth_bearer) {
                return Response::AuthErr;
            }
            if let Some(identity) = r.path.pop() {
                match async {
                    ta_res!(Response);
                    let identity = Identity::from_str(&identity)?;

                    // Respond
                    return Ok(Response::json(publisher.0.admin.get_published_data(&identity).await?));
                }.await {
                    Ok(d) => {
                        return d;
                    },
                    Err(e) => {
                        publisher.0.log.log_err(WARN, e.context("Error getting published identity data"));
                        return Response::InternalErr;
                    },
                }
            } else {
                match async {
                    ta_res!(Response);

                    #[derive(Debug, Deserialize)]
                    struct Params {
                        after: Option<String>,
                    }

                    let query = match serde_urlencoded::from_str::<Params>(&r.query) {
                        Ok(q) => q,
                        Err(e) => {
                            return Ok(Response::UserErr(format!("Invalid query parameters: {}", e)));
                        },
                    };
                    let after = match query.after {
                        Some(i) => {
                            Some(Identity::from_str(&i)?)
                        },
                        None => None,
                    };

                    // Respond
                    return Ok(
                        Response::json(
                            publisher
                                .0
                                .admin
                                .list_announcements(after.as_ref())
                                .await?
                                .into_iter()
                                .map(|e| e.0)
                                .collect::<Vec<_>>(),
                        ),
                    );
                }.await {
                    Ok(d) => {
                        return d;
                    },
                    Err(e) => {
                        publisher.0.log.log_err(WARN, e.context("Error getting published identities"));
                        return Response::InternalErr;
                    },
                }
            }
        })));
        routes
    });
    return Ok(routes);
}
