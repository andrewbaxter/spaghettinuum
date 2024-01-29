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
    DebugDisplay,
    ResultContext,
};
use poem::{
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
    cap_fn,
    interface::{
        config::shared::StrSocketAddr,
        stored::{
            self,
            announcement::Announcement,
            identity::Identity,
        },
        wire,
    },
    node::{
        Node,
    },
    ta_res,
    ta_vis_res,
    utils::{
        blob::{
            Blob,
            ToBlob,
        },
        db_util::{
            setup_db,
            DbTx,
        },
        htserve::{
            Routes,
            Leaf,
            Response,
        },
        log::{
            Log,
            DEBUG_PUBLISH,
            WARN,
        },
        signed::IdentSignatureMethods,
        tls_util::{
            encode_priv_pem,
            encode_pub_pem,
        },
        ResultVisErr,
        VisErr,
    },
};

pub mod db;
pub mod admin_db;

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

struct PublisherInner {
    log: Log,
    node: Node,
    cert_pub_hash: Blob,
    advertise_addr: SocketAddr,
    db_pool: Pool,
}

/// A publisher that stores data it publishes in a sqlite database, with methods
/// for maintaining this data.
pub struct Publisher(Arc<PublisherInner>);

impl Clone for Publisher {
    fn clone(&self) -> Self {
        return Self(self.0.clone());
    }
}

impl Publisher {
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
        persistent_dir: &Path,
    ) -> Result<Publisher, loga::Error> {
        let log = &log.fork(ea!(sys = "publisher"));
        let db_pool =
            setup_db(&persistent_dir.join("publisher.sqlite3"), db::migrate)
                .await
                .stack_context(log, "Error initializing database")?;

        // Prepare publisher certs for publisher-resolver communication
        let certs = {
            match db_pool
                .tx(|conn| Ok(db::get_certs(conn)?))
                .await
                .stack_context(log, "Error looking up certs")? {
                Some(c) => match c {
                    stored::publisher::Certs::V1(v1) => {
                        v1
                    },
                },
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
                    let certs = stored::publisher::latest::Certs {
                        pub_der: pub_key_der,
                        priv_der: priv_key.to_pkcs8_der().unwrap().as_bytes().blob(),
                    };
                    db_pool.tx({
                        let certs = certs.clone();
                        move |conn| Ok(db::ensure_certs(conn, &stored::publisher::Certs::V1(certs.clone()))?)
                    }).await.stack_context(log, "Error persisting generated certs")?;
                    certs
                },
            }
        };
        let publisher = Publisher(Arc::new(PublisherInner {
            node: node.clone(),
            log: log.clone(),
            cert_pub_hash: publisher_cert_hash(&certs.pub_der).unwrap(),
            advertise_addr: advertise_addr,
            db_pool: db_pool,
        }));
        tm.critical_task("Publisher - network server", {
            let log = log.fork(ea!(subsys = "wirecol"));
            let mut routes = Routes::new();
            let tm = tm.clone();
            routes.add("", Leaf::new().get(cap_fn!((mut r)(publisher, log) {
                match async {
                    ta_vis_res!(Response);
                    log.log_with(DEBUG_PUBLISH, "Recieved request", ea!(path = r.path.dbg_str()));

                    // Params
                    let Some(ident) = r.path.pop() else {
                        return Ok(Response::user_err("Missing identity in path"));
                    };
                    let ident = Identity::from_str(&ident).context("Couldn't parse identity").err_external()?;

                    // Respond
                    return Ok(
                        Response::json(
                            publisher
                                .get_values(&ident, r.query.split(",").map(|k| k.to_string()).collect())
                                .await
                                .err_internal()?,
                        ),
                    );
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
                        let announce_pairs = publisher.list_announcements(after.as_ref()).await?;
                        let count = announce_pairs.len();
                        if count == 0 {
                            break;
                        }
                        for (i, (identity, announcement)) in announce_pairs.into_iter().enumerate() {
                            let accepted = node.put(identity.clone(), announcement.clone()).await;
                            if let Some(accepted) = accepted {
                                match accepted {
                                    Announcement::V1(accepted) => {
                                        let have_published = match &announcement {
                                            Announcement::V1(a) => a.parse_unwrap().published,
                                        };
                                        if accepted.parse_unwrap().published > have_published {
                                            // Newer announcement published elsewhere, delete this announcement to save some
                                            // network effort
                                            publisher.clear_identity(&identity).await.log(&log, WARN, "Error deleting obsolete announcement");
                                        }
                                    },
                                }
                            }
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

    pub fn pub_cert_hash(&self) -> Blob {
        return self.0.cert_pub_hash.clone();
    }

    pub async fn announce(
        &self,
        identity: &Identity,
        announcement: stored::announcement::Announcement,
    ) -> Result<(), loga::Error> {
        let accepted = self.0.node.put(identity.clone(), announcement.clone()).await;
        match accepted {
            Some(accepted) => {
                let new_published = match &announcement {
                    Announcement::V1(a) => a.parse_unwrap().published,
                };
                let accepted_published = match accepted {
                    Announcement::V1(a) => a.parse_unwrap().published,
                };
                if accepted_published > new_published {
                    return Ok(());
                }
            },
            None => (),
        }
        self.0.db_pool.tx({
            let identity = identity.clone();
            let announcement = announcement.clone();
            move |db| Ok(db::set_announce(db, &identity, &announcement)?)
        }).await?;
        return Ok(())
    }

    pub async fn clear_identity(&self, identity: &Identity) -> Result<(), loga::Error> {
        self.0.db_pool.tx({
            let identity = identity.clone();
            move |db| {
                db::delete_announce(db, &identity)?;
                db::values_delete_all(db, &identity)?;
                return Ok(());
            }
        }).await?;
        return Ok(());
    }

    pub async fn list_announcements(
        &self,
        after: Option<&Identity>,
    ) -> Result<Vec<(Identity, Announcement)>, loga::Error> {
        let after = after.cloned();
        return Ok(match after {
            None => {
                let res =
                    self
                        .0
                        .db_pool
                        .tx(move |db| Ok(db::list_announce_start(db)?))
                        .await?
                        .into_iter()
                        .map(|p| (p.identity, p.value))
                        .collect();
                res
            },
            Some(a) => {
                self
                    .0
                    .db_pool
                    .tx(move |db| Ok(db::list_announce_after(db, &a)?))
                    .await?
                    .into_iter()
                    .map(|p| (p.identity, p.value))
                    .collect()
            },
        });
    }

    pub async fn modify_values(
        &self,
        identity: &Identity,
        args: wire::api::publish::latest::PublishRequestContent,
    ) -> Result<(), loga::Error> {
        self.0.db_pool.tx({
            let identity = identity.clone();
            move |db| {
                if let Some(missing_ttl) = args.missing_ttl {
                    db::ident_set(db, &identity, missing_ttl as i64)?;
                }
                if args.clear_all {
                    db::values_delete_all(db, &identity)?;
                }
                for k in args.clear {
                    db::values_delete(db, &identity, &k)?;
                }
                for (k, v) in args.set {
                    db::values_set(db, &identity, &k, &v)?;
                }
                return Ok(());
            }
        }).await?;
        return Ok(());
    }

    async fn get_values(
        &self,
        identity: &Identity,
        keys: Vec<String>,
    ) -> Result<wire::resolve::ResolveKeyValues, loga::Error> {
        let identity = identity.clone();
        return Ok(self.0.db_pool.tx(move |db| {
            let mut out = HashMap::new();
            let missing_ttl = db::ident_get(db, &identity)?.unwrap_or_else(|| 5);
            let now = Utc::now();
            for k in keys {
                let expires;
                let data;
                match db::values_get(db, &identity, &k)? {
                    Some(v) => match v {
                        stored::record::RecordValue::V1(v) => {
                            expires = now + Duration::minutes(v.ttl as i64);
                            data = v.data;
                        },
                    },
                    None => {
                        expires = now + Duration::minutes(missing_ttl as i64);
                        data = None;
                    },
                }
                out.insert(k, wire::resolve::v1::ResolveValue {
                    expires: expires,
                    data: data,
                });
            }
            return Ok(wire::resolve::ResolveKeyValues::V1(out));
        }).await?);
    }

    async fn list_value_keys(
        &self,
        identity: &Identity,
        after: Option<String>,
    ) -> Result<Vec<String>, loga::Error> {
        let identity = identity.clone();
        return Ok(self.0.db_pool.tx(move |conn| match after {
            Some(v) => {
                return Ok(db::values_keys_list_after(conn, &identity, &v)?);
            },
            None => {
                return Ok(db::values_keys_list_start(conn, &identity)?);
            },
        }).await?);
    }
}

pub async fn build_api_endpoints(
    publisher: &Publisher,
    admin_token: Option<&String>,
    persist_dir: &Path,
) -> Result<Routes, loga::Error> {
    let db_pool =
        setup_db(&persist_dir.join("publisher_admin.sqlite3"), admin_db::migrate)
            .await
            .context("Error initializing database")?;

    struct State {
        db_pool: Pool,
        publisher: Publisher,
    }

    impl State {
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
    }

    let state = Arc::new(State {
        db_pool: db_pool,
        publisher: publisher.clone(),
    });
    let mut routes = Routes::new();
    routes.nest("v1", {
        let mut routes = Routes::new();
        routes.add("announce", Leaf::new().post(cap_fn!((r)(state) {
            match async {
                ta_res!(Response);

                // Params
                let req = match serde_json::from_slice::<wire::api::publish::v1::AnnounceRequest>(&r.body) {
                    Ok(r) => r,
                    Err(e) => {
                        return Ok(Response::user_err(format!("Invalid json: {}", e))) as Result<_, loga::Error>;
                    },
                };
                match &req.announcement {
                    Announcement::V1(a) => {
                        let Ok(_) = a.verify(&req.identity) else {
                            return Ok(Response::user_err("Couldn't verify payload"));
                        };
                    },
                };

                // Auth
                if !state.is_identity_allowed(&req.identity).await? {
                    return Ok(Response::AuthErr);
                }

                // Publish it
                state.publisher.announce(&req.identity, req.announcement).await?;
                return Ok(Response::Ok);
            }.await {
                Ok(r) => {
                    return r;
                },
                Err(e) => {
                    state.publisher.0.log.log_err(WARN, e.context("Error publishing key values"));
                    return Response::InternalErr;
                },
            }
        }))).add("clear_identity", Leaf::new().post(cap_fn!((r)(state) {
            match async {
                ta_res!(Response);

                // Params
                let req = match serde_json::from_slice::<wire::api::publish::v1::DeleteAnnouncementRequest>(&r.body) {
                    Ok(r) => r,
                    Err(e) => {
                        return Ok(Response::user_err(format!("Invalid json: {}", e))) as Result<_, loga::Error>;
                    },
                };
                let Ok(_) = req.challenge.verify(&req.identity) else {
                    return Ok(Response::user_err("Couldn't verify payload"));
                };

                // Auth
                if !state.is_identity_allowed(&req.identity).await? {
                    return Ok(Response::AuthErr);
                }

                // Respond
                state.publisher.clear_identity(&req.identity).await?;
                return Ok(Response::Ok);
            }.await {
                Ok(r) => {
                    return r;
                },
                Err(e) => {
                    state.publisher.0.log.log_err(WARN, e.context("Error unpublishing key values"));
                    return Response::InternalErr;
                },
            }
        }))).add("publish", Leaf::new().post(cap_fn!((r)(state) {
            match async {
                ta_res!(Response);

                // Params
                let req = match serde_json::from_slice::<wire::api::publish::v1::PublishRequest>(&r.body) {
                    Ok(r) => r,
                    Err(e) => {
                        return Ok(Response::user_err(format!("Invalid json: {}", e))) as Result<_, loga::Error>;
                    },
                };
                let Ok(body) = req.content.verify(&req.identity) else {
                    return Ok(Response::user_err("Couldn't verify payload"));
                };

                // Auth
                if !state.is_identity_allowed(&req.identity).await? {
                    return Ok(Response::AuthErr);
                }

                // Publish it
                state.publisher.modify_values(&req.identity, body).await?;
                return Ok(Response::Ok);
            }.await {
                Ok(r) => {
                    return r;
                },
                Err(e) => {
                    state.publisher.0.log.log_err(WARN, e.context("Error publishing key values"));
                    return Response::InternalErr;
                },
            }
        })));
        routes.add("info", Leaf::new().get(cap_fn!((_r)(state) {
            // Respond
            return Response::json(wire::api::publish::v1::InfoResponse {
                advertise_addr: state.publisher.0.advertise_addr,
                cert_pub_hash: state.publisher.0.cert_pub_hash.clone(),
            });
        })));
        routes
    });
    if let Some(admin_token) = admin_token {
        routes.nest("admin", {
            let admin_token = auth_hash(admin_token);
            let mut routes = Routes::new();
            routes.add("allowed_identities", Leaf::new().get(cap_fn!((r)(state, admin_token) {
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
                    return Ok(Response::json(state.list_allowed_identities(after.as_ref()).await?));
                }.await {
                    Ok(d) => {
                        return d;
                    },
                    Err(e) => {
                        state.publisher.0.log.log_err(WARN, e.context("Error getting published identities"));
                        return Response::InternalErr;
                    },
                }
            })).post(cap_fn!((mut r)(state, admin_token) {
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
                    return Ok(Response::json(state.allow_identity(&identity).await?));
                }.await {
                    Ok(d) => {
                        return d;
                    },
                    Err(e) => {
                        state.publisher.0.log.log_err(WARN, e.context("Error registering identity for publishing"));
                        return Response::InternalErr;
                    },
                }
            })).delete(cap_fn!((mut r)(state, admin_token) {
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
                    state.disallow_identity(&identity).await?;
                    state.publisher.clear_identity(&identity).await?;
                    return Ok(Response::Ok);
                }.await {
                    Ok(d) => {
                        return d;
                    },
                    Err(e) => {
                        state
                            .publisher
                            .0
                            .log
                            .log_err(WARN, e.context("Error unregistering identity for publishing"));
                        return Response::InternalErr;
                    },
                }
            })));
            routes.add("keys", Leaf::new().get(cap_fn!((mut r)(state, admin_token) {
                // Auth
                if !auth(&admin_token, &r.auth_bearer) {
                    return Response::AuthErr;
                }
                match async {
                    ta_res!(Response);
                    let Some(identity) = r.path.pop() else {
                        return Ok(Response::user_err("Missing identity in path"));
                    };
                    let identity = Identity::from_str(&identity)?;

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

                    // Respond
                    return Ok(Response::json(state.publisher.list_value_keys(&identity, query.after).await?));
                }.await {
                    Ok(d) => {
                        return d;
                    },
                    Err(e) => {
                        state.publisher.0.log.log_err(WARN, e.context("Error getting published keys for identity"));
                        return Response::InternalErr;
                    },
                }
            })));
            routes.add("announcements", Leaf::new().get(cap_fn!((r)(state, admin_token) {
                // Auth
                if !auth(&admin_token, &r.auth_bearer) {
                    return Response::AuthErr;
                }
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
                            state
                                .publisher
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
                        state.publisher.0.log.log_err(WARN, e.context("Error getting published identities"));
                        return Response::InternalErr;
                    },
                }
            })));
            routes
        });
    }
    return Ok(routes);
}
