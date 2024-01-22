use chrono::{
    Utc,
    DateTime,
};
use itertools::Itertools;
use loga::{
    ea,
    ResultContext,
    DebugDisplay,
};
use openpgp_card_pcsc::PcscBackend;
use openpgp_card_sequoia::{
    state::Open,
    Card,
};
use poem::{
    http::{
        Uri,
        uri::Authority,
    },
};
use rand::{
    distributions::{
        Alphanumeric,
        DistString,
    },
};
use serde::de::DeserializeOwned;
use serde_json::json;
use spaghettinuum::{
    config::{
        Config,
        SelfIdentityConfig,
        GlobalAddrConfig,
        self,
    },
    node::{
        config::{
            BootstrapConfig,
            NodeConfig,
        },
        IdentSignatureMethods,
    },
    utils::{
        log::{
            Flags,
            NON_DEBUG,
            DEBUG_OTHER,
            WARN,
            Log,
        },
        backed_identity::{
            get_identity_signer,
        },
        pgp::{
            self,
        },
        local_identity::write_identity,
        tls_util::{
            encode_priv_pem,
            extract_expiry,
        },
        ip_util::{
            local_resolve_global_ip,
            remote_resolve_global_ip,
        },
        htreq,
    },
    interface::{
        spagh_cli::{
            ENV_API_ADDR,
            BackedIdentityLocal,
            BackedIdentityArg,
            StrSocketAddr,
            PORT_NODE,
            ENV_API_ADMIN_TOKEN,
            PORT_PUBLISHER,
            ENV_API_ADMIN_ADDR,
        },
        node_protocol::{
            self,
            latest::SerialAddr,
        },
        spagh_api::{
            publish::{
                self,
                latest::JsonSignature,
            },
            resolve::{
                KEY_DNS_TXT,
                KEY_DNS_AAAA,
                KEY_DNS_A,
                KEY_DNS_CNAME,
                self,
            },
        },
        identity::Identity,
        node_identity::NodeIdentity,
    },
    self_tls::{
        request_cert,
        certifier_url,
    },
    publisher::PublishIdentSignatureMethods,
};
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use std::{
    collections::HashMap,
    env::{
        current_dir,
        self,
    },
    str::FromStr,
};

mod args {
    use std::{
        path::PathBuf,
    };
    use aargvark::{
        Aargvark,
        AargvarkJson,
    };
    use poem::http::Uri;
    use spaghettinuum::{
        interface::{
            spagh_cli::{
                BackedIdentityArg,
                BackedIdentityLocal,
            },
            spagh_api::publish,
        },
        config::GlobalAddrConfig,
    };

    #[derive(Aargvark)]
    pub struct NewLocalIdentity {
        /// Store the new id and secret in a file at this path
        pub path: PathBuf,
    }

    #[derive(Aargvark)]
    pub struct AllowIdentity {
        /// Private/admin URL of a server with publishing set up. Defaults to the value of
        /// environment variable `SPAGH_ADMIN`.
        pub server: Option<Uri>,
        pub identity_id: String,
    }

    #[derive(Aargvark)]
    pub struct DisallowIdentity {
        /// Private/admin URL of a server with publishing set up. Defaults to the value of
        /// environment variable `SPAGH_ADMIN`.
        pub server: Option<Uri>,
        pub identity_id: String,
    }

    #[derive(Aargvark)]
    pub struct ListAllowedIdentities {
        /// Private/admin URL of a server with publishing set up. Defaults to the value of
        /// environment variable `SPAGH_ADMIN`.
        pub server: Option<Uri>,
        pub identity_id: String,
    }

    #[derive(Aargvark)]
    pub struct Publish {
        /// URL of a server with publishing set up. Defaults to the value of environment
        /// variable `SPAGH_ADMIN`.
        pub server: Option<Uri>,
        /// Identity to publish as
        pub identity: BackedIdentityArg,
        /// Data to publish.  Must be json in the structure
        /// `{KEY: {"ttl": SECONDS, "value": "DATA"}, ...}`
        pub data: AargvarkJson<publish::latest::Publish>,
    }

    #[derive(Aargvark)]
    pub struct PublishDns {
        /// URL of a server with publishing set up. Defaults to the value of environment
        /// variable `SPAGH_ADMIN`.
        pub server: Option<Uri>,
        /// Identity to publish as
        pub identity: BackedIdentityArg,
        pub ttl: u32,
        pub dns_cname: Vec<String>,
        pub dns_a: Vec<String>,
        pub dns_aaaa: Vec<String>,
        pub dns_txt: Vec<String>,
    }

    #[derive(Aargvark)]
    pub struct SelfPublish {
        /// URL of a server with publishing set up. Defaults to the value of environment
        /// variable `SPAGH_ADMIN`.
        pub server: Option<Uri>,
        /// How to detect the public ip to publish
        pub addr: GlobalAddrConfig,
        /// Identity to publish address under
        pub identity: BackedIdentityArg,
    }

    #[derive(Aargvark)]
    pub struct Unpublish {
        /// URL of a server with publishing set up. Defaults to the value of environment
        /// variable `SPAGH_ADMIN`.
        pub server: Option<Uri>,
        pub identity: BackedIdentityArg,
    }

    #[derive(Aargvark)]
    pub struct ListPublishingIdentities {
        /// URL of a server with publishing set up. Defaults to the value of environment
        /// variable `SPAGH_ADMIN`.
        pub server: Option<Uri>,
    }

    #[derive(Aargvark)]
    pub struct ListPublishingKeyValues {
        /// URL of a server with publishing set up. Defaults to the value of environment
        /// variable `SPAGH_ADMIN`.
        pub server: Option<Uri>,
        pub identity: String,
    }

    #[derive(Aargvark)]
    pub struct Query {
        /// URL of a server with the resolver enabled. Defaults to the value of environment
        /// variable `SPAGH`.
        pub server: Option<Uri>,
        /// Identity to query
        pub identity: String,
        /// Keys published by the identity, to query
        pub keys: Vec<String>,
    }

    #[derive(Aargvark)]
    pub struct GenerateConfig {
        /// Enable the publisher, allowing you to publish data on your server
        pub publisher: Option<()>,
        /// Build config for enabling the resolver
        pub resolver: Option<()>,
        /// Build config for enabling the dns bridge
        pub dns_bridge: Option<()>,
        /// An identity to use to enable self-identity features. This can be an existing
        /// identity or a path to a file where a new local identity will be written.
        pub self_identity: Option<BackedIdentityArg>,
    }

    #[derive(Aargvark)]
    pub struct GenerateDnsKeyValues {
        pub ttl: u32,
        pub dns_cname: Vec<String>,
        pub dns_a: Vec<String>,
        pub dns_aaaa: Vec<String>,
        pub dns_txt: Vec<String>,
    }

    #[derive(Aargvark)]
    pub enum Command {
        // # Local
        //
        // ---
        /// Create a new local (file) identity
        NewLocalIdentity(NewLocalIdentity),
        /// Show the identity for a local identity file
        ShowLocalIdentity(AargvarkJson<BackedIdentityLocal>),
        /// List usable pcsc cards (configured with curve25519/ed25519 signing keys)
        ListCardIdentities,
        /// Generate base server configs
        GenerateConfig(GenerateConfig),
        /// Generate data for publishing DNS records
        GenerateDnsKeyValues(GenerateDnsKeyValues),
        /// Get a new `.s` TLS cert from a Spaghettinuum certifier. Returns the certs (pub
        /// and priv) as JSON along with the expiration date.
        IssueCert(BackedIdentityArg),
        /// Publish the ip of the host this command runs on using the DNS-equivalent A/AAAA
        /// records.
        SelfPublish(SelfPublish),
        // # Resolver
        //
        // ---
        /// Request values associated with provided identity and keys from a resolver
        Query(Query),
        // # Publisher non-admin
        //
        // ---
        /// Create or replace existing publish data for an identity on a publisher server
        Publish(Publish),
        /// A shortcut for publishing DNS data, generating the key values for you
        PublishDns(PublishDns),
        /// Stop publishing data
        Unpublish(Unpublish),
        // # Publisher admin
        //
        // ---
        /// Register an identity with the publisher, allowing it to publish
        AllowIdentity(AllowIdentity),
        /// Unregister an identity with the publisher, disallowing it from publishing
        DisallowIdentity(DisallowIdentity),
        /// Unregister an identity with the publisher, disallowing it from publishing
        ListAllowedIdentities(ListAllowedIdentities),
        /// List identities a publisher is currently publishing
        ListPublishingIdentities(ListPublishingIdentities),
        /// List data a publisher is publishing for an identity
        ListPublishingKeyValues(ListPublishingKeyValues),
    }

    #[derive(Aargvark)]
    pub struct Args {
        pub debug: Option<()>,
        pub command: Command,
    }
}

fn admin_headers() -> Result<HashMap<String, String>, loga::Error> {
    let mut out = HashMap::new();
    let env_key = ENV_API_ADMIN_TOKEN;
    out.insert(
        "Authorization".to_string(),
        format!(
            "Bearer {}",
            env::var(
                env_key,
            ).context_with(
                "This operation uses an admin endpoint, but missing the admin token in the environment",
                ea!(key = env_key),
            )?
        ),
    );
    return Ok(out);
}

fn api_url(url: Option<Uri>) -> Result<Uri, loga::Error> {
    return api_url_(url, ENV_API_ADDR);
}

fn admin_api_url(url: Option<Uri>) -> Result<Uri, loga::Error> {
    return api_url_(url, ENV_API_ADMIN_ADDR);
}

fn api_url_(mut url: Option<Uri>, env_key: &'static str) -> Result<Uri, loga::Error> {
    let default_port = 443;
    if url.is_none() {
        match env::var(env_key) {
            Ok(e) => {
                url =
                    Some(
                        Uri::from_str(&e).context_with("Couldn't parse environment variable", ea!(env = env_key))?,
                    );
            },
            Err(e) => {
                match e {
                    env::VarError::NotPresent => { },
                    env::VarError::NotUnicode(e) => {
                        return Err(
                            loga::err_with(
                                "Environment variable isn't valid unicode",
                                ea!(env = env_key, value = e.to_string_lossy()),
                            ),
                        );
                    },
                }
            },
        }
    }
    let url = match url {
        Some(u) => u,
        None => Uri::from_static("http://localhost"),
    };
    if url.scheme_str() == Some("http") && url.port().is_none() {
        let mut u = url.into_parts();
        u.authority =
            Some(
                Authority::try_from(
                    format!(
                        "{}:{}",
                        u.authority.map(|a| a.to_string()).unwrap_or(String::new()),
                        default_port
                    ).as_bytes(),
                ).unwrap(),
            );
        return Ok(Uri::from_parts(u).unwrap());
    } else {
        return Ok(url);
    }
}

async fn api_list<
    T: DeserializeOwned,
>(server: Option<Uri>, path: &str, get_key: fn(&T) -> String) -> Result<Vec<T>, loga::Error> {
    let mut out = vec![];
    let admin_headers = admin_headers()?;
    let base_url = admin_api_url(server)?;
    let mut res = htreq::get(format!("{}{}", base_url, path), &admin_headers, 1024 * 1024).await?;
    loop {
        let page: Vec<T> =
            serde_json::from_slice(&res).context("Failed to parse response page from publisher admin")?;
        let after = match page.last() {
            Some(a) => Some(get_key(a)),
            None => None,
        };
        out.extend(page);
        let Some(after) = after else {
            break;
        };
        res = htreq::get(format!("{}{}?after={}", base_url, path, after), &admin_headers, 1024 * 1024).await?;
    }
    return Ok(out);
}

async fn publish(
    log: &Log,
    server: &Uri,
    identity_arg: BackedIdentityArg,
    keyvalues: publish::latest::Publish,
) -> Result<(), loga::Error> {
    let mut signer = get_identity_signer(identity_arg).stack_context(&log, "Error constructing signer")?;
    let info_body =
        htreq::get(&format!("{}info", server), &HashMap::new(), 100 * 1024)
            .await
            .stack_context(log, "Error getting publisher info")?;
    let info: publish::latest::InfoResponse =
        serde_json::from_slice(
            &info_body,
        ).stack_context_with(
            log,
            "Error parsing info response from publisher as json",
            ea!(body = String::from_utf8_lossy(&info_body)),
        )?;
    log.log_with(
        DEBUG_OTHER,
        "Got publisher information",
        ea!(info = serde_json::to_string_pretty(&info_body).unwrap()),
    );
    let announcement_content = node_protocol::latest::PublisherAnnouncementContent {
        addr: SerialAddr(info.advertise_addr),
        cert_hash: info.cert_pub_hash,
        published: Utc::now(),
    };
    log.log_with(
        DEBUG_OTHER,
        "Unsigned publisher announcement",
        ea!(message = serde_json::to_string_pretty(&announcement_content).unwrap()),
    );
    let (identity, signed_announcement_content) =
        node_protocol::latest::PublisherAnnouncement::sign(
            signer.as_mut(),
            announcement_content,
        ).stack_context(&log, "Failed to sign announcement")?;
    let request_content = publish::latest::PublishRequestContent {
        announce: node_protocol::PublisherAnnouncement::V1(signed_announcement_content),
        keyvalues: keyvalues,
    };
    log.log_with(
        DEBUG_OTHER,
        "Unsigned request message",
        ea!(message = serde_json::to_string_pretty(&request_content).unwrap()),
    );
    let (_, signed_request_content) =
        JsonSignature::sign(
            signer.as_mut(),
            request_content,
        ).stack_context(&log, "Failed to sign publish request content")?;
    let request = publish::PublishRequest::V1(publish::latest::PublishRequest {
        identity: identity,
        content: signed_request_content,
    });
    let url = format!("{}publish/publish", server);
    log.log_with(
        DEBUG_OTHER,
        "Sending publish request",
        ea!(url = url, body = serde_json::to_string_pretty(&request).unwrap()),
    );
    htreq::post(&url, &HashMap::new(), serde_json::to_vec(&request).unwrap(), 100)
        .await
        .stack_context(log, "Error making publish request")?;
    return Ok(());
}

#[tokio::main]
async fn main() {
    async fn inner() -> Result<(), loga::Error> {
        let args = aargvark::vark::<args::Args>();
        let log = Log::new().with_flags(match args.debug {
            Some(_) => Flags::all(),
            None => NON_DEBUG,
        });
        let log = &log;
        match args.command {
            // Local
            args::Command::NewLocalIdentity(args) => {
                let (ident, secret) = BackedIdentityLocal::new();
                write_identity(&args.path, &secret).await.stack_context(&log, "Error creating local identity")?;
                println!("{}", serde_json::to_string_pretty(&json!({
                    "identity": ident.to_string()
                })).unwrap());
            },
            args::Command::ShowLocalIdentity(p) => {
                let secret = p.value;
                let identity = secret.identity();
                println!("{}", serde_json::to_string_pretty(&json!({
                    "identity": identity.to_string()
                })).unwrap());
            },
            args::Command::ListCardIdentities => {
                let mut out = vec![];
                for card in PcscBackend::cards(None).stack_context(log, "Failed to list smart cards")? {
                    let mut card: Card<Open> = card.into();
                    let mut transaction =
                        card.transaction().stack_context(log, "Error starting transaction with card")?;
                    let card_id =
                        transaction
                            .application_identifier()
                            .stack_context(log, "Error getting gpg id of card")?
                            .ident();
                    let identity = match pgp::card_to_ident(&mut transaction) {
                        Ok(i) => match i {
                            Some(i) => i,
                            None => {
                                continue;
                            },
                        },
                        Err(e) => {
                            log.log_err(
                                WARN,
                                e.context_with("Error getting identity of card", ea!(card = card_id)),
                            );
                            continue;
                        },
                    };
                    out.push(json!({
                        "pcsc_id": card_id,
                        "identity": identity.to_string(),
                    }));
                }
                println!("{}", serde_json::to_string_pretty(&out).unwrap());
            },
            args::Command::GenerateConfig(config) => {
                let api = config.publisher.is_some() || config.resolver.is_some();
                let cwd = current_dir().unwrap();
                let config = Config {
                    persistent_dir: cwd.join("spagh_persistent"),
                    global_addrs: vec![GlobalAddrConfig::FromInterface {
                        name: None,
                        ip_version: Some(config::IpVer::V4),
                    }, GlobalAddrConfig::FromInterface {
                        name: None,
                        ip_version: Some(config::IpVer::V6),
                    }],
                    node: NodeConfig {
                        bind_addr: StrSocketAddr::new_fake(format!("[::]:{}", PORT_NODE)),
                        bootstrap: vec![BootstrapConfig {
                            addr: StrSocketAddr::new_fake(format!("spaghettinuum.isandrew.com:{}", PORT_NODE)),
                            ident: NodeIdentity::from_str(
                                "yryyyyyyybidytwtduewf13mpisf3uc3boutecdscyyucqd7ksi767957yua4",
                            ).unwrap(),
                        }],
                    },
                    api_bind_addrs: if api {
                        let port = if config.self_identity.is_some() {
                            443
                        } else {
                            8080
                        };
                        vec![StrSocketAddr::new_fake(format!("[::]:{}", port))]
                    } else {
                        vec![]
                    },
                    admin_token: if api {
                        Some(Alphanumeric.sample_string(&mut rand::thread_rng(), 20))
                    } else {
                        None
                    },
                    identity: match config.self_identity {
                        Some(i) => {
                            match &i {
                                BackedIdentityArg::Local(l) => {
                                    if !l.exists() {
                                        let (_, secret) = BackedIdentityLocal::new();
                                        write_identity(l, &secret)
                                            .await
                                            .stack_context(&log, "Error creating local identity")?;
                                    }
                                },
                                _ => { },
                            }
                            Some(SelfIdentityConfig {
                                identity: i,
                                self_tls: true,
                                self_publish: config.publisher.is_some(),
                            })
                        },
                        None => None,
                    },
                    resolver: if config.resolver.is_some() || config.dns_bridge.is_some() {
                        Some(spaghettinuum::resolver::config::ResolverConfig {
                            max_cache: None,
                            dns_bridge: if config.dns_bridge.is_some() {
                                Some(spaghettinuum::resolver::config::DnsBridgeConfig {
                                    udp_bind_addrs: vec![StrSocketAddr::new_fake("[::]:53".to_string())],
                                    tcp_bind_addrs: vec![],
                                    tls: None,
                                })
                            } else {
                                None
                            },
                        })
                    } else {
                        None
                    },
                    publisher: if config.publisher.is_some() {
                        Some(spaghettinuum::publisher::config::PublisherConfig {
                            bind_addr: StrSocketAddr::new_fake(format!("[::]:{}", PORT_PUBLISHER)),
                            advertise_port: Some(PORT_PUBLISHER),
                        })
                    } else {
                        None
                    },
                };
                println!("{}", serde_json::to_string_pretty(&config).unwrap());
            },
            args::Command::GenerateDnsKeyValues(config) => {
                println!("{}", serde_json::to_string_pretty(&publish::latest::Publish {
                    missing_ttl: config.ttl,
                    data: {
                        let mut kvs = HashMap::new();
                        if !config.dns_cname.is_empty() {
                            kvs.insert(KEY_DNS_CNAME.to_string(), publish::latest::PublishValue {
                                ttl: config.ttl,
                                data: serde_json::to_string(
                                    &resolve::DnsCname::V1(resolve::latest::DnsCname(config.dns_cname)),
                                ).unwrap(),
                            });
                        }
                        if !config.dns_a.is_empty() {
                            kvs.insert(KEY_DNS_A.to_string(), publish::latest::PublishValue {
                                ttl: config.ttl,
                                data: serde_json::to_string(
                                    &resolve::DnsA::V1(resolve::latest::DnsA(config.dns_a)),
                                ).unwrap(),
                            });
                        }
                        if !config.dns_aaaa.is_empty() {
                            kvs.insert(KEY_DNS_AAAA.to_string(), publish::latest::PublishValue {
                                ttl: config.ttl,
                                data: serde_json::to_string(
                                    &resolve::DnsAaaa::V1(resolve::latest::DnsAaaa(config.dns_aaaa)),
                                ).unwrap(),
                            });
                        }
                        if !config.dns_txt.is_empty() {
                            kvs.insert(KEY_DNS_TXT.to_string(), publish::latest::PublishValue {
                                ttl: config.ttl,
                                data: serde_json::to_string(
                                    &resolve::DnsTxt::V1(resolve::latest::DnsTxt(config.dns_txt)),
                                ).unwrap(),
                            });
                        }
                        kvs
                    },
                }).unwrap());
            },
            args::Command::IssueCert(ident) => {
                let priv_key = p256::SecretKey::random(&mut rand::thread_rng());
                let cert_pub =
                    request_cert(
                        log,
                        &certifier_url(),
                        &SubjectPublicKeyInfoOwned::from_key(priv_key.public_key()).unwrap(),
                        &mut get_identity_signer(ident).stack_context(log, "Error accessing specified identity")?,
                    )
                        .await
                        .map_err(|e| log.err_with("Failed to get certificate", ea!(err = e)))?
                        .pub_pem;
                let expiry = <DateTime<Utc>>::from(extract_expiry(cert_pub.as_bytes())?);
                println!("{}", serde_json::to_string_pretty(&json!({
                    "expires_at": expiry,
                    "cert_pub_pem": cert_pub,
                    "cert_priv_pem": encode_priv_pem(&priv_key.to_sec1_der().unwrap())
                })).unwrap());
            },
            args::Command::SelfPublish(config) => {
                let global_ip = match config.addr {
                    config::GlobalAddrConfig::Fixed(s) => s,
                    config::GlobalAddrConfig::FromInterface { name, ip_version } => {
                        local_resolve_global_ip(&name, &ip_version)
                            .await?
                            .stack_context(log, "No global IP found on local interface")?
                    },
                    config::GlobalAddrConfig::Lookup(lookup) => {
                        remote_resolve_global_ip(&lookup.lookup, lookup.contact_ip_ver).await?
                    },
                };
                publish(log, &admin_api_url(config.server)?, config.identity, publish::latest::Publish {
                    missing_ttl: 60 * 24,
                    data: {
                        let mut out = HashMap::new();
                        match global_ip {
                            std::net::IpAddr::V4(ip) => {
                                out.insert(KEY_DNS_A.to_string(), publish::latest::PublishValue {
                                    ttl: 60,
                                    data: ip.to_string(),
                                });
                            },
                            std::net::IpAddr::V6(ip) => {
                                out.insert(KEY_DNS_AAAA.to_string(), publish::latest::PublishValue {
                                    ttl: 60,
                                    data: ip.to_string(),
                                });
                            },
                        }
                        out
                    },
                }).await?;
            },
            // Resolver
            args::Command::Query(config) => {
                let url =
                    format!(
                        "{}v1/{}?{}",
                        api_url(config.server)?,
                        config.identity,
                        config.keys.iter().map(|k| urlencoding::encode(k)).join(",")
                    );
                log.log_with(DEBUG_OTHER, "Sending query request", ea!(url = url));
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &serde_json::from_slice::<serde_json::Value>(
                            &htreq::get(&url, &HashMap::new(), 1024 * 1024).await?,
                        ).stack_context(log, "Response could not be parsed as JSON")?,
                    ).unwrap()
                );
            },
            // Publisher registered non-admin
            args::Command::Publish(config) => {
                publish(log, &admin_api_url(config.server)?, config.identity, config.data.value).await?;
            },
            args::Command::PublishDns(config) => {
                publish(log, &admin_api_url(config.server)?, config.identity, publish::latest::Publish {
                    missing_ttl: config.ttl,
                    data: {
                        let mut kvs = HashMap::new();
                        if !config.dns_cname.is_empty() {
                            kvs.insert(KEY_DNS_CNAME.to_string(), publish::latest::PublishValue {
                                ttl: config.ttl,
                                data: serde_json::to_string(
                                    &resolve::DnsCname::V1(resolve::latest::DnsCname(config.dns_cname)),
                                ).unwrap(),
                            });
                        }
                        if !config.dns_a.is_empty() {
                            kvs.insert(KEY_DNS_A.to_string(), publish::latest::PublishValue {
                                ttl: config.ttl,
                                data: serde_json::to_string(
                                    &resolve::DnsA::V1(resolve::latest::DnsA(config.dns_a)),
                                ).unwrap(),
                            });
                        }
                        if !config.dns_aaaa.is_empty() {
                            kvs.insert(KEY_DNS_AAAA.to_string(), publish::latest::PublishValue {
                                ttl: config.ttl,
                                data: serde_json::to_string(
                                    &resolve::DnsAaaa::V1(resolve::latest::DnsAaaa(config.dns_aaaa)),
                                ).unwrap(),
                            });
                        }
                        if !config.dns_txt.is_empty() {
                            kvs.insert(KEY_DNS_TXT.to_string(), publish::latest::PublishValue {
                                ttl: config.ttl,
                                data: serde_json::to_string(
                                    &resolve::DnsTxt::V1(resolve::latest::DnsTxt(config.dns_txt)),
                                ).unwrap(),
                            });
                        }
                        kvs
                    },
                }).await?;
            },
            args::Command::Unpublish(config) => {
                let mut signer =
                    get_identity_signer(config.identity).stack_context(&log, "Error constructing signer")?;
                let request_message = publish::latest::UnpublishRequestContent { now: Utc::now() };
                log.log_with(DEBUG_OTHER, "Unsigned request message", ea!(message = request_message.dbg_str()));
                let (identity, signature) =
                    PublishIdentSignatureMethods::sign(
                        signer.as_mut(),
                        request_message,
                    ).stack_context(&log, "Failed to sign unpublish request")?;
                let request = publish::UnpublishRequest::V1(publish::latest::UnpublishRequest {
                    identity: identity,
                    content: signature,
                });
                let url = format!("{}publish/unpublish", admin_api_url(config.server)?);
                log.log_with(
                    DEBUG_OTHER,
                    "Sending unpublish request",
                    ea!(url = url, body = serde_json::to_string_pretty(&request).unwrap()),
                );
                htreq::post(&url, &HashMap::new(), serde_json::to_vec(&request).unwrap(), 100)
                    .await
                    .stack_context(log, "Error making unpublish request")?;
            },
            // Publisher admin
            args::Command::AllowIdentity(config) => {
                let url =
                    format!(
                        "{}publish/admin/allowed_identities/{}",
                        admin_api_url(config.server)?,
                        config.identity_id
                    );
                log.log_with(DEBUG_OTHER, "Sending register request (POST)", ea!(url = url));
                htreq::post(&url, &admin_headers()?, vec![], 100).await?;
            },
            args::Command::DisallowIdentity(config) => {
                let url =
                    format!(
                        "{}publish/admin/allowed_identities/{}",
                        admin_api_url(config.server)?,
                        config.identity_id
                    );
                log.log_with(DEBUG_OTHER, "Sending unregister request (POST)", ea!(url = url));
                htreq::delete(&url, &admin_headers()?, 100).await?;
            },
            args::Command::ListAllowedIdentities(config) => {
                let out =
                    api_list::<Identity>(config.server, "publish/admin/allowed_identities", |v| v.to_string())
                        .await
                        .stack_context(log, "Error listing allowed identities")?;
                println!("{}", serde_json::to_string_pretty(&out).unwrap());
            },
            args::Command::ListPublishingIdentities(config) => {
                let out =
                    api_list::<Identity>(config.server, "publish/admin/announcements", |v| v.to_string())
                        .await
                        .stack_context(log, "Error listing publishing identities")?;
                println!("{}", serde_json::to_string_pretty(&out).unwrap());
            },
            args::Command::ListPublishingKeyValues(config) => {
                println!(
                    "{}",
                    htreq::get_text(
                        &format!("{}publish/admin/announcements/{}", admin_api_url(config.server)?, config.identity),
                        &admin_headers()?,
                        1024 * 1024,
                    ).await?
                );
            },
        }
        return Ok(());
    }

    match inner().await {
        Ok(_) => { },
        Err(e) => {
            loga::fatal(e);
        },
    }
}
