use chrono::Utc;
use itertools::Itertools;
use loga::{
    ea,
    Log,
    ResultContext,
};
use openpgp_card_pcsc::PcscBackend;
use openpgp_card_sequoia::{
    state::Open,
    Card,
};
use poem::{
    async_trait,
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
use reqwest::{
    Response,
    header::AUTHORIZATION,
};
use ring::rand::SystemRandom;
use serde_json::json;
use spaghettinuum::{
    config::{
        Config,
        SelfIdentityConfig,
        GlobalAddrConfig,
        self,
    },
    node::config::{
        BootstrapConfig,
        NodeConfig,
    },
    utils::{
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
            DEFAULT_CERTIFIER_URL,
        },
        node_protocol::{
            self,
            latest::SerialAddr,
            NodeIdentity,
        },
        spagh_api::{
            publish::{
                self,
            },
            resolve::{
                KEY_DNS_MX,
                KEY_DNS_TXT,
                KEY_DNS_AAAA,
                KEY_DNS_A,
                KEY_DNS_CNAME,
                self,
            },
        },
        identity::Identity,
    },
    self_tls::{
        request_cert,
        default_generate_cert_keys,
        certifier_url,
    },
};
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
    };

    #[derive(Aargvark)]
    pub struct NewLocalIdentity {
        /// Store the new id and secret in a file at this path
        pub path: PathBuf,
    }

    #[derive(Aargvark)]
    pub struct Register {
        /// Private/admin URL of a server with publishing set up. Defaults to the value of
        /// environment variable `SPAGH_PRIV` or else localhost with the default port.
        pub server: Option<Uri>,
        pub identity_id: String,
    }

    #[derive(Aargvark)]
    pub struct Unregister {
        /// Private/admin URL of a server with publishing set up. Defaults to the value of
        /// environment variable `SPAGH_PRIV` or else localhost with the default port.
        pub server: Option<Uri>,
        pub identity_id: String,
    }

    #[derive(Aargvark)]
    pub struct Publish {
        /// URL of a server with publishing set up. Defaults to the value of environment
        /// variable `SPAGH` or else localhost with the default port.
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
        /// variable `SPAGH` or else localhost with the default port.
        pub server: Option<Uri>,
        /// Identity to publish as
        pub identity: BackedIdentityArg,
        pub ttl: u32,
        pub dns_cname: Vec<String>,
        pub dns_a: Vec<String>,
        pub dns_aaaa: Vec<String>,
        pub dns_txt: Vec<String>,
        /// In the format `PRIORITY/NAME` ex `10/mail.example.org`
        pub dns_mx: Vec<String>,
    }

    #[derive(Aargvark)]
    pub struct Unpublish {
        /// URL of a server with publishing set up. Defaults to the value of environment
        /// variable `SPAGH` or else localhost with the default port.
        pub server: Option<Uri>,
        pub identity: BackedIdentityArg,
    }

    #[derive(Aargvark)]
    pub struct ListPublisherIdentities {
        /// URL of a server with publishing set up. Defaults to the value of environment
        /// variable `SPAGH_PRIV` or else localhost with the default port.
        pub server: Option<Uri>,
    }

    #[derive(Aargvark)]
    pub struct ListPublisherKeyValues {
        /// URL of a server with publishing set up. Defaults to the value of environment
        /// variable `SPAGH_PRIV` or else localhost with the default port.
        pub server: Option<Uri>,
        pub identity: String,
    }

    #[derive(Aargvark)]
    pub struct Query {
        /// URL of a server with the resolver enabled. Defaults to the value of environment
        /// variable `SPAGH_RESOLVER` or else localhost with the default port.
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
        /// In the format `PRIORITY/NAME` ex `10/mail.example.org`
        pub dns_mx: Vec<String>,
    }

    #[derive(Aargvark)]
    pub enum Args {
        /// Create a new local (file) identity
        NewLocalIdentity(NewLocalIdentity),
        /// Show the identity for a local identity file
        ShowLocalIdentity(AargvarkJson<BackedIdentityLocal>),
        /// List usable pcsc cards (configured with curve25519/ed25519 signing keys)
        ListCardIdentities,
        /// Register an identity with the server, allowing it to publish
        Register(Register),
        /// Unregister an identity with the server, disallowing it from publishing
        Unregister(Unregister),
        /// Create or replace existing publish data for an identity on a publisher server
        Publish(Publish),
        /// A shortcut for publishing DNS data, generating the key values for you
        PublishDns(PublishDns),
        /// Create or replace existing publish data for an identity on a publisher server
        Unpublish(Unpublish),
        /// List identities a publisher is currently publishing
        ListPublisherIdentities(ListPublisherIdentities),
        /// List data a publisher is publishing for an identity
        ListPublisherKeyValues(ListPublisherKeyValues),
        /// Request values associated with provided identity and keys from a resolver
        Query(Query),
        /// Generate base server configs
        GenerateConfig(GenerateConfig),
        /// Generate data for publishing DNS records
        GenerateDnsKeyValues(GenerateDnsKeyValues),
        /// Get a new `.s` TLS cert from a Spaghettinuum certifier. Returns the certs (pub
        /// and priv) as JSON along with the expiration date.
        ProvisionCert(BackedIdentityArg),
    }
}

#[async_trait]
trait ReqwestCheck {
    async fn check(self) -> Result<(), loga::Error>;
    async fn check_text(self) -> Result<String, loga::Error>;
    async fn check_bytes(self) -> Result<Vec<u8>, loga::Error>;
}

#[async_trait]
impl ReqwestCheck for Result<Response, reqwest::Error> {
    async fn check(self) -> Result<(), loga::Error> {
        let resp = self?;
        let status = resp.status();
        let body = resp.bytes().await?.to_vec();
        if !status.is_success() {
            return Err(
                loga::err_with("Request failed", ea!(status = status, body = String::from_utf8_lossy(&body))),
            );
        }
        return Ok(());
    }

    async fn check_text(self) -> Result<String, loga::Error> {
        let resp = self?;
        let status = resp.status();
        let body = resp.bytes().await?.to_vec();
        if !status.is_success() {
            return Err(
                loga::err_with("Request failed", ea!(status = status, body = String::from_utf8_lossy(&body))),
            );
        }
        return Ok(
            String::from_utf8(
                body.clone(),
            ).context_with(
                "Failed to parse response as bytes",
                ea!(status = status, body = String::from_utf8_lossy(&body)),
            )?,
        );
    }

    async fn check_bytes(self) -> Result<Vec<u8>, loga::Error> {
        let resp = self?;
        let status = resp.status();
        let body = resp.bytes().await?.to_vec();
        if !status.is_success() {
            return Err(
                loga::err_with("Request failed", ea!(status = status, body = String::from_utf8_lossy(&body))),
            );
        }
        return Ok(body);
    }
}

fn publisher_priv_client() -> Result<reqwest::Client, loga::Error> {
    return Ok(reqwest::ClientBuilder::new().default_headers({
        let mut h = reqwest::header::HeaderMap::new();
        let env_key = ENV_API_ADMIN_TOKEN;
        h.insert(
            AUTHORIZATION,
            format!(
                "Bearer {}",
                env::var(
                    env_key,
                ).context_with(
                    "This operation uses an admin endpoint, but missing the admin token in the environment",
                    ea!(key = env_key),
                )?
            )
                .try_into()
                .context_with(
                    "The admin token in the environment isn't a valid HTTP authorization token",
                    ea!(key = env_key),
                )?,
        );
        h
    }).build().unwrap());
}

fn api_url(mut url: Option<Uri>) -> Result<Uri, loga::Error> {
    let env_key = ENV_API_ADDR;
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

async fn publish(
    log: &loga::Log,
    c: reqwest::Client,
    server: &Uri,
    identity_arg: BackedIdentityArg,
    keyvalues: publish::latest::Publish,
) -> Result<(), loga::Error> {
    let info_body =
        c
            .get(format!("{}info", server))
            .send()
            .await
            .check_bytes()
            .await
            .log_context(log, "Error getting publisher info")?;
    let info: publish::latest::InfoResponse =
        serde_json::from_slice(
            &info_body,
        ).log_context_with(
            log,
            "Error parsing info response from publisher as json",
            ea!(body = String::from_utf8_lossy(&info_body)),
        )?;
    let announce_message = node_protocol::latest::ValueBody {
        addr: SerialAddr(info.advertise_addr),
        cert_hash: zbase32::decode_full_bytes_str(
            &info.cert_pub_hash,
        ).map_err(
            |e| log.new_err_with("Couldn't parse zbase32 pub cert hash in response from publisher", ea!(text = e)),
        )?,
        published: Utc::now(),
    }.to_bytes();
    let mut signer = get_identity_signer(identity_arg).log_context(&log, "Error constructing signer")?;
    let (identity, request_message_sig) =
        signer.sign(&announce_message).log_context(&log, "Failed to sign announcement")?;
    let request_message = publish::latest::PublishRequestBody {
        announce: publish::latest::Announcement {
            message: announce_message.clone(),
            signature: request_message_sig,
        },
        keyvalues: keyvalues,
    }.to_bytes();
    let request = publish::PublishRequest::V1(publish::latest::PublishRequest {
        identity: identity,
        signed: publish::latest::PublishRequestSigned {
            signature: signer.sign(&request_message).log_context(&log, "Failed to sign publish request")?.1,
            message: request_message,
        },
    });
    c
        .post(format!("{}publish/publish", server))
        .json(&request)
        .send()
        .await
        .check()
        .await
        .log_context(log, "Error making publish request")?;
    return Ok(());
}

#[tokio::main]
async fn main() {
    let log = loga::new(loga::Level::Info);

    async fn inner(log: &Log) -> Result<(), loga::Error> {
        match aargvark::vark::<args::Args>() {
            args::Args::NewLocalIdentity(args) => {
                let (ident, secret) = BackedIdentityLocal::new();
                write_identity(&args.path, &secret).await.log_context(&log, "Error creating local identity")?;
                println!("{}", serde_json::to_string_pretty(&json!({
                    "identity": ident.to_string()
                })).unwrap());
            },
            args::Args::ShowLocalIdentity(p) => {
                let secret = p.value;
                let identity = secret.identity();
                println!("{}", serde_json::to_string_pretty(&json!({
                    "identity": identity.to_string()
                })).unwrap());
            },
            args::Args::ListCardIdentities => {
                let mut out = vec![];
                for card in PcscBackend::cards(None).log_context(log, "Failed to list smart cards")? {
                    let mut card: Card<Open> = card.into();
                    let mut transaction =
                        card.transaction().log_context(log, "Error starting transaction with card")?;
                    let card_id =
                        transaction
                            .application_identifier()
                            .log_context(log, "Error getting gpg id of card")?
                            .ident();
                    let identity = match pgp::card_to_ident(&mut transaction) {
                        Ok(i) => match i {
                            Some(i) => i,
                            None => {
                                continue;
                            },
                        },
                        Err(e) => {
                            log.warn_e(e, "Error getting identity of card", ea!(card = card_id));
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
            args::Args::Register(config) => {
                publisher_priv_client()?
                    .post(format!("{}publish/register/{}", api_url(config.server)?, config.identity_id))
                    .send()
                    .await
                    .check_text()
                    .await?;
            },
            args::Args::Unregister(config) => {
                publisher_priv_client()?
                    .post(format!("{}publish/unregister/{}", api_url(config.server)?, config.identity_id))
                    .send()
                    .await
                    .check_text()
                    .await?;
            },
            args::Args::Publish(config) => {
                publish(
                    log,
                    reqwest::ClientBuilder::new().build().unwrap(),
                    &api_url(config.server)?,
                    config.identity,
                    config.data.value,
                ).await?;
            },
            args::Args::PublishDns(config) => {
                publish(
                    log,
                    reqwest::ClientBuilder::new().build().unwrap(),
                    &api_url(config.server)?,
                    config.identity,
                    publish::latest::Publish {
                        missing_ttl: config.ttl,
                        data: {
                            let mut kvs = HashMap::new();
                            if !config.dns_cname.is_empty() {
                                kvs.insert(KEY_DNS_CNAME.to_string(), publish::latest::PublishValue {
                                    ttl: config.ttl,
                                    data: serde_json::to_string(
                                        &resolve::DnsRecordsetJson::V1(
                                            resolve::latest::DnsRecordsetJson::Cname(config.dns_cname),
                                        ),
                                    ).unwrap(),
                                });
                            }
                            if !config.dns_a.is_empty() {
                                kvs.insert(KEY_DNS_A.to_string(), publish::latest::PublishValue {
                                    ttl: config.ttl,
                                    data: serde_json::to_string(
                                        &resolve::DnsRecordsetJson::V1(
                                            resolve::latest::DnsRecordsetJson::A(config.dns_a),
                                        ),
                                    ).unwrap(),
                                });
                            }
                            if !config.dns_aaaa.is_empty() {
                                kvs.insert(KEY_DNS_AAAA.to_string(), publish::latest::PublishValue {
                                    ttl: config.ttl,
                                    data: serde_json::to_string(
                                        &resolve::DnsRecordsetJson::V1(
                                            resolve::latest::DnsRecordsetJson::Aaaa(config.dns_aaaa),
                                        ),
                                    ).unwrap(),
                                });
                            }
                            if !config.dns_txt.is_empty() {
                                kvs.insert(KEY_DNS_TXT.to_string(), publish::latest::PublishValue {
                                    ttl: config.ttl,
                                    data: serde_json::to_string(
                                        &resolve::DnsRecordsetJson::V1(
                                            resolve::latest::DnsRecordsetJson::Txt(config.dns_txt),
                                        ),
                                    ).unwrap(),
                                });
                            }
                            if !config.dns_mx.is_empty() {
                                let mut values = vec![];
                                for v in config.dns_mx {
                                    let (priority, name) =
                                        v
                                            .split_once("/")
                                            .ok_or_else(
                                                || loga::err_with(
                                                    "Incorrect mx record specification, must be like `PRIORITY/NAME`",
                                                    ea!(entry = v),
                                                ),
                                            )?;
                                    let priority =
                                        u16::from_str(&priority).context("Couldn't parse priority as int")?;
                                    values.push((priority, name.to_string()));
                                }
                                kvs.insert(KEY_DNS_MX.to_string(), publish::latest::PublishValue {
                                    ttl: config.ttl,
                                    data: serde_json::to_string(
                                        &resolve::DnsRecordsetJson::V1(resolve::latest::DnsRecordsetJson::Mx(values)),
                                    ).unwrap(),
                                });
                            }
                            kvs
                        },
                    },
                ).await?;
            },
            args::Args::Unpublish(config) => {
                let c = reqwest::ClientBuilder::new().build().unwrap();
                let mut signer =
                    get_identity_signer(config.identity).log_context(&log, "Error constructing signer")?;
                let request_message = publish::latest::UnpublishRequestBody { now: Utc::now() }.to_bytes();
                let (identity, request_message_sig) =
                    signer.sign(&request_message).log_context(&log, "Failed to sign unpublish request")?;
                let request = publish::UnpublishRequest::V1(publish::latest::UnpublishRequest {
                    identity: identity,
                    signed: publish::latest::UnpublishRequestSigned {
                        signature: request_message_sig,
                        message: request_message,
                    },
                });
                c
                    .post(format!("{}publish/unpublish", api_url(config.server)?))
                    .json(&request)
                    .send()
                    .await
                    .check()
                    .await
                    .log_context(log, "Error making unpublish request")?;
            },
            args::Args::ListPublisherIdentities(config) => {
                let mut out = vec![];
                let c = publisher_priv_client()?;
                let url = api_url(config.server)?;
                let mut res = c.get(format!("{}publish", url)).send().await.check_bytes().await?;
                loop {
                    let mut identities: Vec<Identity> =
                        serde_json::from_slice(
                            &res,
                        ).log_context(log, "Failed to parse response from publisher admin")?;
                    for i in &identities {
                        out.push(json!({
                            "identity": i.to_string()
                        }));
                    }
                    let after = match identities.pop() {
                        Some(a) => a,
                        None => break,
                    };
                    res = c.get(format!("{}publish?after={}", url, after)).send().await.check_bytes().await?;
                }
                println!("{}", serde_json::to_string_pretty(&out).unwrap());
            },
            args::Args::ListPublisherKeyValues(config) => {
                println!(
                    "{}",
                    publisher_priv_client()?
                        .get(format!("{}publish/{}", api_url(config.server)?, config.identity))
                        .send()
                        .await
                        .check_text()
                        .await?
                );
            },
            args::Args::Query(config) => {
                println!(
                    "{}",
                    reqwest::ClientBuilder::new()
                        .build()
                        .unwrap()
                        .get(
                            format!(
                                "{}v1/{}?{}",
                                api_url(config.server)?,
                                config.identity,
                                config.keys.iter().map(|k| urlencoding::encode(k)).join(",")
                            ),
                        )
                        .send()
                        .await
                        .check_text()
                        .await?
                );
            },
            args::Args::GenerateConfig(config) => {
                let api = config.publisher.is_some() || config.resolver.is_some();
                let cwd = current_dir().unwrap();
                let config = Config {
                    persistent_dir: cwd.join("spagh_persistent"),
                    global_addr: GlobalAddrConfig::FromInterface {
                        name: None,
                        ip_version: Some(config::IpVer::V6),
                    },
                    node: NodeConfig {
                        bind_addr: StrSocketAddr::new_fake(format!("0.0.0.0:{}", PORT_NODE)),
                        bootstrap: vec![BootstrapConfig {
                            addr: StrSocketAddr::new_fake(format!("spaghettinuum.isandrew.com:{}", PORT_NODE)),
                            id: NodeIdentity::from_str(
                                "yryyyyyyyb3jndem1w1e4f56cfhu3di3kpj5c6n8emk4bkye3ien388tj1thg",
                            ).unwrap(),
                        }],
                    },
                    publisher: if config.publisher.is_some() {
                        Some(spaghettinuum::publisher::config::PublisherConfig {
                            bind_addr: StrSocketAddr::new_fake(format!("0.0.0.0:{}", PORT_PUBLISHER)),
                            advertise_port: PORT_PUBLISHER,
                        })
                    } else {
                        None
                    },
                    resolver: if config.resolver.is_some() || config.dns_bridge.is_some() {
                        Some(spaghettinuum::resolver::config::ResolverConfig {
                            max_cache: None,
                            dns_bridge: if config.dns_bridge.is_some() {
                                Some(spaghettinuum::resolver::config::DnsBridgeConfig {
                                    upstream: StrSocketAddr::new_fake("1.1.1.1:53".to_string()),
                                    bind_addr: StrSocketAddr::new_fake("0.0.0.0:53".to_string()),
                                })
                            } else {
                                None
                            },
                        })
                    } else {
                        None
                    },
                    api_bind_addr: if api {
                        if config.self_identity.is_some() {
                            Some(StrSocketAddr::new_fake(format!("0.0.0.0:{}", 443)))
                        } else {
                            Some(StrSocketAddr::new_fake(format!("0.0.0.0:{}", 8080)))
                        }
                    } else {
                        None
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
                                            .log_context(&log, "Error creating local identity")?;
                                    }
                                },
                                _ => { },
                            }
                            Some(SelfIdentityConfig {
                                identity: i,
                                self_tls: Some(DEFAULT_CERTIFIER_URL.to_string()),
                                self_publish: true,
                            })
                        },
                        None => None,
                    },
                };
                println!("{}", serde_json::to_string_pretty(&config).unwrap());
            },
            args::Args::GenerateDnsKeyValues(config) => {
                println!("{}", serde_json::to_string_pretty(&publish::latest::Publish {
                    missing_ttl: config.ttl,
                    data: {
                        let mut kvs = HashMap::new();
                        if !config.dns_cname.is_empty() {
                            kvs.insert(KEY_DNS_CNAME.to_string(), publish::latest::PublishValue {
                                ttl: config.ttl,
                                data: serde_json::to_string(
                                    &resolve::DnsRecordsetJson::V1(
                                        resolve::latest::DnsRecordsetJson::Cname(config.dns_cname),
                                    ),
                                ).unwrap(),
                            });
                        }
                        if !config.dns_a.is_empty() {
                            kvs.insert(KEY_DNS_A.to_string(), publish::latest::PublishValue {
                                ttl: config.ttl,
                                data: serde_json::to_string(
                                    &resolve::DnsRecordsetJson::V1(
                                        resolve::latest::DnsRecordsetJson::A(config.dns_a),
                                    ),
                                ).unwrap(),
                            });
                        }
                        if !config.dns_aaaa.is_empty() {
                            kvs.insert(KEY_DNS_AAAA.to_string(), publish::latest::PublishValue {
                                ttl: config.ttl,
                                data: serde_json::to_string(
                                    &resolve::DnsRecordsetJson::V1(
                                        resolve::latest::DnsRecordsetJson::Aaaa(config.dns_aaaa),
                                    ),
                                ).unwrap(),
                            });
                        }
                        if !config.dns_txt.is_empty() {
                            kvs.insert(KEY_DNS_TXT.to_string(), publish::latest::PublishValue {
                                ttl: config.ttl,
                                data: serde_json::to_string(
                                    &resolve::DnsRecordsetJson::V1(
                                        resolve::latest::DnsRecordsetJson::Txt(config.dns_txt),
                                    ),
                                ).unwrap(),
                            });
                        }
                        if !config.dns_mx.is_empty() {
                            let mut values = vec![];
                            for v in config.dns_mx {
                                let (priority, name) =
                                    v
                                        .split_once("/")
                                        .ok_or_else(
                                            || loga::err_with(
                                                "Incorrect mx record specification, must be like `PRIORITY/NAME`",
                                                ea!(entry = v),
                                            ),
                                        )?;
                                let priority = u16::from_str(&priority).context("Couldn't parse priority as int")?;
                                values.push((priority, name.to_string()));
                            }
                            kvs.insert(KEY_DNS_MX.to_string(), publish::latest::PublishValue {
                                ttl: config.ttl,
                                data: serde_json::to_string(
                                    &resolve::DnsRecordsetJson::V1(resolve::latest::DnsRecordsetJson::Mx(values)),
                                ).unwrap(),
                            });
                        }
                        kvs
                    },
                }).unwrap());
            },
            args::Args::ProvisionCert(ident) => {
                let random = SystemRandom::new();
                let priv_key = default_generate_cert_keys(&random);
                let cert_pub =
                    request_cert(
                        &certifier_url(),
                        &mut get_identity_signer(ident).log_context(log, "Error accessing specified identity")?,
                        &priv_key,
                    )
                        .await
                        .map_err(|e| log.new_err_with("Failed to get certificate", ea!(err = e)))?
                        .pub_pem;
                let expiry = extract_expiry(&cert_pub)?;
                println!("{}", serde_json::to_string_pretty(&json!({
                    "expires_at": expiry,
                    "cert_pub_pem": cert_pub,
                    "cert_priv_pem": encode_priv_pem(&priv_key)
                })).unwrap());
            },
        }
        return Ok(());
    }

    match inner(&log).await {
        Ok(_) => { },
        Err(e) => {
            loga::fatal(e);
        },
    }
}
