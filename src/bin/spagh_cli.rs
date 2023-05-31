use clap::{
    builder::PossibleValue,
    Parser,
    ValueEnum,
};
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
    http::Uri,
};
use reqwest::Response;
use serde::{
    Deserialize,
    Serialize,
};
use spaghettinuum::{
    config::Config,
    data::{
        self,
        identity::{
            Identity,
            IdentitySecret,
        },
        node::nodeidentity::NodeIdentity,
        publisher::v1::PublishValue,
        standard::{
            KEY_DNS_A,
            KEY_DNS_AAAA,
            KEY_DNS_CNAME,
            KEY_DNS_MX,
            KEY_DNS_TXT,
            PORT_NODE,
            PORT_PUBLISHER,
            PORT_PUBLISHER_API,
            PORT_RESOLVER,
        },
        utils::StrSocketAddr,
    },
    node::config::{
        BootstrapConfig,
        NodeConfig,
    },
    publisher::config::{
        IdentityData,
        SecretType,
        SecretTypeCard,
    },
    utils::pgp,
};
use std::{
    collections::HashMap,
    env::current_dir,
    fs,
    net::{
        IpAddr,
        SocketAddr,
        SocketAddrV4,
        SocketAddrV6,
    },
    path::PathBuf,
    str::FromStr,
};

#[derive(clap::Args)]
struct NewLocalIdentityArgs {
    /// Store the new id and secret in a file at this path
    pub path: PathBuf,
}

#[derive(clap::Args)]
struct RegisterLocalIdentityArgs {
    /// URL of a server with dynamic publishing set up
    pub server: Uri,
    /// Path to identity file (not identity id)
    pub identity: PathBuf,
}

#[derive(clap::Args)]
struct RegisterCardIdentityArgs {
    /// URL of a server with dynamic publishing set up
    pub server: Uri,
    /// Card to register, using id per pcscd (not identity id)
    pub pcsc_id: String,
    /// Card pin
    pub pin: String,
}

#[derive(clap::Args)]
struct UnregisterIdentityArgs {
    /// URL of a server with dynamic publishing set up
    pub server: Uri,
    /// Identity to unregister
    pub identity: String,
}

#[derive(clap::Args)]
struct PublishArgs {
    /// URL of a server with dynamic publishing set up
    pub server: Uri,
    /// Identity to publish as
    pub identity: String,
    /// Data to publish.  Must be a json in the structure
    /// `{KEY: {"ttl": SECONDS, "value": "DATA"}}`
    pub data: PathBuf,
}

#[derive(clap::Args)]
struct PublishDnsArgs {
    /// URL of a server with dynamic publishing set up
    pub server: Uri,
    /// Identity to publish as
    pub identity: String,
    pub ttl: u32,
    #[arg(long)]
    pub dns_cname: Vec<String>,
    #[arg(long)]
    pub dns_a: Vec<String>,
    #[arg(long)]
    pub dns_aaaa: Vec<String>,
    #[arg(long)]
    pub dns_txt: Vec<String>,
    /// In the format `PRIORITY/NAME` ex `10/mail.example.org`
    #[arg(long)]
    pub dns_mx: Vec<String>,
}

#[derive(clap::Args)]
struct QueryArgs {
    /// URL of a server with the resolver enabled for sending requests
    pub server: Uri,
    /// Identity to query
    pub identity: String,
    /// Keys published by the identity, to query
    pub keys: Vec<String>,
}

#[derive(Clone, clap::Subcommand)]
enum GenerateConfigPublisherArgs {
    Static,
    Dynamic,
}

impl ValueEnum for GenerateConfigPublisherArgs {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::Static, Self::Dynamic]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        match self {
            GenerateConfigPublisherArgs::Static => Some(PossibleValue::new("static")),
            GenerateConfigPublisherArgs::Dynamic => Some(PossibleValue::new("dynamic")),
        }
    }
}

#[derive(clap::Args)]
struct GenerateConfigArgs {
    /// Force ipv4 public ip for published addr
    #[arg(long)]
    pub ipv4: bool,
    /// Force ipv6 public ip for published addr
    #[arg(long)]
    pub ipv6: bool,
    #[arg(long)]
    /// Which type of publishing database. Static means the data to publish is part of
    /// the config, useful for terraform/service discovery. Dynamic means use an sqlite
    /// database.
    pub publisher: Option<GenerateConfigPublisherArgs>,
    /// Cards to use for static publishing (formatted as `PCSCID/PIN`)
    #[arg(long)]
    pub publisher_card_identities: Option<Vec<String>>,
    /// Local identities to use for static publishing (paths to identity files, not
    /// identity id)
    #[arg(long)]
    pub publisher_local_identities: Option<Vec<PathBuf>>,
    /// Build config for enabling the resolver
    #[arg(long)]
    pub resolver: bool,
    /// Build config for enabling the dns bridge
    #[arg(long)]
    pub dns_bridge: bool,
}

#[derive(clap::Args)]
struct GenerateDnsDataArgs {
    pub ttl: u32,
    #[arg(long)]
    pub dns_cname: Vec<String>,
    #[arg(long)]
    pub dns_a: Vec<String>,
    #[arg(long)]
    pub dns_aaaa: Vec<String>,
    #[arg(long)]
    pub dns_txt: Vec<String>,
    /// In the format `PRIORITY/NAME` ex `10/mail.example.org`
    #[arg(long)]
    pub dns_mx: Vec<String>,
}

#[derive(Parser)]
enum Args {
    /// Create a new local (file) identity
    NewLocalIdentity(NewLocalIdentityArgs),
    /// Register a local identity on a dynamic publisher
    RegisterLocalIdentity(RegisterLocalIdentityArgs),
    /// List usable pcsc cards (configured with curve25519/ed25519 signing keys)
    ListCards,
    /// Register a pcsc card with a dynamic publisher (card should be connected to
    /// publisher host)
    RegisterCardIdentity(RegisterCardIdentityArgs),
    /// Unregister an identity from a dynamic publisher
    UnregisterIdentity(UnregisterIdentityArgs),
    /// Create or replace existing publish data for an identity on a dynamic publisher
    /// server
    Publish(PublishArgs),
    /// Generate publish data for wrapping DNS and publish it on a dynamic publisher
    PublishDns(PublishDnsArgs),
    /// Query a resolver server for keys published under an identity
    Query(QueryArgs),
    /// Generate base server configs
    GenerateConfig(GenerateConfigArgs),
    /// Generate data for publishing DNS records
    GenerateDnsData(GenerateDnsDataArgs),
}

#[derive(Serialize, Deserialize)]
struct IdentitySecretFile {
    identity: Identity,
    secret: IdentitySecret,
}

#[async_trait]
trait ReqwestCheck {
    async fn check(self) -> Result<(), loga::Error>;
    async fn check_text(self) -> Result<String, loga::Error>;
}

#[async_trait]
impl ReqwestCheck for Result<Response, reqwest::Error> {
    async fn check(self) -> Result<(), loga::Error> {
        let resp = self?;
        let status = resp.status();
        let body = resp.bytes().await?.to_vec();
        if !status.is_success() {
            return Err(
                loga::Error::new("Request failed", ea!(status = status, body = String::from_utf8_lossy(&body))),
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
                loga::Error::new("Request failed", ea!(status = status, body = String::from_utf8_lossy(&body))),
            );
        }
        return Ok(
            String::from_utf8(
                body.clone(),
            ).context(
                "Failed to parse response as bytes",
                ea!(status = status, body = String::from_utf8_lossy(&body)),
            )?,
        );
    }
}

#[tokio::main]
async fn main() {
    let log = Log::new(loga::Level::Info);

    async fn inner(log: &Log) -> Result<(), loga::Error> {
        match Args::parse() {
            Args::NewLocalIdentity(args) => {
                let (ident, secret) = Identity::new();
                {
                    let log = log.fork(ea!(path = args.path.to_string_lossy()));
                    fs::write(args.path, &serde_json::to_string_pretty(&IdentitySecretFile {
                        identity: ident.clone(),
                        secret: secret,
                    }).unwrap()).log_context(&log, "Failed to write identity secret to file", ea!())?;
                }
                println!("identity [{}]", ident.to_string());
            },
            Args::RegisterLocalIdentity(config) => {
                let log = log.fork(ea!(path = config.identity.to_string_lossy()));
                let pair: IdentitySecretFile =
                    serde_json::from_slice(
                        &fs::read(&config.identity).log_context(&log, "Error opening identity file", ea!())?,
                    ).log_context(&log, "Error parsing identity from file", ea!())?;
                reqwest::ClientBuilder::new()
                    .build()
                    .unwrap()
                    .post(format!("{}identity", config.server))
                    .json(
                        &spaghettinuum::data::publisher::admin::RegisterIdentityRequest::Local(
                            spaghettinuum::data::publisher::admin::RegisterIdentityRequestLocal {
                                identity: pair.identity,
                                secret: pair.secret,
                            },
                        ),
                    )
                    .send()
                    .await
                    .check()
                    .await?;
            },
            Args::ListCards => {
                for card in PcscBackend::cards(None).log_context(log, "Failed to list smart cards", ea!())? {
                    let mut card: Card<Open> = card.into();
                    let mut transaction =
                        card.transaction().log_context(log, "Error starting transaction with card", ea!())?;
                    let card_id =
                        transaction
                            .application_identifier()
                            .log_context(log, "Error getting gpg id of card", ea!())?
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
                    println!("pcsc id [{}], identity [{}]", card_id, identity);
                }
            },
            Args::RegisterCardIdentity(config) => {
                reqwest::ClientBuilder::new()
                    .build()
                    .unwrap()
                    .post(format!("{}identity", config.server))
                    .json(
                        &spaghettinuum::data::publisher::admin::RegisterIdentityRequest::Card(
                            spaghettinuum::data::publisher::admin::RegisteryIdentityRequestCard {
                                pcsc_id: config.pcsc_id,
                                pin: config.pin,
                            },
                        ),
                    )
                    .send()
                    .await
                    .check()
                    .await?;
            },
            Args::UnregisterIdentity(config) => {
                reqwest::ClientBuilder::new()
                    .build()
                    .unwrap()
                    .delete(format!("{}identity/{}", config.server, config.identity))
                    .send()
                    .await
                    .check()
                    .await?;
            },
            Args::Publish(config) => {
                reqwest::ClientBuilder::new()
                    .build()
                    .unwrap()
                    .post(format!("{}publish/{}", config.server, config.identity))
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(fs::read(&config.data).log_context(log, "Failed to open data to publish", ea!())?)
                    .send()
                    .await
                    .check()
                    .await?;
            },
            Args::PublishDns(config) => {
                reqwest::ClientBuilder::new()
                    .build()
                    .unwrap()
                    .post(format!("{}publish/{}", config.server, config.identity))
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .json(&spaghettinuum::data::publisher::v1::Publish {
                        missing_ttl: config.ttl,
                        data: {
                            let mut kvs = HashMap::new();
                            if !config.dns_cname.is_empty() {
                                kvs.insert(KEY_DNS_CNAME.to_string(), PublishValue {
                                    ttl: config.ttl,
                                    data: serde_json::to_string(
                                        &crate::data::dns::DnsRecordsetJson::V1(
                                            crate::data::dns::v1::DnsRecordsetJson::Cname(config.dns_cname),
                                        ),
                                    ).unwrap(),
                                });
                            }
                            if !config.dns_a.is_empty() {
                                kvs.insert(KEY_DNS_A.to_string(), PublishValue {
                                    ttl: config.ttl,
                                    data: serde_json::to_string(
                                        &crate::data::dns::DnsRecordsetJson::V1(
                                            crate::data::dns::v1::DnsRecordsetJson::A(config.dns_a),
                                        ),
                                    ).unwrap(),
                                });
                            }
                            if !config.dns_aaaa.is_empty() {
                                kvs.insert(KEY_DNS_AAAA.to_string(), PublishValue {
                                    ttl: config.ttl,
                                    data: serde_json::to_string(
                                        &crate::data::dns::DnsRecordsetJson::V1(
                                            crate::data::dns::v1::DnsRecordsetJson::Aaaa(config.dns_aaaa),
                                        ),
                                    ).unwrap(),
                                });
                            }
                            if !config.dns_txt.is_empty() {
                                kvs.insert(KEY_DNS_TXT.to_string(), PublishValue {
                                    ttl: config.ttl,
                                    data: serde_json::to_string(
                                        &crate::data::dns::DnsRecordsetJson::V1(
                                            crate::data::dns::v1::DnsRecordsetJson::Txt(config.dns_txt),
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
                                                || loga::Error::new(
                                                    "Incorrect mx record specification, must be like `PRIORITY/NAME`",
                                                    ea!(entry = v),
                                                ),
                                            )?;
                                    let priority =
                                        u16::from_str(&priority).context("Couldn't parse priority as int", ea!())?;
                                    values.push((priority, name.to_string()));
                                }
                                kvs.insert(KEY_DNS_MX.to_string(), PublishValue {
                                    ttl: config.ttl,
                                    data: serde_json::to_string(
                                        &crate::data::dns::DnsRecordsetJson::V1(
                                            crate::data::dns::v1::DnsRecordsetJson::Mx(values),
                                        ),
                                    ).unwrap(),
                                });
                            }
                            kvs
                        },
                    })
                    .send()
                    .await
                    .check()
                    .await?;
            },
            Args::Query(config) => {
                println!(
                    "{}",
                    reqwest::ClientBuilder::new()
                        .build()
                        .unwrap()
                        .get(
                            format!(
                                "{}/v1/{}?{}",
                                config.server,
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
            Args::GenerateConfig(config) => {
                if config.ipv4 && config.ipv6 {
                    return Err(log.new_err("Both --ipv4 and --ipv6 specified; only one may be specified", ea!()));
                }
                let cwd = current_dir().unwrap();
                let config: Config = Config {
                    node: NodeConfig {
                        bind_addr: StrSocketAddr::new_fake(format!("0.0.0.0:{}", PORT_NODE)),
                        bootstrap: vec![BootstrapConfig {
                            addr: StrSocketAddr::new_fake(format!("spaghettinuum.isandrew.com:{}", PORT_NODE)),
                            id: NodeIdentity::from_str(
                                "yryyyyyyyb3jndem1w1e4f56cfhu3di3kpj5c6n8emk4bkye3ien388tj1thg",
                            ).unwrap(),
                        }],
                        persist_path: Some(cwd.join("node_persist.json")),
                    },
                    publisher: match config.publisher {
                        Some(c) => Some(spaghettinuum::publisher::config::Config {
                            bind_addr: StrSocketAddr::new_fake(format!("0.0.0.0:{}", PORT_PUBLISHER)),
                            cert_path: cwd.join("publisher_cert.json"),
                            advertise_addr: {
                                let log = log.fork(ea!(action = "external_ip_lookup"));
                                let resp =
                                    reqwest::get(if config.ipv4 {
                                        "https://ipv4.seeip.org"
                                    } else if config.ipv6 {
                                        "https://ipv6.seeip.org"
                                    } else {
                                        "https://api.seeip.org"
                                    })
                                        .await
                                        .log_context(&log, "Failed to make upstream request", ea!())?
                                        .text()
                                        .await
                                        .log_context(&log, "Error while reading upstream request", ea!())?;
                                const PORT: u16 = 43890;
                                match IpAddr::from_str(
                                    &resp,
                                ).log_context(&log, "Unable to parse reported external ip", ea!(body = resp))? {
                                    IpAddr::V4(i) => SocketAddr::V4(SocketAddrV4::new(i, PORT)),
                                    IpAddr::V6(i) => {
                                        SocketAddr::V6(SocketAddrV6::new(i, PORT, 0, 0))
                                    },
                                }
                            },
                            data: match c {
                                GenerateConfigPublisherArgs::Static => {
                                    spaghettinuum::publisher::config::DataConfig::Static({
                                        let mut idents = HashMap::new();
                                        for local in config.publisher_local_identities.iter().flatten() {
                                            let log = log.fork(ea!(path = local.to_string_lossy()));
                                            let local: IdentitySecretFile =
                                                serde_json::from_slice(
                                                    &fs::read(
                                                        local,
                                                    ).log_context(&log, "Error opening local identity", ea!())?,
                                                ).log_context(&log, "Error parsing local identity", ea!())?;
                                            idents.insert(local.identity, IdentityData {
                                                secret: SecretType::Local(local.secret),
                                                kvs: spaghettinuum::data::publisher::v1::Publish {
                                                    missing_ttl: 60,
                                                    data: {
                                                        let mut kvs = HashMap::new();
                                                        kvs.insert("somekey".to_string(), PublishValue {
                                                            ttl: 60,
                                                            data: "somevalue".to_string(),
                                                        });
                                                        kvs
                                                    },
                                                },
                                            });
                                        }
                                        for card in config.publisher_card_identities.iter().flatten() {
                                            let (pcsc_id, pin) =
                                                card
                                                    .split_once("/")
                                                    .ok_or_else(
                                                        || loga::Error::new(
                                                            "Incorrect card description; should be like `PCSCID/PIN`",
                                                            ea!(desc = card),
                                                        ),
                                                    )?;
                                            let log = log.fork(ea!(card = card));
                                            let ident =
                                                match pgp::card_to_ident(
                                                    &mut <Card<Open>>::from(
                                                        PcscBackend::open_by_ident(
                                                            card,
                                                            None,
                                                        ).log_context(&log, "Error opening smartcard", ea!())?,
                                                    )
                                                        .transaction()
                                                        .log_context(&log, "Error starting transaction", ea!())?,
                                                ).log_context(&log, "Error looking up key information", ea!())? {
                                                    Some(ident) => ident,
                                                    None => {
                                                        return Err(
                                                            log.new_err(
                                                                "Card doesn't have a supported key type",
                                                                ea!(card = card),
                                                            ),
                                                        );
                                                    },
                                                };
                                            idents.insert(ident, IdentityData {
                                                secret: SecretType::Card(SecretTypeCard {
                                                    pcsc_id: pcsc_id.to_string(),
                                                    pin: pin.to_string(),
                                                }),
                                                kvs: spaghettinuum::data::publisher::v1::Publish {
                                                    missing_ttl: 60,
                                                    data: {
                                                        let mut kvs = HashMap::new();
                                                        kvs.insert("somekey".to_string(), PublishValue {
                                                            ttl: 60,
                                                            data: "somevalue".to_string(),
                                                        });
                                                        kvs
                                                    },
                                                },
                                            });
                                        }
                                        idents
                                    })
                                },
                                GenerateConfigPublisherArgs::Dynamic => {
                                    spaghettinuum::publisher::config::DataConfig::Dynamic(
                                        spaghettinuum::publisher::config::DynamicDataConfig {
                                            db_path: cwd.join("publisher.sqlite3"),
                                            bind_addr: StrSocketAddr::new_fake(
                                                format!("0.0.0.0:{}", PORT_PUBLISHER_API),
                                            ),
                                        },
                                    )
                                },
                            },
                        }),
                        None => None,
                    },
                    resolver: if config.resolver || config.dns_bridge {
                        Some(spaghettinuum::resolver::config::ResolverConfig {
                            bind_addr: if config.dns_bridge {
                                Some(StrSocketAddr::new_fake(format!("0.0.0.0:{}", PORT_RESOLVER)))
                            } else {
                                None
                            },
                            cache_persist_path: Some(cwd.join("resolver_cache.sqlite3")),
                            max_cache: None,
                            dns_bridge: if config.dns_bridge {
                                Some(spaghettinuum::resolver::config::DnsBridgerConfig {
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
                };
                println!("{}", serde_json::to_string_pretty(&config).unwrap());
            },
            Args::GenerateDnsData(config) => {
                println!("{}", serde_json::to_string_pretty(&spaghettinuum::data::publisher::v1::Publish {
                    missing_ttl: config.ttl,
                    data: {
                        let mut kvs = HashMap::new();
                        if !config.dns_cname.is_empty() {
                            kvs.insert(KEY_DNS_CNAME.to_string(), PublishValue {
                                ttl: config.ttl,
                                data: serde_json::to_string(
                                    &crate::data::dns::DnsRecordsetJson::V1(
                                        crate::data::dns::v1::DnsRecordsetJson::Cname(config.dns_cname),
                                    ),
                                ).unwrap(),
                            });
                        }
                        if !config.dns_a.is_empty() {
                            kvs.insert(KEY_DNS_A.to_string(), PublishValue {
                                ttl: config.ttl,
                                data: serde_json::to_string(
                                    &crate::data::dns::DnsRecordsetJson::V1(
                                        crate::data::dns::v1::DnsRecordsetJson::A(config.dns_a),
                                    ),
                                ).unwrap(),
                            });
                        }
                        if !config.dns_aaaa.is_empty() {
                            kvs.insert(KEY_DNS_AAAA.to_string(), PublishValue {
                                ttl: config.ttl,
                                data: serde_json::to_string(
                                    &crate::data::dns::DnsRecordsetJson::V1(
                                        crate::data::dns::v1::DnsRecordsetJson::Aaaa(config.dns_aaaa),
                                    ),
                                ).unwrap(),
                            });
                        }
                        if !config.dns_txt.is_empty() {
                            kvs.insert(KEY_DNS_TXT.to_string(), PublishValue {
                                ttl: config.ttl,
                                data: serde_json::to_string(
                                    &crate::data::dns::DnsRecordsetJson::V1(
                                        crate::data::dns::v1::DnsRecordsetJson::Txt(config.dns_txt),
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
                                            || loga::Error::new(
                                                "Incorrect mx record specification, must be like `PRIORITY/NAME`",
                                                ea!(entry = v),
                                            ),
                                        )?;
                                let priority =
                                    u16::from_str(&priority).context("Couldn't parse priority as int", ea!())?;
                                values.push((priority, name.to_string()));
                            }
                            kvs.insert(KEY_DNS_MX.to_string(), PublishValue {
                                ttl: config.ttl,
                                data: serde_json::to_string(
                                    &crate::data::dns::DnsRecordsetJson::V1(
                                        crate::data::dns::v1::DnsRecordsetJson::Mx(values),
                                    ),
                                ).unwrap(),
                            });
                        }
                        kvs
                    },
                }).unwrap());
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
