use std::{
    path::PathBuf,
    fs,
    net::{
        SocketAddr,
        SocketAddrV4,
        Ipv4Addr,
        IpAddr,
        SocketAddrV6,
    },
    env::current_dir,
    str::FromStr,
    collections::HashMap,
};
use clap::{
    Parser,
    builder::{
        PossibleValue,
    },
    ValueEnum,
};
use itertools::Itertools;
use loga::{
    Log,
    ea,
    ResultContext,
};
use openpgp_card_pcsc::{
    PcscBackend,
};
use openpgp_card_sequoia::{
    state::Open,
    Card,
};
use poem::{
    http::{
        Uri,
    },
    async_trait,
};
use reqwest::Response;
use serde::{
    Serialize,
    Deserialize,
};
use spaghettinuum::{
    model::{
        identity::{
            Identity,
            IdentitySecret,
        },
        config::{
            Config,
        },
        self,
        publish::v1::{
            KeyValues,
            Value,
        },
    },
    utils::{
        card,
        standard::{
            PORT_RESOLVER,
            PORT_PUBLISHER_API,
            PORT_NODE,
            PORT_PUBLISHER,
        },
    },
    publisher::{
        self,
        model::config::{
            SecretType,
            IdentityData,
        },
    },
    resolver,
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
    pub gpg_id: String,
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
    /// Card identities to use for static publishing (card ids per pcscd, not identity
    /// id)
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

#[derive(Parser)]
enum Args {
    NewLocalIdentity(NewLocalIdentityArgs),
    RegisterLocalIdentity(RegisterLocalIdentityArgs),
    ListCards,
    RegisterCardIdentity(RegisterCardIdentityArgs),
    UnregisterIdentity(UnregisterIdentityArgs),
    Publish(PublishArgs),
    Query(QueryArgs),
    GenerateConfig(GenerateConfigArgs),
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
                        &publisher::model::protocol::admin::RegisterIdentityRequest::Local(
                            publisher::model::protocol::admin::RegisterIdentityRequestLocal {
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
                    let identity = match card::card_to_ident(&mut transaction) {
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
                    println!("card [{}], identity [{}]", card_id, identity);
                }
            },
            Args::RegisterCardIdentity(config) => {
                reqwest::ClientBuilder::new()
                    .build()
                    .unwrap()
                    .post(format!("{}identity", config.server))
                    .json(
                        &crate::publisher::model::protocol::admin::RegisterIdentityRequest::Card(
                            crate::publisher::model::protocol::admin::RegisteryIdentityRequestCard {
                                gpg_id: config.gpg_id,
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
            Args::Query(config) => {
                println!(
                    "{}",
                    reqwest::ClientBuilder::new()
                        .build()
                        .unwrap()
                        .get(
                            format!(
                                "{}/{}?{}",
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
                let config: Config = model::config::Config {
                    node: model::config::NodeConfig {
                        bind_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), PORT_NODE)),
                        // TODO!
                        bootstrap: vec![],
                        persist_path: Some(cwd.join("node_persist.json")),
                    },
                    publisher: match config.publisher {
                        Some(c) => Some(publisher::model::config::Config {
                            bind_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), PORT_PUBLISHER)),
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
                                    IpAddr::V6(i) => SocketAddr::V6(SocketAddrV6::new(i, PORT, 0, 0)),
                                }
                            },
                            data: match c {
                                GenerateConfigPublisherArgs::Static => publisher::model::config::DataConfig::Static({
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
                                            kvs: {
                                                let mut kvs = HashMap::new();
                                                kvs.insert("somekey".to_string(), Value {
                                                    ttl: 3600u32,
                                                    data: "somevalue".to_string(),
                                                });
                                                KeyValues(kvs)
                                            },
                                        });
                                    }
                                    for card in config.publisher_card_identities.iter().flatten() {
                                        let log = log.fork(ea!(card = card));
                                        let ident =
                                            match card::card_to_ident(
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
                                            secret: SecretType::Card(card.clone()),
                                            kvs: {
                                                let mut kvs = HashMap::new();
                                                kvs.insert("somekey".to_string(), Value {
                                                    ttl: 3600u32,
                                                    data: "somevalue".to_string(),
                                                });
                                                KeyValues(kvs)
                                            },
                                        });
                                    }
                                    idents
                                }),
                                GenerateConfigPublisherArgs::Dynamic => publisher::model::config::DataConfig::Dynamic(
                                    publisher::model::config::DynamicDataConfig {
                                        db: cwd.join("publisher.sqlite3"),
                                        bind_addr: SocketAddr::V4(
                                            SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), PORT_PUBLISHER_API),
                                        ),
                                    },
                                ),
                            },
                        }),
                        None => None,
                    },
                    resolver: if config.resolver || config.dns_bridge {
                        Some(resolver::ResolverConfig {
                            bind_addr: if config.dns_bridge {
                                Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), PORT_RESOLVER)))
                            } else {
                                None
                            },
                            cache_path: Some(cwd.join("resolver_cache.sqlite3")),
                            max_cache: None,
                            dns_bridge: if config.dns_bridge {
                                Some(resolver::DnsBridgerConfig {
                                    upstream: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 53)),
                                    bind_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 53)),
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
