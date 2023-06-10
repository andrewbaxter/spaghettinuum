use chrono::Utc;
use clap::{
    Parser,
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
use sequoia_openpgp::{
    types::HashAlgorithm,
    crypto::Signer,
};
use spaghettinuum::{
    config::Config,
    data::{
        self,
        identity::{
            Identity,
            IdentitySecret,
            IdentitySecretVersionMethods,
        },
        node::{
            nodeidentity::NodeIdentity,
            protocol::SerialAddr,
        },
        publisher::{
            v1::{
                PublishValue,
                Publish,
            },
            admin::PublishRequest,
            announcement::v1::Announcement,
        },
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
        AdvertiseAddrConfig,
        AdvertiseAddrLookupConfig,
    },
    utils::{
        pgp::{
            self,
            extract_pgp_ed25519_sig,
            pgp_eddsa_to_identity,
        },
        lookup_ip,
    },
    es,
};
use std::{
    collections::HashMap,
    env::current_dir,
    fs,
    net::{
        SocketAddr,
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
struct ShowLocalIdentityArgs {
    /// Path to local identity file
    pub path: PathBuf,
}

#[derive(Clone, clap::Args)]
struct LocalIdentityArg {
    pub path: PathBuf,
}

#[derive(Clone, clap::Args)]
struct CardIdentityArg {
    /// Card to register, using id per pcscd (not identity id)
    pub pcsc_id: String,
    /// Card pin
    pub pin: String,
}

#[derive(Clone, clap::Subcommand)]
enum IdentityArg {
    Local(LocalIdentityArg),
    Card(CardIdentityArg),
}

#[derive(clap::Args)]
struct PublishArgs {
    /// URL of a server with publishing set up
    pub server: Uri,
    /// Identity to publish as
    #[clap(subcommand)]
    pub identity: IdentityArg,
    /// Data to publish.  Must be a json in the structure
    /// `{KEY: {"ttl": SECONDS, "value": "DATA"}}`
    pub data: PathBuf,
}

#[derive(clap::Args)]
struct PublishDnsArgs {
    /// URL of a server with publishing set up
    pub server: Uri,
    /// Identity to publish as
    #[clap(subcommand)]
    pub identity: IdentityArg,
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
struct UnpublishArgs {
    /// URL of a server with publishing set up
    pub server: Uri,
    #[clap(subcommand)]
    pub identity: IdentityArg,
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

#[derive(clap::Args)]
struct GenerateConfigArgs {
    /// Enable the publisher, allowing you to publish data on your server
    #[arg(long)]
    pub publisher: bool,
    /// Use specific address for publishing announcements, rather than automatic
    /// detection
    #[arg(long)]
    pub publisher_advertise_addr: Option<SocketAddr>,
    /// Configure the publisher to look up the advertise addr at startup via this URL.
    /// The URL must respond to a GET with the body containing just the IP address
    /// string.
    #[arg(long)]
    pub publisher_advertise_addr_lookup: Option<String>,
    /// Force ipv4 public ip for publisher advertised addr detection
    #[arg(long)]
    pub publisher_advertise_addr_ipv4: bool,
    /// Force ipv6 public ip for publisher advertised addr detection
    #[arg(long)]
    pub publisher_advertise_addr_ipv6: bool,
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
struct GenerateDnsKeyValuesArgs {
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
    /// Show the identity for a local identity file
    ShowLocalIdentity(ShowLocalIdentityArgs),
    /// List usable pcsc cards (configured with curve25519/ed25519 signing keys)
    ShowCardIdentities,
    /// Create or replace existing publish data for an identity on a publisher server
    Publish(PublishArgs),
    /// Generate publish data for wrapping DNS and publish it on a publisher
    PublishDns(PublishDnsArgs),
    /// Create or replace existing publish data for an identity on a publisher server
    Unpublish(UnpublishArgs),
    /// Query a resolver server for keys published under an identity
    Query(QueryArgs),
    /// Generate base server configs
    GenerateConfig(GenerateConfigArgs),
    /// Generate data for publishing DNS records
    GenerateDnsKeyValues(GenerateDnsKeyValuesArgs),
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

    async fn check_bytes(self) -> Result<Vec<u8>, loga::Error> {
        let resp = self?;
        let status = resp.status();
        let body = resp.bytes().await?.to_vec();
        if !status.is_success() {
            return Err(
                loga::Error::new("Request failed", ea!(status = status, body = String::from_utf8_lossy(&body))),
            );
        }
        return Ok(body);
    }
}

async fn publish(
    log: &loga::Log,
    server: &Uri,
    identity_arg: IdentityArg,
    keyvalues: Publish,
) -> Result<(), loga::Error> {
    let c = reqwest::ClientBuilder::new().build().unwrap();
    let info_body = c.get(format!("{}/info", server)).send().await.check_bytes().await?;
    let info: crate::data::publisher::admin::InfoResponse =
        serde_json::from_slice(
            &info_body,
        ).log_context(
            log,
            "Error parsing info response from publisher as json",
            ea!(body = String::from_utf8_lossy(&info_body)),
        )?;
    let announce_message = crate::data::node::protocol::v1::ValueBody {
        addr: SerialAddr(info.advertise_addr),
        cert_hash: zbase32::decode_full_bytes_str(
            &info.cert_pub_hash,
        ).map_err(
            |e| log.new_err("Couldn't parse zbase32 pub cert hash in response from publisher", ea!(text = e)),
        )?,
        published: Utc::now(),
    }.to_bytes();
    let (identity, announcement) = match identity_arg {
        IdentityArg::Local(ident_config) => {
            let secret: IdentitySecret =
                serde_json::from_slice(
                    &fs::read(&ident_config.path).log_context(&log, "Error opening identity secret file", ea!())?,
                ).log_context(&log, "Error parsing identity secret from file", ea!())?;
            let identity = secret.identity();
            (identity, Announcement {
                message: announce_message.clone(),
                signature: secret.sign(announce_message.as_ref()),
            })
        },
        IdentityArg::Card(ident_config) => {
            let mut card: Card<Open> = PcscBackend::open_by_ident(&ident_config.pcsc_id, None)?.into();
            let mut transaction = card.transaction()?;
            let pin = if ident_config.pin == "-" {
                rpassword::prompt_password(
                    "Enter your pin to sign announcement: ",
                ).log_context(log, "Error securely reading pin", ea!())?
            } else {
                ident_config.pin
            };
            transaction
                .verify_user_for_signing(pin.as_bytes())
                .log_context(log, "Error unlocking card with pin", ea!(card = ident_config.pcsc_id))?;
            let mut user = transaction.signing_card().unwrap();
            let signer_interact = || eprintln!("Card {} requests interaction to sign", ident_config.pcsc_id);
            let mut signer = user.signer(&signer_interact)?;
            match es!({
                match signer.public() {
                    sequoia_openpgp::packet::Key::V4(k) => match k.mpis() {
                        sequoia_openpgp::crypto::mpi::PublicKey::EdDSA { curve, q } => {
                            let identity = match pgp_eddsa_to_identity(curve, q) {
                                Some(i) => i,
                                None => return Ok(None),
                            };
                            let hash = crate::data::identity::hash_for_ed25519(&announce_message);
                            return Ok(Some((identity, Announcement {
                                message: announce_message.clone(),
                                signature: extract_pgp_ed25519_sig(
                                    &signer
                                        .sign(HashAlgorithm::SHA512, &hash)
                                        .map_err(|e| loga::Error::new("Card signature failed", ea!(err = e)))?,
                                ).to_vec(),
                            })));
                        },
                        _ => {
                            return Ok(None);
                        },
                    },
                    _ => {
                        return Ok(None);
                    },
                };
            })? {
                Some(r) => r,
                None => {
                    return Err(loga::Error::new("Unsupported key type - must be Ed25519", ea!()));
                },
            }
        },
    };
    c.post(format!("{}publish/{}", server, identity.to_string())).json(&PublishRequest {
        announce: announcement,
        keyvalues: keyvalues,
    }).send().await.check().await?;
    return Ok(());
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
                    fs::write(
                        args.path,
                        &serde_json::to_string_pretty(&secret).unwrap(),
                    ).log_context(&log, "Failed to write identity secret to file", ea!())?;
                }
                println!("identity [{}]", ident.to_string());
            },
            Args::ShowLocalIdentity(p) => {
                let secret: IdentitySecret =
                    serde_json::from_slice(
                        &fs::read(&p.path).log_context(&log, "Error opening identity secret file", ea!())?,
                    ).log_context(&log, "Error parsing identity secret from file", ea!())?;
                let identity = secret.identity();
                println!("identity [{}]", identity.to_string());
            },
            Args::ShowCardIdentities => {
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
            Args::Publish(config) => {
                publish(
                    log,
                    &config.server,
                    config.identity,
                    serde_json::from_slice(
                        &fs::read(&config.data).log_context(log, "Failed to open data to publish", ea!())?,
                    ).log_context(log, "Failed to parse publish data json into key values structure", ea!())?,
                ).await?;
            },
            Args::PublishDns(config) => {
                publish(log, &config.server, config.identity, spaghettinuum::data::publisher::v1::Publish {
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
                }).await?;
            },
            Args::Unpublish(config) => {
                let identity = match config.identity {
                    IdentityArg::Local(ident_config) => {
                        let secret: IdentitySecret =
                            serde_json::from_slice(
                                &fs::read(
                                    &ident_config.path,
                                ).log_context(&log, "Error opening identity secret file", ea!())?,
                            ).log_context(&log, "Error parsing identity secret from file", ea!())?;
                        secret.identity()
                    },
                    IdentityArg::Card(ident_config) => {
                        let mut card: Card<Open> = PcscBackend::open_by_ident(&ident_config.pcsc_id, None)?.into();
                        let mut transaction = card.transaction()?;
                        let mut user = transaction.signing_card().unwrap();
                        let signer_interact = || panic!("Card requesting interaction despite not signing");
                        let signer = user.signer(&signer_interact)?;
                        match es!({
                            match signer.public() {
                                sequoia_openpgp::packet::Key::V4(k) => match k.mpis() {
                                    sequoia_openpgp::crypto::mpi::PublicKey::EdDSA { curve, q } => {
                                        return Ok(Some(match pgp_eddsa_to_identity(curve, q) {
                                            Some(i) => i,
                                            None => return Ok(None),
                                        }));
                                    },
                                    _ => {
                                        return Ok(None);
                                    },
                                },
                                _ => {
                                    return Ok(None);
                                },
                            };
                        })? {
                            Some(r) => r,
                            None => {
                                return Err(loga::Error::new("Unsupported key type - must be Ed25519", ea!()));
                            },
                        }
                    },
                };
                reqwest::ClientBuilder::new()
                    .build()
                    .unwrap()
                    .delete(format!("{}publish/{}", config.server, identity.to_string()))
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
                if (config.publisher_advertise_addr.is_some() as i32) + (config.publisher_advertise_addr_ipv4 as i32) +
                    (config.publisher_advertise_addr_ipv6 as i32) >
                    1 {
                    return Err(
                        log.new_err("Only one of --advertise-addr, --ipv4 and --ipv6 may be specified", ea!()),
                    );
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
                    publisher: if config.publisher {
                        Some(spaghettinuum::publisher::config::Config {
                            bind_addr: StrSocketAddr::new_fake(format!("0.0.0.0:{}", PORT_PUBLISHER)),
                            cert_path: cwd.join("publisher_cert.json"),
                            advertise_addr: if let Some(advertise_addr) = config.publisher_advertise_addr {
                                AdvertiseAddrConfig::Fixed(advertise_addr)
                            } else {
                                match config.publisher_advertise_addr_lookup {
                                    Some(l) => {
                                        AdvertiseAddrConfig::Lookup(AdvertiseAddrLookupConfig {
                                            lookup: l,
                                            port: PORT_PUBLISHER,
                                            ipv4_only: config.publisher_advertise_addr_ipv4,
                                            ipv6_only: config.publisher_advertise_addr_ipv6,
                                        })
                                    },
                                    None => {
                                        AdvertiseAddrConfig::Fixed(
                                            SocketAddr::new(
                                                lookup_ip(
                                                    "https://api.seeip.org",
                                                    config.publisher_advertise_addr_ipv4,
                                                    config.publisher_advertise_addr_ipv6,
                                                ).await?,
                                                PORT_PUBLISHER,
                                            ),
                                        )
                                    },
                                }
                            },
                            db_path: cwd.join("publisher.sqlite3"),
                            admin_bind_addr: StrSocketAddr::new_fake(format!("0.0.0.0:{}", PORT_PUBLISHER_API)),
                        })
                    } else {
                        None
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
            Args::GenerateDnsKeyValues(config) => {
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
