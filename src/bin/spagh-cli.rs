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
use reqwest::{
    Response,
};
use sequoia_openpgp::{
    types::HashAlgorithm,
    crypto::Signer,
};
use serde_json::json;
use spaghettinuum::{
    config::Config,
    data::{
        self,
        identity::{
            Identity,
            IdentitySecretVersionMethods,
            IdentitySecret,
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
            public::{
                PublishRequest,
                PublishRequestBody,
                PublishRequestSigned,
                UnpublishRequestBody,
                UnpublishRequest,
                UnpublishRequestSigned,
            },
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
            PORT_PRIV,
            PORT_PUB,
            ENV_PRIV_ADDR,
            ENV_PUB_ADDR,
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
};
use std::{
    collections::HashMap,
    env::{
        current_dir,
        self,
    },
    fs,
    net::{
        SocketAddr,
    },
    str::FromStr,
};

mod args {
    use std::{
        path::PathBuf,
        net::SocketAddr,
    };
    use aargvark::{
        Aargvark,
        AargvarkJson,
    };
    use poem::http::Uri;
    use spaghettinuum::data::identity::IdentitySecret;

    #[derive(Aargvark)]
    pub struct NewLocalIdentity {
        /// Store the new id and secret in a file at this path
        pub path: PathBuf,
    }

    #[derive(Clone, Aargvark)]
    pub enum Identity {
        Local(AargvarkJson<IdentitySecret>),
        Card {
            /// Card to register, using id per pcscd (not identity id)
            pcsc_id: String,
            /// Card pin
            pin: String,
        },
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
        pub identity: Identity,
        /// Data to publish.  Must be json in the structure
        /// `{KEY: {"ttl": SECONDS, "value": "DATA"}, ...}`
        pub data: AargvarkJson<crate::data::publisher::v1::Publish>,
    }

    #[derive(Aargvark)]
    pub struct PublishDns {
        /// URL of a server with publishing set up. Defaults to the value of environment
        /// variable `SPAGH` or else localhost with the default port.
        pub server: Option<Uri>,
        /// Identity to publish as
        pub identity: Identity,
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
        pub identity: Identity,
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
        /// Use specific address for publishing announcements, rather than automatic
        /// detection
        pub publisher_advertise_addr: Option<SocketAddr>,
        /// Configure the publisher to look up the advertise addr at startup via this URL.
        /// The URL must respond to a GET with the body containing just the IP address
        /// string.
        pub publisher_advertise_addr_lookup: Option<String>,
        /// Force ipv4 public ip for publisher advertised addr detection
        pub publisher_advertise_addr_ipv4: Option<()>,
        /// Force ipv6 public ip for publisher advertised addr detection
        pub publisher_advertise_addr_ipv6: Option<()>,
        /// Build config for enabling the resolver
        pub resolver: Option<()>,
        /// Build config for enabling the dns bridge
        pub dns_bridge: Option<()>,
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
        ShowLocalIdentity(AargvarkJson<IdentitySecret>),
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

fn default_url(
    log: &loga::Log,
    mut url: Option<Uri>,
    env_key: &'static str,
    default_port: u16,
) -> Result<Uri, loga::Error> {
    if url.is_none() {
        match env::var(env_key) {
            Ok(e) => {
                url =
                    Some(
                        Uri::from_str(
                            &e,
                        ).log_context_with(log, "Couldn't parse environment variable", ea!(env = env_key))?,
                    );
            },
            Err(e) => {
                match e {
                    env::VarError::NotPresent => { },
                    env::VarError::NotUnicode(e) => {
                        return Err(
                            log.new_err_with(
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

fn publisher_priv_client(_log: &loga::Log) -> Result<reqwest::Client, loga::Error> {
    return Ok(reqwest::ClientBuilder::new().build().unwrap());
}

fn default_priv_url(log: &loga::Log, url: Option<Uri>) -> Result<Uri, loga::Error> {
    return default_url(log, url, ENV_PRIV_ADDR, PORT_PRIV);
}

fn default_pub_url(log: &loga::Log, url: Option<Uri>) -> Result<Uri, loga::Error> {
    return default_url(log, url, ENV_PUB_ADDR, PORT_PUB);
}

trait IdentitySigner {
    fn sign(&mut self, data: &[u8]) -> Result<(Identity, Vec<u8>), loga::Error>;
}

struct LocalIdentitySigner(IdentitySecret);

impl IdentitySigner for LocalIdentitySigner {
    fn sign(&mut self, data: &[u8]) -> Result<(Identity, Vec<u8>), loga::Error> {
        return Ok((self.0.identity(), self.0.sign(data)));
    }
}

fn get_identity_signer(ident: args::Identity) -> Result<Box<dyn IdentitySigner>, loga::Error> {
    match ident {
        args::Identity::Local(ident_config) => {
            return Ok(Box::new(LocalIdentitySigner(ident_config.0)));
        },
        args::Identity::Card { pcsc_id, pin } => {
            let pin = if pin == "-" {
                rpassword::prompt_password(
                    "Enter your pin to sign announcement: ",
                ).context("Error securely reading pin")?
            } else {
                pin
            };
            return Ok(Box::new(CardIdentitySigner {
                card: PcscBackend::open_by_ident(&pcsc_id, None)
                    .context_with("Failed to open card", ea!(card = pcsc_id))?
                    .into(),
                pcsc_id: pcsc_id,
                pin: pin,
            }));
        },
    };
}

struct CardIdentitySigner {
    pcsc_id: String,
    pin: String,
    card: Card<Open>,
}

impl IdentitySigner for CardIdentitySigner {
    fn sign(&mut self, data: &[u8]) -> Result<(Identity, Vec<u8>), loga::Error> {
        let mut transaction = self.card.transaction().context("Failed to start card transaction")?;
        transaction
            .verify_user_for_signing(self.pin.as_bytes())
            .context_with("Error unlocking card with pin", ea!(card = self.pcsc_id))?;
        let mut user = transaction.signing_card().unwrap();
        let signer_interact = || eprintln!("Card {} requests interaction to sign", self.pcsc_id);
        let mut signer = user.signer(&signer_interact).context("Failed to get signer from card")?;
        let identity;
        loop {
            match signer.public() {
                sequoia_openpgp::packet::Key::V4(k) => match k.mpis() {
                    sequoia_openpgp::crypto::mpi::PublicKey::EdDSA { curve, q } => {
                        if let Some(i) = pgp_eddsa_to_identity(curve, q) {
                            identity = i;
                            break;
                        };
                    },
                    _ => (),
                },
                _ => (),
            };
            return Err(loga::err("Unsupported key type - must be Ed25519"));
        }
        return Ok(
            (
                identity,
                extract_pgp_ed25519_sig(
                    &signer
                        .sign(HashAlgorithm::SHA512, &crate::data::identity::hash_for_ed25519(data))
                        .map_err(|e| loga::err_with("Card signature failed", ea!(err = e)))?,
                ).to_vec(),
            ),
        );
    }
}

async fn publish(
    log: &loga::Log,
    c: reqwest::Client,
    server: &Uri,
    identity_arg: args::Identity,
    keyvalues: Publish,
) -> Result<(), loga::Error> {
    let info_body =
        c
            .get(format!("{}info", server))
            .send()
            .await
            .check_bytes()
            .await
            .log_context(log, "Error getting publisher info")?;
    let info: crate::data::publisher::public::InfoResponse =
        serde_json::from_slice(
            &info_body,
        ).log_context_with(
            log,
            "Error parsing info response from publisher as json",
            ea!(body = String::from_utf8_lossy(&info_body)),
        )?;
    let announce_message = crate::data::node::protocol::v1::ValueBody {
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
    let request_message = PublishRequestBody {
        announce: Announcement {
            message: announce_message.clone(),
            signature: request_message_sig,
        },
        keyvalues: keyvalues,
    }.to_bytes();
    let request = PublishRequest {
        identity: identity,
        signed: PublishRequestSigned {
            signature: signer.sign(&request_message).log_context(&log, "Failed to sign publish request")?.1,
            message: request_message,
        },
    };
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
                let (ident, secret) = Identity::new();
                {
                    let log = log.fork(ea!(path = args.path.to_string_lossy()));
                    fs::write(
                        args.path,
                        &serde_json::to_string_pretty(&secret).unwrap(),
                    ).log_context(&log, "Failed to write identity secret to file")?;
                }
                println!("{}", serde_json::to_string_pretty(&json!({
                    "identity": ident.to_string()
                })).unwrap());
            },
            args::Args::ShowLocalIdentity(p) => {
                let secret = p.0;
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
                publisher_priv_client(log)?
                    .post(format!("{}publish/register/{}", default_priv_url(log, config.server)?, config.identity_id))
                    .send()
                    .await
                    .check_text()
                    .await?;
            },
            args::Args::Unregister(config) => {
                publisher_priv_client(log)?
                    .post(
                        format!("{}publish/unregister/{}", default_priv_url(log, config.server)?, config.identity_id),
                    )
                    .send()
                    .await
                    .check_text()
                    .await?;
            },
            args::Args::Publish(config) => {
                publish(
                    log,
                    reqwest::ClientBuilder::new().build().unwrap(),
                    &default_priv_url(log, config.server)?,
                    config.identity,
                    config.data.0,
                ).await?;
            },
            args::Args::PublishDns(config) => {
                publish(
                    log,
                    reqwest::ClientBuilder::new().build().unwrap(),
                    &default_priv_url(log, config.server)?,
                    config.identity,
                    spaghettinuum::data::publisher::v1::Publish {
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
                                                || loga::err_with(
                                                    "Incorrect mx record specification, must be like `PRIORITY/NAME`",
                                                    ea!(entry = v),
                                                ),
                                            )?;
                                    let priority =
                                        u16::from_str(&priority).context("Couldn't parse priority as int")?;
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
                    },
                ).await?;
            },
            args::Args::Unpublish(config) => {
                let c = reqwest::ClientBuilder::new().build().unwrap();
                let mut signer =
                    get_identity_signer(config.identity).log_context(&log, "Error constructing signer")?;
                let request_message = UnpublishRequestBody { now: Utc::now() }.to_bytes();
                let (identity, request_message_sig) =
                    signer.sign(&request_message).log_context(&log, "Failed to sign unpublish request")?;
                let request = UnpublishRequest {
                    identity: identity,
                    signed: UnpublishRequestSigned {
                        signature: request_message_sig,
                        message: request_message,
                    },
                };
                c
                    .post(format!("{}publish/unpublish", default_pub_url(&log, config.server)?))
                    .json(&request)
                    .send()
                    .await
                    .check()
                    .await
                    .log_context(log, "Error making unpublish request")?;
            },
            args::Args::ListPublisherIdentities(config) => {
                let mut out = vec![];
                let c = publisher_priv_client(log)?;
                let url = default_priv_url(log, config.server)?;
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
                    publisher_priv_client(log)?
                        .get(format!("{}publish/{}", default_priv_url(log, config.server)?, config.identity))
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
                                default_pub_url(log, config.server)?,
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
                if (config.publisher_advertise_addr.is_some() as i32) +
                    (config.publisher_advertise_addr_ipv4.is_some() as i32) +
                    (config.publisher_advertise_addr_ipv6.is_some() as i32) >
                    1 {
                    return Err(log.new_err("Only one of --advertise-addr, --ipv4 and --ipv6 may be specified"));
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
                    public_http_addr: if config.publisher.is_some() || config.resolver.is_some() {
                        Some(StrSocketAddr::new_fake(format!("0.0.0.0:{}", PORT_PUB)))
                    } else {
                        None
                    },
                    private_http_addr: if config.publisher.is_some() {
                        Some(StrSocketAddr::new_fake(format!("0.0.0.0:{}", PORT_PRIV)))
                    } else {
                        None
                    },
                    publisher: if config.publisher.is_some() {
                        Some(spaghettinuum::publisher::config::PublisherConfig {
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
                                            ipv4_only: config.publisher_advertise_addr_ipv4.is_some(),
                                            ipv6_only: config.publisher_advertise_addr_ipv6.is_some(),
                                        })
                                    },
                                    None => {
                                        AdvertiseAddrConfig::Fixed(
                                            SocketAddr::new(
                                                lookup_ip(
                                                    "https://api.seeip.org",
                                                    config.publisher_advertise_addr_ipv4.is_some(),
                                                    config.publisher_advertise_addr_ipv6.is_some(),
                                                ).await?,
                                                PORT_PUBLISHER,
                                            ),
                                        )
                                    },
                                }
                            },
                            db_path: cwd.join("publisher.sqlite3"),
                        })
                    } else {
                        None
                    },
                    resolver: if config.resolver.is_some() || config.dns_bridge.is_some() {
                        Some(spaghettinuum::resolver::config::ResolverConfig {
                            cache_persist_path: Some(cwd.join("resolver_cache.sqlite3")),
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
                };
                println!("{}", serde_json::to_string_pretty(&config).unwrap());
            },
            args::Args::GenerateDnsKeyValues(config) => {
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
                                            || loga::err_with(
                                                "Incorrect mx record specification, must be like `PRIORITY/NAME`",
                                                ea!(entry = v),
                                            ),
                                        )?;
                                let priority = u16::from_str(&priority).context("Couldn't parse priority as int")?;
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
