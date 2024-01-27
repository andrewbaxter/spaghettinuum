use chrono::{
    Utc,
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
use serde::de::DeserializeOwned;
use serde_json::json;
use spaghettinuum::{
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
        htreq,
        publish_util,
    },
    interface::{
        spagh_cli::{
            ENV_API_ADDR,
            BackedIdentityLocal,
            ENV_API_ADMIN_TOKEN,
        },
        spagh_api::{
            publish::self,
            resolve::{
                self,
                KEY_DNS_A,
                KEY_DNS_AAAA,
                KEY_DNS_CNAME,
                KEY_DNS_MX,
                KEY_DNS_TXT,
            },
        },
        identity::Identity,
    },
    publisher::PublishIdentSignatureMethods,
};
use std::{
    collections::HashMap,
    env::self,
    str::FromStr,
};

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

fn api_url() -> Result<Uri, loga::Error> {
    let default_port = 443;
    let url =
        env::var(
            ENV_API_ADDR,
        ).context_with("Missing environment variable to notify node", ea!(env_var = ENV_API_ADDR))?;
    let url = Uri::from_str(&url).context_with("Couldn't parse environment variable", ea!(env_var = ENV_API_ADDR))?;
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
>(base_url: Uri, path: &str, get_key: fn(&T) -> String) -> Result<Vec<T>, loga::Error> {
    let mut out = vec![];
    let admin_headers = admin_headers()?;
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

mod args {
    use std::{
        path::PathBuf,
    };
    use aargvark::{
        Aargvark,
        AargvarkJson,
    };
    use spaghettinuum::{
        interface::{
            spagh_cli::{
                BackedIdentityArg,
                BackedIdentityLocal,
            },
            spagh_api::publish,
            spagh_node::GlobalAddrConfig,
        },
    };

    #[derive(Aargvark)]
    pub struct NewLocalIdentity {
        /// Store the new id and secret in a file at this path
        pub path: PathBuf,
    }

    #[derive(Aargvark)]
    pub struct AllowIdentity {
        pub identity_id: String,
    }

    #[derive(Aargvark)]
    pub struct DisallowIdentity {
        pub identity_id: String,
    }

    #[derive(Aargvark)]
    pub struct Publish {
        /// Identity to publish as
        pub identity: BackedIdentityArg,
        /// Data to publish.  Must be json in the structure
        /// `{KEY: {"ttl": SECONDS, "value": "DATA"}, ...}`
        pub data: AargvarkJson<publish::latest::Publish>,
    }

    #[derive(Aargvark)]
    pub struct PublishDns {
        /// Identity to publish as
        pub identity: BackedIdentityArg,
        /// TTL for hits and misses, in minutes
        pub ttl: u32,
        /// A list of other DNS names.
        pub dns_cname: Vec<String>,
        /// A list of Ipv4 addresses
        pub dns_a: Vec<String>,
        /// A list of Ipv6 addresses
        pub dns_aaaa: Vec<String>,
        /// A list of valid TXT record strings
        pub dns_txt: Vec<String>,
        /// Mail server names. These are automatically prioritized, with the first having
        /// priority 0, second 1, etc.
        pub dns_mx: Vec<String>,
    }

    #[derive(Aargvark)]
    pub struct SelfPublish {
        /// How to detect the public ip to publish
        pub addr: GlobalAddrConfig,
        /// Identity to publish address under
        pub identity: BackedIdentityArg,
    }

    #[derive(Aargvark)]
    pub struct Unpublish {
        pub identity: BackedIdentityArg,
    }

    #[derive(Aargvark)]
    pub struct ListPublishingKeyValues {
        pub identity: String,
    }

    #[derive(Aargvark)]
    pub struct Query {
        /// Identity to query
        pub identity: String,
        /// Keys published by the identity, to query
        pub keys: Vec<String>,
    }

    #[derive(Aargvark)]
    pub enum Identity {
        /// Create a new local (file) identity
        NewLocal(NewLocalIdentity),
        /// Show the id for a local identity
        ShowLocal(AargvarkJson<BackedIdentityLocal>),
        /// List ids for usable pcsc cards (configured with curve25519/ed25519 signing keys)
        ListCards,
    }

    #[derive(Aargvark)]
    pub enum Admin {
        /// Get detailed node health information
        HealthDetail,
        /// List identities allowed to publish
        ListAllowedIdentities,
        /// Register an identity with the publisher, allowing it to publish
        AllowIdentity(AllowIdentity),
        /// Unregister an identity with the publisher, disallowing it from publishing
        DisallowIdentity(DisallowIdentity),
        /// List identities a publisher is currently publishing
        ListPublishingIdentities,
        /// List data a publisher is publishing for an identity
        ListPublishingKeyValues(ListPublishingKeyValues),
    }

    #[derive(Aargvark)]
    pub enum Command {
        /// Simple liveness check
        Ping,
        /// Request values associated with provided identity and keys from a resolver
        Get(Query),
        /// Create or replace existing publish data for an identity on a publisher server
        Set(Publish),
        /// A shortcut for publishing DNS data, generating the key values for you
        SetDns(PublishDns),
        /// Stop publishing data
        Unset(Unpublish),
        /// Commands for managing identities
        Identity(Identity),
        /// Commands for node administration
        Admin(Admin),
    }

    #[derive(Aargvark)]
    pub struct Args {
        pub debug: Option<()>,
        pub command: Command,
    }
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
            args::Command::Ping => {
                let url = format!("{}health", api_url()?);
                log.log_with(DEBUG_OTHER, "Sending ping request (GET)", ea!(url = url));
                htreq::get(&url, &admin_headers()?, 100).await?;
            },
            args::Command::Get(config) => {
                let url =
                    format!(
                        "{}v1/{}?{}",
                        api_url()?,
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
            args::Command::Set(config) => {
                let mut signer =
                    get_identity_signer(
                        config.identity,
                    ).stack_context(&log, "Error constructing signer for identity")?;
                publish_util::publish(log, &api_url()?, signer.as_mut(), config.data.value).await?;
            },
            args::Command::SetDns(config) => {
                let mut signer =
                    get_identity_signer(
                        config.identity,
                    ).stack_context(&log, "Error constructing signer for identity")?;
                publish_util::publish(log, &api_url()?, signer.as_mut(), publish::latest::Publish {
                    missing_ttl: config.ttl,
                    data: {
                        let mut kvs = HashMap::new();
                        if !config.dns_mx.is_empty() {
                            kvs.insert(KEY_DNS_CNAME.to_string(), publish::latest::PublishValue {
                                ttl: config.ttl,
                                data: serde_json::to_value(
                                    &resolve::DnsCname::V1(resolve::latest::DnsCname(config.dns_cname)),
                                ).unwrap(),
                            });
                        }
                        if !config.dns_a.is_empty() {
                            kvs.insert(KEY_DNS_A.to_string(), publish::latest::PublishValue {
                                ttl: config.ttl,
                                data: serde_json::to_value(
                                    &resolve::DnsA::V1(resolve::latest::DnsA(config.dns_a)),
                                ).unwrap(),
                            });
                        }
                        if !config.dns_aaaa.is_empty() {
                            kvs.insert(KEY_DNS_AAAA.to_string(), publish::latest::PublishValue {
                                ttl: config.ttl,
                                data: serde_json::to_value(
                                    &resolve::DnsAaaa::V1(resolve::latest::DnsAaaa(config.dns_aaaa)),
                                ).unwrap(),
                            });
                        }
                        if !config.dns_txt.is_empty() {
                            kvs.insert(KEY_DNS_TXT.to_string(), publish::latest::PublishValue {
                                ttl: config.ttl,
                                data: serde_json::to_value(
                                    &resolve::DnsTxt::V1(resolve::latest::DnsTxt(config.dns_txt)),
                                ).unwrap(),
                            });
                        }
                        if !config.dns_mx.is_empty() {
                            kvs.insert(KEY_DNS_MX.to_string(), publish::latest::PublishValue {
                                ttl: config.ttl,
                                data: serde_json::to_value(
                                    &resolve::DnsMx::V1(resolve::latest::DnsMx(config.dns_mx)),
                                ).unwrap(),
                            });
                        }
                        kvs
                    },
                }).await?;
            },
            args::Command::Unset(config) => {
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
                let url = format!("{}publish/unpublish", api_url()?);
                log.log_with(
                    DEBUG_OTHER,
                    "Sending unpublish request",
                    ea!(url = url, body = serde_json::to_string_pretty(&request).unwrap()),
                );
                htreq::post(&url, &HashMap::new(), serde_json::to_vec(&request).unwrap(), 100)
                    .await
                    .stack_context(log, "Error making unpublish request")?;
            },
            args::Command::Identity(args) => match args {
                args::Identity::NewLocal(args) => {
                    let (ident, secret) = BackedIdentityLocal::new();
                    write_identity(&args.path, &secret).await.stack_context(&log, "Error creating local identity")?;
                    println!("{}", serde_json::to_string_pretty(&json!({
                        "identity": ident.to_string()
                    })).unwrap());
                },
                args::Identity::ShowLocal(p) => {
                    let secret = p.value;
                    let identity = secret.identity();
                    println!("{}", serde_json::to_string_pretty(&json!({
                        "identity": identity.to_string()
                    })).unwrap());
                },
                args::Identity::ListCards => {
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
            },
            args::Command::Admin(args) => match args {
                args::Admin::HealthDetail => {
                    let url = format!("{}admin/health", api_url()?);
                    log.log_with(DEBUG_OTHER, "Sending health detail request (GET)", ea!(url = url));
                    htreq::get(&url, &admin_headers()?, 100).await?;
                },
                args::Admin::AllowIdentity(config) => {
                    let url = format!("{}publish/admin/allowed_identities/{}", api_url()?, config.identity_id);
                    log.log_with(DEBUG_OTHER, "Sending register request (POST)", ea!(url = url));
                    htreq::post(&url, &admin_headers()?, vec![], 100).await?;
                },
                args::Admin::DisallowIdentity(config) => {
                    let url = format!("{}publish/admin/allowed_identities/{}", api_url()?, config.identity_id);
                    log.log_with(DEBUG_OTHER, "Sending unregister request (POST)", ea!(url = url));
                    htreq::delete(&url, &admin_headers()?, 100).await?;
                },
                args::Admin::ListAllowedIdentities => {
                    let out =
                        api_list::<Identity>(api_url()?, "publish/admin/allowed_identities", |v| v.to_string())
                            .await
                            .stack_context(log, "Error listing allowed identities")?;
                    println!("{}", serde_json::to_string_pretty(&out).unwrap());
                },
                args::Admin::ListPublishingIdentities => {
                    let out =
                        api_list::<Identity>(api_url()?, "publish/admin/announcements", |v| v.to_string())
                            .await
                            .stack_context(log, "Error listing publishing identities")?;
                    println!("{}", serde_json::to_string_pretty(&out).unwrap());
                },
                args::Admin::ListPublishingKeyValues(config) => {
                    println!(
                        "{}",
                        htreq::get_text(
                            &format!("{}publish/admin/announcements/{}", api_url()?, config.identity),
                            &admin_headers()?,
                            1024 * 1024,
                        ).await?
                    );
                },
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
