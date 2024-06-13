use {
    http::{
        uri::Authority,
        Uri,
    },
    itertools::Itertools,
    loga::{
        ea,
        ResultContext,
    },
    serde::{
        de::DeserializeOwned,
        Serialize,
    },
    serde_json::json,
    spaghettinuum::{
        interface::config::{
            identity::BackedIdentityLocal,
            ENV_API_ADDR,
            ENV_API_ADMIN_TOKEN,
        },
        interface::{
            stored::{
                self,
                dns_record::{
                    format_dns_key,
                    RecordType,
                },
                identity::Identity,
            },
            wire,
        },
        ta_res,
        utils::{
            log::{
                ALL_FLAGS,
                NON_DEBUG_FLAGS,
                DEBUG_OTHER,
                WARN,
                Log,
            },
            backed_identity::{
                get_identity_signer,
            },
            local_identity::write_identity,
            htreq,
            publish_util,
        },
    },
    std::{
        collections::HashMap,
        env::self,
        str::FromStr,
    },
};
#[cfg(feature = "card")]
use spaghettinuum::{
    utils::{
        pgp::{
            self,
        },
    },
};
#[cfg(feature = "card")]
use openpgp_card_pcsc::PcscBackend;
#[cfg(feature = "card")]
use openpgp_card_sequoia::{
    state::Open,
    Card,
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

fn api_urls() -> Result<Vec<Uri>, loga::Error> {
    let default_port = 443;
    let urls =
        env::var(
            ENV_API_ADDR,
        ).context_with("Missing environment variable to notify node", ea!(env_var = ENV_API_ADDR))?;
    let mut out = vec![];
    for url in urls.split(',') {
        let url =
            Uri::from_str(
                &url,
            ).context_with("Couldn't parse environment variable", ea!(env_var = ENV_API_ADDR, value = url))?;
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
            out.push(Uri::from_parts(u).unwrap());
        } else {
            out.push(url);
        }
    }
    return Ok(out);
}

async fn api_list<
    T: DeserializeOwned,
>(log: &Log, base_url: &Uri, path: &str, get_key: fn(&T) -> String) -> Result<Vec<T>, loga::Error> {
    let mut out = vec![];
    let admin_headers = admin_headers()?;
    let mut res = htreq::get(log, format!("{}{}", base_url, path), &admin_headers, 1024 * 1024).await?;
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
        res = htreq::get(log, format!("{}{}?after={}", base_url, path, after), &admin_headers, 1024 * 1024).await?;
    }
    return Ok(out);
}

mod args {
    use std::{
        collections::{
            HashMap,
            HashSet,
        },
        path::PathBuf,
    };
    use aargvark::{
        Aargvark,
        AargvarkJson,
    };
    use spaghettinuum::{
        interface::{
            config::{
                identity::BackedIdentityLocal,
                shared::{
                    BackedIdentityArg,
                },
            },
            stored,
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
    pub struct UnsetAll {
        /// Identity whose records to wipe
        pub identity: BackedIdentityArg,
    }

    #[derive(Aargvark)]
    pub struct Set {
        /// Identity to publish as
        pub identity: BackedIdentityArg,
        /// Data to publish.  Must be json in the structure
        /// `{KEY: {"ttl": MINUTES, "value": DATA}, ...}`
        pub data: AargvarkJson<HashMap<String, stored::record::latest::RecordValue>>,
    }

    #[derive(Aargvark)]
    pub struct SetDns {
        /// Identity to publish as
        pub identity: BackedIdentityArg,
        /// Subdomain, prefixed to the identity. Must end with `.`.
        pub subdomain: Option<String>,
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
    pub struct Unset {
        /// Identity whose keys to stop publishing
        pub identity: BackedIdentityArg,
        /// Keys to stop publishing
        pub keys: HashSet<String>,
    }

    #[derive(Aargvark)]
    pub struct ListKeys {
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
    pub struct Announce {
        /// Identity to advertise this publisher for
        pub identity: BackedIdentityArg,
    }

    #[derive(Aargvark)]
    pub enum Identity {
        /// Create a new local (file) identity
        NewLocal(NewLocalIdentity),
        /// Show the id for a local identity
        ShowLocal(AargvarkJson<BackedIdentityLocal>),
        /// List ids for usable pcsc cards (configured with curve25519/ed25519 signing keys)
        #[cfg(feature = "card")]
        ListCards,
    }

    #[derive(Aargvark)]
    #[vark(break)]
    pub enum Admin {
        /// Get detailed node health information
        HealthDetail,
        /// List identities allowed to publish
        ListAllowedIdentities,
        /// Register an identity with the publisher, allowing it to publish
        AllowIdentity(AllowIdentity),
        /// Unregister an identity with the publisher, disallowing it from publishing
        DisallowIdentity(DisallowIdentity),
        /// List announced identities
        ListAnnouncements,
        /// List keys published here for an identity
        ListKeys(ListKeys),
    }

    #[derive(Aargvark)]
    #[vark(break)]
    pub enum Command {
        /// Simple liveness check
        Ping,
        /// Request values associated with provided identity and keys from a resolver
        Get(Query),
        /// Announce the publisher server as the authority for this identity. This must be
        /// done before any values published on this publisher can be queried, and replaces
        /// the previous publisher.
        Announce(Announce),
        /// Create or replace existing publish data for an identity on a publisher server
        Set(Set),
        /// A shortcut for publishing DNS data, generating the key values for you
        SetDns(SetDns),
        /// Stop publishing specific records
        Unset(Unset),
        /// Stop publishing all records for an identity
        UnsetAll(UnsetAll),
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
            Some(_) => ALL_FLAGS,
            None => NON_DEBUG_FLAGS,
        });
        let log = &log;
        match args.command {
            args::Command::Ping => {
                for url in api_urls()? {
                    let url = format!("{}health", url);
                    log.log_with(DEBUG_OTHER, "Sending ping request (GET)", ea!(url = url));
                    htreq::get(log, &url, &admin_headers()?, 100).await?;
                }
            },
            args::Command::Get(config) => {
                let mut errs = vec![];
                for url in api_urls()? {
                    match async {
                        ta_res!(());
                        let url =
                            format!(
                                "{}resolve/v1/{}?{}",
                                url,
                                config.identity,
                                config.keys.iter().map(|k| urlencoding::encode(k)).join(",")
                            );
                        log.log_with(DEBUG_OTHER, "Sending query request", ea!(url = url));
                        println!(
                            "{}",
                            serde_json::to_string_pretty(
                                &serde_json::from_slice::<serde_json::Value>(
                                    &htreq::get(log, &url, &HashMap::new(), 1024 * 1024).await?,
                                ).stack_context(log, "Response could not be parsed as JSON")?,
                            ).unwrap()
                        );
                        return Ok(());
                    }.await {
                        Ok(_) => {
                            return Ok(());
                        },
                        Err(e) => {
                            errs.push(e.context_with("Error reaching resolver", ea!(resolver = url)));
                        },
                    }
                }
                return Err(loga::agg_err("Error making requests to any resolver", errs));
            },
            args::Command::Announce(config) => {
                let signer =
                    get_identity_signer(
                        config.identity,
                    ).stack_context(&log, "Error constructing signer for identity")?;
                publish_util::announce(log, signer.clone(), &api_urls()?).await?;
            },
            args::Command::Set(config) => {
                let signer =
                    get_identity_signer(
                        config.identity,
                    ).stack_context(&log, "Error constructing signer for identity")?;
                publish_util::publish(log, &api_urls()?, signer, wire::api::publish::latest::PublishRequestContent {
                    set: config
                        .data
                        .value
                        .into_iter()
                        .map(|(k, v)| (k, stored::record::RecordValue::V1(v)))
                        .collect(),
                    ..Default::default()
                }).await?;
            },
            args::Command::SetDns(config) => {
                let subdomain = match &config.subdomain {
                    Some(s) => {
                        if !s.ends_with('.') {
                            return Err(log.err("Subdomain must end with ."));
                        }
                        s.as_str()
                    },
                    None => ".",
                };

                fn rec_val(ttl: u32, data: impl Serialize) -> stored::record::RecordValue {
                    return stored::record::RecordValue::latest(stored::record::latest::RecordValue {
                        ttl: ttl as i32,
                        data: Some(serde_json::to_value(&data).unwrap()),
                    });
                }

                let mut kvs = HashMap::new();
                if !config.dns_mx.is_empty() {
                    kvs.insert(
                        format_dns_key(subdomain, RecordType::Cname),
                        rec_val(
                            config.ttl,
                            stored::dns_record::DnsCname::V1(stored::dns_record::latest::DnsCname(config.dns_cname)),
                        ),
                    );
                }
                if !config.dns_a.is_empty() {
                    kvs.insert(
                        format_dns_key(subdomain, RecordType::A),
                        rec_val(
                            config.ttl,
                            stored::dns_record::DnsA::V1(stored::dns_record::latest::DnsA(config.dns_a)),
                        ),
                    );
                }
                if !config.dns_aaaa.is_empty() {
                    kvs.insert(
                        format_dns_key(subdomain, RecordType::Aaaa),
                        rec_val(
                            config.ttl,
                            &stored::dns_record::DnsAaaa::V1(stored::dns_record::latest::DnsAaaa(config.dns_aaaa)),
                        ),
                    );
                }
                if !config.dns_txt.is_empty() {
                    kvs.insert(
                        format_dns_key(subdomain, RecordType::Txt),
                        rec_val(
                            config.ttl,
                            &stored::dns_record::DnsTxt::V1(stored::dns_record::latest::DnsTxt(config.dns_txt)),
                        ),
                    );
                }
                if !config.dns_mx.is_empty() {
                    kvs.insert(
                        format_dns_key(subdomain, RecordType::Mx),
                        rec_val(
                            config.ttl,
                            &stored::dns_record::DnsMx::V1(stored::dns_record::latest::DnsMx(config.dns_mx)),
                        ),
                    );
                }
                let signer =
                    get_identity_signer(
                        config.identity,
                    ).stack_context(&log, "Error constructing signer for identity")?;
                publish_util::publish(log, &api_urls()?, signer, wire::api::publish::latest::PublishRequestContent {
                    set: kvs,
                    ..Default::default()
                }).await?;
            },
            args::Command::Unset(config) => {
                let signer =
                    get_identity_signer(
                        config.identity,
                    ).stack_context(&log, "Error constructing signer for identity")?;
                publish_util::publish(log, &api_urls()?, signer, wire::api::publish::latest::PublishRequestContent {
                    clear: config.keys,
                    ..Default::default()
                }).await?;
            },
            args::Command::UnsetAll(config) => {
                let signer =
                    get_identity_signer(
                        config.identity,
                    ).stack_context(&log, "Error constructing signer for identity")?;
                publish_util::publish(log, &api_urls()?, signer, wire::api::publish::latest::PublishRequestContent {
                    clear_all: true,
                    ..Default::default()
                }).await?;
            },
            args::Command::Identity(args) => match args {
                args::Identity::NewLocal(args) => {
                    let (ident, secret) = BackedIdentityLocal::new();
                    write_identity(&args.path, &secret).await.stack_context(&log, "Error creating local identity")?;
                    println!("{}", serde_json::to_string_pretty(&json!({
                        "id": ident.to_string()
                    })).unwrap());
                },
                args::Identity::ShowLocal(p) => {
                    let secret = p.value;
                    let identity = secret.identity();
                    println!("{}", serde_json::to_string_pretty(&json!({
                        "id": identity.to_string()
                    })).unwrap());
                },
                #[cfg(feature = "card")]
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
                            "id": identity.to_string(),
                        }));
                    }
                    println!("{}", serde_json::to_string_pretty(&out).unwrap());
                },
            },
            args::Command::Admin(args) => match args {
                args::Admin::HealthDetail => {
                    for url in api_urls()? {
                        let url = format!("{}admin/health", url);
                        log.log_with(DEBUG_OTHER, "Sending health detail request (GET)", ea!(url = url));
                        htreq::get(log, &url, &admin_headers()?, 10 * 1024).await?;
                    }
                },
                args::Admin::AllowIdentity(config) => {
                    for url in api_urls()? {
                        let url = format!("{}publish/admin/allowed_identities/{}", url, config.identity_id);
                        log.log_with(DEBUG_OTHER, "Sending register request (POST)", ea!(url = url));
                        htreq::post(log, &url, &admin_headers()?, vec![], 100).await?;
                    }
                },
                args::Admin::DisallowIdentity(config) => {
                    for url in api_urls()? {
                        let url = format!("{}publish/admin/allowed_identities/{}", url, config.identity_id);
                        log.log_with(DEBUG_OTHER, "Sending unregister request (POST)", ea!(url = url));
                        htreq::delete(log, &url, &admin_headers()?, 100).await?;
                    }
                },
                args::Admin::ListAllowedIdentities => {
                    let mut errs = vec![];
                    for url in api_urls()? {
                        match async {
                            ta_res!(());
                            let out =
                                api_list::<Identity>(
                                    log,
                                    &url,
                                    "publish/admin/allowed_identities",
                                    |v| v.to_string(),
                                )
                                    .await
                                    .stack_context(log, "Error listing allowed identities")?;
                            println!("{}", serde_json::to_string_pretty(&out).unwrap());
                            return Ok(());
                        }.await {
                            Ok(_) => {
                                return Ok(());
                            },
                            Err(e) => {
                                errs.push(e.context_with("Error reaching publisher", ea!(url = url)));
                            },
                        }
                    }
                    return Err(loga::agg_err("Error making request", errs));
                },
                args::Admin::ListAnnouncements => {
                    let mut errs = vec![];
                    for url in api_urls()? {
                        match async {
                            ta_res!(());
                            let out =
                                api_list::<Identity>(log, &url, "publish/admin/announcements", |v| v.to_string())
                                    .await
                                    .stack_context(log, "Error listing publishing identities")?;
                            println!("{}", serde_json::to_string_pretty(&out).unwrap());
                            return Ok(());
                        }.await {
                            Ok(_) => {
                                return Ok(());
                            },
                            Err(e) => {
                                errs.push(e.context_with("Error reaching publisher", ea!(url = url)));
                            },
                        }
                    }
                    return Err(loga::agg_err("Error making request", errs));
                },
                args::Admin::ListKeys(config) => {
                    let mut errs = vec![];
                    for url in api_urls()? {
                        match async {
                            ta_res!(());
                            println!(
                                "{}",
                                htreq::get_text(
                                    log,
                                    &format!("{}publish/admin/keys/{}", url, config.identity),
                                    &admin_headers()?,
                                    1024 * 1024,
                                ).await?
                            );
                            return Ok(());
                        }.await {
                            Ok(_) => {
                                return Ok(());
                            },
                            Err(e) => {
                                errs.push(e.context_with("Error reaching publisher", ea!(url = url)));
                            },
                        }
                    }
                    return Err(loga::agg_err("Error making request", errs));
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
