use {
    loga::{
        Log,
        ResultContext,
    },
    serde::Serialize,
    spaghettinuum::{
        interface::{
            stored::{
                self,
                record::dns_record::{
                    format_dns_key,
                    RecordType,
                },
            },
            wire,
        },
        publishing::system_publisher_url_pairs,
        resolving::system_resolver_url_pairs,
        utils::{
            identity_secret::get_identity_signer,
            publish_util,
        },
    },
    std::{
        collections::HashMap,
        net::{
            Ipv4Addr,
            Ipv6Addr,
        },
        str::FromStr,
    },
};

pub mod args {
    use {
        aargvark::{
            Aargvark,
            AargvarkJson,
        },
        spaghettinuum::interface::{
            config::{
                shared::IdentitySecretArg,
            },
            stored,
        },
        std::{
            collections::{
                HashMap,
                HashSet,
            },
            path::PathBuf,
        },
    };

    #[derive(Aargvark)]
    pub struct NewLocalIdentity {
        /// Store the new id and secret in a file at this path
        pub path: PathBuf,
    }

    #[derive(Aargvark)]
    pub struct UnsetAll {
        /// Identity whose records to wipe
        pub identity: IdentitySecretArg,
    }

    #[derive(Aargvark)]
    pub struct Set {
        /// Identity to publish as
        pub identity: IdentitySecretArg,
        /// Data to publish.  Must be json in the structure
        /// `{KEY: {"ttl": MINUTES, "value": DATA}, ...}`
        pub data: AargvarkJson<HashMap<String, stored::record::latest::RecordValue>>,
    }

    #[derive(Aargvark)]
    pub struct SetDns {
        /// Identity to publish as
        pub identity: IdentitySecretArg,
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
        pub identity: IdentitySecretArg,
        /// Keys to stop publishing
        pub keys: HashSet<String>,
    }

    #[derive(Aargvark)]
    pub struct ListKeys {
        pub identity: String,
    }

    #[derive(Aargvark)]
    pub struct Announce {
        /// Identity to advertise this publisher for
        pub identity: IdentitySecretArg,
    }

    #[derive(Aargvark)]
    #[vark(stop)]
    pub enum Publish {
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
    }
}

pub async fn run(log: &Log, config: args::Publish) -> Result<(), loga::Error> {
    let resolvers = system_resolver_url_pairs(log)?;
    let publishers = system_publisher_url_pairs(log)?;
    match config {
        args::Publish::Announce(config) => {
            let signer =
                get_identity_signer(config.identity)
                    .await
                    .stack_context(&log, "Error constructing signer for identity")?;
            publish_util::announce(log, &resolvers, &publishers, &signer).await?;
        },
        args::Publish::Set(config) => {
            let signer =
                get_identity_signer(config.identity)
                    .await
                    .stack_context(&log, "Error constructing signer for identity")?;
            publish_util::publish(
                log,
                &resolvers,
                &publishers,
                &signer,
                wire::api::publish::latest::PublishRequestContent {
                    set: config
                        .data
                        .value
                        .into_iter()
                        .map(|(k, v)| (k, stored::record::RecordValue::V1(v)))
                        .collect(),
                    ..Default::default()
                },
            ).await?;
        },
        args::Publish::SetDns(config) => {
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
                        stored::record::dns_record::DnsCname::V1(
                            stored::record::dns_record::latest::DnsCname(config.dns_cname),
                        ),
                    ),
                );
            }
            if !config.dns_a.is_empty() {
                let mut v = vec![];
                for r in config.dns_a {
                    v.push(Ipv4Addr::from_str(&r).context("Invalid IP address for A record")?);
                }
                kvs.insert(
                    format_dns_key(subdomain, RecordType::A),
                    rec_val(
                        config.ttl,
                        stored::record::dns_record::DnsA::V1(stored::record::dns_record::latest::DnsA(v)),
                    ),
                );
            }
            if !config.dns_aaaa.is_empty() {
                let mut v = vec![];
                for r in config.dns_aaaa {
                    v.push(Ipv6Addr::from_str(&r).context("Invalid IP address for AAAA record")?);
                }
                kvs.insert(
                    format_dns_key(subdomain, RecordType::Aaaa),
                    rec_val(
                        config.ttl,
                        &stored::record::dns_record::DnsAaaa::V1(stored::record::dns_record::latest::DnsAaaa(v)),
                    ),
                );
            }
            if !config.dns_txt.is_empty() {
                kvs.insert(
                    format_dns_key(subdomain, RecordType::Txt),
                    rec_val(
                        config.ttl,
                        &stored::record::dns_record::DnsTxt::V1(
                            stored::record::dns_record::latest::DnsTxt(config.dns_txt),
                        ),
                    ),
                );
            }
            if !config.dns_mx.is_empty() {
                kvs.insert(
                    format_dns_key(subdomain, RecordType::Mx),
                    rec_val(
                        config.ttl,
                        &stored::record::dns_record::DnsMx::V1(
                            stored::record::dns_record::latest::DnsMx(config.dns_mx),
                        ),
                    ),
                );
            }
            let signer =
                get_identity_signer(config.identity)
                    .await
                    .stack_context(&log, "Error constructing signer for identity")?;
            publish_util::publish(
                log,
                &resolvers,
                &publishers,
                &signer,
                wire::api::publish::latest::PublishRequestContent {
                    set: kvs,
                    ..Default::default()
                },
            ).await?;
        },
        args::Publish::Unset(config) => {
            let signer =
                get_identity_signer(config.identity)
                    .await
                    .stack_context(&log, "Error constructing signer for identity")?;
            publish_util::publish(
                log,
                &resolvers,
                &publishers,
                &signer,
                wire::api::publish::latest::PublishRequestContent {
                    clear: config.keys,
                    ..Default::default()
                },
            ).await?;
        },
        args::Publish::UnsetAll(config) => {
            let signer =
                get_identity_signer(config.identity)
                    .await
                    .stack_context(&log, "Error constructing signer for identity")?;
            publish_util::publish(
                log,
                &resolvers,
                &publishers,
                &signer,
                wire::api::publish::latest::PublishRequestContent {
                    clear_all: true,
                    ..Default::default()
                },
            ).await?;
        },
    }
    return Ok(());
}
