use {
    loga::{
        ea,
        Log,
        ResultContext,
    },
    serde::Serialize,
    spaghettinuum::{
        interface::{
            stored::{
                self,
                record::{
                    delegate_record::build_delegate_key,
                    dns_record::{
                        build_dns_key,
                        RecordType,
                    },
                    record_utils::{
                        split_dns_name,
                        split_record_key,
                    },
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
            traits_impls::{
                AargvarkJson,
                NotFlag,
            },
            Aargvark,
        },
        spaghettinuum::interface::{
            config::shared::IdentitySecretArg,
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
        /// `{KEY: {"ttl": MINUTES, "value": DATA}, ...}`. `KEY` is a string that's a
        /// dotted list of key segments, with `/` to escape dots and escape characters.
        pub data: AargvarkJson<HashMap<String, stored::record::latest::RecordValue>>,
    }

    #[derive(Aargvark)]
    pub struct SetCommon {
        /// Identity to publish
        pub identity: IdentitySecretArg,
        /// Dotted list of subdomains to publish under in DNS order (ex: 'a.b.c').
        pub path: Vec<NotFlag>,
        /// TTL for hits and misses, in minutes
        pub ttl: u32,
        /// A list of other DNS names (`.s` spaghettinuum names or non-spaghettinuum names).
        pub delegate: Option<Vec<NotFlag>>,
        /// A list of Ipv4 addresses
        pub dns_a: Option<Vec<NotFlag>>,
        /// A list of Ipv6 addresses
        pub dns_aaaa: Option<Vec<NotFlag>>,
        /// A list of valid TXT record strings
        pub dns_txt: Option<Vec<NotFlag>>,
        /// Mail server names. These are automatically prioritized, with the first having
        /// priority 0, second 1, etc.
        pub dns_mx: Option<Vec<NotFlag>>,
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
    #[vark(break_help)]
    pub enum Publish {
        /// Announce the publisher server as the authority for this identity. This must be
        /// done before any values published on this publisher can be queried, and replaces
        /// the previous publisher.
        Announce(Announce),
        /// Create or replace existing publish data for an identity on a publisher server
        Set(Set),
        /// A shortcut for publishing common data, generating the appropriate key-values
        /// for you
        SetCommon(SetCommon),
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
                        .map(|(k, v)| (split_record_key(&k), stored::record::RecordValue::V1(v)))
                        .collect(),
                    ..Default::default()
                },
            ).await?;
        },
        args::Publish::SetCommon(config) => {
            let path = config.path.into_iter().map(|x| x.0).collect::<Vec<_>>();

            fn rec_val(ttl: u32, data: impl Serialize) -> stored::record::RecordValue {
                return stored::record::RecordValue::latest(stored::record::latest::RecordValue {
                    ttl: ttl as i32,
                    data: Some(serde_json::to_value(&data).unwrap()),
                });
            }

            let mut kvs = HashMap::new();
            let config_delegate = config.delegate.unwrap_or_default();
            if !config_delegate.is_empty() {
                let mut values = vec![];
                for v in config_delegate {
                    values.push(
                        split_dns_name(
                            hickory_resolver::Name::from_utf8(&v.0).context("Invalid DNS name for delegation")?,
                        ).context_with("Invalid delegation", ea!(value = v))?,
                    );
                }
                kvs.insert(
                    build_delegate_key(path.clone()),
                    rec_val(
                        config.ttl,
                        stored::record::delegate_record::Delegate::latest(
                            stored::record::delegate_record::latest::Delegate(values),
                        ),
                    ),
                );
            }
            let config_dns_a = config.dns_a.unwrap_or_default();
            if !config_dns_a.is_empty() {
                let mut v = vec![];
                for r in config_dns_a {
                    v.push(Ipv4Addr::from_str(&r.0).context("Invalid IP address for A record")?);
                }
                kvs.insert(
                    build_dns_key(path.clone(), RecordType::A),
                    rec_val(
                        config.ttl,
                        stored::record::dns_record::DnsA::V1(stored::record::dns_record::latest::DnsA(v)),
                    ),
                );
            }
            let config_dns_aaaa = config.dns_aaaa.unwrap_or_default();
            if !config_dns_aaaa.is_empty() {
                let mut v = vec![];
                for r in config_dns_aaaa {
                    v.push(Ipv6Addr::from_str(&r.0).context("Invalid IP address for AAAA record")?);
                }
                kvs.insert(
                    build_dns_key(path.clone(), RecordType::Aaaa),
                    rec_val(
                        config.ttl,
                        &stored::record::dns_record::DnsAaaa::V1(stored::record::dns_record::latest::DnsAaaa(v)),
                    ),
                );
            }
            let config_dns_txt = config.dns_txt.unwrap_or_default();
            if !config_dns_txt.is_empty() {
                kvs.insert(
                    build_dns_key(path.clone(), RecordType::Txt),
                    rec_val(
                        config.ttl,
                        &stored::record::dns_record::DnsTxt::V1(
                            stored::record::dns_record::latest::DnsTxt(
                                config_dns_txt.into_iter().map(|x| x.into()).collect(),
                            ),
                        ),
                    ),
                );
            }
            let config_dns_mx = config.dns_mx.unwrap_or_default();
            if !config_dns_mx.is_empty() {
                kvs.insert(
                    build_dns_key(path.clone(), RecordType::Mx),
                    rec_val(
                        config.ttl,
                        &stored::record::dns_record::DnsMx::V1(
                            stored::record::dns_record::latest::DnsMx(
                                config_dns_mx.into_iter().map(|x| x.into()).collect(),
                            ),
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
                    clear: config.keys.into_iter().map(|k| split_record_key(&k)).collect(),
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
