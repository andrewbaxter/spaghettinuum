use {
    crate::{
        interface::{
            config::{
                spagh::DEFAULT_API_PORT,
                ENV_RESOLVER_PAIRS,
            },
            stored::record::{
                self,
                delegate_record::{
                    build_delegate_key,
                    Delegate,
                },
                dns_record::build_dns_key,
                record_utils::{
                    join_query_record_keys,
                    split_dns_name,
                    RecordKey,
                    RecordRoot,
                },
            },
            wire::{
                self,
                api::resolve::v1::ResolveKeyValues,
            },
        },
        service::resolver::API_ROUTE_RESOLVE,
        utils::tls_util::{
            cert_pem_hash,
            SpaghTlsClientVerifier,
            UnverifyingVerifier,
        },
    },
    flowcontrol::{
        shed,
        superif,
    },
    http::Uri,
    htwrap::{
        htreq::{
            self,
            connect_ips,
            uri_parts,
            Conn,
            Ips,
        },
        url::{
            IpUrl,
            UriJoin,
        },
    },
    idna::punycode,
    loga::{
        ea,
        ErrContext,
        Log,
        ResultContext,
    },
    rand::{
        seq::SliceRandom,
        thread_rng,
    },
    rustls::client::danger::ServerCertVerifier,
    std::{
        collections::{
            HashMap,
            HashSet,
        },
        env,
        net::IpAddr,
        str::FromStr,
        sync::Arc,
    },
};

/// For TLS (cert-based identity verification) a connection may need to be made to
/// a domain name whose address can't be resolved, and must instead be provided
/// over a separate channel (ex: DoT via manual configuration or RA/DHCP ADN).
///
/// This is kind of a super-URL that may carry with it associated address
/// information to be used instead of looking up the address.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct UrlPair {
    pub address: Option<IpAddr>,
    pub url: Uri,
}

impl UrlPair {
    pub fn join(&self, other: impl AsRef<str>) -> Self {
        return Self {
            address: self.address,
            url: self.url.join(other),
        };
    }
}

impl From<Uri> for UrlPair {
    fn from(value: Uri) -> Self {
        return Self {
            address: None,
            url: value,
        };
    }
}

impl std::fmt::Display for UrlPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(addr) = &self.address {
            return format_args!("{}={}", addr, self.url).fmt(f);
        } else {
            return self.url.fmt(f);
        }
    }
}

/// This returns a list of ip address/url pairs of resolvers on the system.
pub fn default_resolver_url_pairs(log: &Log) -> Result<Vec<UrlPair>, loga::Error> {
    let mut out = HashSet::new();
    if let Ok(pairs) = env::var(ENV_RESOLVER_PAIRS) {
        for pair in pairs.split(',') {
            let (ip, url) =
                pair
                    .split_once("=")
                    .context_with(
                        "URL pair in env has wrong format",
                        ea!(env_var = ENV_RESOLVER_PAIRS, pair = pair),
                    )?;
            let ip =
                IpAddr::from_str(
                    ip,
                ).context_with("Couldn't parse IP addr in URL pair", ea!(env_var = ENV_RESOLVER_PAIRS, ip = ip))?;
            let url =
                Uri::from_str(
                    &url,
                ).context_with("Couldn't parse URL in URL pair", ea!(env_var = ENV_RESOLVER_PAIRS, url = url))?;
            out.insert(UrlPair {
                address: Some(ip),
                url: url,
            });
        }
    } else {
        let (conf, _) =
            hickory_resolver
            ::system_conf
            ::read_system_conf().context("Error reading system conf to find configured DNS server to use for API")?;
        for s in conf.name_servers() {
            let Some(name) = &s.tls_dns_name else {
                log.log_with(
                    loga::DEBUG,
                    "Found name server with no ADN while searching for system resolvers, skipping",
                    ea!(resolver = s.socket_addr.ip()),
                );
                continue;
            };
            let raw_url = format!("https://{}:{}", name, DEFAULT_API_PORT);
            out.insert(UrlPair {
                url: Uri::from_str(
                    &raw_url,
                ).context_with("Invalid ADN for URL in system resolver configuration", ea!(url = raw_url))?,
                address: Some(s.socket_addr.ip()),
            });
        }

        // If no resolvers with ADN fall back to non-named resolvers
        if out.is_empty() {
            for s in conf.name_servers() {
                let raw_url = format!("https://{}:{}", s.socket_addr.ip().as_url_host(), DEFAULT_API_PORT);
                out.insert(UrlPair {
                    url: Uri::from_str(
                        &raw_url,
                    ).context_with("Invalid ADN for URL in system resolver configuration", ea!(url = raw_url))?,
                    address: Some(s.socket_addr.ip()),
                });
            }
        }
    }
    if out.is_empty() {
        return Err(loga::err("Couldn't identify any default resolvers by scanning the system"));
    }
    return Ok(out.into_iter().collect());
}

/// Connect to a publisher node which either might be colocated with the resolver
/// (full url pair) or standalone, resolved via a separate resolver (just a url).
pub async fn connect_publisher_node(log: &Log, resolvers: &[UrlPair], pair: &UrlPair) -> Result<Conn, loga::Error> {
    let log = log.fork(ea!(url = pair));
    let (scheme, host, port) = htreq::uri_parts(&pair.url).stack_context(&log, "Invalid url")?;
    if pair.address.is_some() {
        return Ok(connect_resolver_node(pair).await?);
    } else {
        let ResolveTlsRes { ips, certs } =
            resolve_for_tls(&log, resolvers, &host).await.stack_context(&log, "Error resolving host")?;
        let mut cert_hashes = HashSet::new();
        for cert in certs {
            cert_hashes.insert(cert_pem_hash(&cert).stack_context(&log, "Invalid cert for host")?);
        }
        return Ok(
            connect_ips(
                ips,
                rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(SpaghTlsClientVerifier {
                        hashes: cert_hashes,
                        inner: None,
                    }))
                    .with_no_client_auth(),
                scheme,
                host,
                port,
            )
                .await
                .stack_context(&log, "Failed to establish connection")?,
        );
    }
}

/// Connect to some http server that publishes its ip and tls certs over
/// spaghettinuum. This is the ideal way to connect to such sites, it uses
/// distributed certificate verification.
pub async fn connect_content(log: &Log, resolvers: &[UrlPair], url: &Uri) -> Result<Conn, loga::Error> {
    let (scheme, host, port) = uri_parts(&url)?;
    let ResolveTlsRes { ips, certs } = resolve_for_tls(log, resolvers, &host).await?;
    let mut cert_hashes = HashSet::new();
    for cert in certs {
        cert_hashes.insert(cert_pem_hash(&cert).stack_context(&log, "Invalid cert for host")?);
    }
    return Ok(
        htreq::connect_ips(
            ips,
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(SpaghTlsClientVerifier {
                    hashes: cert_hashes,
                    inner: None,
                }))
                .with_no_client_auth(),
            scheme,
            host,
            port,
        ).await?,
    );
}

/// Connect to a resolver node. A full UrlPair (with both ip address and domain
/// name) is expected, since this doesn't do name resolution and the name should be
/// provided via other channels.
///
/// As a fallback, skip verification on non-named hosts (similar to DoT fallbacks).
pub async fn connect_resolver_node(pair: &UrlPair) -> Result<Conn, loga::Error> {
    let (scheme, host, port) = uri_parts(&pair.url).context("API URL incomplete")?;
    let verifier = if matches!(host, htreq::Host::Name(_)) {
        Arc::new(SpaghTlsClientVerifier {
            hashes: Default::default(),
            inner: None,
        }) as Arc<dyn ServerCertVerifier>
    } else {
        Arc::new(UnverifyingVerifier)
    };
    return Ok(
        connect_ips(
            Ips::from(pair.address.unwrap()),
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth(),
            scheme,
            host,
            port,
        ).await?,
    );
}

/// Resolve ip addresses for a host plus any additional keys. Delegation records
/// are followed, with all returned results being from the final hop. The returned
/// hash map contains only exact keys in additional keys - prefixes due to
/// delegation or the initial host name are trimmed before returning.
///
/// `name` is a DNS name like `a.b.identity.s` - however this can handle both
/// spaghettinuum and non- names.
pub async fn resolve(
    log: &Log,
    resolvers: &[UrlPair],
    name: &str,
    additional_keys: &[RecordKey],
) -> Result<(htreq::Ips, HashMap<RecordKey, wire::resolve::v1::ResolveValue>), loga::Error> {
    let log = log.fork(ea!(name = name));
    if resolvers.is_empty() { }
    let (root, mut path) =
        split_dns_name(
            hickory_resolver::Name::from_str(name).stack_context(&log, "Error parsing name to resolve as DNS name")?,
        )?;
    let mut root = match root {
        RecordRoot::S(i) => i,
        RecordRoot::Dns(name) => {
            return Ok(
                (
                    htreq::resolve(&htreq::Host::Name(name.to_string()))
                        .await
                        .stack_context(&log, "Error resolving normal DNS name")?,
                    HashMap::new(),
                ),
            );
        },
        RecordRoot::Ip(ip) => {
            return Ok((htreq::Ips::from(ip), HashMap::new()));
        },
    };

    // Resolve, repeatedly following delegations
    'delegated : loop {
        // Look up information required to connect
        let mut keys_delegate = vec![];
        for i in 1 ..= path.len() {
            keys_delegate.push(build_delegate_key(path[..i].to_vec()));
        }
        let key_aaaa = build_dns_key(path.clone(), record::dns_record::RecordType::Aaaa);
        let key_a = build_dns_key(path.clone(), record::dns_record::RecordType::A);
        let mut keys = vec![];
        keys.extend(keys_delegate.clone());
        keys.push(key_aaaa.clone());
        keys.push(key_a.clone());
        keys.extend(additional_keys.iter().map(|x| {
            let mut out = path.clone();
            out.extend(x.clone());
            out
        }));
        let query_path = format!("{}/v1/{}?{}", API_ROUTE_RESOLVE, root.to_string(), join_query_record_keys(&keys));
        let mut resolved = shed!{
            'done _;
            let mut errs = vec![];
            for resolver_url in resolvers {
                match htreq::get_json::<wire::api::resolve::v1::ResolveResp>(
                    &log,
                    &mut connect_resolver_node(&resolver_url).await?,
                    &resolver_url.url.join(&query_path),
                    &HashMap::new(),
                    1024 * 1024,
                ).await {
                    Ok(r) => {
                        break 'done r;
                    },
                    Err(e) => {
                        errs.push(
                            e.stack_context_with(&log, "Error reaching resolver", ea!(resolver = resolver_url)),
                        );
                    },
                }
            }
            return Err(log.agg_err("Error making requests to any resolver", errs));
        }.into_iter().collect::<ResolveKeyValues>();

        // Check if delegated, repeat
        for key_delegate in keys_delegate {
            shed!{
                let Some(delegate) = resolved.remove(&key_delegate).and_then(|c| c.data) else {
                    break;
                };
                let Ok(delegate) = serde_json::from_value::<Delegate>(delegate) else {
                    break;
                };
                match delegate {
                    Delegate::V1(d) => {
                        let Some((choose_root, mut choose_head)) =
                            d.0.as_slice().choose(&mut thread_rng()).cloned() else {
                                return Ok((Ips {
                                    ipv4s: vec![],
                                    ipv6s: vec![],
                                }, HashMap::new()));
                            };

                        // Replace prefix of head
                        choose_head.extend(path.split_off(key_delegate.len()));
                        path = choose_head;
                        superif!({
                            match choose_root {
                                RecordRoot::S(choose_root) => {
                                    root = choose_root.clone();
                                    continue 'delegated;
                                },
                                RecordRoot::Dns(dns_root) => {
                                    let mut dns_path = vec![];
                                    dns_path.reserve(path.len() + 1);
                                    for e in path.iter().rev() {
                                        dns_path.push(
                                            punycode::encode_str(
                                                e,
                                            ).stack_context_with(
                                                &log,
                                                "Delegation to DNS root produces invalid DNS name from segment",
                                                ea!(segment = e),
                                            )?,
                                        );
                                    }
                                    break 'external htreq::resolve(
                                        &htreq::Host::Name(format!("{}.{}", dns_path.join("."), dns_root)),
                                    ).await?
                                },
                                RecordRoot::Ip(ip) => break 'external htreq::Ips::from(ip),
                            }
                        } ips = 'external {
                            return Ok((ips, HashMap::new()));
                        })
                    },
                }
            }
        }

        // No cname, handle what we have at this final hop
        let ips = htreq::Ips {
            ipv4s: shed!{
                let Some(r) = resolved.remove(&key_a) else {
                    log.log(loga::DEBUG, "Response missing A record, assuming no IPv4 addresses");
                    break vec![];
                };
                let Some(r) = r.data else {
                    log.log(loga::DEBUG, "Response A record data is empty, assuming no IPv4 addresses");
                    break vec![];
                };
                let r = match serde_json::from_value::<record::dns_record::DnsA>(r) {
                    Ok(r) => r,
                    Err(e) => {
                        log.log_err(
                            loga::DEBUG,
                            e.context(
                                "Couldn't parse A record into expected JSON format, treating as no IPv4 addresses",
                            ),
                        );
                        break vec![];
                    },
                };
                match r {
                    record::dns_record::DnsA::V1(r) => {
                        break r.0;
                    },
                }
            },
            ipv6s: shed!{
                let Some(r) = resolved.remove(&key_aaaa) else {
                    log.log(loga::DEBUG, "Response missing AAAA record, assuming no IPv6 addresses");
                    break vec![];
                };
                let Some(r) = r.data else {
                    log.log(loga::DEBUG, "Response AAAA record data is empty, assuming no IPv6 addresses");
                    break vec![];
                };
                let r = match serde_json::from_value::<record::dns_record::DnsAaaa>(r) {
                    Ok(r) => r,
                    Err(e) => {
                        log.log_err(
                            loga::DEBUG,
                            e.context_with(
                                "Couldn't parse A record into expected JSON format, treating as no IPv6 addresses",
                                ea!(name = name),
                            ),
                        );
                        break vec![];
                    },
                };
                match r {
                    record::dns_record::DnsAaaa::V1(r) => {
                        break r.0;
                    },
                }
            },
        };
        if ips.ipv4s.is_empty() && ips.ipv6s.is_empty() {
            return Err(log.err("Couldn't resolve name to any IP addresses"));
        }
        return Ok((ips, resolved.into_iter().filter_map(|(mut k, v)| {
            if !k.starts_with(&path) {
                return None;
            }
            return Some((k.split_off(path.len()), v));
        }).collect::<HashMap::<_, _>>()));
    }
}

pub struct ResolveTlsRes {
    /// IP addresses of host (from A and AAAA records)
    pub ips: htreq::Ips,
    /// TLS public keys (PEM) for the host
    pub certs: Vec<String>,
}

/// Like `resolve` but also requests TLS certs for the host. This should be
/// sufficient for making http requests.
pub async fn resolve_for_tls(
    log: &Log,
    resolvers: &[UrlPair],
    host: &htreq::Host,
) -> Result<ResolveTlsRes, loga::Error> {
    let tls_key = vec![record::tls_record::KEY_SUFFIX_TLS.to_string()];
    let (ips, mut additional_records) = resolve(log, resolvers, &host.to_string(), &[tls_key.clone()]).await?;
    let mut certs = vec![];
    shed!{
        let Some(r) = additional_records.remove(&tls_key) else {
            log.log(loga::DEBUG, "Response missing TLS record entry; not using for verification");
            break;
        };
        let Some(r) = r.data else {
            log.log(loga::DEBUG, "Response TLS record is empty; not using for verification");
            break;
        };
        let r = match serde_json::from_value::<record::tls_record::TlsCerts>(r) {
            Ok(r) => r,
            Err(e) => {
                log.log_err(
                    loga::DEBUG,
                    e.context("Couldn't parse TLS record into expected JSON format, not using for verification"),
                );
                break;
            },
        };
        match r {
            record::tls_record::TlsCerts::V1(r) => {
                certs.extend(r.0);
            },
        }
        break;
    };
    return Ok(ResolveTlsRes {
        ips: ips,
        certs: certs,
    });
}
