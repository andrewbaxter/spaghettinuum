use {
    crate::{
        bb,
        interface::{
            config::{
                node::api_config::DEFAULT_API_PORT,
                ENV_RESOLVER_PAIRS,
            },
            stored::record::{
                self,
                dns_record::format_dns_key,
            },
            wire,
        },
        utils::tls_util::{
            cert_pem_hash,
            SpaghTlsClientVerifier,
        },
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
        UriJoin,
    },
    itertools::Itertools,
    loga::{
        ea,
        ErrContext,
        Log,
        ResultContext,
    },
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
#[derive(Clone)]
pub struct UrlPair {
    pub address: Option<IpAddr>,
    pub url: Uri,
}

impl UrlPair {
    pub fn join(&self, other: impl TryInto<Uri, Error = http::uri::InvalidUri>) -> Self {
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
pub fn system_resolver_url_pairs(log: &Log) -> Result<Vec<UrlPair>, loga::Error> {
    let mut out = vec![];
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
            out.push(UrlPair {
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
            let Some(name) =& s.tls_dns_name else {
                log.log_with(
                    loga::DEBUG,
                    "System name server doesn't have ADN, skipping",
                    ea!(resolver = s.socket_addr.ip()),
                );
                continue;
            };
            let raw_url = format!("https://{}:{}", name, DEFAULT_API_PORT);
            out.push(UrlPair {
                url: Uri::from_str(
                    &raw_url,
                ).context_with("Invalid ADN for URL in system resolver configuration", ea!(url = raw_url))?,
                address: Some(s.socket_addr.ip()),
            });
        }
    }
    return Ok(out);
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
/// name) is expected, since this doesn't do name resolution and those are expected
/// via other channels.
pub async fn connect_resolver_node(pair: &UrlPair) -> Result<Conn, loga::Error> {
    let (scheme, host, port) = uri_parts(&pair.url).context("API URL incomplete")?;
    return Ok(
        connect_ips(
            Ips::from(pair.address.unwrap()),
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(SpaghTlsClientVerifier {
                    hashes: Default::default(),
                    inner: None,
                }))
                .with_no_client_auth(),
            scheme,
            host,
            port,
        ).await.context("Failed to establish connection")?,
    );
}

/// Resolve ip addresses for a host plus any additional keys. DNS CNAME records are
/// followed, with all returned results being from the final hop.
///
/// `name` is a DNS name like `a.b.identity.s` - can handle both spaghettinuum and
/// non- names.
pub async fn resolve(
    log: &Log,
    resolvers: &[UrlPair],
    name: &str,
    additional_keys: &[&str],
) -> Result<(htreq::Ips, HashMap<String, wire::resolve::v1::ResolveValue>), loga::Error> {
    // Resolve, repeatedly following CNAMEs
    let mut at = Some(name.to_string());
    loop {
        let host = at.take().unwrap();

        // Get key bits from next hop host
        let Some(host) = host.strip_suffix(".s").or_else(|| host.strip_suffix(".s.")) else {
            let ips;
            match IpAddr::from_str(&host).ok() {
                Some(i) => {
                    ips = htreq::Ips::from(i);
                },
                None => {
                    ips = htreq::resolve(&htreq::Host::Name(host.to_string())).await?;
                },
            };
            return Ok((ips, HashMap::new()));
        };
        let (subdomain, ident_str) = host.rsplit_once(".").unwrap_or(("", host));
        let subdomain = format!("{}.", subdomain);

        // Look up information required to connect
        let key_cname = format_dns_key(&subdomain, record::dns_record::RecordType::Cname);
        let key_aaaa = format_dns_key(&subdomain, record::dns_record::RecordType::Aaaa);
        let key_a = format_dns_key(&subdomain, record::dns_record::RecordType::A);
        let query_path =
            format!(
                "resolve/v1/{}?{}",
                ident_str,
                Iterator::chain(
                    [key_cname.as_str(), key_aaaa.as_str(), key_a.as_str()].iter(),
                    additional_keys.iter(),
                )
                    .map(|k| urlencoding::encode(k))
                    .join(",")
            );
        let resolved = bb!{
            'done _;
            let mut errs = vec![];
            for resolver_url in resolvers {
                match htreq::get_json::<wire::resolve::ResolveKeyValues>(
                    log,
                    &mut connect_resolver_node(&resolver_url).await?,
                    &resolver_url.url.join(&query_path),
                    &HashMap::new(),
                    1024 * 1024,
                ).await {
                    Ok(r) => {
                        break 'done r;
                    },
                    Err(e) => {
                        errs.push(e.context_with("Error reaching resolver", ea!(resolver = resolver_url)));
                    },
                }
            }
            return Err(loga::agg_err("Error making requests to any resolver", errs));
        };
        let mut resolved = match resolved {
            wire::resolve::ResolveKeyValues::V1(r) => r,
        };

        // Got another cname, continue loop
        if let Some(serde_json::Value::String(cname)) = resolved.remove(&key_cname).and_then(|c| c.data) {
            at = Some(cname);
            continue;
        }

        // No cname, handle what we have at this final hop
        let ips = htreq::Ips {
            ipv4s: bb!{
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
                        break r.0.into_iter().map(|i| IpAddr::V4(i)).collect();
                    },
                }
            },
            ipv6s: bb!{
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
                            e.context(
                                "Couldn't parse A record into expected JSON format, treating as no IPv6 addresses",
                            ),
                        );
                        break vec![];
                    },
                };
                match r {
                    record::dns_record::DnsAaaa::V1(r) => {
                        break r.0.into_iter().map(|i| IpAddr::V6(i)).collect();
                    },
                }
            },
        };
        return Ok((ips, resolved));
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
    let (ips, mut additional_records) =
        resolve(log, resolvers, &host.to_string(), &[record::tls_record::KEY]).await?;
    let mut certs = vec![];

    bb!{
        let Some(r) = additional_records.remove(record::tls_record::KEY) else {
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
