use {
    crate::{
        bb,
        interface::{
            stored::{
                identity::Identity,
                record::{
                    self,
                    dns_record::format_dns_key,
                },
            },
            wire,
        },
        utils::tls_util::UnverifyingVerifier,
    },
    http::Uri,
    htwrap::{
        htreq::{
            self,
            connect_with_tls,
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
        collections::HashMap,
        net::IpAddr,
        str::FromStr,
        sync::Arc,
    },
};

/// Resolve ip addresses for a host plus any additional keys. DNS CNAME records are
/// followed, with all returned results being from the final hop.
///
/// `name` is a DNS name like `a.b.identity.s`
pub async fn resolve(
    log: &Log,
    resolvers: Vec<Uri>,
    name: &str,
    additional_keys: &[&str],
) -> Result<(htreq::Ips, Option<Identity>, HashMap<String, wire::resolve::v1::ResolveValue>), loga::Error> {
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
            return Ok((ips, None, HashMap::new()));
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
            for resolver_url in &resolvers {
                match htreq::get_json::<wire::resolve::ResolveKeyValues>(
                    log,
                    &mut connect_with_tls(
                        &resolver_url,
                        rustls::ClientConfig::builder()
                            .dangerous()
                            .with_custom_certificate_verifier(Arc::new(UnverifyingVerifier))
                            .with_no_client_auth(),
                    ).await?,
                    &resolver_url.join(&query_path),
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
        let identity = Some(Identity::from_str(ident_str).context("Invalid identity in .s domain")?);
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
        return Ok((ips, identity, resolved));
    }
}

pub struct ResolveTlsRes {
    /// IP addresses of host (from A and AAAA records)
    pub ips: htreq::Ips,
    /// The identity of the host, if it's a spaghettinuum name
    pub identity: Option<Identity>,
    /// TLS public keys (PEM) for the host
    pub certs: Vec<String>,
}

/// Like `resolve` but also requests TLS certs for the host. This should be
/// sufficient for making http requests.
pub async fn resolve_tls(log: &Log, resolvers: Vec<Uri>, host: &htreq::Host) -> Result<ResolveTlsRes, loga::Error> {
    let (ips, identity, mut additional_records) =
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
        identity: identity,
        certs: certs,
    });
}
