use {
    super::unstable_ip::{
        UnstableIpv4,
        UnstableIpv6,
    },
    crate::interface::config::shared::{
        GlobalAddrConfig,
        IpVer,
    },
    http_body_util::Full,
    htwrap::htreq::{
        default_tls,
        uri_parts,
        Host,
        Ips,
    },
    hyper::{
        body::Bytes,
        Request,
    },
    loga::{
        ea,
        Log,
        ResultContext,
    },
    network_interface::{
        NetworkInterface,
        NetworkInterfaceConfig,
    },
    std::{
        net::IpAddr,
        str::FromStr,
        time::Duration,
    },
    tokio::time::sleep,
};

pub async fn local_resolve_global_ip(
    restrict_name: &Option<String>,
    restrict_ip_version: &Option<IpVer>,
) -> Result<Option<IpAddr>, loga::Error> {
    for iface in NetworkInterface::show().context("Failure listing network interfaces")?.iter() {
        match restrict_name {
            Some(n) => {
                if n != &iface.name {
                    continue;
                } else {
                    // pass
                }
            },
            _ => {
                // pass
            },
        }
        for addr in &iface.addr {
            match addr.ip() {
                std::net::IpAddr::V4(addr) => {
                    match restrict_ip_version {
                        Some(v) => {
                            if !matches!(v, IpVer::V4) {
                                continue;
                            } else {
                                // pass
                            }
                        },
                        _ => {
                            // pass
                        },
                    }
                    if !addr.unstable_is_global() {
                        continue;
                    }
                    return Ok(Some(IpAddr::V4(addr)));
                },
                std::net::IpAddr::V6(addr) => {
                    match restrict_ip_version {
                        Some(v) => {
                            if !matches!(v, IpVer::V6) {
                                continue;
                            } else {
                                // pass
                            }
                        },
                        _ => {
                            // pass
                        },
                    }
                    if !addr.unstable_is_global() {
                        continue;
                    }
                    return Ok(Some(IpAddr::V6(addr)));
                },
            }
        }
    }
    return Ok(None);
}

pub async fn remote_resolve_global_ip(
    log: &Log,
    lookup: &str,
    contact_ip_ver: Option<IpVer>,
) -> Result<IpAddr, loga::Error> {
    let log = &log.fork(ea!(lookup = lookup));
    let lookup = hyper::Uri::from_str(&lookup).stack_context(log, "Couldn't parse `advertise_addr` lookup as URL")?;
    let (lookup_scheme, lookup_host, lookup_port) = uri_parts(&lookup).stack_context(log, "Incomplete URL")?;
    let mut ips = Ips {
        ipv4s: Default::default(),
        ipv6s: Default::default(),
    };
    match &lookup_host {
        Host::Ip(i) => ips.push(*i),
        Host::Name(lookup_host) => {
            for ip in hickory_resolver::TokioAsyncResolver::tokio(
                hickory_resolver::config::ResolverConfig::default(),
                {
                    let mut opts = hickory_resolver::config::ResolverOpts::default();
                    opts.ip_strategy = match contact_ip_ver {
                        Some(IpVer::V4) => hickory_resolver::config::LookupIpStrategy::Ipv4Only,
                        Some(IpVer::V6) => hickory_resolver::config::LookupIpStrategy::Ipv6Only,
                        None => hickory_resolver::config::LookupIpStrategy::Ipv4AndIpv6,
                    };
                    opts
                },
            )
                .lookup_ip(&format!("{}.", lookup_host))
                .await
                .stack_context(log, "Failed to look up lookup host ip addresses")?
                .into_iter() {
                ips.push(ip);
            }
        },
    }
    if ips.ipv4s.is_empty() && ips.ipv6s.is_empty() {
        return Err(log.err("Unable to resolve any lookup server addresses matching ipv4/6 requirements"));
    }
    let mut conn =
        htwrap::htreq::connect_ips(ips, default_tls(), lookup_scheme, lookup_host.clone(), lookup_port)
            .await
            .context("Error connecting to lookup host")?;
    let resp =
        htwrap::htreq::send_simple(
            log,
            &mut conn,
            1024,
            Duration::from_secs(10),
            Request::builder()
                .uri(lookup)
                .header(hyper::header::HOST, lookup_host.to_string())
                .body(Full::<Bytes>::new(Bytes::new()))
                .unwrap(),
        )
            .await
            .stack_context(log, "Error sending request")?;
    let ip = String::from_utf8(resp).stack_context(log, "Failed to parse response as utf8")?;
    let ip = IpAddr::from_str(&ip).stack_context_with(log, "Failed to parse response as socket addr", ea!(ip = ip))?;
    return Ok(ip);
}

pub async fn resolve_global_ip(log: &Log, config: &GlobalAddrConfig) -> Result<IpAddr, loga::Error> {
    return Ok(match config {
        GlobalAddrConfig::Fixed(s) => {
            log.log_with(loga::INFO, "Identified fixed public ip address from config", ea!(addr = s));
            *s
        },
        GlobalAddrConfig::FromInterface { name, ip_version } => {
            let res = loop {
                if let Some(res) = local_resolve_global_ip(&name, &ip_version).await? {
                    break res;
                }
                log.log_with(loga::INFO, "Waiting for public ip address on interface", ea!());
                sleep(Duration::from_secs(10)).await;
            };
            log.log_with(loga::INFO, "Identified public ip address via interface", ea!(addr = res));
            res
        },
        GlobalAddrConfig::Lookup(lookup) => {
            let res = loop {
                match remote_resolve_global_ip(log, &lookup.lookup, lookup.contact_ip_ver).await {
                    Ok(r) => break r,
                    Err(e) => {
                        log.log_err(
                            loga::INFO,
                            e.context("Error looking up public ip through external service, retrying"),
                        );
                    },
                }
                sleep(Duration::from_secs(10)).await;
            };
            log.log_with(loga::INFO, "Identified public ip address via external lookup", ea!(addr = res));
            res
        },
    });
}
