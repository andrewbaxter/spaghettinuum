use std::{
    net::{
        IpAddr,
    },
    str::FromStr,
};
use chrono::Duration;
use http_body_util::Empty;
use hyper::{
    Request,
    Uri,
    body::Bytes,
};
use hyper_rustls::{
    HttpsConnectorBuilder,
};
use loga::{
    ea,
    ResultContext,
};
use network_interface::{
    NetworkInterface,
    NetworkInterfaceConfig,
};
use crate::{
    config::IpVer,
    utils::{
        htreq::{
            self,
            uri_parts,
            rustls_client_config,
        },
    },
};
use super::{
    unstable_ip::{
        UnstableIpv4,
        UnstableIpv6,
    },
    log::Log,
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

pub async fn remote_resolve_global_ip(lookup: &str, contact_ip_ver: Option<IpVer>) -> Result<IpAddr, loga::Error> {
    use tower_service::Service;

    let log = &Log::new().fork(ea!(lookup = lookup));
    let lookup = hyper::Uri::from_str(&lookup).stack_context(log, "Couldn't parse `advertise_addr` lookup as URL")?;
    let (lookup_scheme, lookup_host, lookup_port) = uri_parts(&lookup).stack_context(log, "Incomplete URL")?;
    let (lookup_ip, lookup_host) = match lookup_host {
        htreq::HostPart::Ip(i) => (i, i.to_string()),
        htreq::HostPart::Name(lookup_host) => {
            let ip =
                hickory_resolver::TokioAsyncResolver::tokio(hickory_resolver::config::ResolverConfig::default(), {
                    let mut opts = hickory_resolver::config::ResolverOpts::default();
                    opts.ip_strategy = match contact_ip_ver {
                        Some(IpVer::V4) => hickory_resolver::config::LookupIpStrategy::Ipv4Only,
                        Some(IpVer::V6) => hickory_resolver::config::LookupIpStrategy::Ipv6Only,
                        None => hickory_resolver::config::LookupIpStrategy::Ipv4AndIpv6,
                    };
                    opts
                })
                    .lookup_ip(&format!("{}.", lookup_host))
                    .await
                    .stack_context(log, "Failed to look up lookup host ip addresses")?
                    .into_iter()
                    .next()
                    .stack_context(
                        log,
                        "Unable to resolve any lookup server addresses matching ipv4/6 requirements",
                    )?;
            (ip, lookup_host)
        },
    };
    let resp =
        htreq::send(
            HttpsConnectorBuilder::new()
                .with_tls_config(rustls_client_config())
                .https_or_http()
                .with_server_name(lookup_host.clone())
                .enable_http1()
                .build()
                .call(Uri::from_str(&format!("{}://{}:{}", lookup_scheme, match lookup_ip {
                    IpAddr::V4(v) => v.to_string(),
                    IpAddr::V6(v) => format!("[{}]", v),
                }, lookup_port)).unwrap())
                .await
                .map_err(|e| loga::err_with("Error connecting to lookup host", ea!(err = e.to_string())))?,
            1024,
            Duration::seconds(10),
            Request::builder()
                .uri(lookup)
                .header(hyper::header::HOST, lookup_host)
                .body(Empty::<Bytes>::new())
                .unwrap(),
        )
            .await
            .stack_context(log, "Error sending request")?;
    let ip = String::from_utf8(resp.to_vec()).stack_context(log, "Failed to parse response as utf8")?;
    let ip = IpAddr::from_str(&ip).stack_context_with(log, "Failed to parse response as socket addr", ea!(ip = ip))?;
    return Ok(ip);
}
