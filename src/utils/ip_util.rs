use std::{
    net::{
        IpAddr,
        ToSocketAddrs,
    },
    str::FromStr,
};
use loga::{
    ea,
    ResultContext,
};
use network_interface::{
    NetworkInterface,
    NetworkInterfaceConfig,
};
use reqwest::Url;
use crate::config::IpVer;
use super::{
    unstable_ip::{
        UnstableIpv4,
        UnstableIpv6,
    },
    reqwest_get,
};

pub async fn local_resolve_global_ip(
    restrict_name: Option<String>,
    restrict_ip_version: Option<IpVer>,
) -> Result<IpAddr, loga::Error> {
    for iface in NetworkInterface::show().context("Failure listing network interfaces")?.iter() {
        match &restrict_name {
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
                    match &restrict_ip_version {
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
                    return Ok(IpAddr::V4(addr));
                },
                std::net::IpAddr::V6(addr) => {
                    match &restrict_ip_version {
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
                    return Ok(IpAddr::V6(addr));
                },
            }
        }
    }
    return Err(
        loga::err("Couldn't find any interfaces matching specification or configured with a public ip address"),
    );
}

pub async fn remote_resolve_global_ip(lookup: &str, contact_ip_ver: Option<IpVer>) -> Result<IpAddr, loga::Error> {
    let log = &loga::new(loga::Level::Info).fork(ea!(lookup = lookup));
    let lookup = Url::parse(&lookup).log_context(log, "Couldn't parse `advertise_addr` lookup as URL")?;
    let lookup_host =
        lookup.host().ok_or_else(|| loga::err("Missing host portion in `advertise_addr` url"))?.to_string();
    let lookup_port = lookup.port().unwrap_or(match lookup.scheme() {
        "http" => 80,
        "https" => 443,
        _ => return Err(loga::err("Only http/https are supported for ip lookups")),
    });
    let ip =
        reqwest_get(
            reqwest::ClientBuilder::new()
                .resolve(
                    &lookup_host,
                    format!("{}:{}", lookup_host, lookup_port)
                        .to_socket_addrs()
                        .log_context_with(log, "Failed to look up lookup host", ea!(host = lookup_host))?
                        .into_iter()
                        .filter(|a| {
                            match contact_ip_ver {
                                Some(IpVer::V4) => {
                                    return a.is_ipv4();
                                },
                                Some(IpVer::V6) => {
                                    return a.is_ipv6();
                                },
                                None => {
                                    return true;
                                },
                            }
                        })
                        .next()
                        .ok_or_else(
                            || log.new_err(
                                "Unable to resolve any addresses (matching ipv4/6 requirements) via lookup",
                            ),
                        )?,
                )
                .build()
                .unwrap()
                .get(lookup)
                .send()
                .await?,
            10 * 1024,
        ).await?;
    let ip =
        String::from_utf8(
            ip.clone(),
        ).log_context_with(log, "Failed to parse response as utf8", ea!(resp = String::from_utf8_lossy(&ip)))?;
    let ip = IpAddr::from_str(&ip).log_context_with(log, "Failed to parse response as socket addr", ea!(ip = ip))?;
    return Ok(ip);
}
