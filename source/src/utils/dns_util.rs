use {
    crate::interface::config::shared::AdnSocketAddr,
    hickory_proto::{
        op::{
            Message,
            MessageType,
            OpCode,
            Query,
        },
        rr::{
            DNSClass,
            RData,
            RecordType,
        },
        xfer::{
            DnsHandle,
            DnsRequest,
            DnsRequestOptions,
        },
    },
    hickory_resolver::{
        config::{
            NameServerConfig,
            NameServerConfigGroup,
            ResolverOpts,
        },
        name_server::{
            GenericConnector,
            NameServerPool,
            TokioConnectionProvider,
            TokioRuntimeProvider,
        },
        Name,
    },
    http::Uri,
    htwrap::htreq::Ips,
    loga::{
        ea,
        ResultContext,
    },
    rand::{
        thread_rng,
        Rng,
    },
    std::{
        collections::HashSet,
        net::SocketAddr,
        sync::LazyLock,
    },
    tokio_stream::StreamExt,
};

pub type UpstreamDns = NameServerPool<TokioConnectionProvider>;

pub fn build_upstream_dns(config: &Option<Vec<AdnSocketAddr>>) -> Result<UpstreamDns, loga::Error> {
    let mut upstream_servers = NameServerConfigGroup::new();
    let mut upstream_opts;
    if let Some(dns_config_upstream) = &config {
        for n in dns_config_upstream {
            let mut upstream;
            match &n.adn {
                Some(adn) => {
                    upstream =
                        NameServerConfig::new(
                            SocketAddr::new(n.ip, n.port.unwrap_or(853)),
                            hickory_resolver::config::Protocol::Tls,
                        );
                    upstream.tls_dns_name = Some(adn.clone());
                },
                None => {
                    upstream =
                        NameServerConfig::new(
                            SocketAddr::new(n.ip, n.port.unwrap_or(53)),
                            hickory_resolver::config::Protocol::Udp,
                        );
                },
            }
            upstream_servers.push(upstream);
        }
        upstream_opts = ResolverOpts::default();
        upstream_opts.shuffle_dns_servers = true;
    } else {
        let (config, options) =
            hickory_resolver
            ::system_conf
            ::read_system_conf().context("Error reading system dns resolver config for DNS bridge upstream")?;
        for n in config.name_servers() {
            upstream_servers.push(n.clone());
        }
        upstream_opts = options;
    }
    return Ok(
        NameServerPool::from_config(
            upstream_servers,
            upstream_opts,
            GenericConnector::new(TokioRuntimeProvider::new()),
        ),
    );
}

// This basically duplicates htwrap's lookup, but with a lower level resolver.
// Ideally there'd be a way to create a high level resolver from the
// nameserverpool, then the code could be reused...
pub async fn query(upstream_dns: &UpstreamDns, url: &Uri) -> Result<Ips, loga::Error> {
    let host = url.host().context("Url has no host, cannot resolve")?;
    let host = format!("{}.", host);
    let name = Name::from_utf8(&host).context_with("Url has invalid host name", ea!(name = host))?;
    let mut ips = Ips {
        ipv4s: Default::default(),
        ipv6s: Default::default(),
    };

    // Local lookup
    static HOSTSFILE: LazyLock<hickory_resolver::Hosts> = LazyLock::new(|| hickory_resolver::Hosts::new());
    if let Some(res) = HOSTSFILE.lookup_static_host(&Query::query(name.clone(), RecordType::A)) {
        for rec in res {
            let RData::A(rec) = rec else {
                continue;
            };
            ips.ipv4s.push(rec.0);
        }
    };
    if let Some(res) = HOSTSFILE.lookup_static_host(&Query::query(name.clone(), RecordType::AAAA)) {
        for rec in res {
            let RData::AAAA(rec) = rec else {
                continue;
            };
            ips.ipv6s.push(rec.0);
        }
    };
    if !ips.ipv4s.is_empty() || ips.ipv6s.is_empty() {
        return Ok(ips);
    }

    // Remote lookup
    let mut seen_names = HashSet::new();
    let mut names = vec![name];
    while let Some(name) = names.pop() {
        if seen_names.insert(name.clone()) {
            continue;
        }
        let Some(resp) = upstream_dns.send(DnsRequest::new({
            let mut m = Message::new();
            m.set_id(thread_rng().gen());
            m.set_message_type(MessageType::Query);
            m.set_op_code(OpCode::Query);
            m.add_query({
                let mut q = hickory_proto::op::Query::new();
                q.set_name(name.clone());
                q.set_query_type(RecordType::A);
                q.set_query_class(DNSClass::IN);
                q
            });
            m.add_query({
                let mut q = hickory_proto::op::Query::new();
                q.set_name(name.clone());
                q.set_query_type(RecordType::AAAA);
                q.set_query_class(DNSClass::IN);
                q
            });
            m.add_query({
                let mut q = hickory_proto::op::Query::new();
                q.set_name(name);
                q.set_query_type(RecordType::CNAME);
                q.set_query_class(DNSClass::IN);
                q
            });
            m
        }, DnsRequestOptions::default())).next().await else {
            return Err(loga::err_with("Failed to resolve url, upstream dns returned no results", ea!(url = url)));
        };
        let resp = resp.context_with("Error resolving url", ea!(url = url))?;
        for answer in resp.answers() {
            let Some(data) = answer.data() else {
                continue;
            };
            match data {
                RData::A(data) => {
                    ips.ipv4s.push(data.0);
                },
                RData::AAAA(data) => {
                    ips.ipv6s.push(data.0);
                },
                RData::CNAME(data) => {
                    names.push(data.0.clone());
                },
                _ => { },
            }
        }
    }
    return Ok(ips);
}
