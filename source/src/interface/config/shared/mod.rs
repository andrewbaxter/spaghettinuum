use {
    aargvark::Aargvark,
    htwrap::url::IpUrl,
    loga::{
        ea,
        ResultContext,
    },
    schemars::{
        schema::{
            InstanceType,
            Metadata,
            SchemaObject,
        },
        JsonSchema,
    },
    serde::{
        Deserialize,
        Serialize,
    },
    std::{
        hash::Hash,
        net::{
            IpAddr,
            Ipv4Addr,
            Ipv6Addr,
            SocketAddr,
            ToSocketAddrs,
        },
        path::PathBuf,
        str::FromStr,
        sync::{
            Arc,
            Mutex,
        },
    },
};

/// This boils down to a `SocketAddr`, but it's used for specifying SocketAddrs by
/// providing a DNS name (ex: localhost). Because this may access the network,
/// resolution is deferred to the `resolve` method call. It has the added bonus of
/// keeping the original name when being displayed.
#[derive(Clone)]
pub struct StrSocketAddr(pub String, Arc<Mutex<Option<SocketAddr>>>);

impl Eq for StrSocketAddr { }

impl PartialEq for StrSocketAddr {
    fn eq(&self, other: &Self) -> bool {
        return self.0 == other.0;
    }
}

impl Hash for StrSocketAddr {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl StrSocketAddr {
    /// Only for serialization, dummy socketaddr with no lookup
    pub fn new(s: impl ToString) -> StrSocketAddr {
        return StrSocketAddr(s.to_string(), Arc::new(Mutex::new(None)));
    }

    pub fn resolve(&self) -> Result<SocketAddr, loga::Error> {
        let mut resolved = self.1.lock().unwrap();
        match *resolved {
            Some(v) => return Ok(v),
            None => {
                // This should only be resolving local names, like `localhost`... some way to make
                // it more specific (and not potentially blocking/internet accessing?)
                let v =
                    self
                        .0
                        .to_socket_addrs()
                        .context_with("Error turning socket address into IP", ea!(name = self.0))?
                        .into_iter()
                        .next()
                        .context_with("No address resolved from name", ea!(name = self.0))?;
                *resolved = Some(v);
                return Ok(v);
            },
        }
    }
}

impl From<SocketAddr> for StrSocketAddr {
    fn from(value: SocketAddr) -> Self {
        return StrSocketAddr(value.to_string(), Arc::new(Mutex::new(Some(value))));
    }
}

impl std::fmt::Display for StrSocketAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        format!(
            "{} ({})",
            self.0,
            self.1.lock().unwrap().map(|x| x.to_string()).unwrap_or("unresolved".to_string())
        ).fmt(f)
    }
}

impl Serialize for StrSocketAddr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        return self.0.serialize(serializer);
    }
}

impl<'t> Deserialize<'t> for StrSocketAddr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'t> {
        let s = String::deserialize(deserializer)?;
        return Ok(StrSocketAddr(s.clone(), Arc::new(Mutex::new(None))));
    }
}

impl JsonSchema for StrSocketAddr {
    fn schema_name() -> String {
        return "StrSocketAddr".to_string();
    }

    fn json_schema(_gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        return SchemaObject {
            instance_type: Some(InstanceType::String.into()),
            metadata: Some(Box::new(Metadata {
                description: Some(
                    "An ip address or domain (ex: \"localhost\") which resolves to an address".to_string(),
                ),
                ..Default::default()
            })),
            ..Default::default()
        }.into();
    }
}

/// An IP address, optional port, and optional ADN (authentication domain name).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdnSocketAddr {
    pub ip: IpAddr,
    pub port: Option<u16>,
    /// Authentication domain name (imaginary domain name associated with ip for tls
    /// resolution)
    pub adn: Option<String>,
}

impl std::fmt::Display for AdnSocketAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.ip.as_url_host().fmt(f)?;
        if let Some(port) = self.port {
            format_args!(":{}", port).fmt(f)?;
        }
        if let Some(adn) = &self.adn {
            format_args!("#{}", adn).fmt(f)?;
        }
        return Ok(());
    }
}

impl Serialize for AdnSocketAddr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        return self.to_string().serialize(serializer);
    }
}

#[structre::structre("^(?:(?:\\[(?<ipv6>[0-9:]+)\\])|(?<ipv4>[0-9.]+))(?::(?<port>[0-9]+))?(?:#(?P<adn>.*))?$")]
struct AdnSockAddrRegex {
    ipv4: Option<String>,
    ipv6: Option<String>,
    port: Option<u16>,
    adn: Option<String>,
}

impl FromStr for AdnSocketAddr {
    type Err = loga::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let r = AdnSockAddrRegex::from_str(s).context("String can't be parsed as AdnSocketAddr (`ip:port#adn`)")?;
        let ip = if let Some(ipv4) = r.ipv4 {
            IpAddr::V4(Ipv4Addr::from_str(&ipv4)?)
        } else if let Some(ipv6) = r.ipv6 {
            IpAddr::V6(Ipv6Addr::from_str(&ipv6)?)
        } else {
            unreachable!();
        };
        return Ok(Self {
            ip: ip,
            port: r.port,
            adn: r.adn,
        });
    }
}

impl<'t> Deserialize<'t> for AdnSocketAddr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'t> {
        let s = String::deserialize(deserializer)?;
        return Ok(AdnSocketAddr::from_str(&s).map_err(|e| serde::de::Error::custom(e.to_string()))?);
    }
}

#[cfg(test)]
mod test_adn_socket_addr {
    use std::{
        net::{
            Ipv4Addr,
            Ipv6Addr,
        },
        str::FromStr,
    };
    use super::AdnSocketAddr;

    #[test]
    fn adn_socket_addr_roundtrip_ipv4() {
        let start = AdnSocketAddr {
            ip: std::net::IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            port: None,
            adn: None,
        };
        let mid = start.to_string();
        assert_eq!(&mid, "1.2.3.4");
        assert_eq!(AdnSocketAddr::from_str(&mid).unwrap(), start);
    }

    #[test]
    fn adn_socket_addr_roundtrip_ipv6() {
        let start = AdnSocketAddr {
            ip: std::net::IpAddr::V6(Ipv6Addr::from_str("::").unwrap()),
            port: None,
            adn: None,
        };
        let mid = start.to_string();
        assert_eq!(&mid, "[::]");
        assert_eq!(AdnSocketAddr::from_str(&mid).unwrap(), start);
    }

    #[test]
    fn adn_socket_addr_roundtrip_port() {
        let start = AdnSocketAddr {
            ip: std::net::IpAddr::V6(Ipv6Addr::from_str("::").unwrap()),
            port: Some(44),
            adn: None,
        };
        let mid = start.to_string();
        assert_eq!(&mid, "[::]:44");
        assert_eq!(AdnSocketAddr::from_str(&mid).unwrap(), start);
    }

    #[test]
    fn adn_socket_addr_roundtrip_ipv4_port() {
        let start = AdnSocketAddr {
            ip: std::net::IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            port: Some(44),
            adn: None,
        };
        let mid = start.to_string();
        assert_eq!(&mid, "1.2.3.4:44");
        assert_eq!(AdnSocketAddr::from_str(&mid).unwrap(), start);
    }

    #[test]
    fn adn_socket_addr_roundtrip_adn() {
        let start = AdnSocketAddr {
            ip: std::net::IpAddr::V6(Ipv6Addr::from_str("::").unwrap()),
            port: None,
            adn: Some("abc.def".to_string()),
        };
        let mid = start.to_string();
        assert_eq!(&mid, "[::]#abc.def");
        assert_eq!(AdnSocketAddr::from_str(&mid).unwrap(), start);
    }

    #[test]
    fn adn_socket_addr_roundtrip_port_adn() {
        let start = AdnSocketAddr {
            ip: std::net::IpAddr::V6(Ipv6Addr::from_str("::").unwrap()),
            port: Some(44),
            adn: Some("abc.def".to_string()),
        };
        let mid = start.to_string();
        assert_eq!(&mid, "[::]:44#abc.def");
        assert_eq!(AdnSocketAddr::from_str(&mid).unwrap(), start);
    }
}

impl JsonSchema for AdnSocketAddr {
    fn schema_name() -> String {
        return "AdnSocketAddr".to_string();
    }

    fn json_schema(_gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        return SchemaObject {
            instance_type: Some(InstanceType::String.into()),
            metadata: Some(Box::new(Metadata {
                description: Some(
                    "Either just an IP address (and port) as it would appear as in a URL host part (IPv6 surrounded by `[]`), followed by `#` then the ADN (authentication domain name - that will appear on the server's TLS certificate). Default ports may change based on the context and presence of the ADN.".to_string(),
                ),
                ..Default::default()
            })),
            ..Default::default()
        }.into();
    }
}

/// An identity with its associated secret.
#[derive(Clone, Aargvark, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IdentitySecretArg {
    /// A file containing a generated key
    Local(PathBuf),
    /// PC/SC card with ED25519 key
    #[cfg(feature = "card")]
    Card {
        /// Card to register, using id per pcscd (not identity id)
        pcsc_id: String,
        /// Card pin
        pin: String,
    },
}

#[derive(Deserialize, Serialize, JsonSchema, Aargvark, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum IpVer {
    V4,
    V6,
}

#[derive(Deserialize, Serialize, JsonSchema, Aargvark)]
#[serde(rename_all = "snake_case")]
pub struct GlobalAddrLookupConfig {
    /// Host to look up address on.
    pub lookup: String,
    /// Which ip protocol to use to contact lookup server (hence: which ip ver the
    /// lookup server will see and return).  If empty, use any ip version.
    #[serde(default)]
    pub contact_ip_ver: Option<IpVer>,
}

#[derive(Deserialize, Serialize, JsonSchema, Aargvark)]
#[serde(rename_all = "snake_case")]
pub enum GlobalAddrConfig {
    /// Use this if you know the IP address beforehand (ex: in terraform, if you
    /// allocate a floating ip before provisioning this host) and it's not the address
    /// of any local interface.
    Fixed(IpAddr),
    /// If your server is directly on the internet (with an externally reachable IP
    /// configured on an interface) this will cause that IP to be used. Specify an
    /// interface name (ex: `eth0`) or leave blank to scan all interfaces for a public
    /// IP.  All ipv6 addresses are considered public.
    FromInterface {
        /// Restrict to an interface with this name (like `eth0`); unrestricted if empty.
        #[serde(default)]
        name: Option<String>,
        /// Restrict to ip addresses of this version; unrestricted if empty.
        #[serde(default)]
        ip_version: Option<IpVer>,
    },
    /// Look up a socket address via a remote service (ex: whatismyip). The service
    /// must reply with the ip address as plain text.
    Lookup(GlobalAddrLookupConfig),
}
