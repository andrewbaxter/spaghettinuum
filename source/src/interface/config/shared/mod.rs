use loga::{
    ea,
    ResultContext,
};
use std::{
    net::IpAddr,
    path::PathBuf,
    sync::{
        Arc,
        Mutex,
    },
};
use aargvark::Aargvark;
use schemars::JsonSchema;
use serde::{
    Serialize,
    Deserialize,
};
use std::net::{
    SocketAddr,
    ToSocketAddrs,
};
use schemars::{
    schema::{
        SchemaObject,
        Metadata,
        InstanceType,
    },
};

/// This boils down to a `SocketAddr`, but it's used for specifying SocketAddrs by
/// providing a DNS name (ex: localhost). Because this may access the network,
/// resolution is deferred to the `resolve` method call. It has the added bonus of
/// keeping the original name when being displayed.
#[derive(Clone)]
pub struct StrSocketAddr(pub String, Arc<Mutex<Option<SocketAddr>>>);

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
