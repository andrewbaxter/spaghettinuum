use std::{
    path::PathBuf,
    net::{
        IpAddr,
    },
};
use aargvark::Aargvark;
use schemars::JsonSchema;
use serde::{
    Deserialize,
    Serialize,
};
use crate::{
    node::{
        self,
    },
    resolver,
    publisher,
    interface::spagh_cli::{
        StrSocketAddr,
        BackedIdentityArg,
    },
};

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

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct SelfIdentityConfig {
    pub identity: BackedIdentityArg,
    /// Retrieve a TLS cert for the identity's domain (`.s`) and configure TLS on the
    /// public endpoint (https instead of http) via `certipasta.isandrew.com`.
    pub self_tls: bool,
    /// Wait for a local interface configured with a public ip and publish it using
    /// this server's identity.
    pub self_publish: bool,
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct Config {
    /// Path to a dir for subsystems to store persistent data (mostly sqlite
    /// databases). Will be created if it doesn't exist.
    pub persistent_dir: PathBuf,
    /// How to determine the public ip for publisher advertisements and
    /// self-publishing. Publisher advertisements always use the first address.
    #[serde(default)]
    pub global_addrs: Vec<GlobalAddrConfig>,
    /// Core DHT node config, for publishing and looking up addresses
    pub node: node::config::NodeConfig,
    /// Specify to enable resolver functionality.
    #[serde(default)]
    pub resolver: Option<resolver::config::ResolverConfig>,
    /// Specify to enable publisher functionality.
    #[serde(default)]
    pub publisher: Option<publisher::config::PublisherConfig>,
    /// Addresses for client interaction - resolver lookups, publishing, and admin.
    /// Required for publisher and resolver.  This serves both token-protected and
    /// public endpoints.
    #[serde(default)]
    pub api_bind_addrs: Vec<StrSocketAddr>,
    /// When configuring the publisher, admin endpoints must be accessed with this as a
    /// bearer http authorization token.  Required for publisher.
    #[serde(default)]
    pub admin_token: Option<String>,
    /// An backed identity (by file or card) this server can use as its own.  See the
    /// structure fields for more information on what this provides.
    #[serde(default)]
    pub identity: Option<SelfIdentityConfig>,
}
