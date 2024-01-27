use schemars::JsonSchema;
use serde::{
    Deserialize,
    Serialize,
};
use crate::interface::config::shared::StrSocketAddr;

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DnsType {
    Udp,
    Tls,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct EabConfig {
    /// Provided by ACME provider.
    pub kid: String,
    /// Provided by ACME provider.
    pub hmac_b64: String,
}

/// Use ACME to provision a TLS cert.  This uses the HTTP verification method.  For
/// verification, a http server is started briefly on port 80, so make sure traffic
/// can reach the server on port 80 and the normal api listener isn't operating on
/// port 80.
#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct AcmeConfig {
    /// DNS over TLS, with automatic cert provisioning via ZeroSSL. Certificates are
    /// issued for each global address identified in the main config.
    pub bind_addrs: Vec<StrSocketAddr>,
    /// DNS name (A, AAAA) for the certificate, must also be a valid DNS record.
    /// Explanation: Unless you own an IP block it's basically impossible to get a TLS
    /// cert for a bare ip address. DoT clients will either ignore the name on the
    /// certificate or allow the user to specify an alternative, so we can get an SSL
    /// cert that way.
    pub name: String,
    /// Ex: `https://acme.zerossl.com/v2/DV90`
    pub acme_directory_url: String,
    /// External account binding credentials provided by SSL cert issuer in advance.
    /// Not all cert providers need this (Let's Encrypt doesn't need it).
    pub eab: Option<EabConfig>,
    /// Contacts by which the issuer can reach you if there's an issue.
    pub contacts: Vec<String>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct DnsBridgeConfig {
    /// Normal DNS - typically port 53.
    pub udp_bind_addrs: Vec<StrSocketAddr>,
    /// TCP for DNS over TLS, but you need to proxy the TLS connection. Can be whatever
    /// (proxy's external port is normally 853).
    pub tcp_bind_addrs: Vec<StrSocketAddr>,
    /// Self managed DNS over TLS via ACME.
    pub tls: Option<AcmeConfig>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct ResolverConfig {
    /// Maximum number of entries (identity, key pairs) in resolver cache.
    #[serde(default)]
    pub max_cache: Option<u64>,
    /// Specify to enable the DNS bridge.
    #[serde(default)]
    pub dns_bridge: Option<DnsBridgeConfig>,
}
