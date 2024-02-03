use aargvark::Aargvark;
use loga::FlagStyle;
use loga::republish::console::Style as TextStyle;

/// URLs of resolver/publishers, for `spagh` CLI. Comma separated if providing
/// multiple.
pub const ENV_API_ADDR: &'static str = "SPAGH";

/// The token for making admin requests, for `spagh` CLI.
pub const ENV_API_ADMIN_TOKEN: &'static str = "SPAGH_TOKEN";

/// The JSON config (itself, not a path), for `spagh-node` and `spagh-auto`.
pub const ENV_CONFIG: &'static str = "SPAGH_CONFIG";

/// Persisted identity types
pub mod identity;

/// Configs for `spagh-auto`
pub mod auto;

/// Configs for `spagh-node`
pub mod node;

/// Common config structures
pub mod shared;

#[derive(Clone, Hash, PartialEq, Eq, Copy, Aargvark)]
pub enum DebugFlag {
    Node,
    Publish,
    Resolve,
    Dns,
    DnsS,
    DnsNonS,
    SelfTls,
    Htreq,
    Htserve,
    Other,
}

#[derive(Clone, Hash, PartialEq, Eq, Copy, Aargvark)]
pub enum Flag {
    Warning,
    Info,
    Debug(DebugFlag),
}

impl loga::Flag for Flag {
    fn style(self) -> FlagStyle {
        match self {
            Flag::Warning => FlagStyle {
                body_style: TextStyle::new().for_stderr().black(),
                label_style: TextStyle::new().for_stderr().black(),
                label: "INFO",
            },
            Flag::Info => FlagStyle {
                body_style: TextStyle::new().for_stderr().black(),
                label_style: TextStyle::new().for_stderr().yellow(),
                label: "WARN",
            },
            Flag::Debug(d) => FlagStyle {
                body_style: TextStyle::new().for_stderr().black().bright(),
                label_style: TextStyle::new().for_stderr().black().bright(),
                label: match d {
                    DebugFlag::Node => "DEBUG(NODE)",
                    DebugFlag::Publish => "DEBUG(PUBLISH)",
                    DebugFlag::Resolve => "DEBUG(RESOLVE)",
                    DebugFlag::Dns => "DEBUG(DNS)",
                    DebugFlag::DnsS => "DEBUG(DNS_S)",
                    DebugFlag::DnsNonS => "DEBUG(DNS_NONS)",
                    DebugFlag::SelfTls => "DEBUG(SELF_TLS)",
                    DebugFlag::Htreq => "DEBUG(HTREQ)",
                    DebugFlag::Htserve => "DEBUG(HTSERVE)",
                    DebugFlag::Other => "DEBUG(OTHER)",
                },
            },
        }
    }
}
