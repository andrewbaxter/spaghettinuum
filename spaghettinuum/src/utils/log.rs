use loga::FlagsStyle;
use loga::republish::console::Style as TextStyle;

loga::republish::bitflags::bitflags!{
    #[derive(PartialEq, Eq, Clone, Copy)] pub struct Flags: u16 {
        const WARN = 1 << 0;
        const INFO = 1 << 1;
        const DEBUG_NODE = 1 << 2;
        const DEBUG_PUBLISH = 1 << 3;
        const DEBUG_RESOLVE = 1 << 4;
        const DEBUG_DNS_S = 1 << 5;
        const DEBUG_DNS_OTHER = 1 << 6;
        const DEBUG_API = 1 << 7;
        const DEBUG_SELF_TLS = 1 << 8;
        const DEBUG_HTREQ = 1 << 9;
        const DEBUG_HTSERVE = 1 << 10;
        const DEBUG_OTHER = 1 << 11;
    }
}

pub const WARN: Flags = Flags::WARN;
pub const INFO: Flags = Flags::INFO;
pub const DEBUG_OTHER: Flags = Flags::DEBUG_OTHER;
pub const DEBUG_NODE: Flags = Flags::DEBUG_NODE;
pub const DEBUG_PUBLISH: Flags = Flags::DEBUG_PUBLISH;
pub const DEBUG_RESOLVE: Flags = Flags::DEBUG_RESOLVE;
pub const DEBUG_DNS_S: Flags = Flags::DEBUG_DNS_S;
pub const DEBUG_DNS_OTHER: Flags = Flags::DEBUG_DNS_OTHER;
pub const DEBUG_API: Flags = Flags::DEBUG_API;
pub const DEBUG_SELF_TLS: Flags = Flags::DEBUG_SELF_TLS;
pub const DEBUG_HTREQ: Flags = Flags::DEBUG_HTREQ;
pub const DEBUG_HTSERVE: Flags = Flags::DEBUG_HTSERVE;

// Aggregate
pub const DEBUG_DNS: Flags = Flags::DEBUG_DNS_S.union(Flags::DEBUG_DNS_OTHER);
pub const NON_DEBUG: Flags = WARN.union(INFO);

impl loga::Flags for Flags {
    fn style(self) -> FlagsStyle {
        match self.iter().next().unwrap() {
            Flags::INFO => FlagsStyle {
                body_style: TextStyle::new().for_stderr().black(),
                label_style: TextStyle::new().for_stderr().black(),
                label: "INFO",
            },
            Flags::WARN => FlagsStyle {
                body_style: TextStyle::new().for_stderr().black(),
                label_style: TextStyle::new().for_stderr().yellow(),
                label: "WARN",
            },
            Flags::DEBUG_OTHER |
            Flags::DEBUG_NODE |
            Flags::DEBUG_DNS_S |
            Flags::DEBUG_DNS_OTHER |
            Flags::DEBUG_PUBLISH |
            Flags::DEBUG_RESOLVE |
            Flags::DEBUG_API |
            Flags::DEBUG_SELF_TLS => FlagsStyle {
                body_style: TextStyle::new().for_stderr().black().bright(),
                label_style: TextStyle::new().for_stderr().black().bright(),
                label: "DEBUG",
            },
            _ => panic!(),
        }
    }
}

pub type Log = loga::Log<Flags>;
