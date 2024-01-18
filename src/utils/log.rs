use loga::FlagsStyle;
use loga::republish::console::Style as TextStyle;

loga::republish::bitflags::bitflags!{
    #[derive(PartialEq, Eq, Clone, Copy)] pub struct Flags: u8 {
        const WARN = 1 << 0;
        const INFO = 1 << 1;
        const DEBUG_NODE = 1 << 2;
        const DEBUG_PUBLISH = 1 << 3;
        const DEBUG_RESOLVE = 1 << 4;
        const DEBUG_DNS_S = 1 << 5;
        const DEBUG_DNS_OTHER = 1 << 6;
        const DEBUG_OTHER = 1 << 7;
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
            Flags::DEBUG_NODE |
            Flags::DEBUG_DNS_S |
            Flags::DEBUG_DNS_OTHER |
            Flags::DEBUG_PUBLISH |
            Flags::DEBUG_RESOLVE => FlagsStyle {
                body_style: TextStyle::new().for_stderr().black().bright(),
                label_style: TextStyle::new().for_stderr().black().bright(),
                label: "DEBUG",
            },
            _ => panic!(),
        }
    }
}

pub type Log = loga::Log<Flags>;
