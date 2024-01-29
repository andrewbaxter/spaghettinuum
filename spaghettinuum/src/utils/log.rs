use crate::interface::config::{
    DebugFlag,
    Flag,
};

pub const WARN: Flag = Flag::Warning;
pub const INFO: Flag = Flag::Info;
pub const DEBUG_OTHER: Flag = Flag::Debug(DebugFlag::Other);
pub const DEBUG_NODE: Flag = Flag::Debug(DebugFlag::Node);
pub const DEBUG_PUBLISH: Flag = Flag::Debug(DebugFlag::Publish);
pub const DEBUG_RESOLVE: Flag = Flag::Debug(DebugFlag::Resolve);
pub const DEBUG_DNS: Flag = Flag::Debug(DebugFlag::Dns);
pub const DEBUG_DNS_S: Flag = Flag::Debug(DebugFlag::DnsS);
pub const DEBUG_DNS_NONS: Flag = Flag::Debug(DebugFlag::DnsNonS);
pub const DEBUG_SELF_TLS: Flag = Flag::Debug(DebugFlag::SelfTls);
pub const DEBUG_HTREQ: Flag = Flag::Debug(DebugFlag::Htreq);
pub const DEBUG_HTSERVE: Flag = Flag::Debug(DebugFlag::Htserve);

// Aggregate
pub const ALL_FLAGS: &'static [Flag] =
    &[
        Flag::Warning,
        Flag::Info,
        Flag::Debug(DebugFlag::Other),
        Flag::Debug(DebugFlag::Node),
        Flag::Debug(DebugFlag::Publish),
        Flag::Debug(DebugFlag::Resolve),
        Flag::Debug(DebugFlag::Dns),
        Flag::Debug(DebugFlag::DnsS),
        Flag::Debug(DebugFlag::DnsNonS),
        Flag::Debug(DebugFlag::SelfTls),
        Flag::Debug(DebugFlag::Htreq),
        Flag::Debug(DebugFlag::Htserve),
    ];
pub const NON_DEBUG_FLAGS: &'static [Flag] = &[WARN, INFO];
pub type Log = loga::Log<Flag>;
