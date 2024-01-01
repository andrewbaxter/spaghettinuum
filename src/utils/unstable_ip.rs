//! Pulled from standard libary, unstable features
//! https://github.com/rust-lang/rust/issues/27709
use std::net::{
    Ipv4Addr,
    Ipv6Addr,
};

pub trait UnstableIpv4 {
    #[must_use]
    fn unstable_is_unspecified(&self) -> bool;
    #[must_use]
    fn unstable_is_loopback(&self) -> bool;
    #[must_use]
    fn unstable_is_private(&self) -> bool;
    #[must_use]
    fn unstable_is_link_local(&self) -> bool;
    #[must_use]
    fn unstable_is_global(&self) -> bool;
    #[must_use]
    fn unstable_is_shared(&self) -> bool;
    #[must_use]
    fn unstable_is_benchmarking(&self) -> bool;
    #[must_use]
    fn unstable_is_reserved(&self) -> bool;
    #[must_use]
    fn unstable_is_multicast(&self) -> bool;
    #[must_use]
    fn unstable_is_broadcast(&self) -> bool;
    #[must_use]
    fn unstable_is_documentation(&self) -> bool;
}

impl UnstableIpv4 for Ipv4Addr {
    #[must_use]
    #[inline]
    fn unstable_is_unspecified(&self) -> bool {
        u32::from_be_bytes(self.octets()) == 0
    }

    #[must_use]
    #[inline]
    fn unstable_is_loopback(&self) -> bool {
        self.octets()[0] == 127
    }

    #[must_use]
    #[inline]
    fn unstable_is_private(&self) -> bool {
        match self.octets() {
            [10, ..] => true,
            [172, b, ..] if b >= 16 && b <= 31 => true,
            [192, 168, ..] => true,
            _ => false,
        }
    }

    #[must_use]
    #[inline]
    fn unstable_is_link_local(&self) -> bool {
        matches!(self.octets(), [169, 254, ..])
    }

    #[must_use]
    #[inline]
    fn unstable_is_global(&self) -> bool {
        // "This network"
        !(self.octets()[0] == 0 || self.unstable_is_private() || UnstableIpv4::unstable_is_shared(self) ||
            self.unstable_is_loopback() ||
            self.unstable_is_link_local()
        // addresses reserved for future protocols (`192.0.0.0/24`)
        || (self.octets()[0] == 192 && self.octets()[1] == 0 && self.octets()[2] == 0) || self.unstable_is_documentation() ||
            UnstableIpv4::unstable_is_benchmarking(self) ||
            UnstableIpv4::unstable_is_reserved(self) ||
            self.unstable_is_broadcast())
    }

    #[must_use]
    #[inline]
    fn unstable_is_shared(&self) -> bool {
        self.octets()[0] == 100 && (self.octets()[1] & 0b1100_0000 == 0b0100_0000)
    }

    #[must_use]
    #[inline]
    fn unstable_is_benchmarking(&self) -> bool {
        self.octets()[0] == 198 && (self.octets()[1] & 0xfe) == 18
    }

    #[must_use]
    #[inline]
    fn unstable_is_reserved(&self) -> bool {
        self.octets()[0] & 240 == 240 && !self.unstable_is_broadcast()
    }

    #[must_use]
    #[inline]
    fn unstable_is_multicast(&self) -> bool {
        self.octets()[0] >= 224 && self.octets()[0] <= 239
    }

    #[must_use]
    #[inline]
    fn unstable_is_broadcast(&self) -> bool {
        u32::from_be_bytes(self.octets()) == u32::from_be_bytes(Self::BROADCAST.octets())
    }

    #[must_use]
    #[inline]
    fn unstable_is_documentation(&self) -> bool {
        matches!(self.octets(), [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _])
    }
}

pub trait UnstableIpv6 {
    #[must_use]
    fn unstable_is_unspecified(&self) -> bool;
    #[must_use]
    fn unstable_is_loopback(&self) -> bool;
    #[must_use]
    fn unstable_is_global(&self) -> bool;
    #[must_use]
    fn unstable_is_unique_local(&self) -> bool;
    #[must_use]
    fn unstable_is_unicast(&self) -> bool;
    #[must_use]
    fn unstable_is_unicast_link_local(&self) -> bool;
    #[must_use]
    fn unstable_is_documentation(&self) -> bool;
    #[must_use]
    fn unstable_is_benchmarking(&self) -> bool;
    #[must_use]
    fn unstable_is_unicast_global(&self) -> bool;
    #[must_use]
    fn unstable_is_multicast(&self) -> bool;
}

impl UnstableIpv6 for Ipv6Addr {
    #[must_use]
    #[inline]
    fn unstable_is_unspecified(&self) -> bool {
        u128::from_be_bytes(self.octets()) == u128::from_be_bytes(Ipv6Addr::UNSPECIFIED.octets())
    }

    #[must_use]
    #[inline]
    fn unstable_is_loopback(&self) -> bool {
        u128::from_be_bytes(self.octets()) == u128::from_be_bytes(Ipv6Addr::LOCALHOST.octets())
    }

    #[must_use]
    #[inline]
    fn unstable_is_global(&self) -> bool {
        !(self.unstable_is_unspecified() || self.unstable_is_loopback()
        // IPv4-mapped Address (`::ffff:0:0/96`)
        || matches!(self.segments(), [0, 0, 0, 0, 0, 0xffff, _, _])
        // IPv4-IPv6 Translat. (`64:ff9b:1::/48`)
        || matches!(self.segments(), [0x64, 0xff9b, 1, _, _, _, _, _])
        // Discard-Only Address Block (`100::/64`)
        || matches!(self.segments(), [0x100, 0, 0, 0, _, _, _, _])
        // IETF Protocol Assignments (`2001::/23`)
        || (matches!(self.segments(), [0x2001, b, _, _, _, _, _, _] if b < 0x200) && !(
            // Port Control Protocol Anycast (`2001:1::1`)
            u128::from_be_bytes(self.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0001
            // Traversal Using Relays around NAT Anycast (`2001:1::2`)
            || u128::from_be_bytes(self.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0002
            // AMT (`2001:3::/32`)
            || matches!(self.segments(), [0x2001, 3, _, _, _, _, _, _])
            // AS112-v6 (`2001:4:112::/48`)
            || matches!(self.segments(), [0x2001, 4, 0x112, _, _, _, _, _])
            // ORCHIDv2 (`2001:20::/28`)
            || matches!(self.segments(), [0x2001, b, _, _, _, _, _, _] if b >= 0x20 && b <= 0x2F))) ||
            UnstableIpv6::unstable_is_documentation(self) ||
            UnstableIpv6::unstable_is_unique_local(self) ||
            UnstableIpv6::unstable_is_unicast_link_local(self))
    }

    #[must_use]
    #[inline]
    fn unstable_is_unique_local(&self) -> bool {
        (self.segments()[0] & 0xfe00) == 0xfc00
    }

    #[must_use]
    #[inline]
    fn unstable_is_unicast(&self) -> bool {
        !self.unstable_is_multicast()
    }

    #[must_use]
    #[inline]
    fn unstable_is_unicast_link_local(&self) -> bool {
        (self.segments()[0] & 0xffc0) == 0xfe80
    }

    #[must_use]
    #[inline]
    fn unstable_is_documentation(&self) -> bool {
        (self.segments()[0] == 0x2001) && (self.segments()[1] == 0xdb8)
    }

    #[inline]
    fn unstable_is_benchmarking(&self) -> bool {
        (self.segments()[0] == 0x2001) && (self.segments()[1] == 0x2) && (self.segments()[2] == 0)
    }

    #[must_use]
    #[inline]
    fn unstable_is_unicast_global(&self) -> bool {
        UnstableIpv6::unstable_is_unicast(self) && !self.unstable_is_loopback() &&
            !UnstableIpv6::unstable_is_unicast_link_local(self) &&
            !UnstableIpv6::unstable_is_unique_local(self) &&
            !self.unstable_is_unspecified() &&
            !UnstableIpv6::unstable_is_documentation(self) &&
            !UnstableIpv6::unstable_is_benchmarking(self)
    }

    #[must_use]
    #[inline]
    fn unstable_is_multicast(&self) -> bool {
        (self.segments()[0] & 0xff00) == 0xff00
    }
}
