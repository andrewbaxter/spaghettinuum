pub const ENV_CONFIG: &'static str = "SPAGH_CONFIG";
pub const ENV_RESOLVER: &'static str = "SPAGH_RESOLVER";
pub const ENV_PUBLISHER: &'static str = "SPAGH_PUBLISHER";
pub const ENV_PUBLISHER_AUTH: &'static str = "SPAGH_PUBLISHER_TOKEN";
pub const PORT_NODE: u16 = 43889;
pub const PORT_PUBLISHER: u16 = 43890;
pub const PORT_PUBLISHER_ADMIN: u16 = 43892;
pub const PORT_RESOLVER: u16 = 43891;
pub const KEY_DNS_A: &'static str = "dsf9oyfz83fatqpscp9yt8wkuw";
pub const KEY_DNS_AAAA: &'static str = "wwfukygd6tykiqrmi3jp6qnoiw";
pub const KEY_DNS_CNAME: &'static str = "gi3saqn8pfn7tmwbd4pxj3tour";
pub const KEY_DNS_MX: &'static str = "zm5zzaotiib4bbqg9befbr1kro";
pub const KEY_DNS_NS: &'static str = "ic6hcun6zjnqtxe5ft8i6wox4w";
pub const KEY_DNS_PTR: &'static str = "t7ou17qiefnozbe1uef7ym5hih";
pub const KEY_DNS_SOA: &'static str = "371z1qxg5jnftcjr3g9x7ihzdo";
pub const KEY_DNS_SRV: &'static str = "pyte8mamfbgijefzc8a47gcq4h";
pub const KEY_DNS_TXT: &'static str = "rht6tfoc4pnbipesgjejkzeeta";
pub const KEY_DNS_NSEC: &'static str = "o5qooyyh4pfo7pm8j8z5aaxtwo";
pub const KEY_DNS_NSEC3: &'static str = "x18s8kzedpgy9k9yhm46gxjdky";
pub const KEY_DNS_NSEC3PARAM: &'static str = "k1qkz4rn5p8gp8qmurt7ohijuy";
pub const KEY_DNS_RRSIG: &'static str = "xdgo9zk4p7ntxjuk1tomoqpfja";
pub const KEY_DNS_TLSA: &'static str = "75raif7nhtf87gxqf7h4binmdr";
pub const KEY_DNS_DNSKEY: &'static str = "wngk1zrw4p8ojbkbpxzdqk6wwy";
pub const KEY_DNS_DS: &'static str = "wjfjjd8ysiyb5xdgmmm514e64c";
pub const KEY_DNS_CDNSKEY: &'static str = "5m9p4wwsjprtxpzkp7s4ctk3hh";
pub const COMMON_KEYS_DNS: &[&'static str] =
    &[
        KEY_DNS_A,
        KEY_DNS_AAAA,
        KEY_DNS_CNAME,
        KEY_DNS_MX,
        KEY_DNS_NS,
        KEY_DNS_PTR,
        KEY_DNS_SOA,
        KEY_DNS_SRV,
        KEY_DNS_TXT,
        KEY_DNS_NSEC,
        KEY_DNS_NSEC3,
        KEY_DNS_NSEC3PARAM,
        KEY_DNS_RRSIG,
        KEY_DNS_TLSA,
        KEY_DNS_DNSKEY,
        KEY_DNS_DS,
        KEY_DNS_CDNSKEY,
    ];
// Not yet supported
//. pub const KEY_DNS_AFSDB: &'static str = "3dmm7eocsjbnmy1jokcban5bre";
//. pub const KEY_DNS_APL: &'static str = "74yih9nx63gd5e5ea9u77bswjc";
//. pub const KEY_DNS_CAA: &'static str = "mkt18be4ebyzjd9ushujkdgd3w";
//. pub const KEY_DNS_CDS: &'static str = "yfp769ynsfneubrsya773f9ubr";
//. pub const KEY_DNS_CERT: &'static str = "xtby1psjtff1me44w3wnrdwfdw";
//. pub const KEY_DNS_CSYNC: &'static str = "px8ana558tbyubn11by9ju7xue";
//. pub const KEY_DNS_DHCID: &'static str = "6bn6oyeertbizy3bd6eiim8xxh";
//. pub const KEY_DNS_DLV: &'static str = "xbuh5zkc87rktgpbux8mx7adeh";
//. pub const KEY_DNS_DNAME: &'static str = "39b73zajj3bwx8h9x3c9fzxkxc";
//. pub const KEY_DNS_EUI48: &'static str = "yzaykod1utd3xy5mm31niktoew";
//. pub const KEY_DNS_EUI64: &'static str = "bobfkaefs3ywzecfx6kwc7q8ye";
//. pub const KEY_DNS_HINFO: &'static str = "wijsunu9hidqipabhdosj1ryor";
//. pub const KEY_DNS_HIP: &'static str = "ir4mz7q7jjrumr8io5x1rmxb7o";
//. pub const KEY_DNS_HTTPS: &'static str = "af9ggtncy7gk5qrg7e1qrka4he";
//. pub const KEY_DNS_IPSECKEY: &'static str = "oz181b9dhff4mgsahcqwf3o84o";
//. pub const KEY_DNS_KEY: &'static str = "d6n1q796ntfef8w4xhfdd8e3ih";
//. pub const KEY_DNS_KX: &'static str = "7tsx91qyu3rwmdgsdscbc448py";
//. pub const KEY_DNS_LOC: &'static str = "41ciwyocmtyxxecagfau633wqo";
//. pub const KEY_DNS_NAPTR: &'static str = "edncym8jgjgctjagghc81n4r7e";
//. pub const KEY_DNS_OPENPGPKEY: &'static str = "bus8bas8jfbh9g4wi13s5cix9h";
//. pub const KEY_DNS_RP: &'static str = "n3za9djpr3bbjkfw7xp5ynb5dy";
//. pub const KEY_DNS_SIG: &'static str = "kbq5umit1i8bmng3dmmkkwdujo";
//. pub const KEY_DNS_SMIMEA: &'static str = "744jqnambfnnbmr8ww68syxncw";
//. pub const KEY_DNS_SSHFP: &'static str = "631mu91517b6ugosuwdqc8yxde";
//. pub const KEY_DNS_SVCB: &'static str = "rr6834nx5tnfup7rz44anpoe7r";
//. pub const KEY_DNS_TA: &'static str = "o8wt8bc9g7fhzyf5fyjnx4w6or";
//. pub const KEY_DNS_TKEY: &'static str = "ebygsh9ce3dk5met8e4ute9uoo";
//. pub const KEY_DNS_TSIG: &'static str = "1rqocmfbnpg8dg4rp54ucggqoa";
//. pub const KEY_DNS_URI: &'static str = "rskkuenpmffbbpqxfo5kkwueqy";
//. pub const KEY_DNS_ZONEMD: &'static str = "yar9fu1px7f3pygrfuxjejm61a";
