use {
    crate::interface::{
        stored::identity::Identity,
        wire::resolve::DNS_SUFFIX,
    },
    idna::{
        uts46::{
            DnsLength,
            Hyphens,
            Uts46,
        },
        AsciiDenyList,
    },
    loga::{
        ea,
        DebugDisplay,
        ResultContext,
    },
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
    },
    std::net::IpAddr,
};

#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum RecordRoot {
    S(Identity),
    Dns(String),
    Ip(IpAddr),
}

pub type RecordKey = Vec<String>;
const KEY_DELIM: char = '.';
const KEY_ESCAPE: char = '/';

pub fn join_record_key(key: &RecordKey) -> String {
    let mut total_len = 0usize;
    let mut count = 0usize;
    for part in key {
        count += 1;
        total_len += part.len();
    }
    let mut out = String::new();
    out.reserve(total_len + (count - 1));
    for (i, part) in key.iter().enumerate() {
        if i > 0 {
            out.push(KEY_DELIM);
        }
        for c in part.chars() {
            if match c {
                KEY_DELIM => true,
                KEY_ESCAPE => true,
                _ => false,
            } {
                out.push(KEY_ESCAPE);
            }
            out.push(c);
        }
    }
    return out;
}

pub fn split_record_key(key: &str) -> RecordKey {
    let mut out = vec![];
    let mut current = String::new();
    let mut escape = false;
    for c in key.chars() {
        if escape {
            escape = false;
            current.push(c);
        } else {
            match c {
                KEY_DELIM => {
                    out.push(current);
                    current = String::new();
                },
                KEY_ESCAPE => {
                    escape = true;
                },
                c => {
                    current.push(c);
                },
            }
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    return out;
}

pub fn join_query_record_keys(keys: &[RecordKey]) -> String {
    return keys
        .iter()
        .map(|k| urlencoding::encode(&join_record_key(k)).to_string())
        .collect::<Vec<_>>()
        .join(",");
}

pub fn split_query_record_keys(keys: &str) -> Vec<RecordKey> {
    return keys.split(",").map(|x| match urlencoding::decode(&x) {
        Ok(x) => split_record_key(&x),
        Err(_) => split_record_key(x),
    }).collect();
}

fn domain_part_raw_to_string(part: &str) -> Result<String, loga::Error> {
    let (part1, e) = Uts46::new().to_unicode(part.as_bytes(), AsciiDenyList::URL, Hyphens::Check);
    e.context_with("DNS name part isn't valid international domain segment", ea!(part = part))?;
    return Ok(part1.to_string());
}

fn domain_part_string_to_raw(part: &str) -> Result<String, loga::Error> {
    let part1 =
        Uts46::new()
            .to_ascii(part.as_bytes(), AsciiDenyList::URL, Hyphens::Check, DnsLength::Ignore)
            .context_with("DNS name part isn't valid international domain segment", ea!(part = part))?;
    return Ok(part1.to_string());
}

pub fn split_dns_path(name: &str) -> Result<RecordKey, loga::Error> {
    let mut path = vec![];
    for part in name.split(".") {
        path.push(domain_part_raw_to_string(part).context_with("DNS name part isn't valid", ea!(full = name))?);
    }
    path.reverse();
    return Ok(path);
}

pub fn split_dns_name(name: impl Into<hickory_resolver::Name>) -> Result<(RecordRoot, RecordKey), loga::Error> {
    let name = name.into();
    let mut path = vec![];
    for part in name.iter() {
        let part =
            String::from_utf8(
                part.to_vec(),
            ).context_with("DNS name part isn't valid utf-8", ea!(part = String::from_utf8_lossy(part)))?;
        path.push(domain_part_raw_to_string(&part).context_with("DNS name part isn't valid", ea!(full = name))?);
    }
    let root = path.pop().context("DNS name is empty")?;
    let root = if match root.as_str() {
        "s" | "s." => true,
        _ => false,
    } {
        let Some(ident_part) = path.pop() else {
            return Err(
                loga::err_with(
                    "Expected at least two parts in request (ident, .s) but got different number",
                    ea!(name = name, count = name.num_labels()),
                ),
            );
        };
        let ident =
            Identity::from_str(
                &ident_part,
            ).context_with("Couldn't parse ident in request", ea!(ident = ident_part))?;
        RecordRoot::S(ident)
    } else {
        RecordRoot::Dns(root)
    };
    path.reverse();
    return Ok((root, path));
}

#[cfg(test)]
mod test_split_dns_name {
    use {
        super::{
            split_dns_name,
            RecordRoot,
        },
        hickory_proto::rr::LowerName,
        std::str::FromStr,
    };

    #[test]
    fn test_wild1() {
        let (root, key) = split_dns_name(LowerName::from_str("1.something.other").unwrap()).unwrap();
        let RecordRoot::Dns(root) = root else {
            panic!();
        };
        assert_eq!(root, "other");
        assert_eq!(key, vec!["something".to_string(), "1".to_string()]);
    }
}

pub fn join_dns_name(root: RecordRoot, path: RecordKey) -> Result<String, loga::Error> {
    let mut parts = vec![];
    match root {
        RecordRoot::S(ident) => {
            parts.push(DNS_SUFFIX.to_string());
            parts.push(ident.to_string());
        },
        RecordRoot::Dns(n) => {
            parts.push(n);
        },
        RecordRoot::Ip(i) => {
            if !path.is_empty() {
                return Err(
                    loga::err_with(
                        "Invalid data for DNS-compatible host name: root is IP address but has additional name segments",
                        ea!(segments = path.dbg_str()),
                    ),
                );
            }
            return Ok(i.to_string());
        },
    }
    parts.reserve(parts.len() + path.len());
    for e in path {
        parts.push(
            domain_part_string_to_raw(
                &e,
            ).context_with(
                "Error converting spagh record key to DNS name, incompatible part",
                ea!(parts = parts.dbg_str()),
            )?,
        );
    }
    parts.reverse();
    return Ok(parts.join("."));
}
