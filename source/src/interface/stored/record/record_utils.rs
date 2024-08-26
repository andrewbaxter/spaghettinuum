use {
    crate::interface::{
        stored::identity::Identity,
        wire::resolve::DNS_SUFFIX,
    },
    idna::punycode,
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

pub fn split_dns_path(name: &str) -> Result<RecordKey, loga::Error> {
    let mut path = vec![];
    for part in name.split(".") {
        path.push(
            punycode::decode_to_string(&part).context_with("DNS name part isn't valid punycode", ea!(part = part))?,
        );
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
        path.push(
            punycode::decode_to_string(&part).context_with("DNS name part isn't valid punycode", ea!(part = part))?,
        );
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
            punycode::encode_str(
                &e,
            ).context_with("Error converting spagh record key to DNS name, incompatible segment", ea!(segment = e))?,
        );
    }
    parts.reverse();
    return Ok(parts.join("."));
}
