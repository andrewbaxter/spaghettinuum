use std::{
    fs,
    path::PathBuf,
    env,
};
use schemars::schema_for;
use spaghettinuum::{
    interface::{
        stored,
        wire,
    },
};

pub fn main() {
    let out =
        PathBuf::from(&env::var("CARGO_MANIFEST_DIR").unwrap())
            .parent()
            .unwrap()
            .join("readme")
            .join("schemas")
            .to_path_buf();
    fs::remove_dir_all(&out).unwrap();
    fs::create_dir_all(&out).unwrap();
    fs::write(
        out.join("config_spagh_node.schema.json"),
        &serde_json::to_string_pretty(&schema_for!(spaghettinuum::interface::config::node::Config)).unwrap(),
    ).unwrap();
    fs::write(
        out.join("config_spagh_auto.schema.json"),
        &serde_json::to_string_pretty(&schema_for!(spaghettinuum::interface::config::auto::Config)).unwrap(),
    ).unwrap();
    fs::write(
        out.join("record_dns_cname.schema.json"),
        &serde_json::to_string_pretty(&schema_for!(stored::dns_record::DnsCname)).unwrap(),
    ).unwrap();
    fs::write(
        out.join("record_dns_a.schema.json"),
        &serde_json::to_string_pretty(&schema_for!(stored::dns_record::DnsA)).unwrap(),
    ).unwrap();
    fs::write(
        out.join("record_dns_aaaa.schema.json"),
        &serde_json::to_string_pretty(&schema_for!(stored::dns_record::DnsAaaa)).unwrap(),
    ).unwrap();
    fs::write(
        out.join("record_dns_txt.schema.json"),
        &serde_json::to_string_pretty(&schema_for!(stored::dns_record::DnsTxt)).unwrap(),
    ).unwrap();
    fs::write(
        out.join("record_dns_mx.schema.json"),
        &serde_json::to_string_pretty(&schema_for!(stored::dns_record::DnsMx)).unwrap(),
    ).unwrap();
    fs::write(
        out.join("resolve.schema.json"),
        &serde_json::to_string_pretty(&schema_for!(wire::api::resolve::latest::ResolveValues)).unwrap(),
    ).unwrap();
}
