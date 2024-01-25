use std::{
    fs,
    path::PathBuf,
    env,
};
use schemars::schema_for;
use spaghettinuum::{
    config::Config,
    interface::spagh_api::{
        publish,
        resolve,
    },
};

pub fn main() {
    let root = PathBuf::from(&env::var("CARGO_MANIFEST_DIR").unwrap());
    fs::write(
        root.join("node_config.schema.json"),
        &serde_json::to_string_pretty(&schema_for!(Config)).unwrap(),
    ).unwrap();
    fs::write(
        root.join("publish_data.schema.json"),
        &serde_json::to_string_pretty(&schema_for!(publish::v1::Publish)).unwrap(),
    ).unwrap();
    fs::write(
        root.join("publish_dns_a.schema.json"),
        &serde_json::to_string_pretty(&schema_for!(resolve::DnsA)).unwrap(),
    ).unwrap();
    fs::write(
        root.join("publish_dns_aaaa.schema.json"),
        &serde_json::to_string_pretty(&schema_for!(resolve::DnsAaaa)).unwrap(),
    ).unwrap();
    fs::write(
        root.join("publish_dns_cname.schema.json"),
        &serde_json::to_string_pretty(&schema_for!(resolve::DnsCname)).unwrap(),
    ).unwrap();
    fs::write(
        root.join("publish_dns_txt.schema.json"),
        &serde_json::to_string_pretty(&schema_for!(resolve::DnsTxt)).unwrap(),
    ).unwrap();
}
