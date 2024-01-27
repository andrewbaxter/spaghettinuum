use std::{
    fs,
    path::PathBuf,
    env,
};
use schemars::schema_for;
use spaghettinuum::{
    interface::spagh_api::{
        publish,
        resolve,
    },
};

pub fn main() {
    let out = PathBuf::from(&env::var("CARGO_MANIFEST_DIR").unwrap());
    let out = out.join("schemas");
    fs::write(
        out.join("config_spagh_node.schema.json"),
        &serde_json::to_string_pretty(&schema_for!(spaghettinuum::interface::spagh_node::Config)).unwrap(),
    ).unwrap();
    fs::write(
        out.join("config_spagh_auto.schema.json"),
        &serde_json::to_string_pretty(&schema_for!(spaghettinuum::interface::spagh_auto::Config)).unwrap(),
    ).unwrap();
    fs::write(
        out.join("publish.schema.json"),
        &serde_json::to_string_pretty(&schema_for!(publish::v1::Publish)).unwrap(),
    ).unwrap();
    fs::write(
        out.join("publish_data_dns_cname.schema.json"),
        &serde_json::to_string_pretty(&schema_for!(resolve::DnsCname)).unwrap(),
    ).unwrap();
    fs::write(
        out.join("publish_data_dns_a.schema.json"),
        &serde_json::to_string_pretty(&schema_for!(resolve::DnsA)).unwrap(),
    ).unwrap();
    fs::write(
        out.join("publish_data_dns_aaaa.schema.json"),
        &serde_json::to_string_pretty(&schema_for!(resolve::DnsAaaa)).unwrap(),
    ).unwrap();
    fs::write(
        out.join("publish_data_dns_txt.schema.json"),
        &serde_json::to_string_pretty(&schema_for!(resolve::DnsTxt)).unwrap(),
    ).unwrap();
    fs::write(
        out.join("publish_data_dns_mx.schema.json"),
        &serde_json::to_string_pretty(&schema_for!(resolve::DnsMx)).unwrap(),
    ).unwrap();
    fs::write(
        out.join("resolve.schema.json"),
        &serde_json::to_string_pretty(&schema_for!(resolve::v1::ResolveKeyValues)).unwrap(),
    ).unwrap();
}
