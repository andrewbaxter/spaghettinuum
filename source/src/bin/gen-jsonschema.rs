use std::{
    env,
    fs::{
        self,
        read,
    },
    path::{
        Path,
        PathBuf,
    },
    process::exit,
};
use schemars::schema_for;
use spaghettinuum::{
    interface::{
        stored,
        wire,
    },
};

fn validate(schema: &jsonschema::JSONSchema, path: &Path) {
    if let Err(e) = schema.validate(&serde_json::from_slice(&read(path).unwrap()).unwrap()) {
        for e in e {
            println!("Validation error: {}", e);
            println!("Instance path: {}", e.instance_path);
        }
        exit(1);
    }
}

pub fn main() {
    let readme_root = PathBuf::from(&env::var("CARGO_MANIFEST_DIR").unwrap()).parent().unwrap().join("readme");
    let out = readme_root.join("schemas");
    let examples = readme_root.join("examples");
    fs::remove_dir_all(&out).unwrap();
    fs::create_dir_all(&out).unwrap();
    let node_schema_raw =
        serde_json::to_string_pretty(&schema_for!(spaghettinuum::interface::config::node::Config)).unwrap();
    fs::write(out.join("config_spagh_node.schema.json"), &node_schema_raw).unwrap();
    let node_schema = jsonschema::JSONSchema::compile(&serde_json::from_str(&node_schema_raw).unwrap()).unwrap();
    validate(&node_schema, &examples.join("spagh_node_full.json"));
    let auto_schema_raw =
        serde_json::to_string_pretty(&schema_for!(spaghettinuum::interface::config::auto::Config)).unwrap();
    fs::write(out.join("config_spagh_auto.schema.json"), &auto_schema_raw).unwrap();
    let auto_schema = jsonschema::JSONSchema::compile(&serde_json::from_str(&auto_schema_raw).unwrap()).unwrap();
    validate(&auto_schema, &examples.join("spagh_auto_discovery_only.json"));
    validate(&auto_schema, &examples.join("spagh_auto_reverse_proxy.json"));
    validate(&auto_schema, &examples.join("spagh_auto_static_files.json"));
    fs::write(
        out.join("record_dns_cname.schema.json"),
        &serde_json::to_string_pretty(&schema_for!(stored::record::dns_record::DnsCname)).unwrap(),
    ).unwrap();
    fs::write(
        out.join("record_dns_a.schema.json"),
        &serde_json::to_string_pretty(&schema_for!(stored::record::dns_record::DnsA)).unwrap(),
    ).unwrap();
    fs::write(
        out.join("record_dns_aaaa.schema.json"),
        &serde_json::to_string_pretty(&schema_for!(stored::record::dns_record::DnsAaaa)).unwrap(),
    ).unwrap();
    fs::write(
        out.join("record_dns_txt.schema.json"),
        &serde_json::to_string_pretty(&schema_for!(stored::record::dns_record::DnsTxt)).unwrap(),
    ).unwrap();
    fs::write(
        out.join("record_dns_mx.schema.json"),
        &serde_json::to_string_pretty(&schema_for!(stored::record::dns_record::DnsMx)).unwrap(),
    ).unwrap();
    fs::write(
        out.join("record_tls_certs.schema.json"),
        &serde_json::to_string_pretty(&schema_for!(stored::record::tls_record::TlsCerts)).unwrap(),
    ).unwrap();
    fs::write(
        out.join("record_ssh_host_keys.schema.json"),
        &serde_json::to_string_pretty(&schema_for!(stored::record::ssh_record::SshHostKeys)).unwrap(),
    ).unwrap();
    fs::write(
        out.join("resolve.schema.json"),
        &serde_json::to_string_pretty(&schema_for!(wire::api::resolve::latest::ResolveValues)).unwrap(),
    ).unwrap();
}
