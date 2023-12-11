use std::{
    fs,
    path::PathBuf,
    env,
};
use schemars::schema_for;
use spaghettinuum::config::Config;

pub fn main() {
    let root = PathBuf::from(&env::var("CARGO_MANIFEST_DIR").unwrap());
    fs::write(
        root.join("server_config.schema.json"),
        &serde_json::to_string_pretty(&schema_for!(Config)).unwrap(),
    ).unwrap();
}
