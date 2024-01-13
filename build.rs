use std::{
    path::PathBuf,
    env,
};

pub mod build_src;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let root = PathBuf::from(&env::var("CARGO_MANIFEST_DIR").unwrap());
    build_src::self_tls::build(&root);
    build_src::node::build(&root);
    build_src::publisher_admin::build(&root);
    build_src::resolver::build(&root);
}
