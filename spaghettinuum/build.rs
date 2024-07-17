use std::{
    path::PathBuf,
    env,
};

pub mod buildlib;

fn main() {
    #[cfg(not(docsrs))]
    {
        println!("cargo:rerun-if-changed=build.rs");
        let root = PathBuf::from(&env::var("CARGO_MANIFEST_DIR").unwrap());
        buildlib::self_tls::build(&root);
        buildlib::node::build(&root);
        buildlib::publisher::build(&root);
        buildlib::publisher_admin::build(&root);
        buildlib::resolver::build(&root);
        buildlib::resolver_dns::build(&root);
    }
}
