pub mod buildlib;

fn main() {
    #[cfg(not(docsrs))]
    {
        println!("cargo:rerun-if-changed=build.rs");
        buildlib::self_tls::build();
        buildlib::node::build();
        buildlib::publisher::build();
        buildlib::publisher_admin::build();
        buildlib::resolver::build();
    }
}
