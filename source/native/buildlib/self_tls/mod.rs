pub mod v0;

pub fn build() {
    good_ormning::sqlite::generate(good_ormning::sqlite::GenerateArgs {
        db_name: Some("self_tls".to_string()),
        versions: vec![(0usize, v0::build())],
        queries: vec![],
    }).unwrap();
}
