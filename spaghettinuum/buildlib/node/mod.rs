use std::path::Path;

pub mod v0;

pub fn build(root: &Path) {
    let mut queries = vec![];
    good_ormning::sqlite::generate(
        &root.join("src/service/node/db.rs"),
        vec![(0usize, v0::build(Some(&mut queries)))],
        queries,
    ).unwrap();
}
