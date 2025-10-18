use {
    std::{
        fs::create_dir_all,
        path::Path,
    },
};

pub mod v0;

pub fn build(root: &Path) {
    let mut queries = vec![];
    let out_dir = root.join("src/service/publisher");
    create_dir_all(&out_dir).unwrap();
    good_ormning::sqlite::generate(
        &out_dir.join("db.rs"),
        vec![(0usize, v0::build(Some(&mut queries)))],
        queries,
    ).unwrap();
}
