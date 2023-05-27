use std::{
    path::PathBuf,
    env,
};
use good_ormning::{
    sqlite::{
        Version,
        query::{
            helpers::{
                set_field,
                field_eq,
            },
            expr::{
                Expr,
                BinOp,
            },
            select::Order,
            insert::InsertConflict,
        },
        new_delete,
        schema::field::{
            field_bytes,
            field_str,
            field_utctime_ms,
        },
        QueryResCount,
        new_insert,
        new_select,
    },
};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let root = PathBuf::from(&env::var("CARGO_MANIFEST_DIR").unwrap());
    let field_ident = field_bytes().custom("crate::model::identity::Identity").build();

    // Resolver cache
    {
        let mut latest_version = Version::default();
        let persist = latest_version.table("z18UDNDQB", "cache_persist");
        let persist_row = persist.rowid_field(&mut latest_version, None);
        let persist_ident = persist.field(&mut latest_version, "zUS446K3I", "identity", field_ident.clone());
        let persist_key = persist.field(&mut latest_version, "zKMLG4285", "key", field_str().build());
        let persist_expires = persist.field(&mut latest_version, "z4NGKQ5LL", "expires", field_utctime_ms().build());
        let persist_value = persist.field(&mut latest_version, "zZJ7T4VPM", "value", field_str().opt().build());
        good_ormning::sqlite::generate(&root.join("src/resolver/db.rs"), vec![
            // Versions
            (0usize, latest_version)
        ], vec![
            // Queries
            new_insert(
                &persist,
                vec![
                    set_field(&persist_ident),
                    set_field(&persist_key),
                    set_field(&persist_expires),
                    set_field(&persist_value)
                ],
            ).build_query("push", QueryResCount::None),
            new_select(&persist)
                .return_fields(&[&persist_row, &persist_ident, &persist_key, &persist_expires, &persist_value])
                .where_(Expr::BinOp {
                    left: Box::new(Expr::Field(persist_row.clone())),
                    op: BinOp::LessThan,
                    right: Box::new(Expr::Param {
                        name: "row".to_string(),
                        type_: persist_row.type_.type_.clone(),
                    }),
                })
                .order(Expr::Field(persist_row.clone()), Order::Desc)
                .limit(50)
                .build_query("list", QueryResCount::Many)
        ]).unwrap();
    }

    // Publisher
    {
        let mut latest_version = Version::default();
        let identities = latest_version.table("zNMSOUSV6", "identities");
        let ident_ident = identities.field(&mut latest_version, "zEC5LV9D2", "identity", field_ident.clone());
        let ident_secret =
            identities.field(
                &mut latest_version,
                "zZ9J6717C",
                "secret",
                field_bytes().custom("crate::publisher::SecretType").build(),
            );
        identities.index("zDZXPBB1L", "ident_ident", &[&ident_ident]).unique().build(&mut latest_version);
        let publish = latest_version.table("zYLNH9GCP", "publish");
        let publish_ident = publish.field(&mut latest_version, "zXQXWUVLT", "identity", field_ident.clone());
        let publish_keyvalues =
            publish.field(
                &mut latest_version,
                "zMC0B1T32",
                "keyvalues",
                field_bytes().custom("crate::model::publish::Publish").build(),
            );
        publish.index("zZ15A1Y6P", "publish_ident", &[&publish_ident]).unique().build(&mut latest_version);
        good_ormning::sqlite::generate(&root.join("src/publisher/db.rs"), vec![
            // Versions
            (0usize, latest_version)
        ], vec![
            // Queries
            new_insert(
                &identities,
                vec![set_field(&ident_ident), set_field(&ident_secret)],
            ).build_query("add_ident", QueryResCount::None),
            new_select(&identities)
                .return_fields(&[&ident_secret])
                .where_(field_eq(&ident_ident))
                .build_query("get_ident", QueryResCount::One),
            new_delete(&identities)
                .where_(field_eq(&ident_ident))
                .build_query("delete_ident", QueryResCount::None),
            new_select(&identities)
                .return_fields(&[&ident_ident, &ident_secret])
                .order(Expr::Field(ident_ident.clone()), Order::Asc)
                .limit(50)
                .build_query("list_idents_start", QueryResCount::Many),
            new_select(&identities)
                .return_fields(&[&ident_ident, &ident_secret])
                .where_(Expr::BinOp {
                    left: Box::new(Expr::Field(ident_ident.clone())),
                    op: BinOp::LessThan,
                    right: Box::new(Expr::Param {
                        name: "ident".to_string(),
                        type_: ident_ident.type_.type_.clone(),
                    }),
                })
                .order(Expr::Field(ident_ident.clone()), Order::Asc)
                .limit(50)
                .build_query("list_idents_after", QueryResCount::Many),
            new_insert(&publish, vec![set_field(&publish_ident), set_field(&publish_keyvalues)])
                .on_conflict(InsertConflict::DoUpdate(vec![set_field(&publish_keyvalues)]))
                .build_query("set_keyvalues", QueryResCount::None),
            new_select(&publish)
                .return_fields(&[&publish_keyvalues])
                .where_(field_eq(&publish_ident))
                .build_query("get_keyvalues", QueryResCount::MaybeOne),
            new_delete(&publish)
                .where_(field_eq(&publish_ident))
                .build_query("delete_keyvalues", QueryResCount::None)
        ]).unwrap();
    }
}
