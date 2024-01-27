use good_ormning::sqlite::{
    Query,
    Version,
    query::{
        helpers::{
            eq_field,
            expr_and,
            gt_field,
            set_field,
        },
        expr::Expr,
        select::Order,
        insert::InsertConflict,
    },
    new_delete,
    schema::{
        field::{
            field_i32,
            field_i64,
            field_str,
        },
        constraint::{
            PrimaryKeyDef,
            ConstraintType,
        },
    },
    QueryResCount,
    new_insert,
    new_select,
};
use crate::build_src::db_shared::field_ident;

pub fn build(mut queries: Option<&mut Vec<Query>>) -> Version {
    let mut v_ = Version::default();
    let v = &mut v_;

    // Publisher-resolver certs
    let singleton_apilish_certs = v.table("zPZXM5WLP", "certs");
    let singleton_apilish_certs_uniuqe = singleton_apilish_certs.field(v, "zUAWRTQGK", "unique", field_i32().build());
    let singleton_apilish_certs_certs =
        singleton_apilish_certs.field(
            v,
            "zJ0MPA5DK",
            "certs",
            field_str().custom("crate::interface::stored::publisher::Certs").build(),
        );
    if let Some(queries) = &mut queries {
        queries.push(
            new_insert(
                &singleton_apilish_certs,
                vec![
                    (singleton_apilish_certs_uniuqe.clone(), Expr::LitI32(0)),
                    set_field("certs", &singleton_apilish_certs_certs)
                ],
            )
                .on_conflict(InsertConflict::DoUpdate(vec![set_field("certs", &singleton_apilish_certs_certs)]))
                .build_query("ensure_certs", QueryResCount::None),
        );
        queries.push(
            new_select(&singleton_apilish_certs)
                .return_field(&singleton_apilish_certs_certs)
                .build_query("get_certs", QueryResCount::MaybeOne),
        );
    }

    // Announcements
    let announce = v.table("zNMSOUSV6", "announce");
    let announce_ident = announce.field(v, "zEC5LV9D2", "identity", field_ident());
    let announce_value =
        announce.field(
            v,
            "zZ9J6717C",
            "value",
            field_str().custom("crate::interface::stored::announcement::Announcement").build(),
        );
    announce.index("zDZXPBB1L", "announce_ident", &[&announce_ident]).unique().build(v);
    if let Some(queries) = &mut queries {
        queries.push(
            new_insert(&announce, vec![set_field("ident", &announce_ident), set_field("value", &announce_value)])
                .on_conflict(InsertConflict::DoUpdate(vec![set_field("value", &announce_value)]))
                .build_query("set_announce", QueryResCount::None),
        );
        queries.push(
            new_delete(&announce)
                .where_(eq_field("ident", &announce_ident))
                .build_query("delete_announce", QueryResCount::None),
        );
        queries.push(
            new_select(&announce)
                .return_fields(&[&announce_ident, &announce_value])
                .order(Expr::Field(announce_ident.clone()), Order::Asc)
                .limit(Expr::LitI32(50))
                .build_query("list_announce_start", QueryResCount::Many),
        );
        queries.push(
            new_select(&announce)
                .return_fields(&[&announce_ident, &announce_value])
                .where_(gt_field("ident", &announce_ident))
                .order(Expr::Field(announce_ident.clone()), Order::Asc)
                .limit(Expr::LitI32(50))
                .build_query("list_announce_after", QueryResCount::Many),
        );
    }

    // Published ident global config
    {
        let t = v.table("zX3JY9PDC", "publish_idents");
        let f_ident = t.field(v, "zXQXWUVLT", "identity", field_ident());
        let f_missing_ttl = t.field(v, "z2BLD4BI2", "missing_ttl", field_i64().build());
        t.constraint(
            v,
            "z183FPXF9",
            "publish_idents_pk",
            ConstraintType::PrimaryKey(PrimaryKeyDef { fields: vec![f_ident.clone()] }),
        );
        if let Some(queries) = &mut queries {
            queries.push(
                new_select(&t)
                    .return_fields(&[&f_missing_ttl])
                    .where_(eq_field("ident", &f_ident))
                    .build_query_named_res("ident_get", QueryResCount::MaybeOne, "PublishedIdentMeta"),
            );
            queries.push(
                new_insert(&t, vec![set_field("ident", &f_ident), set_field("missing_ttl", &f_missing_ttl)])
                    .on_conflict(InsertConflict::DoUpdate(vec![set_field("missing_ttl", &f_missing_ttl)]))
                    .build_query("ident_set", QueryResCount::None),
            );
            queries.push(
                new_delete(&t).where_(eq_field("ident", &f_ident)).build_query("ident_delete", QueryResCount::None),
            );
        }
    }

    // Published key values
    {
        let publish = v.table("z13RW1O0W", "publish_values");
        let publish_ident = publish.field(v, "zXQXWUVLT", "identity", field_ident());
        let publish_key = publish.field(v, "zSOCRPVSQ", "key", field_str().build());
        let publish_value =
            publish.field(
                v,
                "zMC0B1T32",
                "values",
                field_str().custom("crate::interface::stored::record::RecordValue").build(),
            );
        publish.constraint(
            v,
            "zGQW81T28",
            "publish_values_pk",
            ConstraintType::PrimaryKey(PrimaryKeyDef { fields: vec![publish_ident.clone(), publish_key.clone()] }),
        );
        if let Some(queries) = &mut queries {
            queries.push(
                new_insert(
                    &publish,
                    vec![
                        set_field("ident", &publish_ident),
                        set_field("key", &publish_key),
                        set_field("value", &publish_value)
                    ],
                )
                    .on_conflict(InsertConflict::DoUpdate(vec![set_field("value", &publish_value)]))
                    .build_query("values_set", QueryResCount::None),
            );
            queries.push(
                new_select(&publish)
                    .return_fields(&[&publish_value])
                    .where_(expr_and(vec![eq_field("ident", &publish_ident), eq_field("key", &publish_key)]))
                    .build_query("values_get", QueryResCount::MaybeOne),
            );
            queries.push(
                new_select(&publish)
                    .return_fields(&[&publish_key])
                    .where_(eq_field("ident", &publish_ident))
                    .order_from_iter(
                        [
                            (Expr::Field(publish_ident.clone()), Order::Asc),
                            (Expr::Field(publish_key.clone()), Order::Asc),
                        ].into_iter(),
                    )
                    .limit(Expr::LitI32(50))
                    .build_query("values_keys_list_start", QueryResCount::Many),
            );
            queries.push(
                new_select(&publish)
                    .return_fields(&[&publish_key])
                    .where_(expr_and(vec![eq_field("ident", &publish_ident), gt_field("after", &publish_key)]))
                    .order_from_iter(
                        [
                            (Expr::Field(publish_ident.clone()), Order::Asc),
                            (Expr::Field(publish_key.clone()), Order::Asc),
                        ].into_iter(),
                    )
                    .limit(Expr::LitI32(50))
                    .build_query("values_keys_list_after", QueryResCount::Many),
            );
            queries.push(
                new_delete(&publish)
                    .where_(expr_and(vec![eq_field("ident", &publish_ident), eq_field("key", &publish_key)]))
                    .build_query("values_delete", QueryResCount::None),
            );
            queries.push(
                new_delete(&publish)
                    .where_(eq_field("ident", &publish_ident))
                    .build_query("values_delete_all", QueryResCount::None),
            );
        }
    }
    return v_;
}
