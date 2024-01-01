use good_ormning::sqlite::{
    Query,
    Version,
    query::{
        helpers::{
            set_field,
            eq_field,
            gt_field,
        },
        expr::Expr,
        select::Order,
        insert::InsertConflict,
    },
    new_delete,
    schema::{
        field::{
            field_str,
            field_i32,
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
            field_str().custom("crate::interface::spagh_internal::PublishCerts").build(),
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

    // Registration
    let allowed_identities = v.table("zMJAKGR8Z", "allowed_identities");
    let allowed_identities_ident = allowed_identities.field(v, "zPASWU9NI", "identity", field_ident());
    allowed_identities.constraint(
        v,
        "zIRUS5EQ1",
        "allowed_identities_pk_ident",
        ConstraintType::PrimaryKey(PrimaryKeyDef { fields: vec![allowed_identities_ident.clone()] }),
    );
    if let Some(queries) = &mut queries {
        queries.push(
            new_insert(&allowed_identities, vec![set_field("ident", &allowed_identities_ident)])
                .on_conflict(InsertConflict::DoNothing)
                .build_query("allow_identity", QueryResCount::None),
        );
        queries.push(
            new_delete(&allowed_identities)
                .where_(eq_field("ident", &allowed_identities_ident))
                .build_query("disallow_identity", QueryResCount::None),
        );
        queries.push(
            new_select(&allowed_identities)
                .where_(eq_field("ident", &allowed_identities_ident))
                .return_named("found", Expr::LitI32(0))
                .limit(Expr::LitI32(1))
                .build_query("is_identity_allowed", QueryResCount::MaybeOne),
        );
        queries.push(
            new_select(&allowed_identities)
                .return_fields(&[&allowed_identities_ident])
                .order(Expr::Field(allowed_identities_ident.clone()), Order::Asc)
                .limit(Expr::LitI32(50))
                .build_query("list_allowed_identities_start", QueryResCount::Many),
        );
        queries.push(
            new_select(&allowed_identities)
                .return_fields(&[&allowed_identities_ident])
                .where_(gt_field("ident", &allowed_identities_ident))
                .order(Expr::Field(allowed_identities_ident.clone()), Order::Asc)
                .limit(Expr::LitI32(50))
                .build_query("list_allowed_identities_after", QueryResCount::Many),
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
            field_str().custom("crate::interface::spagh_api::publish::Announcement").build(),
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

    // Published data
    let publish = v.table("zYLNH9GCP", "publish");
    let publish_ident = publish.field(v, "zXQXWUVLT", "identity", field_ident());
    let publish_keyvalues =
        publish.field(
            v,
            "zMC0B1T32",
            "keyvalues",
            field_str().custom("crate::interface::spagh_api::publish::Publish").build(),
        );
    publish.index("zZ15A1Y6P", "ident", &[&publish_ident]).unique().build(v);
    if let Some(queries) = &mut queries {
        queries.push(
            new_insert(
                &publish,
                vec![set_field("ident", &publish_ident), set_field("keyvalues", &publish_keyvalues)],
            )
                .on_conflict(InsertConflict::DoUpdate(vec![set_field("keyvalues", &publish_keyvalues)]))
                .build_query("set_keyvalues", QueryResCount::None),
        );
        queries.push(
            new_select(&publish)
                .return_fields(&[&publish_keyvalues])
                .where_(eq_field("ident", &publish_ident))
                .build_query("get_keyvalues", QueryResCount::MaybeOne),
        );
        queries.push(
            new_delete(&publish)
                .where_(eq_field("ident", &publish_ident))
                .build_query("delete_keyvalues", QueryResCount::None),
        );
    }
    return v_;
}
