use good_ormning::sqlite::{
    new_delete,
    new_insert,
    new_select,
    query::{
        expr::Expr,
        helpers::{
            eq_field,
            gt_field,
            set_field,
        },
        insert::InsertConflict,
        select::Order,
    },
    schema::{
        constraint::{
            ConstraintType,
            PrimaryKeyDef,
        },
        field::field_str,
    },
    Query,
    QueryResCount,
    Version,
};
use crate::buildlib::db_shared::field_ident;

pub fn build(mut queries: Option<&mut Vec<Query>>) -> Version {
    let mut v_ = Version::default();
    let v = &mut v_;

    // Registration
    let table = v.table("zMJAKGR8Z", "allowed_identities");
    let ident = table.field(v, "zPASWU9NI", "identity", field_ident());
    table.constraint(
        v,
        "zIRUS5EQ1",
        "allowed_identities_pk_ident",
        ConstraintType::PrimaryKey(PrimaryKeyDef { fields: vec![ident.clone()] }),
    );
    let group = table.field(v, "zP8LB0OAD", "group", field_str().build());
    if let Some(queries) = &mut queries {
        queries.push(
            new_insert(&table, vec![set_field("ident", &ident), set_field("group", &group)])
                .on_conflict(InsertConflict::DoNothing)
                .build_query("allow_identity", QueryResCount::None),
        );
        queries.push(
            new_delete(&table)
                .where_(eq_field("ident", &ident))
                .build_query("disallow_identity", QueryResCount::None),
        );
        queries.push(
            new_select(&table)
                .where_(eq_field("ident", &ident))
                .return_named("found", Expr::LitI32(0))
                .limit(Expr::LitI32(1))
                .build_query("is_identity_allowed", QueryResCount::MaybeOne),
        );
        queries.push(
            new_select(&table)
                .return_fields(&[&ident, &group])
                .order(Expr::Field(ident.clone()), Order::Asc)
                .limit(Expr::LitI32(50))
                .build_query("list_allowed_identities_start", QueryResCount::Many),
        );
        queries.push(
            new_select(&table)
                .return_fields(&[&ident, &group])
                .where_(gt_field("ident", &ident))
                .order(Expr::Field(ident.clone()), Order::Asc)
                .limit(Expr::LitI32(50))
                .build_query("list_allowed_identities_after", QueryResCount::Many),
        );
    }
    return v_;
}
