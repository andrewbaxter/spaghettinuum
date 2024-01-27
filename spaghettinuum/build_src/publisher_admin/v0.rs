use good_ormning::sqlite::{
    Query,
    Version,
    query::{
        helpers::{
            eq_field,
            gt_field,
            set_field,
        },
        expr::Expr,
        select::Order,
        insert::InsertConflict,
    },
    new_delete,
    schema::{
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
    return v_;
}
