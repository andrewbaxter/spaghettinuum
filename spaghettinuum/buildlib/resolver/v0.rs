use good_ormning::sqlite::{
    Version,
    Query,
    new_delete,
    schema::field::{
        field_str,
        field_utctime_ms,
    },
    QueryResCount,
    query::{
        helpers::set_field,
        expr::{
            Expr,
            BinOp,
        },
        select::Order,
    },
    new_select,
    new_insert,
};
use crate::buildlib::db_shared::field_ident;

pub fn build(mut queries: Option<&mut Vec<Query>>) -> Version {
    let mut v_ = Version::default();
    let v = &mut v_;
    let persist = v.table("z18UDNDQB", "cache_persist");
    let persist_row = persist.rowid_field(v, None);
    let persist_ident = persist.field(v, "zUS446K3I", "identity", field_ident());
    let persist_key = persist.field(v, "zKMLG4285", "key", field_str().build());
    let persist_expires = persist.field(v, "z4NGKQ5LL", "expires", field_utctime_ms().build());
    let persist_value = persist.field(v, "zZJ7T4VPM", "value", field_str().opt().build());
    if let Some(queries) = &mut queries {
        queries.push(new_delete(&persist).build_query("cache_clear", QueryResCount::None));
        queries.push(
            new_insert(
                &persist,
                vec![
                    set_field("ident", &persist_ident),
                    set_field("key", &persist_key),
                    set_field("expires", &persist_expires),
                    set_field("value", &persist_value)
                ],
            ).build_query("cache_push", QueryResCount::None),
        );
        queries.push(
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
                .limit(Expr::LitI32(50))
                .build_query("cache_list", QueryResCount::Many),
        );
    }
    return v_;
}
