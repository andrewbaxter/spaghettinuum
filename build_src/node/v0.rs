use good_ormning::sqlite::{
    Version,
    Query,
    schema::field::{
        field_str,
        field_u32,
        field_i32,
    },
    query::{
        insert::InsertConflict,
        expr::Expr,
        helpers::set_field,
    },
    new_insert,
    QueryResCount,
    new_select,
    new_delete,
};

pub fn build(mut queries: Option<&mut Vec<Query>>) -> Version {
    let mut v_ = Version::default();
    let v = &mut v_;

    // Persisted node scret, maybe avoid some reliability churn
    let secret = v.table("z8OGO6MLD", "secret");
    let secret_unique = secret.field(v, "zWX8E3UUW", "unique", field_i32().build());
    let secret_secret =
        secret.field(
            v,
            "zNNMCRDDB",
            "secret",
            field_str().custom("crate::interface::node_protocol::NodeSecret").build(),
        );
    if let Some(queries) = &mut queries {
        queries.push(
            new_insert(&secret, vec![(secret_unique.clone(), Expr::LitI32(0)), set_field("secret", &secret_secret)])
                .on_conflict(InsertConflict::DoUpdate(vec![set_field("secret", &secret_secret)]))
                .build_query("secret_ensure", QueryResCount::None),
        );
        queries.push(
            new_select(&secret).return_field(&secret_secret).build_query("secret_get", QueryResCount::MaybeOne),
        );
    }

    // Persistend neighbors
    let neighbors = v.table("zDY20L3FM", "neighbors");
    let neighbors_bucket = neighbors.field(v, "zM12Y66J2", "bucket", field_u32().build());
    let neighbors_neighbor =
        neighbors.field(
            v,
            "zF8F58Y52",
            "neighbor",
            field_str().custom("crate::interface::node_protocol::NodeState").build(),
        );
    if let Some(queries) = &mut queries {
        queries.push(
            new_insert(
                &neighbors,
                vec![set_field("bucket", &neighbors_bucket), set_field("neighbor", &neighbors_neighbor)],
            ).build_query("neighbors_insert", QueryResCount::None),
        );
        queries.push(new_delete(&neighbors).build_query("neighbors_clear", QueryResCount::None));
        queries.push(
            new_select(&neighbors)
                .return_fields(&[&neighbors_bucket, &neighbors_neighbor])
                .build_query("neighbors_get", QueryResCount::Many),
        );
    }
    return v_;
}
