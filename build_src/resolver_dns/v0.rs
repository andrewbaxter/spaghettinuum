use good_ormning::sqlite::{
    Version,
    Query,
    schema::{
        field::{
            field_str,
            field_i32,
        },
        constraint::{
            ConstraintType,
            PrimaryKeyDef,
        },
    },
    QueryResCount,
    query::{
        helpers::set_field,
        expr::Expr,
        insert::InsertConflict,
    },
    new_select,
    new_insert,
    new_update,
};

pub fn build(mut queries: Option<&mut Vec<Query>>) -> Version {
    let mut v_ = Version::default();
    let v = &mut v_;
    let singleton_dot_certs = v.table("z488Y1LA8", "singleton_dot_certs");
    let singleton_unique = singleton_dot_certs.field(v, "zO911YAXM", "unique", field_i32().build());
    let singleton_pub = singleton_dot_certs.field(v, "zQTPPZ4K7", "pub_pem", field_str().opt().build());
    let singleton_priv = singleton_dot_certs.field(v, "zYLDNUW8V", "priv_pem", field_str().opt().build());
    singleton_dot_certs.constraint(
        v,
        "zFUG0I2A0",
        "singleton_unique",
        ConstraintType::PrimaryKey(PrimaryKeyDef { fields: vec![singleton_unique.clone()] }),
    );
    if let Some(queries) = &mut queries {
        queries.push(
            new_insert(
                &singleton_dot_certs,
                vec![
                    (singleton_unique.clone(), Expr::LitI32(0)),
                    (singleton_pub.clone(), Expr::LitNull(singleton_pub.0.type_.type_.type_.clone())),
                    (singleton_priv.clone(), Expr::LitNull(singleton_priv.0.type_.type_.type_.clone()))
                ],
            )
                .on_conflict(InsertConflict::DoNothing)
                .build_query("dot_certs_setup", QueryResCount::None),
        );
        queries.push(
            new_select(&singleton_dot_certs)
                .return_field(&singleton_pub)
                .return_field(&singleton_priv)
                .build_query("dot_certs_get", QueryResCount::One),
        );
        queries.push(
            new_update(
                &singleton_dot_certs,
                vec![set_field("pub", &singleton_pub), set_field("priv", &singleton_priv)],
            ).build_query("dot_certs_set", QueryResCount::None),
        );
    }
    return v_;
}
