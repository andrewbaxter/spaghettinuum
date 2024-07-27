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
    query::{
        insert::InsertConflict,
        expr::Expr,
        helpers::{
            set_field,
        },
    },
    new_insert,
    QueryResCount,
    new_update,
    new_select,
};

pub fn build(mut queries: Option<&mut Vec<Query>>) -> Version {
    let mut v_ = Version::default();
    let v = &mut v_;
    let singleton_api_certs = v.table("z488Y1LA8", "singleton_api_certs");
    let singleton_unique = singleton_api_certs.field(v, "zO911YAXM", "unique", field_i32().build());
    let singleton_state =
        singleton_api_certs.field(
            v,
            "z6FBFBQ15",
            "state",
            field_str().custom("crate::interface::stored::self_tls::SelfTlsState").opt().build(),
        );
    singleton_api_certs.constraint(
        v,
        "zFUG0I2A0",
        "singleton_unique",
        ConstraintType::PrimaryKey(PrimaryKeyDef { fields: vec![singleton_unique.clone()] }),
    );
    if let Some(queries) = &mut queries {
        queries.push(
            new_insert(
                &singleton_api_certs,
                vec![
                    (singleton_unique.clone(), Expr::LitI32(0)),
                    (singleton_state.clone(), Expr::LitNull(singleton_state.0.type_.type_.type_.clone()))
                ],
            )
                .on_conflict(InsertConflict::DoNothing)
                .build_query("api_certs_setup", QueryResCount::None),
        );
        queries.push(
            new_select(&singleton_api_certs)
                .return_field(&singleton_state)
                .build_query("api_certs_get", QueryResCount::One),
        );
        queries.push(
            new_update(
                &singleton_api_certs,
                vec![set_field("state", &singleton_state)],
            ).build_query("api_certs_set", QueryResCount::None),
        );
    }
    return v_;
}
