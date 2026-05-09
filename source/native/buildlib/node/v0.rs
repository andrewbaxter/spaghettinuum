use good_ormning::sqlite::{
    Version,
    schema::field::field_i32,
    types::type_str,
};

pub fn build() -> Version {
    let v = Version::new();

    // Persisted node secret, maybe avoid some reliability churn
    let secret = v.table("secret");
    let secret_unique = secret.field("unique", field_i32().build());
    let node_secret_type =
        v
            .custom_type("NodeSecret")
            .rust_type("crate::interface::stored::node_identity::NodeSecret")
            .base_type(type_str().build())
            .field_type();
    secret.field("secret", node_secret_type);
    secret.primary_key("secret_pk", &[&secret_unique]);

    // Persisted neighbors
    let neighbors = v.table("neighbors");
    let node_state_type =
        v
            .custom_type("NodeState")
            .rust_type("crate::interface::wire::node::NodeState")
            .base_type(type_str().build())
            .field_type();
    neighbors.field("neighbor", node_state_type);
    return v.build();
}
