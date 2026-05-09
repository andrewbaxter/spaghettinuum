use {
    good_ormning::sqlite::{
        Version,
        schema::field::field_str,
    },
    crate::buildlib::db_shared::field_ident,
};

pub fn build() -> Version {
    let v = Version::new();
    let table = v.table("allowed_identities");
    let ident = table.field("identity", field_ident(&v));
    table.field("group", field_str().build());
    table.primary_key("allowed_identities_pk_ident", &[&ident]);
    return v.build();
}
