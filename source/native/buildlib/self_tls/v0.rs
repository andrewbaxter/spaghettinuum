use good_ormning::sqlite::{
    Version,
    schema::field::field_i32,
    types::type_str,
};

pub fn build() -> Version {
    let v = Version::new();
    let singleton_api_certs = v.table("singleton_api_certs");
    let singleton_unique = singleton_api_certs.field("unique", field_i32().build());
    let state_type =
        v
            .custom_type("RefreshTlsState")
            .rust_type("crate::interface::stored::self_tls::RefreshTlsState")
            .base_type(type_str().opt().build())
            .field_type();
    singleton_api_certs.field("state", state_type);
    singleton_api_certs.primary_key("singleton_unique", &[&singleton_unique]);
    return v.build();
}
