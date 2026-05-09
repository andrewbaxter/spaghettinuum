use good_ormning::sqlite::{
    VersionHandle,
    schema::field::FieldType,
    types::type_str,
};

pub fn field_ident(v: &VersionHandle) -> FieldType {
    v
        .custom_type("ident")
        .rust_type("crate::interface::stored::dbidentity::DbIdentity")
        .base_type(type_str().build())
        .field_type()
}
