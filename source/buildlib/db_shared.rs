use good_ormning::sqlite::schema::field::{
    FieldType,
    field_str,
};

pub fn field_ident() -> FieldType {
    return field_str().custom("crate::interface::stored::identity::Identity").build();
}
