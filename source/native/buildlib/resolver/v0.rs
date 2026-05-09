use {
    good_ormning::sqlite::{
        Version,
        schema::field::field_str,
        types::type_i64,
    },
    crate::buildlib::db_shared::field_ident,
};

pub fn build() -> Version {
    let v = Version::new();
    let persist = v.table("cache_persist");
    persist.rowid_field(None);
    persist.field("identity", field_ident(&v));
    persist.field("key", field_str().build());
    let utc_secs_type = v
        .custom_type("utc_secs")
        .rust_type("crate::utils::time_util::UtcSecs")
        .base_type(type_i64().build())
        .field_type();
    persist.field("expires", utc_secs_type);
    persist.field("value", field_str().opt().build());
    return v.build();
}
