use {
    good_ormning::sqlite::{
        Version,
        schema::field::{
            field_i32,
            field_i64,
            field_str,
        },
        types::type_str,
    },
    crate::buildlib::db_shared::field_ident,
};

pub fn build() -> Version {
    let v = Version::new();

    // Publisher-resolver certs
    let certs = v.table("certs");
    let certs_unique = certs.field("unique", field_i32().build());
    v
        .custom_type("certs")
        .rust_type("crate::interface::stored::publisher::Certs")
        .base_type(type_str().build());
    certs.field(
        "certs",
        v
            .custom_type("certs")
            .rust_type("crate::interface::stored::publisher::Certs")
            .base_type(type_str().build())
            .field_type(),
    );
    certs.primary_key("certs_pk", &[&certs_unique]);

    // Announcements
    let announce = v.table("announce");
    let announce_ident = announce.field("identity", field_ident(&v));
    v
        .custom_type("announcement")
        .rust_type("crate::interface::stored::announcement::Announcement")
        .base_type(type_str().build());
    announce.field(
        "value",
        v
            .custom_type("announcement")
            .rust_type("crate::interface::stored::announcement::Announcement")
            .base_type(type_str().build())
            .field_type(),
    );
    announce.unique_index("announce_ident", &[&announce_ident]);

    // Published ident global config
    {
        let t = v.table("publish_idents");
        let f_ident = t.field("identity", field_ident(&v));
        t.field("missing_ttl", field_i64().build());
        t.primary_key("publish_idents_pk", &[&f_ident]);
    }

    // Published key values
    {
        let publish = v.table("publish_values");
        let publish_ident = publish.field("identity", field_ident(&v));
        let publish_key = publish.field("key", field_str().build());
        v
            .custom_type("record_value")
            .rust_type("crate::interface::stored::record::RecordValue")
            .base_type(type_str().build());
        publish.field(
            "values",
            v
                .custom_type("record_value")
                .rust_type("crate::interface::stored::record::RecordValue")
                .base_type(type_str().build())
                .field_type(),
        );
        publish.primary_key("publish_values_pk", &[&publish_ident, &publish_key]);
    }
    return v.build();
}
