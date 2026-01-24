use {
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
    },
};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BytesZb32(pub Vec<u8>);

impl std::fmt::Debug for BytesZb32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("BytesZb32").field(&zbase32::encode_full_bytes(&self.0)).finish()
    }
}

impl Serialize for BytesZb32 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        return zbase32::encode_full_bytes(&self.0).serialize(serializer);
    }
}

impl<'a> Deserialize<'a> for BytesZb32 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'a> {
        let s = String::deserialize(deserializer)?;
        return Ok(BytesZb32(zbase32::decode_full_bytes_str(&s).map_err(serde::de::Error::custom)?));
    }
}

impl JsonSchema for BytesZb32 {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        return format!("BytesZbase32").into();
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        return String::json_schema(generator);
    }
}
