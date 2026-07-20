use {
    crate::versioned,
    schemars::{
        json_schema,
        JsonSchema,
    },
    std::{
        fmt::Display,
        str::FromStr,
    },
};

pub mod v1;

versioned!(
    Id,
    PartialEq,
    Eq,
    Clone,
    Hash,
    PartialOrd,
    Ord;
    (V1, 1, v1::Id)
);

impl JsonSchema for Id {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        return "Id".into();
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        return json_schema!({
            "type":["string"],
            "description": "An identity (zbase32 string), the fingerprint of a public key"
        });
    }
}

impl Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <dyn Display>::fmt(&zbase32::encode_full_bytes(&self.to_bytes()), f)
    }
}

impl std::fmt::Debug for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <dyn std::fmt::Debug>::fmt(&<dyn Display>::to_string(self), f)
    }
}

impl FromStr for Id {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        return Ok(
            Self::from_bytes(
                &zbase32::decode_full_bytes_str(
                    s,
                ).map_err(|e| format!("Failed to decode zbase32 for id: {}", e))?,
            )?,
        );
    }
}
