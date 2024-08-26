use std::fmt::Display;
use good_ormning_runtime::sqlite::{
    GoodOrmningCustomString,
};
use loga::{
    ea,
};
use schemars::JsonSchema;
use sha2::{
    Sha512,
    Digest,
};
use crate::{
    versioned,
    utils::blob::{
        Blob,
        ToBlob,
    },
};

pub mod v1;

/// For gpg-card compatibility we doubly hash the messages passed in for
/// signatures.  GPG takes a hash, passes it in as an ed25519 message, and the
/// ed25519 sign method hashes it again.
pub fn hash_for_ed25519(data: &[u8]) -> Blob {
    return <Sha512 as Digest>::digest(data).blob();
}

versioned!(
    Identity,
    PartialEq,
    Eq,
    Clone,
    Copy,
    Hash;
    (V1, 1, v1::Identity)
);

impl JsonSchema for Identity {
    fn schema_name() -> String {
        return "Identity".to_string();
    }

    fn json_schema(_gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        return schemars::schema::SchemaObject {
            instance_type: Some(schemars::schema::InstanceType::String.into()),
            metadata: Some(Box::new(schemars::schema::Metadata {
                description: Some("An identity (zbase32 string)".to_string()),
                ..Default::default()
            })),
            ..Default::default()
        }.into();
    }
}

impl Display for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <dyn Display>::fmt(&zbase32::encode_full_bytes(&self.to_bytes()), f)
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <dyn std::fmt::Debug>::fmt(&<dyn Display>::to_string(self), f)
    }
}

impl GoodOrmningCustomString<Identity> for Identity {
    fn to_sql<'a>(value: &'a Identity) -> std::borrow::Cow<'a, str> {
        return value.to_string().into();
    }

    fn from_sql(value: String) -> Result<Identity, String> {
        return Self::from_str(&value).map_err(|e| e.to_string());
    }
}

impl Identity {
    pub fn from_str(data: &str) -> Result<Self, loga::Error> {
        return Ok(
            Self::from_bytes(
                &zbase32::decode_full_bytes_str(
                    data,
                ).map_err(|e| loga::err_with("Failed to decode zbase32 for identity", ea!(err = e)))?,
            )?,
        );
    }
}

impl Identity {
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), &'static str> {
        match self {
            Identity::V1(v) => v.verify(message, signature),
        }
    }
}
