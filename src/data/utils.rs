use std::net::{
    SocketAddr,
    ToSocketAddrs,
    SocketAddrV4,
    Ipv4Addr,
};
use schemars::{
    JsonSchema,
    schema::{
        SchemaObject,
        Metadata,
        InstanceType,
    },
};
use serde::{
    Serialize,
    Deserialize,
};

#[derive(Clone)]
pub struct StrSocketAddr(pub String, pub SocketAddr);

impl StrSocketAddr {
    /// Only for serialization, dummy socketaddr with no lookup
    pub fn new_fake(s: String) -> StrSocketAddr {
        return StrSocketAddr(s, SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)));
    }
}

impl From<SocketAddr> for StrSocketAddr {
    fn from(value: SocketAddr) -> Self {
        return StrSocketAddr(value.to_string(), value);
    }
}

impl std::fmt::Display for StrSocketAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        format!("{} ({})", self.0, self.1).fmt(f)
    }
}

impl Serialize for StrSocketAddr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        return self.0.serialize(serializer);
    }
}

impl<'t> Deserialize<'t> for StrSocketAddr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'t> {
        let s = String::deserialize(deserializer)?;
        return Ok(
            StrSocketAddr(
                s.clone(),
                s
                    .to_socket_addrs()
                    .map_err(
                        |e| serde::de::Error::custom(
                            format!("Error turning socket address [{}] into IP: {}", s, e.to_string()),
                        ),
                    )?
                    .into_iter()
                    .next()
                    .ok_or_else(|| serde::de::Error::custom(format!("No recognizable address in [{}]", s)))?,
            ),
        );
    }
}

impl JsonSchema for StrSocketAddr {
    fn schema_name() -> String {
        return "StrSocketAddr".to_string();
    }

    fn json_schema(_gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        return SchemaObject {
            instance_type: Some(InstanceType::String.into()),
            metadata: Some(Box::new(Metadata {
                description: Some(
                    "An ip address or domain (ex: \"localhost\") which resolves to an address".to_string(),
                ),
                ..Default::default()
            })),
            ..Default::default()
        }.into();
    }
}
