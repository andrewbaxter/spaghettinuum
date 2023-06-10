pub mod v1;

pub use v1::*;
use crate::versioned;

versioned!(
    Announcement,
    Debug;
    (V1, 1, v1::Announcement)
);

impl Announcement {
    pub fn to_sql(&self) -> Vec<u8> {
        return bincode::serialize(self).unwrap();
    }

    pub fn from_sql(data: Vec<u8>) -> Result<Self, loga::Error> {
        return Ok(bincode::deserialize(&data)?);
    }
}
