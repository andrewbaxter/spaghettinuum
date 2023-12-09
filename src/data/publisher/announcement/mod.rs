pub mod v1;

use good_ormning_runtime::sqlite::GoodOrmningCustomBytes;
pub use v1::*;
use crate::versioned;

versioned!(
    Announcement,
    Debug;
    (V1, 1, v1::Announcement)
);

impl GoodOrmningCustomBytes<Announcement> for Announcement {
    fn to_sql<'a>(value: &'a Announcement) -> std::borrow::Cow<'a, [u8]> {
        return bincode::serialize(value).unwrap().into();
    }

    fn from_sql(value: Vec<u8>) -> Result<Announcement, String> {
        return bincode::deserialize(&value).map_err(|e| e.to_string());
    }
}
