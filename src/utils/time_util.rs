use chrono::{
    DateTime,
    Utc,
};
use tokio::time::Instant;

pub trait ToInstant {
    fn to_instant(&self) -> Instant;
}

impl ToInstant for DateTime<Utc> {
    fn to_instant(&self) -> Instant {
        return Instant::now() + self.signed_duration_since(Utc::now()).to_std().unwrap();
    }
}
