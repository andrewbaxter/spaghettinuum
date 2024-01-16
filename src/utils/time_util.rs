use std::ops::Neg;
use chrono::{
    DateTime,
    Utc,
    Duration,
};
use tokio::time::Instant;

pub trait ToInstant {
    fn to_instant(&self) -> Instant;
}

impl ToInstant for DateTime<Utc> {
    fn to_instant(&self) -> Instant {
        let diff = self.signed_duration_since(Utc::now());
        match (move || {
            // Showcasing rust core developers in denial of negative numbers
            if diff < Duration::zero() {
                return Ok(Instant::now().checked_sub(diff.neg().to_std().map_err(|_| ())?).ok_or_else(|| ())?) as
                    Result<Instant, ()>;
            } else {
                return Ok(Instant::now() + diff.to_std().map_err(|_| ())?);
            }
        })() {
            Ok(d) => return d,
            Err(_) => panic!("Error generating instant from datetime, diff is {:?}", diff),
        }
    }
}
