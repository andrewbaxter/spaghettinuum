use {
    good_ormning_runtime::sqlite::GoodOrmningCustomI64,
    schemars::JsonSchema,
    serde::{
        Deserialize,
        Serialize,
    },
    std::{
        i64,
        time::{
            Duration,
            Instant,
            SystemTime,
            UNIX_EPOCH,
        },
    },
};

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, JsonSchema)]
pub struct UtcSecs(pub u64);

impl From<SystemTime> for UtcSecs {
    fn from(value: SystemTime) -> Self {
        return Self(value.duration_since(UNIX_EPOCH).unwrap().as_secs());
    }
}

impl Into<SystemTime> for UtcSecs {
    fn into(self) -> SystemTime {
        return UNIX_EPOCH + Duration::from_secs(self.0);
    }
}

impl GoodOrmningCustomI64<UtcSecs> for UtcSecs {
    fn to_sql(value: &UtcSecs) -> i64 {
        return i64::try_from(value.0).unwrap_or(i64::MAX);
    }

    fn from_sql(value: i64) -> Result<UtcSecs, String> {
        return Ok(UtcSecs(value as u64));
    }
}

pub trait ToInstant {
    fn to_instant(&self) -> Instant;
}

impl ToInstant for SystemTime {
    fn to_instant(&self) -> Instant {
        let diff = self.duration_since(SystemTime::now());
        let now = Instant::now();

        // Showcasing rust core developers in denial of negative numbers
        match diff {
            Ok(past) => {
                return now - past;
            },
            Err(future) => {
                return now + future.duration();
            },
        }
    }
}
