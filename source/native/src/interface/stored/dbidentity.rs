use {
    good_ormning::runtime::sqlite::GoodOrmningCustomString,
    spaghettinuum::interface::id::Identity,
    std::str::FromStr,
};

pub struct DbIdentity(pub Identity);

impl GoodOrmningCustomString<DbIdentity> for DbIdentity {
    fn from_sql(value: String) -> Result<DbIdentity, String> {
        return Ok(DbIdentity(Identity::from_str(&value)?));
    }

    fn to_sql<'a>(value: &'a DbIdentity) -> String {
        return value.0.to_string();
    }
}
