use {
    good_ormning_runtime::sqlite::GoodOrmningCustomString,
    spaghettinuum::interface::identity::Identity,
    std::str::FromStr,
};

pub struct DbIdentity(pub Identity);

impl GoodOrmningCustomString<DbIdentity> for DbIdentity {
    fn to_sql<'a>(value: &'a DbIdentity) -> String {
        return value.0.to_string();
    }

    fn from_sql(value: String) -> Result<DbIdentity, String> {
        return Ok(DbIdentity(Identity::from_str(&value)?));
    }
}
