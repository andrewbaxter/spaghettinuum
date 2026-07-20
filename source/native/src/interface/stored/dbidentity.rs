use {
    good_ormning::runtime::sqlite::GoodOrmningCustomString,
    spaghettinuum::interface::public_key::PublicKey,
    std::str::FromStr,
};

pub struct DbIdentity(pub PublicKey);

impl GoodOrmningCustomString<DbIdentity> for DbIdentity {
    fn to_sql<'a>(value: &'a DbIdentity) -> String {
        return value.0.to_string();
    }

    fn from_sql(value: String) -> Result<DbIdentity, String> {
        return Ok(DbIdentity(PublicKey::from_str(&value)?));
    }
}
