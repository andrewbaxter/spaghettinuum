use good_ormning_runtime::GoodError;
use good_ormning_runtime::ToGoodError;

pub fn migrate(db: &mut rusqlite::Connection) -> Result<(), GoodError> {
    {
        let query =
            "create table if not exists __good_version (rid int primary key, version bigint not null, lock int not null);";
        db.execute(query, ()).to_good_error_query(query)?;
    }
    {
        let query = "insert into __good_version (rid, version, lock) values (0, -1, 0) on conflict do nothing;";
        db.execute(query, ()).to_good_error_query(query)?;
    }
    loop {
        let txn = db.transaction().to_good_error(|| "Starting transaction".to_string())?;
        match (|| {
            let query = "update __good_version set lock = 1 where rid = 0 and lock = 0 returning version";
            let mut stmt = txn.prepare(query).to_good_error_query(query)?;
            let mut rows = stmt.query(()).to_good_error_query(query)?;
            let version = match rows.next().to_good_error_query(query)? {
                Some(r) => {
                    let ver: i64 = r.get(0usize).to_good_error_query(query)?;
                    ver
                },
                None => return Ok(false),
            };
            drop(rows);
            stmt.finalize().to_good_error_query(query)?;
            if version > 0i64 {
                return Err(
                    GoodError(
                        format!(
                            "The latest known version is {}, but the schema is at unknown version {}",
                            0i64,
                            version
                        ),
                    ),
                );
            }
            if version < 0i64 {
                {
                    let query =
                        "create table \"cache_persist\" ( \"value\" text , \"identity\" blob not null , \"key\" text not null , \"expires\" text not null )";
                    txn.execute(query, ()).to_good_error_query(query)?
                };
            }
            let query = "update __good_version set version = $1, lock = 0";
            txn.execute(query, rusqlite::params![0i64]).to_good_error_query(query)?;
            let out: Result<bool, GoodError> = Ok(true);
            out
        })() {
            Err(e) => {
                match txn.rollback() {
                    Err(e1) => {
                        return Err(
                            GoodError(
                                format!("{}\n\nRolling back the transaction due to the above also failed: {}", e, e1),
                            ),
                        );
                    },
                    Ok(_) => {
                        return Err(e);
                    },
                };
            },
            Ok(migrated) => {
                match txn.commit() {
                    Err(e) => {
                        return Err(GoodError(format!("Error committing the migration transaction: {}", e)));
                    },
                    Ok(_) => {
                        if migrated {
                            return Ok(())
                        } else {
                            std::thread::sleep(std::time::Duration::from_millis(5 * 1000));
                        }
                    },
                };
            },
        }
    }
}

pub fn push(
    db: &rusqlite::Connection,
    ident: &crate::data::identity::Identity,
    key: &str,
    expires: chrono::DateTime<chrono::Utc>,
    value: Option<&str>,
) -> Result<(), GoodError> {
    let query =
        "insert into \"cache_persist\" ( \"identity\" , \"key\" , \"expires\" , \"value\" ) values ( $1 , $2 , $3 , $4 )";
    db
        .execute(
            query,
            rusqlite::params![
                <crate::data::identity::Identity as good_ormning_runtime
                ::sqlite
                ::GoodOrmningCustomBytes<crate::data::identity::Identity>>::to_sql(
                    &ident,
                ),
                key,
                expires.to_rfc3339(),
                value.map(|value| value)
            ],
        )
        .to_good_error_query(query)?;
    Ok(())
}

pub struct DbRes1 {
    pub rowid: i64,
    pub identity: crate::data::identity::Identity,
    pub key: String,
    pub expires: chrono::DateTime<chrono::Utc>,
    pub value: Option<String>,
}

pub fn list(db: &rusqlite::Connection, row: i64) -> Result<Vec<DbRes1>, GoodError> {
    let mut out = vec![];
    let query =
        "select \"cache_persist\" . \"rowid\" , \"cache_persist\" . \"identity\" , \"cache_persist\" . \"key\" , \"cache_persist\" . \"expires\" , \"cache_persist\" . \"value\" from \"cache_persist\" where ( \"cache_persist\" . \"rowid\" < $1 ) order by \"cache_persist\" . \"rowid\" desc limit 50";
    let mut stmt = db.prepare(query).to_good_error_query(query)?;
    let mut rows = stmt.query(rusqlite::params![row]).to_good_error_query(query)?;
    while let Some(r) = rows.next().to_good_error(|| format!("Getting row in query [{}]", query))? {
        out.push(DbRes1 {
            rowid: {
                let x: i64 = r.get(0usize).to_good_error(|| format!("Getting result {}", 0usize))?;
                x
            },
            identity: {
                let x: Vec<u8> = r.get(1usize).to_good_error(|| format!("Getting result {}", 1usize))?;
                let x =
                    <crate::data::identity::Identity as good_ormning_runtime
                    ::sqlite
                    ::GoodOrmningCustomBytes<crate::data::identity::Identity>>::from_sql(
                        x,
                    ).to_good_error(|| format!("Parsing result {}", 1usize))?;
                x
            },
            key: {
                let x: String = r.get(2usize).to_good_error(|| format!("Getting result {}", 2usize))?;
                x
            },
            expires: {
                let x: String = r.get(3usize).to_good_error(|| format!("Getting result {}", 3usize))?;
                let x =
                    chrono::DateTime::<chrono::Utc>::from(
                        chrono::DateTime::<chrono::FixedOffset>::parse_from_rfc3339(
                            &x,
                        ).to_good_error(|| format!("Getting result {}", 3usize))?,
                    );
                x
            },
            value: {
                let x: Option<String> = r.get(4usize).to_good_error(|| format!("Getting result {}", 4usize))?;
                x
            },
        });
    }
    Ok(out)
}
