#[derive(Debug)]
pub struct GoodError(pub String);

impl std::fmt::Display for GoodError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for GoodError { }

impl From<rusqlite::Error> for GoodError {
    fn from(value: rusqlite::Error) -> Self {
        GoodError(value.to_string())
    }
}

pub fn migrate(db: &mut rusqlite::Connection) -> Result<(), GoodError> {
    db.execute(
        "create table if not exists __good_version (rid int primary key, version bigint not null, lock int not null);",
        (),
    )?;
    db.execute("insert into __good_version (rid, version, lock) values (0, -1, 0) on conflict do nothing;", ())?;
    loop {
        let txn = db.transaction()?;
        match (|| {
            let mut stmt =
                txn.prepare("update __good_version set lock = 1 where rid = 0 and lock = 0 returning version")?;
            let mut rows = stmt.query(())?;
            let version = match rows.next()? {
                Some(r) => {
                    let ver: i64 = r.get(0usize)?;
                    ver
                },
                None => return Ok(false),
            };
            drop(rows);
            stmt.finalize()?;
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
                txn.execute(
                    "create table \"cache_persist\" ( \"value\" text , \"identity\" blob not null , \"key\" text not null , \"expires\" text not null )",
                    (),
                )?;
            }
            txn.execute("update __good_version set version = $1, lock = 0", rusqlite::params![0i64])?;
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
    db: &mut rusqlite::Connection,
    identity: &crate::model::identity::Identity,
    key: &str,
    expires: chrono::DateTime<chrono::Utc>,
    value: Option<&str>,
) -> Result<(), GoodError> {
    db
        .execute(
            "insert into \"cache_persist\" ( \"identity\" , \"key\" , \"expires\" , \"value\" ) values ( $1 , $2 , $3 , $4 )",
            rusqlite::params![identity.to_sql(), key, expires.to_rfc3339(), value.map(|value| value)],
        )
        .map_err(|e| GoodError(e.to_string()))?;
    Ok(())
}

pub struct DbRes1 {
    pub rowid: i64,
    pub identity: crate::model::identity::Identity,
    pub key: String,
    pub expires: chrono::DateTime<chrono::Utc>,
    pub value: Option<String>,
}

pub fn list(db: &mut rusqlite::Connection, row: i64) -> Result<Vec<DbRes1>, GoodError> {
    let mut out = vec![];
    let mut stmt =
        db.prepare(
            "select \"cache_persist\" . \"rowid\" , \"cache_persist\" . \"identity\" , \"cache_persist\" . \"key\" , \"cache_persist\" . \"expires\" , \"cache_persist\" . \"value\" from \"cache_persist\" where ( \"cache_persist\" . \"rowid\" < $1 ) order by \"cache_persist\" . \"rowid\" desc limit 50",
        )?;
    let mut rows = stmt.query(rusqlite::params![row]).map_err(|e| GoodError(e.to_string()))?;
    while let Some(r) = rows.next()? {
        out.push(DbRes1 {
            rowid: {
                let x: i64 = r.get(0usize)?;
                x
            },
            identity: {
                let x: Vec<u8> = r.get(1usize)?;
                let x = crate::model::identity::Identity::from_sql(x).map_err(|e| GoodError(e.to_string()))?;
                x
            },
            key: {
                let x: String = r.get(2usize)?;
                x
            },
            expires: {
                let x: String = r.get(3usize)?;
                let x =
                    chrono::DateTime::<chrono::Utc>::from(
                        chrono::DateTime::<chrono::FixedOffset>::parse_from_rfc3339(
                            &x,
                        ).map_err(|e| GoodError(e.to_string()))?,
                    );
                x
            },
            value: {
                let x: Option<String> = r.get(4usize)?;
                x
            },
        });
    }
    Ok(out)
}
