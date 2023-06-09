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
                    "create table \"publish\" ( \"identity\" blob not null , \"keyvalues\" blob not null )",
                    (),
                )?;
                txn.execute("create unique index \"publish_ident\" on \"publish\" ( \"identity\" )", ())?;
                txn.execute(
                    "create table \"announce\" ( \"value\" blob not null , \"identity\" blob not null )",
                    (),
                )?;
                txn.execute("create unique index \"announce_ident\" on \"announce\" ( \"identity\" )", ())?;
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

pub fn set_announce(
    db: &mut rusqlite::Connection,
    identity: &crate::data::identity::Identity,
    value: &crate::data::publisher::announcement::Announcement,
) -> Result<(), GoodError> {
    db
        .execute(
            "insert into \"announce\" ( \"identity\" , \"value\" ) values ( $1 , $2 ) on conflict do update set \"value\" = $2",
            rusqlite::params![identity.to_sql(), value.to_sql()],
        )
        .map_err(|e| GoodError(e.to_string()))?;
    Ok(())
}

pub fn delete_announce(
    db: &mut rusqlite::Connection,
    identity: &crate::data::identity::Identity,
) -> Result<(), GoodError> {
    db
        .execute(
            "delete from \"announce\" where ( \"announce\" . \"identity\" = $1 )",
            rusqlite::params![identity.to_sql()],
        )
        .map_err(|e| GoodError(e.to_string()))?;
    Ok(())
}

pub struct DbRes1 {
    pub identity: crate::data::identity::Identity,
    pub value: crate::data::publisher::announcement::Announcement,
}

pub fn list_announce_start(db: &mut rusqlite::Connection) -> Result<Vec<DbRes1>, GoodError> {
    let mut out = vec![];
    let mut stmt =
        db.prepare(
            "select \"announce\" . \"identity\" , \"announce\" . \"value\" from \"announce\" order by \"announce\" . \"identity\" asc limit 50",
        )?;
    let mut rows = stmt.query(rusqlite::params![]).map_err(|e| GoodError(e.to_string()))?;
    while let Some(r) = rows.next()? {
        out.push(DbRes1 {
            identity: {
                let x: Vec<u8> = r.get(0usize)?;
                let x = crate::data::identity::Identity::from_sql(x).map_err(|e| GoodError(e.to_string()))?;
                x
            },
            value: {
                let x: Vec<u8> = r.get(1usize)?;
                let x =
                    crate::data::publisher::announcement::Announcement::from_sql(
                        x,
                    ).map_err(|e| GoodError(e.to_string()))?;
                x
            },
        });
    }
    Ok(out)
}

pub fn list_announce_after(
    db: &mut rusqlite::Connection,
    ident: &crate::data::identity::Identity,
) -> Result<Vec<DbRes1>, GoodError> {
    let mut out = vec![];
    let mut stmt =
        db.prepare(
            "select \"announce\" . \"identity\" , \"announce\" . \"value\" from \"announce\" where ( \"announce\" . \"identity\" < $1 ) order by \"announce\" . \"identity\" asc limit 50",
        )?;
    let mut rows = stmt.query(rusqlite::params![ident.to_sql()]).map_err(|e| GoodError(e.to_string()))?;
    while let Some(r) = rows.next()? {
        out.push(DbRes1 {
            identity: {
                let x: Vec<u8> = r.get(0usize)?;
                let x = crate::data::identity::Identity::from_sql(x).map_err(|e| GoodError(e.to_string()))?;
                x
            },
            value: {
                let x: Vec<u8> = r.get(1usize)?;
                let x =
                    crate::data::publisher::announcement::Announcement::from_sql(
                        x,
                    ).map_err(|e| GoodError(e.to_string()))?;
                x
            },
        });
    }
    Ok(out)
}

pub fn set_keyvalues(
    db: &mut rusqlite::Connection,
    identity: &crate::data::identity::Identity,
    keyvalues: &crate::data::publisher::Publish,
) -> Result<(), GoodError> {
    db
        .execute(
            "insert into \"publish\" ( \"identity\" , \"keyvalues\" ) values ( $1 , $2 ) on conflict do update set \"keyvalues\" = $2",
            rusqlite::params![identity.to_sql(), keyvalues.to_sql()],
        )
        .map_err(|e| GoodError(e.to_string()))?;
    Ok(())
}

pub fn get_keyvalues(
    db: &mut rusqlite::Connection,
    identity: &crate::data::identity::Identity,
) -> Result<Option<crate::data::publisher::Publish>, GoodError> {
    let mut stmt =
        db.prepare("select \"publish\" . \"keyvalues\" from \"publish\" where ( \"publish\" . \"identity\" = $1 )")?;
    let mut rows = stmt.query(rusqlite::params![identity.to_sql()]).map_err(|e| GoodError(e.to_string()))?;
    let r = rows.next()?;
    if let Some(r) = r {
        return Ok(Some({
            let x: Vec<u8> = r.get(0usize)?;
            let x = crate::data::publisher::Publish::from_sql(x).map_err(|e| GoodError(e.to_string()))?;
            x
        }));
    }
    Ok(None)
}

pub fn delete_keyvalues(
    db: &mut rusqlite::Connection,
    identity: &crate::data::identity::Identity,
) -> Result<(), GoodError> {
    db
        .execute(
            "delete from \"publish\" where ( \"publish\" . \"identity\" = $1 )",
            rusqlite::params![identity.to_sql()],
        )
        .map_err(|e| GoodError(e.to_string()))?;
    Ok(())
}
