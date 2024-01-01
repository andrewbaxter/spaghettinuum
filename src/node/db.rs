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
                        "create table \"neighbors\" ( \"bucket\" integer not null , \"neighbor\" text not null )";
                    txn.execute(query, ()).to_good_error_query(query)?
                };
                {
                    let query = "create table \"secret\" ( \"unique\" integer not null , \"secret\" text not null )";
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

pub fn secret_ensure(
    db: &rusqlite::Connection,
    secret: &crate::interface::node_protocol::NodeSecret,
) -> Result<(), GoodError> {
    let query =
        "insert into \"secret\" ( \"unique\" , \"secret\" ) values ( 0 , $1 ) on conflict do update set \"secret\" = $1";
    db
        .execute(
            query,
            rusqlite::params![
                <crate::interface::node_protocol::NodeSecret as good_ormning_runtime
                ::sqlite
                ::GoodOrmningCustomString<crate::interface::node_protocol::NodeSecret>>::to_sql(
                    &secret,
                )
            ],
        )
        .to_good_error_query(query)?;
    Ok(())
}

pub fn secret_get(
    db: &rusqlite::Connection,
) -> Result<Option<crate::interface::node_protocol::NodeSecret>, GoodError> {
    let query = "select \"secret\" . \"secret\" from \"secret\"";
    let mut stmt = db.prepare(query).to_good_error_query(query)?;
    let mut rows = stmt.query(rusqlite::params![]).to_good_error_query(query)?;
    let r = rows.next().to_good_error(|| format!("Getting row in query [{}]", query))?;
    if let Some(r) = r {
        return Ok(Some({
            let x: String = r.get(0usize).to_good_error(|| format!("Getting result {}", 0usize))?;
            let x =
                <crate::interface::node_protocol::NodeSecret as good_ormning_runtime
                ::sqlite
                ::GoodOrmningCustomString<crate::interface::node_protocol::NodeSecret>>::from_sql(
                    x,
                ).to_good_error(|| format!("Parsing result {}", 0usize))?;
            x
        }));
    }
    Ok(None)
}

pub fn neighbors_insert(
    db: &rusqlite::Connection,
    bucket: u32,
    neighbor: &crate::interface::node_protocol::NodeState,
) -> Result<(), GoodError> {
    let query = "insert into \"neighbors\" ( \"bucket\" , \"neighbor\" ) values ( $1 , $2 )";
    db
        .execute(
            query,
            rusqlite::params![
                bucket,
                <crate::interface::node_protocol::NodeState as good_ormning_runtime
                ::sqlite
                ::GoodOrmningCustomString<crate::interface::node_protocol::NodeState>>::to_sql(
                    &neighbor,
                )
            ],
        )
        .to_good_error_query(query)?;
    Ok(())
}

pub fn neighbors_clear(db: &rusqlite::Connection) -> Result<(), GoodError> {
    let query = "delete from \"neighbors\"";
    db.execute(query, rusqlite::params![]).to_good_error_query(query)?;
    Ok(())
}

pub struct DbRes1 {
    pub bucket: u32,
    pub neighbor: crate::interface::node_protocol::NodeState,
}

pub fn neighbors_get(db: &rusqlite::Connection) -> Result<Vec<DbRes1>, GoodError> {
    let mut out = vec![];
    let query = "select \"neighbors\" . \"bucket\" , \"neighbors\" . \"neighbor\" from \"neighbors\"";
    let mut stmt = db.prepare(query).to_good_error_query(query)?;
    let mut rows = stmt.query(rusqlite::params![]).to_good_error_query(query)?;
    while let Some(r) = rows.next().to_good_error(|| format!("Getting row in query [{}]", query))? {
        out.push(DbRes1 {
            bucket: {
                let x: u32 = r.get(0usize).to_good_error(|| format!("Getting result {}", 0usize))?;
                x
            },
            neighbor: {
                let x: String = r.get(1usize).to_good_error(|| format!("Getting result {}", 1usize))?;
                let x =
                    <crate::interface::node_protocol::NodeState as good_ormning_runtime
                    ::sqlite
                    ::GoodOrmningCustomString<crate::interface::node_protocol::NodeState>>::from_sql(
                        x,
                    ).to_good_error(|| format!("Parsing result {}", 1usize))?;
                x
            },
        });
    }
    Ok(out)
}
