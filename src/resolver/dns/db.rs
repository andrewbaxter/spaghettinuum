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
                        "create table \"singleton_dot_certs\" ( \"priv_pem\" text , \"pub_pem\" text , \"unique\" integer not null , constraint \"singleton_unique\" primary key ( \"unique\" ) )";
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

pub fn dot_certs_setup(db: &rusqlite::Connection) -> Result<(), GoodError> {
    let query =
        "insert into \"singleton_dot_certs\" ( \"unique\" , \"pub_pem\" , \"priv_pem\" ) values ( 0 , null , null ) on conflict do nothing";
    db.execute(query, rusqlite::params![]).to_good_error_query(query)?;
    Ok(())
}

pub struct DbRes1 {
    pub pub_pem: Option<String>,
    pub priv_pem: Option<String>,
}

pub fn dot_certs_get(db: &rusqlite::Connection) -> Result<DbRes1, GoodError> {
    let query =
        "select \"singleton_dot_certs\" . \"pub_pem\" , \"singleton_dot_certs\" . \"priv_pem\" from \"singleton_dot_certs\"";
    let mut stmt = db.prepare(query).to_good_error_query(query)?;
    let mut rows = stmt.query(rusqlite::params![]).to_good_error_query(query)?;
    let r =
        rows
            .next()
            .to_good_error(|| format!("Getting row in query [{}]", query))?
            .ok_or_else(
                || GoodError(format!("Expected to return one row but returned no rows in query [{}]", query)),
            )?;
    Ok(DbRes1 {
        pub_pem: {
            let x: Option<String> = r.get(0usize).to_good_error(|| format!("Getting result {}", 0usize))?;
            x
        },
        priv_pem: {
            let x: Option<String> = r.get(1usize).to_good_error(|| format!("Getting result {}", 1usize))?;
            x
        },
    })
}

pub fn dot_certs_set(db: &rusqlite::Connection, pub_: Option<&str>, priv_: Option<&str>) -> Result<(), GoodError> {
    let query = "update \"singleton_dot_certs\" set \"pub_pem\" = $1 , \"priv_pem\" = $2";
    db
        .execute(query, rusqlite::params![pub_.map(|pub_| pub_), priv_.map(|priv_| priv_)])
        .to_good_error_query(query)?;
    Ok(())
}
