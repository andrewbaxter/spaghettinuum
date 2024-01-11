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
                        "create table \"publish\" ( \"identity\" text not null , \"keyvalues\" text not null )";
                    txn.execute(query, ()).to_good_error_query(query)?
                };
                {
                    let query = "create unique index \"ident\" on \"publish\" ( \"identity\" )";
                    txn.execute(query, ()).to_good_error_query(query)?
                };
                {
                    let query = "create table \"certs\" ( \"unique\" integer not null , \"certs\" text not null )";
                    txn.execute(query, ()).to_good_error_query(query)?
                };
                {
                    let query = "create table \"announce\" ( \"value\" text not null , \"identity\" text not null )";
                    txn.execute(query, ()).to_good_error_query(query)?
                };
                {
                    let query = "create unique index \"announce_ident\" on \"announce\" ( \"identity\" )";
                    txn.execute(query, ()).to_good_error_query(query)?
                };
                {
                    let query =
                        "create table \"allowed_identities\" ( \"identity\" text not null , constraint \"allowed_identities_pk_ident\" primary key ( \"identity\" ) )";
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

pub fn ensure_certs(
    db: &rusqlite::Connection,
    certs: &crate::interface::spagh_internal::PublishCerts,
) -> Result<(), GoodError> {
    let query =
        "insert into \"certs\" ( \"unique\" , \"certs\" ) values ( 0 , $1 ) on conflict do update set \"certs\" = $1";
    db
        .execute(
            query,
            rusqlite::params![
                <crate::interface::spagh_internal::PublishCerts as good_ormning_runtime
                ::sqlite
                ::GoodOrmningCustomString<crate::interface::spagh_internal::PublishCerts>>::to_sql(
                    &certs,
                )
            ],
        )
        .to_good_error_query(query)?;
    Ok(())
}

pub fn get_certs(
    db: &rusqlite::Connection,
) -> Result<Option<crate::interface::spagh_internal::PublishCerts>, GoodError> {
    let query = "select \"certs\" . \"certs\" from \"certs\"";
    let mut stmt = db.prepare(query).to_good_error_query(query)?;
    let mut rows = stmt.query(rusqlite::params![]).to_good_error_query(query)?;
    let r = rows.next().to_good_error(|| format!("Getting row in query [{}]", query))?;
    if let Some(r) = r {
        return Ok(Some({
            let x: String = r.get(0usize).to_good_error(|| format!("Getting result {}", 0usize))?;
            let x =
                <crate::interface::spagh_internal::PublishCerts as good_ormning_runtime
                ::sqlite
                ::GoodOrmningCustomString<crate::interface::spagh_internal::PublishCerts>>::from_sql(
                    x,
                ).to_good_error(|| format!("Parsing result {}", 0usize))?;
            x
        }));
    }
    Ok(None)
}

pub fn allow_identity(
    db: &rusqlite::Connection,
    ident: &crate::interface::identity::Identity,
) -> Result<(), GoodError> {
    let query = "insert into \"allowed_identities\" ( \"identity\" ) values ( $1 ) on conflict do nothing";
    db
        .execute(
            query,
            rusqlite::params![
                <crate::interface::identity::Identity as good_ormning_runtime
                ::sqlite
                ::GoodOrmningCustomString<crate::interface::identity::Identity>>::to_sql(
                    &ident,
                )
            ],
        )
        .to_good_error_query(query)?;
    Ok(())
}

pub fn disallow_identity(
    db: &rusqlite::Connection,
    ident: &crate::interface::identity::Identity,
) -> Result<(), GoodError> {
    let query = "delete from \"allowed_identities\" where ( \"allowed_identities\" . \"identity\" = $1 )";
    db
        .execute(
            query,
            rusqlite::params![
                <crate::interface::identity::Identity as good_ormning_runtime
                ::sqlite
                ::GoodOrmningCustomString<crate::interface::identity::Identity>>::to_sql(
                    &ident,
                )
            ],
        )
        .to_good_error_query(query)?;
    Ok(())
}

pub fn is_identity_allowed(
    db: &rusqlite::Connection,
    ident: &crate::interface::identity::Identity,
) -> Result<Option<i32>, GoodError> {
    let query =
        "select 0 as \"found\" from \"allowed_identities\" where ( \"allowed_identities\" . \"identity\" = $1 ) limit 1";
    let mut stmt = db.prepare(query).to_good_error_query(query)?;
    let mut rows =
        stmt
            .query(
                rusqlite::params![
                    <crate::interface::identity::Identity as good_ormning_runtime
                    ::sqlite
                    ::GoodOrmningCustomString<crate::interface::identity::Identity>>::to_sql(
                        &ident,
                    )
                ],
            )
            .to_good_error_query(query)?;
    let r = rows.next().to_good_error(|| format!("Getting row in query [{}]", query))?;
    if let Some(r) = r {
        return Ok(Some({
            let x: i32 = r.get(0usize).to_good_error(|| format!("Getting result {}", 0usize))?;
            x
        }));
    }
    Ok(None)
}

pub fn list_allowed_identities_start(
    db: &rusqlite::Connection,
) -> Result<Vec<crate::interface::identity::Identity>, GoodError> {
    let mut out = vec![];
    let query =
        "select \"allowed_identities\" . \"identity\" from \"allowed_identities\" order by \"allowed_identities\" . \"identity\" asc limit 50";
    let mut stmt = db.prepare(query).to_good_error_query(query)?;
    let mut rows = stmt.query(rusqlite::params![]).to_good_error_query(query)?;
    while let Some(r) = rows.next().to_good_error(|| format!("Getting row in query [{}]", query))? {
        out.push({
            let x: String = r.get(0usize).to_good_error(|| format!("Getting result {}", 0usize))?;
            let x =
                <crate::interface::identity::Identity as good_ormning_runtime
                ::sqlite
                ::GoodOrmningCustomString<crate::interface::identity::Identity>>::from_sql(
                    x,
                ).to_good_error(|| format!("Parsing result {}", 0usize))?;
            x
        });
    }
    Ok(out)
}

pub fn list_allowed_identities_after(
    db: &rusqlite::Connection,
    ident: &crate::interface::identity::Identity,
) -> Result<Vec<crate::interface::identity::Identity>, GoodError> {
    let mut out = vec![];
    let query =
        "select \"allowed_identities\" . \"identity\" from \"allowed_identities\" where ( \"allowed_identities\" . \"identity\" > $1 ) order by \"allowed_identities\" . \"identity\" asc limit 50";
    let mut stmt = db.prepare(query).to_good_error_query(query)?;
    let mut rows =
        stmt
            .query(
                rusqlite::params![
                    <crate::interface::identity::Identity as good_ormning_runtime
                    ::sqlite
                    ::GoodOrmningCustomString<crate::interface::identity::Identity>>::to_sql(
                        &ident,
                    )
                ],
            )
            .to_good_error_query(query)?;
    while let Some(r) = rows.next().to_good_error(|| format!("Getting row in query [{}]", query))? {
        out.push({
            let x: String = r.get(0usize).to_good_error(|| format!("Getting result {}", 0usize))?;
            let x =
                <crate::interface::identity::Identity as good_ormning_runtime
                ::sqlite
                ::GoodOrmningCustomString<crate::interface::identity::Identity>>::from_sql(
                    x,
                ).to_good_error(|| format!("Parsing result {}", 0usize))?;
            x
        });
    }
    Ok(out)
}

pub fn set_announce(
    db: &rusqlite::Connection,
    ident: &crate::interface::identity::Identity,
    value: &crate::interface::node_protocol::PublisherAnnouncement,
) -> Result<(), GoodError> {
    let query =
        "insert into \"announce\" ( \"identity\" , \"value\" ) values ( $1 , $2 ) on conflict do update set \"value\" = $2";
    db
        .execute(
            query,
            rusqlite::params![
                <crate::interface::identity::Identity as good_ormning_runtime
                ::sqlite
                ::GoodOrmningCustomString<crate::interface::identity::Identity>>::to_sql(
                    &ident,
                ),
                <crate::interface::node_protocol::PublisherAnnouncement as good_ormning_runtime
                ::sqlite
                ::GoodOrmningCustomString<crate::interface::node_protocol::PublisherAnnouncement>>::to_sql(
                    &value,
                )
            ],
        )
        .to_good_error_query(query)?;
    Ok(())
}

pub fn delete_announce(
    db: &rusqlite::Connection,
    ident: &crate::interface::identity::Identity,
) -> Result<(), GoodError> {
    let query = "delete from \"announce\" where ( \"announce\" . \"identity\" = $1 )";
    db
        .execute(
            query,
            rusqlite::params![
                <crate::interface::identity::Identity as good_ormning_runtime
                ::sqlite
                ::GoodOrmningCustomString<crate::interface::identity::Identity>>::to_sql(
                    &ident,
                )
            ],
        )
        .to_good_error_query(query)?;
    Ok(())
}

pub struct DbRes1 {
    pub identity: crate::interface::identity::Identity,
    pub value: crate::interface::node_protocol::PublisherAnnouncement,
}

pub fn list_announce_start(db: &rusqlite::Connection) -> Result<Vec<DbRes1>, GoodError> {
    let mut out = vec![];
    let query =
        "select \"announce\" . \"identity\" , \"announce\" . \"value\" from \"announce\" order by \"announce\" . \"identity\" asc limit 50";
    let mut stmt = db.prepare(query).to_good_error_query(query)?;
    let mut rows = stmt.query(rusqlite::params![]).to_good_error_query(query)?;
    while let Some(r) = rows.next().to_good_error(|| format!("Getting row in query [{}]", query))? {
        out.push(DbRes1 {
            identity: {
                let x: String = r.get(0usize).to_good_error(|| format!("Getting result {}", 0usize))?;
                let x =
                    <crate::interface::identity::Identity as good_ormning_runtime
                    ::sqlite
                    ::GoodOrmningCustomString<crate::interface::identity::Identity>>::from_sql(
                        x,
                    ).to_good_error(|| format!("Parsing result {}", 0usize))?;
                x
            },
            value: {
                let x: String = r.get(1usize).to_good_error(|| format!("Getting result {}", 1usize))?;
                let x =
                    <crate::interface::node_protocol::PublisherAnnouncement as good_ormning_runtime
                    ::sqlite
                    ::GoodOrmningCustomString<crate::interface::node_protocol::PublisherAnnouncement>>::from_sql(
                        x,
                    ).to_good_error(|| format!("Parsing result {}", 1usize))?;
                x
            },
        });
    }
    Ok(out)
}

pub fn list_announce_after(
    db: &rusqlite::Connection,
    ident: &crate::interface::identity::Identity,
) -> Result<Vec<DbRes1>, GoodError> {
    let mut out = vec![];
    let query =
        "select \"announce\" . \"identity\" , \"announce\" . \"value\" from \"announce\" where ( \"announce\" . \"identity\" > $1 ) order by \"announce\" . \"identity\" asc limit 50";
    let mut stmt = db.prepare(query).to_good_error_query(query)?;
    let mut rows =
        stmt
            .query(
                rusqlite::params![
                    <crate::interface::identity::Identity as good_ormning_runtime
                    ::sqlite
                    ::GoodOrmningCustomString<crate::interface::identity::Identity>>::to_sql(
                        &ident,
                    )
                ],
            )
            .to_good_error_query(query)?;
    while let Some(r) = rows.next().to_good_error(|| format!("Getting row in query [{}]", query))? {
        out.push(DbRes1 {
            identity: {
                let x: String = r.get(0usize).to_good_error(|| format!("Getting result {}", 0usize))?;
                let x =
                    <crate::interface::identity::Identity as good_ormning_runtime
                    ::sqlite
                    ::GoodOrmningCustomString<crate::interface::identity::Identity>>::from_sql(
                        x,
                    ).to_good_error(|| format!("Parsing result {}", 0usize))?;
                x
            },
            value: {
                let x: String = r.get(1usize).to_good_error(|| format!("Getting result {}", 1usize))?;
                let x =
                    <crate::interface::node_protocol::PublisherAnnouncement as good_ormning_runtime
                    ::sqlite
                    ::GoodOrmningCustomString<crate::interface::node_protocol::PublisherAnnouncement>>::from_sql(
                        x,
                    ).to_good_error(|| format!("Parsing result {}", 1usize))?;
                x
            },
        });
    }
    Ok(out)
}

pub fn set_keyvalues(
    db: &rusqlite::Connection,
    ident: &crate::interface::identity::Identity,
    keyvalues: &crate::interface::spagh_api::publish::Publish,
) -> Result<(), GoodError> {
    let query =
        "insert into \"publish\" ( \"identity\" , \"keyvalues\" ) values ( $1 , $2 ) on conflict do update set \"keyvalues\" = $2";
    db
        .execute(
            query,
            rusqlite::params![
                <crate::interface::identity::Identity as good_ormning_runtime
                ::sqlite
                ::GoodOrmningCustomString<crate::interface::identity::Identity>>::to_sql(
                    &ident,
                ),
                <crate::interface::spagh_api::publish::Publish as good_ormning_runtime
                ::sqlite
                ::GoodOrmningCustomString<crate::interface::spagh_api::publish::Publish>>::to_sql(
                    &keyvalues,
                )
            ],
        )
        .to_good_error_query(query)?;
    Ok(())
}

pub fn get_keyvalues(
    db: &rusqlite::Connection,
    ident: &crate::interface::identity::Identity,
) -> Result<Option<crate::interface::spagh_api::publish::Publish>, GoodError> {
    let query = "select \"publish\" . \"keyvalues\" from \"publish\" where ( \"publish\" . \"identity\" = $1 )";
    let mut stmt = db.prepare(query).to_good_error_query(query)?;
    let mut rows =
        stmt
            .query(
                rusqlite::params![
                    <crate::interface::identity::Identity as good_ormning_runtime
                    ::sqlite
                    ::GoodOrmningCustomString<crate::interface::identity::Identity>>::to_sql(
                        &ident,
                    )
                ],
            )
            .to_good_error_query(query)?;
    let r = rows.next().to_good_error(|| format!("Getting row in query [{}]", query))?;
    if let Some(r) = r {
        return Ok(Some({
            let x: String = r.get(0usize).to_good_error(|| format!("Getting result {}", 0usize))?;
            let x =
                <crate::interface::spagh_api::publish::Publish as good_ormning_runtime
                ::sqlite
                ::GoodOrmningCustomString<crate::interface::spagh_api::publish::Publish>>::from_sql(
                    x,
                ).to_good_error(|| format!("Parsing result {}", 0usize))?;
            x
        }));
    }
    Ok(None)
}

pub fn delete_keyvalues(
    db: &rusqlite::Connection,
    ident: &crate::interface::identity::Identity,
) -> Result<(), GoodError> {
    let query = "delete from \"publish\" where ( \"publish\" . \"identity\" = $1 )";
    db
        .execute(
            query,
            rusqlite::params![
                <crate::interface::identity::Identity as good_ormning_runtime
                ::sqlite
                ::GoodOrmningCustomString<crate::interface::identity::Identity>>::to_sql(
                    &ident,
                )
            ],
        )
        .to_good_error_query(query)?;
    Ok(())
}
