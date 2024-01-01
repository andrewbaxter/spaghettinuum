use std::path::Path;
use deadpool_sqlite::{
    Config,
    Pool,
    Runtime,
};
use good_ormning_runtime::GoodError;
use loga::{
    ResultContext,
    ea,
    ErrContext,
};
use rusqlite::{
    Connection,
    Transaction,
};

pub async fn setup_db(
    p: &Path,
    migrate: fn(&mut rusqlite::Connection) -> Result<(), GoodError>,
) -> Result<Pool, loga::Error> {
    let log = &loga::new(loga::Level::Info).fork(ea!(path = p.to_string_lossy()));
    let pool = Config::new(p).create_pool(Runtime::Tokio1).log_context(log, "Error constructing db pool")?;
    let conn = pool.get().await.log_context(log, "Error getting db connection from pool")?;
    conn.interact(move |conn| {
        migrate(conn)?;
        return Ok(()) as Result<(), loga::Error>;
    }).await.log_context(log, "Error performing db interaction")?.log_context(log, "Error migrating database")?;
    return Ok(pool);
}

pub fn tx<
    R,
    F: FnOnce(&mut Transaction) -> Result<R, loga::Error>,
>(dbc: &mut Connection, handler: F) -> Result<R, loga::Error> {
    let mut tx = dbc.transaction()?;
    match handler(&mut tx) {
        Ok(v) => {
            match tx.commit() {
                Ok(_) => return Ok(v),
                Err(e) => return Err(e.context("Failed to commit transaction")),
            }
        },
        Err(e) => {
            match tx.rollback() {
                Ok(_) => return Err(e),
                Err(e2) => return Err(e.also(e2.context("Failed to roll back transaction after error"))),
            }
        },
    }
}
