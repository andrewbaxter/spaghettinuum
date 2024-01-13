use std::{
    path::Path,
};
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
use poem::async_trait;
use rusqlite::{
    Transaction,
};

pub async fn setup_db(
    p: &Path,
    migrate: fn(&mut rusqlite::Connection) -> Result<(), GoodError>,
) -> Result<Pool, loga::Error> {
    let log = &loga::new().fork(ea!(path = p.to_string_lossy()));
    let pool = Config::new(p).create_pool(Runtime::Tokio1).log_context(log, "Error constructing db pool")?;
    let conn = pool.get().await.log_context(log, "Error getting db connection from pool")?;
    conn.interact(move |conn| {
        migrate(conn)?;
        return Ok(()) as Result<(), loga::Error>;
    }).await.log_context(log, "Error performing db interaction")?.log_context(log, "Error migrating database")?;
    return Ok(pool);
}

#[async_trait]
pub trait DbTx {
    async fn tx<
        R: 'static + Send,
        F: 'static + Send + FnOnce(&mut Transaction) -> Result<R, loga::Error>,
    >(&self, handler: F) -> Result<R, loga::Error>;
}

#[async_trait]
impl DbTx for Pool {
    async fn tx<
        R: 'static + Send,
        F: 'static + Send + FnOnce(&mut Transaction) -> Result<R, loga::Error>,
    >(&self, handler: F) -> Result<R, loga::Error> {
        let db = self.get().await?;
        return Ok(db.interact(|dbc| {
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
        }).await??);
    }
}
