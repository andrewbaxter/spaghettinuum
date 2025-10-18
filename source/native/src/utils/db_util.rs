use {
    async_trait::async_trait,
    deadpool_sqlite::{
        Config,
        Pool,
        Runtime,
    },
    good_ormning_runtime::GoodError,
    loga::{
        ea,
        ErrContext,
        Log,
        ResultContext,
    },
    rusqlite::Transaction,
    std::path::Path,
    tokio::fs::create_dir_all,
};

pub async fn setup_db(
    p: &Path,
    migrate: fn(&mut rusqlite::Connection) -> Result<(), GoodError>,
) -> Result<Pool, loga::Error> {
    let log = &Log::new().fork(ea!(path = p.to_string_lossy()));
    if let Some(parent) = p.parent() {
        create_dir_all(parent).await.stack_context(log, "Error creating parent directories for database")?;
    }
    let pool = Config::new(p).create_pool(Runtime::Tokio1).stack_context(log, "Error constructing db pool")?;
    let conn = pool.get().await.stack_context(log, "Error getting db connection from pool")?;
    conn.interact(move |conn| {
        migrate(conn)?;
        return Ok(()) as Result<(), loga::Error>;
    }).await.stack_context(log, "Error performing db interaction")?.stack_context(log, "Error migrating database")?;
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
