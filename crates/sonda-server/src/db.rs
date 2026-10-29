//! Infrastructure: the PostgreSQL pool and schema migrations.

use anyhow::{Context, Result};
use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use std::time::Duration;

/// How long startup waits for the database, e.g. while its container boots.
const CONNECT_PATIENCE: Duration = Duration::from_secs(30);

pub async fn connect(options: PgConnectOptions) -> Result<PgPool> {
    let pool_options = PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(5));
    let deadline = tokio::time::Instant::now() + CONNECT_PATIENCE;
    loop {
        match pool_options.clone().connect_with(options.clone()).await {
            Ok(pool) => return Ok(pool),
            Err(e) if tokio::time::Instant::now() < deadline => {
                tracing::warn!(error = %e, "database not reachable yet, retrying");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err(e) => return Err(e).context("connecting to the database"),
        }
    }
}

/// Applies pending migrations from `migrations/`, each in its own
/// transaction, and fails if the database has one this build does not know
/// (it was migrated by a newer sonda-server).
pub async fn migrate(pool: &PgPool) -> Result<()> {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .context("migrating the database")?;
    tracing::info!("database schema is up to date");
    Ok(())
}

/// Whether the database answers within `timeout`.
pub async fn ping(pool: &PgPool, timeout: Duration) -> bool {
    let query = sqlx::query("SELECT 1").execute(pool);
    matches!(tokio::time::timeout(timeout, query).await, Ok(Ok(_)))
}
