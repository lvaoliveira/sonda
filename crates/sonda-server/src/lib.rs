//! sonda server (ADR-0005): stores analyses uploaded by `sonda upload` in
//! PostgreSQL and serves the web app's API.
//!
//! Layers, as in sonda-core: `http`, `api` and `ingest` (interface: routes,
//! auth, validation) → `store` and `db` (infrastructure); `config` is read
//! once at startup.

pub mod api;
pub mod config;
pub mod db;
pub mod drill;
pub mod http;
pub mod ingest;
pub mod issues;
pub mod overview;
pub mod rules;
pub mod session;
pub mod store;
pub mod throttle;
pub mod users;

use anyhow::{Context, Result};
use config::Config;
use tokio::net::TcpListener;

/// Connects, migrates, then serves until SIGTERM or Ctrl-C. A failed
/// migration stops startup: never serve on a half-migrated schema.
pub async fn run(config: Config) -> Result<()> {
    let pool = db::connect(config.database).await?;
    db::migrate(&pool).await?;
    users::bootstrap_admin(&pool, config.admin).await?;
    let reads_require_auth = !config.listen.ip().is_loopback();
    if reads_require_auth {
        tracing::info!("reads require the token or a session (not listening on loopback only)");
    }
    let state = http::State {
        pool,
        token: std::sync::Arc::new(config.token),
        reads_require_auth,
    };
    let app = http::router(state, config.web_dir.as_deref());
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("listening on {}", config.listen))?;
    tracing::info!(address = %config.listen, "listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await
        .context("serving")
}

async fn shutdown() {
    let ctrl_c = async {
        // If the handler cannot be installed, rely on the other signal.
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
    tracing::info!("shutting down");
}
