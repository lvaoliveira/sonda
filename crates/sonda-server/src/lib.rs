//! sonda server (ADR-0005): stores analyses uploaded by `sonda upload` in
//! PostgreSQL and serves the web app's API.
//!
//! Layers, as in sonda-core: `http` (routes, interface) → `db`
//! (infrastructure); `config` is read once at startup.

pub mod config;
pub mod db;
pub mod http;

use anyhow::{Context, Result};
use config::Config;
use tokio::net::TcpListener;

/// Connects, migrates, then serves until SIGTERM or Ctrl-C. A failed
/// migration stops startup: never serve on a half-migrated schema.
pub async fn run(config: Config) -> Result<()> {
    let pool = db::connect(config.database).await?;
    db::migrate(&pool).await?;
    let state = http::State {
        pool,
        token: std::sync::Arc::new(config.token),
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
