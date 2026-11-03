//! sonda server (ADR-0005): stores analyses uploaded by `sonda upload` in
//! PostgreSQL and serves the web app's API.
//!
//! Layers, as in sonda-core: `http`, `api` and `ingest` (interface: routes,
//! auth, validation) → `store` and `db` (infrastructure); `config` is read
//! once at startup.

pub mod advisories;
pub mod advisory_sync;
pub mod analyses;
pub mod api;
pub mod components;
pub mod config;
pub mod coverage;
pub mod db;
pub mod decorations;
pub mod deleted_projects;
pub mod dependencies;
pub mod drill;
pub mod gates;
pub mod github;
mod health;
pub mod http;
pub mod ingest;
pub mod issues;
pub mod new_code;
pub mod observability;
pub mod overview;
pub mod profiles;
pub mod project_settings;
pub mod projects;
pub mod pull_requests;
pub mod quality_gates;
pub mod retention;
pub mod review;
pub mod rule_settings;
pub mod rules;
pub mod security;
pub mod session;
pub mod store;
pub mod throttle;
pub mod tokens;
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
    let metrics = std::sync::Arc::new(observability::Metrics::default());
    if let Some(base_url) = config.advisory_sync {
        tracing::info!(source = %base_url, "syncing advisories daily");
        let pool = pool.clone();
        let metrics = metrics.clone();
        tokio::spawn(async move {
            loop {
                match advisory_sync::sync_once(&pool, &base_url).await {
                    Ok(s) => {
                        tracing::info!(
                            read = s.read,
                            imported = s.imported,
                            errors = s.errors,
                            first_errors = ?s.first_errors,
                            "synced advisories"
                        );
                        metrics.record_advisory_sync(Some(&s));
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "advisory sync failed; retrying later");
                        metrics.record_advisory_sync(None);
                    }
                }
                tokio::time::sleep(advisory_sync::INTERVAL).await;
            }
        });
    }
    {
        let pool = pool.clone();
        tokio::spawn(async move {
            loop {
                match pull_requests::remove_stale(&pool).await {
                    Ok(0) => {}
                    Ok(n) => {
                        tracing::info!(pull_requests = n, "removed stale pull request analyses")
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "removing stale pull requests failed; retrying later")
                    }
                }
                tokio::time::sleep(pull_requests::CLEANUP_INTERVAL).await;
            }
        });
    }
    if let Some(days) = config.thin_analyses_after_days {
        tracing::info!(
            days,
            "thinning branch analyses older than that to one a day"
        );
        let pool = pool.clone();
        tokio::spawn(async move {
            loop {
                match retention::thin(&pool, days).await {
                    Ok(0) => {}
                    Ok(n) => tracing::info!(analyses = n, "thinned old analyses"),
                    Err(e) => {
                        tracing::warn!(error = %e, "thinning old analyses failed; retrying later")
                    }
                }
                tokio::time::sleep(retention::INTERVAL).await;
            }
        });
    }
    let reads_require_auth = !config.listen.ip().is_loopback();
    if reads_require_auth {
        tracing::info!("reads require the token or a session (not listening on loopback only)");
    }
    let github = config.github.map(std::sync::Arc::new);
    if let Some(app) = &github {
        tracing::info!(app = ?app, "decorating pull requests on GitHub");
        let (pool, app, public_url) = (pool.clone(), app.clone(), config.public_url.clone());
        tokio::spawn(async move {
            loop {
                if let Err(e) = decorations::post_due(&pool, &app, public_url.as_deref()).await {
                    tracing::warn!(error = %e, "posting pull request decorations failed; retrying later");
                }
                tokio::time::sleep(decorations::INTERVAL).await;
            }
        });
    }
    let cookie = if config.plain_http {
        tracing::warn!(
            "SONDA_PLAIN_HTTP: signing in over plain HTTP, so anyone who can see this \
             network's traffic can take a session; use it on a trusted network only"
        );
        session::Cookie::PlainHttp
    } else {
        session::Cookie::Secure
    };
    let state = http::State {
        pool: pool.clone(),
        token: config.token.map(std::sync::Arc::new),
        reads_require_auth,
        metrics: metrics.clone(),
        github,
        cookie,
    };
    let app = http::router(state, config.web_dir.as_deref());
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("listening on {}", config.listen))?;
    if let Some(address) = config.metrics_listen {
        let metrics_listener = TcpListener::bind(address)
            .await
            .with_context(|| format!("listening for metrics on {address}"))?;
        tracing::info!(%address, "serving metrics");
        // No graceful shutdown: the task ends with the runtime once the API
        // server has drained, and a scrape cut short loses nothing.
        tokio::spawn(async move {
            if let Err(e) = axum::serve(metrics_listener, http::metrics_router(metrics, pool)).await
            {
                tracing::error!(error = %e, "the metrics listener stopped");
            }
        });
    }
    tracing::info!(
        address = %config.listen,
        version = env!("CARGO_PKG_VERSION"),
        "listening"
    );
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
