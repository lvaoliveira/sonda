//! Interface: the HTTP routes. The API lives under `/api`; every other path
//! serves the web app, when one is configured.

use crate::config::Token;
use crate::{api, db, ingest};
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::StatusCode;
use axum::middleware;
use axum::routing::{get, post};
use serde_json::{Value, json};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::timeout::TimeoutLayer;

#[derive(Clone)]
pub struct State {
    pub pool: sqlx::PgPool,
    pub token: Arc<Token>,
}

pub fn router(state: State, web_dir: Option<&Path>) -> Router {
    let writes = Router::new()
        .route("/analyses", post(ingest::create))
        .layer(DefaultBodyLimit::max(ingest::MAX_BODY_BYTES))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            api::require_token,
        ));
    let api = Router::new()
        .route("/health", get(health))
        .merge(writes)
        // An unknown API path is a 404, never the web app's index.html.
        .fallback(|| async {
            (
                StatusCode::NOT_FOUND,
                axum::Json(json!({ "error": "not found" })),
            )
        })
        .with_state(state);
    let api = Router::new().nest("/api", api);
    let app = match web_dir {
        // Client-side routes (/issues, /rules, ...) all load index.html.
        Some(dir) => api
            .fallback_service(ServeDir::new(dir).fallback(ServeFile::new(dir.join("index.html")))),
        None => api,
    };
    app.layer(TimeoutLayer::with_status_code(
        StatusCode::REQUEST_TIMEOUT,
        Duration::from_secs(30),
    ))
}

/// For load balancers and `docker compose`: 200 when the database answers.
/// Unauthenticated, and says nothing beyond up or down.
async fn health(
    axum::extract::State(state): axum::extract::State<State>,
) -> (StatusCode, axum::Json<Value>) {
    if db::ping(&state.pool, Duration::from_secs(2)).await {
        (StatusCode::OK, axum::Json(json!({ "status": "ok" })))
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(json!({ "status": "database unavailable" })),
        )
    }
}
