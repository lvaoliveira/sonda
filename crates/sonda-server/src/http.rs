//! Interface: the HTTP routes. The API lives under `/api`; every other path
//! serves the web app, when one is configured.

use crate::api::{ApiError, Caller};
use crate::config::Token;
use crate::users::{self, User};
use crate::{api, db, drill, ingest, issues, overview, rules, session};
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
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
    /// True unless the server listens on loopback only (see `api::require_read`).
    pub reads_require_auth: bool,
}

pub fn router(state: State, web_dir: Option<&Path>) -> Router {
    let writes = Router::new()
        .route("/analyses", post(ingest::create))
        .layer(DefaultBodyLimit::max(ingest::MAX_BODY_BYTES))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            api::require_token,
        ));
    let reads = Router::new()
        .route("/rules", get(rules::list))
        .route("/overview", get(overview::get_overview))
        .route("/drill/{metric}", get(drill::get_drill))
        .route("/issues", get(issues::list_issues))
        .route("/issues/{id}", get(issues::get_issue))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            api::require_read,
        ));
    let triage = Router::new()
        .route("/issues/{id}", patch(issues::patch_issue))
        .layer(DefaultBodyLimit::max(4096))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            api::require_write,
        ));
    let account = Router::new()
        .route("/me/password", put(users::change_own_password))
        .layer(DefaultBodyLimit::max(4096))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            api::require_write,
        ));
    let admin = Router::new()
        .route("/users", get(users::list_users).post(users::create_user))
        .route("/users/{id}", patch(users::update_user))
        .layer(DefaultBodyLimit::max(4096))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            api::require_admin,
        ));
    let sessions = Router::new()
        .route(
            "/session",
            get(session_status).post(sign_in).delete(sign_out),
        )
        .layer(DefaultBodyLimit::max(4096));
    let api = Router::new()
        .route("/health", get(health))
        .merge(writes)
        .merge(reads)
        .merge(triage)
        .merge(account)
        .merge(admin)
        .merge(sessions)
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionStatus {
    /// The signed-in user; null when signed out, or for the API token.
    user: Option<User>,
    authenticated: bool,
    /// Whether the web app must sign in before it can read anything.
    reads_require_auth: bool,
}

async fn session_status(
    axum::extract::State(state): axum::extract::State<State>,
    headers: HeaderMap,
) -> Result<Json<SessionStatus>, ApiError> {
    let caller = api::caller(&state, &headers).await?;
    Ok(Json(SessionStatus {
        authenticated: !matches!(caller, Caller::Anonymous),
        user: match caller {
            Caller::User(u) => Some(u),
            _ => None,
        },
        reads_require_auth: state.reads_require_auth,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignIn {
    username: String,
    password: String,
}

/// Signs a user in with username and password (ADR-0006). Every failure,
/// unknown user, wrong password or disabled account, gets the same answer
/// after the same amount of hashing, so nothing reveals which usernames
/// exist.
async fn sign_in(
    axum::extract::State(state): axum::extract::State<State>,
    Json(body): Json<SignIn>,
) -> Result<Response, ApiError> {
    let found: Option<(i64, Option<String>, bool)> =
        sqlx::query_as("SELECT id, password_hash, disabled FROM users WHERE username = $1")
            .bind(body.username.trim().to_lowercase())
            .fetch_optional(&state.pool)
            .await?;
    let (id, stored, disabled) = match found {
        Some((id, hash, disabled)) => (Some(id), hash, disabled),
        None => (None, None, false),
    };
    let valid = users::verify_password(stored, body.password).await;
    let Some(id) = id.filter(|_| valid && !disabled) else {
        tracing::warn!("failed sign-in");
        return Err(ApiError::SignInFailed);
    };
    sqlx::query("UPDATE users SET last_login_at = now() WHERE id = $1")
        .bind(id)
        .execute(&state.pool)
        .await?;
    let token = session::create(&state.pool, id).await?;
    Ok((
        StatusCode::NO_CONTENT,
        [(header::SET_COOKIE, session::set_cookie(Some(&token)))],
    )
        .into_response())
}

async fn sign_out(
    axum::extract::State(state): axum::extract::State<State>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if let Some(token) = session::from_headers(&headers) {
        session::delete(&state.pool, token).await?;
    }
    Ok((
        StatusCode::NO_CONTENT,
        [(header::SET_COOKIE, session::set_cookie(None))],
    )
        .into_response())
}
