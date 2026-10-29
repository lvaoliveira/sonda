//! Interface: what every API route shares: JSON errors and authorization.

use crate::http::State;
use crate::session;
use axum::Json;
use axum::extract::Request;
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// An API failure. Its message is shown to the client, so it describes
/// only what the client sent; internal errors are logged, not returned.
#[derive(Debug)]
pub enum ApiError {
    Unauthorized,
    BadRequest(String),
    PayloadTooLarge(String),
    UnsupportedMediaType(String),
    /// Well-formed, but violates a rule (unknown rule id, hash mismatch, ...).
    Unprocessable(String),
    Internal(anyhow::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "missing or invalid token".into()),
            Self::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            Self::PayloadTooLarge(m) => (StatusCode::PAYLOAD_TOO_LARGE, m),
            Self::UnsupportedMediaType(m) => (StatusCode::UNSUPPORTED_MEDIA_TYPE, m),
            Self::Unprocessable(m) => (StatusCode::UNPROCESSABLE_ENTITY, m),
            Self::Internal(e) => {
                tracing::error!(error = format!("{e:#}"), "internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
            }
        };
        let mut response = (status, Json(json!({ "error": message }))).into_response();
        if status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                header::HeaderValue::from_static("Bearer"),
            );
        }
        response
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        Self::Internal(e.into())
    }
}

/// Who is calling, as far as the API cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Caller {
    /// The API token, as a bearer header: `sonda upload`, scripts.
    Token,
    /// A browser signed in with the token (see `session`).
    Session,
    Anonymous,
}

pub async fn caller(state: &State, headers: &HeaderMap) -> Result<Caller, ApiError> {
    if bearer(headers).is_some_and(|t| state.token.matches(t)) {
        return Ok(Caller::Token);
    }
    if let Some(token) = session::from_headers(headers)
        && session::is_valid(&state.pool, token).await?
    {
        return Ok(Caller::Session);
    }
    Ok(Caller::Anonymous)
}

/// Middleware for routes that need the API token. It runs before the body
/// is read, so an unauthenticated client cannot make the server buffer an
/// upload.
pub async fn require_token(
    axum::extract::State(state): axum::extract::State<State>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    if bearer(request.headers()).is_some_and(|t| state.token.matches(t)) {
        Ok(next.run(request).await)
    } else {
        Err(ApiError::Unauthorized)
    }
}

/// Middleware for reads. Anyone may read while the server listens on
/// loopback only; otherwise reads need the token or a session, because the
/// server holds source code.
pub async fn require_read(
    axum::extract::State(state): axum::extract::State<State>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    if state.reads_require_auth && caller(&state, request.headers()).await? == Caller::Anonymous {
        return Err(ApiError::Unauthorized);
    }
    Ok(next.run(request).await)
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}
