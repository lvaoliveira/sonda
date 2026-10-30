//! Interface: what every API route shares: JSON errors and authorization.

use crate::http::State;
use crate::session;
use crate::users::User;
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
    /// A failed sign-in. One message for every cause, so nothing reveals
    /// whether the username exists.
    SignInFailed,
    /// Too many failed sign-ins for this username; the seconds to wait.
    TooManyAttempts(i64),
    /// Authenticated, but the request is not allowed as sent.
    Forbidden(String),
    NotFound,
    BadRequest(String),
    PayloadTooLarge(String),
    UnsupportedMediaType(String),
    /// Well-formed, but violates a rule (unknown rule id, hash mismatch, ...).
    Unprocessable(String),
    Internal(anyhow::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let retry_after = match self {
            Self::TooManyAttempts(secs) => Some(secs),
            _ => None,
        };
        let (status, message) = match self {
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "sign in or send the API token".into(),
            ),
            Self::SignInFailed => (
                StatusCode::UNAUTHORIZED,
                "invalid username or password".into(),
            ),
            Self::TooManyAttempts(secs) => (
                StatusCode::TOO_MANY_REQUESTS,
                format!(
                    "too many failed sign-ins; try again in {secs} {}",
                    if secs == 1 { "second" } else { "seconds" }
                ),
            ),
            Self::Forbidden(m) => (StatusCode::FORBIDDEN, m),
            Self::NotFound => (StatusCode::NOT_FOUND, "not found".into()),
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
        if let Some(secs) = retry_after {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, header::HeaderValue::from(secs));
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
#[derive(Debug, Clone)]
pub enum Caller {
    /// The API token, as a bearer header: `sonda upload`, scripts.
    Token,
    /// A signed-in user (see `session`).
    User(User),
    Anonymous,
}

impl Caller {
    /// For logs and the audit trail.
    pub fn name(&self) -> &str {
        match self {
            Caller::Token => "api-token",
            Caller::User(u) => &u.username,
            Caller::Anonymous => "anonymous",
        }
    }
}

pub async fn caller(state: &State, headers: &HeaderMap) -> Result<Caller, ApiError> {
    if bearer(headers).is_some_and(|t| state.token.matches(t)) {
        return Ok(Caller::Token);
    }
    if let Some(token) = session::from_headers(headers)
        && let Some(user) = session::user(&state.pool, token).await?
    {
        return Ok(Caller::User(user));
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
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let caller = caller(&state, request.headers()).await?;
    if state.reads_require_auth && matches!(caller, Caller::Anonymous) {
        return Err(ApiError::Unauthorized);
    }
    request.extensions_mut().insert(caller);
    Ok(next.run(request).await)
}

/// The header a browser session must add to every change. A cross-site
/// form or script cannot set it without a CORS preflight, which this server
/// never approves, so a session cookie alone can never make a change.
pub const CSRF_HEADER: &str = "sonda-csrf";

/// Middleware for changes made from the web app (triage): the token, or a
/// signed-in user plus `CSRF_HEADER`. Handlers get the `Caller` as an
/// extension, for the audit trail.
pub async fn require_write(
    axum::extract::State(state): axum::extract::State<State>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let caller = caller(&state, request.headers()).await?;
    check_write(&caller, request.headers())?;
    request.extensions_mut().insert(caller);
    Ok(next.run(request).await)
}

/// Middleware for user management: a signed-in admin, never the API token.
/// Changes also need `CSRF_HEADER`.
pub async fn require_admin(
    axum::extract::State(state): axum::extract::State<State>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let caller = caller(&state, request.headers()).await?;
    match &caller {
        Caller::User(u) if u.is_admin() => {}
        Caller::User(_) => return Err(ApiError::Forbidden("admins only".into())),
        Caller::Token => {
            return Err(ApiError::Forbidden(
                "the API token cannot manage users; sign in as an admin".into(),
            ));
        }
        Caller::Anonymous => return Err(ApiError::Unauthorized),
    }
    if request.method() != axum::http::Method::GET {
        check_write(&caller, request.headers())?;
    }
    request.extensions_mut().insert(caller);
    Ok(next.run(request).await)
}

fn check_write(caller: &Caller, headers: &HeaderMap) -> Result<(), ApiError> {
    match caller {
        Caller::Token => Ok(()),
        Caller::User(_) if headers.contains_key(CSRF_HEADER) => Ok(()),
        Caller::User(_) => Err(ApiError::Forbidden(format!(
            "missing the {CSRF_HEADER} header"
        ))),
        Caller::Anonymous => Err(ApiError::Unauthorized),
    }
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}
