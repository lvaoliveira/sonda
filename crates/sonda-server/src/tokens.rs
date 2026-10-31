//! User and analysis tokens (ADR-0012), as in SonarQube. Each belongs to the
//! user who generated it and never has more rights than that user:
//!
//! - a **user token** (`sonda_u_`) acts as its owner, uploads included;
//! - a **project analysis token** (`sonda_p_`) uploads one project;
//! - a **global analysis token** (`sonda_a_`) uploads any project.
//!
//! Secrets are shown once and stored as SHA-256: they're 256 random bits,
//! so a slow hash adds nothing.

use crate::api::{ApiError, Caller};
use crate::health::rfc3339;
use crate::http::State;
use crate::users::{USER_COLUMNS, User};
use axum::Json;
use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;

/// Every token starts with this, then its type's letter.
const PREFIX: &str = "sonda_";

/// How many leading characters identify a token in lists.
const SHOWN_PREFIX: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    User,
    ProjectAnalysis,
    GlobalAnalysis,
}

impl TokenType {
    fn as_str(self) -> &'static str {
        match self {
            TokenType::User => "user",
            TokenType::ProjectAnalysis => "project_analysis",
            TokenType::GlobalAnalysis => "global_analysis",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        [Self::User, Self::ProjectAnalysis, Self::GlobalAnalysis]
            .into_iter()
            .find(|t| t.as_str() == s)
    }

    fn prefix(self) -> &'static str {
        match self {
            TokenType::User => "sonda_u_",
            TokenType::ProjectAnalysis => "sonda_p_",
            TokenType::GlobalAnalysis => "sonda_a_",
        }
    }

    /// Analysis tokens only upload.
    pub fn analysis_only(self) -> bool {
        self != TokenType::User
    }
}

/// The token a request came with, once checked.
#[derive(Debug, Clone)]
pub struct TokenRef {
    pub id: i64,
    pub name: String,
    pub kind: TokenType,
    /// The one project a project analysis token uploads.
    pub project: Option<String>,
}

/// The owner and the token, if `presented` is a token that works now: not
/// revoked, not expired, and its owner not disabled.
pub async fn authenticate(
    pool: &PgPool,
    presented: &str,
) -> Result<Option<(User, TokenRef)>, sqlx::Error> {
    if !presented.starts_with(PREFIX) {
        return Ok(None);
    }
    let hash: Vec<u8> = Sha256::digest(presented.as_bytes()).to_vec();
    let found: Option<(i64, String, String, Option<String>, i64)> = sqlx::query_as(
        "SELECT t.id, t.name, t.type, t.project_key, t.user_id FROM api_tokens t
         JOIN users u ON u.id = t.user_id
         WHERE t.hash = $1 AND t.revoked_at IS NULL
           AND (t.expires_at IS NULL OR t.expires_at > now()) AND NOT u.disabled",
    )
    .bind(&hash)
    .fetch_optional(pool)
    .await?;
    let Some((id, name, kind, project, user_id)) = found else {
        return Ok(None);
    };
    let Some(kind) = TokenType::parse(&kind) else {
        return Ok(None);
    };
    let user: User = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {USER_COLUMNS} FROM users u WHERE u.id = $1"
    )))
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    // At most once a minute, so requests don't each write the row.
    sqlx::query(
        "UPDATE api_tokens SET last_used_at = now()
         WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute')",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(Some((
        user,
        TokenRef {
            id,
            name,
            kind,
            project,
        },
    )))
}

/// A new secret: the type's prefix and 32 random bytes, base32-encoded
/// (lowercase, no padding), so secret scanners can recognize it.
fn generate(kind: TokenType) -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("the operating system's random source");
    format!("{}{}", kind.prefix(), base32(&bytes))
}

/// RFC 4648 base32, lowercase, without padding.
fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &b in bytes {
        buffer = (buffer << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[((buffer >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(ALPHABET[((buffer << (5 - bits)) & 31) as usize]));
    }
    out
}

/// A token as lists show it: never its secret.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenView {
    pub id: i64,
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub project: Option<String>,
    /// The secret's first characters.
    pub prefix: String,
    /// The user who generated it.
    pub owner: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
    pub revoked_at: Option<String>,
    pub revoked_by: Option<String>,
    /// `active`, `expired` or `revoked`.
    pub status: &'static str,
}

/// (view, created, expires, last used, revoked) in epoch seconds.
type TokenRow = (
    i64,
    String,
    String,
    Option<String>,
    String,
    String,
    f64,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<String>,
    f64,
);

const TOKEN_COLUMNS: &str = "t.id, t.name, t.type, t.project_key, t.prefix, u.username,
    extract(epoch FROM t.created_at)::float8, extract(epoch FROM t.expires_at)::float8,
    extract(epoch FROM t.last_used_at)::float8, extract(epoch FROM t.revoked_at)::float8,
    t.revoked_by, extract(epoch FROM now())::float8";

fn view(row: TokenRow) -> TokenView {
    let (id, name, kind, project, prefix, owner, created, expires, used, revoked, by, now) = row;
    TokenView {
        id,
        name,
        kind,
        project,
        prefix,
        owner,
        created_at: rfc3339(created),
        expires_at: expires.map(rfc3339),
        last_used_at: used.map(rfc3339),
        revoked_at: revoked.map(rfc3339),
        revoked_by: by,
        status: match (revoked, expires) {
            (Some(_), _) => "revoked",
            (None, Some(e)) if e <= now => "expired",
            _ => "active",
        },
    }
}

/// Tokens, newest first: one user's, or everyone's.
async fn list(pool: &PgPool, user: Option<i64>) -> Result<Vec<TokenView>, sqlx::Error> {
    let rows: Vec<TokenRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {TOKEN_COLUMNS} FROM api_tokens t JOIN users u ON u.id = t.user_id
         WHERE $1::bigint IS NULL OR t.user_id = $1 ORDER BY t.id DESC"
    )))
    .bind(user)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(view).collect())
}

/// The signed-in user; token management needs a session (`require_session`).
fn session_user(caller: &Caller) -> Result<&User, ApiError> {
    match caller {
        Caller::User(u) => Ok(u),
        _ => Err(ApiError::Forbidden("sign in to manage tokens".into())),
    }
}

/// `GET /api/me/tokens`: your tokens, revoked and expired ones included.
pub async fn list_mine(
    axum::extract::State(state): axum::extract::State<State>,
    Extension(caller): Extension<Caller>,
) -> Result<Json<Vec<TokenView>>, ApiError> {
    let user = session_user(&caller)?;
    Ok(Json(list(&state.pool, Some(user.id)).await?))
}

/// `GET /api/tokens`: every user's tokens, for admins.
pub async fn list_all(
    axum::extract::State(state): axum::extract::State<State>,
) -> Result<Json<Vec<TokenView>>, ApiError> {
    Ok(Json(list(&state.pool, None).await?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NewToken {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    project: Option<String>,
    /// 30, 60 or 90; null for no expiry.
    expires_in_days: Option<u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Created {
    /// The secret, shown this once.
    token: String,
    #[serde(flatten)]
    view: TokenView,
}

/// `POST /api/me/tokens`: generates a token for yourself.
pub async fn create(
    axum::extract::State(state): axum::extract::State<State>,
    Extension(caller): Extension<Caller>,
    Json(new): Json<NewToken>,
) -> Result<(StatusCode, Json<Created>), ApiError> {
    let user = session_user(&caller)?;
    let invalid = |m: &str| ApiError::Unprocessable(m.into());
    let name = new.name.trim();
    if name.is_empty() || name.chars().count() > 100 || name.chars().any(char::is_control) {
        return Err(invalid(
            "a token's name has 1-100 characters, no control characters",
        ));
    }
    let kind = TokenType::parse(&new.kind)
        .ok_or_else(|| invalid("type is user, project_analysis or global_analysis"))?;
    let project = match (kind, new.project.as_deref().map(str::trim)) {
        (TokenType::ProjectAnalysis, Some(p)) => {
            sonda_core::upload::check_project_key(p)
                .map_err(|e| ApiError::Unprocessable(e.to_string()))?;
            Some(p.to_string())
        }
        (TokenType::ProjectAnalysis, None) => {
            return Err(invalid("a project analysis token needs a project"));
        }
        (_, Some(_)) => return Err(invalid("only project analysis tokens have a project")),
        (_, None) => None,
    };
    if !matches!(new.expires_in_days, None | Some(30 | 60 | 90)) {
        return Err(invalid("expiresInDays is 30, 60, 90 or null (no expiry)"));
    }

    let secret = generate(kind);
    let hash: Vec<u8> = Sha256::digest(secret.as_bytes()).to_vec();
    let inserted: Result<i64, sqlx::Error> = sqlx::query_scalar(
        "INSERT INTO api_tokens (user_id, type, project_key, name, hash, prefix, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, now() + make_interval(days => $7))
         RETURNING id",
    )
    .bind(user.id)
    .bind(kind.as_str())
    .bind(&project)
    .bind(name)
    .bind(&hash)
    .bind(&secret[..SHOWN_PREFIX])
    .bind(new.expires_in_days.map(|d| d as i32))
    .fetch_one(&state.pool)
    .await;
    let id = match inserted {
        Ok(id) => id,
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(invalid("you already have a token with this name"));
        }
        Err(e) => return Err(e.into()),
    };
    tracing::info!(by = %user.username, id, kind = kind.as_str(), "generated a token");
    let view = list(&state.pool, Some(user.id))
        .await?
        .into_iter()
        .find(|t| t.id == id)
        .ok_or(ApiError::NotFound)?;
    Ok((
        StatusCode::CREATED,
        Json(Created {
            token: secret,
            view,
        }),
    ))
}

/// `DELETE /api/me/tokens/{id}`: revokes one of your tokens.
pub async fn revoke_mine(
    axum::extract::State(state): axum::extract::State<State>,
    Extension(caller): Extension<Caller>,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let user = session_user(&caller)?;
    revoke(&state.pool, id, Some(user.id), &user.username).await
}

/// `DELETE /api/tokens/{id}`: revokes anyone's token, for admins.
pub async fn revoke_any(
    axum::extract::State(state): axum::extract::State<State>,
    Extension(caller): Extension<Caller>,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    revoke(&state.pool, id, None, &caller.name()).await
}

/// Revoking is final; revoking a revoked token changes nothing.
async fn revoke(
    pool: &PgPool,
    id: i64,
    owner: Option<i64>,
    by: &str,
) -> Result<StatusCode, ApiError> {
    let found: Option<bool> = sqlx::query_scalar(
        "SELECT revoked_at IS NOT NULL FROM api_tokens
         WHERE id = $1 AND ($2::bigint IS NULL OR user_id = $2)",
    )
    .bind(id)
    .bind(owner)
    .fetch_optional(pool)
    .await?;
    match found {
        None => Err(ApiError::NotFound),
        Some(true) => Ok(StatusCode::NO_CONTENT),
        Some(false) => {
            sqlx::query("UPDATE api_tokens SET revoked_at = now(), revoked_by = $2 WHERE id = $1")
                .bind(id)
                .bind(by)
                .execute(pool)
                .await?;
            tracing::info!(by, id, "revoked a token");
            Ok(StatusCode::NO_CONTENT)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_matches_rfc_4648() {
        // RFC 4648's test vectors, lowercase and without padding.
        let cases = [
            ("", ""),
            ("f", "my"),
            ("fo", "mzxq"),
            ("foo", "mzxw6"),
            ("foob", "mzxw6yq"),
            ("fooba", "mzxw6ytb"),
            ("foobar", "mzxw6ytboi"),
        ];
        for (input, expected) in cases {
            assert_eq!(base32(input.as_bytes()), expected, "{input:?}");
        }
    }

    #[test]
    fn secrets_carry_their_type_and_256_random_bits() {
        let a = generate(TokenType::ProjectAnalysis);
        let b = generate(TokenType::ProjectAnalysis);
        assert!(a.starts_with("sonda_p_"));
        assert_eq!(a.len(), "sonda_p_".len() + 52);
        assert_ne!(a, b);
        assert!(generate(TokenType::User).starts_with("sonda_u_"));
        assert!(generate(TokenType::GlobalAnalysis).starts_with("sonda_a_"));
    }
}
