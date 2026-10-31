//! Users, passwords and the admin's user management (ADR-0006).

use crate::api::{ApiError, Caller};
use crate::http::State;
use axum::extract::{Extension, Path};
use axum::{Json, http::StatusCode};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::OnceLock;

/// Long passphrases beat composition rules (NIST SP 800-63B).
pub const MIN_PASSWORD_CHARS: usize = 12;
/// Hashing is deliberately slow: cap the input so a huge "password" cannot
/// tie up the server.
const MAX_PASSWORD_BYTES: usize = 1024;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub id: i64,
    pub username: String,
    pub display_name: String,
    /// `admin` or `member`.
    pub role: String,
    pub disabled: bool,
}

impl User {
    pub fn is_admin(&self) -> bool {
        self.role == "admin"
    }
}

/// Columns for `User`, over `users u`.
pub const USER_COLUMNS: &str = "u.id, u.username, u.display_name, u.role::text AS role, u.disabled";

// ------------------------------------------------------------- validation

pub fn check_username(username: &str) -> Result<(), String> {
    let ok = (2..=64).contains(&username.len())
        && username.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && username.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        });
    if ok {
        Ok(())
    } else {
        Err("username must be 2-64 lowercase letters, digits, '.', '_' or '-', starting with a letter or digit".into())
    }
}

pub fn check_password(password: &str) -> Result<(), String> {
    if password.chars().count() < MIN_PASSWORD_CHARS || password.len() > MAX_PASSWORD_BYTES {
        Err(format!(
            "password must have at least {MIN_PASSWORD_CHARS} characters"
        ))
    } else {
        Ok(())
    }
}

fn check_display_name(name: &str) -> Result<(), String> {
    let n = name.trim();
    if n.is_empty() || n.chars().count() > 100 || n.chars().any(char::is_control) {
        Err("display name must be 1-100 characters, without control characters".into())
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------- hashing

/// Argon2id with the crate's defaults, which are OWASP's (19 MiB, 2
/// iterations). Off the async workers: each hash takes tens of milliseconds.
pub async fn hash_password(password: String) -> Result<String, ApiError> {
    tokio::task::spawn_blocking(move || {
        use argon2::PasswordHasher;
        argon2::Argon2::default()
            .hash_password(password.as_bytes())
            .map(|h| h.to_string())
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("hashing a password: {e}")))
    })
    .await
    .map_err(|e| ApiError::Internal(e.into()))?
}

/// Whether `password` matches `stored`. With no stored hash (an unknown
/// user, or an SSO-only one), checks against a dummy hash anyway, so the
/// response takes as long and does not reveal which usernames exist.
pub async fn verify_password(stored: Option<String>, password: String) -> bool {
    let known = stored.is_some();
    let stored = stored.unwrap_or_else(|| dummy_hash().to_string());
    let matches = tokio::task::spawn_blocking(move || {
        use argon2::PasswordVerifier;
        argon2::PasswordHash::new(&stored).is_ok_and(|h| {
            argon2::Argon2::default()
                .verify_password(password.as_bytes(), &h)
                .is_ok()
        })
    })
    .await
    .unwrap_or(false);
    known && matches
}

fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| {
        use argon2::PasswordHasher;
        // Cannot fail: a fixed, valid input with default parameters.
        argon2::Argon2::default()
            .hash_password(b"no such user, never a valid password")
            .expect("hashing a constant")
            .to_string()
    })
}

// ------------------------------------------------------------ persistence

/// Admins have to be able to sign in: a passwordless admin would count as
/// the last active admin while nobody could act as it.
const NO_PASSWORD_ADMIN: &str =
    "a user without a password can't sign in, so it can't be an admin; set a password first";

/// Without a password, a service user: it can't sign in and only owns
/// tokens (such as CI's), so it must be a member.
pub async fn create(
    pool: &PgPool,
    username: &str,
    display_name: &str,
    role: &str,
    password: Option<&str>,
) -> Result<User, ApiError> {
    check_username(username).map_err(ApiError::Unprocessable)?;
    check_display_name(display_name).map_err(ApiError::Unprocessable)?;
    if !matches!(role, "admin" | "member") {
        return Err(ApiError::Unprocessable(
            "role must be admin or member".into(),
        ));
    }
    let hash = match password {
        Some(p) => {
            check_password(p).map_err(ApiError::Unprocessable)?;
            Some(hash_password(p.to_string()).await?)
        }
        None if role == "admin" => return Err(ApiError::Unprocessable(NO_PASSWORD_ADMIN.into())),
        None => None,
    };
    let sql = format!(
        "WITH u AS (INSERT INTO users (username, display_name, role, password_hash)
                    VALUES ($1, $2, $3::user_role, $4) ON CONFLICT (username) DO NOTHING RETURNING *)
         SELECT {USER_COLUMNS} FROM u"
    );
    sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(username)
        .bind(display_name.trim())
        .bind(role)
        .bind(hash)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| ApiError::Unprocessable(format!("username {username:?} is taken")))
}

/// Creates the first admin when no users exist (ADR-0006). Once any user
/// exists this does nothing, so the secret never resets a password.
pub async fn bootstrap_admin(pool: &PgPool, admin: Option<(String, String)>) -> anyhow::Result<()> {
    let users: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(pool)
        .await?;
    match (users, admin) {
        (0, Some((username, password))) => {
            create(pool, &username, "Administrator", "admin", Some(&password))
                .await
                .map_err(|e| anyhow::anyhow!("creating the first admin: {e:?}"))?;
            tracing::info!(username = %username, "created the first admin");
        }
        (0, None) => tracing::warn!(
            "no users yet: set SONDA_ADMIN_PASSWORD_FILE (or SONDA_ADMIN_PASSWORD) to create the first admin"
        ),
        _ => {}
    }
    Ok(())
}

// ---------------------------------------------------------------- handlers

pub async fn list_users(
    axum::extract::State(state): axum::extract::State<State>,
) -> Result<Json<Vec<UserRow>>, ApiError> {
    let sql = format!(
        "SELECT {USER_COLUMNS}, u.password_hash IS NOT NULL AS has_password,
                to_char(u.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS created_at,
                to_char(u.last_login_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS last_login_at
         FROM users u ORDER BY u.username"
    );
    Ok(Json(
        sqlx::query_as(sqlx::AssertSqlSafe(sql))
            .fetch_all(&state.pool)
            .await?,
    ))
}

/// A user as admins see it.
#[derive(Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct UserRow {
    #[sqlx(flatten)]
    #[serde(flatten)]
    pub user: User,
    pub has_password: bool,
    pub created_at: String,
    pub last_login_at: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NewUser {
    username: String,
    display_name: String,
    role: String,
    /// None for a service user, which can't sign in.
    #[serde(default)]
    password: Option<String>,
}

pub async fn create_user(
    axum::extract::State(state): axum::extract::State<State>,
    Extension(caller): Extension<Caller>,
    Json(new): Json<NewUser>,
) -> Result<(StatusCode, Json<User>), ApiError> {
    let user = create(
        &state.pool,
        &new.username,
        &new.display_name,
        &new.role,
        new.password.as_deref(),
    )
    .await?;
    tracing::info!(by = caller.name(), username = %user.username, role = %user.role, "created user");
    Ok((StatusCode::CREATED, Json(user)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UserPatch {
    display_name: Option<String>,
    role: Option<String>,
    disabled: Option<bool>,
    /// An admin's password reset.
    password: Option<String>,
}

pub async fn update_user(
    axum::extract::State(state): axum::extract::State<State>,
    Extension(caller): Extension<Caller>,
    Path(id): Path<i64>,
    Json(patch): Json<UserPatch>,
) -> Result<Json<User>, ApiError> {
    if let Some(name) = &patch.display_name {
        check_display_name(name).map_err(ApiError::Unprocessable)?;
    }
    if let Some(role) = &patch.role
        && !matches!(role.as_str(), "admin" | "member")
    {
        return Err(ApiError::Unprocessable(
            "role must be admin or member".into(),
        ));
    }
    let hash = match patch.password {
        Some(p) => {
            check_password(&p).map_err(ApiError::Unprocessable)?;
            Some(hash_password(p).await?)
        }
        None => None,
    };

    let mut tx = state.pool.begin().await?;
    // Lock every active admin, so two requests cannot each remove "the
    // other" last admin at the same time.
    let admins: Vec<i64> = sqlx::query_scalar(
        "SELECT id FROM users WHERE role = 'admin' AND NOT disabled ORDER BY id FOR UPDATE",
    )
    .fetch_all(&mut *tx)
    .await?;
    let stays_admin =
        patch.role.as_deref().is_none_or(|r| r == "admin") && patch.disabled != Some(true);
    if admins == [id] && !stays_admin {
        return Err(ApiError::Unprocessable(
            "the last active admin cannot be disabled or made a member".into(),
        ));
    }
    if patch.role.as_deref() == Some("admin") && hash.is_none() {
        let has_password: Option<bool> =
            sqlx::query_scalar("SELECT password_hash IS NOT NULL FROM users WHERE id = $1")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
        if has_password == Some(false) {
            return Err(ApiError::Unprocessable(NO_PASSWORD_ADMIN.into()));
        }
    }
    let sql = format!(
        "WITH u AS (
            UPDATE users SET
                display_name = coalesce($2, display_name),
                role = coalesce($3::user_role, role),
                disabled = coalesce($4, disabled),
                password_hash = coalesce($5, password_hash)
            WHERE id = $1 RETURNING *)
         SELECT {USER_COLUMNS} FROM u"
    );
    let user: User = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(id)
        .bind(patch.display_name.as_deref().map(str::trim))
        .bind(&patch.role)
        .bind(patch.disabled)
        .bind(&hash)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    // A disabled user, or one whose password was reset, is signed out
    // everywhere.
    if user.disabled || hash.is_some() {
        sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    tracing::info!(by = caller.name(), username = %user.username, "updated user");
    Ok(Json(user))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PasswordChange {
    current: String,
    new: String,
}

/// Changes the signed-in user's own password, which needs the current one,
/// and ends their other sessions.
pub async fn change_own_password(
    axum::extract::State(state): axum::extract::State<State>,
    Extension(caller): Extension<Caller>,
    headers: axum::http::HeaderMap,
    Json(change): Json<PasswordChange>,
) -> Result<StatusCode, ApiError> {
    let Caller::User(user) = caller else {
        return Err(ApiError::Forbidden(
            "the API token has no password; sign in as a user".into(),
        ));
    };
    check_password(&change.new).map_err(ApiError::Unprocessable)?;
    let stored: Option<String> =
        sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
            .bind(user.id)
            .fetch_one(&state.pool)
            .await?;
    if !verify_password(stored, change.current).await {
        return Err(ApiError::Forbidden("the current password is wrong".into()));
    }
    let hash = hash_password(change.new).await?;
    let mut tx = state.pool.begin().await?;
    sqlx::query("UPDATE users SET password_hash = $2 WHERE id = $1")
        .bind(user.id)
        .bind(hash)
        .execute(&mut *tx)
        .await?;
    let keep = crate::session::from_headers(&headers).map(crate::session::hash);
    sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND token_sha256 IS DISTINCT FROM $2")
        .bind(user.id)
        .bind(keep)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usernames_and_passwords_are_validated() {
        for ok in ["admin", "ann.lee", "a1", "x_y-z"] {
            assert!(check_username(ok).is_ok(), "{ok}");
        }
        for bad in [
            "A",
            "a",
            "Admin",
            ".x",
            "-x",
            "a b",
            "ann@lee",
            &"a".repeat(65),
        ] {
            assert!(check_username(bad).is_err(), "{bad}");
        }
        assert!(check_password("short").is_err());
        assert!(check_password("twelve chars").is_ok());
        assert!(check_password(&"x".repeat(2000)).is_err());
    }

    #[tokio::test]
    async fn passwords_hash_with_argon2id_and_verify() {
        let hash = hash_password("correct horse battery".into()).await.unwrap();
        assert!(hash.starts_with("$argon2id$"), "{hash}");
        assert!(verify_password(Some(hash.clone()), "correct horse battery".into()).await);
        assert!(!verify_password(Some(hash), "wrong horse battery".into()).await);
        // Unknown users never match, but still cost a hash.
        assert!(!verify_password(None, "no such user, never a valid password".into()).await);
    }
}
