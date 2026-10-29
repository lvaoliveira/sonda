//! Browser sessions: signing in with the API token sets a session cookie, so
//! the web app never holds the token itself (ADR-0005).

use axum::http::{HeaderMap, HeaderValue, header};
use sha2::{Digest, Sha256};
use sqlx::PgPool;

/// `__Host-` makes browsers reject the cookie unless it is `Secure`, has
/// `Path=/` and no `Domain`, so no other site or subdomain can set or read
/// it. (Browsers treat http://localhost as secure.)
pub const COOKIE: &str = "__Host-sonda_session";
/// Sessions end after 12 hours, signed in or not; there is no refresh.
pub const LIFETIME_SECS: i64 = 12 * 60 * 60;

/// Starts a session and returns its token, which only the cookie holds.
pub async fn create(pool: &PgPool) -> Result<String, sqlx::Error> {
    let mut bytes = [0u8; 32];
    // The OS random source; failing it is not recoverable.
    getrandom::fill(&mut bytes).expect("the operating system's random source");
    let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    sqlx::query("DELETE FROM sessions WHERE expires_at < now()")
        .execute(pool)
        .await?;
    sqlx::query(
        "INSERT INTO sessions (token_sha256, expires_at)
         VALUES ($1, now() + make_interval(secs => $2))",
    )
    .bind(hash(&token))
    .bind(LIFETIME_SECS as f64)
    .execute(pool)
    .await?;
    Ok(token)
}

pub async fn is_valid(pool: &PgPool, token: &str) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM sessions WHERE token_sha256 = $1 AND expires_at > now())",
    )
    .bind(hash(token))
    .fetch_one(pool)
    .await
}

pub async fn delete(pool: &PgPool, token: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM sessions WHERE token_sha256 = $1")
        .bind(hash(token))
        .execute(pool)
        .await?;
    Ok(())
}

/// The session token from the request's cookies, if one is well formed.
pub fn from_headers(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|pair| pair.trim().strip_prefix(COOKIE)?.strip_prefix('='))
        .filter(|t| t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// `Set-Cookie` for `token`, or one that clears the cookie.
pub fn set_cookie(token: Option<&str>) -> HeaderValue {
    let (value, max_age) = match token {
        Some(t) => (t, LIFETIME_SECS),
        None => ("", 0),
    };
    let cookie =
        format!("{COOKIE}={value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={max_age}");
    // Cannot fail: hex digits and fixed ASCII.
    HeaderValue::from_str(&cookie).expect("valid header value")
}

fn hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_well_formed_session_cookie_is_read() {
        let token = "ab".repeat(32);
        let mut headers = HeaderMap::new();
        let cookie = format!("theme=dark; {COOKIE}={token}; other=1");
        headers.insert(header::COOKIE, cookie.parse().unwrap());
        assert_eq!(from_headers(&headers), Some(token.as_str()));
        for bad in ["x", "'; DROP TABLE sessions; --", &"zz".repeat(32)] {
            let mut headers = HeaderMap::new();
            headers.insert(header::COOKIE, format!("{COOKIE}={bad}").parse().unwrap());
            assert_eq!(from_headers(&headers), None, "{bad}");
        }
        // A look-alike name is not the session cookie.
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!("{COOKIE}x={token}").parse().unwrap(),
        );
        assert_eq!(from_headers(&headers), None);
    }

    #[test]
    fn the_cookie_is_locked_down() {
        let set = set_cookie(Some(&"ab".repeat(32)));
        let set = set.to_str().unwrap();
        for attribute in [
            "__Host-",
            "Path=/",
            "HttpOnly",
            "Secure",
            "SameSite=Strict",
            "Max-Age=43200",
        ] {
            assert!(set.contains(attribute), "{set}");
        }
        assert!(set_cookie(None).to_str().unwrap().contains("Max-Age=0"));
    }
}
