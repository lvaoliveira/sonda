//! Sign-in throttling (ADR-0006). Failed attempts are counted per
//! normalized username, whether or not that user exists, so throttling
//! never reveals which usernames are real. After `FREE_FAILURES` in a
//! window, each further failure doubles a wait, capped at `MAX_DELAY`.
//! Waits, not lockouts: an attacker can slow a real user down, but not lock
//! them out for long. Kept in PostgreSQL, so restarts and multiple server
//! instances don't reset it.

use sqlx::PgPool;

/// Failures allowed within `WINDOW_SECS` before waits start.
pub const FREE_FAILURES: i32 = 5;
pub const WINDOW_SECS: i64 = 15 * 60;
/// The longest wait, in seconds.
pub const MAX_DELAY_SECS: i64 = 15 * 60;

/// The key failures are counted under: what sign-in looks users up by,
/// bounded in length.
pub fn key(username: &str) -> String {
    username.trim().to_lowercase().chars().take(256).collect()
}

/// The wait after `failures` failures in the window: none for the first
/// `FREE_FAILURES`, then 1, 2, 4, ... seconds, capped at `MAX_DELAY_SECS`.
pub fn delay_secs(failures: i32) -> i64 {
    let over = failures - FREE_FAILURES;
    if over <= 0 {
        0
    } else {
        // `over - 1` is at most 2^31: shifting by 20+ already exceeds the cap.
        (1i64 << (over - 1).min(20)).min(MAX_DELAY_SECS)
    }
}

/// Seconds `key` must still wait, if it is throttled.
pub async fn blocked_for(pool: &PgPool, key: &str) -> Result<Option<i64>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT ceil(extract(epoch FROM blocked_until - now()))::bigint
         FROM sign_in_failures WHERE username = $1 AND blocked_until > now()",
    )
    .bind(key)
    .fetch_optional(pool)
    .await
}

/// Counts a failure for `key`, starting a new window if the last one has
/// expired, and sets the wait the count calls for.
pub async fn record_failure(pool: &PgPool, key: &str) -> Result<(), sqlx::Error> {
    // Old entries go first, so the table stays small.
    sqlx::query(
        "DELETE FROM sign_in_failures
         WHERE first_at < now() - interval '1 day' AND coalesce(blocked_until, now()) <= now()",
    )
    .execute(pool)
    .await?;
    let failures: i32 = sqlx::query_scalar(
        "INSERT INTO sign_in_failures (username, failures, first_at) VALUES ($1, 1, now())
         ON CONFLICT (username) DO UPDATE SET
             failures = CASE WHEN sign_in_failures.first_at < now() - make_interval(secs => $2)
                             THEN 1 ELSE sign_in_failures.failures + 1 END,
             first_at = CASE WHEN sign_in_failures.first_at < now() - make_interval(secs => $2)
                             THEN now() ELSE sign_in_failures.first_at END
         RETURNING failures",
    )
    .bind(key)
    .bind(WINDOW_SECS as f64)
    .fetch_one(pool)
    .await?;
    let delay = delay_secs(failures);
    if delay > 0 {
        sqlx::query("UPDATE sign_in_failures SET blocked_until = now() + make_interval(secs => $2) WHERE username = $1")
            .bind(key)
            .bind(delay as f64)
            .execute(pool)
            .await?;
    }
    Ok(())
}

/// Forgets `key`'s failures, after a successful sign-in.
pub async fn clear(pool: &PgPool, key: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM sign_in_failures WHERE username = $1")
        .bind(key)
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waits_start_after_the_free_failures_and_double_up_to_the_cap() {
        let delays: Vec<i64> = (1..=12).map(delay_secs).collect();
        assert_eq!(delays, [0, 0, 0, 0, 0, 1, 2, 4, 8, 16, 32, 64]);
        assert_eq!(delay_secs(40), MAX_DELAY_SECS);
        assert_eq!(delay_secs(i32::MAX), MAX_DELAY_SECS);
    }

    #[test]
    fn keys_match_how_sign_in_looks_users_up() {
        assert_eq!(key("  Ann "), "ann");
        assert_eq!(key(&"x".repeat(1000)).len(), 256);
    }
}
