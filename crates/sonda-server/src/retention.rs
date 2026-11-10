//! Retention (docs/release-1.0.md, M2): branch analyses older than a number
//! of days are thinned to one a day, so storage stops growing with every CI
//! run while the history stays readable. SonarQube's housekeeping does the
//! same, with more tiers.
//!
//! Always kept, whatever their age, because other things point at them:
//! - a branch's first analysis (the baseline its issues are measured from)
//!   and its latest;
//! - the last analysis of each day (UTC);
//! - the analysis that starts the new code period: the admin's choice, and
//!   the first of each project version;
//! - those a reset of the new code period names.
//!
//! The issues keep their triage. An issue records the analyses that first
//! and last saw it, and the one that found it fixed; when one of those is
//! thinned away the record moves to the nearest analysis that stays (the
//! next one for "first" and "fixed", the previous one for "last"), so
//! nothing is deleted with its analysis. Pull requests have their own
//! cleanup, and aren't touched here.

use sqlx::{PgPool, Postgres, Transaction};
use std::time::Duration;

/// How often the server looks for analyses to thin.
pub const INTERVAL: Duration = Duration::from_secs(3600);

/// The analyses to thin: older than `$1` days, not one of those listed
/// above. `$2` and `$3` narrow it to one branch of one project, or both
/// null for all; the windows see a whole branch either way.
const THINNED: &str = "
    WITH a AS (
        SELECT id, project_id, branch, received_at, project_version,
               lag(project_version) OVER w AS previous_version,
               id = max(id) OVER branch AS is_latest,
               id = min(id) OVER branch AS is_first,
               id = max(id) OVER (PARTITION BY project_id, branch,
                                  (received_at AT TIME ZONE 'UTC')::date) AS ends_its_day
        FROM analyses
        WHERE pull_request IS NULL AND ($2::bigint IS NULL OR project_id = $2)
          AND ($3::text IS NULL OR branch = $3)
        WINDOW w AS (PARTITION BY project_id, branch ORDER BY id),
               branch AS (PARTITION BY project_id, branch))
    SELECT id, project_id, branch FROM a
    WHERE received_at < now() - make_interval(days => $1)
      AND NOT is_latest AND NOT is_first AND NOT ends_its_day
      AND NOT (project_version IS NOT NULL AND project_version IS DISTINCT FROM previous_version)
      AND id NOT IN (SELECT new_code_since FROM projects WHERE new_code_since IS NOT NULL
                     UNION SELECT old_since FROM new_code_resets WHERE old_since IS NOT NULL
                     UNION SELECT new_since FROM new_code_resets WHERE new_since IS NOT NULL)
    ORDER BY id";

/// Thins every branch's analyses older than `days` days. Returns how many
/// analyses went.
pub async fn thin(pool: &PgPool, days: i32) -> sqlx::Result<usize> {
    let branches: Vec<(i64, String)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT DISTINCT project_id, branch FROM ({THINNED}) t"
    )))
    .bind(days)
    .bind(None::<i64>)
    .bind(None::<String>)
    .fetch_all(pool)
    .await?;
    let mut removed = 0;
    for (project, branch) in branches {
        removed += thin_branch(pool, days, project, &branch).await?;
    }
    Ok(removed)
}

async fn thin_branch(pool: &PgPool, days: i32, project: i64, branch: &str) -> sqlx::Result<usize> {
    let mut tx = pool.begin().await?;
    // The lock an upload to the branch takes (store::ingest), so one arriving
    // now lands before this or after it, never in between.
    crate::store::lock_branch(&mut tx, project, branch).await?;
    // Chosen under the lock, so what's thinned is what's there now.
    let thinned: Vec<i64> =
        sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT id FROM ({THINNED}) t")))
            .bind(days)
            .bind(project)
            .bind(branch)
            .fetch_all(&mut *tx)
            .await?;
    if thinned.is_empty() {
        return Ok(0);
    }
    repoint_issues(&mut tx, project, branch, &thinned).await?;
    let contents: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT DISTINCT sha256 FROM analysis_files WHERE analysis_id = ANY($1)",
    )
    .bind(&thinned)
    .fetch_all(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM analyses WHERE id = ANY($1)")
        .bind(&thinned)
        .execute(&mut *tx)
        .await?;
    crate::deleted_projects::remove_unused_sources(&mut tx, &contents).await?;
    tx.commit().await?;
    Ok(thinned.len())
}

/// Moves what the branch's issues record off the analyses about to go, to
/// the ones that stay.
async fn repoint_issues(
    tx: &mut Transaction<'_, Postgres>,
    project: i64,
    branch: &str,
    thinned: &[i64],
) -> sqlx::Result<()> {
    // First seen and fixed: the next analysis that stays. One always exists,
    // since the latest stays.
    sqlx::query(
        "UPDATE issues i SET
             first_analysis_id = CASE WHEN i.first_analysis_id = ANY($3)
                 THEN (SELECT min(a.id) FROM analyses a
                       WHERE a.project_id = $1 AND a.branch = $2
                         AND a.id > i.first_analysis_id AND a.id <> ALL($3))
                 ELSE i.first_analysis_id END,
             fixed_analysis_id = CASE WHEN i.fixed_analysis_id = ANY($3)
                 THEN (SELECT min(a.id) FROM analyses a
                       WHERE a.project_id = $1 AND a.branch = $2
                         AND a.id > i.fixed_analysis_id AND a.id <> ALL($3))
                 ELSE i.fixed_analysis_id END
         WHERE i.project_id = $1 AND i.branch = $2
           AND (i.first_analysis_id = ANY($3) OR i.fixed_analysis_id = ANY($3))",
    )
    .bind(project)
    .bind(branch)
    .bind(thinned)
    .execute(&mut **tx)
    .await?;
    // Last seen: the previous analysis that stays, but never before the
    // first (an issue that lived and was fixed inside one thinned stretch).
    sqlx::query(
        "UPDATE issues i SET last_analysis_id = greatest(i.first_analysis_id,
             (SELECT max(a.id) FROM analyses a
              WHERE a.project_id = $1 AND a.branch = $2
                AND a.id < i.last_analysis_id AND a.id <> ALL($3)))
         WHERE i.project_id = $1 AND i.branch = $2 AND i.last_analysis_id = ANY($3)",
    )
    .bind(project)
    .bind(branch)
    .bind(thinned)
    .execute(&mut **tx)
    .await?;
    Ok(())
}
