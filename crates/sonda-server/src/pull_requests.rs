//! Pull request analyses (ADR-0021). Stored under the branch key
//! `pr:<number>`, so issue tracking, the gate and triage work as on
//! branches; kept out of branch lists and main-branch counts, listed on
//! the project page, and removed some days after their last analysis.

use crate::health::{ago, gate_state, rfc3339};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use std::time::Duration;

/// A pull request's analyses go this many days after its last one.
pub const KEEP_DAYS: i32 = 30;

/// How often the server looks for pull requests to remove.
pub const CLEANUP_INTERVAL: Duration = Duration::from_secs(3600);

/// Which pull request an analysis belongs to; null for a branch's.
#[derive(Serialize, Deserialize, Debug)]
pub struct PullRequestRef {
    pub number: i64,
    pub base: String,
    pub head: String,
}

/// `analyses a`'s pull request as one JSON column, for [`PullRequestRef`]:
/// a constant, never input.
pub(crate) const PULL_REQUEST_COLUMN: &str = "CASE WHEN a.pull_request IS NULL THEN NULL
     ELSE jsonb_build_object('number', a.pull_request, 'base', a.pull_request_base,
                             'head', a.pull_request_head) END";

/// A pull request as of its latest analysis.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PullRequestRow {
    pub number: i64,
    pub base: String,
    pub head: String,
    /// Its latest analysis.
    pub analysis: i64,
    pub sha: String,
    pub gate: &'static str,
    pub new_issues: Option<f64>,
    pub analyzed_at: String,
    pub ago: String,
}

type Row = (i64, String, String, i64, String, f64, Value, bool, Value);

/// The project's pull requests, most recently analyzed first.
pub(crate) async fn list(
    pool: &PgPool,
    project: i64,
    now: f64,
) -> sqlx::Result<Vec<PullRequestRow>> {
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT DISTINCT ON (pull_request) pull_request, pull_request_base, pull_request_head,
                id, commit_sha, extract(epoch FROM received_at)::float8, gate, gate_passed,
                measures
         FROM analyses WHERE project_id = $1 AND pull_request IS NOT NULL
         ORDER BY pull_request, id DESC",
    )
    .bind(project)
    .fetch_all(pool)
    .await?;
    let mut prs: Vec<PullRequestRow> = rows
        .into_iter()
        .map(
            |(number, base, head, analysis, sha, at, gate, passed, measures)| PullRequestRow {
                number,
                base,
                head,
                analysis,
                sha,
                gate: gate_state(passed, &gate),
                new_issues: measures["new_issues"].as_f64(),
                analyzed_at: rfc3339(at),
                ago: ago(now - at),
            },
        )
        .collect();
    prs.sort_by_key(|p| std::cmp::Reverse(p.analysis));
    Ok(prs)
}

/// Removes the pull requests whose last analysis is older than
/// [`KEEP_DAYS`]: their analyses, issues, and the file contents nothing
/// else has. Returns how many pull requests went.
pub async fn remove_stale(pool: &PgPool) -> sqlx::Result<usize> {
    let stale: Vec<(i64, String)> = sqlx::query_as(
        "SELECT project_id, branch FROM analyses WHERE pull_request IS NOT NULL
         GROUP BY project_id, branch
         HAVING max(received_at) < now() - make_interval(days => $1)",
    )
    .bind(KEEP_DAYS)
    .fetch_all(pool)
    .await?;
    let mut removed = 0;
    for (project, branch) in stale {
        let mut tx = pool.begin().await?;
        // The lock an upload to it takes (store::ingest), so one arriving
        // now either lands first, and the check below keeps it, or after.
        crate::store::lock_branch(&mut tx, project, &branch).await?;
        let still: bool = sqlx::query_scalar(
            "SELECT max(received_at) < now() - make_interval(days => $3) FROM analyses
             WHERE project_id = $1 AND branch = $2",
        )
        .bind(project)
        .bind(&branch)
        .bind(KEEP_DAYS)
        .fetch_one(&mut *tx)
        .await
        .map(|s: Option<bool>| s.unwrap_or(false))?;
        if !still {
            continue;
        }
        let contents: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT DISTINCT f.sha256 FROM analysis_files f JOIN analyses a ON a.id = f.analysis_id
             WHERE a.project_id = $1 AND a.branch = $2",
        )
        .bind(project)
        .bind(&branch)
        .fetch_all(&mut *tx)
        .await?;
        // Its issues and their history go with its analyses.
        sqlx::query("DELETE FROM analyses WHERE project_id = $1 AND branch = $2")
            .bind(project)
            .bind(&branch)
            .execute(&mut *tx)
            .await?;
        crate::deleted_projects::remove_unused_sources(&mut tx, &contents).await?;
        tx.commit().await?;
        removed += 1;
    }
    Ok(removed)
}
