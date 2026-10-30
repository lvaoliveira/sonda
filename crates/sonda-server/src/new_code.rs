//! The main branch's new code period (ADR-0011): it starts at an analysis
//! (the project's first, unless an admin moved it), and on the main branch
//! an issue is new if it was first seen after that. The server recomputes
//! the issue measures, `new_lines` and the gate of the branch's latest
//! analysis from it, on upload and when the period moves.

use crate::api::{ApiError, Caller};
use crate::health::{evaluate_gate, rfc3339};
use crate::http::State;
use axum::Json;
use axum::extract::{Extension, Path};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use std::collections::HashMap;

/// Where a project's period starts.
#[derive(Serialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Period {
    pub analysis: i64,
    pub sha: String,
    pub analyzed_at: String,
    /// Moved by an admin, rather than the project's first analysis.
    pub reset: bool,
    /// New-code measures the server can't recompute without per-line data;
    /// these keep the scan's own values.
    pub from_scan: &'static [&'static str],
}

const FROM_SCAN: &[&str] = &["new_coverage", "new_duplicated_lines_density"];

/// The project's period, if its main branch has an analysis.
pub async fn period(pool: &PgPool, project: i64) -> Result<Option<Period>, sqlx::Error> {
    let row: Option<(i64, bool, String, f64)> = sqlx::query_as(
        "SELECT a.id, p.new_code_since IS NOT NULL, a.commit_sha,
                extract(epoch FROM a.received_at)::float8
         FROM projects p
         JOIN analyses a ON a.id = coalesce(
             p.new_code_since,
             (SELECT min(f.id) FROM analyses f
              WHERE f.project_id = p.id AND f.branch = p.main_branch))
         WHERE p.id = $1",
    )
    .bind(project)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(analysis, reset, sha, at)| Period {
        analysis,
        sha,
        analyzed_at: rfc3339(at),
        reset,
        from_scan: FROM_SCAN,
    }))
}

/// Recomputes new code on the project's main branch against its period:
/// which issues are new, the new-issue measures and `new_lines` of the
/// branch's latest analysis, and that analysis's gate. Older analyses keep
/// what they had.
pub async fn refresh(pool: &PgPool, project: i64) -> Result<(), sqlx::Error> {
    let Some(start) = period(pool, project).await? else {
        return Ok(());
    };
    let latest: Option<(i64, String, Value, Value)> = sqlx::query_as(
        "SELECT a.id, p.main_branch, a.measures, a.gate
         FROM projects p JOIN analyses a ON a.project_id = p.id AND a.branch = p.main_branch
         WHERE p.id = $1 ORDER BY a.id DESC LIMIT 1",
    )
    .bind(project)
    .fetch_optional(pool)
    .await?;
    let Some((latest, branch, mut measures, mut gate)) = latest else {
        return Ok(());
    };

    let mut tx = pool.begin().await?;
    sqlx::query(
        "UPDATE issues SET is_new = (first_analysis_id > $3)
         WHERE project_id = $1 AND branch = $2",
    )
    .bind(project)
    .bind(&branch)
    .bind(start.analysis)
    .execute(&mut *tx)
    .await?;
    // The issues present in the latest analysis that are new.
    let new: Vec<(String, String, i32)> = sqlx::query_as(
        "SELECT category, severity, effort_minutes FROM issues
         WHERE project_id = $1 AND branch = $2 AND fixed_analysis_id IS NULL AND is_new",
    )
    .bind(project)
    .bind(&branch)
    .fetch_all(&mut *tx)
    .await?;
    let count =
        |p: &dyn Fn(&(String, String, i32)) -> bool| new.iter().filter(|i| p(i)).count() as f64;
    let values = [
        ("new_issues", new.len() as f64),
        ("new_bugs", count(&|i| i.0 == "bug")),
        ("new_vulnerabilities", count(&|i| i.0 == "vulnerability")),
        ("new_code_smells", count(&|i| i.0 == "code_smell")),
        ("new_blocker_issues", count(&|i| i.1 == "blocker")),
        ("new_critical_issues", count(&|i| i.1 == "critical")),
        ("new_major_issues", count(&|i| i.1 == "major")),
        ("new_debt_minutes", new.iter().map(|i| f64::from(i.2)).sum()),
        (
            "new_lines",
            new_lines(&mut tx, start.analysis, latest).await?,
        ),
    ];
    for (metric, value) in values {
        measures[metric] = Value::from(value);
    }
    let passed = evaluate_gate(&mut gate, &measures);
    sqlx::query("UPDATE analyses SET measures = $2, gate = $3, gate_passed = $4 WHERE id = $1")
        .bind(latest)
        .bind(&measures)
        .bind(&gate)
        .bind(passed)
        .execute(&mut *tx)
        .await?;
    tx.commit().await
}

/// Non-blank lines of `latest`'s files that are new or changed since
/// `start`. The CLI counts code lines (comments excluded), which needs
/// parsing; the server doesn't parse uploaded code (ADR-0003).
async fn new_lines(
    tx: &mut sqlx::PgConnection,
    start: i64,
    latest: i64,
) -> Result<f64, sqlx::Error> {
    if start == latest {
        return Ok(0.0);
    }
    // (path, sha in latest, sha in start if the file existed there)
    let files: Vec<(String, Vec<u8>, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT f.path, f.sha256, s.sha256
         FROM analysis_files f
         LEFT JOIN analysis_files s ON s.analysis_id = $2 AND s.path = f.path
         WHERE f.analysis_id = $1 AND f.sha256 IS DISTINCT FROM s.sha256",
    )
    .bind(latest)
    .bind(start)
    .fetch_all(&mut *tx)
    .await?;
    let shas: Vec<Vec<u8>> = files
        .iter()
        .flat_map(|(_, new, old)| std::iter::once(new.clone()).chain(old.clone()))
        .collect();
    let contents: HashMap<Vec<u8>, String> =
        sqlx::query_as("SELECT sha256, content FROM sources WHERE sha256 = ANY($1)")
            .bind(&shas)
            .fetch_all(&mut *tx)
            .await?
            .into_iter()
            .collect();
    let mut total = 0usize;
    for (_, new, old) in &files {
        let Some(new) = contents.get(new) else {
            continue;
        };
        let non_blank = |n: &usize| new.lines().nth(n - 1).is_some_and(|l| !l.trim().is_empty());
        total += match old.as_ref().and_then(|o| contents.get(o)) {
            Some(old) => sonda_core::changed_lines(old, new)
                .iter()
                .filter(|n| non_blank(n))
                .count(),
            None => new.lines().filter(|l| !l.trim().is_empty()).count(),
        };
    }
    Ok(total as f64)
}

#[derive(Deserialize)]
pub struct PeriodPatch {
    /// An analysis of the main branch; null for the project's first.
    pub analysis: Option<i64>,
}

/// `PUT /api/projects/{key}/new-code`: moves the period's start, admins
/// only. Moving it accepts the debt up to that analysis, so it's audited.
pub async fn put_period(
    axum::extract::State(state): axum::extract::State<State>,
    Extension(caller): Extension<Caller>,
    Path(key): Path<String>,
    Json(patch): Json<PeriodPatch>,
) -> Result<Json<Period>, ApiError> {
    let pool = &state.pool;
    let (project, old): (i64, Option<i64>) =
        sqlx::query_as("SELECT id, new_code_since FROM projects WHERE key = $1")
            .bind(&key)
            .fetch_optional(pool)
            .await?
            .ok_or(ApiError::NotFound)?;
    if let Some(analysis) = patch.analysis {
        let on_main: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM analyses a JOIN projects p ON p.id = a.project_id
                            WHERE a.id = $1 AND p.id = $2 AND a.branch = p.main_branch)",
        )
        .bind(analysis)
        .bind(project)
        .fetch_one(pool)
        .await?;
        if !on_main {
            return Err(ApiError::Unprocessable(
                "the new code period starts at an analysis of the project's main branch".into(),
            ));
        }
    }
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE projects SET new_code_since = $2 WHERE id = $1")
        .bind(project)
        .bind(patch.analysis)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO new_code_resets (project_id, actor, old_since, new_since)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(project)
    .bind(caller.name())
    .bind(old)
    .bind(patch.analysis)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    refresh(pool, project).await?;
    crate::dependencies::refresh_gates(pool, crate::dependencies::GateScope::Project(project))
        .await?;
    period(pool, project)
        .await?
        .map(Json)
        .ok_or(ApiError::NotFound)
}
