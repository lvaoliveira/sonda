//! The main branch's new code period (ADR-0011): it starts at an analysis
//! (the first of the project's current version, or the project's first,
//! unless an admin moved it), and on the main branch an issue is new if it
//! was first seen after that. The server recomputes the issue measures,
//! `new_lines`, `new_coverage` (from per-file coverage) and the gate of the
//! branch's latest analysis from it, on upload and when the period moves.

use crate::api::{ApiError, Caller};
use crate::health::{evaluate_gate, rfc3339};
use crate::http::State;
use axum::Json;
use axum::extract::{Extension, Path};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use std::collections::{HashMap, HashSet};

/// Where a project's period starts.
#[derive(Serialize, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Period {
    pub analysis: i64,
    pub sha: String,
    pub analyzed_at: String,
    /// Moved by an admin, rather than following the project's versions.
    pub reset: bool,
    /// The version whose first analysis starts the period, when a version
    /// change started it; otherwise it's the project's first analysis.
    pub version: Option<String>,
    /// New-code measures the server can't recompute without per-line data;
    /// these keep the scan's own values. Coverage is recomputed when the
    /// latest analysis's report carries it per file.
    pub from_scan: Vec<&'static str>,
}

/// The project's period, if its main branch has an analysis.
///
/// Without an admin's start, it's "previous version": the first analysis
/// of the latest version, after the last analysis with another version.
/// Analyses without a version don't change it, so a project that never
/// sends one keeps its first analysis.
pub async fn period(pool: &PgPool, project: i64) -> Result<Option<Period>, sqlx::Error> {
    let row: Option<(i64, bool, Option<String>, String, f64)> = sqlx::query_as(
        "WITH main AS (
             SELECT a.id, a.project_version FROM analyses a JOIN projects p ON p.id = a.project_id
             WHERE p.id = $1 AND a.branch = p.main_branch),
         latest AS (
             SELECT project_version AS v FROM main
             WHERE project_version IS NOT NULL ORDER BY id DESC LIMIT 1),
         change AS (
             SELECT max(m.id) AS before, l.v FROM main m, latest l
             WHERE m.project_version IS NOT NULL AND m.project_version <> l.v
             GROUP BY l.v),
         by_version AS (
             SELECT min(m.id) AS id, c.v FROM main m, change c
             WHERE m.id > c.before AND m.project_version = c.v
             GROUP BY c.v)
         SELECT a.id, p.new_code_since IS NOT NULL,
                CASE WHEN p.new_code_since IS NULL THEN (SELECT v FROM by_version) END,
                a.commit_sha, extract(epoch FROM a.received_at)::float8
         FROM projects p
         JOIN analyses a ON a.id = coalesce(
             p.new_code_since,
             (SELECT id FROM by_version),
             (SELECT min(id) FROM main))
         WHERE p.id = $1",
    )
    .bind(project)
    .fetch_optional(pool)
    .await?;
    let Some((analysis, reset, version, sha, at)) = row else {
        return Ok(None);
    };
    let per_file_coverage: bool = sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1 FROM analysis_files f
             WHERE f.metrics ? 'coverage' AND f.analysis_id = (
                 SELECT a.id FROM analyses a JOIN projects p ON p.id = a.project_id
                 WHERE p.id = $1 AND a.branch = p.main_branch ORDER BY a.id DESC LIMIT 1))",
    )
    .bind(project)
    .fetch_one(pool)
    .await?;
    let mut from_scan = vec!["new_duplicated_lines_density"];
    if !per_file_coverage {
        from_scan.insert(0, "new_coverage");
    }
    Ok(Some(Period {
        analysis,
        sha,
        analyzed_at: rfc3339(at),
        reset,
        version,
        from_scan,
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
    let changed = changed_lines(&mut tx, start.analysis, latest).await?;
    // An issue is new if it was first seen after the start and sits on a
    // line changed since then. First seen alone isn't enough: a rule added
    // to sonda finds issues in old code too, and those are old debt.
    // Fixed issues have no line in the latest analysis, so they keep the
    // first-seen test.
    let present: Vec<(i64, String, i32)> = sqlx::query_as(
        "SELECT id, path, line FROM issues
         WHERE project_id = $1 AND branch = $2 AND fixed_analysis_id IS NULL
           AND first_analysis_id > $3",
    )
    .bind(project)
    .bind(&branch)
    .bind(start.analysis)
    .fetch_all(&mut *tx)
    .await?;
    let new_ids: Vec<i64> = present
        .into_iter()
        .filter(|(_, path, line)| changed.contains(path, *line as usize))
        .map(|(id, _, _)| id)
        .collect();
    sqlx::query(
        "UPDATE issues
         SET is_new = CASE WHEN fixed_analysis_id IS NULL THEN id = ANY($4)
                           ELSE first_analysis_id > $3 END
         WHERE project_id = $1 AND branch = $2",
    )
    .bind(project)
    .bind(&branch)
    .bind(start.analysis)
    .bind(&new_ids)
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
    ];
    for (metric, value) in values {
        measures[metric] = Value::from(value);
    }
    measures["new_lines"] = Value::from(changed.lines as f64);
    // Without per-file coverage (an older CLI, or no --coverage), the scan's
    // value stays.
    if let Some(coverage) = changed.coverage {
        measures["new_coverage"] = Value::from(coverage);
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

/// What changed in `latest` since `start`.
struct Changed {
    /// Non-blank lines of `latest`'s files that are new or changed. The CLI
    /// counts code lines (comments excluded), which needs parsing; the
    /// server doesn't parse uploaded code (ADR-0003).
    lines: usize,
    /// Coverage on those lines, as the CLI computes it: covered among the
    /// lines the coverage reports list. `None` when `latest` has no
    /// per-file coverage; `Some(None)` when no changed line is coverable.
    coverage: Option<Option<f64>>,
    /// The files that changed: their changed lines, or `None` for a file
    /// that didn't exist at the start.
    files: HashMap<String, Option<HashSet<usize>>>,
}

impl Changed {
    fn contains(&self, path: &str, line: usize) -> bool {
        self.files
            .get(path)
            .is_some_and(|lines| lines.as_ref().is_none_or(|l| l.contains(&line)))
    }
}

/// A file's coverage in the report: (covered, uncovered) lines.
#[derive(Deserialize, Default)]
struct FileCoverage {
    covered: Vec<usize>,
    uncovered: Vec<usize>,
}

async fn changed_lines(
    tx: &mut sqlx::PgConnection,
    start: i64,
    latest: i64,
) -> Result<Changed, sqlx::Error> {
    let has_coverage: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM analysis_files WHERE analysis_id = $1 AND metrics ? 'coverage')",
    )
    .bind(latest)
    .fetch_one(&mut *tx)
    .await?;
    if start == latest {
        return Ok(Changed {
            lines: 0,
            coverage: has_coverage.then_some(None),
            files: HashMap::new(),
        });
    }
    // (path, sha in latest, sha in start if the file existed there, coverage)
    type Row = (
        String,
        Vec<u8>,
        Option<Vec<u8>>,
        Option<sqlx::types::Json<FileCoverage>>,
    );
    let files: Vec<Row> = sqlx::query_as(
        "SELECT f.path, f.sha256, s.sha256, f.metrics->'coverage'
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
        .flat_map(|(_, new, old, _)| std::iter::once(new.clone()).chain(old.clone()))
        .collect();
    let contents: HashMap<Vec<u8>, String> =
        sqlx::query_as("SELECT sha256, content FROM sources WHERE sha256 = ANY($1)")
            .bind(&shas)
            .fetch_all(&mut *tx)
            .await?
            .into_iter()
            .collect();
    let (mut lines, mut coverable, mut covered) = (0usize, 0usize, 0usize);
    let mut changed_files = HashMap::with_capacity(files.len());
    for (path, new, old, coverage) in files {
        let Some(new) = contents.get(&new) else {
            continue;
        };
        // None: every line of a file that didn't exist at the start.
        let changed: Option<HashSet<usize>> = old
            .as_ref()
            .and_then(|o| contents.get(o))
            .map(|old| sonda_core::changed_lines(old, new));
        let is_new = |n: usize| changed.as_ref().is_none_or(|c| c.contains(&n));
        lines += new
            .lines()
            .enumerate()
            .filter(|(i, l)| is_new(i + 1) && !l.trim().is_empty())
            .count();
        if let Some(c) = coverage {
            let new_covered = c.covered.iter().filter(|n| is_new(**n)).count();
            covered += new_covered;
            coverable += new_covered + c.uncovered.iter().filter(|n| is_new(**n)).count();
        }
        changed_files.insert(path, changed);
    }
    Ok(Changed {
        lines,
        files: changed_files,
        coverage: has_coverage.then(|| {
            (coverable > 0).then(|| (1000.0 * covered as f64 / coverable as f64).round() / 10.0)
        }),
    })
}

#[derive(Deserialize)]
pub struct PeriodPatch {
    /// An analysis of the main branch; null to follow the project's
    /// versions again (its first analysis, if it has none).
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
