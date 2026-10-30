//! `GET /api/analyses`: stored analyses, newest first, across projects or
//! for one project and branch. `GET /api/analyses/{id}`: one analysis, with
//! its gate, measures, warnings, and the issues it introduced and fixed.
//!
//! Commit messages, scan durations and stage logs are not uploaded, so
//! neither is reported.

use crate::api::ApiError;
use crate::health::{
    GateDetail, Measures, component_of, conditions, gate_state, measure_set, rfc3339,
};
use crate::http::State;
use axum::Json;
use axum::extract::{Path, Query};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const MAX_LIMIT: i64 = 100;
/// Issues listed per change (introduced, fixed); the totals are exact.
const MAX_CHANGES: i64 = 50;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListQuery {
    project: Option<String>,
    branch: Option<String>,
    /// `failed`, or `passed` (passing, including partial).
    gate: Option<String>,
    offset: Option<i64>,
    limit: Option<i64>,
}

#[derive(Serialize)]
pub struct AnalysisPage {
    pub total: i64,
    pub offset: i64,
    pub limit: i64,
    pub items: Vec<AnalysisRow>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisRow {
    pub id: i64,
    pub project: String,
    pub branch: String,
    pub sha: String,
    pub analyzed_at: String,
    pub tool_version: String,
    pub gate: &'static str,
    /// Labels of the conditions that failed.
    pub failing: Vec<String>,
    pub issues: Option<f64>,
    pub new_issues: Option<f64>,
    pub warnings: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisDetail {
    pub id: i64,
    pub project: String,
    pub branch: String,
    pub main_branch: String,
    pub sha: String,
    pub analyzed_at: String,
    pub tool_version: String,
    pub new_code_reference: Option<String>,
    pub gate: GateDetail,
    pub measures: Measures,
    pub files: usize,
    /// Files per language, most first.
    pub languages: Vec<LanguageFiles>,
    pub components: usize,
    /// As the CLI reported them: skipped files, syntax errors, timeouts.
    pub warnings: Vec<String>,
    /// The branch's first analysis: its issues are the baseline, not new.
    pub baseline: bool,
    pub introduced: Changes,
    pub fixed: Changes,
    pub previous: Option<Neighbor>,
    pub next: Option<Neighbor>,
}

#[derive(Serialize)]
pub struct LanguageFiles {
    pub id: String,
    pub files: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Changes {
    pub total: i64,
    /// Counts per severity, for every issue (not only the listed ones).
    pub by_severity: BTreeMap<String, i64>,
    pub items: Vec<IssueRef>,
}

#[derive(Serialize)]
pub struct IssueRef {
    pub id: i64,
    pub severity: String,
    pub category: String,
    pub rule: String,
    pub message: String,
    pub path: String,
    pub line: i32,
}

#[derive(Serialize)]
pub struct Neighbor {
    pub id: i64,
    pub sha: String,
}

type ListRow = (
    i64,
    String,
    String,
    String,
    f64,
    String,
    Value,
    Value,
    bool,
    Value,
);

pub async fn list_analyses(
    axum::extract::State(state): axum::extract::State<State>,
    Query(q): Query<ListQuery>,
) -> Result<Json<AnalysisPage>, ApiError> {
    let limit = q.limit.unwrap_or(50);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(ApiError::BadRequest(format!(
            "limit must be between 1 and {MAX_LIMIT}"
        )));
    }
    let offset = q.offset.unwrap_or(0);
    if offset < 0 {
        return Err(ApiError::BadRequest("offset must not be negative".into()));
    }
    let passed = match q.gate.as_deref() {
        None => None,
        Some("failed") => Some(false),
        Some("passed") => Some(true),
        Some(other) => {
            return Err(ApiError::BadRequest(format!(
                "unknown gate {other:?}; use failed or passed"
            )));
        }
    };
    // $1 project key, $2 branch, $3 gate passed: each NULL when not filtered.
    const FILTER: &str = "FROM analyses a JOIN projects p ON p.id = a.project_id
         WHERE ($1::text IS NULL OR p.key = $1)
           AND ($2::text IS NULL OR a.branch = $2)
           AND ($3::boolean IS NULL OR a.gate_passed = $3)";
    let pool = &state.pool;
    let total: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) {FILTER}")))
        .bind(&q.project)
        .bind(&q.branch)
        .bind(passed)
        .fetch_one(pool)
        .await?;
    let rows: Vec<ListRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT a.id, p.key, a.branch, a.commit_sha, extract(epoch FROM a.received_at)::float8,
                a.tool_version, a.measures, a.gate, a.gate_passed, a.warnings
         {FILTER} ORDER BY a.received_at DESC, a.id DESC OFFSET $4 LIMIT $5"
    )))
    .bind(&q.project)
    .bind(&q.branch)
    .bind(passed)
    .bind(offset)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    let items = rows
        .into_iter()
        .map(
            |(id, project, branch, sha, at, tool_version, measures, gate, passed, warnings)| {
                AnalysisRow {
                    id,
                    project,
                    branch,
                    sha,
                    analyzed_at: rfc3339(at),
                    tool_version,
                    gate: gate_state(passed, &gate),
                    failing: conditions(&gate)
                        .into_iter()
                        .filter(|c| c.status == "error")
                        .map(|c| c.label)
                        .collect(),
                    issues: measures["issues"].as_f64(),
                    new_issues: measures["new_issues"].as_f64(),
                    warnings: warnings.as_array().map_or(0, Vec::len),
                }
            },
        )
        .collect();
    Ok(Json(AnalysisPage {
        total,
        offset,
        limit,
        items,
    }))
}

type DetailRow = (
    i64,
    i64,
    String,
    String,
    String,
    String,
    f64,
    String,
    Option<String>,
    Value,
    Value,
    bool,
    Value,
);

type IssueRow = (i64, String, String, String, String, String, i32);

pub async fn get_analysis(
    axum::extract::State(state): axum::extract::State<State>,
    Path(id): Path<i64>,
) -> Result<Json<AnalysisDetail>, ApiError> {
    let pool = &state.pool;
    let row: DetailRow = sqlx::query_as(
        "SELECT a.id, a.project_id, p.key, p.main_branch, a.branch, a.commit_sha,
                extract(epoch FROM a.received_at)::float8, a.tool_version, a.new_code_reference,
                a.measures, a.gate, a.gate_passed, a.warnings
         FROM analyses a JOIN projects p ON p.id = a.project_id WHERE a.id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    let (
        id,
        project_id,
        project,
        main_branch,
        branch,
        sha,
        at,
        tool_version,
        new_code_reference,
        measures,
        gate,
        passed,
        warnings,
    ) = row;

    let files: Vec<(String, String)> =
        sqlx::query_as("SELECT path, language FROM analysis_files WHERE analysis_id = $1")
            .bind(id)
            .fetch_all(pool)
            .await?;
    let mut by_language: BTreeMap<String, usize> = BTreeMap::new();
    for (_, language) in &files {
        *by_language.entry(language.clone()).or_default() += 1;
    }
    let mut languages: Vec<LanguageFiles> = by_language
        .into_iter()
        .map(|(id, files)| LanguageFiles { id, files })
        .collect();
    languages.sort_by(|a, b| b.files.cmp(&a.files).then_with(|| a.id.cmp(&b.id)));
    let components: BTreeSet<&str> = files.iter().map(|(p, _)| component_of(p)).collect();

    let neighbor = |cmp: &str, order: &str| {
        format!(
            "SELECT id, commit_sha FROM analyses WHERE project_id = $1 AND branch = $2
             AND id {cmp} $3 ORDER BY id {order} LIMIT 1"
        )
    };
    let previous: Option<(i64, String)> =
        sqlx::query_as(sqlx::AssertSqlSafe(neighbor("<", "DESC")))
            .bind(project_id)
            .bind(&branch)
            .bind(id)
            .fetch_optional(pool)
            .await?;
    let next: Option<(i64, String)> = sqlx::query_as(sqlx::AssertSqlSafe(neighbor(">", "ASC")))
        .bind(project_id)
        .bind(&branch)
        .bind(id)
        .fetch_optional(pool)
        .await?;

    let introduced = changes(pool, "first_analysis_id", id).await?;
    let fixed = changes(pool, "fixed_analysis_id", id).await?;

    Ok(Json(AnalysisDetail {
        id,
        project,
        branch,
        main_branch,
        sha,
        analyzed_at: rfc3339(at),
        tool_version,
        new_code_reference,
        gate: GateDetail {
            state: gate_state(passed, &gate),
            conditions: conditions(&gate),
        },
        measures: Measures {
            overall: measure_set(&measures, ""),
            new_code: measure_set(&measures, "new_"),
        },
        files: files.len(),
        languages,
        components: components.len(),
        warnings: warnings
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|w| w.as_str().map(str::to_string))
            .collect(),
        baseline: previous.is_none(),
        introduced,
        fixed,
        previous: previous.map(|(id, sha)| Neighbor { id, sha }),
        next: next.map(|(id, sha)| Neighbor { id, sha }),
    }))
}

/// The issues whose `column` (first seen, or fixed) is this analysis.
async fn changes(
    pool: &sqlx::PgPool,
    column: &'static str,
    analysis: i64,
) -> Result<Changes, sqlx::Error> {
    let counts: Vec<(String, i64)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT severity, count(*) FROM issues WHERE {column} = $1 GROUP BY severity"
    )))
    .bind(analysis)
    .fetch_all(pool)
    .await?;
    let items: Vec<IssueRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT id, severity, category, rule, message, path, line FROM issues
         WHERE {column} = $1
         ORDER BY array_position(ARRAY['blocker', 'critical', 'major', 'minor', 'info'], severity),
                  path, line, id
         LIMIT $2"
    )))
    .bind(analysis)
    .bind(MAX_CHANGES)
    .fetch_all(pool)
    .await?;
    Ok(Changes {
        total: counts.iter().map(|(_, n)| n).sum(),
        by_severity: counts.into_iter().collect(),
        items: items
            .into_iter()
            .map(
                |(id, severity, category, rule, message, path, line)| IssueRef {
                    id,
                    severity,
                    category,
                    rule,
                    message,
                    path,
                    line,
                },
            )
            .collect(),
    })
}
