//! `GET /api/projects/{key}/coverage`: line, branch and function coverage
//! per file of a branch's latest analysis, and `.../coverage/file`: one
//! file's source with its covered and uncovered lines, branches and
//! functions, as an LCOV HTML report shows them. Both come
//! from the per-file coverage in the uploaded report (`sonda scan
//! --coverage`); files the coverage reports didn't list have no data.

use crate::api::ApiError;
use crate::health::rfc3339;
use crate::http::State;
use axum::Json;
use axum::extract::{Path, Query};
use serde::{Deserialize, Serialize};
use sonda_core::highlight::{self, Line};
use sonda_core::lang::Lang;
use sqlx::PgPool;
use sqlx::types::Json as Stored;

/// Lines of one file shown at most; longer files are cut, and say so.
const MAX_LINES: usize = 20_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageQuery {
    branch: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileQuery {
    path: String,
    branch: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisRef {
    pub id: i64,
    pub sha: String,
    pub analyzed_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoverageList {
    pub project: String,
    pub branch: String,
    pub analysis: AnalysisRef,
    /// The analysis's `coverage` measure; null without coverage.
    pub coverage: Option<f64>,
    /// Every analyzed file, by path.
    pub files: Vec<FileRow>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileRow {
    pub path: String,
    pub language: String,
    /// Lines the coverage reports list as run, and as not run; both null
    /// when they don't list the file.
    pub covered: Option<i32>,
    pub uncovered: Option<i32>,
    /// Branches taken at least once, of all; null without branch data.
    pub branches: Option<Counts>,
    /// Functions called at least once, of all; null without function data.
    pub functions: Option<Counts>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Counts {
    pub covered: i64,
    pub total: i64,
}

#[derive(Serialize, Deserialize)]
pub struct LineBranches {
    pub line: usize,
    pub taken: usize,
    pub total: usize,
}

#[derive(Serialize, Deserialize)]
pub struct FunctionCalls {
    pub name: String,
    pub line: usize,
    pub calls: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileCoverage {
    pub project: String,
    pub branch: String,
    pub analysis: AnalysisRef,
    pub path: String,
    pub language: String,
    /// Null when the coverage reports don't list the file.
    pub covered: Option<Vec<usize>>,
    pub uncovered: Option<Vec<usize>>,
    /// Lines with branches; null without branch data.
    pub branches: Option<Vec<LineBranches>>,
    /// Functions by line; null without function data.
    pub functions: Option<Vec<FunctionCalls>>,
    pub lines: Vec<Line>,
    /// More than `MAX_LINES` lines; only the first are in `lines`.
    pub truncated: bool,
}

/// The branch (the main one by default) and its latest analysis.
async fn latest(
    pool: &PgPool,
    key: &str,
    branch: Option<String>,
) -> Result<(String, AnalysisRef, Option<f64>), ApiError> {
    let main: String = sqlx::query_scalar("SELECT main_branch FROM projects WHERE key = $1")
        .bind(key)
        .fetch_optional(pool)
        .await?
        .ok_or(ApiError::NotFound)?;
    let branch = branch.unwrap_or(main);
    let row: Option<(i64, String, f64, Option<f64>)> = sqlx::query_as(
        "SELECT a.id, a.commit_sha, extract(epoch FROM a.received_at)::float8,
                (a.measures->>'coverage')::float8
         FROM analyses a JOIN projects p ON p.id = a.project_id
         WHERE p.key = $1 AND a.branch = $2 ORDER BY a.id DESC LIMIT 1",
    )
    .bind(key)
    .bind(&branch)
    .fetch_optional(pool)
    .await?;
    let (id, sha, at, coverage) =
        row.ok_or_else(|| ApiError::BadRequest(format!("branch {branch:?} has no analyses")))?;
    Ok((
        branch,
        AnalysisRef {
            id,
            sha,
            analyzed_at: rfc3339(at),
        },
        coverage,
    ))
}

pub async fn get_coverage(
    axum::extract::State(state): axum::extract::State<State>,
    Path(key): Path<String>,
    Query(q): Query<CoverageQuery>,
) -> Result<Json<CoverageList>, ApiError> {
    let pool = &state.pool;
    let (branch, analysis, coverage) = latest(pool, &key, q.branch).await?;
    type Row = (
        String,
        String,
        Option<i32>,
        Option<i32>,
        Option<i64>,
        Option<i64>,
        Option<i64>,
        Option<i64>,
    );
    let files: Vec<Row> = sqlx::query_as(
        "SELECT path, language, jsonb_array_length(metrics->'coverage'->'covered'),
                jsonb_array_length(metrics->'coverage'->'uncovered'),
                (SELECT sum((b->>'taken')::bigint)::bigint FROM jsonb_array_elements(
                     CASE WHEN jsonb_typeof(metrics->'branch_coverage') = 'array'
                          THEN metrics->'branch_coverage' END) b),
                (SELECT sum((b->>'total')::bigint)::bigint FROM jsonb_array_elements(
                     CASE WHEN jsonb_typeof(metrics->'branch_coverage') = 'array'
                          THEN metrics->'branch_coverage' END) b),
                (SELECT count(*) FILTER (WHERE (f->>'calls')::numeric > 0) FROM jsonb_array_elements(
                     CASE WHEN jsonb_typeof(metrics->'function_coverage') = 'array'
                          THEN metrics->'function_coverage' END) f),
                (SELECT count(*) FROM jsonb_array_elements(
                     CASE WHEN jsonb_typeof(metrics->'function_coverage') = 'array'
                          THEN metrics->'function_coverage' END) f)
         FROM analysis_files WHERE analysis_id = $1 ORDER BY path",
    )
    .bind(analysis.id)
    .fetch_all(pool)
    .await?;
    Ok(Json(CoverageList {
        project: key,
        branch,
        analysis,
        coverage,
        files: files
            .into_iter()
            .map(
                |(path, language, covered, uncovered, b_taken, b_total, f_called, f_total)| {
                    // Absent fields count nothing: no data, not 0 of 0.
                    let counts = |covered: Option<i64>, total: Option<i64>| match total {
                        Some(total) if total > 0 => Some(Counts {
                            covered: covered.unwrap_or(0),
                            total,
                        }),
                        _ => None,
                    };
                    FileRow {
                        path,
                        language,
                        covered,
                        uncovered,
                        branches: counts(b_taken, b_total),
                        functions: counts(f_called, f_total),
                    }
                },
            )
            .collect(),
    }))
}

pub async fn get_file_coverage(
    axum::extract::State(state): axum::extract::State<State>,
    Path(key): Path<String>,
    Query(q): Query<FileQuery>,
) -> Result<Json<FileCoverage>, ApiError> {
    let pool = &state.pool;
    let (branch, analysis, _) = latest(pool, &key, q.branch).await?;
    type Row = (
        String,
        String,
        Option<Stored<Vec<usize>>>,
        Option<Stored<Vec<usize>>>,
        Option<Stored<Vec<LineBranches>>>,
        Option<Stored<Vec<FunctionCalls>>>,
    );
    let row: Option<Row> = sqlx::query_as(
        "SELECT f.language, src.content, f.metrics->'coverage'->'covered',
                f.metrics->'coverage'->'uncovered', f.metrics->'branch_coverage',
                f.metrics->'function_coverage'
         FROM analysis_files f JOIN sources src ON src.sha256 = f.sha256
         WHERE f.analysis_id = $1 AND f.path = $2",
    )
    .bind(analysis.id)
    .bind(&q.path)
    .fetch_optional(pool)
    .await?;
    let (language, source, covered, uncovered, branches, functions) =
        row.ok_or(ApiError::NotFound)?;
    let lang = sonda_core::lang::ALL
        .iter()
        .copied()
        .find(|l: &Lang| l.name() == language);
    let total = source.lines().count();
    let mut lines = match lang {
        Some(lang) => highlight::highlight(lang, &source, 1, MAX_LINES),
        None => Vec::new(),
    };
    // Not the empty "line" after a final line break.
    lines.truncate(total);
    Ok(Json(FileCoverage {
        project: key,
        branch,
        analysis,
        path: q.path,
        language,
        covered: covered.map(|c| c.0),
        uncovered: uncovered.map(|c| c.0),
        branches: branches.map(|b| b.0),
        functions: functions.map(|f| f.0),
        lines,
        truncated: total > MAX_LINES,
    }))
}
