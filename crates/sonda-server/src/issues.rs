//! The issues API: a filtered, paginated list with facet counts, one
//! issue with its code, and triage (status, assignee) with an audit trail.

use crate::api::ApiError;
use crate::http::State;
use axum::Json;
use axum::extract::{Path, Query};
use serde::{Deserialize, Serialize};
use sonda_core::highlight::{self, Line};
use sonda_core::lang::Lang;
use sqlx::PgPool;
use std::collections::BTreeMap;

pub const DEFAULT_LIMIT: i64 = 50;
pub const MAX_LIMIT: i64 = 200;
/// Lines of context shown above and below an issue.
const CONTEXT_LINES: usize = 6;
/// The most code lines one issue view shows.
const MAX_CODE_LINES: usize = 80;

const SEVERITIES: &[&str] = &["blocker", "critical", "major", "minor", "info"];
const CATEGORIES: &[&str] = &["bug", "vulnerability", "code_smell"];
/// `fixed` is derived from scans; the others are a human's triage.
const STATES: &[&str] = &["open", "confirmed", "accepted", "false_positive", "fixed"];

// SQL in this module is assembled with `format!` from the constants below
// and fixed column names only, never from request input (which is always
// bound as parameters). That is why `sqlx::AssertSqlSafe` is sound here.

/// Columns derived for every issue: the project's key, the status shown
/// (`fixed` comes from scans), and the component (top-level directory).
const DERIVED: &str = "
    i.*, p.key AS project_key,
    CASE WHEN i.fixed_analysis_id IS NOT NULL THEN 'fixed' ELSE i.status::text END AS state,
    CASE WHEN strpos(i.path, '/') > 0 THEN split_part(i.path, '/', 1) ELSE '.' END AS component";

/// UTC, ISO 8601, e.g. `2026-10-29T20:56:14.053Z`.
const ISO_8601: &str = "'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'";

/// The issues of the chosen project (or all projects) on the chosen branch
/// (or each project's main branch). Parameters: $1 project key, $2 branch.
fn scoped() -> String {
    format!(
        "WITH scoped AS (
            SELECT {DERIVED} FROM issues i JOIN projects p ON p.id = i.project_id
            WHERE ($1::text IS NULL OR p.key = $1)
              AND i.branch = coalesce($2::text, p.main_branch)
        )"
    )
}

/// Filters, as parameters $3.. after `scoped()`'s. An empty list matches
/// everything, so one static query serves every combination: no SQL is
/// ever built from request input.
const FILTERED: &str = "
    FROM scoped s
    WHERE (cardinality($3::text[]) = 0 OR s.severity = ANY($3))
      AND (cardinality($4::text[]) = 0 OR s.category = ANY($4))
      AND (cardinality($5::text[]) = 0 OR s.state = ANY($5))
      AND (cardinality($6::text[]) = 0 OR s.component = ANY($6))
      AND ($7::text IS NULL OR strpos(s.path, $7) > 0)
      AND ($8::text IS NULL OR s.assignee = $8)
      AND (NOT $9 OR s.is_new)";

const SEVERITY_RANK: &str =
    "array_position(ARRAY['blocker','critical','major','minor','info'], s.severity)";

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ListQuery {
    project: Option<String>,
    branch: Option<String>,
    /// Comma-separated, like the other list filters.
    severity: Option<String>,
    category: Option<String>,
    status: Option<String>,
    component: Option<String>,
    /// Matches any part of the path.
    file: Option<String>,
    assignee: Option<String>,
    /// Only issues on new code.
    #[serde(default)]
    new: bool,
    offset: Option<i64>,
    limit: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Page {
    pub total: i64,
    pub offset: i64,
    pub limit: i64,
    pub items: Vec<IssueView>,
    /// For each facet, the count per value, as if that facet had no
    /// selection, so choosing one severity keeps the others' counts.
    pub facets: BTreeMap<&'static str, BTreeMap<String, i64>>,
}

#[derive(Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct IssueView {
    pub id: i64,
    /// The fingerprint, stable across analyses.
    pub key: String,
    pub project: String,
    pub branch: String,
    pub severity: String,
    pub category: String,
    pub rule: String,
    pub message: String,
    pub component: String,
    pub file: String,
    pub line: i32,
    pub end_line: i32,
    pub language: Option<String>,
    pub effort_minutes: i32,
    pub status: String,
    pub assignee: Option<String>,
    pub is_new: bool,
    /// When the analysis that first saw it arrived (UTC, ISO 8601).
    pub detected_at: String,
    /// Why it was confirmed, accepted or ruled a false positive (ADR-0014).
    pub reason: Option<String>,
}

/// Columns for `IssueView`, over `scoped s`.
fn view_columns() -> String {
    format!(
        "s.id, encode(s.fingerprint, 'hex') AS key, s.project_key AS project, s.branch,
        s.severity, s.category, s.rule, s.message, s.component, s.path AS file, s.line,
        s.end_line,
        (SELECT f.language FROM analysis_files f
         WHERE f.analysis_id = s.last_analysis_id AND f.path = s.path) AS language,
        s.effort_minutes, s.state AS status, s.assignee, s.is_new,
        (SELECT to_char(a.received_at AT TIME ZONE 'UTC', {ISO_8601})
         FROM analyses a WHERE a.id = s.first_analysis_id) AS detected_at,
        s.reason"
    )
}

/// The parsed filters, bound in `FILTERED`'s order.
struct Filters {
    project: Option<String>,
    branch: Option<String>,
    severity: Vec<String>,
    category: Vec<String>,
    state: Vec<String>,
    component: Vec<String>,
    file: Option<String>,
    assignee: Option<String>,
    new: bool,
}

impl Filters {
    fn parse(q: ListQuery) -> Result<Self, ApiError> {
        Ok(Self {
            project: q.project,
            branch: q.branch,
            severity: list(q.severity, "severity", Some(SEVERITIES))?,
            category: list(q.category, "category", Some(CATEGORIES))?,
            state: list(q.status, "status", Some(STATES))?,
            component: list(q.component, "component", None)?,
            file: q.file.filter(|f| !f.is_empty()),
            assignee: q.assignee.filter(|a| !a.is_empty()),
            new: q.new,
        })
    }

    /// Binds `scoped()` and `FILTERED` parameters ($1-$9) onto `query`.
    /// `except` binds an empty list for that facet instead.
    fn bind<'q, O>(
        &'q self,
        query: sqlx::query::QueryAs<'q, sqlx::Postgres, O, sqlx::postgres::PgArguments>,
        except: Option<&str>,
    ) -> sqlx::query::QueryAs<'q, sqlx::Postgres, O, sqlx::postgres::PgArguments> {
        let empty: &[String] = &[];
        let facet =
            |name: &str, values: &'q [String]| if except == Some(name) { empty } else { values };
        query
            .bind(&self.project)
            .bind(&self.branch)
            .bind(facet("severity", &self.severity))
            .bind(facet("category", &self.category))
            .bind(facet("status", &self.state))
            .bind(facet("component", &self.component))
            .bind(&self.file)
            .bind(&self.assignee)
            .bind(self.new)
    }
}

/// A comma-separated filter. Unknown values are an error, not an empty
/// result: a typo must not look like "no issues".
fn list(
    raw: Option<String>,
    name: &str,
    allowed: Option<&[&str]>,
) -> Result<Vec<String>, ApiError> {
    let values: Vec<String> = raw
        .iter()
        .flat_map(|r| r.split(','))
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .collect();
    if let Some(allowed) = allowed
        && let Some(bad) = values.iter().find(|v| !allowed.contains(&v.as_str()))
    {
        return Err(ApiError::BadRequest(format!(
            "unknown {name} {bad:?}; expected one of {}",
            allowed.join(", ")
        )));
    }
    Ok(values)
}

pub async fn list_issues(
    axum::extract::State(state): axum::extract::State<State>,
    Query(q): Query<ListQuery>,
) -> Result<Json<Page>, ApiError> {
    let offset = q.offset.unwrap_or(0);
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT);
    if offset < 0 || !(1..=MAX_LIMIT).contains(&limit) {
        return Err(ApiError::BadRequest(format!(
            "offset must be >= 0 and limit 1-{MAX_LIMIT}"
        )));
    }
    let filters = Filters::parse(q)?;

    let (scoped, columns) = (scoped(), view_columns());
    let items_sql = format!(
        "{scoped} SELECT {columns} {FILTERED}
         ORDER BY {SEVERITY_RANK}, s.project_key, s.path, s.line, s.id
         OFFSET $10 LIMIT $11"
    );
    let items: Vec<IssueView> = filters
        .bind(sqlx::query_as(sqlx::AssertSqlSafe(items_sql)), None)
        .bind(offset)
        .bind(limit)
        .fetch_all(&state.pool)
        .await?;
    let (total,): (i64,) = filters
        .bind(
            sqlx::query_as(sqlx::AssertSqlSafe(format!(
                "{scoped} SELECT count(*) {FILTERED}"
            ))),
            None,
        )
        .fetch_one(&state.pool)
        .await?;

    let mut facets = BTreeMap::new();
    for (name, column) in [
        ("severity", "s.severity"),
        ("category", "s.category"),
        ("status", "s.state"),
        ("component", "s.component"),
    ] {
        let sql = format!("{scoped} SELECT {column}, count(*) {FILTERED} GROUP BY 1");
        let rows: Vec<(String, i64)> = filters
            .bind(sqlx::query_as(sqlx::AssertSqlSafe(sql)), Some(name))
            .fetch_all(&state.pool)
            .await?;
        facets.insert(name, rows.into_iter().collect());
    }
    Ok(Json(Page {
        total,
        offset,
        limit,
        items,
        facets,
    }))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueDetail {
    #[serde(flatten)]
    pub issue: IssueView,
    pub rule_name: Option<&'static str>,
    pub rule_description: Option<&'static str>,
    pub noncompliant: Option<&'static str>,
    pub compliant: Option<&'static str>,
    /// The code around the issue, as of the latest analysis that saw it.
    pub code: Vec<Line>,
    pub history: Vec<Event>,
}

#[derive(Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    /// UTC, ISO 8601.
    pub at: String,
    /// A username, `api-token`, or null for changes made before users
    /// existed.
    pub actor: Option<String>,
    pub field: String,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    /// Why, for a status change that gave one.
    pub reason: Option<String>,
}

pub async fn get_issue(
    axum::extract::State(state): axum::extract::State<State>,
    Path(id): Path<i64>,
) -> Result<Json<IssueDetail>, ApiError> {
    Ok(Json(detail(&state.pool, id).await?))
}

async fn view(pool: &PgPool, id: i64) -> Result<IssueView, ApiError> {
    // One issue by id, on whatever project and branch it belongs to.
    let sql = format!(
        "WITH scoped AS (
            SELECT {DERIVED} FROM issues i JOIN projects p ON p.id = i.project_id WHERE i.id = $1
        ) SELECT {} FROM scoped s",
        view_columns()
    );
    sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or(ApiError::NotFound)
}

async fn detail(pool: &PgPool, id: i64) -> Result<IssueDetail, ApiError> {
    let issue = view(pool, id).await?;
    let source: Option<String> = sqlx::query_scalar(
        "SELECT src.content FROM issues i
         JOIN analysis_files f ON f.analysis_id = i.last_analysis_id AND f.path = i.path
         JOIN sources src ON src.sha256 = f.sha256
         WHERE i.id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    let lang = issue.language.as_deref().and_then(|l| {
        sonda_core::lang::ALL
            .iter()
            .copied()
            .find(|x: &Lang| x.name() == l)
    });
    let code = match (source, lang) {
        (Some(src), Some(lang)) => {
            let line = issue.line as usize;
            let first = line.saturating_sub(CONTEXT_LINES).max(1);
            let last = (issue.end_line as usize + CONTEXT_LINES).min(first + MAX_CODE_LINES - 1);
            highlight::highlight(lang, &src, first, last)
        }
        _ => Vec::new(),
    };
    let history: Vec<Event> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT to_char(at AT TIME ZONE 'UTC', {ISO_8601}) AS at, actor, field, old_value, new_value,
                reason
             FROM issue_events WHERE issue_id = $1 ORDER BY id"
    )))
    .bind(id)
    .fetch_all(pool)
    .await?;
    let rule = sonda_core::rules::find(&issue.rule);
    Ok(IssueDetail {
        rule_name: rule.map(|r| r.name),
        rule_description: rule.map(|r| r.description),
        noncompliant: rule.and_then(|r| r.example.as_ref()).map(|e| e.bad),
        compliant: rule.and_then(|r| r.example.as_ref()).map(|e| e.good),
        issue,
        code,
        history,
    })
}

/// A triage change. `assignee: ""` unassigns; an absent field is unchanged.
/// `reason` comes with a status: required for accepted and false positive
/// (ADR-0014), optional for confirmed.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Patch {
    status: Option<String>,
    assignee: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

/// Statuses a person sets; `fixed` is decided by analyses.
const SETTABLE: &[&str] = &["open", "confirmed", "accepted", "false_positive"];

/// Decisions that take an issue out of the counts and the gate (ADR-0014).
pub(crate) const DECIDED: &[&str] = &["accepted", "false_positive"];

pub async fn patch_issue(
    axum::extract::State(state): axum::extract::State<State>,
    axum::extract::Extension(caller): axum::extract::Extension<crate::api::Caller>,
    Path(id): Path<i64>,
    Json(patch): Json<Patch>,
) -> Result<Json<IssueDetail>, ApiError> {
    let actor = caller.name().to_string();
    if let Some(s) = &patch.status
        && !SETTABLE.contains(&s.as_str())
    {
        return Err(ApiError::Unprocessable(format!(
            "status {s:?} cannot be set; use open, confirmed, accepted or false_positive \
             (fixed is decided by analyses)"
        )));
    }
    let reason = match patch.reason.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(r) if r.chars().count() <= 500 && !r.chars().any(|c| c.is_control() && c != '\n') => {
            Some(r.to_string())
        }
        Some(_) => {
            return Err(ApiError::Unprocessable(
                "a reason has at most 500 characters".into(),
            ));
        }
    };
    match patch.status.as_deref() {
        Some(s) if DECIDED.contains(&s) && reason.is_none() => {
            return Err(ApiError::Unprocessable(format!(
                "say why: {} needs a reason",
                s.replace('_', " ")
            )));
        }
        None | Some("open") if reason.is_some() => {
            return Err(ApiError::Unprocessable(
                "a reason goes with confirmed, accepted or false_positive".into(),
            ));
        }
        _ => {}
    }
    let assignee = match patch.assignee.as_deref().map(str::trim) {
        None => None,
        Some("") => Some(None),
        Some(a) if a.chars().count() <= 100 && !a.chars().any(char::is_control) => {
            Some(Some(a.to_string()))
        }
        Some(_) => {
            return Err(ApiError::Unprocessable(
                "assignee must be at most 100 characters, without control characters".into(),
            ));
        }
    };

    let mut tx = state.pool.begin().await?;
    let current: Option<(String, Option<String>)> =
        sqlx::query_as("SELECT status::text, assignee FROM issues WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    let (old_status, old_assignee) = current.ok_or(ApiError::NotFound)?;
    // A new reason for the same decision is recorded too.
    let status_changed = patch
        .status
        .as_ref()
        .is_some_and(|s| *s != old_status || reason.is_some());
    if let Some(new) = patch.status.filter(|_| status_changed) {
        sqlx::query("UPDATE issues SET status = $2::issue_status, reason = $3 WHERE id = $1")
            .bind(id)
            .bind(&new)
            .bind(&reason)
            .execute(&mut *tx)
            .await?;
        record(
            &mut tx,
            id,
            &actor,
            "status",
            Some(old_status),
            Some(new),
            reason,
        )
        .await?;
    }
    if let Some(new) = assignee.filter(|a| *a != old_assignee) {
        sqlx::query("UPDATE issues SET assignee = $2 WHERE id = $1")
            .bind(id)
            .bind(&new)
            .execute(&mut *tx)
            .await?;
        record(&mut tx, id, &actor, "assignee", old_assignee, new, None).await?;
    }
    tx.commit().await?;
    // Decided issues leave the counts, so the branch's gate may change.
    if status_changed {
        let (project, branch): (i64, String) =
            sqlx::query_as("SELECT project_id, branch FROM issues WHERE id = $1")
                .bind(id)
                .fetch_one(&state.pool)
                .await?;
        crate::new_code::recount(&state.pool, project, &branch).await?;
    }
    Ok(Json(detail(&state.pool, id).await?))
}

async fn record(
    tx: &mut sqlx::PgConnection,
    id: i64,
    actor: &str,
    field: &str,
    old: Option<String>,
    new: Option<String>,
    reason: Option<String>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO issue_events (issue_id, actor, field, old_value, new_value, reason)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(actor)
    .bind(field)
    .bind(old)
    .bind(new)
    .bind(reason)
    .execute(tx)
    .await?;
    Ok(())
}
