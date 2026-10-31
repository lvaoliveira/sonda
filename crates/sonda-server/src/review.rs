//! `GET /api/security/review`: the security review queue (ADR-0014). Open
//! vulnerabilities to decide on, most severe first, with how far the review
//! has come. Decisions are made with the issue triage endpoint.

use crate::api::ApiError;
use crate::health::rfc3339;
use crate::http::State;
use axum::Json;
use axum::extract::Query;
use serde::{Deserialize, Serialize};
use sonda_core::rules::Edition;

/// Rows returned at once; filters narrow the rest.
const MAX_ITEMS: usize = 200;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewQuery {
    /// A project key; every project without one.
    project: Option<String>,
    /// A branch of `project`; each project's main branch without one.
    branch: Option<String>,
    /// `open` (the default), `confirmed`, `accepted`, `false_positive` or
    /// `all`.
    status: Option<String>,
    /// Comma-separated severities.
    severity: Option<String>,
    /// An OWASP Top 10 category id, `A01` to `A10`, in `edition`.
    owasp: Option<String>,
    /// `2021` or `2025` (the default).
    edition: Option<String>,
    /// A username.
    assignee: Option<String>,
    /// Only findings on new code.
    #[serde(default)]
    new: bool,
}

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Progress {
    pub open: usize,
    pub confirmed: usize,
    pub accepted: usize,
    pub false_positive: usize,
    /// Share of findings that aren't open, 0-100; null without findings.
    pub reviewed: Option<u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Category {
    pub id: &'static str,
    pub title: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub id: i64,
    pub project: String,
    pub branch: String,
    pub rule: String,
    pub rule_name: Option<&'static str>,
    pub message: String,
    pub severity: String,
    pub file: String,
    pub line: i32,
    pub is_new: bool,
    pub detected_at: String,
    pub status: String,
    pub assignee: Option<String>,
    pub reason: Option<String>,
    pub cwe: &'static [u16],
    /// In the query's edition.
    pub owasp: Vec<Category>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Review {
    /// Over every finding in scope, whatever the other filters.
    pub progress: Progress,
    /// The same, on new code only.
    pub new_code: Progress,
    /// Findings matching every filter; `items` holds the first ones.
    pub total: usize,
    pub items: Vec<Finding>,
}

type Row = (
    i64,
    String,
    String,
    String,
    String,
    String,
    String,
    i32,
    bool,
    String,
    Option<String>,
    Option<String>,
    f64,
);

pub async fn get_review(
    axum::extract::State(state): axum::extract::State<State>,
    Query(q): Query<ReviewQuery>,
) -> Result<Json<Review>, ApiError> {
    let bad = |m: &str| ApiError::BadRequest(m.into());
    let status = q.status.as_deref().unwrap_or("open");
    if !["open", "confirmed", "accepted", "false_positive", "all"].contains(&status) {
        return Err(bad(
            "status is open, confirmed, accepted, false_positive or all",
        ));
    }
    let edition = match q.edition.as_deref() {
        None | Some("2025") => Edition::Y2025,
        Some("2021") => Edition::Y2021,
        Some(_) => return Err(bad("edition is 2021 or 2025")),
    };
    if q.branch.is_some() && q.project.is_none() {
        return Err(bad("a branch needs a project"));
    }
    let severities: Option<Vec<&str>> = q.severity.as_deref().map(|s| s.split(',').collect());

    let rows: Vec<Row> = sqlx::query_as(
        "SELECT i.id, p.key, i.branch, i.rule, i.message, i.severity, i.path, i.line, i.is_new,
                i.status::text, i.assignee, i.reason, extract(epoch FROM fa.received_at)::float8
         FROM issues i JOIN projects p ON p.id = i.project_id
         JOIN analyses fa ON fa.id = i.first_analysis_id
         WHERE i.category = 'vulnerability' AND i.fixed_analysis_id IS NULL
           AND ($1::text IS NULL OR p.key = $1)
           AND i.branch = coalesce($2, p.main_branch)",
    )
    .bind(&q.project)
    .bind(&q.branch)
    .fetch_all(&state.pool)
    .await?;

    let progress = |new_only: bool| {
        let mut p = Progress::default();
        for r in rows.iter().filter(|r| !new_only || r.8) {
            match r.9.as_str() {
                "open" => p.open += 1,
                "confirmed" => p.confirmed += 1,
                "accepted" => p.accepted += 1,
                "false_positive" => p.false_positive += 1,
                _ => {}
            }
        }
        let total = p.open + p.confirmed + p.accepted + p.false_positive;
        p.reviewed = (total > 0).then(|| (100 * (total - p.open) / total) as u32);
        p
    };
    let (all, new_code) = (progress(false), progress(true));

    let mut items: Vec<Finding> = rows
        .into_iter()
        .filter(|r| status == "all" || r.9 == status)
        .filter(|r| {
            severities
                .as_ref()
                .is_none_or(|s| s.contains(&r.5.as_str()))
        })
        .filter(|r| q.assignee.as_ref().is_none_or(|a| r.10.as_ref() == Some(a)))
        .filter(|r| !q.new || r.8)
        .map(
            |(
                id,
                project,
                branch,
                rule,
                message,
                severity,
                file,
                line,
                is_new,
                status,
                assignee,
                reason,
                at,
            )| {
                let catalog = sonda_core::rules::find(&rule);
                let standards = catalog.map(|r| r.standards()).unwrap_or_default();
                Finding {
                    id,
                    project,
                    branch,
                    rule_name: catalog.map(|r| r.name),
                    rule,
                    message,
                    severity,
                    file,
                    line,
                    is_new,
                    detected_at: rfc3339(at),
                    status,
                    assignee,
                    reason,
                    cwe: standards.cwe,
                    owasp: standards
                        .owasp(edition)
                        .iter()
                        .map(|o| Category {
                            id: o.id(),
                            title: o.title(),
                        })
                        .collect(),
                }
            },
        )
        .filter(|f| {
            q.owasp
                .as_ref()
                .is_none_or(|id| f.owasp.iter().any(|o| o.id == id))
        })
        .collect();
    // Most severe first, new code before older code, then the oldest.
    items.sort_by(|a, b| {
        rank(&a.severity)
            .cmp(&rank(&b.severity))
            .then(b.is_new.cmp(&a.is_new))
            .then(a.detected_at.cmp(&b.detected_at))
            .then(a.id.cmp(&b.id))
    });
    let total = items.len();
    items.truncate(MAX_ITEMS);
    Ok(Json(Review {
        progress: all,
        new_code,
        total,
        items,
    }))
}

fn rank(severity: &str) -> usize {
    ["blocker", "critical", "major", "minor", "info"]
        .iter()
        .position(|s| *s == severity)
        .unwrap_or(5)
}
