//! `GET /api/rules`: sonda's rule catalog with live counts. Read-only: rules
//! are configured in each repository's sonda.toml, not on the server.

use crate::api::ApiError;
use crate::http::State;
use axum::Json;
use serde::Serialize;
use sonda_core::lang::{ALL, Lang};
use sonda_core::model::Category;
use sonda_core::rules::RULES;
use std::collections::HashMap;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Catalog {
    pub total: usize,
    pub languages: Vec<LanguageCount>,
    pub rules: Vec<RuleView>,
}

#[derive(Serialize)]
pub struct LanguageCount {
    /// As in reports (`javascript`, `tsx`, ...); the web app names them.
    pub id: &'static str,
    pub rules: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleView {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    /// Language ids, as in reports.
    pub languages: Vec<&'static str>,
    pub category: Category,
    pub severity: sonda_core::model::Severity,
    pub effort_minutes: u32,
    /// Open or confirmed issues on each project's main branch.
    pub open_issues: i64,
    /// Projects with at least one of those.
    pub projects: i64,
    pub tags: Vec<&'static str>,
    pub noncompliant: Option<&'static str>,
    pub compliant: Option<&'static str>,
}

pub async fn list(
    axum::extract::State(state): axum::extract::State<State>,
) -> Result<Json<Catalog>, ApiError> {
    let rows: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT i.rule, count(*), count(DISTINCT i.project_id)
         FROM issues i JOIN projects p ON p.id = i.project_id AND i.branch = p.main_branch
         WHERE i.fixed_analysis_id IS NULL AND i.status IN ('open', 'confirmed')
         GROUP BY i.rule",
    )
    .fetch_all(&state.pool)
    .await?;
    let counts: HashMap<String, (i64, i64)> = rows
        .into_iter()
        .map(|(rule, n, p)| (rule, (n, p)))
        .collect();

    let rules = RULES
        .iter()
        .map(|r| {
            let (open_issues, projects) = counts.get(r.id).copied().unwrap_or_default();
            let mut tags = vec![r.category.as_str()];
            if r.category == Category::Vulnerability {
                tags.push("security");
            }
            RuleView {
                id: r.id,
                name: r.name,
                description: r.description,
                languages: r.langs().iter().map(|l| l.name()).collect(),
                category: r.category,
                severity: r.severity,
                effort_minutes: r.effort_minutes,
                open_issues,
                projects,
                tags,
                noncompliant: r.example.as_ref().map(|e| e.bad),
                compliant: r.example.as_ref().map(|e| e.good),
            }
        })
        .collect();
    let languages = ALL
        .iter()
        .map(|&lang: &Lang| LanguageCount {
            id: lang.name(),
            rules: RULES.iter().filter(|r| r.langs().contains(&lang)).count(),
        })
        .collect();
    Ok(Json(Catalog {
        total: RULES.len(),
        languages,
        rules,
    }))
}
