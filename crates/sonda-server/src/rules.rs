//! `GET /api/rules`: sonda's rule catalog with live counts, and where each
//! rule is off: in repositories' sonda.toml, or on the server (ADR-0016).

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

/// A rule as the catalog describes it, the same everywhere.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleInfo {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    /// Language ids, as in reports.
    pub languages: Vec<&'static str>,
    pub category: Category,
    pub severity: sonda_core::model::Severity,
    pub effort_minutes: u32,
    /// False for rules a repository must list in `rules.enabled`.
    pub on_by_default: bool,
    /// The category, `security`, then `cwe-89`, `owasp-a05` (2025) and
    /// `owasp2021-a03` style tags.
    pub tags: Vec<String>,
    pub cwe: &'static [u16],
    /// OWASP Top 10 2025 categories, from the CWE ids.
    pub owasp2025: Vec<OwaspRef>,
    /// OWASP Top 10 2021 categories, as SonarQube reports them.
    pub owasp2021: Vec<OwaspRef>,
    pub noncompliant: Option<&'static str>,
    pub compliant: Option<&'static str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleView {
    #[serde(flatten)]
    pub info: RuleInfo,
    /// Set when the default profile turns it off (ADR-0016, ADR-0018): who,
    /// when and why.
    pub server_off: Option<crate::rule_settings::Change>,
    /// The profiles that set it, on or off, with their severity.
    pub in_profiles: Vec<crate::rule_settings::InProfile>,
    /// In how many projects it's off, by what turned it off; null when on
    /// everywhere.
    pub off_in: Option<crate::rule_settings::OffIn>,
    /// Open or confirmed issues on each project's main branch.
    pub open_issues: i64,
    /// Projects with at least one of those.
    pub projects: i64,
}

/// The catalog's description of `r`, with its tags and standards.
pub(crate) fn info(r: &sonda_core::rules::Rule) -> RuleInfo {
    let mut tags = vec![r.category.as_str()];
    if r.category == Category::Vulnerability {
        tags.push("security");
    }
    let standards = r.standards();
    let mut tags: Vec<String> = tags.into_iter().map(String::from).collect();
    tags.extend(standards.cwe.iter().map(|c| format!("cwe-{c}")));
    // `owasp-a05` is the current (2025) edition; `owasp2021-a03` the older one.
    tags.extend(
        standards
            .owasp_2025
            .iter()
            .map(|o| format!("owasp-{}", o.id().to_lowercase())),
    );
    tags.extend(
        standards
            .owasp_2021
            .iter()
            .map(|o| format!("owasp2021-{}", o.id().to_lowercase())),
    );
    RuleInfo {
        id: r.id,
        name: r.name,
        description: r.description,
        languages: r.langs().iter().map(|l| l.name()).collect(),
        category: r.category,
        severity: r.severity,
        effort_minutes: r.effort_minutes,
        on_by_default: r.on_by_default(),
        tags,
        cwe: standards.cwe,
        owasp2025: owasp_refs(standards.owasp_2025),
        owasp2021: owasp_refs(standards.owasp_2021),
        noncompliant: r.example.as_ref().map(|e| e.bad),
        compliant: r.example.as_ref().map(|e| e.good),
    }
}

#[derive(Serialize)]
pub struct OwaspRef {
    /// `A01` to `A10`.
    pub id: &'static str,
    pub title: &'static str,
}

fn owasp_refs(categories: &[sonda_core::rules::Owasp]) -> Vec<OwaspRef> {
    categories
        .iter()
        .map(|o| OwaspRef {
            id: o.id(),
            title: o.title(),
        })
        .collect()
}

pub async fn list(
    axum::extract::State(state): axum::extract::State<State>,
) -> Result<Json<Catalog>, ApiError> {
    let rows: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT i.rule, count(*), count(DISTINCT i.project_id)
         FROM issues i JOIN projects p ON p.id = i.project_id AND i.branch = p.main_branch
         WHERE i.fixed_analysis_id IS NULL AND i.status IN ('open', 'confirmed')
           AND NOT rule_off(i.project_id, i.rule)
         GROUP BY i.rule",
    )
    .fetch_all(&state.pool)
    .await?;
    let counts: HashMap<String, (i64, i64)> = rows
        .into_iter()
        .map(|(rule, n, p)| (rule, (n, p)))
        .collect();
    let overview = crate::rule_settings::rule_overview(&state.pool).await?;

    let rules = RULES
        .iter()
        .map(|r| {
            let (open_issues, projects) = counts.get(r.id).copied().unwrap_or_default();
            RuleView {
                info: info(r),
                server_off: overview.default_off.get(r.id).cloned(),
                in_profiles: overview.in_profiles.get(r.id).cloned().unwrap_or_default(),
                off_in: overview.off_in.get(r.id).copied(),
                open_issues,
                projects,
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
