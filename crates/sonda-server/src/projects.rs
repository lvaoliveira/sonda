//! `GET /api/projects`: every project as of its main branch's latest
//! analysis. `GET /api/projects/{key}`: one project on one branch, with its
//! gate, measures, history and components.
//!
//! Ratings follow ADR-0005 and are computed as the Overview computes them
//! (see `health`), from the issue tracker: accepted issues don't count.

use crate::api::ApiError;
use crate::components::{ComponentRow, LanguageShare, components, language_shares};
use crate::health::{
    GateDetail, Measures, ago, conditions, coverage_level, debt_level, gate_state, measure_set,
    project_score, rfc3339, severity_level,
};
use crate::http::State;
use axum::Json;
use axum::extract::{Path, Query};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

/// Analyses the project page charts.
const HISTORY: i64 = 12;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectList {
    pub projects: Vec<ProjectRow>,
    /// Every language in any project, most code first, for the filters.
    pub languages: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectRow {
    pub key: String,
    /// The display name (ADR-0017); null shows the key alone.
    pub name: Option<String>,
    pub main_branch: String,
    /// Languages by lines of code, most first.
    pub languages: Vec<String>,
    pub gate: &'static str,
    pub score: u32,
    pub reliability: u8,
    pub security: u8,
    pub maintainability: u8,
    pub coverage: Option<f64>,
    pub duplication: Option<f64>,
    /// Open and confirmed issues on the main branch.
    pub issues: i64,
    pub ncloc: f64,
    pub analyzed_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectDetail {
    pub key: String,
    /// The display name (ADR-0017); null shows the key alone.
    pub name: Option<String>,
    pub main_branch: String,
    pub branch: String,
    pub branches: Vec<BranchRow>,
    pub languages: Vec<LanguageShare>,
    pub analysis: AnalysisRef,
    pub gate: GateDetail,
    pub score: u32,
    pub ratings: Ratings,
    /// The analysis's own measures, overall and on new code.
    pub measures: Measures,
    /// The branch's latest analyses, oldest first.
    pub history: Vec<HistoryPoint>,
    /// Top-level directories.
    pub components: Vec<ComponentRow>,
    /// From the analysis's lockfiles; null when it recorded none.
    pub dependencies: Option<crate::dependencies::Summary>,
    /// On the main branch, where new code starts (ADR-0011); null on other
    /// branches, whose new code is what their scans compared with.
    pub new_code_period: Option<crate::new_code::Period>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BranchRow {
    pub name: String,
    pub gate: &'static str,
    pub ago: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisRef {
    pub id: i64,
    pub sha: String,
    pub analyzed_at: String,
    pub ago: String,
    pub tool_version: String,
    pub new_code_reference: Option<String>,
    /// The project's version it was uploaded with.
    pub version: Option<String>,
}

#[derive(Serialize)]
pub struct Ratings {
    pub reliability: u8,
    pub security: u8,
    pub maintainability: u8,
    /// Null without coverage.
    pub coverage: Option<u8>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryPoint {
    pub id: i64,
    pub sha: String,
    pub analyzed_at: String,
    pub version: Option<String>,
    pub gate: &'static str,
    pub issues: Option<f64>,
    pub coverage: Option<f64>,
    pub duplication: Option<f64>,
    pub debt_minutes: Option<f64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectQuery {
    branch: Option<String>,
}

type LatestRow = (
    i64,
    String,
    Option<String>,
    String,
    i64,
    f64,
    Value,
    Value,
    bool,
);

pub async fn list_projects(
    axum::extract::State(state): axum::extract::State<State>,
) -> Result<Json<ProjectList>, ApiError> {
    let pool = &state.pool;
    let latest: Vec<LatestRow> = sqlx::query_as(
        "SELECT p.id, p.key, p.name, p.main_branch, a.id, extract(epoch FROM a.received_at)::float8,
                a.measures, a.gate, a.gate_passed
         FROM projects p
         JOIN LATERAL (SELECT * FROM analyses a WHERE a.project_id = p.id
                         AND a.branch = p.main_branch
                       ORDER BY a.id DESC LIMIT 1) a ON true
         ORDER BY p.key",
    )
    .fetch_all(pool)
    .await?;
    let analysis_ids: Vec<i64> = latest.iter().map(|r| r.4).collect();
    let languages: Vec<(i64, String, i64)> = sqlx::query_as(
        "SELECT analysis_id, language, sum((metrics->>'ncloc')::bigint)::bigint
         FROM analysis_files WHERE analysis_id = ANY($1)
         GROUP BY analysis_id, language ORDER BY 3 DESC, 2",
    )
    .bind(&analysis_ids)
    .fetch_all(pool)
    .await?;
    let mut by_analysis: HashMap<i64, Vec<String>> = HashMap::new();
    let mut totals: BTreeMap<String, i64> = BTreeMap::new();
    for (analysis, language, ncloc) in languages {
        *totals.entry(language.clone()).or_default() += ncloc;
        by_analysis.entry(analysis).or_default().push(language);
    }
    let open = open_issue_stats(pool).await?;

    let projects = latest
        .into_iter()
        .map(
            |(project, key, name, main_branch, analysis, at, measures, gate, passed)| {
                let stats = open.get(&project);
                let ratings = ratings(&measures, stats);
                let coverage = measures["coverage"].as_f64();
                ProjectRow {
                    key,
                    name,
                    main_branch,
                    languages: by_analysis.remove(&analysis).unwrap_or_default(),
                    gate: gate_state(passed, &gate),
                    score: score(&ratings, coverage),
                    reliability: ratings.reliability,
                    security: ratings.security,
                    maintainability: ratings.maintainability,
                    coverage,
                    duplication: measures["duplicated_lines_density"].as_f64(),
                    issues: stats.map_or(0, |s| s.count),
                    ncloc: measures["ncloc"].as_f64().unwrap_or(0.0),
                    analyzed_at: rfc3339(at),
                }
            },
        )
        .collect();
    let mut languages: Vec<(String, i64)> = totals.into_iter().collect();
    languages.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    Ok(Json(ProjectList {
        projects,
        languages: languages.into_iter().map(|(l, _)| l).collect(),
    }))
}

type AnalysisRow = (
    i64,
    String,
    f64,
    String,
    Option<String>,
    Value,
    Value,
    bool,
    Option<String>,
    Option<String>,
);

pub async fn get_project(
    axum::extract::State(state): axum::extract::State<State>,
    Path(key): Path<String>,
    Query(q): Query<ProjectQuery>,
) -> Result<Json<ProjectDetail>, ApiError> {
    let pool = &state.pool;
    let (project, name, main_branch): (i64, Option<String>, String) =
        sqlx::query_as("SELECT id, name, main_branch FROM projects WHERE key = $1")
            .bind(&key)
            .fetch_optional(pool)
            .await?
            .ok_or(ApiError::NotFound)?;
    let branch = q.branch.unwrap_or_else(|| main_branch.clone());
    let now: f64 = sqlx::query_scalar("SELECT extract(epoch FROM now())::float8")
        .fetch_one(pool)
        .await?;

    let branches: Vec<(String, f64, Value, bool)> = sqlx::query_as(
        "SELECT DISTINCT ON (branch) branch, extract(epoch FROM received_at)::float8, gate,
                gate_passed
         FROM analyses WHERE project_id = $1 ORDER BY branch, id DESC",
    )
    .bind(project)
    .fetch_all(pool)
    .await?;
    let mut branches: Vec<BranchRow> = branches
        .into_iter()
        .map(|(name, at, gate, passed)| BranchRow {
            gate: gate_state(passed, &gate),
            ago: ago(now - at),
            name,
        })
        .collect();
    // The main branch first, then by name.
    branches.sort_by_key(|b| (b.name != main_branch, b.name.clone()));

    let mut recent: Vec<AnalysisRow> = sqlx::query_as(
        "SELECT id, commit_sha, extract(epoch FROM received_at)::float8, tool_version,
                new_code_reference, measures, gate, gate_passed, codeowners, project_version
         FROM analyses WHERE project_id = $1 AND branch = $2 ORDER BY id DESC LIMIT $3",
    )
    .bind(project)
    .bind(&branch)
    .bind(HISTORY)
    .fetch_all(pool)
    .await?;
    if recent.is_empty() {
        return Err(ApiError::BadRequest(format!(
            "branch {branch:?} has no analyses; analyzed branches: {}",
            branches
                .iter()
                .map(|b| b.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    recent.reverse();
    let history = recent
        .iter()
        .map(
            |(id, sha, at, _, _, measures, gate, passed, _, version)| HistoryPoint {
                id: *id,
                sha: sha.clone(),
                analyzed_at: rfc3339(*at),
                version: version.clone(),
                gate: gate_state(*passed, gate),
                issues: measures["issues"].as_f64(),
                coverage: measures["coverage"].as_f64(),
                duplication: measures["duplicated_lines_density"].as_f64(),
                debt_minutes: measures["debt_minutes"].as_f64(),
            },
        )
        .collect();
    let (
        analysis,
        sha,
        at,
        tool_version,
        new_code_reference,
        measures,
        gate,
        passed,
        codeowners,
        version,
    ) = recent.pop().expect("checked non-empty");

    let files: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT path, language, coalesce((metrics->>'ncloc')::bigint, 0)
         FROM analysis_files WHERE analysis_id = $1 ORDER BY path",
    )
    .bind(analysis)
    .fetch_all(pool)
    .await?;
    let issues: Vec<(String, String, String, i32)> = sqlx::query_as(
        "SELECT path, category, severity, effort_minutes FROM issues
         WHERE project_id = $1 AND branch = $2 AND fixed_analysis_id IS NULL
           AND status NOT IN ('accepted', 'false_positive') AND NOT rule_off(project_id, rule)",
    )
    .bind(project)
    .bind(&branch)
    .fetch_all(pool)
    .await?;

    let stats = issue_stats(issues.iter().map(|(_, c, s, _)| (c.as_str(), s.as_str())));
    let ratings = ratings(&measures, Some(&stats));
    let coverage = measures["coverage"].as_f64();
    let score = score(&ratings, coverage);
    let languages = language_shares(&files);
    let components = components(&files, &issues, codeowners.as_deref());
    let dependencies = crate::dependencies::summary(pool, project, analysis).await?;
    let new_code_period = if branch == main_branch {
        crate::new_code::period(pool, project).await?
    } else {
        None
    };

    Ok(Json(ProjectDetail {
        key,
        name,
        main_branch,
        branch,
        branches,
        languages,
        analysis: AnalysisRef {
            id: analysis,
            sha,
            analyzed_at: rfc3339(at),
            ago: ago(now - at),
            tool_version,
            new_code_reference,
            version,
        },
        gate: GateDetail {
            state: gate_state(passed, &gate),
            conditions: conditions(&gate),
        },
        score,
        ratings,
        measures: Measures {
            overall: measure_set(&measures, ""),
            new_code: measure_set(&measures, "new_"),
        },
        history,
        components,
        dependencies,
        new_code_period,
    }))
}

// ------------------------------------------------------------- building

/// What ratings need from a project's open issues.
#[derive(Default)]
struct IssueStats {
    count: i64,
    worst_bug: Option<String>,
    worst_vulnerability: Option<String>,
}

const SEVERITIES: [&str; 5] = ["blocker", "critical", "major", "minor", "info"];

fn worse(current: &mut Option<String>, severity: &str) {
    let rank = |s: &str| {
        SEVERITIES
            .iter()
            .position(|x| *x == s)
            .unwrap_or(SEVERITIES.len())
    };
    if current.as_deref().is_none_or(|c| rank(severity) < rank(c)) {
        *current = Some(severity.to_string());
    }
}

fn issue_stats<'a>(issues: impl Iterator<Item = (&'a str, &'a str)>) -> IssueStats {
    let mut stats = IssueStats::default();
    for (category, severity) in issues {
        stats.count += 1;
        match category {
            "bug" => worse(&mut stats.worst_bug, severity),
            "vulnerability" => worse(&mut stats.worst_vulnerability, severity),
            _ => {}
        }
    }
    stats
}

/// Open issues on each project's main branch.
async fn open_issue_stats(pool: &sqlx::PgPool) -> Result<HashMap<i64, IssueStats>, sqlx::Error> {
    let rows: Vec<(i64, String, String)> = sqlx::query_as(
        "SELECT i.project_id, i.category, i.severity FROM issues i
         JOIN projects p ON p.id = i.project_id AND i.branch = p.main_branch
         WHERE i.fixed_analysis_id IS NULL AND i.status NOT IN ('accepted', 'false_positive')
           AND NOT rule_off(i.project_id, i.rule)",
    )
    .fetch_all(pool)
    .await?;
    let mut grouped: HashMap<i64, Vec<(String, String)>> = HashMap::new();
    for (project, category, severity) in rows {
        grouped
            .entry(project)
            .or_default()
            .push((category, severity));
    }
    Ok(grouped
        .into_iter()
        .map(|(project, issues)| {
            let stats = issue_stats(issues.iter().map(|(c, s)| (c.as_str(), s.as_str())));
            (project, stats)
        })
        .collect())
}

fn ratings(measures: &Value, stats: Option<&IssueStats>) -> Ratings {
    let ncloc = measures["ncloc"].as_f64().unwrap_or(0.0).max(1.0);
    let debt = measures["debt_minutes"].as_f64().unwrap_or(0.0);
    Ratings {
        reliability: severity_level(stats.and_then(|s| s.worst_bug.as_deref())),
        security: severity_level(stats.and_then(|s| s.worst_vulnerability.as_deref())),
        maintainability: debt_level(debt / (ncloc * 30.0)),
        coverage: measures["coverage"].as_f64().map(coverage_level),
    }
}

fn score(r: &Ratings, coverage: Option<f64>) -> u32 {
    project_score([r.reliability, r.security, r.maintainability], coverage).round() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_worst_open_issue_sets_the_rating() {
        let stats = issue_stats(
            [
                ("bug", "minor"),
                ("bug", "critical"),
                ("code_smell", "blocker"),
            ]
            .into_iter(),
        );
        assert_eq!(stats.count, 3);
        assert_eq!(stats.worst_bug.as_deref(), Some("critical"));
        assert_eq!(stats.worst_vulnerability, None);
    }
}
