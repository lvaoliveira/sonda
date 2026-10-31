//! Components: a project's top-level directories. `GET /api/components`
//! lists them across projects (each project's main branch);
//! `GET /api/projects/{key}/components/{component}` is one of them on one
//! branch, with its files, owners and an eight-week trend of open issues.
//!
//! Nothing records monorepo layouts or dependencies between components, so
//! a component is simply a top-level directory (`.` for files at the root).

use crate::api::ApiError;
use crate::health::{DAY, component_of, rfc3339};
use crate::http::State;
use axum::Json;
use axum::extract::{Path, Query};
use serde::{Deserialize, Serialize};
use sonda_core::codeowners::CodeOwners;
use std::collections::{BTreeMap, HashMap};

/// Weekly points in the open-issues trend, ending now.
const TREND_WEEKS: usize = 8;

#[derive(Serialize)]
pub struct LanguageShare {
    pub id: String,
    pub ncloc: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComponentRow {
    pub path: String,
    pub languages: Vec<String>,
    pub files: usize,
    pub ncloc: i64,
    pub owner: Option<String>,
    /// Open and confirmed issues.
    pub issues: i64,
    pub debt_minutes: i64,
}

pub(crate) fn language_shares(files: &[(String, String, i64)]) -> Vec<LanguageShare> {
    let mut totals: BTreeMap<&str, i64> = BTreeMap::new();
    for (_, language, ncloc) in files {
        *totals.entry(language).or_default() += ncloc;
    }
    let mut shares: Vec<LanguageShare> = totals
        .into_iter()
        .map(|(id, ncloc)| LanguageShare {
            id: id.to_string(),
            ncloc,
        })
        .collect();
    shares.sort_by(|a, b| b.ncloc.cmp(&a.ncloc).then_with(|| a.id.cmp(&b.id)));
    shares
}

pub(crate) fn components(
    files: &[(String, String, i64)],
    issues: &[(String, String, String, i32)],
    codeowners: Option<&str>,
) -> Vec<ComponentRow> {
    let owners = codeowners.map(CodeOwners::parse);
    let mut by_component: BTreeMap<&str, Vec<&(String, String, i64)>> = BTreeMap::new();
    for f in files {
        by_component.entry(component_of(&f.0)).or_default().push(f);
    }
    let mut open: HashMap<&str, (i64, i64)> = HashMap::new();
    for (path, _, _, effort) in issues {
        let e = open.entry(component_of(path)).or_default();
        e.0 += 1;
        e.1 += i64::from(*effort);
    }
    let mut rows: Vec<ComponentRow> = by_component
        .into_iter()
        .map(|(path, files)| {
            let languages =
                language_shares(&files.iter().map(|f| (*f).clone()).collect::<Vec<_>>())
                    .into_iter()
                    .map(|l| l.id)
                    .collect();
            let (issues, debt_minutes) = open.get(path).copied().unwrap_or_default();
            ComponentRow {
                path: path.to_string(),
                languages,
                files: files.len(),
                ncloc: files.iter().map(|f| f.2).sum(),
                owner: owners
                    .as_ref()
                    .and_then(|o| o.majority(files.iter().map(|f| f.0.as_str()))),
                issues,
                debt_minutes,
            }
        })
        .collect();
    // Most issues first, then the largest.
    rows.sort_by(|a, b| {
        b.issues
            .cmp(&a.issues)
            .then_with(|| b.ncloc.cmp(&a.ncloc))
            .then_with(|| a.path.cmp(&b.path))
    });
    rows
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListQuery {
    project: Option<String>,
}

#[derive(Serialize)]
pub struct ComponentList {
    pub components: Vec<ProjectComponent>,
    /// Every owner of any listed component, for filters.
    pub owners: Vec<String>,
}

#[derive(Serialize)]
pub struct ProjectComponent {
    pub project: String,
    #[serde(flatten)]
    pub component: ComponentRow,
}

/// A file, as each project's latest analysis lists it.
type FileRow = (String, String, i64);
/// An open issue: path, category, severity, effort.
type OpenIssue = (String, String, String, i32);

pub async fn list_components(
    axum::extract::State(state): axum::extract::State<State>,
    Query(q): Query<ListQuery>,
) -> Result<Json<ComponentList>, ApiError> {
    let pool = &state.pool;
    let latest: Vec<(i64, String, i64, Option<String>)> = sqlx::query_as(
        "SELECT p.id, p.key, a.id, a.codeowners
         FROM projects p
         JOIN LATERAL (SELECT id, codeowners FROM analyses a WHERE a.project_id = p.id
                         AND a.branch = p.main_branch ORDER BY a.id DESC LIMIT 1) a ON true
         WHERE $1::text IS NULL OR p.key = $1
         ORDER BY p.key",
    )
    .bind(&q.project)
    .fetch_all(pool)
    .await?;
    let analyses: Vec<i64> = latest.iter().map(|r| r.2).collect();
    let projects: Vec<i64> = latest.iter().map(|r| r.0).collect();
    let file_rows: Vec<(i64, String, String, i64)> = sqlx::query_as(
        "SELECT analysis_id, path, language, coalesce((metrics->>'ncloc')::bigint, 0)
         FROM analysis_files WHERE analysis_id = ANY($1)",
    )
    .bind(&analyses)
    .fetch_all(pool)
    .await?;
    let issue_rows: Vec<(i64, String, String, String, i32)> = sqlx::query_as(
        "SELECT i.project_id, i.path, i.category, i.severity, i.effort_minutes FROM issues i
         JOIN projects p ON p.id = i.project_id AND i.branch = p.main_branch
         WHERE i.project_id = ANY($1) AND i.fixed_analysis_id IS NULL
           AND i.status NOT IN ('accepted', 'false_positive')",
    )
    .bind(&projects)
    .fetch_all(pool)
    .await?;
    let mut files: HashMap<i64, Vec<FileRow>> = HashMap::new();
    for (analysis, path, language, ncloc) in file_rows {
        files
            .entry(analysis)
            .or_default()
            .push((path, language, ncloc));
    }
    let mut issues: HashMap<i64, Vec<OpenIssue>> = HashMap::new();
    for (project, path, category, severity, effort) in issue_rows {
        issues
            .entry(project)
            .or_default()
            .push((path, category, severity, effort));
    }
    let mut components = Vec::new();
    for (project, key, analysis, codeowners) in latest {
        let rows = self::components(
            files.get(&analysis).map_or(&[][..], Vec::as_slice),
            issues.get(&project).map_or(&[][..], Vec::as_slice),
            codeowners.as_deref(),
        );
        components.extend(rows.into_iter().map(|component| ProjectComponent {
            project: key.clone(),
            component,
        }));
    }
    let mut owners: Vec<String> = components
        .iter()
        .filter_map(|c| c.component.owner.clone())
        .collect();
    owners.sort();
    owners.dedup();
    Ok(Json(ComponentList { components, owners }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetailQuery {
    branch: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComponentDetail {
    pub project: String,
    pub branch: String,
    pub main_branch: String,
    pub path: String,
    pub analyzed_at: String,
    pub languages: Vec<LanguageShare>,
    pub files: usize,
    pub ncloc: i64,
    /// Whoever owns most of its files, under CODEOWNERS.
    pub owner: Option<String>,
    /// Every owner of any of its files, with how many files each owns.
    pub owners: Vec<OwnerShare>,
    pub issues: IssueBreakdown,
    /// The project's other components, for navigation.
    pub siblings: Vec<ComponentRow>,
    /// Open issues at the end of each of the last eight weeks, oldest first.
    pub trend: Vec<TrendPoint>,
    pub file_list: Vec<ComponentFile>,
}

#[derive(Serialize)]
pub struct OwnerShare {
    pub owner: String,
    pub files: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueBreakdown {
    /// Open and confirmed.
    pub total: i64,
    /// Found on new code.
    pub new: i64,
    pub by_severity: BTreeMap<String, i64>,
    pub by_category: BTreeMap<String, i64>,
    pub debt_minutes: i64,
}

#[derive(Serialize)]
pub struct TrendPoint {
    pub date: String,
    pub open: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComponentFile {
    pub path: String,
    pub language: String,
    pub ncloc: i64,
    pub issues: i64,
    pub debt_minutes: i64,
    /// The most severe open issue's severity.
    pub worst: Option<String>,
}

const SEVERITIES: [&str; 5] = ["blocker", "critical", "major", "minor", "info"];

fn rank(severity: &str) -> usize {
    SEVERITIES
        .iter()
        .position(|s| *s == severity)
        .unwrap_or(SEVERITIES.len())
}

type IssueHistory = (String, String, String, i32, bool, bool, f64, Option<f64>);

pub async fn get_component(
    axum::extract::State(state): axum::extract::State<State>,
    Path((key, component)): Path<(String, String)>,
    Query(q): Query<DetailQuery>,
) -> Result<Json<ComponentDetail>, ApiError> {
    let pool = &state.pool;
    let (project, main_branch): (i64, String) =
        sqlx::query_as("SELECT id, main_branch FROM projects WHERE key = $1")
            .bind(&key)
            .fetch_optional(pool)
            .await?
            .ok_or(ApiError::NotFound)?;
    let branch = q.branch.unwrap_or_else(|| main_branch.clone());
    let (analysis, at, codeowners, now): (i64, f64, Option<String>, f64) = sqlx::query_as(
        "SELECT id, extract(epoch FROM received_at)::float8, codeowners,
                extract(epoch FROM now())::float8
         FROM analyses WHERE project_id = $1 AND branch = $2 ORDER BY id DESC LIMIT 1",
    )
    .bind(project)
    .bind(&branch)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| ApiError::BadRequest(format!("branch {branch:?} has no analyses")))?;
    let files: Vec<FileRow> = sqlx::query_as(
        "SELECT path, language, coalesce((metrics->>'ncloc')::bigint, 0)
         FROM analysis_files WHERE analysis_id = $1 ORDER BY path",
    )
    .bind(analysis)
    .fetch_all(pool)
    .await?;
    // Every issue the branch has tracked: path, category, severity, effort,
    // new code, accepted, when first seen and when fixed.
    let history: Vec<IssueHistory> = sqlx::query_as(
        "SELECT i.path, i.category, i.severity, i.effort_minutes, i.is_new,
                i.status IN ('accepted', 'false_positive'), extract(epoch FROM fa.received_at)::float8,
                extract(epoch FROM xa.received_at)::float8
         FROM issues i
         JOIN analyses fa ON fa.id = i.first_analysis_id
         LEFT JOIN analyses xa ON xa.id = i.fixed_analysis_id
         WHERE i.project_id = $1 AND i.branch = $2",
    )
    .bind(project)
    .bind(&branch)
    .fetch_all(pool)
    .await?;
    let open: Vec<&IssueHistory> = history.iter().filter(|i| i.7.is_none() && !i.5).collect();
    let open_tuples: Vec<OpenIssue> = open
        .iter()
        .map(|i| (i.0.clone(), i.1.clone(), i.2.clone(), i.3))
        .collect();
    let siblings = components(&files, &open_tuples, codeowners.as_deref());
    let row = siblings
        .iter()
        .find(|c| c.path == component)
        .ok_or(ApiError::NotFound)?;

    let mine = |path: &str| component_of(path) == component;
    let own_files: Vec<FileRow> = files.iter().filter(|f| mine(&f.0)).cloned().collect();
    let co = codeowners.as_deref().map(CodeOwners::parse);
    let mut owner_counts: BTreeMap<String, usize> = BTreeMap::new();
    if let Some(co) = &co {
        for f in &own_files {
            for o in co.owners(&f.0).unwrap_or(&[]) {
                *owner_counts.entry(o.clone()).or_default() += 1;
            }
        }
    }
    let mut owners: Vec<OwnerShare> = owner_counts
        .into_iter()
        .map(|(owner, files)| OwnerShare { owner, files })
        .collect();
    owners.sort_by(|a, b| b.files.cmp(&a.files).then_with(|| a.owner.cmp(&b.owner)));

    let own_open: Vec<&&IssueHistory> = open.iter().filter(|i| mine(&i.0)).collect();
    let mut issues = IssueBreakdown {
        total: own_open.len() as i64,
        new: own_open.iter().filter(|i| i.4).count() as i64,
        by_severity: BTreeMap::new(),
        by_category: BTreeMap::new(),
        debt_minutes: own_open.iter().map(|i| i64::from(i.3)).sum(),
    };
    let mut per_file: HashMap<&str, (i64, i64, Option<&str>)> = HashMap::new();
    for i in &own_open {
        *issues.by_severity.entry(i.2.clone()).or_default() += 1;
        *issues.by_category.entry(i.1.clone()).or_default() += 1;
        let e = per_file.entry(i.0.as_str()).or_default();
        e.0 += 1;
        e.1 += i64::from(i.3);
        if e.2.is_none_or(|w| rank(&i.2) < rank(w)) {
            e.2 = Some(i.2.as_str());
        }
    }
    let mut file_list: Vec<ComponentFile> = own_files
        .iter()
        .map(|(path, language, ncloc)| {
            let (issues, debt_minutes, worst) =
                per_file.get(path.as_str()).copied().unwrap_or_default();
            ComponentFile {
                path: path.clone(),
                language: language.clone(),
                ncloc: *ncloc,
                issues,
                debt_minutes,
                worst: worst.map(str::to_string),
            }
        })
        .collect();
    file_list.sort_by(|a, b| b.issues.cmp(&a.issues).then_with(|| a.path.cmp(&b.path)));

    // Accepted issues are left out throughout, as in the open count.
    let trend = (0..TREND_WEEKS)
        .rev()
        .map(|weeks_ago| {
            let t = now - weeks_ago as f64 * 7.0 * DAY;
            TrendPoint {
                date: rfc3339(t),
                open: history
                    .iter()
                    .filter(|i| mine(&i.0) && !i.5 && i.6 <= t && i.7.is_none_or(|fixed| fixed > t))
                    .count(),
            }
        })
        .collect();

    Ok(Json(ComponentDetail {
        project: key,
        branch,
        main_branch,
        path: component.clone(),
        analyzed_at: rfc3339(at),
        languages: language_shares(&own_files),
        files: own_files.len(),
        ncloc: row.ncloc,
        owner: row.owner.clone(),
        owners,
        issues,
        siblings,
        trend,
        file_list,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn components_group_files_issues_and_owners() {
        let file = |p: &str, l: &str, n: i64| (p.to_string(), l.to_string(), n);
        let files = [
            file("api/a.js", "javascript", 100),
            file("api/b.ts", "typescript", 300),
            file("web/c.ts", "typescript", 50),
            file("README.js", "javascript", 1),
        ];
        let issue = |p: &str, e: i32| (p.to_string(), "bug".to_string(), "major".to_string(), e);
        let issues = [issue("web/c.ts", 5), issue("web/c.ts", 10)];
        let rows = components(&files, &issues, Some("/api/ @team-api\n"));
        let paths: Vec<_> = rows.iter().map(|r| r.path.as_str()).collect();
        assert_eq!(paths, ["web", "api", "."]);
        assert_eq!((rows[0].issues, rows[0].debt_minutes), (2, 15));
        assert_eq!(rows[1].languages, ["typescript", "javascript"]);
        assert_eq!(rows[1].owner.as_deref(), Some("@team-api"));
        assert_eq!(rows[0].owner, None);
    }
}
