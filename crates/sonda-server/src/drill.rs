//! `GET /api/drill/{metric}`: what is behind one Overview metric, by
//! component (a project's top-level directory) and file, from each
//! project's main branch. Owners come from the CODEOWNERS file uploaded
//! with each project's latest analysis; null without one.

use crate::api::ApiError;
use crate::health::component_of;
use crate::http::State;
use axum::Json;
use axum::extract::{Path, Query};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sonda_core::codeowners::CodeOwners;
use std::collections::{BTreeMap, HashMap};

const MAX_ITEMS: usize = 8;
const MAX_FILES: usize = 5;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DrillQuery {
    scope: Option<String>,
}

#[derive(Serialize)]
pub struct Drill {
    pub metric: &'static str,
    pub title: String,
    pub sub: String,
    pub tone: &'static str,
    pub cta: &'static str,
    pub unit: &'static str,
    /// Lower values are worse (coverage).
    pub invert: bool,
    pub items: Vec<DrillComponent>,
}

#[derive(Serialize)]
pub struct DrillComponent {
    pub component: String,
    pub project: String,
    pub owner: Option<String>,
    pub value: f64,
    pub files: Vec<DrillFile>,
}

#[derive(Serialize)]
pub struct DrillFile {
    pub dir: String,
    pub base: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issue: Option<DrillIssue>,
}

#[derive(Serialize)]
pub struct DrillIssue {
    pub severity: String,
    pub title: String,
    pub line: i32,
}

pub async fn get_drill(
    axum::extract::State(state): axum::extract::State<State>,
    Path(metric): Path<String>,
    Query(q): Query<DrillQuery>,
) -> Result<Json<Drill>, ApiError> {
    if q.scope.as_deref().is_some_and(|s| s != "all") {
        return Err(ApiError::BadRequest(
            "teams do not exist yet; the only scope is all".into(),
        ));
    }
    let pool = &state.pool;
    let owners = owners(pool).await?;
    let drill = match metric.as_str() {
        "critical" => {
            let rows = open_issues(pool, Some(&["blocker", "critical"]), None, None).await?;
            let total = rows.len();
            by_component(
                rows,
                Measure::Count,
                &owners,
                Drill {
                    metric: "critical",
                    title: format!(
                        "{total} blocker & critical {}",
                        plural(total, "issue", "issues")
                    ),
                    sub: "Open on each project's main branch, by top-level directory.".into(),
                    tone: "crit",
                    cta: "Triage in issue explorer",
                    unit: "",
                    invert: false,
                    items: vec![],
                },
            )
        }
        "vulns" => {
            let rows = open_issues(pool, None, Some("vulnerability"), None).await?;
            let total = rows.len();
            let mut per_severity: BTreeMap<usize, (String, usize)> = BTreeMap::new();
            for r in &rows {
                per_severity
                    .entry(rank(&r.severity))
                    .or_insert((r.severity.clone(), 0))
                    .1 += 1;
            }
            let breakdown: Vec<String> = per_severity
                .into_values()
                .map(|(s, n)| format!("{n} {s}"))
                .collect();
            by_component(
                rows,
                Measure::Count,
                &owners,
                Drill {
                    metric: "vulns",
                    title: format!(
                        "{total} open {}",
                        plural(total, "vulnerability", "vulnerabilities")
                    ),
                    sub: if breakdown.is_empty() {
                        "None open on main branches.".into()
                    } else {
                        format!("{}.", breakdown.join(" · "))
                    },
                    tone: "crit",
                    cta: "Open vulnerabilities",
                    unit: "",
                    invert: false,
                    items: vec![],
                },
            )
        }
        "debt" => {
            let rows = open_issues(pool, None, None, None).await?;
            let minutes: i64 = rows.iter().map(|r| i64::from(r.effort)).sum();
            by_component(
                rows,
                Measure::Effort,
                &owners,
                Drill {
                    metric: "debt",
                    title: format!("{} of technical debt", effort_text(minutes)),
                    sub: "Estimated effort to fix the open issues, by top-level directory.".into(),
                    tone: "warn",
                    cta: "Open code smells",
                    unit: "h",
                    invert: false,
                    items: vec![],
                },
            )
        }
        "gate" => gate(pool, &owners).await?,
        "dup" => duplication(pool, &owners).await?,
        "coverage" => coverage(pool, &owners).await?,
        other => {
            return Err(ApiError::BadRequest(format!(
                "unknown metric {other:?}; expected gate, critical, vulns, coverage, dup or debt"
            )));
        }
    };
    Ok(Json(drill))
}

// ------------------------------------------------------------------ owners

/// Owners by (project, component), and by (project, `*`) for a whole
/// project: the owners most of their files share, per the CODEOWNERS file
/// uploaded with the project's latest main-branch analysis.
type Owners = HashMap<(String, String), String>;

async fn owners(pool: &sqlx::PgPool) -> Result<Owners, sqlx::Error> {
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT p.key, last.codeowners, f.path
         FROM projects p
         JOIN LATERAL (SELECT a.id, a.codeowners FROM analyses a
                       WHERE a.project_id = p.id AND a.branch = p.main_branch
                       ORDER BY a.id DESC LIMIT 1) last ON true
         JOIN analysis_files f ON f.analysis_id = last.id
         WHERE last.codeowners IS NOT NULL
         ORDER BY p.key, f.path",
    )
    .fetch_all(pool)
    .await?;
    let mut by_project: BTreeMap<String, (String, Vec<String>)> = BTreeMap::new();
    for (project, text, path) in rows {
        by_project
            .entry(project)
            .or_insert_with(|| (text, Vec::new()))
            .1
            .push(path);
    }
    let mut owners = Owners::new();
    for (project, (text, paths)) in by_project {
        let co = CodeOwners::parse(&text);
        let mut components: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for path in &paths {
            components.entry(component_of(path)).or_default().push(path);
        }
        for (component, files) in components {
            if let Some(o) = co.majority(files) {
                owners.insert((project.clone(), component.to_string()), o);
            }
        }
        if let Some(o) = co.majority(paths.iter().map(String::as_str)) {
            owners.insert((project, "*".into()), o);
        }
    }
    Ok(owners)
}

// ------------------------------------------------------------ issue drills

struct OpenIssue {
    project: String,
    component: String,
    path: String,
    severity: String,
    message: String,
    line: i32,
    effort: i32,
}

type IssueRow = (String, String, String, String, String, i32, i32);

/// Open (not fixed, not accepted) issues on main branches. Every filter is
/// a bound parameter; null means "any".
async fn open_issues(
    pool: &sqlx::PgPool,
    severities: Option<&[&str]>,
    category: Option<&str>,
    new_in_projects: Option<&[i64]>,
) -> Result<Vec<OpenIssue>, sqlx::Error> {
    let rows: Vec<IssueRow> = sqlx::query_as(
        "SELECT p.key,
                CASE WHEN strpos(i.path, '/') > 0 THEN split_part(i.path, '/', 1) ELSE '.' END,
                i.path, i.severity, i.message, i.line, i.effort_minutes
         FROM issues i JOIN projects p ON p.id = i.project_id AND i.branch = p.main_branch
         WHERE i.fixed_analysis_id IS NULL AND i.status NOT IN ('accepted', 'false_positive')
           AND NOT rule_off(i.project_id, i.rule)
           AND ($1::text[] IS NULL OR i.severity = ANY($1))
           AND ($2::text IS NULL OR i.category = $2)
           AND ($3::bigint[] IS NULL OR (i.is_new AND p.id = ANY($3)))",
    )
    .bind(severities.map(|s| s.iter().map(|x| x.to_string()).collect::<Vec<_>>()))
    .bind(category)
    .bind(new_in_projects.map(<[i64]>::to_vec))
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(project, component, path, severity, message, line, effort)| OpenIssue {
                project,
                component,
                path,
                severity,
                message,
                line,
                effort,
            },
        )
        .collect())
}

#[derive(Clone, Copy)]
enum Measure {
    Count,
    /// Hours of effort.
    Effort,
}

/// Groups issues by (project, component), then by file: the largest first,
/// each file with its most severe issue.
fn by_component(
    rows: Vec<OpenIssue>,
    measure: Measure,
    owners: &Owners,
    mut drill: Drill,
) -> Drill {
    let weight = |r: &OpenIssue| match measure {
        Measure::Count => 1.0,
        Measure::Effort => f64::from(r.effort),
    };
    let mut groups: BTreeMap<(String, String), BTreeMap<String, Vec<&OpenIssue>>> = BTreeMap::new();
    for r in &rows {
        groups
            .entry((r.project.clone(), r.component.clone()))
            .or_default()
            .entry(r.path.clone())
            .or_default()
            .push(r);
    }
    let mut items: Vec<DrillComponent> = groups
        .into_iter()
        .map(|((project, component), files)| {
            let total: f64 = files.values().flatten().map(|r| weight(r)).sum();
            let mut files: Vec<(f64, DrillFile)> = files
                .into_iter()
                .map(|(path, issues)| {
                    let sum: f64 = issues.iter().map(|r| weight(r)).sum();
                    let worst = issues
                        .iter()
                        .min_by_key(|r| (rank(&r.severity), r.line))
                        .expect("a file group has at least one issue");
                    let (dir, base) = split_path(&path);
                    let value = match measure {
                        Measure::Count => format!(
                            "{} {}",
                            issues.len(),
                            plural(issues.len(), "issue", "issues")
                        ),
                        Measure::Effort => effort_text(sum as i64),
                    };
                    (
                        sum,
                        DrillFile {
                            dir,
                            base,
                            value,
                            issue: Some(DrillIssue {
                                severity: worst.severity.clone(),
                                title: worst.message.clone(),
                                line: worst.line,
                            }),
                        },
                    )
                })
                .collect();
            files.sort_by(|a, b| b.0.total_cmp(&a.0).then_with(|| a.1.base.cmp(&b.1.base)));
            DrillComponent {
                owner: owners.get(&(project.clone(), component.clone())).cloned(),
                component: if component == "." {
                    format!("{project} (root)")
                } else {
                    component
                },
                project,
                value: match measure {
                    Measure::Count => total,
                    Measure::Effort => (total / 60.0 * 10.0).round() / 10.0,
                },
                files: files.into_iter().take(MAX_FILES).map(|(_, f)| f).collect(),
            }
        })
        .collect();
    items.sort_by(|a, b| {
        b.value
            .total_cmp(&a.value)
            .then_with(|| a.component.cmp(&b.component))
    });
    items.truncate(MAX_ITEMS);
    drill.items = items;
    drill
}

// ------------------------------------------------------- analysis drills

type LatestRow = (i64, String, String, Value, Value, bool);

/// Each project's latest main-branch analysis.
async fn latest(pool: &sqlx::PgPool) -> Result<Vec<LatestRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT DISTINCT ON (p.id) p.id, p.key, a.branch, a.measures, a.gate, a.gate_passed
         FROM projects p JOIN analyses a ON a.project_id = p.id AND a.branch = p.main_branch
         ORDER BY p.id, a.id DESC",
    )
    .fetch_all(pool)
    .await
}

/// Projects failing their gate, by failed conditions, with the files that
/// hold the most new issues.
async fn gate(pool: &sqlx::PgPool, owners: &Owners) -> Result<Drill, sqlx::Error> {
    let failing: Vec<LatestRow> = latest(pool).await?.into_iter().filter(|r| !r.5).collect();
    let ids: Vec<i64> = failing.iter().map(|r| r.0).collect();
    let new_issues = open_issues(pool, None, None, Some(&ids)).await?;
    let mut items: Vec<DrillComponent> = failing
        .iter()
        .map(|(_, key, branch, _, gate, _)| {
            let failed = gate["conditions"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|c| c["status"] == "error")
                .count();
            let mine: Vec<OpenIssue> = new_issues
                .iter()
                .filter(|r| &r.project == key)
                .map(|r| OpenIssue {
                    project: r.project.clone(),
                    component: r.project.clone(),
                    path: r.path.clone(),
                    severity: r.severity.clone(),
                    message: r.message.clone(),
                    line: r.line,
                    effort: r.effort,
                })
                .collect();
            let files = by_component(mine, Measure::Count, &Owners::new(), empty_drill())
                .items
                .into_iter()
                .flat_map(|c| c.files)
                .take(MAX_FILES)
                .collect();
            DrillComponent {
                component: key.clone(),
                project: format!(
                    "{branch} · {failed} failing {}",
                    plural(failed, "condition", "conditions")
                ),
                owner: owners.get(&(key.clone(), "*".to_string())).cloned(),
                value: failed as f64,
                files,
            }
        })
        .collect();
    items.sort_by(|a, b| {
        b.value
            .total_cmp(&a.value)
            .then_with(|| a.component.cmp(&b.component))
    });
    items.truncate(MAX_ITEMS);
    let n = failing.len();
    Ok(Drill {
        metric: "gate",
        title: if n == 0 { "Every quality gate passes".into() } else { format!("{n} {} failing {} gate", plural(n, "project", "projects"), plural(n, "its", "their")) },
        sub: "Projects by failed conditions on their main branch, with the files holding the most new issues.".into(),
        tone: "crit",
        cta: "Open new-code issues",
        unit: "",
        invert: false,
        items,
    })
}

type FileRow = (String, String, f64, f64);

/// Duplicated lines per component and file, from the latest analyses.
async fn duplication(pool: &sqlx::PgPool, owners: &Owners) -> Result<Drill, sqlx::Error> {
    let rows: Vec<FileRow> = sqlx::query_as(
        "SELECT p.key, f.path, coalesce((f.metrics->>'lines')::float8, 0),
                coalesce((f.metrics->>'duplicated_lines')::float8, 0)
         FROM projects p
         JOIN LATERAL (SELECT a.id FROM analyses a WHERE a.project_id = p.id AND a.branch = p.main_branch
                       ORDER BY a.id DESC LIMIT 1) last ON true
         JOIN analysis_files f ON f.analysis_id = last.id",
    )
    .fetch_all(pool)
    .await?;
    let (lines, dup): (f64, f64) = rows.iter().fold((0.0, 0.0), |(l, d), r| (l + r.2, d + r.3));
    let mut groups: BTreeMap<(String, String), Vec<&FileRow>> = BTreeMap::new();
    for r in &rows {
        let component = component_of(&r.1).to_string();
        groups.entry((r.0.clone(), component)).or_default().push(r);
    }
    let mut items: Vec<DrillComponent> = groups
        .into_iter()
        .filter_map(|((project, component), files)| {
            let (l, d): (f64, f64) = files
                .iter()
                .fold((0.0, 0.0), |(l, d), r| (l + r.2, d + r.3));
            if d == 0.0 || l == 0.0 {
                return None;
            }
            let mut files: Vec<(f64, DrillFile)> = files
                .iter()
                .filter(|r| r.3 > 0.0 && r.2 > 0.0)
                .map(|r| {
                    let pct = r.3 / r.2 * 100.0;
                    let (dir, base) = split_path(&r.1);
                    (
                        pct,
                        DrillFile {
                            dir,
                            base,
                            value: format!("{pct:.1}%"),
                            issue: None,
                        },
                    )
                })
                .collect();
            files.sort_by(|a, b| b.0.total_cmp(&a.0));
            Some(DrillComponent {
                owner: owners.get(&(project.clone(), component.clone())).cloned(),
                component: if component == "." {
                    format!("{project} (root)")
                } else {
                    component
                },
                project,
                value: (d / l * 1000.0).round() / 10.0,
                files: files.into_iter().take(MAX_FILES).map(|(_, f)| f).collect(),
            })
        })
        .collect();
    items.sort_by(|a, b| b.value.total_cmp(&a.value));
    items.truncate(MAX_ITEMS);
    Ok(Drill {
        metric: "dup",
        title: format!(
            "Duplication {:.1}% of lines",
            if lines > 0.0 {
                dup / lines * 100.0
            } else {
                0.0
            }
        ),
        sub: "Directories with the largest share of duplicated lines, and their files.".into(),
        tone: "warn",
        cta: "Open code smells",
        unit: "%",
        invert: false,
        items,
    })
}

/// Coverage by project, worst first, with each project's least covered
/// files when its report carried coverage per file.
async fn coverage(pool: &sqlx::PgPool, owners: &Owners) -> Result<Drill, sqlx::Error> {
    // (project, path, covered, uncovered) for files with coverage.
    let rows: Vec<(String, String, i32, i32)> = sqlx::query_as(
        "SELECT p.key, f.path, jsonb_array_length(f.metrics->'coverage'->'covered'),
                jsonb_array_length(f.metrics->'coverage'->'uncovered')
         FROM projects p
         JOIN LATERAL (SELECT a.id FROM analyses a WHERE a.project_id = p.id AND a.branch = p.main_branch
                       ORDER BY a.id DESC LIMIT 1) last ON true
         JOIN analysis_files f ON f.analysis_id = last.id
         WHERE f.metrics ? 'coverage'",
    )
    .fetch_all(pool)
    .await?;
    let mut files: HashMap<String, Vec<(f64, i32, DrillFile)>> = HashMap::new();
    for (project, path, covered, uncovered) in rows {
        if uncovered == 0 {
            continue;
        }
        let pct = f64::from(covered) / f64::from(covered + uncovered) * 100.0;
        let (dir, base) = split_path(&path);
        files.entry(project).or_default().push((
            pct,
            uncovered,
            DrillFile {
                dir,
                base,
                value: format!("{pct:.1}%"),
                issue: None,
            },
        ));
    }
    let mut items: Vec<DrillComponent> = latest(pool)
        .await?
        .into_iter()
        .filter_map(|(_, key, branch, measures, _, _)| {
            let c = measures["coverage"].as_f64()?;
            // The least covered first; among equals, the most lines to cover.
            let mut worst = files.remove(&key).unwrap_or_default();
            worst.sort_by(|a, b| a.0.total_cmp(&b.0).then(b.1.cmp(&a.1)));
            Some(DrillComponent {
                owner: owners.get(&(key.clone(), "*".to_string())).cloned(),
                component: key,
                project: branch,
                value: (c * 10.0).round() / 10.0,
                files: worst
                    .into_iter()
                    .take(MAX_FILES)
                    .map(|(_, _, f)| f)
                    .collect(),
            })
        })
        .collect();
    items.sort_by(|a, b| a.value.total_cmp(&b.value));
    items.truncate(MAX_ITEMS);
    let empty = items.is_empty();
    Ok(Drill {
        metric: "coverage",
        title: if empty {
            "No coverage uploaded".into()
        } else {
            "Coverage by project".into()
        },
        sub: if empty {
            "Scan with sonda scan --coverage lcov.info to see coverage here.".into()
        } else {
            "Lowest first, with each project's least covered files.".into()
        },
        tone: "warn",
        cta: "Open the coverage report",
        unit: "%",
        invert: true,
        items,
    })
}

// ----------------------------------------------------------------- helpers

fn empty_drill() -> Drill {
    Drill {
        metric: "",
        title: String::new(),
        sub: String::new(),
        tone: "",
        cta: "",
        unit: "",
        invert: false,
        items: vec![],
    }
}

fn rank(severity: &str) -> usize {
    ["blocker", "critical", "major", "minor", "info"]
        .iter()
        .position(|s| *s == severity)
        .unwrap_or(5)
}

/// "src/a/b.js" → ("src/a/", "b.js").
fn split_path(path: &str) -> (String, String) {
    match path.rfind('/') {
        Some(i) => (path[..=i].to_string(), path[i + 1..].to_string()),
        None => (String::new(), path.to_string()),
    }
}

fn plural<'a>(n: usize, one: &'a str, many: &'a str) -> &'a str {
    if n == 1 { one } else { many }
}

/// "45min", "3h 20min", "12d" (8-hour days).
fn effort_text(minutes: i64) -> String {
    match minutes {
        m if m >= 480 => format!("{:.0}d", m as f64 / 480.0),
        m if m >= 60 && m % 60 == 0 => format!("{}h", m / 60),
        m if m >= 60 => format!("{}h {}min", m / 60, m % 60),
        m => format!("{m}min"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(split_path("src/a/b.js"), ("src/a/".into(), "b.js".into()));
        assert_eq!(split_path("b.js"), (String::new(), "b.js".into()));
        assert_eq!(
            [30, 60, 135, 4094].map(effort_text),
            ["30min", "1h", "2h 15min", "9d"]
        );
        assert!(rank("blocker") < rank("critical") && rank("info") < rank("unknown"));
    }
}
