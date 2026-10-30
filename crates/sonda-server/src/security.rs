//! `GET /api/security`: vulnerabilities across projects, each project's main
//! branch. What's open by severity, what to fix first, a twelve-week risk
//! trend, where vulnerabilities concentrate (projects, components, rules)
//! and how fast they get fixed.
//!
//! Hotspots, CWE/OWASP mappings and reachability are not recorded, so none
//! is reported.

use crate::api::ApiError;
use crate::health::{DAY, component_of, rfc3339};
use crate::http::State;
use axum::Json;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};

const TREND_WEEKS: usize = 12;
const FOCUS: usize = 10;
const TOP: usize = 6;

/// How much an open vulnerability weighs in the risk trend and rankings:
/// a blocker counts as two criticals, a critical as two-and-a-half majors.
fn weight(severity: &str) -> u32 {
    match severity {
        "blocker" => 10,
        "critical" => 5,
        "major" => 2,
        "minor" => 1,
        _ => 0,
    }
}

fn rank(severity: &str) -> usize {
    ["blocker", "critical", "major", "minor", "info"]
        .iter()
        .position(|s| *s == severity)
        .unwrap_or(5)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Security {
    /// Open and confirmed, by severity.
    pub open_by_severity: BTreeMap<String, usize>,
    pub open: usize,
    pub new_this_week: usize,
    pub projects_affected: usize,
    pub status: StatusCounts,
    /// The open vulnerabilities to fix first: most severe, then oldest.
    pub focus: Vec<Finding>,
    pub trend: Vec<RiskPoint>,
    pub projects: Vec<ProjectRisk>,
    pub components: Vec<ComponentRisk>,
    pub rules: Vec<RuleCount>,
    pub remediation: Remediation,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusCounts {
    pub open: usize,
    pub confirmed: usize,
    pub accepted: usize,
    pub fixed_last_30_days: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub id: i64,
    pub severity: String,
    pub rule: String,
    pub message: String,
    pub project: String,
    pub branch: String,
    pub component: String,
    pub path: String,
    pub line: i32,
    pub first_seen: String,
    pub age_days: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RiskPoint {
    pub date: String,
    pub open: usize,
    /// Open vulnerabilities weighted by severity (see `weight`).
    pub weighted: u32,
    /// Found and fixed during the week ending at `date`.
    pub introduced: usize,
    pub fixed: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectRisk {
    pub project: String,
    /// Blocker and critical.
    pub severe: usize,
    pub other: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComponentRisk {
    pub project: String,
    pub path: String,
    pub count: usize,
    pub worst: String,
    pub weighted: u32,
}

#[derive(Serialize)]
pub struct RuleCount {
    pub rule: String,
    pub count: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Remediation {
    /// Median days from first seen to fixed, over vulnerabilities fixed in
    /// the last 90 days; null when none was.
    pub median_days_severe: Option<f64>,
    pub median_days_all: Option<f64>,
    pub fixed_last_90_days: usize,
}

struct Vuln {
    id: i64,
    project: String,
    branch: String,
    severity: String,
    rule: String,
    message: String,
    path: String,
    line: i32,
    status: String,
    first_at: f64,
    fixed_at: Option<f64>,
    /// Found by the branch's first analysis: already there, not introduced.
    baseline: bool,
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
    String,
    f64,
    Option<f64>,
    bool,
);

pub async fn get_security(
    axum::extract::State(state): axum::extract::State<State>,
) -> Result<Json<Security>, ApiError> {
    let pool = &state.pool;
    let now: f64 = sqlx::query_scalar("SELECT extract(epoch FROM now())::float8")
        .fetch_one(pool)
        .await?;
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT i.id, p.key, i.branch, i.severity, i.rule, i.message, i.path, i.line,
                i.status::text, extract(epoch FROM fa.received_at)::float8,
                extract(epoch FROM xa.received_at)::float8,
                i.first_analysis_id = (SELECT min(b.id) FROM analyses b
                                       WHERE b.project_id = i.project_id AND b.branch = i.branch)
         FROM issues i
         JOIN projects p ON p.id = i.project_id AND i.branch = p.main_branch
         JOIN analyses fa ON fa.id = i.first_analysis_id
         LEFT JOIN analyses xa ON xa.id = i.fixed_analysis_id
         WHERE i.category = 'vulnerability'",
    )
    .fetch_all(pool)
    .await?;
    let vulns: Vec<Vuln> = rows
        .into_iter()
        .map(
            |(
                id,
                project,
                branch,
                severity,
                rule,
                message,
                path,
                line,
                status,
                first_at,
                fixed_at,
                baseline,
            )| Vuln {
                id,
                project,
                branch,
                severity,
                rule,
                message,
                path,
                line,
                status,
                first_at,
                fixed_at,
                baseline,
            },
        )
        .collect();
    Ok(Json(build(now, &vulns)))
}

fn median(mut values: Vec<f64>) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    values.sort_by(f64::total_cmp);
    let mid = values.len() / 2;
    Some(if values.len().is_multiple_of(2) {
        (values[mid - 1] + values[mid]) / 2.0
    } else {
        values[mid]
    })
}

fn build(now: f64, vulns: &[Vuln]) -> Security {
    // Open: present and not accepted (accepted is a decision, not a fix).
    let is_open = |v: &&Vuln| v.fixed_at.is_none() && v.status != "accepted";
    let open: Vec<&Vuln> = vulns.iter().filter(is_open).collect();

    let mut open_by_severity: BTreeMap<String, usize> = BTreeMap::new();
    for v in &open {
        *open_by_severity.entry(v.severity.clone()).or_default() += 1;
    }

    let mut focus: Vec<&Vuln> = open.clone();
    focus.sort_by(|a, b| {
        rank(&a.severity)
            .cmp(&rank(&b.severity))
            .then(a.first_at.total_cmp(&b.first_at))
            .then(a.id.cmp(&b.id))
    });
    let focus = focus
        .into_iter()
        .take(FOCUS)
        .map(|v| Finding {
            id: v.id,
            severity: v.severity.clone(),
            rule: v.rule.clone(),
            message: v.message.clone(),
            project: v.project.clone(),
            branch: v.branch.clone(),
            component: component_of(&v.path).to_string(),
            path: v.path.clone(),
            line: v.line,
            first_seen: rfc3339(v.first_at),
            age_days: ((now - v.first_at) / DAY).max(0.0) as u32,
        })
        .collect();

    let trend = (0..TREND_WEEKS)
        .rev()
        .map(|weeks_ago| {
            let end = now - weeks_ago as f64 * 7.0 * DAY;
            let start = end - 7.0 * DAY;
            let open_at: Vec<&Vuln> = vulns
                .iter()
                .filter(|v| {
                    v.status != "accepted"
                        && v.first_at <= end
                        && v.fixed_at.is_none_or(|f| f > end)
                })
                .collect();
            RiskPoint {
                date: rfc3339(end),
                open: open_at.len(),
                weighted: open_at.iter().map(|v| weight(&v.severity)).sum(),
                introduced: vulns
                    .iter()
                    .filter(|v| !v.baseline && v.first_at > start && v.first_at <= end)
                    .count(),
                fixed: vulns
                    .iter()
                    .filter(|v| v.fixed_at.is_some_and(|f| f > start && f <= end))
                    .count(),
            }
        })
        .collect();

    let mut by_project: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    for v in &open {
        let e = by_project.entry(v.project.as_str()).or_default();
        if rank(&v.severity) <= 1 {
            e.0 += 1;
        } else {
            e.1 += 1;
        }
    }
    let mut projects: Vec<ProjectRisk> = by_project
        .into_iter()
        .map(|(project, (severe, other))| ProjectRisk {
            project: project.to_string(),
            severe,
            other,
        })
        .collect();
    projects.sort_by(|a, b| {
        (b.severe, b.other)
            .cmp(&(a.severe, a.other))
            .then_with(|| a.project.cmp(&b.project))
    });

    let mut by_component: HashMap<(&str, &str), Vec<&Vuln>> = HashMap::new();
    for v in &open {
        by_component
            .entry((v.project.as_str(), component_of(&v.path)))
            .or_default()
            .push(v);
    }
    let mut components: Vec<ComponentRisk> = by_component
        .into_iter()
        .map(|((project, path), vs)| ComponentRisk {
            project: project.to_string(),
            path: path.to_string(),
            count: vs.len(),
            worst: vs
                .iter()
                .min_by_key(|v| rank(&v.severity))
                .map(|v| v.severity.clone())
                .unwrap_or_default(),
            weighted: vs.iter().map(|v| weight(&v.severity)).sum(),
        })
        .collect();
    components.sort_by(|a, b| {
        b.weighted
            .cmp(&a.weighted)
            .then_with(|| (&a.project, &a.path).cmp(&(&b.project, &b.path)))
    });
    components.truncate(TOP);

    let mut by_rule: BTreeMap<&str, usize> = BTreeMap::new();
    for v in &open {
        *by_rule.entry(v.rule.as_str()).or_default() += 1;
    }
    let mut rules: Vec<RuleCount> = by_rule
        .into_iter()
        .map(|(rule, count)| RuleCount {
            rule: rule.to_string(),
            count,
        })
        .collect();
    rules.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.rule.cmp(&b.rule)));
    rules.truncate(TOP);

    let fixed_since = |days: f64| -> Vec<&Vuln> {
        vulns
            .iter()
            .filter(|v| v.fixed_at.is_some_and(|f| f >= now - days * DAY))
            .collect()
    };
    let recent_fixes = fixed_since(90.0);
    let days_to_fix = |v: &&Vuln| (v.fixed_at.unwrap_or(now) - v.first_at) / DAY;
    let remediation = Remediation {
        median_days_severe: median(
            recent_fixes
                .iter()
                .filter(|v| rank(&v.severity) <= 1)
                .map(days_to_fix)
                .collect(),
        ),
        median_days_all: median(recent_fixes.iter().map(days_to_fix).collect()),
        fixed_last_90_days: recent_fixes.len(),
    };

    let present = vulns.iter().filter(|v| v.fixed_at.is_none());
    let status = StatusCounts {
        open: present.clone().filter(|v| v.status == "open").count(),
        confirmed: present.clone().filter(|v| v.status == "confirmed").count(),
        accepted: present.filter(|v| v.status == "accepted").count(),
        fixed_last_30_days: fixed_since(30.0).len(),
    };

    let mut affected: Vec<&str> = open.iter().map(|v| v.project.as_str()).collect();
    affected.sort_unstable();
    affected.dedup();
    Security {
        open: open.len(),
        new_this_week: open
            .iter()
            .filter(|v| !v.baseline && v.first_at > now - 7.0 * DAY)
            .count(),
        projects_affected: affected.len(),
        open_by_severity,
        status,
        focus,
        trend,
        projects,
        components,
        rules,
        remediation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vuln(
        id: i64,
        project: &str,
        path: &str,
        severity: &str,
        status: &str,
        first_days_ago: f64,
        fixed_days_ago: Option<f64>,
    ) -> Vuln {
        let now = 100.0 * DAY;
        Vuln {
            id,
            project: project.into(),
            branch: "main".into(),
            severity: severity.into(),
            rule: format!("js/{severity}-rule"),
            message: "m".into(),
            path: path.into(),
            line: 1,
            status: status.into(),
            first_at: now - first_days_ago * DAY,
            fixed_at: fixed_days_ago.map(|d| now - d * DAY),
            baseline: false,
        }
    }

    #[test]
    fn severity_then_age_decides_what_to_fix_first() {
        let now = 100.0 * DAY;
        let vulns = [
            vuln(1, "a", "src/x.js", "major", "open", 50.0, None),
            vuln(2, "a", "src/y.js", "critical", "open", 3.0, None),
            vuln(3, "b", "lib/z.js", "critical", "confirmed", 20.0, None),
            vuln(4, "b", "lib/z.js", "blocker", "accepted", 30.0, None),
            vuln(5, "b", "lib/w.js", "critical", "open", 40.0, Some(10.0)),
        ];
        let s = build(now, &vulns);
        assert_eq!(s.open, 3, "accepted and fixed are not open");
        assert_eq!(s.focus.iter().map(|f| f.id).collect::<Vec<_>>(), [3, 2, 1]);
        assert_eq!(s.focus[0].age_days, 20);
        assert_eq!(s.new_this_week, 1);
        assert_eq!(
            (s.status.open, s.status.confirmed, s.status.accepted),
            (2, 1, 1)
        );
        assert_eq!(s.status.fixed_last_30_days, 1);
        assert_eq!(s.remediation.median_days_severe, Some(30.0));
        assert_eq!(s.projects[0].project, "a");
        assert_eq!((s.projects[0].severe, s.projects[0].other), (1, 1));
        assert_eq!(s.components[0].path, "src");
        assert_eq!(s.components[0].weighted, 7);
        let last = s.trend.last().unwrap();
        assert_eq!((last.open, last.weighted, last.introduced), (3, 12, 1));
        // Ten days ago the critical in lib/w.js was still open.
        let fixed_week = &s.trend[s.trend.len() - 2];
        assert_eq!(fixed_week.fixed, 1);
    }

    #[test]
    fn medians() {
        assert_eq!(median(vec![]), None);
        assert_eq!(median(vec![3.0, 1.0, 2.0]), Some(2.0));
        assert_eq!(median(vec![4.0, 1.0, 2.0, 3.0]), Some(2.5));
    }
}
