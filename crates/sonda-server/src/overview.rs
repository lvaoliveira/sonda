//! `GET /api/overview`: the portfolio built from stored analyses (ADR-0005,
//! phase 3). Every number comes from analyses the server received; what it
//! cannot know (teams, components, commit messages, durations) is null, never
//! made up.
//!
//! A point in time is a snapshot: each project's latest main-branch analysis
//! received by then. Charts are series of snapshots, daily for 7 and 30
//! days and weekly for 90.

use crate::api::ApiError;
use crate::health::{
    self, DAY, ago, condition_label, coverage_level, debt_level, debt_text, iso_date, plural,
};
use crate::http::State;
use axum::Json;
use axum::extract::Query;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverviewQuery {
    range: Option<String>,
    scope: Option<String>,
}

// ------------------------------------------------------------- response

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Overview {
    /// Teams do not exist yet, so the "My team" scope is not offered.
    pub teams: bool,
    pub summary: Summary,
    pub focus: Vec<FocusItem>,
    pub focus_total: usize,
    pub health: Health,
    pub kpis: Vec<Kpi>,
    pub flow: Vec<FlowBucket>,
    pub severities: Vec<SeverityCount>,
    pub projects: Vec<ProjectHealth>,
    pub project_total: usize,
    pub gate_history: GateHistory,
    pub recent: Vec<AnalysisSummary>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub projects: usize,
    pub components: Option<usize>,
    pub last_sounding: String,
}

#[derive(Serialize)]
pub struct FocusItem {
    pub severity: &'static str,
    pub tag: String,
    pub title: String,
    pub body: String,
    pub trail: Vec<Crumb>,
    pub cta: &'static str,
    pub drill: &'static str,
}

#[derive(Serialize)]
pub struct Crumb {
    pub text: String,
    pub emphasis: &'static str,
}

#[derive(Serialize)]
pub struct Health {
    /// Mean of the dimensions with data, 0-100.
    pub score: u32,
    /// Change over the range; null until ratings history is kept.
    pub delta: Option<String>,
    pub dimensions: Vec<Dimension>,
}

#[derive(Serialize)]
pub struct Dimension {
    pub label: &'static str,
    /// 1 (worst) to 5; null without data (coverage never uploaded).
    pub level: Option<u8>,
    pub score: Option<u32>,
    pub note: String,
    pub drill: &'static str,
}

#[derive(Serialize)]
pub struct Kpi {
    pub metric: &'static str,
    pub label: &'static str,
    pub value: String,
    pub unit: &'static str,
    pub delta: String,
    pub improving: bool,
    pub sub: String,
    pub series: Vec<f64>,
}

#[derive(Serialize)]
pub struct FlowBucket {
    pub date: String,
    pub introduced: u32,
    pub resolved: u32,
    pub open: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SeverityCount {
    pub severity: &'static str,
    pub open: u32,
    pub new_this_period: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectHealth {
    pub name: String,
    pub sub: String,
    pub gate: &'static str,
    pub reliability: u8,
    pub security: u8,
    pub maintainability: u8,
    pub coverage: Option<f64>,
    pub new_issues: u32,
    /// Issues found by each daily snapshot over the last 30 days.
    pub trend: Vec<f64>,
}

#[derive(Serialize)]
pub struct GateHistory {
    /// Percent of main-branch analyses in the range that passed.
    pub rate: Option<u32>,
    /// Points against the previous range of the same length.
    pub delta: Option<i32>,
    pub days: Vec<GateDay>,
    pub failing: Vec<FailingCondition>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GateDay {
    pub date: String,
    /// Null on days without an analysis.
    pub pass_rate: Option<u32>,
}

#[derive(Serialize)]
pub struct FailingCondition {
    pub label: String,
    pub failures: u32,
}

#[derive(Serialize)]
pub struct AnalysisSummary {
    pub id: i64,
    pub state: &'static str,
    pub project: String,
    pub branch: String,
    pub sha: String,
    /// Commit messages are not uploaded.
    pub message: Option<String>,
    pub note: String,
    /// Scan durations are not uploaded.
    pub duration: Option<String>,
    pub ago: String,
}

// ---------------------------------------------------------------- loading

/// One stored analysis, as far as the overview needs it.
struct Analysis {
    project: i64,
    key: String,
    branch: String,
    sha: String,
    at: f64,
    measures: Value,
    gate: Value,
    passed: bool,
}

impl Analysis {
    fn m(&self, name: &str) -> f64 {
        self.measures[name].as_f64().unwrap_or(0.0)
    }

    fn coverage(&self) -> Option<f64> {
        self.measures["coverage"].as_f64()
    }

    /// Labels of the gate conditions that failed, and of those without data.
    fn conditions(&self, status: &str) -> Vec<String> {
        self.gate["conditions"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|c| c["status"] == status)
            .map(condition_label)
            .collect()
    }
}

/// A main-branch issue: when it appeared and was fixed.
struct TrackedIssue {
    project: i64,
    severity: String,
    category: String,
    accepted: bool,
    first_at: f64,
    fixed_at: Option<f64>,
    /// Found by the branch's first analysis: the baseline, not "new" or
    /// "introduced", or uploading a project would look like a flood.
    baseline: bool,
}

type IssueRow = (i64, String, String, bool, f64, Option<f64>, bool);

/// A new blocker or critical issue: project, severity, message, path, line,
/// and when it was first seen.
type SevereRow = (i64, String, String, String, i32, f64);

type AnalysisRow = (i64, String, String, String, f64, Value, Value, bool);

/// An analysis id, then the same columns as `AnalysisRow`.
type RecentRow = (i64, i64, String, String, String, f64, Value, Value, bool);

pub async fn get_overview(
    axum::extract::State(state): axum::extract::State<State>,
    Query(q): Query<OverviewQuery>,
) -> Result<Json<Overview>, ApiError> {
    let days: u32 = match q.range.as_deref() {
        Some("7d") => 7,
        Some("30d") => 30,
        Some("90d") | None => 90,
        Some(other) => {
            return Err(ApiError::BadRequest(format!(
                "unknown range {other:?}; use 7d, 30d or 90d"
            )));
        }
    };
    if q.scope.as_deref().is_some_and(|s| s != "all") {
        return Err(ApiError::BadRequest(
            "teams do not exist yet; the only scope is all".into(),
        ));
    }
    let pool = &state.pool;
    let now: f64 = sqlx::query_scalar("SELECT extract(epoch FROM now())::float8")
        .fetch_one(pool)
        .await?;
    // Twice the range, for the previous-range comparison, and at least the
    // 30 days the trends and gate history show.
    let horizon = f64::from((2 * days).max(30)) * DAY;
    let rows: Vec<AnalysisRow> = sqlx::query_as(
        "SELECT p.id, p.key, a.branch, a.commit_sha, extract(epoch FROM a.received_at)::float8,
                a.measures, a.gate, a.gate_passed
         FROM analyses a JOIN projects p ON p.id = a.project_id AND a.branch = p.main_branch
         WHERE a.received_at >= to_timestamp($1)
            OR a.id = (SELECT max(b.id) FROM analyses b
                       WHERE b.project_id = p.id AND b.branch = p.main_branch
                         AND b.received_at < to_timestamp($1))
         ORDER BY a.received_at, a.id",
    )
    .bind(now - horizon)
    .fetch_all(pool)
    .await?;
    let analyses: Vec<Analysis> = rows
        .into_iter()
        .map(
            |(project, key, branch, sha, at, measures, gate, passed)| Analysis {
                project,
                key,
                branch,
                sha,
                at,
                measures,
                gate,
                passed,
            },
        )
        .collect();
    let issues: Vec<TrackedIssue> = sqlx::query_as::<_, IssueRow>(
        "SELECT i.project_id, i.severity, i.category, i.status = 'accepted',
                extract(epoch FROM fa.received_at)::float8,
                extract(epoch FROM xa.received_at)::float8,
                i.first_analysis_id = (SELECT min(b.id) FROM analyses b
                                       WHERE b.project_id = i.project_id AND b.branch = i.branch)
         FROM issues i
         JOIN projects p ON p.id = i.project_id AND i.branch = p.main_branch
         JOIN analyses fa ON fa.id = i.first_analysis_id
         LEFT JOIN analyses xa ON xa.id = i.fixed_analysis_id",
    )
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(
        |(project, severity, category, accepted, first_at, fixed_at, baseline)| TrackedIssue {
            project,
            severity,
            category,
            accepted,
            first_at,
            fixed_at,
            baseline,
        },
    )
    .collect();
    let new_severe: Vec<SevereRow> = sqlx::query_as(
        "SELECT i.project_id, i.severity, i.message, i.path, i.line,
                extract(epoch FROM fa.received_at)::float8
         FROM issues i
         JOIN projects p ON p.id = i.project_id AND i.branch = p.main_branch
         JOIN analyses fa ON fa.id = i.first_analysis_id
         WHERE i.fixed_analysis_id IS NULL AND i.status <> 'accepted'
           AND i.severity IN ('blocker', 'critical') AND fa.received_at >= to_timestamp($1)
           AND i.first_analysis_id <> (SELECT min(b.id) FROM analyses b
                                       WHERE b.project_id = i.project_id AND b.branch = i.branch)
         ORDER BY array_position(ARRAY['blocker', 'critical'], i.severity), fa.received_at DESC",
    )
    .bind(now - f64::from(days) * DAY)
    .fetch_all(pool)
    .await?;
    let recent: Vec<RecentRow> = sqlx::query_as(
        "SELECT a.id, p.id, p.key, a.branch, a.commit_sha, extract(epoch FROM a.received_at)::float8,
                a.measures, a.gate, a.gate_passed
         FROM analyses a JOIN projects p ON p.id = a.project_id
         ORDER BY a.received_at DESC, a.id DESC LIMIT 8",
    )
    .fetch_all(pool)
    .await?;

    Ok(Json(build(
        now,
        days,
        &analyses,
        &issues,
        &new_severe,
        recent,
    )))
}

// --------------------------------------------------------------- building

fn build(
    now: f64,
    days: u32,
    analyses: &[Analysis],
    issues: &[TrackedIssue],
    new_severe: &[SevereRow],
    recent: Vec<RecentRow>,
) -> Overview {
    let window_start = now - f64::from(days) * DAY;
    let points = points(now, days);
    let snapshots: Vec<Vec<&Analysis>> = points.iter().map(|&t| snapshot(analyses, t)).collect();
    let latest = snapshot(analyses, now);
    let ratings = ratings(&latest, issues);

    let mut projects: Vec<ProjectHealth> = latest
        .iter()
        .map(|a| {
            let r = &ratings.by_project[&a.project];
            ProjectHealth {
                name: a.key.clone(),
                sub: format!("{} · {} ago", a.branch, ago(now - a.at)),
                gate: gate_state(a),
                reliability: r.reliability,
                security: r.security,
                maintainability: r.maintainability,
                coverage: a.coverage(),
                new_issues: a.m("new_issues") as u32,
                trend: (0..30)
                    .map(|k| now - f64::from(29 - k) * DAY)
                    .map(|t| {
                        snapshot(analyses, t)
                            .iter()
                            .find(|s| s.project == a.project)
                            .map_or(0.0, |s| s.m("issues"))
                    })
                    .collect(),
            }
        })
        .collect();
    // Lowest scores first, as the table's subtitle says.
    projects.sort_by(|a, b| {
        project_score(a)
            .partial_cmp(&project_score(b))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.name.cmp(&b.name))
    });
    let project_total = projects.len();
    projects.truncate(10);

    let mut focus = focus_items(now, &latest, analyses, new_severe);
    let focus_total = focus.len();
    focus.truncate(4);

    Overview {
        teams: false,
        summary: Summary {
            projects: latest.len(),
            components: None,
            last_sounding: latest
                .iter()
                .map(|a| a.at)
                .fold(None, |m: Option<f64>, t| Some(m.map_or(t, |m| m.max(t))))
                .map_or_else(|| "never".into(), |t| format!("{} ago", ago(now - t))),
        },
        focus,
        focus_total,
        health: ratings.health,
        kpis: kpis(&snapshots),
        flow: flow(&points, step(days), issues),
        severities: ["blocker", "critical", "major", "minor", "info"]
            .into_iter()
            .map(|severity| {
                let open = issues
                    .iter()
                    .filter(|i| i.severity == severity && i.fixed_at.is_none() && !i.accepted);
                SeverityCount {
                    severity,
                    open: open.clone().count() as u32,
                    new_this_period: open
                        .filter(|i| !i.baseline && i.first_at >= window_start)
                        .count() as u32,
                }
            })
            .collect(),
        projects,
        project_total,
        gate_history: gate_history(now, days, analyses),
        recent: recent
            .into_iter()
            .map(
                |(id, project, key, branch, sha, at, measures, gate, passed)| {
                    let a = Analysis {
                        project,
                        key,
                        branch,
                        sha,
                        at,
                        measures,
                        gate,
                        passed,
                    };
                    let failed = a.conditions("error");
                    let no_data = a.conditions("no_data");
                    let note = if let Some(first) = failed.first() {
                        format!("Gate failed: {first}{}", more(failed.len()))
                    } else if let Some(first) = no_data.first() {
                        format!("No data for: {first}{}", more(no_data.len()))
                    } else {
                        match a.m("new_issues") as u32 {
                            0 => "No new issues".into(),
                            1 => "1 new issue".into(),
                            n => format!("{n} new issues"),
                        }
                    };
                    AnalysisSummary {
                        id,
                        state: gate_state(&a),
                        project: a.key,
                        branch: a.branch,
                        sha: a.sha.chars().take(7).collect(),
                        message: None,
                        note,
                        duration: None,
                        ago: ago(now - a.at),
                    }
                },
            )
            .collect(),
    }
}

fn more(n: usize) -> String {
    if n > 1 {
        format!(" (+{})", n - 1)
    } else {
        String::new()
    }
}

/// Passed, failed, or partial: passed with some condition lacking data.
fn gate_state(a: &Analysis) -> &'static str {
    health::gate_state(a.passed, &a.gate)
}

fn step(days: u32) -> f64 {
    if days > 30 { 7.0 * DAY } else { DAY }
}

/// Snapshot times, oldest first, ending now.
fn points(now: f64, days: u32) -> Vec<f64> {
    let (n, step) = if days > 30 {
        (13, 7.0 * DAY)
    } else {
        (days, DAY)
    };
    (0..n).map(|k| now - f64::from(n - 1 - k) * step).collect()
}

/// Each project's latest analysis received at or before `t`.
fn snapshot(analyses: &[Analysis], t: f64) -> Vec<&Analysis> {
    let mut latest: BTreeMap<i64, &Analysis> = BTreeMap::new();
    // `analyses` is sorted by arrival, so later entries win.
    for a in analyses.iter().take_while(|a| a.at <= t) {
        latest.insert(a.project, a);
    }
    latest.into_values().collect()
}

// ---------------------------------------------------------------- ratings

struct ProjectRatings {
    reliability: u8,
    security: u8,
    maintainability: u8,
}

struct Ratings {
    by_project: HashMap<i64, ProjectRatings>,
    health: Health,
}

/// ADR-0005's rating table. Reliability and security: the worst open bug
/// or vulnerability (accepted ones excluded); none is 5, minor 4, major 3,
/// critical 2, blocker 1. Maintainability: debt ratio, debt / (ncloc x 30
/// min). Coverage: percent. Portfolio levels weight projects by ncloc.
fn ratings(latest: &[&Analysis], issues: &[TrackedIssue]) -> Ratings {
    let worst = |project: i64, category: &str| -> u8 {
        issues
            .iter()
            .filter(|i| {
                i.project == project
                    && i.category == category
                    && i.fixed_at.is_none()
                    && !i.accepted
            })
            .map(|i| health::severity_level(Some(&i.severity)))
            .min()
            .unwrap_or(5)
    };
    let mut by_project = HashMap::new();
    let mut weighted = [(0.0, 0.0); 4]; // (sum of level x weight, sum of weights)
    let (mut debt, mut ncloc_total) = (0.0, 0.0);
    let (mut cov_sum, mut cov_weight) = (0.0, 0.0);
    for a in latest {
        let ncloc = a.m("ncloc").max(1.0);
        let ratio = a.m("debt_minutes") / (ncloc * 30.0);
        let r = ProjectRatings {
            reliability: worst(a.project, "bug"),
            security: worst(a.project, "vulnerability"),
            maintainability: debt_level(ratio),
        };
        for (slot, level) in [r.reliability, r.security, r.maintainability]
            .into_iter()
            .enumerate()
        {
            weighted[slot].0 += f64::from(level) * ncloc;
            weighted[slot].1 += ncloc;
        }
        if let Some(c) = a.coverage() {
            weighted[3].0 += f64::from(coverage_level(c)) * ncloc;
            weighted[3].1 += ncloc;
            cov_sum += c * ncloc;
            cov_weight += ncloc;
        }
        debt += a.m("debt_minutes");
        ncloc_total += ncloc;
        by_project.insert(a.project, r);
    }
    let level = |slot: usize| (weighted[slot].1 > 0.0).then(|| weighted[slot].0 / weighted[slot].1);
    let open = |category: &'static str| {
        issues
            .iter()
            .filter(move |i| i.category == category && i.fixed_at.is_none() && !i.accepted)
    };
    let bugs = open("bug").count();
    let severe_bugs = open("bug")
        .filter(|i| i.severity == "blocker" || i.severity == "critical")
        .count();
    let vulns = open("vulnerability").count();
    let vuln_projects = open("vulnerability")
        .map(|i| i.project)
        .collect::<std::collections::HashSet<_>>()
        .len();
    let notes = [
        format!(
            "{bugs} {} · {severe_bugs} critical or worse",
            plural(bugs, "bug", "bugs")
        ),
        format!(
            "{vulns} {} in {vuln_projects} {}",
            plural(vulns, "vulnerability", "vulnerabilities"),
            plural(vuln_projects, "project", "projects")
        ),
        format!(
            "{} debt · {:.1}% ratio",
            debt_text(debt),
            if ncloc_total > 0.0 {
                debt / (ncloc_total * 30.0) * 100.0
            } else {
                0.0
            }
        ),
        if cov_weight > 0.0 {
            format!("{:.1}% where measured", cov_sum / cov_weight)
        } else {
            "No coverage uploaded (sonda scan --coverage)".into()
        },
    ];
    let labels = [
        ("Reliability", "critical"),
        ("Security", "vulns"),
        ("Maintainability", "debt"),
        ("Coverage", "coverage"),
    ];
    let dimensions: Vec<Dimension> = labels
        .into_iter()
        .zip(notes)
        .enumerate()
        .map(|(slot, ((label, drill), note))| {
            let mean = level(slot);
            Dimension {
                label,
                level: mean.map(|m| m.round().clamp(1.0, 5.0) as u8),
                score: mean.map(|m| ((m - 1.0) / 4.0 * 100.0).round() as u32),
                note,
                drill,
            }
        })
        .collect();
    let scores: Vec<u32> = dimensions.iter().filter_map(|d| d.score).collect();
    let score = if scores.is_empty() {
        0
    } else {
        (scores.iter().sum::<u32>() as f64 / scores.len() as f64).round() as u32
    };
    Ratings {
        by_project,
        health: Health {
            score,
            delta: None,
            dimensions,
        },
    }
}

fn project_score(p: &ProjectHealth) -> f64 {
    health::project_score([p.reliability, p.security, p.maintainability], p.coverage)
}

// -------------------------------------------------------------------- KPIs

fn kpis(snapshots: &[Vec<&Analysis>]) -> Vec<Kpi> {
    let sum = |s: &[&Analysis], f: &dyn Fn(&Analysis) -> f64| s.iter().map(|a| f(a)).sum::<f64>();
    let gate = |s: &[&Analysis]| {
        (!s.is_empty())
            .then(|| s.iter().filter(|a| a.passed).count() as f64 / s.len() as f64 * 100.0)
    };
    let critical =
        |s: &[&Analysis]| Some(sum(s, &|a| a.m("blocker_issues") + a.m("critical_issues")));
    let vulns = |s: &[&Analysis]| Some(sum(s, &|a| a.m("vulnerabilities")));
    let coverage = |s: &[&Analysis]| {
        let measured: Vec<&&Analysis> = s.iter().filter(|a| a.coverage().is_some()).collect();
        let weight: f64 = measured.iter().map(|a| a.m("ncloc").max(1.0)).sum();
        (weight > 0.0).then(|| {
            measured
                .iter()
                .map(|a| a.coverage().unwrap_or(0.0) * a.m("ncloc").max(1.0))
                .sum::<f64>()
                / weight
        })
    };
    let dup = |s: &[&Analysis]| {
        let lines = sum(s, &|a| a.m("lines"));
        Some(if lines > 0.0 {
            sum(s, &|a| a.m("duplicated_lines")) / lines * 100.0
        } else {
            0.0
        })
    };
    let debt = |s: &[&Analysis]| Some(sum(s, &|a| a.m("debt_minutes")));
    // Points before any project was analyzed are left out, so a delta
    // never compares against "nothing existed yet".
    let series = |f: &dyn Fn(&[&Analysis]) -> Option<f64>| -> Vec<f64> {
        snapshots
            .iter()
            .skip_while(|s| s.is_empty())
            .filter_map(|s| f(s))
            .collect()
    };
    let now = snapshots.last().map(Vec::as_slice).unwrap_or(&[]);
    let n = now.len();

    let make = |metric,
                label,
                unit,
                value: Option<f64>,
                series: Vec<f64>,
                higher_is_better: bool,
                fmt: &dyn Fn(f64) -> String,
                delta_unit: &str,
                sub: String| {
        let change = match (series.first(), series.last()) {
            (Some(a), Some(b)) => b - a,
            _ => 0.0,
        };
        Kpi {
            metric,
            label,
            value: value.map_or_else(|| "—".into(), fmt),
            unit: if value.is_some() { unit } else { "" },
            delta: signed(change, fmt, delta_unit),
            improving: change == 0.0 || (change > 0.0) == higher_is_better,
            sub,
            series,
        }
    };
    let whole = |v: f64| format!("{v:.0}");
    let tenth = |v: f64| format!("{v:.1}");
    let passing = now.iter().filter(|a| a.passed).count();
    let vuln_projects = now.iter().filter(|a| a.m("vulnerabilities") > 0.0).count();
    let measured = now.iter().filter(|a| a.coverage().is_some()).count();
    let lines = sum(now, &|a| a.m("ncloc"));
    vec![
        make(
            "gate",
            "Gate pass rate",
            "%",
            gate(now),
            series(&gate),
            true,
            &whole,
            " pts",
            format!("{passing} of {n} {} pass", plural(n, "project", "projects")),
        ),
        make(
            "critical",
            "Critical issues",
            "",
            critical(now),
            series(&critical),
            false,
            &whole,
            "",
            "Blocker and critical, latest analyses".into(),
        ),
        make(
            "vulns",
            "Vulnerabilities",
            "",
            vulns(now),
            series(&vulns),
            false,
            &whole,
            "",
            format!(
                "In {vuln_projects} {}",
                plural(vuln_projects, "project", "projects")
            ),
        ),
        make(
            "coverage",
            "Coverage",
            "%",
            coverage(now),
            series(&coverage),
            true,
            &tenth,
            " pts",
            if measured > 0 {
                format!("{measured} of {n} projects report coverage")
            } else {
                "None uploaded: sonda scan --coverage".into()
            },
        ),
        make(
            "dup",
            "Duplication",
            "%",
            dup(now),
            series(&dup),
            false,
            &tenth,
            " pts",
            format!(
                "{:.0} duplicated lines",
                sum(now, &|a| a.m("duplicated_lines"))
            ),
        ),
        make(
            "debt",
            "Technical debt",
            "",
            debt(now),
            series(&debt),
            false,
            &|m| debt_text(m),
            "",
            format!(
                "{:.1}% debt ratio",
                if lines > 0.0 {
                    debt(now).unwrap_or(0.0) / (lines * 30.0) * 100.0
                } else {
                    0.0
                }
            ),
        ),
    ]
}

/// "+3 pts", "−12", or "no change". Uses a real minus sign, as the design does.
fn signed(change: f64, fmt: &dyn Fn(f64) -> String, unit: &str) -> String {
    let text = fmt(change.abs());
    if text.trim_start_matches(['0', '.']).is_empty() || fmt(0.0) == text {
        return "no change".into();
    }
    format!("{}{text}{unit}", if change > 0.0 { "+" } else { "−" })
}

// --------------------------------------------------------- flow, gates, focus

fn flow(points: &[f64], step: f64, issues: &[TrackedIssue]) -> Vec<FlowBucket> {
    points
        .iter()
        .map(|&end| {
            let start = end - step;
            let within = |t: f64| t > start && t <= end;
            FlowBucket {
                date: iso_date(start + 1.0),
                introduced: issues
                    .iter()
                    .filter(|i| !i.baseline && within(i.first_at))
                    .count() as u32,
                resolved: issues
                    .iter()
                    .filter(|i| i.fixed_at.is_some_and(within))
                    .count() as u32,
                open: issues
                    .iter()
                    .filter(|i| i.first_at <= end && i.fixed_at.is_none_or(|f| f > end))
                    .count() as u32,
            }
        })
        .collect()
}

fn gate_history(now: f64, days: u32, analyses: &[Analysis]) -> GateHistory {
    let range = f64::from(days) * DAY;
    let rate = |from: f64, to: f64| {
        let within: Vec<&Analysis> = analyses
            .iter()
            .filter(|a| a.at > from && a.at <= to)
            .collect();
        (!within.is_empty()).then(|| {
            (within.iter().filter(|a| a.passed).count() as f64 / within.len() as f64 * 100.0)
                .round() as u32
        })
    };
    let current = rate(now - range, now);
    let previous = rate(now - 2.0 * range, now - range);
    let mut failing: BTreeMap<String, u32> = BTreeMap::new();
    for a in analyses.iter().filter(|a| a.at > now - range) {
        for label in a.conditions("error") {
            *failing.entry(label).or_default() += 1;
        }
    }
    let mut failing: Vec<FailingCondition> = failing
        .into_iter()
        .map(|(label, failures)| FailingCondition { label, failures })
        .collect();
    failing.sort_by(|a, b| {
        b.failures
            .cmp(&a.failures)
            .then_with(|| a.label.cmp(&b.label))
    });
    failing.truncate(4);
    GateHistory {
        rate: current,
        delta: current.zip(previous).map(|(c, p)| c as i32 - p as i32),
        days: (0..30)
            .map(|k| {
                let end = now - f64::from(29 - k) * DAY;
                GateDay {
                    date: iso_date(end - DAY + 1.0),
                    pass_rate: rate(end - DAY, end),
                }
            })
            .collect(),
        failing,
    }
}

/// What needs attention, most severe first: projects whose main branch
/// fails its gate, then new blocker or critical issues of the range.
fn focus_items(
    now: f64,
    latest: &[&Analysis],
    analyses: &[Analysis],
    new_severe: &[SevereRow],
) -> Vec<FocusItem> {
    let mut items = Vec::new();
    for a in latest.iter().filter(|a| !a.passed) {
        let failed = a.conditions("error");
        // Consecutive failing analyses, newest first.
        let streak = analyses
            .iter()
            .rev()
            .filter(|b| b.project == a.project)
            .take_while(|b| !b.passed)
            .count();
        let first = failed
            .first()
            .cloned()
            .unwrap_or_else(|| "a condition".into());
        let drill = a.gate["conditions"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|c| c["status"] == "error")
            .map_or("gate", |c| drill_for(c["metric"].as_str().unwrap_or("")));
        items.push((
            0,
            FocusItem {
                severity: "critical",
                tag: format!(
                    "Blocks {} · {} {}",
                    a.branch,
                    streak,
                    plural(streak, "analysis", "analyses")
                ),
                title: format!("{} is failing its quality gate", a.key),
                body: format!(
                    "{}{}.",
                    first,
                    if failed.len() > 1 {
                        format!(", and {} more", failed.len() - 1)
                    } else {
                        String::new()
                    }
                ),
                trail: vec![
                    Crumb {
                        text: a.key.clone(),
                        emphasis: "muted",
                    },
                    Crumb {
                        text: a.branch.clone(),
                        emphasis: "strong",
                    },
                    Crumb {
                        text: format!("{} ago", ago(now - a.at)),
                        emphasis: "faint",
                    },
                ],
                cta: "Review",
                drill,
            },
        ));
    }
    let key_of = |project: i64| {
        latest
            .iter()
            .find(|a| a.project == project)
            .map_or_else(String::new, |a| a.key.clone())
    };
    let mut by_project: Vec<(i64, Vec<&SevereRow>)> = Vec::new();
    for issue in new_severe {
        match by_project.iter_mut().find(|(p, _)| *p == issue.0) {
            Some((_, list)) => list.push(issue),
            None => by_project.push((issue.0, vec![issue])),
        }
    }
    for (project, list) in by_project {
        // Sorted blockers first, newest first: the first is the headline.
        let head = list[0];
        let severity = if list.iter().any(|i| i.1 == "blocker") {
            "blocker"
        } else {
            "critical"
        };
        items.push((
            if severity == "blocker" { 1 } else { 2 },
            FocusItem {
                severity,
                tag: format!("New · {} ago", ago(now - head.5)),
                title: format!(
                    "{} new {} {} in {}",
                    list.len(),
                    severity,
                    plural(list.len(), "issue", "issues"),
                    key_of(project)
                ),
                body: format!("{} ({}:{})", head.2, head.3, head.4),
                trail: vec![
                    Crumb {
                        text: key_of(project),
                        emphasis: "muted",
                    },
                    Crumb {
                        text: head.3.clone(),
                        emphasis: "strong",
                    },
                ],
                cta: "Open",
                drill: "critical",
            },
        ));
    }
    items.sort_by_key(|(rank, _)| *rank);
    items.into_iter().map(|(_, item)| item).collect()
}

fn drill_for(metric: &str) -> &'static str {
    match metric {
        m if m.contains("vulnerabilit") => "vulns",
        m if m.contains("coverage") => "coverage",
        m if m.contains("duplicat") => "dup",
        m if m.contains("debt") => "debt",
        m if m.contains("blocker") || m.contains("critical") || m.contains("bug") => "critical",
        _ => "gate",
    }
}

// ----------------------------------------------------------------- formats

#[cfg(test)]
mod tests {
    #[test]
    fn deltas_are_signed_or_no_change() {
        let whole = |v: f64| format!("{v:.0}");
        let tenth = |v: f64| format!("{v:.1}");
        assert_eq!(signed(3.0, &whole, " pts"), "+3 pts");
        assert_eq!(signed(-12.0, &whole, ""), "−12");
        assert_eq!(signed(0.0, &whole, ""), "no change");
        assert_eq!(signed(0.04, &tenth, " pts"), "no change");
    }

    #[test]
    fn conditions_point_at_their_drill_down() {
        assert_eq!(drill_for("new_vulnerabilities"), "vulns");
        assert_eq!(drill_for("new_critical_issues"), "critical");
    }

    use super::*;
}
