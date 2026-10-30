//! `GET /api/projects/{key}/dependencies`: the packages a branch's latest
//! analysis pinned (ADR-0009), with what changed since the analysis before
//! it.

use crate::advisories::{self, Finding, Review};
use crate::api::ApiError;
use crate::health::rfc3339;
use crate::http::State;
use axum::Json;
use axum::extract::{Path, Query};
use serde::{Deserialize, Serialize};
use sonda_core::deps::{Ecosystem, package_key};
use sqlx::PgPool;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Licenses listed by count; the rest are summed as "other".
const TOP_LICENSES: usize = 8;

#[derive(Deserialize)]
pub struct DependencyQuery {
    pub branch: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DependencyList {
    pub project: String,
    pub branch: String,
    pub main_branch: String,
    pub analysis: AnalysisRef,
    pub summary: Summary,
    pub lockfiles: Vec<Count>,
    /// Most common first; `null` is no recorded license.
    pub licenses: Vec<LicenseCount>,
    /// One row per package URL, by ecosystem then name.
    pub dependencies: Vec<DependencyRow>,
    /// Against the branch's previous analysis; null for its first.
    pub changes: Option<Changes>,
    /// When advisories were last imported; null before the first import,
    /// when no package can be known vulnerable.
    pub advisory_data: Option<AdvisoryData>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdvisoryData {
    pub imported_at: String,
    pub advisories: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisRef {
    pub id: i64,
    pub sha: String,
    pub analyzed_at: String,
}

/// What the project page shows; also part of the list.
#[derive(Serialize, Default, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub total: usize,
    pub direct: usize,
    /// Packages with at least one known vulnerability.
    pub vulnerable: usize,
    pub ecosystems: Vec<Count>,
}

#[derive(Serialize, PartialEq, Debug)]
pub struct Count {
    pub id: String,
    pub count: usize,
}

#[derive(Serialize)]
pub struct LicenseCount {
    pub license: Option<String>,
    pub count: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DependencyRow {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub purl: String,
    /// True if any lockfile says so; null if none says either way.
    pub direct: Option<bool>,
    pub license: Option<String>,
    pub lockfiles: Vec<String>,
    /// Known vulnerabilities affecting this version, most severe first.
    pub advisories: Vec<Finding>,
    /// Advisories for this package that couldn't be checked against it.
    pub unchecked: Vec<String>,
}

#[derive(Serialize, Default, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Changes {
    pub previous_analysis: i64,
    pub added: Vec<Package>,
    pub removed: Vec<Package>,
    pub updated: Vec<Update>,
}

#[derive(Serialize, PartialEq, Debug)]
pub struct Package {
    pub ecosystem: String,
    pub name: String,
    pub versions: Vec<String>,
}

/// A package whose pinned versions changed; npm can pin several at once.
#[derive(Serialize, PartialEq, Debug)]
pub struct Update {
    pub ecosystem: String,
    pub name: String,
    pub from: Vec<String>,
    pub to: Vec<String>,
}

/// An analysis id, then a [`Row`]'s fields.
type AnalysisRow = (
    i64,
    String,
    String,
    String,
    String,
    Option<bool>,
    String,
    Option<String>,
);

/// (project, ecosystem, name, advisory, status, reason, reviewed by, at)
type ReviewRow = (
    i64,
    String,
    String,
    String,
    String,
    Option<String>,
    String,
    f64,
);

/// (ecosystem, name, version, purl, direct, lockfile, license)
type Row = (
    String,
    String,
    String,
    String,
    Option<bool>,
    String,
    Option<String>,
);

async fn rows(pool: &PgPool, analysis: i64) -> Result<Vec<Row>, sqlx::Error> {
    sqlx::query_as(
        "SELECT ecosystem, name, version, purl, direct, lockfile, license
         FROM analysis_dependencies WHERE analysis_id = $1
         ORDER BY ecosystem, name, version, lockfile",
    )
    .bind(analysis)
    .fetch_all(pool)
    .await
}

/// The latest analysis's summary, for the project page; None without
/// dependencies.
pub async fn summary(
    pool: &PgPool,
    project: i64,
    analysis: i64,
) -> Result<Option<Summary>, sqlx::Error> {
    let mut deps = merge(rows(pool, analysis).await?);
    annotate(pool, &mut [(project, &mut deps)]).await?;
    let s = summarize(&deps);
    Ok((s.total > 0).then_some(s))
}

/// Adds known vulnerabilities, and each project's reviews of them, to its
/// dependencies: every project's in one query.
async fn annotate(
    pool: &PgPool,
    projects: &mut [(i64, &mut Vec<DependencyRow>)],
) -> Result<(), sqlx::Error> {
    // Ingest only stores known ecosystems; anything else is left unchecked.
    let mut known: Vec<(usize, usize, Ecosystem)> = Vec::new();
    for (p, (_, deps)) in projects.iter().enumerate() {
        for (i, d) in deps.iter().enumerate() {
            if let Some(e) = Ecosystem::parse(&d.ecosystem) {
                known.push((p, i, e));
            }
        }
    }
    let query: Vec<(Ecosystem, &str, &str)> = known
        .iter()
        .map(|&(p, i, e)| {
            let d = &projects[p].1[i];
            (e, d.name.as_str(), d.version.as_str())
        })
        .collect();
    let verdicts = advisories::check(pool, &query).await?;

    let ids: Vec<i64> = projects.iter().map(|(id, _)| *id).collect();
    let reviews: Vec<ReviewRow> = sqlx::query_as(
        "SELECT project_id, ecosystem, name, advisory_id, status::text, reason, reviewed_by,
                extract(epoch FROM reviewed_at)::float8
         FROM dependency_reviews WHERE project_id = ANY($1)",
    )
    .bind(&ids)
    .fetch_all(pool)
    .await?;
    let reviews: HashMap<(i64, String, String, String), Review> = reviews
        .into_iter()
        .map(|(project, eco, name, advisory, status, reason, by, at)| {
            (
                (project, eco, name, advisory),
                Review {
                    status,
                    reason,
                    reviewed_by: by,
                    reviewed_at: rfc3339(at),
                },
            )
        })
        .collect();

    for ((p, i, e), v) in known.into_iter().zip(verdicts) {
        let project = projects[p].0;
        let d = &mut projects[p].1[i];
        let key = package_key(e, &d.name);
        d.advisories = v
            .advisories
            .into_iter()
            .map(|mut f| {
                f.review = reviews
                    .get(&(project, e.as_str().to_string(), key.clone(), f.id.clone()))
                    .cloned();
                f
            })
            .collect();
        d.unchecked = v.unchecked;
    }
    Ok(())
}

pub async fn get_dependencies(
    axum::extract::State(state): axum::extract::State<State>,
    Path(key): Path<String>,
    Query(q): Query<DependencyQuery>,
) -> Result<Json<DependencyList>, ApiError> {
    let pool = &state.pool;
    let (project, main_branch): (i64, String) =
        sqlx::query_as("SELECT id, main_branch FROM projects WHERE key = $1")
            .bind(&key)
            .fetch_optional(pool)
            .await?
            .ok_or(ApiError::NotFound)?;
    let branch = q.branch.unwrap_or_else(|| main_branch.clone());
    let latest: Vec<(i64, String, f64)> = sqlx::query_as(
        "SELECT id, commit_sha, extract(epoch FROM received_at)::float8
         FROM analyses WHERE project_id = $1 AND branch = $2 ORDER BY id DESC LIMIT 2",
    )
    .bind(project)
    .bind(&branch)
    .fetch_all(pool)
    .await?;
    let Some((id, sha, at)) = latest.first().cloned() else {
        return Err(ApiError::BadRequest(format!(
            "branch {branch:?} has no analyses"
        )));
    };
    let mut current = merge(rows(pool, id).await?);
    annotate(pool, &mut [(project, &mut current)]).await?;
    let changes = match latest.get(1) {
        Some((previous, ..)) => Some(diff(
            *previous,
            &merge(rows(pool, *previous).await?),
            &current,
        )),
        None => None,
    };

    let mut lockfiles: BTreeMap<&str, usize> = BTreeMap::new();
    let mut licenses: BTreeMap<Option<&str>, usize> = BTreeMap::new();
    for d in &current {
        for l in &d.lockfiles {
            *lockfiles.entry(l).or_default() += 1;
        }
        *licenses.entry(d.license.as_deref()).or_default() += 1;
    }
    let mut licenses: Vec<LicenseCount> = licenses
        .into_iter()
        .map(|(license, count)| LicenseCount {
            license: license.map(str::to_string),
            count,
        })
        .collect();
    licenses.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then_with(|| a.license.cmp(&b.license))
    });
    if licenses.len() > TOP_LICENSES {
        let rest: usize = licenses.drain(TOP_LICENSES - 1..).map(|l| l.count).sum();
        licenses.push(LicenseCount {
            license: Some("other".into()),
            count: rest,
        });
    }

    Ok(Json(DependencyList {
        project: key,
        branch,
        main_branch,
        analysis: AnalysisRef {
            id,
            sha,
            analyzed_at: rfc3339(at),
        },
        summary: summarize(&current),
        lockfiles: lockfiles
            .into_iter()
            .map(|(id, count)| Count {
                id: id.to_string(),
                count,
            })
            .collect(),
        licenses,
        changes,
        dependencies: current,
        advisory_data: advisories::status(pool)
            .await?
            .map(|(at, advisories)| AdvisoryData {
                imported_at: rfc3339(at),
                advisories,
            }),
    }))
}

/// One row per package URL, its lockfiles listed. `rows` is ordered by
/// ecosystem, name, version, lockfile.
fn merge(rows: Vec<Row>) -> Vec<DependencyRow> {
    let mut merged: Vec<DependencyRow> = Vec::new();
    for (ecosystem, name, version, purl, direct, lockfile, license) in rows {
        match merged.last_mut() {
            Some(last) if last.purl == purl => {
                last.direct = match (last.direct, direct) {
                    (Some(a), Some(b)) => Some(a || b),
                    (a, b) => a.or(b),
                };
                last.license = last.license.take().or(license);
                last.lockfiles.push(lockfile);
            }
            _ => merged.push(DependencyRow {
                ecosystem,
                name,
                version,
                purl,
                direct,
                license,
                lockfiles: vec![lockfile],
                advisories: Vec::new(),
                unchecked: Vec::new(),
            }),
        }
    }
    merged
}

fn summarize(deps: &[DependencyRow]) -> Summary {
    let mut ecosystems: BTreeMap<&str, usize> = BTreeMap::new();
    for d in deps {
        *ecosystems.entry(&d.ecosystem).or_default() += 1;
    }
    let mut ecosystems: Vec<Count> = ecosystems
        .into_iter()
        .map(|(id, count)| Count {
            id: id.to_string(),
            count,
        })
        .collect();
    ecosystems.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.id.cmp(&b.id)));
    Summary {
        total: deps.len(),
        direct: deps.iter().filter(|d| d.direct == Some(true)).count(),
        vulnerable: deps
            .iter()
            .filter(|d| d.advisories.iter().any(|a| !a.accepted()))
            .count(),
        ecosystems,
    }
}

type Versions<'a> = BTreeMap<(&'a str, &'a str), BTreeSet<&'a str>>;

/// Each package's pinned versions.
fn versions(deps: &[DependencyRow]) -> Versions<'_> {
    let mut m: Versions = BTreeMap::new();
    for d in deps {
        m.entry((d.ecosystem.as_str(), d.name.as_str()))
            .or_default()
            .insert(d.version.as_str());
    }
    m
}

/// By package (ecosystem and name): its set of pinned versions appeared,
/// disappeared or changed.
fn diff(previous_analysis: i64, before: &[DependencyRow], after: &[DependencyRow]) -> Changes {
    let (old, new) = (versions(before), versions(after));
    let list = |v: &BTreeSet<&str>| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let mut changes = Changes {
        previous_analysis,
        ..Changes::default()
    };
    for (&(ecosystem, name), versions) in &new {
        match old.get(&(ecosystem, name)) {
            None => changes.added.push(Package {
                ecosystem: ecosystem.into(),
                name: name.into(),
                versions: list(versions),
            }),
            Some(was) if was != versions => changes.updated.push(Update {
                ecosystem: ecosystem.into(),
                name: name.into(),
                from: list(was),
                to: list(versions),
            }),
            Some(_) => {}
        }
    }
    for (&(ecosystem, name), versions) in &old {
        if !new.contains_key(&(ecosystem, name)) {
            changes.removed.push(Package {
                ecosystem: ecosystem.into(),
                name: name.into(),
                versions: list(versions),
            });
        }
    }
    changes
}

#[derive(Deserialize)]
pub struct ReviewPatch {
    pub ecosystem: String,
    /// The package's name, as listed.
    pub name: String,
    pub advisory: String,
    /// `open`, `confirmed` or `accepted`.
    pub status: String,
    /// Required to accept.
    pub reason: Option<String>,
}

/// `PATCH /api/projects/{key}/dependencies/reviews`: triages one known
/// vulnerability in one of the project's packages, on every branch, for
/// as long as the package has it.
pub async fn patch_review(
    axum::extract::State(state): axum::extract::State<State>,
    axum::extract::Extension(caller): axum::extract::Extension<crate::api::Caller>,
    Path(key): Path<String>,
    Json(patch): Json<ReviewPatch>,
) -> Result<Json<Review>, ApiError> {
    let invalid = |m: &str| ApiError::Unprocessable(m.to_string());
    if !["open", "confirmed", "accepted"].contains(&patch.status.as_str()) {
        return Err(invalid("status must be open, confirmed or accepted"));
    }
    let ecosystem =
        Ecosystem::parse(&patch.ecosystem).ok_or_else(|| invalid("unknown ecosystem"))?;
    let reason = patch
        .reason
        .map(|r| r.trim().to_string())
        .filter(|r| !r.is_empty());
    if reason
        .as_ref()
        .is_some_and(|r| r.chars().count() > 500 || r.chars().any(|c| c.is_control() && c != '\n'))
    {
        return Err(invalid(
            "the reason must be at most 500 characters, without control characters",
        ));
    }
    if patch.status == "accepted" && reason.is_none() {
        return Err(invalid("accepting a vulnerability needs a reason"));
    }
    let name = package_key(ecosystem, &patch.name);
    let actor = caller.name().to_string();

    let mut tx = state.pool.begin().await?;
    let project: i64 = sqlx::query_scalar("SELECT id FROM projects WHERE key = $1")
        .bind(&key)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(ApiError::NotFound)?;
    let known: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM advisories WHERE id = $1)")
        .bind(&patch.advisory)
        .fetch_one(&mut *tx)
        .await?;
    if !known {
        return Err(ApiError::NotFound);
    }
    let old: Option<String> = sqlx::query_scalar(
        "SELECT status::text FROM dependency_reviews
         WHERE project_id = $1 AND ecosystem = $2 AND name = $3 AND advisory_id = $4 FOR UPDATE",
    )
    .bind(project)
    .bind(ecosystem.as_str())
    .bind(&name)
    .bind(&patch.advisory)
    .fetch_optional(&mut *tx)
    .await?;
    let (status, reason, by, at): (String, Option<String>, String, f64) = sqlx::query_as(
        "INSERT INTO dependency_reviews
             (project_id, ecosystem, name, advisory_id, status, reason, reviewed_by)
         VALUES ($1, $2, $3, $4, $5::issue_status, $6, $7)
         ON CONFLICT (project_id, ecosystem, name, advisory_id) DO UPDATE
             SET status = EXCLUDED.status, reason = EXCLUDED.reason,
                 reviewed_by = EXCLUDED.reviewed_by, reviewed_at = now()
         RETURNING status::text, reason, reviewed_by, extract(epoch FROM reviewed_at)::float8",
    )
    .bind(project)
    .bind(ecosystem.as_str())
    .bind(&name)
    .bind(&patch.advisory)
    .bind(&patch.status)
    .bind(&reason)
    .bind(&actor)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO dependency_review_events
             (project_id, ecosystem, name, advisory_id, actor, old_status, new_status, reason)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(project)
    .bind(ecosystem.as_str())
    .bind(&name)
    .bind(&patch.advisory)
    .bind(&actor)
    .bind(old.as_deref().unwrap_or("open"))
    .bind(&status)
    .bind(&reason)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    refresh_gates(&state.pool, GateScope::Project(project)).await?;
    Ok(Json(Review {
        status,
        reason,
        reviewed_by: by,
        reviewed_at: rfc3339(at),
    }))
}

/// Vulnerable dependencies across every project's main branch, for the
/// Security screen. Accepted findings are left out.
#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Portfolio {
    /// Open or confirmed findings (package and advisory) by severity.
    pub by_severity: BTreeMap<String, usize>,
    pub vulnerable_packages: usize,
    pub projects_affected: usize,
    /// Most severe first.
    pub top: Vec<PortfolioFinding>,
    pub advisory_data: Option<AdvisoryData>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortfolioFinding {
    pub project: String,
    pub ecosystem: String,
    pub package: String,
    pub version: String,
    pub advisory: String,
    pub summary: String,
    pub severity: String,
    pub fixed_in: Option<String>,
    pub url: String,
}

/// Findings listed in `Portfolio::top`.
const TOP_FINDINGS: usize = 10;

pub async fn portfolio(pool: &PgPool) -> Result<Portfolio, sqlx::Error> {
    let latest: Vec<(i64, String, i64)> = sqlx::query_as(
        "SELECT DISTINCT ON (p.id) p.id, p.key, a.id
         FROM projects p JOIN analyses a ON a.project_id = p.id AND a.branch = p.main_branch
         ORDER BY p.id, a.id DESC",
    )
    .fetch_all(pool)
    .await?;
    let analyses: Vec<i64> = latest.iter().map(|l| l.2).collect();
    let all: Vec<AnalysisRow> = sqlx::query_as(
        "SELECT analysis_id, ecosystem, name, version, purl, direct, lockfile, license
             FROM analysis_dependencies WHERE analysis_id = ANY($1)
             ORDER BY analysis_id, ecosystem, name, version, lockfile",
    )
    .bind(&analyses)
    .fetch_all(pool)
    .await?;
    let mut by_analysis: HashMap<i64, Vec<Row>> = HashMap::new();
    for (analysis, e, n, v, purl, direct, lockfile, license) in all {
        by_analysis
            .entry(analysis)
            .or_default()
            .push((e, n, v, purl, direct, lockfile, license));
    }
    let mut merged: Vec<(i64, Vec<DependencyRow>)> = latest
        .iter()
        .map(|(project, _, analysis)| {
            (
                *project,
                merge(by_analysis.remove(analysis).unwrap_or_default()),
            )
        })
        .collect();
    let mut refs: Vec<(i64, &mut Vec<DependencyRow>)> =
        merged.iter_mut().map(|(p, d)| (*p, d)).collect();
    annotate(pool, &mut refs).await?;

    let mut p = Portfolio {
        advisory_data: advisories::status(pool).await?.map(|(at, n)| AdvisoryData {
            imported_at: rfc3339(at),
            advisories: n,
        }),
        ..Portfolio::default()
    };
    for ((_, key, _), (_, deps)) in latest.iter().zip(&merged) {
        let mut affected = false;
        for d in deps {
            let open: Vec<&Finding> = d.advisories.iter().filter(|a| !a.accepted()).collect();
            if open.is_empty() {
                continue;
            }
            affected = true;
            p.vulnerable_packages += 1;
            for a in open {
                *p.by_severity.entry(a.severity.clone()).or_default() += 1;
                p.top.push(PortfolioFinding {
                    project: key.clone(),
                    ecosystem: d.ecosystem.clone(),
                    package: d.name.clone(),
                    version: d.version.clone(),
                    advisory: a.id.clone(),
                    summary: a.summary.clone(),
                    severity: a.severity.clone(),
                    fixed_in: a.fixed_in.clone(),
                    url: a.url.clone(),
                });
            }
        }
        p.projects_affected += usize::from(affected);
    }
    let rank = |s: &str| {
        ["blocker", "critical", "major", "minor", "info"]
            .iter()
            .position(|x| *x == s)
            .unwrap_or(5)
    };
    p.top.sort_by(|a, b| {
        rank(&a.severity).cmp(&rank(&b.severity)).then_with(|| {
            (&a.project, &a.package, &a.advisory).cmp(&(&b.project, &b.package, &b.advisory))
        })
    });
    p.top.truncate(TOP_FINDINGS);
    Ok(p)
}

/// Gate metrics the server keeps current from its advisories (ADR-0009).
const GATE_METRICS: &[&str] = &["vulnerable_dependencies", "severe_vulnerable_dependencies"];

/// Which analyses' gates to refresh.
pub enum GateScope {
    /// One analysis, as it's uploaded.
    Analysis(i64),
    /// The latest analysis of each of the project's branches.
    Project(i64),
    /// The latest analysis of every branch.
    All,
}

/// Re-evaluates gate conditions on vulnerable dependencies with the
/// server's advisories and reviews, and stores the result with the
/// analysis, so every page shows the same gate. Without advisory data, the
/// values the CLI reported (usually "no data") stand. Returns how many
/// gates it updated.
pub async fn refresh_gates(pool: &PgPool, scope: GateScope) -> Result<usize, sqlx::Error> {
    if advisories::status(pool).await?.is_none() {
        return Ok(0);
    }
    let targets: Vec<(i64, i64, serde_json::Value, serde_json::Value)> = match scope {
        GateScope::Analysis(id) => {
            sqlx::query_as("SELECT id, project_id, gate, measures FROM analyses WHERE id = $1")
                .bind(id)
                .fetch_all(pool)
                .await?
        }
        GateScope::Project(_) | GateScope::All => {
            let project = match scope {
                GateScope::Project(p) => Some(p),
                _ => None,
            };
            sqlx::query_as(
                "SELECT DISTINCT ON (project_id, branch) id, project_id, gate, measures
                 FROM analyses WHERE $1::bigint IS NULL OR project_id = $1
                 ORDER BY project_id, branch, id DESC",
            )
            .bind(project)
            .fetch_all(pool)
            .await?
        }
    };
    let uses_metrics = |gate: &serde_json::Value| {
        gate["conditions"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|c| {
                c["metric"]
                    .as_str()
                    .is_some_and(|m| GATE_METRICS.contains(&m))
            })
    };
    let mut updated = 0;
    for (id, project, mut gate, mut measures) in targets.into_iter().filter(|t| uses_metrics(&t.2))
    {
        let mut deps = merge(rows(pool, id).await?);
        annotate(pool, &mut [(project, &mut deps)]).await?;
        let count = |severe: bool| {
            deps.iter()
                .filter(|d| {
                    d.advisories.iter().any(|a| {
                        !a.accepted()
                            && (!severe || matches!(a.severity.as_str(), "blocker" | "critical"))
                    })
                })
                .count() as f64
        };
        let values = [
            ("vulnerable_dependencies", count(false)),
            ("severe_vulnerable_dependencies", count(true)),
        ];
        for c in gate["conditions"].as_array_mut().into_iter().flatten() {
            let Some(&(_, value)) = values.iter().find(|(m, _)| c["metric"] == *m) else {
                continue;
            };
            let threshold = c["threshold"].as_f64().unwrap_or(0.0);
            let failing = match c["op"].as_str() {
                Some("gt") => value > threshold,
                Some("lt") => value < threshold,
                _ => false,
            };
            c["actual"] = serde_json::json!(value);
            c["status"] = serde_json::json!(if failing { "error" } else { "ok" });
        }
        let passed = gate["conditions"]
            .as_array()
            .into_iter()
            .flatten()
            .all(|c| c["status"] != "error");
        gate["passed"] = serde_json::json!(passed);
        for (metric, value) in values {
            measures[metric] = serde_json::json!(value);
        }
        sqlx::query("UPDATE analyses SET gate = $2, gate_passed = $3, measures = $4 WHERE id = $1")
            .bind(id)
            .bind(&gate)
            .bind(passed)
            .bind(&measures)
            .execute(pool)
            .await?;
        updated += 1;
    }
    Ok(updated)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(eco: &str, name: &str, version: &str, direct: Option<bool>, lockfile: &str) -> Row {
        (
            eco.into(),
            name.into(),
            version.into(),
            format!("pkg:{eco}/{name}@{version}"),
            direct,
            lockfile.into(),
            None,
        )
    }

    #[test]
    fn merges_lockfiles_and_summarizes() {
        let merged = merge(vec![
            row("npm", "a", "1.0.0", Some(false), "package-lock.json"),
            row("npm", "a", "1.0.0", Some(true), "web/package-lock.json"),
            row("npm", "b", "2.0.0", None, "package-lock.json"),
            row("pypi", "c", "3.0", None, "requirements.txt"),
        ]);
        assert_eq!(merged.len(), 3);
        assert_eq!(
            merged[0].lockfiles,
            ["package-lock.json", "web/package-lock.json"]
        );
        assert_eq!(merged[0].direct, Some(true));
        let s = summarize(&merged);
        assert_eq!((s.total, s.direct), (3, 1));
        assert_eq!(
            s.ecosystems,
            [
                Count {
                    id: "npm".into(),
                    count: 2
                },
                Count {
                    id: "pypi".into(),
                    count: 1
                }
            ]
        );
    }

    #[test]
    fn diffs_by_package() {
        let before = merge(vec![
            row("npm", "a", "1.0.0", None, "l"),
            row("npm", "gone", "1.0.0", None, "l"),
            row("npm", "same", "1.0.0", None, "l"),
        ]);
        let after = merge(vec![
            row("npm", "a", "1.1.0", None, "l"),
            row("npm", "a", "2.0.0", None, "l"),
            row("npm", "same", "1.0.0", None, "l"),
            row("pypi", "new", "0.1", None, "r"),
        ]);
        let c = diff(7, &before, &after);
        assert_eq!(c.previous_analysis, 7);
        assert_eq!(
            c.updated,
            [Update {
                ecosystem: "npm".into(),
                name: "a".into(),
                from: vec!["1.0.0".into()],
                to: vec!["1.1.0".into(), "2.0.0".into()],
            }]
        );
        assert_eq!(
            c.added.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
            ["new"]
        );
        assert_eq!(
            c.removed
                .iter()
                .map(|p| p.name.as_str())
                .collect::<Vec<_>>(),
            ["gone"]
        );
    }
}
