//! `GET /api/projects/{key}/dependencies`: the packages a branch's latest
//! analysis pinned (ADR-0009), with what changed since the analysis before
//! it.

use crate::api::ApiError;
use crate::health::rfc3339;
use crate::http::State;
use axum::Json;
use axum::extract::{Path, Query};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::{BTreeMap, BTreeSet};

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
pub async fn summary(pool: &PgPool, analysis: i64) -> Result<Option<Summary>, sqlx::Error> {
    let s = summarize(&merge(rows(pool, analysis).await?));
    Ok((s.total > 0).then_some(s))
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
    let current = merge(rows(pool, id).await?);
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
