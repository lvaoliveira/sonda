//! Infrastructure: imports OSV advisories into the database and matches
//! them against dependencies (ADR-0009). Parsing and version matching are
//! sonda_core's.

use serde::Serialize;
use sonda_core::advisories::{self, AffectedPackage, Match};
use sonda_core::deps::{Ecosystem, package_key};
use sqlx::PgPool;
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};

/// One OSV record is a few kilobytes; this bounds a hostile one.
pub(crate) const MAX_RECORD_BYTES: u64 = 4 << 20;
/// Errors kept for the summary; the rest are only counted.
const MAX_ERRORS_SHOWN: usize = 10;

#[derive(Debug, Default, Serialize)]
pub struct ImportSummary {
    /// JSON files read.
    pub read: usize,
    /// New, or newer than the stored version.
    pub imported: usize,
    pub unchanged: usize,
    /// From databases sonda doesn't import, or for ecosystems it doesn't read.
    pub skipped: usize,
    pub errors: usize,
    pub first_errors: Vec<String>,
}

/// Imports every `*.json` file under `paths` (files or directories, such as
/// an unzipped OSV export).
pub async fn import(pool: &PgPool, paths: &[PathBuf]) -> anyhow::Result<ImportSummary> {
    let mut summary = ImportSummary::default();
    for file in json_files(paths)? {
        summary.read += 1;
        let text = match read_capped(&file) {
            Ok(t) => t,
            Err(e) => {
                summary.error(format!("{}: {e}", file.display()));
                continue;
            }
        };
        record(pool, &file.display().to_string(), &text, &mut summary).await;
    }
    finish(pool, &summary).await?;
    Ok(summary)
}

/// Parses and stores one OSV record, counting the outcome in `summary`.
/// `origin` names it in errors (a path or a URL).
pub(crate) async fn record(pool: &PgPool, origin: &str, text: &str, summary: &mut ImportSummary) {
    let advisory = match advisories::parse(text) {
        Ok(Some(a)) => a,
        Ok(None) => {
            summary.skipped += 1;
            return;
        }
        Err(e) => {
            summary.error(format!("{origin}: {e}"));
            return;
        }
    };
    match store(pool, &advisory).await {
        Ok(true) => summary.imported += 1,
        Ok(false) => summary.unchanged += 1,
        Err(e) => summary.error(format!("{}: {e}", advisory.id)),
    }
}

/// Records that an import (or sync) ran.
pub(crate) async fn finish(pool: &PgPool, summary: &ImportSummary) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO advisory_imports (read, imported) VALUES ($1, $2)")
        .bind(i32::try_from(summary.read).unwrap_or(i32::MAX))
        .bind(i32::try_from(summary.imported).unwrap_or(i32::MAX))
        .execute(pool)
        .await?;
    Ok(())
}

impl ImportSummary {
    pub(crate) fn error(&mut self, msg: String) {
        self.errors += 1;
        if self.first_errors.len() < MAX_ERRORS_SHOWN {
            self.first_errors.push(msg);
        }
    }
}

/// Every `*.json` file under `paths`, sorted, without following symlinks.
fn json_files(paths: &[PathBuf]) -> anyhow::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut stack: Vec<PathBuf> = paths.to_vec();
    while let Some(path) = stack.pop() {
        let meta = std::fs::symlink_metadata(&path)
            .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
        if meta.is_dir() {
            for entry in std::fs::read_dir(&path)? {
                stack.push(entry?.path());
            }
        } else if meta.is_file() && path.extension().is_some_and(|e| e == "json") {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

fn read_capped(path: &Path) -> anyhow::Result<String> {
    let mut text = String::new();
    std::fs::File::open(path)?
        .take(MAX_RECORD_BYTES + 1)
        .read_to_string(&mut text)?;
    anyhow::ensure!(
        text.len() as u64 <= MAX_RECORD_BYTES,
        "larger than {} MB",
        MAX_RECORD_BYTES >> 20
    );
    Ok(text)
}

/// Stores `a` unless the stored version is as new; true if it was stored.
async fn store(pool: &PgPool, a: &advisories::Advisory) -> anyhow::Result<bool> {
    let mut tx = pool.begin().await?;
    let stored: Option<String> = sqlx::query_scalar(
        "INSERT INTO advisories (id, source, aliases, summary, modified, withdrawn, severity,
                                 score, cwe)
         VALUES ($1, $2, $3, $4, $5::timestamptz, $6::timestamptz, $7, $8, $9)
         ON CONFLICT (id) DO UPDATE SET
             source = EXCLUDED.source, aliases = EXCLUDED.aliases,
             summary = EXCLUDED.summary, modified = EXCLUDED.modified,
             withdrawn = EXCLUDED.withdrawn, severity = EXCLUDED.severity,
             score = EXCLUDED.score, cwe = EXCLUDED.cwe, imported_at = now()
         WHERE advisories.modified < EXCLUDED.modified
         RETURNING id",
    )
    .bind(&a.id)
    .bind(a.source.as_str())
    .bind(&a.aliases)
    .bind(&a.summary)
    .bind(&a.modified)
    .bind(&a.withdrawn)
    .bind(a.severity.as_str())
    .bind(a.score.map(|s| s as f32))
    .bind(a.cwe.iter().map(|&c| i32::from(c)).collect::<Vec<_>>())
    .fetch_optional(&mut *tx)
    .await?;
    if stored.is_none() {
        return Ok(false);
    }
    sqlx::query("DELETE FROM advisory_packages WHERE advisory_id = $1")
        .bind(&a.id)
        .execute(&mut *tx)
        .await?;
    for p in &a.packages {
        sqlx::query(
            "INSERT INTO advisory_packages (advisory_id, ecosystem, name, affected)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(&a.id)
        .bind(p.ecosystem.as_str())
        .bind(&p.name)
        .bind(serde_json::to_value(p)?)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(true)
}

/// A known vulnerability affecting a dependency.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub id: String,
    pub aliases: Vec<String>,
    pub summary: String,
    pub severity: String,
    pub score: Option<f32>,
    pub cwe: Vec<i32>,
    /// The lowest later version that fixes it: what to upgrade to. Null
    /// when none does yet.
    pub fixed_in: Option<String>,
    /// The database, for attribution.
    pub source: String,
    pub url: String,
}

/// What the advisories say about one dependency.
#[derive(Debug, Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Verdict {
    pub advisories: Vec<Finding>,
    /// Advisories for the package whose ranges or versions didn't parse:
    /// neither counted nor ruled out.
    pub unchecked: Vec<String>,
}

/// (id, source, aliases, summary, severity, score, cwe, ecosystem, name, affected)
type Row = (
    String,
    String,
    Vec<String>,
    String,
    String,
    Option<f32>,
    Vec<i32>,
    String,
    String,
    serde_json::Value,
);

/// For each `(ecosystem, name, version)`, the advisories affecting it, one
/// per vulnerability: records from several databases that alias each other
/// count once (GitHub's preferred, as it has severities and CWE ids).
pub async fn check(
    pool: &PgPool,
    deps: &[(Ecosystem, &str, &str)],
) -> Result<Vec<Verdict>, sqlx::Error> {
    let keys: Vec<(String, String)> = deps
        .iter()
        .map(|(e, name, _)| (e.as_str().to_string(), package_key(*e, name)))
        .collect();
    let unique: HashSet<&(String, String)> = keys.iter().collect();
    let (ecosystems, names): (Vec<String>, Vec<String>) = unique.into_iter().cloned().unzip();
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT a.id, a.source, a.aliases, a.summary, a.severity, a.score, a.cwe,
                p.ecosystem, p.name, p.affected
         FROM advisory_packages p JOIN advisories a ON a.id = p.advisory_id
         WHERE a.withdrawn IS NULL
           AND (p.ecosystem, p.name) IN (SELECT * FROM UNNEST($1::text[], $2::text[]))
         ORDER BY a.id",
    )
    .bind(&ecosystems)
    .bind(&names)
    .fetch_all(pool)
    .await?;
    let mut by_package: HashMap<(String, String), Vec<(Finding, AffectedPackage)>> = HashMap::new();
    for (id, source, aliases, summary, severity, score, cwe, ecosystem, name, affected) in rows {
        let Ok(package) = serde_json::from_value::<AffectedPackage>(affected) else {
            continue;
        };
        let source = advisories::Source::of(&id).map_or(source, |s| s.attribution().to_string());
        by_package.entry((ecosystem, name)).or_default().push((
            Finding {
                url: format!("https://osv.dev/vulnerability/{id}"),
                id,
                aliases,
                summary,
                severity,
                score,
                cwe,
                fixed_in: None,
                source,
            },
            package,
        ));
    }

    Ok(deps
        .iter()
        .zip(&keys)
        .map(|((_, _, version), key)| {
            let mut verdict = Verdict::default();
            for (finding, package) in by_package.get(key).into_iter().flatten() {
                match package.affects(version) {
                    Match::Affected => verdict.advisories.push(Finding {
                        fixed_in: package.fixed_in(version),
                        ..finding.clone()
                    }),
                    Match::Unknown => verdict.unchecked.push(finding.id.clone()),
                    Match::NotAffected => {}
                }
            }
            verdict.advisories = dedup(std::mem::take(&mut verdict.advisories));
            verdict
        })
        .collect())
}

/// One finding per vulnerability, most severe first.
fn dedup(mut findings: Vec<Finding>) -> Vec<Finding> {
    // GitHub's records first, so they're the ones kept.
    findings.sort_by_key(|f| (!f.id.starts_with("GHSA-"), f.id.clone()));
    let mut seen: HashSet<String> = HashSet::new();
    let mut kept = Vec::new();
    for f in findings {
        let names: Vec<&String> = std::iter::once(&f.id).chain(&f.aliases).collect();
        if names.iter().any(|n| seen.contains(*n)) {
            continue;
        }
        seen.extend(names.into_iter().cloned());
        kept.push(f);
    }
    kept.sort_by_key(|f| (rank(&f.severity), f.id.clone()));
    kept
}

fn rank(severity: &str) -> usize {
    ["blocker", "critical", "major", "minor", "info"]
        .iter()
        .position(|s| *s == severity)
        .unwrap_or(5)
}

/// When advisories were last imported, and how many are stored; None before
/// the first import.
pub async fn status(pool: &PgPool) -> Result<Option<(f64, i64)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT extract(epoch FROM max(i.at))::float8,
                (SELECT count(*) FROM advisories WHERE withdrawn IS NULL)
         FROM advisory_imports i
         HAVING count(*) > 0",
    )
    .fetch_optional(pool)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(id: &str, aliases: &[&str], severity: &str) -> Finding {
        Finding {
            id: id.into(),
            aliases: aliases.iter().map(|s| s.to_string()).collect(),
            summary: String::new(),
            severity: severity.into(),
            score: None,
            cwe: vec![],
            fixed_in: None,
            source: String::new(),
            url: String::new(),
        }
    }

    #[test]
    fn one_finding_per_vulnerability_github_first() {
        let kept = dedup(vec![
            finding(
                "PYSEC-2023-74",
                &["CVE-2023-32681", "GHSA-j8r2-6x86-q33q"],
                "major",
            ),
            finding("GHSA-j8r2-6x86-q33q", &["CVE-2023-32681"], "major"),
            finding("PYSEC-2018-28", &["CVE-2018-18074"], "critical"),
        ]);
        let ids: Vec<&str> = kept.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids, ["PYSEC-2018-28", "GHSA-j8r2-6x86-q33q"]);
    }
}
