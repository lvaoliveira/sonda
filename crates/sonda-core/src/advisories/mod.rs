//! Domain: known vulnerabilities in packages (ADR-0009), read from OSV
//! records, and whether a package version is affected. Pure: the server
//! stores advisories and matches them against analyses' dependencies.

pub mod cvss;
pub mod version;

use crate::deps::{Ecosystem, package_key};
use crate::model::Severity;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::Ordering;

/// Advisory databases sonda imports: those whose terms allow any use with
/// attribution (ADR-0009). OSV also carries others, which are skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    GitHub,
    RustSec,
    PyPa,
    Go,
}

impl Source {
    /// By the advisory id's prefix, which names its database.
    pub fn of(id: &str) -> Option<Source> {
        [
            ("GHSA-", Source::GitHub),
            ("RUSTSEC-", Source::RustSec),
            ("PYSEC-", Source::PyPa),
            ("GO-", Source::Go),
        ]
        .into_iter()
        .find_map(|(prefix, s)| id.starts_with(prefix).then_some(s))
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Source::GitHub => "github",
            Source::RustSec => "rustsec",
            Source::PyPa => "pypa",
            Source::Go => "go",
        }
    }

    /// For attribution, as each database asks.
    pub fn attribution(self) -> &'static str {
        match self {
            Source::GitHub => "GitHub Advisory Database (CC-BY 4.0)",
            Source::RustSec => "RustSec Advisory Database (CC0 1.0)",
            Source::PyPa => "PyPA Advisory Database (CC-BY 4.0)",
            Source::Go => "Go Vulnerability Database (CC-BY 4.0)",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Advisory {
    pub id: String,
    pub source: Source,
    /// CVE and other databases' ids for the same vulnerability.
    pub aliases: Vec<String>,
    pub summary: String,
    /// RFC 3339, as the record gives it.
    pub modified: String,
    /// Set when the database retracted it: it then matches nothing.
    pub withdrawn: Option<String>,
    pub severity: Severity,
    /// CVSS v3 base score, when the advisory has a v3 vector.
    pub score: Option<f64>,
    pub cwe: Vec<u16>,
    pub packages: Vec<AffectedPackage>,
}

/// A package an advisory affects, in an ecosystem sonda reads.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AffectedPackage {
    pub ecosystem: Ecosystem,
    /// As [`package_key`] gives it, to match dependencies by.
    pub name: String,
    pub ranges: Vec<Vec<Event>>,
    /// Versions the advisory lists one by one.
    pub versions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    Introduced(String),
    Fixed(String),
    LastAffected(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Match {
    Affected,
    NotAffected,
    /// A version or range that doesn't parse: never guessed either way.
    Unknown,
}

/// A known vulnerability affecting one of a project's dependencies.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Vulnerability {
    /// The dependency's package URL.
    pub purl: String,
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
    pub advisory: String,
    pub aliases: Vec<String>,
    pub summary: String,
    pub severity: Severity,
    /// The lowest later version that fixes it.
    pub fixed_in: Option<String>,
    /// Not affecting the project at the new-code reference: its package was
    /// added, or moved to an affected version, since. True when there's no
    /// reference (the whole project is new code).
    pub is_new: bool,
}

/// The known vulnerabilities in `deps`, most severe first: one per package
/// and vulnerability (records that alias each other count once, GitHub's
/// kept), withdrawn advisories left out.
pub fn check(deps: &[crate::deps::Dependency], advisories: &[Advisory]) -> Vec<Vulnerability> {
    use std::collections::{HashMap, HashSet};
    let mut by_package: HashMap<(Ecosystem, &str), Vec<(&Advisory, &AffectedPackage)>> =
        HashMap::new();
    for a in advisories.iter().filter(|a| a.withdrawn.is_none()) {
        for p in &a.packages {
            by_package
                .entry((p.ecosystem, p.name.as_str()))
                .or_default()
                .push((a, p));
        }
    }
    let mut found = Vec::new();
    let mut seen_packages = HashSet::new();
    for d in deps {
        // A package pinned by several lockfiles is one package.
        if !seen_packages.insert(&d.purl) {
            continue;
        }
        let key = package_key(d.ecosystem, &d.name);
        let mut hits: Vec<(&Advisory, &AffectedPackage)> = by_package
            .get(&(d.ecosystem, key.as_str()))
            .into_iter()
            .flatten()
            .filter(|(_, p)| p.affects(&d.version) == Match::Affected)
            .copied()
            .collect();
        hits.sort_by_key(|(a, _)| (a.source != Source::GitHub, a.id.clone()));
        let mut names: HashSet<&str> = HashSet::new();
        for (a, p) in hits {
            let ids: Vec<&str> = std::iter::once(a.id.as_str())
                .chain(a.aliases.iter().map(String::as_str))
                .collect();
            if ids.iter().any(|id| names.contains(id)) {
                continue;
            }
            names.extend(ids);
            found.push(Vulnerability {
                purl: d.purl.clone(),
                ecosystem: d.ecosystem,
                name: d.name.clone(),
                version: d.version.clone(),
                advisory: a.id.clone(),
                aliases: a.aliases.clone(),
                summary: a.summary.clone(),
                severity: a.severity,
                fixed_in: p.fixed_in(&d.version),
                is_new: true,
            });
        }
    }
    // Most severe first (Severity orders info..blocker).
    found.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| (&a.purl, &a.advisory).cmp(&(&b.purl, &b.advisory)))
    });
    found
}

/// Summaries are cut to this many characters.
const MAX_SUMMARY: usize = 300;

/// Reads one OSV record. `Ok(None)` for one sonda doesn't import: from
/// another database, or affecting no ecosystem sonda reads.
pub fn parse(json: &str) -> Result<Option<Advisory>, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("not valid JSON ({e})"))?;
    let id = v["id"].as_str().ok_or("no id")?;
    let Some(source) = Source::of(id) else {
        return Ok(None);
    };
    // One entry per package: an advisory may list one several times, with
    // different ranges.
    let mut packages: Vec<AffectedPackage> = Vec::new();
    for p in v["affected"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(affected_package)
    {
        match packages
            .iter_mut()
            .find(|q| q.ecosystem == p.ecosystem && q.name == p.name)
        {
            Some(q) => {
                q.ranges.extend(p.ranges);
                q.versions.extend(p.versions);
            }
            None => packages.push(p),
        }
    }
    if packages.is_empty() {
        return Ok(None);
    }
    let strings = |field: &Value| -> Vec<String> {
        field
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect()
    };
    let summary = v["summary"]
        .as_str()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            v["details"]
                .as_str()
                .and_then(|d| d.lines().find(|l| !l.trim().is_empty()))
        })
        .unwrap_or(id)
        .trim();
    let score = v["severity"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|s| s["type"] == "CVSS_V3")
        .find_map(|s| s["score"].as_str().and_then(cvss::base_score));
    let label = v["database_specific"]["severity"].as_str();
    let mut cwe: Vec<u16> = strings(&v["database_specific"]["cwe_ids"])
        .iter()
        .filter_map(|c| c.strip_prefix("CWE-")?.parse().ok())
        .collect();
    cwe.sort_unstable();
    cwe.dedup();
    Ok(Some(Advisory {
        id: id.to_string(),
        source,
        aliases: strings(&v["aliases"]),
        summary: summary.chars().take(MAX_SUMMARY).collect(),
        modified: v["modified"]
            .as_str()
            .ok_or("no modified time")?
            .to_string(),
        withdrawn: v["withdrawn"].as_str().map(str::to_string),
        severity: severity(score, label),
        score,
        cwe,
        packages,
    }))
}

/// From the CVSS score, else the database's own label; major when neither
/// says (ADR-0009).
fn severity(score: Option<f64>, label: Option<&str>) -> Severity {
    match (score, label.map(str::to_ascii_uppercase).as_deref()) {
        (Some(s), _) if s >= 9.0 => Severity::Blocker,
        (Some(s), _) if s >= 7.0 => Severity::Critical,
        (Some(s), _) if s >= 4.0 => Severity::Major,
        (Some(s), _) if s > 0.0 => Severity::Minor,
        (Some(_), _) => Severity::Info,
        (None, Some("CRITICAL")) => Severity::Blocker,
        (None, Some("HIGH")) => Severity::Critical,
        (None, Some("LOW")) => Severity::Minor,
        (None, _) => Severity::Major,
    }
}

fn affected_package(a: &Value) -> Option<AffectedPackage> {
    let ecosystem = match a["package"]["ecosystem"].as_str()? {
        "npm" => Ecosystem::Npm,
        "crates.io" => Ecosystem::Cargo,
        "PyPI" => Ecosystem::Pypi,
        _ => return None,
    };
    let name = package_key(ecosystem, a["package"]["name"].as_str()?);
    let ranges = a["ranges"]
        .as_array()
        .into_iter()
        .flatten()
        // Git ranges are commits, which lockfiles don't pin.
        .filter(|r| matches!(r["type"].as_str(), Some("SEMVER" | "ECOSYSTEM")))
        .map(|r| {
            r["events"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|e| {
                    let text = |k: &str| e[k].as_str().map(str::to_string);
                    text("introduced")
                        .map(Event::Introduced)
                        .or_else(|| text("fixed").map(Event::Fixed))
                        .or_else(|| text("last_affected").map(Event::LastAffected))
                })
                .collect()
        })
        .collect();
    let versions = a["versions"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect();
    Some(AffectedPackage {
        ecosystem,
        name,
        ranges,
        versions,
    })
}

impl AffectedPackage {
    /// Whether `version` of this package is affected.
    pub fn affects(&self, version: &str) -> Match {
        let same = |listed: &str| {
            listed == version
                || version::compare(self.ecosystem, listed, version) == Some(Ordering::Equal)
        };
        if self.versions.iter().any(|v| same(v)) {
            return Match::Affected;
        }
        let mut unknown = false;
        for events in &self.ranges {
            match in_range(self.ecosystem, events, version) {
                Some(true) => return Match::Affected,
                Some(false) => {}
                None => unknown = true,
            }
        }
        // A listed version set, when there is one, settles the rest.
        if (unknown || self.ranges.is_empty()) && self.versions.is_empty() {
            Match::Unknown
        } else {
            Match::NotAffected
        }
    }

    /// The lowest version above `version` that fixes it, to upgrade to;
    /// `None` when no later version does (yet).
    pub fn fixed_in(&self, version: &str) -> Option<String> {
        let cmp = |a: &str, b: &str| version::compare(self.ecosystem, a, b);
        self.ranges
            .iter()
            .flatten()
            .filter_map(|e| match e {
                Event::Fixed(v) if cmp(v, version) == Some(Ordering::Greater) => Some(v),
                _ => None,
            })
            .min_by(|a, b| cmp(a, b).unwrap_or(Ordering::Equal))
            .cloned()
    }
}

/// The version an event is at.
fn at(e: &Event) -> &str {
    match e {
        Event::Introduced(v) | Event::Fixed(v) | Event::LastAffected(v) => v,
    }
}

/// OSV's range evaluation: events in version order, `introduced` turning
/// "affected" on, `fixed` (at or after) and `last_affected` (after) off.
/// `None` when any version doesn't parse.
fn in_range(ecosystem: Ecosystem, events: &[Event], version: &str) -> Option<bool> {
    let cmp = |a: &str, b: &str| -> Option<Ordering> {
        // "0" in `introduced` means "from the beginning".
        match (a, b) {
            ("0", "0") => Some(Ordering::Equal),
            ("0", _) => Some(Ordering::Less),
            (_, "0") => Some(Ordering::Greater),
            _ => version::compare(ecosystem, a, b),
        }
    };
    cmp(version, version)?;
    let mut sorted: Vec<&Event> = events.iter().collect();
    for e in &sorted {
        cmp(at(e), at(e))?;
    }
    sorted.sort_by(|a, b| cmp(at(a), at(b)).unwrap_or(Ordering::Equal));
    let mut affected = false;
    for e in sorted {
        let order = cmp(version, at(e))?;
        match e {
            Event::Introduced(_) if order != Ordering::Less => affected = true,
            Event::Fixed(_) if order != Ordering::Less => affected = false,
            Event::LastAffected(_) if order == Ordering::Greater => affected = false,
            _ => {}
        }
    }
    Some(affected)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LODASH: &str = r#"{
      "id": "GHSA-35jh-r3h4-6jhm", "modified": "2026-10-17T02:55:38Z",
      "summary": "Command Injection in lodash", "aliases": ["CVE-2021-23337"],
      "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"}],
      "database_specific": {"cwe_ids": ["CWE-94", "CWE-77"], "severity": "HIGH"},
      "affected": [
        {"package": {"name": "lodash", "ecosystem": "npm"},
         "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]},
        {"package": {"name": "lodash", "ecosystem": "Maven"}, "ranges": []}
      ]
    }"#;

    #[test]
    fn reads_an_advisory_and_matches_versions() {
        let a = parse(LODASH).unwrap().unwrap();
        assert_eq!(
            (a.source, a.score, a.severity),
            (Source::GitHub, Some(7.2), Severity::Critical)
        );
        assert_eq!(a.cwe, [77, 94]);
        assert_eq!(a.aliases, ["CVE-2021-23337"]);
        assert_eq!(a.packages.len(), 1, "Maven is not read");
        let p = &a.packages[0];
        assert_eq!(p.affects("4.17.20"), Match::Affected);
        assert_eq!(p.affects("4.17.21"), Match::NotAffected);
        assert_eq!(p.affects("5.0.0"), Match::NotAffected);
        assert_eq!(p.affects("not-a-version"), Match::Unknown);
        assert_eq!(p.fixed_in("4.17.20").as_deref(), Some("4.17.21"));
        assert_eq!(p.fixed_in("4.17.21"), None);
        // One fix per major line: the one above the installed version.
        let lines = AffectedPackage {
            ecosystem: Ecosystem::Npm,
            name: "brace-expansion".into(),
            ranges: [("4.0.0", "5.0.10"), ("2.0.0", "2.1.5"), ("0", "1.1.19")]
                .iter()
                .map(|(i, f)| {
                    vec![
                        Event::Introduced(i.to_string()),
                        Event::Fixed(f.to_string()),
                    ]
                })
                .collect(),
            versions: vec![],
        };
        assert_eq!(lines.affects("5.0.7"), Match::Affected);
        assert_eq!(lines.fixed_in("5.0.7").as_deref(), Some("5.0.10"));
        assert_eq!(lines.fixed_in("2.1.2").as_deref(), Some("2.1.5"));
    }

    #[test]
    fn several_ranges_last_affected_and_listed_versions() {
        let p = AffectedPackage {
            ecosystem: Ecosystem::Cargo,
            name: "time".into(),
            ranges: vec![vec![
                Event::Fixed("0.2.0".into()),
                Event::Introduced("0.0.0-0".into()),
                Event::Introduced("0.2.1-0".into()),
                Event::LastAffected("0.2.5".into()),
            ]],
            versions: vec![],
        };
        // Events out of order are sorted first.
        assert_eq!(p.affects("0.1.43"), Match::Affected);
        assert_eq!(p.affects("0.2.0"), Match::NotAffected);
        assert_eq!(p.affects("0.2.5"), Match::Affected);
        assert_eq!(p.affects("0.2.6"), Match::NotAffected);

        let listed = AffectedPackage {
            ecosystem: Ecosystem::Pypi,
            name: "requests".into(),
            ranges: vec![vec![
                Event::Introduced("2.3.0".into()),
                Event::Fixed("not!a!version".into()),
            ]],
            versions: vec!["2.30.0".into(), "2.31.0rc1".into()],
        };
        assert_eq!(listed.affects("2.30.0"), Match::Affected);
        assert_eq!(
            listed.affects("2.31.0.rc1"),
            Match::Affected,
            "PEP 440 equality"
        );
        assert_eq!(
            listed.affects("2.31.0"),
            Match::NotAffected,
            "the list settles it"
        );
    }

    #[test]
    fn skips_other_databases_and_ecosystems() {
        assert_eq!(parse(&LODASH.replace("GHSA-", "MAL-")).unwrap(), None);
        assert_eq!(parse(&LODASH.replace("\"npm\"", "\"Go\"")).unwrap(), None);
        assert!(parse("{").is_err());
    }

    #[test]
    fn checks_dependencies_once_per_vulnerability() {
        let dep = |name: &str, version: &str, purl: &str| crate::deps::Dependency {
            ecosystem: Ecosystem::Npm,
            name: name.into(),
            version: version.into(),
            purl: purl.into(),
            direct: None,
            source: "package-lock.json".into(),
            license: None,
        };
        let ghsa = parse(LODASH).unwrap().unwrap();
        // The same vulnerability from another database, and a withdrawn one.
        let mut alias = ghsa.clone();
        alias.id = "RUSTSEC-0000-0000".into();
        alias.source = Source::RustSec;
        alias.aliases = vec!["GHSA-35jh-r3h4-6jhm".into()];
        let mut withdrawn = ghsa.clone();
        withdrawn.id = "GHSA-gone".into();
        withdrawn.aliases = vec![];
        withdrawn.withdrawn = Some("2024-01-01T00:00:00Z".into());
        let deps = [
            dep("lodash", "4.17.20", "pkg:npm/lodash@4.17.20"),
            dep("lodash", "4.17.20", "pkg:npm/lodash@4.17.20"),
            dep("lodash", "4.17.21", "pkg:npm/lodash@4.17.21"),
        ];
        let found = check(&deps, &[alias, withdrawn, ghsa]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].advisory, "GHSA-35jh-r3h4-6jhm");
        assert_eq!(found[0].fixed_in.as_deref(), Some("4.17.21"));
        assert_eq!(found[0].severity, Severity::Critical);
    }

    #[test]
    fn severity_without_a_v3_score() {
        assert_eq!(severity(None, Some("critical")), Severity::Blocker);
        assert_eq!(severity(None, Some("MODERATE")), Severity::Major);
        assert_eq!(severity(None, None), Severity::Major);
        assert_eq!(
            severity(Some(9.8), Some("LOW")),
            Severity::Blocker,
            "the score wins"
        );
    }
}
