//! Interface: turns an [`Outcome`] into text, JSON or SARIF.

mod sarif;
pub mod sbom;
mod text;

pub use text::{terminal_safe, terminal_safe_lines};

use crate::Outcome;
use crate::deps::Dependency;
use crate::gate::GateResult;
use crate::lang::Lang;
use crate::measures::Measures;
use crate::model::{FileMetrics, Issue, Severity, Sha256};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Text,
    Json,
    Sarif,
}

/// The JSON report's format version. The report is a contract with
/// `sonda upload` and the server: adding fields keeps the version; removing
/// or changing one bumps it.
pub const REPORT_VERSION: u32 = 1;

#[derive(Serialize)]
pub struct Report<'a> {
    pub tool: &'static str,
    pub version: &'static str,
    pub report_version: u32,
    /// The branch new code is compared against; `None` means the whole project is new code.
    pub new_code_reference: Option<&'a str>,
    /// How it was chosen: `given`, `pull_request`, `push`,
    /// `default_branch`, `uncommitted` or `whole_project` (ADR-0010).
    pub new_code_basis: &'static str,
    /// What counts as new code, in words.
    pub new_code_description: String,
    pub measures: &'a Measures,
    pub gate: &'a GateResult,
    pub files: Vec<FileReport<'a>>,
    pub duplications: Vec<DuplicationReport<'a>>,
    pub issues: Vec<&'a Issue>,
    /// From the project's lockfiles (ADR-0009).
    pub dependencies: &'a [Dependency],
    /// Known vulnerabilities in them, most severe first; absent unless
    /// checked against advisories (`--advisories`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vulnerabilities: Option<&'a [crate::advisories::Vulnerability]>,
    pub warnings: &'a [String],
    /// The `[rules]` settings of the project's sonda.toml the scan ran
    /// with, so the server can show why a rule reports nothing (ADR-0016).
    pub rule_settings: RuleSettings<'a>,
    /// The server's rule profile the scan applied (ADR-0018), set by
    /// `sonda scan --upload`; absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_profile: Option<AppliedProfile>,
}

/// The server's rule profile a scan applied, as the server named it.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct AppliedProfile {
    pub name: String,
    /// Opaque: the server compares it with its current settings.
    pub revision: String,
}

#[derive(Serialize)]
pub struct FileReport<'a> {
    pub path: &'a str,
    pub language: Lang,
    #[serde(flatten)]
    pub metrics: FileMetrics,
    pub duplicated_lines: usize,
    pub sha256: Sha256,
    /// The lines the coverage reports list for this file; absent when they
    /// don't cover it, or without `--coverage`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage: Option<FileCoverage>,
    /// Lines with branches and how many of them ran, from LCOV's `BRDA`;
    /// absent when the coverage reports have none for this file.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub branch_coverage: Vec<LineBranches>,
    /// Functions and how often each was called, from LCOV's `FN` and
    /// `FNDA`; absent when the coverage reports have none for this file.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub function_coverage: Vec<FunctionCalls>,
}

/// The branches starting on one line, such as an `if`'s two outcomes.
#[derive(Serialize, Debug, PartialEq)]
pub struct LineBranches {
    pub line: usize,
    /// Branches taken at least once.
    pub taken: usize,
    pub total: usize,
}

#[derive(Serialize, Debug, PartialEq)]
pub struct FunctionCalls {
    pub name: String,
    pub line: usize,
    pub calls: u64,
}

/// One file's coverage, as line numbers, ascending. The server computes
/// coverage on its own new code from them (ADR-0011).
#[derive(Serialize, Debug, PartialEq)]
pub struct FileCoverage {
    pub covered: Vec<usize>,
    pub uncovered: Vec<usize>,
}

impl FileCoverage {
    fn from_hits(hits: &std::collections::BTreeMap<usize, u64>) -> Self {
        let (covered, uncovered) = hits.iter().partition::<Vec<_>, _>(|(_, h)| **h > 0);
        let lines = |v: Vec<(&usize, &u64)>| v.into_iter().map(|(l, _)| *l).collect();
        FileCoverage {
            covered: lines(covered),
            uncovered: lines(uncovered),
        }
    }
}

#[derive(Serialize)]
pub struct DuplicationReport<'a> {
    pub original: Location<'a>,
    pub copy: Location<'a>,
}

#[derive(Serialize)]
pub struct Location<'a> {
    pub path: &'a str,
    pub start_line: usize,
    pub end_line: usize,
}

type Branches = std::collections::BTreeMap<(usize, String, String), u64>;
type Functions = std::collections::BTreeMap<(usize, String), u64>;

fn line_branches(branches: Option<&Branches>) -> Vec<LineBranches> {
    let mut lines: Vec<LineBranches> = Vec::new();
    // Keys sort by line first, so each line's branches are adjacent.
    for ((line, _, _), &taken) in branches.into_iter().flatten() {
        match lines.last_mut() {
            Some(l) if l.line == *line => {
                l.total += 1;
                l.taken += usize::from(taken > 0);
            }
            _ => lines.push(LineBranches {
                line: *line,
                taken: usize::from(taken > 0),
                total: 1,
            }),
        }
    }
    lines
}

/// By line, then name.
fn function_calls(functions: Option<&Functions>) -> Vec<FunctionCalls> {
    functions
        .into_iter()
        .flatten()
        .map(|((line, name), &calls)| FunctionCalls {
            name: name.clone(),
            line: *line,
            calls,
        })
        .collect()
}

/// `only_new` limits the listed issues to new code; measures and gate are unaffected.
pub fn build(outcome: &Outcome, only_new: bool) -> Report<'_> {
    let scan = &outcome.analysis;
    let files = scan
        .files
        .iter()
        .zip(&scan.duplication.lines)
        .map(|(f, dup)| FileReport {
            path: &f.path,
            language: f.lang,
            metrics: f.metrics,
            duplicated_lines: dup.len(),
            sha256: f.sha256,
            coverage: scan
                .coverage
                .files
                .get(&f.path)
                .map(FileCoverage::from_hits),
            branch_coverage: line_branches(scan.coverage.branches.get(&f.path)),
            function_coverage: function_calls(scan.coverage.functions.get(&f.path)),
        })
        .collect();
    let loc = |s: crate::duplication::Span| Location {
        path: &scan.files[s.file].path,
        start_line: s.start_line,
        end_line: s.end_line,
    };
    let duplications = scan
        .duplication
        .blocks
        .iter()
        .map(|b| DuplicationReport {
            original: loc(b.original),
            copy: loc(b.copy),
        })
        .collect();
    let issues = scan
        .files
        .iter()
        .flat_map(|f| &f.issues)
        .filter(|i| !only_new || i.is_new)
        .collect();
    Report {
        tool: "sonda",
        version: env!("CARGO_PKG_VERSION"),
        report_version: REPORT_VERSION,
        new_code_reference: scan.new_code.reference(),
        new_code_basis: scan.new_code_basis.kind(),
        new_code_description: scan.new_code_basis.describe(),
        measures: &outcome.measures,
        gate: &outcome.gate,
        files,
        duplications,
        issues,
        dependencies: &scan.dependencies,
        vulnerabilities: scan.vulnerabilities.as_deref(),
        warnings: &scan.warnings,
        rule_settings: RuleSettings::from_config(&outcome.rules),
        rule_profile: None,
    }
}

/// `[rules]` from sonda.toml, sorted so the report stays deterministic.
#[derive(Serialize)]
pub struct RuleSettings<'a> {
    /// Rules turned off.
    pub disabled: Vec<&'a str>,
    /// Off-by-default rules turned on.
    pub enabled: Vec<&'a str>,
    /// Changed severities, by rule.
    pub severity: BTreeMap<&'a str, Severity>,
}

impl<'a> RuleSettings<'a> {
    fn from_config(rules: &'a crate::config::RulesConfig) -> Self {
        let sorted = |ids: &'a [String]| {
            let mut v: Vec<&str> = ids.iter().map(String::as_str).collect();
            v.sort_unstable();
            v.dedup();
            v
        };
        RuleSettings {
            disabled: sorted(&rules.disabled),
            enabled: sorted(&rules.enabled),
            severity: rules
                .severity
                .iter()
                .map(|(k, v)| (k.as_str(), *v))
                .collect(),
        }
    }
}

pub fn render(report: &Report, format: Format) -> String {
    match format {
        Format::Text => text::render(report),
        // Cannot fail: every map key serializes as a string (`Metric` is a
        // unit-variant enum) and no type has a fallible Serialize impl.
        Format::Json => serde_json::to_string_pretty(report).expect("report serializes") + "\n",
        Format::Sarif => sarif::render(report),
    }
}
