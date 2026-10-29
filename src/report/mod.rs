mod sarif;
mod text;

pub use text::terminal_safe;

use crate::analysis::FileMetrics;
use crate::gate::GateResult;
use crate::lang::Lang;
use crate::measures::Measures;
use crate::model::Issue;
use crate::scanner::ScanResult;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    Text,
    Json,
    Sarif,
}

#[derive(Serialize)]
pub struct Report<'a> {
    pub tool: &'static str,
    pub version: &'static str,
    /// The branch new code is compared against; `None` means the whole project is new code.
    pub new_code_reference: Option<&'a str>,
    pub measures: &'a Measures,
    pub gate: &'a GateResult,
    pub files: Vec<FileReport<'a>>,
    pub duplications: Vec<DuplicationReport<'a>>,
    pub issues: Vec<&'a Issue>,
    pub warnings: &'a [String],
}

#[derive(Serialize)]
pub struct FileReport<'a> {
    pub path: &'a str,
    pub language: Lang,
    #[serde(flatten)]
    pub metrics: FileMetrics,
    pub duplicated_lines: usize,
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

/// `only_new` limits the listed issues to new code; measures and gate are unaffected.
pub fn build<'a>(
    scan: &'a ScanResult,
    measures: &'a Measures,
    gate: &'a GateResult,
    only_new: bool,
) -> Report<'a> {
    let files = scan
        .files
        .iter()
        .zip(&scan.duplication.lines)
        .map(|(f, dup)| FileReport {
            path: &f.path,
            language: f.lang,
            metrics: f.metrics,
            duplicated_lines: dup.len(),
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
        new_code_reference: scan.new_code.reference(),
        measures,
        gate,
        files,
        duplications,
        issues,
        warnings: &scan.warnings,
    }
}

pub fn render(report: &Report, format: Format) -> String {
    match format {
        Format::Text => text::render(report),
        Format::Json => serde_json::to_string_pretty(report).expect("report serializes") + "\n",
        Format::Sarif => sarif::render(report),
    }
}
