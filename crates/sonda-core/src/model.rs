//! Plain data types shared by every layer. This module depends on nothing
//! else in the crate.

use serde::{Deserialize, Serialize};

/// Size and complexity of one file.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct FileMetrics {
    pub lines: usize,
    /// Lines containing code (not only comments or whitespace).
    pub ncloc: usize,
    pub comment_lines: usize,
    pub functions: usize,
    pub complexity: u32,
    pub cognitive_complexity: u32,
}

/// Declares `Metric` with its serialized names, plus `Metric::ALL`.
macro_rules! metrics {
    ($($variant:ident => $name:literal,)*) => {
        /// A project-level measure, usable in quality-gate conditions. Metrics
        /// starting with `new_` only look at new code.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        pub enum Metric {
            $(#[serde(rename = $name)] $variant,)*
        }

        impl Metric {
            pub const ALL: &[Metric] = &[$(Metric::$variant,)*];

            pub fn as_str(self) -> &'static str {
                match self {
                    $(Metric::$variant => $name,)*
                }
            }
        }
    };
}

metrics! {
    Files => "files",
    Lines => "lines",
    Ncloc => "ncloc",
    Functions => "functions",
    Complexity => "complexity",
    CognitiveComplexity => "cognitive_complexity",
    Issues => "issues",
    Bugs => "bugs",
    Vulnerabilities => "vulnerabilities",
    CodeSmells => "code_smells",
    BlockerIssues => "blocker_issues",
    CriticalIssues => "critical_issues",
    MajorIssues => "major_issues",
    DebtMinutes => "debt_minutes",
    DuplicatedLines => "duplicated_lines",
    DuplicatedLinesDensity => "duplicated_lines_density",
    Coverage => "coverage",
    NewLines => "new_lines",
    NewIssues => "new_issues",
    NewBugs => "new_bugs",
    NewVulnerabilities => "new_vulnerabilities",
    NewCodeSmells => "new_code_smells",
    NewBlockerIssues => "new_blocker_issues",
    NewCriticalIssues => "new_critical_issues",
    NewMajorIssues => "new_major_issues",
    NewDebtMinutes => "new_debt_minutes",
    NewDuplicatedLines => "new_duplicated_lines",
    NewDuplicatedLinesDensity => "new_duplicated_lines_density",
    NewCoverage => "new_coverage",
}

/// A quality-gate condition: the gate fails when `metric <op> threshold` holds.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    pub metric: Metric,
    pub op: Op,
    pub threshold: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Op {
    Gt,
    Lt,
}

impl Op {
    pub fn symbol(self) -> &'static str {
        match self {
            Op::Gt => ">",
            Op::Lt => "<",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Minor,
    Major,
    Critical,
    Blocker,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Minor => "minor",
            Severity::Major => "major",
            Severity::Critical => "critical",
            Severity::Blocker => "blocker",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Bug,
    Vulnerability,
    CodeSmell,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Bug => "bug",
            Category::Vulnerability => "vulnerability",
            Category::CodeSmell => "code_smell",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Category::Bug => "Bug",
            Category::Vulnerability => "Vulnerability",
            Category::CodeSmell => "Code smell",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Issue {
    pub rule: &'static str,
    pub severity: Severity,
    pub category: Category,
    pub message: String,
    /// Path relative to the scan root, always with forward slashes.
    pub path: String,
    /// 1-based line and column (columns count characters).
    pub line: usize,
    pub column: usize,
    pub end_line: usize,
    pub end_column: usize,
    pub effort_minutes: u32,
    /// Whether the issue sits on a line that counts as new code.
    pub is_new: bool,
    /// The issue's identity across scans; see `analysis::fingerprints`.
    pub fingerprint: Fingerprint,
}

/// A hash, serialized as lowercase hex.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest<const N: usize>(pub [u8; N]);

/// Identifies an issue across scans: 128 bits of SHA-256.
pub type Fingerprint = Digest<16>;
/// The SHA-256 of a file's analyzed bytes.
pub type Sha256 = Digest<32>;

impl<const N: usize> Default for Digest<N> {
    fn default() -> Self {
        Self([0; N])
    }
}

impl<const N: usize> std::fmt::Display for Digest<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

impl<const N: usize> Serialize for Digest<N> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}
