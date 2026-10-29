use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, Serialize)]
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
}
