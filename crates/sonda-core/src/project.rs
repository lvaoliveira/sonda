use crate::advisories::Vulnerability;
use crate::analysis::FileAnalysis;
use crate::coverage::Coverage;
use crate::deps::Dependency;
use crate::duplication::Duplication;
use crate::newcode::{Basis, NewCode};

/// Everything known about a project after analysis: the input to measures,
/// the quality gate and reports.
pub struct ProjectAnalysis {
    /// Sorted by path.
    pub(crate) files: Vec<FileAnalysis>,
    /// `duplication.lines` is indexed like `files`.
    pub(crate) duplication: Duplication,
    pub(crate) coverage: Coverage,
    pub(crate) new_code: NewCode,
    /// How new code's reference was chosen (ADR-0010).
    pub(crate) new_code_basis: Basis,
    /// Files that were skipped or only partly analyzed. Sorted.
    pub(crate) warnings: Vec<String>,
    /// From the project's lockfiles (ADR-0009). Sorted.
    pub(crate) dependencies: Vec<Dependency>,
    /// Known vulnerabilities in them, when checked against advisories
    /// (`ScanOptions::advisories`); `None` when not checked.
    pub(crate) vulnerabilities: Option<Vec<Vulnerability>>,
}
