use crate::analysis::FileAnalysis;
use crate::coverage::Coverage;
use crate::duplication::Duplication;
use crate::newcode::NewCode;

/// Everything known about a project after analysis: the input to measures,
/// the quality gate and reports.
pub struct ProjectAnalysis {
    /// Sorted by path.
    pub(crate) files: Vec<FileAnalysis>,
    /// `duplication.lines` is indexed like `files`.
    pub(crate) duplication: Duplication,
    pub(crate) coverage: Coverage,
    pub(crate) new_code: NewCode,
    /// Files that were skipped or only partly analyzed. Sorted.
    pub(crate) warnings: Vec<String>,
}
