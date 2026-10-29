//! New code: lines that differ between the working tree and the merge base
//! with a reference branch, plus files that did not exist there. This module
//! is pure; `crate::git` reads the merge base.

use similar::{DiffTag, TextDiff};
use std::collections::{HashMap, HashSet};
use std::time::Duration;

/// Past this, the line diff of a single file approximates (marks more lines
/// as changed) instead of searching for the minimal diff.
const DIFF_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug)]
pub(crate) enum NewCode {
    /// No reference given: the whole project counts as new code.
    Everything,
    Changes {
        reference: String,
        /// Only files that differ from the merge base are present.
        files: HashMap<String, Changed>,
    },
}

#[derive(Debug, PartialEq)]
pub(crate) enum Changed {
    All,
    /// 1-based line numbers.
    Lines(HashSet<usize>),
}

impl NewCode {
    pub(crate) fn reference(&self) -> Option<&str> {
        match self {
            NewCode::Everything => None,
            NewCode::Changes { reference, .. } => Some(reference),
        }
    }

    pub(crate) fn is_new(&self, path: &str, line: usize) -> bool {
        match self {
            NewCode::Everything => true,
            NewCode::Changes { files, .. } => match files.get(path) {
                Some(Changed::All) => true,
                Some(Changed::Lines(lines)) => lines.contains(&line),
                None => false,
            },
        }
    }
}

/// Lines of `new` that were added or modified relative to `old`.
pub(crate) fn changed_lines(old: &str, new: &str) -> HashSet<usize> {
    let diff = TextDiff::configure()
        .timeout(DIFF_TIMEOUT)
        .diff_lines(old, new);
    diff.ops()
        .iter()
        .map(|op| op.as_tag_tuple())
        .filter(|(tag, _, _)| matches!(tag, DiffTag::Insert | DiffTag::Replace))
        .flat_map(|(_, _, new_range)| new_range.map(|i| i + 1))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changed_lines_are_inserts_and_replacements() {
        let old = "a\nb\nc\nd\n";
        let new = "a\nB\nc\nnew\nd\n";
        assert_eq!(changed_lines(old, new), HashSet::from([2, 4]));
        assert!(changed_lines(old, old).is_empty());
        assert!(changed_lines(old, "a\nd\n").is_empty()); // deletions add no lines
    }

    #[test]
    fn everything_is_new_without_a_reference() {
        assert!(NewCode::Everything.is_new("any.py", 7));
        let nc = NewCode::Changes {
            reference: "main".into(),
            files: HashMap::from([("a.py".into(), Changed::Lines(HashSet::from([2])))]),
        };
        assert!(nc.is_new("a.py", 2) && !nc.is_new("a.py", 1) && !nc.is_new("b.py", 1));
    }
}
