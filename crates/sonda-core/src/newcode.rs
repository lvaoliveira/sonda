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

/// How the new-code reference was chosen (ADR-0010).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Basis {
    /// Named by `--new-code` or `scan.new_code`.
    Given(String),
    /// A pull request, against its base branch.
    PullRequest(String),
    /// A push in CI, against the commit it replaced.
    Push(String),
    /// A branch with commits its default branch lacks: the merge base with
    /// that branch (`origin/main`, say).
    DefaultBranch(String),
    /// Nothing else applies (a local run on the default branch, say):
    /// uncommitted changes, against HEAD.
    Uncommitted,
    /// Nothing to compare with; why.
    WholeProject(String),
}

impl Basis {
    /// For reports: `given`, `pull_request`, `push`, `default_branch`,
    /// `uncommitted`, `whole_project`.
    pub fn kind(&self) -> &'static str {
        match self {
            Basis::Given(_) => "given",
            Basis::PullRequest(_) => "pull_request",
            Basis::Push(_) => "push",
            Basis::DefaultBranch(_) => "default_branch",
            Basis::Uncommitted => "uncommitted",
            Basis::WholeProject(_) => "whole_project",
        }
    }

    /// What counts as new code, in words.
    pub fn describe(&self) -> String {
        match self {
            Basis::Given(r) => format!("changes since {r}"),
            Basis::PullRequest(b) => format!("changes in this pull request, against {b}"),
            Basis::Push(before) => format!(
                "changes in this push, since {}",
                &before[..before.len().min(12)]
            ),
            Basis::DefaultBranch(b) => format!("changes since the merge base with {b}"),
            Basis::Uncommitted => "uncommitted changes, against HEAD".into(),
            Basis::WholeProject(why) => format!("the whole project ({why})"),
        }
    }
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
    use proptest::prelude::*;

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

    fn text() -> impl Strategy<Value = String> {
        prop::collection::vec(prop::sample::select(vec!["a", "b", "c", ""]), 0..40)
            .prop_map(|lines| lines.iter().map(|l| format!("{l}\n")).collect())
    }

    proptest! {
        #![proptest_config(crate::test_support::proptest_config(256))]

        #[test]
        fn changed_lines_are_lines_of_the_new_text(old in text(), new in text()) {
            let changed = changed_lines(&old, &new);
            let count = new.lines().count();
            prop_assert!(changed.iter().all(|&l| l >= 1 && l <= count));
            prop_assert!(changed_lines(&new, &new).is_empty());
            let all: HashSet<usize> = (1..=count).collect();
            prop_assert_eq!(changed_lines("", &new), all);
        }
    }
}
