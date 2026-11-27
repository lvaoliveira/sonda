//! `[[rules.ignore]]` (the stability promise's `sonda.toml`): a rule that
//! doesn't report in some paths. Applied once every pass has run, so it
//! covers what the project's passes add too (a taint finding is at its sink's
//! file).

use crate::analysis::FileAnalysis;
use crate::config::IgnoreRule;
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use std::path::Path;

pub(crate) struct PathIgnores {
    entries: Vec<(Gitignore, Vec<String>)>,
}

impl PathIgnores {
    /// The matchers of the settings, or what's wrong with them.
    pub(crate) fn new(list: &[IgnoreRule]) -> Result<Self, String> {
        let mut entries = Vec::new();
        for (n, entry) in list.iter().enumerate() {
            if entry.paths.is_empty() || entry.rules.is_empty() {
                return Err(format!(
                    "rules.ignore #{}: `paths` and `rules` each need at least one entry",
                    n + 1
                ));
            }
            let mut builder = GitignoreBuilder::new("");
            for pattern in &entry.paths {
                builder.add_line(None, pattern).map_err(|e| {
                    format!("rules.ignore #{}: invalid path '{pattern}': {e}", n + 1)
                })?;
            }
            let paths = builder
                .build()
                .map_err(|e| format!("rules.ignore #{}: {e}", n + 1))?;
            entries.push((paths, entry.rules.clone()));
        }
        Ok(PathIgnores { entries })
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether `rule` doesn't report in `path` (relative, `/`-separated).
    pub(crate) fn applies(&self, path: &str, rule: &str) -> bool {
        self.entries.iter().any(|(paths, rules)| {
            rules.iter().any(|r| matches_rule(r, rule))
                && paths
                    .matched_path_or_any_parents(Path::new(path), false)
                    .is_ignore()
        })
    }
}

/// Whether the setting `pattern` names `rule`: its id, or a prefix and `*`.
pub(crate) fn matches_rule(pattern: &str, rule: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => rule.starts_with(prefix),
        None => pattern == rule,
    }
}

/// Drops what the settings say doesn't report.
pub(crate) fn apply(files: &mut [FileAnalysis], ignores: &PathIgnores) {
    if ignores.is_empty() {
        return;
    }
    for f in files {
        let path = f.path.clone();
        f.issues.retain(|i| !ignores.applies(&path, i.rule));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(paths: &[&str], rules: &[&str]) -> IgnoreRule {
        IgnoreRule {
            paths: paths.iter().map(ToString::to_string).collect(),
            rules: rules.iter().map(ToString::to_string).collect(),
        }
    }

    #[test]
    fn a_rule_by_id_or_prefix_in_the_paths_that_match() {
        let ignores = PathIgnores::new(&[
            entry(
                &["db/legacy/**", "**/*_generated.rb"],
                &["ruby/sql-interpolation"],
            ),
            entry(&["lib/tasks"], &["ruby/*"]),
        ])
        .unwrap();
        assert!(ignores.applies("db/legacy/a/b.rb", "ruby/sql-interpolation"));
        assert!(ignores.applies("app/x_generated.rb", "ruby/sql-interpolation"));
        // Another rule, another path.
        assert!(!ignores.applies("db/legacy/a.rb", "ruby/eval"));
        assert!(!ignores.applies("app/models/a.rb", "ruby/sql-interpolation"));
        // A directory, and a prefix: every Ruby rule, none of another language's.
        assert!(ignores.applies("lib/tasks/ci.rake", "ruby/eval"));
        assert!(!ignores.applies("lib/tasks/ci.rake", "py/eval"));
    }

    #[test]
    fn settings_that_say_nothing_or_cant_be_read_are_errors() {
        assert!(PathIgnores::new(&[entry(&[], &["ruby/eval"])]).is_err());
        assert!(PathIgnores::new(&[entry(&["a/**"], &[])]).is_err());
        assert!(PathIgnores::new(&[entry(&["[z-a]"], &["ruby/eval"])]).is_err());
    }
}
