//! C++ rules that need classes from other files of the project (ADR-0020):
//! a member function compared with its bases' functions. They run once per
//! scan, on the index the files' summaries build (`semantic::cpp_index`),
//! and are `Check::Structural` in the catalog.
//!
//! A base outside the project (Qt's, the standard library's) resolves to
//! nothing, and nothing is reported about it.

use crate::semantic::cpp_index::{ClassId, FACT, FileIndex, MethodDecl, ProjectIndex};
use crate::semantic::cs_index::Span;

/// A finding: the rule, the index of the file it's in, and where.
pub(crate) type Finding = (&'static str, usize, Span);

pub(crate) const HIDDEN_FUNCTION: &str = "cpp/hidden-inherited-function";

/// The rules this module checks.
pub(crate) const RULES: &[&str] = &[HIDDEN_FUNCTION];

/// Checks the active rules on every file's summary.
pub(crate) fn run<'f>(
    facts: impl Iterator<Item = &'f [(String, String)]>,
    active: &[&str],
) -> Vec<Finding> {
    if !RULES.iter().any(|r| active.contains(r)) {
        return Vec::new();
    }
    // (position in the scanner's list, the file's summary)
    let parsed: Vec<(usize, FileIndex)> = facts
        .enumerate()
        .filter_map(|(i, f)| {
            let (_, json) = f.iter().find(|(k, _)| k == FACT)?;
            serde_json::from_str(json).ok().map(|x| (i, x))
        })
        .collect();
    let index = ProjectIndex::new(parsed.iter().map(|(_, x)| x).collect());
    let mut found: Vec<Finding> = Vec::new();
    for (f, file) in index.files().iter().enumerate() {
        for c in 0..file.classes.len() {
            if active.contains(&HIDDEN_FUNCTION) {
                hidden_functions(&index, (f, c), &mut found);
            }
        }
    }
    found
        .into_iter()
        .map(|(rule, file, span)| (rule, parsed[file].0, span))
        .collect()
}

/// A public or protected member function named like functions of its
/// bases, which it hides: a non-virtual one (not private), or virtual
/// overloads it doesn't override each of. Every base counts, as SonarCloud
/// counts them: one an intermediate class hides already is hidden again.
/// Not when `using Base::name;` brings the base's in.
fn hidden_functions(index: &ProjectIndex, id: ClassId, found: &mut Vec<Finding>) {
    let class = index.class(id);
    if class.bases.is_empty() {
        return;
    }
    let ancestors = index.ancestors(id);
    let mut reported_overloads: Vec<&str> = Vec::new();
    for m in &class.methods {
        // A private function hides nothing callers could reach.
        if m.private_ || class.using.contains(&m.name) {
            continue;
        }
        let theirs: Vec<(ClassId, &MethodDecl)> = ancestors
            .iter()
            .flat_map(|b| {
                index
                    .class(*b)
                    .methods
                    .iter()
                    .filter(|x| x.name == m.name)
                    .map(move |x| (*b, x))
            })
            .collect();
        if theirs.is_empty() {
            continue;
        }
        let virtual_in =
            |base: ClassId, x: &MethodDecl| {
                x.virtual_
                    || index.ancestors(base).iter().any(|a| {
                        index.class(*a).methods.iter().any(|y| {
                            y.name == x.name && y.virtual_ && y.params.len() == x.params.len()
                        })
                    })
            };
        if theirs
            .iter()
            .any(|(b, x)| !x.private_ && !virtual_in(*b, x))
        {
            found.push((HIDDEN_FUNCTION, id.0, m.span));
            continue;
        }
        // Every one virtual: each must be overridden here, or the ones left
        // out are hidden.
        if reported_overloads.contains(&m.name.as_str()) {
            continue;
        }
        let ours: Vec<&MethodDecl> = class.methods.iter().filter(|x| x.name == m.name).collect();
        if theirs
            .iter()
            .any(|(_, x)| !ours.iter().any(|o| o.params == x.params))
        {
            reported_overloads.push(&m.name);
            found.push((HIDDEN_FUNCTION, id.0, m.span));
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::analyze;
    use crate::analysis::tests::far_deadline;
    use crate::config::Config;
    use crate::lang::Lang;
    use crate::rules::RuleSet;

    /// `rule`'s findings over files given as (path, source), as (path, line).
    fn flagged(rule: &str, files: &[(&str, &str)]) -> Vec<(String, usize)> {
        let mut cfg = Config::default();
        cfg.rules.enabled = vec![rule.to_string()];
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let mut analyzed: Vec<_> = files
            .iter()
            .map(|(path, src)| analyze(path, Lang::Cpp, src, &rules, &cfg, far_deadline()).unwrap())
            .collect();
        crate::analysis::cpp_project_rules(&mut analyzed, &rules);
        let mut found: Vec<(String, usize)> = analyzed
            .iter()
            .flat_map(|f| {
                f.issues
                    .iter()
                    .filter(|i| i.rule == rule)
                    .map(|i| (f.path.clone(), i.line))
            })
            .collect();
        found.sort();
        found
    }

    fn at(path: &str, line: usize) -> (String, usize) {
        (path.to_string(), line)
    }

    /// Shapes from SonarCloud's analysis of roo_display, the bases in
    /// another file.
    #[test]
    fn hidden_inherited_functions() {
        let base = (
            "output.h",
            "namespace gfx {\nclass Output {\n public:\n  void setAddress(const Box& b, int mode);\n  virtual void setAddress(int x0, int y0, int mode) = 0;\n  virtual void fill(int color);\n  virtual void fill(int color, int count);\n  void read(int* buf);\n  virtual void read(int* buf, int n) = 0;\n};\n}",
        );
        let derived = (
            "device.cpp",
            "namespace gfx {\nclass Device : public Output {\n public:\n  void setAddress(int x0, int y0, int mode) override;\n  void fill(int color) override;\n private:\n  void read(int* buf, int n) override;\n};\nclass Stream : public Output {\n public:\n  using Output::read;\n  void read(int* buf, int n) override;\n};\nclass Counting : public Stream {\n public:\n  void read(int* buf, int n) override;\n};\nclass Widget : public QWidget {\n public:\n  void updateGeometry();\n};\n}",
        );
        assert_eq!(
            flagged("cpp/hidden-inherited-function", &[base, derived]),
            [
                // A non-virtual overload hidden by an override.
                at("device.cpp", 4),
                // One of two virtual overloads overridden.
                at("device.cpp", 5),
                // Brought in one level up, hidden again below.
                at("device.cpp", 16),
            ]
        );
    }
}
