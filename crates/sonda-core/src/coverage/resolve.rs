//! Matching the files an XML coverage report names to the files scanned.

use super::Candidates;
use std::collections::{HashMap, HashSet};

pub(crate) struct Resolver<'a> {
    scanned: &'a HashSet<&'a str>,
    /// The report's directory and its parents, deepest first: tests ran in
    /// the nearest, so a path is tried under each (see `load_coverage`).
    bases: &'a [String],
    /// Scanned paths by their last component, for matching a path's end.
    by_name: HashMap<&'a str, Vec<&'a str>>,
}

impl<'a> Resolver<'a> {
    pub(crate) fn new(scanned: &'a HashSet<&'a str>, bases: &'a [String]) -> Self {
        let mut by_name: HashMap<&str, Vec<&str>> = HashMap::new();
        for path in scanned {
            let name = path.rsplit('/').next().unwrap_or(path);
            by_name.entry(name).or_default().push(path);
        }
        Resolver {
            scanned,
            bases,
            by_name,
        }
    }

    /// The scanned file a report's file is: the first candidate that names
    /// one, else the first candidate as written.
    pub(crate) fn resolve(&self, candidates: &Candidates) -> String {
        candidates
            .paths
            .iter()
            .find_map(|path| self.find(path, candidates.suffix))
            .or_else(|| candidates.paths.first().cloned())
            .unwrap_or_default()
    }

    fn find(&self, path: &str, suffix: bool) -> Option<String> {
        if path.is_empty() || path.starts_with('/') {
            return None;
        }
        let under_base = self
            .bases
            .iter()
            .filter_map(|base| super::normalize(&format!("{base}/{path}")))
            .find(|candidate| self.scanned.contains(candidate.as_str()));
        if under_base.is_some() {
            return under_base;
        }
        if self.scanned.contains(path) {
            return Some(path.to_string());
        }
        suffix.then(|| self.by_suffix(path)).flatten()
    }

    /// The scanned file whose path ends with `/path`: the only one, or the
    /// one under the report's own directories if several do. With several
    /// elsewhere, none: a wrong file's coverage is worse than none.
    fn by_suffix(&self, path: &str) -> Option<String> {
        let name = path.rsplit('/').next().unwrap_or(path);
        let end = format!("/{path}");
        let found: Vec<&str> = self
            .by_name
            .get(name)?
            .iter()
            .copied()
            .filter(|p| p.ends_with(&end))
            .collect();
        let near: Vec<&str> = found
            .iter()
            .copied()
            .filter(|p| self.bases.iter().any(|b| p.starts_with(&format!("{b}/"))))
            .collect();
        let pick = match (near.as_slice(), found.as_slice()) {
            ([one], _) | ([], [one]) => one,
            _ => return None,
        };
        Some(pick.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidates(path: &str, suffix: bool) -> Candidates {
        Candidates {
            paths: vec![path.to_string()],
            suffix,
        }
    }

    #[test]
    fn matches_by_path_then_base_then_suffix() {
        let scanned: HashSet<&str> = [
            "src/a.py",
            "svc/src/a.py",
            "svc/src/main/java/com/acme/Util.java",
            "other/src/main/java/com/acme/Util.java",
        ]
        .into();
        let bases = vec!["svc".to_string()];
        let r = Resolver::new(&scanned, &bases);
        // Tests ran in `svc`, so its file wins over the root's.
        assert_eq!(r.resolve(&candidates("src/a.py", false)), "svc/src/a.py");
        // A path's end finds a Java file; the report's own module wins.
        let util = candidates("com/acme/Util.java", true);
        assert_eq!(r.resolve(&util), "svc/src/main/java/com/acme/Util.java");
        // Without the suffix rule, and for a file nothing matches, the
        // candidate stays as written.
        assert_eq!(
            r.resolve(&candidates("com/acme/Util.java", false)),
            "com/acme/Util.java"
        );
        assert_eq!(r.resolve(&candidates("/abs/x.py", true)), "/abs/x.py");
    }

    #[test]
    fn several_matches_away_from_the_report_match_nothing() {
        let scanned: HashSet<&str> = ["a/src/U.java", "b/src/U.java"].into();
        let r = Resolver::new(&scanned, &[]);
        assert_eq!(r.resolve(&candidates("src/U.java", true)), "src/U.java");
        let near = vec!["b".to_string()];
        let r = Resolver::new(&scanned, &near);
        assert_eq!(r.resolve(&candidates("src/U.java", true)), "b/src/U.java");
    }

    #[test]
    fn a_later_candidate_is_used_when_the_first_matches_nothing() {
        let scanned: HashSet<&str> = ["pkg/mod.py"].into();
        let r = Resolver::new(&scanned, &[]);
        let c = Candidates {
            paths: vec!["src/pkg/mod.py".to_string(), "pkg/mod.py".to_string()],
            suffix: false,
        };
        assert_eq!(r.resolve(&c), "pkg/mod.py");
    }
}
