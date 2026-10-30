//! LCOV coverage data (`--coverage lcov.info`). LCOV is produced by
//! istanbul/c8/vitest (JS/TS), coverage.py (`coverage lcov`), gcov/lcov and
//! llvm-cov (C/C++), and can be converted from JaCoCo. Parsing is pure;
//! reading the report files is done by the scanner.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::{Component, Path};

#[derive(Debug, Default)]
pub(crate) struct Coverage {
    /// Root-relative path -> 1-based line -> hit count.
    pub(crate) files: HashMap<String, BTreeMap<usize, u64>>,
    /// Root-relative path -> (line, block, branch) -> times taken. LCOV's
    /// `BRDA`; a branch whose block never ran (`-`) was taken 0 times.
    pub(crate) branches: HashMap<String, BTreeMap<(usize, String, String), u64>>,
    /// Root-relative path -> (line, function name) -> calls. LCOV's `FN`
    /// and `FNDA`; a file can have two functions of one name.
    pub(crate) functions: HashMap<String, BTreeMap<(usize, String), u64>>,
}

impl Coverage {
    /// Adds one LCOV report. `SF:` paths under a root are made relative to the
    /// first of `roots` they are under (pass the scan root as given and
    /// canonicalized, so symlinked roots such as macOS `/tmp` match).
    pub(crate) fn merge_lcov(&mut self, text: &str, roots: &[&Path]) {
        let mut current: Option<String> = None;
        // The record's functions by name, in `FN` order: `FNDA` names a
        // function, and writers emit one per `FN`, in the same order, so
        // same-named functions take their calls in turn.
        let mut by_name: HashMap<String, VecDeque<usize>> = HashMap::new();
        for line in text.lines() {
            let line = line.trim();
            if let Some(sf) = line.strip_prefix("SF:") {
                current = Some(relative_path(Path::new(sf), roots));
                by_name.clear();
            } else if let Some(da) = line.strip_prefix("DA:") {
                let (Some(file), Some((ln, rest))) = (&current, da.split_once(',')) else {
                    continue;
                };
                let hits = rest.split(',').next().and_then(|h| h.parse::<u64>().ok());
                if let (Ok(ln), Some(hits)) = (ln.parse::<usize>(), hits) {
                    let entry = self.files.entry(file.clone()).or_default();
                    let total = entry.entry(ln).or_insert(0);
                    *total = total.saturating_add(hits);
                }
            } else if let Some(brda) = line.strip_prefix("BRDA:") {
                let Some(file) = &current else { continue };
                let parts: Vec<&str> = brda.splitn(4, ',').collect();
                let [ln, block, branch, taken] = parts[..] else {
                    continue;
                };
                let taken = if taken == "-" {
                    Some(0)
                } else {
                    taken.parse::<u64>().ok()
                };
                if let (Ok(ln), Some(taken)) = (ln.parse::<usize>(), taken) {
                    let entry = self.branches.entry(file.clone()).or_default();
                    let total = entry
                        .entry((ln, block.to_string(), branch.to_string()))
                        .or_insert(0);
                    *total = total.saturating_add(taken);
                }
            } else if let Some(fun) = line.strip_prefix("FN:") {
                // `FN:<line>,<name>`, or lcov 2's `FN:<line>,<end line>,<name>`.
                let Some(file) = &current else { continue };
                let Some((ln, rest)) = fun.split_once(',') else {
                    continue;
                };
                let name = match rest.split_once(',') {
                    Some((end, name)) if end.parse::<usize>().is_ok() => name,
                    _ => rest,
                };
                if let Ok(ln) = ln.parse::<usize>() {
                    self.functions
                        .entry(file.clone())
                        .or_default()
                        .entry((ln, name.to_string()))
                        .or_insert(0);
                    by_name.entry(name.to_string()).or_default().push_back(ln);
                }
            } else if let Some(fnda) = line.strip_prefix("FNDA:") {
                let (Some(file), Some((hits, name))) = (&current, fnda.split_once(',')) else {
                    continue;
                };
                // The next function of that name; extra calls go to the
                // last one, and calls for a function without `FN` are
                // dropped, since it has no line to show them on.
                let Some(lines) = by_name.get_mut(name) else {
                    continue;
                };
                let ln = if lines.len() > 1 {
                    lines.pop_front()
                } else {
                    lines.front().copied()
                };
                if let (Some(ln), Ok(hits)) = (ln, hits.parse::<u64>())
                    && let Some(calls) = self
                        .functions
                        .get_mut(file)
                        .and_then(|f| f.get_mut(&(ln, name.to_string())))
                {
                    *calls = calls.saturating_add(hits);
                }
            } else if line == "end_of_record" {
                current = None;
                by_name.clear();
            }
        }
    }
}

fn relative_path(p: &Path, roots: &[&Path]) -> String {
    // Not gated on `is_absolute()`: on Windows a path like `/repo/a.js` has
    // no drive letter, so it is not "absolute", yet it can still start with
    // the scan root. A relative path never matches an absolute root.
    let rel = roots
        .iter()
        .find_map(|r| p.strip_prefix(r).ok())
        .unwrap_or(p);
    rel.components()
        .filter(|c| !matches!(c, Component::CurDir))
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn parses_and_merges_lcov() {
        let mut cov = Coverage::default();
        let roots = [Path::new("/link/repo"), Path::new("/real/repo")];
        cov.merge_lcov(
            "TN:\nSF:/real/repo/src/a.js\nDA:1,3\nDA:2,0\nend_of_record\nSF:./src/b.py\nDA:5,1,abc\nend_of_record\n",
            &roots,
        );
        cov.merge_lcov("SF:src/a.js\nDA:2,4\nend_of_record\n", &roots);
        assert_eq!(cov.files["src/a.js"], BTreeMap::from([(1, 3), (2, 4)]));
        assert_eq!(cov.files["src/b.py"], BTreeMap::from([(5, 1)]));
    }

    #[test]
    fn ignores_malformed_lines_and_saturates_hit_counts() {
        let mut cov = Coverage::default();
        let lcov = format!(
            "DA:1,1\nSF:a.js\nDA:x,1\nDA:2\nDA:3,-1\nDA:4,{max}\nDA:4,{max}\nend_of_record\n",
            max = u64::MAX
        );
        cov.merge_lcov(&lcov, &[]);
        assert_eq!(cov.files["a.js"], BTreeMap::from([(4, u64::MAX)]));
    }

    #[test]
    fn parses_branches_and_functions() {
        let mut cov = Coverage::default();
        // Two functions named `stop`, as a file with two classes has;
        // each FNDA goes to the next one. lcov 2 adds an end line to FN.
        let lcov = "SF:a.js\nFN:2,f\nFN:9,12,stop\nFN:20,stop\nFN:x,bad\nFNDA:1,f\nFNDA:4,stop\nFNDA:0,stop\nFNDA:7,ghost\n\
                    BRDA:4,0,0,2\nBRDA:4,0,1,-\nBRDA:7,1,0,0\nBRDA:7,1,x\nend_of_record\n";
        cov.merge_lcov(lcov, &[]);
        cov.merge_lcov(
            "SF:a.js\nFN:2,f\nFN:9,stop\nFN:20,stop\nFNDA:2,f\nFNDA:0,stop\nFNDA:5,stop\nBRDA:4,0,1,5\nend_of_record\n",
            &[],
        );
        let key = |l: usize, b: &str, r: &str| (l, b.to_string(), r.to_string());
        assert_eq!(
            cov.branches["a.js"],
            BTreeMap::from([
                (key(4, "0", "0"), 2),
                (key(4, "0", "1"), 5),
                (key(7, "1", "0"), 0)
            ])
        );
        assert_eq!(
            cov.functions["a.js"],
            BTreeMap::from([
                ((2, "f".to_string()), 3),
                ((9, "stop".to_string()), 4),
                ((20, "stop".to_string()), 5),
            ])
        );
    }

    fn lcov_record() -> impl Strategy<Value = String> {
        let path = prop::sample::select(vec!["a.js", "src/b.py", "/root/c.c"]);
        let lines = prop::collection::vec((1usize..50, 0u64..5), 0..10);
        (path, lines).prop_map(|(path, lines)| {
            let da: String = lines.iter().map(|(l, h)| format!("DA:{l},{h}\n")).collect();
            format!("SF:{path}\n{da}end_of_record\n")
        })
    }

    proptest! {
        #![proptest_config(crate::test_support::proptest_config(256))]

        #[test]
        fn parser_accepts_any_input_without_panicking(
            text in prop_oneof![any::<String>(), "(SF:|DA:|end_of_record|[0-9,\\n-])*"]
        ) {
            Coverage::default().merge_lcov(&text, &[Path::new("/root")]);
        }

        #[test]
        fn merge_order_does_not_matter(a in lcov_record(), b in lcov_record()) {
            let roots = [Path::new("/root")];
            let (mut ab, mut ba) = (Coverage::default(), Coverage::default());
            ab.merge_lcov(&a, &roots);
            ab.merge_lcov(&b, &roots);
            ba.merge_lcov(&b, &roots);
            ba.merge_lcov(&a, &roots);
            prop_assert_eq!(ab.files, ba.files);
        }
    }
}
