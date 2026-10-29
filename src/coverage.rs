//! LCOV coverage data (`--coverage lcov.info`). LCOV is produced by
//! istanbul/c8/vitest (JS/TS), coverage.py (`coverage lcov`), gcov/lcov and
//! llvm-cov (C/C++), and can be converted from JaCoCo. Parsing is pure;
//! reading the report files is done by the scanner.

use std::collections::{BTreeMap, HashMap};
use std::path::{Component, Path};

#[derive(Debug, Default)]
pub(crate) struct Coverage {
    /// Root-relative path -> 1-based line -> hit count.
    pub(crate) files: HashMap<String, BTreeMap<usize, u64>>,
}

impl Coverage {
    /// Adds one LCOV report. Absolute `SF:` paths are made relative to the
    /// first of `roots` they are under (pass the scan root as given and
    /// canonicalized, so symlinked roots such as macOS `/tmp` match).
    pub(crate) fn merge_lcov(&mut self, text: &str, roots: &[&Path]) {
        let mut current: Option<String> = None;
        for line in text.lines() {
            let line = line.trim();
            if let Some(sf) = line.strip_prefix("SF:") {
                current = Some(relative_path(Path::new(sf), roots));
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
            } else if line == "end_of_record" {
                current = None;
            }
        }
    }
}

fn relative_path(p: &Path, roots: &[&Path]) -> String {
    let rel = if p.is_absolute() {
        roots
            .iter()
            .find_map(|r| p.strip_prefix(r).ok())
            .unwrap_or(p)
    } else {
        p
    };
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
