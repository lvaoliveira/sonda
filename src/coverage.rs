//! LCOV coverage import (`--coverage lcov.info`). LCOV is produced by
//! istanbul/c8/vitest (JS/TS), coverage.py (`coverage lcov`), gcov/lcov and
//! llvm-cov (C/C++), and can be converted from JaCoCo.

use anyhow::{Context, Result};
use std::collections::{BTreeMap, HashMap};
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Default)]
pub struct Coverage {
    /// Root-relative path -> 1-based line -> hit count.
    pub files: HashMap<String, BTreeMap<usize, u64>>,
}

impl Coverage {
    pub fn load(paths: &[PathBuf], root: &Path) -> Result<Coverage> {
        let mut cov = Coverage::default();
        for p in paths {
            let text = std::fs::read_to_string(p)
                .with_context(|| format!("reading coverage report {}", p.display()))?;
            cov.merge_lcov(&text, root);
        }
        Ok(cov)
    }

    pub fn merge_lcov(&mut self, text: &str, root: &Path) {
        let canonical_root = root.canonicalize().ok();
        let mut current: Option<String> = None;
        for line in text.lines() {
            let line = line.trim();
            if let Some(sf) = line.strip_prefix("SF:") {
                current = Some(relative_path(
                    Path::new(sf),
                    root,
                    canonical_root.as_deref(),
                ));
            } else if let Some(da) = line.strip_prefix("DA:") {
                let (Some(file), Some((ln, rest))) = (&current, da.split_once(',')) else {
                    continue;
                };
                let hits = rest.split(',').next().and_then(|h| h.parse::<u64>().ok());
                if let (Ok(ln), Some(hits)) = (ln.parse::<usize>(), hits) {
                    *self
                        .files
                        .entry(file.clone())
                        .or_default()
                        .entry(ln)
                        .or_insert(0) += hits;
                }
            } else if line == "end_of_record" {
                current = None;
            }
        }
    }
}

fn relative_path(p: &Path, root: &Path, canonical_root: Option<&Path>) -> String {
    let rel = if p.is_absolute() {
        p.strip_prefix(root)
            .ok()
            .or_else(|| canonical_root.and_then(|r| p.strip_prefix(r).ok()))
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

    #[test]
    fn parses_and_merges_lcov() {
        let mut cov = Coverage::default();
        let root = Path::new("/repo");
        cov.merge_lcov("TN:\nSF:/repo/src/a.js\nDA:1,3\nDA:2,0\nend_of_record\nSF:./src/b.py\nDA:5,1,abc\nend_of_record\n", root);
        cov.merge_lcov("SF:src/a.js\nDA:2,4\nend_of_record\n", root);
        assert_eq!(cov.files["src/a.js"], BTreeMap::from([(1, 3), (2, 4)]));
        assert_eq!(cov.files["src/b.py"], BTreeMap::from([(5, 1)]));
    }
}
