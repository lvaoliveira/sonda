//! The baseline file (ADR-0029): the fingerprints of issues a project has
//! accepted, which a scan leaves out. Parsing, applying and writing are pure;
//! finding and reading the file is done by the scanner.

use crate::analysis::FileAnalysis;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Where a scan looks for the baseline when nothing says otherwise.
pub const DEFAULT_FILE: &str = "sonda-baseline.json";

/// The largest baseline read: a million issues is a few tens of megabytes.
pub const MAX_BYTES: u64 = 16 * 1024 * 1024;

const VERSION: u32 = 1;

#[derive(Deserialize)]
struct File {
    version: u32,
    issues: Vec<Entry>,
}

/// An entry as read: only the fingerprint matters; the other fields are for
/// the person reviewing the file.
#[derive(Deserialize)]
struct Entry {
    fingerprint: String,
}

/// An entry as written.
#[derive(Serialize)]
struct Written<'a> {
    fingerprint: String,
    rule: &'a str,
    path: &'a str,
    line: usize,
}

#[derive(Debug, Default)]
pub(crate) struct Baseline {
    fingerprints: HashSet<String>,
}

/// What applying a baseline did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Applied {
    /// The baseline's path, as the scan was told or found it.
    pub file: String,
    /// Issues it removed.
    pub hidden: usize,
    /// Entries that matched no issue: fixed or edited since it was written.
    pub unmatched: usize,
}

impl Baseline {
    pub(crate) fn parse(text: &str) -> Result<Baseline, String> {
        let file: File = serde_json::from_str(text).map_err(|e| format!("not a baseline: {e}"))?;
        if file.version != VERSION {
            return Err(format!(
                "baseline version {} is not one this sonda reads (it reads {VERSION})",
                file.version
            ));
        }
        let mut fingerprints = HashSet::with_capacity(file.issues.len());
        for (i, entry) in file.issues.into_iter().enumerate() {
            let hex = entry.fingerprint.len() == 32
                && entry.fingerprint.bytes().all(|b| b.is_ascii_hexdigit());
            if !hex {
                return Err(format!("entry {} has no valid fingerprint", i + 1));
            }
            fingerprints.insert(entry.fingerprint.to_ascii_lowercase());
        }
        Ok(Baseline { fingerprints })
    }

    /// Removes the issues in the baseline from `files`.
    pub(crate) fn apply(&self, files: &mut [FileAnalysis], file: String) -> Applied {
        let mut matched = HashSet::new();
        let mut hidden = 0;
        for f in files {
            f.issues.retain(|issue| {
                let fingerprint = issue.fingerprint.to_string();
                let known = self.fingerprints.contains(&fingerprint);
                if known {
                    hidden += 1;
                    matched.insert(fingerprint);
                }
                !known
            });
        }
        Applied {
            file,
            hidden,
            unmatched: self.fingerprints.len() - matched.len(),
        }
    }
}

/// The baseline file for `files`' issues, one entry per line so that
/// rewriting it changes only what changed.
pub(crate) fn render(files: &[FileAnalysis]) -> String {
    let mut entries: Vec<Written> = files
        .iter()
        .flat_map(|f| &f.issues)
        .map(|i| Written {
            fingerprint: i.fingerprint.to_string(),
            rule: i.rule,
            path: &i.path,
            line: i.line,
        })
        .collect();
    entries.sort_by(|a, b| {
        (a.path, a.line, a.rule, &a.fingerprint).cmp(&(b.path, b.line, b.rule, &b.fingerprint))
    });
    entries.dedup_by(|a, b| a.fingerprint == b.fingerprint);
    let lines: Vec<String> = entries
        .iter()
        .map(|e| format!("    {}", serde_json::to_string(e).unwrap_or_default()))
        .collect();
    if lines.is_empty() {
        return format!("{{\n  \"version\": {VERSION},\n  \"issues\": []\n}}\n");
    }
    format!(
        "{{\n  \"version\": {VERSION},\n  \"issues\": [\n{}\n  ]\n}}\n",
        lines.join(",\n")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "04d724dbbd800b9d4c64c4649cd55415";

    fn file(entries: &str) -> String {
        format!("{{\"version\":1,\"issues\":[{entries}]}}")
    }

    #[test]
    fn reads_fingerprints_and_ignores_the_review_fields() {
        let text = file(&format!(
            "{{\"fingerprint\":\"{A}\",\"rule\":\"js/no-var\",\"path\":\"a.js\",\"line\":3,\"future\":1}},\
             {{\"fingerprint\":\"{}\"}},{{\"fingerprint\":\"{A}\"}}",
            A.to_uppercase().replace('0', "F")
        ));
        let b = Baseline::parse(&text).unwrap();
        assert_eq!(b.fingerprints.len(), 2, "duplicates count once");
        assert!(Baseline::parse(&file("")).unwrap().fingerprints.is_empty());
    }

    #[test]
    fn a_file_that_is_wrong_is_an_error_never_an_empty_baseline() {
        for (text, expected) in [
            ("", "not a baseline"),
            ("[]", "not a baseline"),
            ("{\"version\":1}", "not a baseline"),
            ("{\"version\":2,\"issues\":[]}", "version 2"),
            (&file("{\"fingerprint\":\"abc\"}"), "entry 1"),
            (
                &file(&format!("{{\"fingerprint\":\"{A}\"}},{{}}")),
                "not a baseline",
            ),
            (
                &file(&format!("{{\"fingerprint\":\"{}z\"}}", &A[1..])),
                "entry 1",
            ),
        ] {
            let err = Baseline::parse(text).unwrap_err();
            assert!(err.contains(expected), "{text}: {err}");
        }
    }

    #[test]
    fn an_empty_baseline_renders_and_reads_back() {
        let text = render(&[]);
        assert_eq!(text, "{\n  \"version\": 1,\n  \"issues\": []\n}\n");
        assert!(Baseline::parse(&text).unwrap().fingerprints.is_empty());
    }
}
