//! Coverage data (`--coverage <file>`), in the format the file's content
//! shows: LCOV, which istanbul/c8/vitest (JS/TS), coverage.py (`coverage
//! lcov`), gcov/lcov and llvm-cov (C/C++) produce, or the XML of JaCoCo
//! (Java, Kotlin) and Cobertura (Python, Java, C#, JavaScript). Parsing is
//! pure; reading the report files is done by the scanner.

mod cobertura;
mod jacoco;
mod resolve;
mod xml;

pub(crate) use resolve::Resolver;

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::{Component, Path};

/// What one file of an XML report holds, before it is matched to a scanned file.
#[derive(Debug, Default)]
pub(crate) struct FileData {
    lines: BTreeMap<usize, u64>,
    branches: BTreeMap<(usize, String, String), u64>,
    functions: BTreeMap<(usize, String), u64>,
}

impl FileData {
    fn add_line(&mut self, line: usize, hits: u64) {
        let total = self.lines.entry(line).or_insert(0);
        *total = total.saturating_add(hits);
    }

    fn add_branch(&mut self, line: usize, block: &str, branch: &str, taken: u64) {
        let key = (line, block.to_string(), branch.to_string());
        let total = self.branches.entry(key).or_insert(0);
        *total = total.saturating_add(taken);
    }

    fn add_function(&mut self, line: usize, name: &str, calls: u64) {
        let total = self.functions.entry((line, name.to_string())).or_insert(0);
        *total = total.saturating_add(calls);
    }
}

/// The paths an XML report's file might be, most likely first; the scanner
/// picks the first that names a scanned file.
#[derive(Debug)]
pub(crate) struct Candidates {
    pub(crate) paths: Vec<String>,
    /// Whether a scanned file whose path ends with a candidate is a match
    /// (JaCoCo names a file from its source root: `com/acme/Util.java`).
    pub(crate) suffix: bool,
}

/// Whether a report is XML (JaCoCo or Cobertura) rather than LCOV.
pub(crate) fn is_xml(text: &str) -> bool {
    text.trim_start_matches('\u{feff}')
        .trim_start()
        .starts_with('<')
}

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
    /// Adds one JaCoCo or Cobertura report; `resolve` says which scanned file
    /// each of its files is. Fails when the XML is neither.
    pub(crate) fn merge_xml(
        &mut self,
        text: &str,
        roots: &[&Path],
        resolve: impl Fn(&Candidates) -> String,
    ) -> Result<(), String> {
        let text = text.trim_start_matches('\u{feff}');
        let mut root = None;
        xml::scan(text, |event| {
            if let xml::Event::Start(tag) = event {
                root = Some(tag.name.to_string());
                return false;
            }
            true
        });
        let files = match root.as_deref() {
            Some("report") => jacoco::parse(text),
            Some("coverage") => cobertura::parse(text, roots),
            _ => return Err("not a JaCoCo or Cobertura report".to_string()),
        };
        for (candidates, data) in files {
            self.add_file(&resolve(&candidates), data);
        }
        Ok(())
    }

    fn add_file(&mut self, path: &str, data: FileData) {
        if !data.lines.is_empty() {
            let entry = self.files.entry(path.to_string()).or_default();
            for (line, hits) in data.lines {
                let total = entry.entry(line).or_insert(0);
                *total = total.saturating_add(hits);
            }
        }
        add_all(&mut self.branches, path, data.branches);
        add_all(&mut self.functions, path, data.functions);
    }

    /// Adds one LCOV report. `SF:` paths under a root are made relative to the
    /// first of `roots` they are under (pass the scan root as given and
    /// canonicalized, so symlinked roots such as macOS `/tmp` match).
    #[cfg(test)]
    pub(crate) fn merge_lcov(&mut self, text: &str, roots: &[&Path]) {
        self.merge_lcov_resolving(text, roots, |path| path);
    }

    /// [`merge_lcov`](Self::merge_lcov), with `resolve` given each record's
    /// root-relative path to say which file it is.
    pub(crate) fn merge_lcov_resolving(
        &mut self,
        text: &str,
        roots: &[&Path],
        resolve: impl Fn(String) -> String,
    ) {
        let mut current: Option<String> = None;
        // The record's functions by name, in `FN` order: `FNDA` names a
        // function, and writers emit one per `FN`, in the same order, so
        // same-named functions take their calls in turn.
        let mut by_name: HashMap<String, VecDeque<usize>> = HashMap::new();
        for line in text.lines() {
            let line = line.trim();
            if let Some(sf) = line.strip_prefix("SF:") {
                current = Some(resolve(relative_path(Path::new(sf), roots)));
                by_name.clear();
            } else if line == "end_of_record" {
                current = None;
                by_name.clear();
            } else if let Some(file) = &current {
                self.add_record_line(file, line, &mut by_name);
            }
        }
    }

    /// One line of `file`'s record, other than `SF:` and `end_of_record`.
    fn add_record_line(
        &mut self,
        file: &str,
        line: &str,
        by_name: &mut HashMap<String, VecDeque<usize>>,
    ) {
        if let Some(da) = line.strip_prefix("DA:") {
            self.add_line_hits(file, da);
        } else if let Some(brda) = line.strip_prefix("BRDA:") {
            self.add_branch(file, brda);
        } else if let Some(fun) = line.strip_prefix("FN:") {
            self.add_function(file, fun, by_name);
        } else if let Some(fnda) = line.strip_prefix("FNDA:") {
            self.add_function_calls(file, fnda, by_name);
        }
    }

    /// `DA:<line>,<hits>[,<checksum>]`.
    fn add_line_hits(&mut self, file: &str, da: &str) {
        let Some((ln, rest)) = da.split_once(',') else {
            return;
        };
        let hits = rest.split(',').next().and_then(|h| h.parse::<u64>().ok());
        if let (Ok(ln), Some(hits)) = (ln.parse::<usize>(), hits) {
            let entry = self.files.entry(file.to_string()).or_default();
            let total = entry.entry(ln).or_insert(0);
            *total = total.saturating_add(hits);
        }
    }

    /// `BRDA:<line>,<block>,<branch>,<taken or ->`.
    fn add_branch(&mut self, file: &str, brda: &str) {
        let parts: Vec<&str> = brda.splitn(4, ',').collect();
        let [ln, block, branch, taken] = parts[..] else {
            return;
        };
        let taken = if taken == "-" {
            Some(0)
        } else {
            taken.parse::<u64>().ok()
        };
        if let (Ok(ln), Some(taken)) = (ln.parse::<usize>(), taken) {
            let entry = self.branches.entry(file.to_string()).or_default();
            let total = entry
                .entry((ln, block.to_string(), branch.to_string()))
                .or_insert(0);
            *total = total.saturating_add(taken);
        }
    }

    /// `FN:<line>,<name>`, or lcov 2's `FN:<line>,<end line>,<name>`.
    fn add_function(
        &mut self,
        file: &str,
        fun: &str,
        by_name: &mut HashMap<String, VecDeque<usize>>,
    ) {
        let Some((ln, rest)) = fun.split_once(',') else {
            return;
        };
        let name = match rest.split_once(',') {
            Some((end, name)) if end.parse::<usize>().is_ok() => name,
            _ => rest,
        };
        if let Ok(ln) = ln.parse::<usize>() {
            self.functions
                .entry(file.to_string())
                .or_default()
                .entry((ln, name.to_string()))
                .or_insert(0);
            by_name.entry(name.to_string()).or_default().push_back(ln);
        }
    }

    /// `FNDA:<hits>,<name>`, for the next function of that name; extra calls
    /// go to the last one, and calls for a function without `FN` are
    /// dropped, since it has no line to show them on.
    fn add_function_calls(
        &mut self,
        file: &str,
        fnda: &str,
        by_name: &mut HashMap<String, VecDeque<usize>>,
    ) {
        let Some((hits, name)) = fnda.split_once(',') else {
            return;
        };
        let Some(lines) = by_name.get_mut(name) else {
            return;
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
    }
}

/// Adds `from` into `path`'s entry of `into`, summing counts, if it has any.
fn add_all<K: Ord>(
    into: &mut HashMap<String, BTreeMap<K, u64>>,
    path: &str,
    from: BTreeMap<K, u64>,
) {
    if from.is_empty() {
        return;
    }
    let entry = into.entry(path.to_string()).or_default();
    for (key, n) in from {
        let total = entry.entry(key).or_insert(0);
        *total = total.saturating_add(n);
    }
}

/// `a/b/../c` as `a/c`; none if it climbs above the root.
pub(crate) fn normalize(path: &str) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            _ => parts.push(part),
        }
    }
    Some(parts.join("/"))
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

    fn merged(xml: &str) -> Result<Coverage, String> {
        let mut cov = Coverage::default();
        cov.merge_xml(xml, &[Path::new("/root")], |c| c.paths[0].clone())?;
        Ok(cov)
    }

    #[test]
    fn xml_is_told_from_lcov_and_checked_for_its_kind() {
        assert!(is_xml("\u{feff}  <?xml version=\"1.0\"?><report/>"));
        assert!(!is_xml("TN:\nSF:a.js\nend_of_record\n"));
        assert!(merged("<report><package name=\"p\"><sourcefile name=\"A.java\"><line nr=\"1\" ci=\"1\"/></sourcefile></package></report>").is_ok());
        assert!(merged("\u{feff}<coverage/>").is_ok());
        for other in ["<project/>", "<?xml version=\"1.0\"?>", "<!-- x -->", "<"] {
            assert!(merged(other).is_err(), "{other}");
        }
    }

    #[test]
    fn reports_merge_by_summing_like_lcov_does() {
        let report = "<report><package name=\"p\"><sourcefile name=\"A.java\">\
                      <line nr=\"1\" ci=\"2\" cb=\"1\" mb=\"1\"/></sourcefile></package></report>";
        let mut cov = merged(report).unwrap();
        cov.merge_xml(report, &[], |c| c.paths[0].clone()).unwrap();
        assert_eq!(cov.files["p/A.java"], BTreeMap::from([(1, 4)]));
        let branches = &cov.branches["p/A.java"];
        assert_eq!(branches.values().copied().collect::<Vec<_>>(), [2, 0]);
    }

    #[test]
    fn hostile_xml_costs_bounded_time_and_memory() {
        // Counts are capped, nesting needs no recursion, and an entity
        // that names more entities is never expanded.
        let cov = merged(
            "<!DOCTYPE report [<!ENTITY a \"&b;&b;&b;\"><!ENTITY b \"&a;&a;&a;\">]>\
             <report><package name=\"&a;\"><sourcefile name=\"A.java\">\
             <line nr=\"1\" ci=\"1\" mb=\"4000000000\" cb=\"4000000000\"/></sourcefile></package></report>",
        )
        .unwrap();
        assert_eq!(cov.branches["&a;/A.java"].len(), 256);
        let max = u64::MAX;
        let huge = format!(
            "<report><package name=\"p\"><sourcefile name=\"A.java\">\
             <line nr=\"1\" mi=\"{max}\" ci=\"{max}\" mb=\"{max}\" cb=\"{max}\"/>\
             </sourcefile></package></report>"
        );
        assert_eq!(merged(&huge).unwrap().files["p/A.java"][&1], max);
        let deep = "<a>".repeat(200_000);
        assert!(merged(&format!("<report>{deep}")).is_ok());
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
        fn xml_parsers_accept_any_input_without_panicking(
            text in prop_oneof![
                any::<String>(),
                "<(report|coverage|package|class|method|sourcefile|line|counter|source|lines)([ ]+[a-z]+=\"[0-9a-z/%() ]{0,6}\")*[/]?>[a-z/]{0,4}</?[a-z]*>?"
                    .prop_map(|s| format!("<report>{s}</report>")),
            ]
        ) {
            let _ = Coverage::default().merge_xml(&text, &[Path::new("/root")], |c| c.paths[0].clone());
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
