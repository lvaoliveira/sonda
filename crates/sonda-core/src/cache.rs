//! A cache of what the scan found in each file (ADR-0030), for scans that
//! run again on mostly the same code.
//!
//! What analyzing one file gives (its issues, metrics, tokens and facts)
//! depends on the file's bytes, its path and language, the configuration
//! and the sonda version, and on nothing else: what crosses files (the
//! project passes of Java, C#, taint, ...) reads each file's *facts* after
//! every file is analyzed, and those run again on a warm cache. So an entry
//! is keyed by exactly those inputs, and a report is the same with the cache,
//! without it, and with a cache from another scan.
//!
//! An entry is two files, `KEY.json` (everything but the tokens) and
//! `KEY.tok` (the tokens, 12 bytes each: they are most of the size, and JSON
//! would make them several times bigger). One that can't be read, or that
//! doesn't have the shape this version writes, is a miss: the file is
//! analyzed and the entry written again. After a scan the entries it didn't
//! use are removed, so the cache holds what the last scan needed and no
//! more.

use crate::analysis::{FileAnalysis, Token};
use crate::config::Config;
use crate::lang::Lang;
use crate::model::{Category, FileMetrics, Fingerprint, FlowStep, Issue, Severity, Sha256};
use crate::rules::RuleSet;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use std::collections::HashSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Changes when what an entry holds does, so an older one is never read.
const FORMAT: u32 = 1;
/// Bytes of one token in `KEY.tok`: its hash, then its line, little-endian.
const TOKEN_BYTES: usize = 12;

pub(crate) struct Cache {
    dir: PathBuf,
    /// Everything but the file that decides what analyzing it gives.
    context: String,
    /// The keys this scan read or wrote.
    used: Mutex<HashSet<String>>,
}

#[derive(Serialize)]
struct EntryOut<'a> {
    sha256: &'a Sha256,
    issues: &'a [Issue],
    metrics: &'a FileMetrics,
    code_lines: &'a [usize],
    has_syntax_errors: bool,
    facts: &'a [(String, String)],
}

#[derive(Deserialize)]
struct EntryIn {
    sha256: Sha256,
    issues: Vec<IssueIn>,
    metrics: FileMetrics,
    code_lines: Vec<usize>,
    has_syntax_errors: bool,
    facts: Vec<(String, String)>,
}

/// An `Issue`, whose rule is a `&'static str` that the rule set gives back.
#[derive(Deserialize)]
struct IssueIn {
    rule: String,
    severity: Severity,
    category: Category,
    message: String,
    path: String,
    line: usize,
    column: usize,
    end_line: usize,
    end_column: usize,
    effort_minutes: u32,
    is_new: bool,
    fingerprint: Fingerprint,
    #[serde(default)]
    flow: Vec<FlowStep>,
}

impl Cache {
    /// Opens (and creates) the cache in `dir`. It ignores itself in git, so
    /// a project doesn't have to.
    pub(crate) fn open(dir: &Path, cfg: &Config) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let ignore = dir.join(".gitignore");
        if !ignore.exists() {
            std::fs::write(ignore, "*\n")?;
        }
        let settings = serde_json::to_string(cfg).map_err(std::io::Error::other)?;
        let mut h = sha2::Sha256::new();
        for part in [
            FORMAT.to_string().as_str(),
            env!("CARGO_PKG_VERSION"),
            settings.as_str(),
        ] {
            h.update((part.len() as u64).to_le_bytes());
            h.update(part.as_bytes());
        }
        Ok(Cache {
            dir: dir.to_path_buf(),
            context: hex(&h.finalize()),
            used: Mutex::new(HashSet::new()),
        })
    }

    /// The key of a file: what analyzing it depends on.
    pub(crate) fn key(&self, path: &str, lang: Lang, src: &str) -> String {
        let mut h = sha2::Sha256::new();
        for part in [self.context.as_str(), path, &format!("{lang:?}")] {
            h.update((part.len() as u64).to_le_bytes());
            h.update(part.as_bytes());
        }
        h.update(src.as_bytes());
        hex(&h.finalize())
    }

    /// What was stored under `key`, or None if nothing was, or it can't be
    /// read as this version writes it.
    pub(crate) fn get(
        &self,
        key: &str,
        path: &str,
        lang: Lang,
        rules: &RuleSet,
    ) -> Option<FileAnalysis> {
        let json = std::fs::read(self.entry(key, "json")).ok()?;
        let tokens = std::fs::read(self.entry(key, "tok")).ok()?;
        let entry: EntryIn = serde_json::from_slice(&json).ok()?;
        let (tokens, rest) = tokens.as_chunks::<TOKEN_BYTES>();
        if !rest.is_empty() {
            return None;
        }
        let issues = entry
            .issues
            .into_iter()
            .map(|i| {
                Some(Issue {
                    rule: rules.get(&i.rule)?.rule.id,
                    severity: i.severity,
                    category: i.category,
                    message: i.message,
                    path: i.path,
                    line: i.line,
                    column: i.column,
                    end_line: i.end_line,
                    end_column: i.end_column,
                    effort_minutes: i.effort_minutes,
                    is_new: i.is_new,
                    fingerprint: i.fingerprint,
                    flow: i.flow,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        let tokens = tokens
            .iter()
            .map(|c| Token {
                hash: u64::from_le_bytes(c[..8].try_into().expect("8 bytes")),
                line: u32::from_le_bytes(c[8..].try_into().expect("4 bytes")) as usize,
            })
            .collect();
        self.note(key);
        Some(FileAnalysis {
            path: path.to_string(),
            lang,
            issues,
            metrics: entry.metrics,
            code_lines: entry.code_lines,
            tokens,
            has_syntax_errors: entry.has_syntax_errors,
            facts: entry.facts,
            semantic_incomplete: false,
            sha256: entry.sha256,
        })
    }

    /// Stores what analyzing a file gave. Not for one that ran out of time
    /// (`semantic_incomplete`): another run could finish. A failed write
    /// loses nothing but the speed-up.
    pub(crate) fn put(&self, key: &str, f: &FileAnalysis) {
        if f.semantic_incomplete {
            return;
        }
        let entry = EntryOut {
            sha256: &f.sha256,
            issues: &f.issues,
            metrics: &f.metrics,
            code_lines: &f.code_lines,
            has_syntax_errors: f.has_syntax_errors,
            facts: &f.facts,
        };
        let Ok(json) = serde_json::to_vec(&entry) else {
            return;
        };
        let mut tokens = Vec::with_capacity(f.tokens.len() * TOKEN_BYTES);
        for t in &f.tokens {
            tokens.extend_from_slice(&t.hash.to_le_bytes());
            tokens.extend_from_slice(&(t.line as u32).to_le_bytes());
        }
        // The tokens first: an entry exists once its `.json` does.
        if self.write(key, "tok", &tokens).is_ok() && self.write(key, "json", &json).is_ok() {
            self.note(key);
        }
    }

    /// Removes the entries this scan didn't use.
    pub(crate) fn prune(&self) {
        let used = self.used.lock().unwrap_or_else(|e| e.into_inner());
        let Ok(dir) = std::fs::read_dir(&self.dir) else {
            return;
        };
        for e in dir.flatten() {
            let name = e.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some((key, ext)) = name.rsplit_once('.') else {
                continue;
            };
            if matches!(ext, "json" | "tok") && key.len() == 64 && !used.contains(key) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }

    fn note(&self, key: &str) {
        self.used
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key.to_string());
    }

    fn entry(&self, key: &str, ext: &str) -> PathBuf {
        self.dir.join(format!("{key}.{ext}"))
    }

    /// Writes through a file of its own and renames it, so a reader (another
    /// scan at the same time, or after this one is killed) never sees half
    /// of one. Not synced to disk: after a crash an entry that is empty or
    /// short fails to read, and is a miss.
    fn write(&self, key: &str, ext: &str, bytes: &[u8]) -> std::io::Result<()> {
        let tmp = self
            .dir
            .join(format!("{key}.{ext}.{}.tmp", std::process::id()));
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        std::fs::rename(&tmp, self.entry(key, ext)).inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp);
        })
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use crate::config::Config;
    use crate::report::{self, Format};
    use crate::scanner::ScanOptions;
    use std::path::Path;

    const HANDLER: &str = "#include <httplib.h>\n#include \"util.h\"\nvoid ping(const httplib::Request& req) {\n    run_ping(req.get_param_value(\"host\"));\n}\n";
    const UTIL: &str = "#include \"util.h\"\nvoid run_ping(std::string host) {\n    std::string cmd = \"ping \" + host;\n    system(cmd.c_str());\n}\n";
    const SAFE_UTIL: &str = "#include \"util.h\"\nvoid run_ping(std::string host) {\n    system(\"ping -c 1 localhost\");\n}\n";

    fn project(util: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (path, content) in [
            ("src/handler.cpp", HANDLER),
            ("src/util.cpp", util),
            ("web/app.js", "var a = 1;\nif (a == '1') { eval(a); }\n"),
            (
                "tools/run.py",
                "import os\ndef f(x):\n    os.system('ls ' + x)\n",
            ),
            (
                "src/dup1.py",
                "def a():\n    x = 1\n    y = 2\n    z = x + y\n    return z * 2 + x - y\n",
            ),
        ] {
            let full = dir.path().join(path);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, content).unwrap();
        }
        dir
    }

    /// The report JSON of a scan of `root`, with the cache in `cache`.
    fn report_of(root: &Path, cache: Option<&str>, cfg: &Config) -> String {
        let opts = ScanOptions {
            root: root.to_path_buf(),
            cache: cache.map(Into::into),
            ..ScanOptions::default()
        };
        let outcome = crate::run(&opts, cfg).unwrap();
        report::render(&report::build(&outcome, false), Format::Json)
    }

    /// How many issues of `rule` a JSON report lists.
    fn found(report: &str, rule: &str) -> usize {
        let json: serde_json::Value = serde_json::from_str(report).unwrap();
        json["issues"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|i| i["rule"] == rule)
            .count()
    }

    fn entries(root: &Path, cache: &str) -> usize {
        std::fs::read_dir(root.join(cache))
            .map(|d| {
                d.flatten()
                    .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
                    .count()
            })
            .unwrap_or(0)
    }

    #[test]
    fn a_report_is_the_same_with_the_cache_cold_or_warm() {
        let dir = project(UTIL);
        let cfg = Config::default();
        let plain = report_of(dir.path(), None, &cfg);
        // The cross-file finding is in it, from facts the cache gave back.
        assert_eq!(found(&plain, "c/command-injection"), 1, "{plain}");
        let cold = report_of(dir.path(), Some(".sonda/cache"), &cfg);
        assert_eq!(cold, plain);
        let stored = entries(dir.path(), ".sonda/cache");
        assert_eq!(stored, 5);
        let warm = report_of(dir.path(), Some(".sonda/cache"), &cfg);
        assert_eq!(warm, plain);
        assert_eq!(entries(dir.path(), ".sonda/cache"), stored);
        // The cache isn't scanned, and ignores itself in git.
        assert!(!warm.contains(".sonda"), "{warm}");
        let ignore = std::fs::read_to_string(dir.path().join(".sonda/cache/.gitignore")).unwrap();
        assert_eq!(ignore, "*\n");
    }

    #[test]
    fn a_changed_file_is_analyzed_again_and_what_crosses_files_follows() {
        let dir = project(UTIL);
        let cfg = Config::default();
        report_of(dir.path(), Some(".sonda/cache"), &cfg);
        // The sink goes away from util.cpp; handler.cpp, unchanged, comes
        // from the cache, and its flow into util.cpp is gone with it.
        std::fs::write(dir.path().join("src/util.cpp"), SAFE_UTIL).unwrap();
        let warm = report_of(dir.path(), Some(".sonda/cache"), &cfg);
        let plain = report_of(dir.path(), None, &cfg);
        assert_eq!(warm, plain);
        assert_eq!(found(&warm, "c/command-injection"), 0, "{warm}");
        // The old version's entry went, the new one's is in: five files.
        assert_eq!(entries(dir.path(), ".sonda/cache"), 5);
    }

    #[test]
    fn another_configuration_does_not_reuse_entries() {
        let dir = project(UTIL);
        let cfg = Config::default();
        report_of(dir.path(), Some(".sonda/cache"), &cfg);
        let mut other = Config::default();
        other.rules.disabled.push("c/command-injection".to_string());
        let cached = report_of(dir.path(), Some(".sonda/cache"), &other);
        assert_eq!(cached, report_of(dir.path(), None, &other));
        assert_eq!(found(&cached, "c/command-injection"), 0, "{cached}");
        assert_eq!(
            found(&report_of(dir.path(), None, &cfg), "c/command-injection"),
            1
        );
    }

    #[test]
    fn an_entry_that_cannot_be_read_is_analyzed_again() {
        let dir = project(UTIL);
        let cfg = Config::default();
        let plain = report_of(dir.path(), None, &cfg);
        report_of(dir.path(), Some(".sonda/cache"), &cfg);
        let cache = dir.path().join(".sonda/cache");
        let mut kinds = [false; 3];
        for (i, e) in std::fs::read_dir(&cache).unwrap().flatten().enumerate() {
            let path = e.path();
            match path.extension().and_then(|x| x.to_str()) {
                Some("json") if !kinds[0] => {
                    std::fs::write(&path, "{ not json").unwrap();
                    kinds[0] = true;
                }
                Some("tok") if !kinds[1] => {
                    std::fs::write(&path, [1u8, 2, 3]).unwrap();
                    kinds[1] = true;
                }
                Some("json") if !kinds[2] && i > 3 => {
                    std::fs::remove_file(&path).unwrap();
                    kinds[2] = true;
                }
                _ => {}
            }
        }
        assert_eq!(report_of(dir.path(), Some(".sonda/cache"), &cfg), plain);
        assert_eq!(report_of(dir.path(), Some(".sonda/cache"), &cfg), plain);
    }
}
