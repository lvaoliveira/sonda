//! Infrastructure: finds and reads the files to analyze, loads coverage
//! reports and asks `git` for new code, then runs the domain analysis.

use crate::analysis::{self, FileAnalysis};
use crate::config::Config;
use crate::coverage::Coverage;
use crate::duplication;
use crate::error::Error;
use crate::git;
use crate::lang::Lang;
use crate::newcode::NewCode;
use crate::project::ProjectAnalysis;
use crate::rules::RuleSet;
use ignore::WalkBuilder;
use ignore::overrides::OverrideBuilder;
use rayon::prelude::*;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// What to analyze.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Project directory.
    pub root: PathBuf,
    /// Git ref new code is compared against (via merge base); `None` makes
    /// the whole project new code.
    pub new_code_ref: Option<String>,
    /// LCOV reports to import.
    pub coverage: Vec<PathBuf>,
}

pub(crate) fn scan(
    opts: &ScanOptions,
    cfg: &Config,
    rules: &RuleSet,
) -> Result<ProjectAnalysis, Error> {
    let (paths, warnings) = collect_files(&opts.root, cfg)?;
    scan_files(opts, cfg, rules, paths, warnings)
}

/// Everything after file discovery. Output must not depend on the order of
/// `paths` or `warnings`, which come from filesystem iteration.
fn scan_files(
    opts: &ScanOptions,
    cfg: &Config,
    rules: &RuleSet,
    mut paths: Vec<Candidate>,
    mut warnings: Vec<String>,
) -> Result<ProjectAnalysis, Error> {
    // Every later stage (analysis order, duplication's "first occurrence")
    // relies on this sort.
    paths.sort_by(|a, b| a.1.cmp(&b.1));
    let root = &opts.root;
    let coverage = load_coverage(&opts.coverage, root)?;
    // Saturating: the config may come from the analyzed repository.
    let max_bytes = cfg.scan.max_file_size_kb.saturating_mul(1024);
    let timeout = Duration::from_secs(cfg.scan.file_timeout_secs);

    let new_code = match &opts.new_code_ref {
        Some(r) => {
            let contents = paths
                .iter()
                .map(|(path, rel, _)| (rel.as_str(), read_capped(path, max_bytes).ok().flatten()));
            git::new_code(root, r, max_bytes, contents)?
        }
        None => NewCode::Everything,
    };

    let results: Vec<Result<FileAnalysis, String>> = paths
        .par_iter()
        .map(|(path, rel, lang)| {
            let bytes = read_capped(path, max_bytes)
                .map_err(|e| format!("{rel}: {e}"))?
                .ok_or_else(|| {
                    format!(
                        "{rel}: skipped, larger than {} KB",
                        cfg.scan.max_file_size_kb
                    )
                })?;
            let src =
                String::from_utf8(bytes).map_err(|_| format!("{rel}: skipped, not valid UTF-8"))?;
            let deadline = Instant::now() + timeout;
            analysis::analyze(rel, *lang, &src, rules, cfg, deadline)
                .map_err(|e| format!("{rel}: skipped, {e}"))
        })
        .collect();

    let mut files = Vec::with_capacity(results.len());
    for r in results {
        match r {
            Ok(f) => files.push(f),
            Err(w) => warnings.push(w),
        }
    }
    // `paths` is sorted and rayon's collect keeps input order, so `files` is too.
    for f in &mut files {
        if f.has_syntax_errors {
            warnings.push(format!(
                "{}: contains syntax errors; results may be incomplete",
                f.path
            ));
        }
        for issue in &mut f.issues {
            issue.is_new = new_code.is_new(&f.path, issue.line);
        }
    }

    let tokens: Vec<&[analysis::Token]> = files.iter().map(|f| f.tokens.as_slice()).collect();
    let duplication = duplication::detect(
        &tokens,
        cfg.duplication.min_tokens,
        cfg.duplication.min_lines,
    );

    // Warnings arrive in filesystem-walk order; sort for stable output.
    warnings.sort();
    warnings.dedup();

    Ok(ProjectAnalysis {
        files,
        duplication,
        coverage,
        new_code,
        warnings,
    })
}

type Candidate = (PathBuf, String, Lang);

/// Walks `root` honoring .gitignore and `scan.exclude`, keeping supported languages.
fn collect_files(root: &Path, cfg: &Config) -> Result<(Vec<Candidate>, Vec<String>), Error> {
    let mut overrides = OverrideBuilder::new(root);
    for pattern in &cfg.scan.exclude {
        overrides
            .add(&format!("!{pattern}"))
            .map_err(|e| Error::Config(format!("invalid exclude pattern '{pattern}': {e}")))?;
    }
    let overrides = overrides
        .build()
        .map_err(|e| Error::Config(format!("invalid exclude patterns: {e}")))?;
    let walker = WalkBuilder::new(root)
        .overrides(overrides)
        .require_git(false)
        .build();

    let mut files = Vec::new();
    let mut warnings = Vec::new();
    for entry in walker {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                warnings.push(e.to_string());
                continue;
            }
        };
        if !entry.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        let path = entry.path();
        let Some(lang) = Lang::from_path(path) else {
            continue;
        };
        let rel = relative(path, root);
        files.push((path.to_path_buf(), rel, lang));
    }
    Ok((files, warnings))
}

/// Reads at most `max_bytes`; `None` if the file is larger. Bounding the read
/// itself (not a prior size check) keeps memory bounded even if the file
/// grows between listing and reading.
fn read_capped(path: &Path, max_bytes: u64) -> std::io::Result<Option<Vec<u8>>> {
    let mut buf = Vec::new();
    File::open(path)?
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut buf)?;
    Ok((buf.len() as u64 <= max_bytes).then_some(buf))
}

/// Reads the LCOV reports the user named. Unlike analyzed files, these are
/// explicit inputs, so a missing or unreadable one is an error.
fn load_coverage(paths: &[PathBuf], root: &Path) -> Result<Coverage, Error> {
    let canonical_root = root.canonicalize().ok();
    let mut roots = vec![root];
    roots.extend(canonical_root.as_deref());
    let mut coverage = Coverage::default();
    for path in paths {
        let text = std::fs::read_to_string(path).map_err(|source| Error::Io {
            path: path.clone(),
            source,
        })?;
        coverage.merge_lcov(&text, &roots);
    }
    Ok(coverage)
}

fn relative(path: &Path, root: &Path) -> String {
    let rel = path.strip_prefix(root).unwrap_or(path);
    rel.components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::measures;
    use crate::model::Metric;

    fn outcome(analysis: ProjectAnalysis, cfg: &Config) -> crate::Outcome {
        let measures = measures::compute(&analysis);
        let gate = crate::gate::evaluate(&cfg.gate.conditions, &measures);
        crate::Outcome {
            analysis,
            measures,
            gate,
        }
    }

    #[test]
    fn scans_a_mixed_project_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let write = |p: &str, s: &str| {
            let full = root.join(p);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, s).unwrap();
        };
        write("src/app.js", "var x = 1;\nif (x == 2) { eval(y); }\n");
        write("src/tool.py", "def f(a=[]):\n    return a\n");
        write("node_modules/dep/index.js", "eval(x);\n");
        write("notes.txt", "eval(x);\n");
        write(".gitignore", "ignored/\n");
        write("ignored/x.py", "eval(x)\n");
        write(
            "lcov.info",
            "SF:src/app.js\nDA:1,1\nDA:2,0\nend_of_record\n",
        );

        let cfg = Config::default();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let opts = ScanOptions {
            root: root.to_path_buf(),
            new_code_ref: None,
            coverage: vec![root.join("lcov.info")],
        };
        let r = scan(&opts, &cfg, &rules).unwrap();

        let paths: Vec<_> = r.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, vec!["src/app.js", "src/tool.py"]);
        let rules_hit: Vec<_> = r
            .files
            .iter()
            .flat_map(|f| &f.issues)
            .map(|i| i.rule)
            .collect();
        assert_eq!(
            rules_hit,
            vec!["js/no-var", "js/eqeqeq", "js/no-eval", "py/mutable-default"]
        );

        let m = measures::compute(&r);
        assert_eq!(m[&Metric::Files], Some(2.0));
        assert_eq!(m[&Metric::Bugs], Some(2.0));
        assert_eq!(m[&Metric::Vulnerabilities], Some(1.0));
        assert_eq!(m[&Metric::NewBugs], Some(2.0)); // no reference: everything is new
        assert_eq!(m[&Metric::Coverage], Some(50.0));
    }

    #[test]
    fn oversized_files_are_skipped_with_a_warning() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("big.py"), "x = 1\n".repeat(400)).unwrap();
        std::fs::write(dir.path().join("small.py"), "x = 1\n").unwrap();
        let cfg = Config {
            scan: crate::config::ScanConfig {
                max_file_size_kb: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let opts = ScanOptions {
            root: dir.path().to_path_buf(),
            new_code_ref: None,
            coverage: vec![],
        };
        let r = scan(&opts, &cfg, &rules).unwrap();
        assert_eq!(r.files.len(), 1);
        assert_eq!(r.warnings, vec!["big.py: skipped, larger than 1 KB"]);
    }

    /// Renders every format; `reverse` feeds the post-discovery stage its
    /// inputs in reversed order, as a different filesystem might.
    fn render_all(root: &Path, cfg: &Config, threads: usize, reverse: bool) -> Vec<String> {
        use crate::report::{self, Format};
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let opts = ScanOptions {
            root: root.to_path_buf(),
            new_code_ref: None,
            coverage: vec![],
        };
        let (mut paths, _) = collect_files(root, cfg).unwrap();
        let mut walk_warnings = vec!["z: walk error".to_string(), "a: walk error".to_string()];
        if reverse {
            paths.reverse();
            walk_warnings.reverse();
        }
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap();
        let r = pool
            .install(|| scan_files(&opts, cfg, &rules, paths, walk_warnings))
            .unwrap();
        assert!(!r.duplication.blocks.is_empty() && r.warnings.len() >= 2);
        let out = outcome(r, cfg);
        let rep = report::build(&out, false);
        [Format::Text, Format::Json, Format::Sarif]
            .map(|f| report::render(&rep, f))
            .to_vec()
    }

    /// Same project, files created in opposite orders, discovery results fed
    /// in opposite orders, 1 vs 4 threads: every report format must be
    /// byte-identical.
    #[test]
    fn reports_are_deterministic() {
        let shared = "function shared(a, b) {\n  if (a == b) { return a + b; }\n  for (let i = 0; i < a; i++) { b += i * 2; }\n  return b - a;\n}\n";
        let files: Vec<(&str, Vec<u8>)> = vec![
            ("src/a.js", format!("var x = 1;\n{shared}").into_bytes()),
            ("src/b.js", format!("{shared}eval(y);\n").into_bytes()),
            ("lib/c.js", shared.as_bytes().to_vec()),
            (
                "tools/t.py",
                b"def f(a=[]):\n    return a  # TODO\n".to_vec(),
            ),
            ("broken.py", b"def (:\n".to_vec()),
            ("latin1.py", b"x = '\xe9'\n".to_vec()),
            (
                "Main.java",
                b"class Main { void f() { System.exit(1); } }\n".to_vec(),
            ),
        ];
        let cfg = Config {
            duplication: crate::config::DuplicationConfig {
                min_tokens: 20,
                min_lines: 3,
            },
            ..Default::default()
        };
        let make = |order: &mut dyn Iterator<Item = &(&str, Vec<u8>)>| {
            let dir = tempfile::tempdir().unwrap();
            for (p, content) in order {
                let full = dir.path().join(p);
                std::fs::create_dir_all(full.parent().unwrap()).unwrap();
                std::fs::write(full, content).unwrap();
            }
            dir
        };
        let forward = make(&mut files.iter());
        let backward = make(&mut files.iter().rev());
        assert_eq!(
            render_all(forward.path(), &cfg, 1, false),
            render_all(backward.path(), &cfg, 4, true)
        );
    }

    /// Regression: file names and identifiers went to the terminal raw, so a
    /// crafted name could inject escape sequences.
    #[cfg(unix)]
    #[test]
    fn text_report_escapes_control_characters_from_the_repository() {
        use crate::report::{self, Format};
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("evil\x1b[2J.js"), "eval(x);\n").unwrap();
        let cfg = Config::default();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let opts = ScanOptions {
            root: dir.path().to_path_buf(),
            new_code_ref: None,
            coverage: vec![],
        };
        let out = outcome(scan(&opts, &cfg, &rules).unwrap(), &cfg);
        let text = report::render(&report::build(&out, false), Format::Text);
        assert!(!text.contains('\x1b'), "{text}");
        assert!(text.contains("evil\\u{1b}[2J.js"), "{text}");
    }
}
