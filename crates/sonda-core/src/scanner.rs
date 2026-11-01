//! Infrastructure: finds and reads the files to analyze, loads coverage
//! reports and asks `git` for new code, then runs the domain analysis.

use crate::analysis::{self, FileAnalysis};
use crate::config::{Config, ScanConfig};
use crate::coverage::Coverage;
use crate::deps::{self, Dependency, Ecosystem, FileKind};
use crate::duplication;
use crate::error::Error;
use crate::git::{self, Auto};
use crate::lang::{JS_TS, Lang};
use crate::newcode::{Basis, NewCode};
use crate::project::ProjectAnalysis;
use crate::rules::RuleSet;
use crate::sandbox::SandboxMode;
use crate::worker::WorkerPool;
use ignore::WalkBuilder;
use ignore::overrides::OverrideBuilder;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tracing::{debug, info};

/// What to analyze.
#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    /// Project directory.
    pub root: PathBuf,
    /// What new code is compared with: a git ref (via merge base), `auto`
    /// or `none`, as `scan.new_code` takes them; `None` uses `scan.new_code`
    /// (ADR-0010).
    pub new_code_ref: Option<String>,
    /// LCOV reports to import.
    pub coverage: Vec<PathBuf>,
    /// Where files are parsed (ADR-0003).
    pub isolation: Isolation,
    /// Files analyzed in parallel; `None` uses every CPU.
    pub jobs: Option<NonZeroUsize>,
    /// A directory of OSV records to check dependencies against (ADR-0009);
    /// without it, dependency metrics have no data.
    pub advisories: Option<PathBuf>,
}

/// Where files are parsed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Isolation {
    /// In this process. A crash in a tree-sitter grammar aborts the scan.
    #[default]
    InProcess,
    /// In worker processes running `program __worker` (the `sonda`
    /// binary). A crash only loses the file being parsed; `sandbox` says
    /// whether the workers are also locked down (ADR-0004).
    Workers {
        program: PathBuf,
        sandbox: SandboxMode,
    },
}

pub(crate) fn scan(
    opts: &ScanOptions,
    cfg: &Config,
    rules: &RuleSet,
) -> Result<ProjectAnalysis, Error> {
    let started = Instant::now();
    let found = collect_files(&opts.root, cfg)?;
    info!(
        files = found.files.len(),
        lockfiles = found.dependency_files.len(),
        elapsed_ms = ms(started),
        "discovered files"
    );
    let (dependencies, dependency_warnings) = load_dependencies(&found.dependency_files);
    let advisories = opts
        .advisories
        .as_deref()
        .map(load_advisories)
        .transpose()?;
    let mut analysis = scan_files(opts, cfg, rules, found.files, found.warnings)?;
    if let Some((advisories, warnings)) = advisories {
        let mut vulnerabilities = crate::advisories::check(&dependencies, &advisories);
        // New: not already affecting the project at the new-code reference.
        if let Some(reference) = analysis.new_code.reference() {
            let base = base_dependencies(
                &opts.root,
                reference,
                &found.dependency_files,
                Duration::from_secs(cfg.scan.git_timeout_secs),
            )?;
            let known: HashSet<(Ecosystem, String, String)> =
                crate::advisories::check(&base, &advisories)
                    .into_iter()
                    .map(|v| finding_key(&v))
                    .collect();
            for v in &mut vulnerabilities {
                v.is_new = !known.contains(&finding_key(v));
            }
        }
        info!(
            advisories = advisories.len(),
            vulnerabilities = vulnerabilities.len(),
            new = vulnerabilities.iter().filter(|v| v.is_new).count(),
            "checked dependencies"
        );
        analysis.vulnerabilities = Some(vulnerabilities);
        analysis.warnings.extend(warnings);
    }
    analysis.dependencies = dependencies;
    analysis.warnings.extend(dependency_warnings);
    analysis.warnings.sort();
    analysis.warnings.dedup();
    Ok(analysis)
}

/// The project's dependencies from its lockfiles, without analyzing any
/// code: what `sonda sbom` exports.
pub(crate) fn dependencies(
    root: &Path,
    cfg: &Config,
) -> Result<(Vec<Dependency>, Vec<String>), Error> {
    let found = collect_files(root, cfg)?;
    let (dependencies, mut warnings) = load_dependencies(&found.dependency_files);
    warnings.extend(found.warnings);
    warnings.sort();
    warnings.dedup();
    Ok((dependencies, warnings))
}

/// One OSV record is a few kilobytes; this bounds a hostile one.
const ADVISORY_MAX_BYTES: u64 = 4 << 20;

/// Every OSV record (`*.json`) under `dir`, such as an unzipped OSV export,
/// that sonda imports; records that can't be read are counted in a warning.
/// A missing directory is an error: the gate would silently lack data.
fn load_advisories(dir: &Path) -> Result<(Vec<crate::advisories::Advisory>, Vec<String>), Error> {
    let started = Instant::now();
    if !dir.is_dir() {
        return Err(Error::InvalidArgument(format!(
            "--advisories {}: not a directory",
            dir.display()
        )));
    }
    let mut stack = vec![dir.to_path_buf()];
    let mut files = Vec::new();
    while let Some(d) = stack.pop() {
        let entries = std::fs::read_dir(&d)
            .map_err(|e| Error::InvalidArgument(format!("{}: {e}", d.display())))?;
        for entry in entries.flatten() {
            let path = entry.path();
            match entry.file_type() {
                Ok(t) if t.is_dir() => stack.push(path),
                // OSV names each record after its id: skip databases sonda
                // doesn't import (most of npm's are malicious-package
                // reports) without reading them.
                Ok(t)
                    if t.is_file()
                        && path.extension().is_some_and(|e| e == "json")
                        && path.file_stem().and_then(|s| s.to_str()).is_none_or(|id| {
                            crate::advisories::Source::of(id).is_some() || !id.contains('-')
                        }) =>
                {
                    files.push(path)
                }
                _ => {}
            }
        }
    }
    files.sort();
    let mut advisories = Vec::new();
    let mut unreadable = 0;
    for path in &files {
        let text = read_listed(path, None, ADVISORY_MAX_BYTES)
            .ok()
            .flatten()
            .and_then(|b| String::from_utf8(b).ok());
        match text.as_deref().map(crate::advisories::parse) {
            Some(Ok(Some(a))) => advisories.push(a),
            Some(Ok(None)) => {}
            _ => unreadable += 1,
        }
    }
    // The same record can be in two ecosystems' directories.
    advisories.sort_by(|a, b| a.id.cmp(&b.id));
    advisories.dedup_by(|a, b| a.id == b.id);
    info!(
        records = files.len(),
        advisories = advisories.len(),
        elapsed_ms = ms(started),
        "read advisories"
    );
    let warnings = (unreadable > 0)
        .then(|| {
            format!(
                "{}: {unreadable} advisory records could not be read",
                dir.display()
            )
        })
        .into_iter()
        .collect();
    Ok((advisories, warnings))
}

/// Lockfiles are machine-written and can be much larger than source files
/// (`scan.max_file_size_kb`); this still bounds memory.
const LOCKFILE_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// A finding, as the same vulnerability in the same package whatever its
/// version: upgrading within an affected range isn't a new finding.
fn finding_key(v: &crate::advisories::Vulnerability) -> (Ecosystem, String, String) {
    (
        v.ecosystem,
        deps::package_key(v.ecosystem, &v.name),
        v.advisory.clone(),
    )
}

/// The dependencies the lockfiles found now pinned at the merge base of
/// HEAD and `reference`. Lockfiles that didn't exist there pinned nothing;
/// their problems there are not this scan's warnings.
fn base_dependencies(
    root: &Path,
    reference: &str,
    files: &[DependencyFile],
    timeout: Duration,
) -> Result<Vec<Dependency>, Error> {
    let paths: Vec<&str> = files.iter().map(|f| f.rel.as_str()).collect();
    let contents = git::files_at(root, reference, &paths, LOCKFILE_MAX_BYTES, timeout)?;
    let (dependencies, _) = parse_dependencies(files, |f| {
        contents
            .get(&f.rel)
            .cloned()
            .ok_or_else(|| format!("{}: not at {reference}", f.rel))
    });
    Ok(dependencies)
}

/// Reads and parses each lockfile; problems become warnings. Sorted, so the
/// result does not depend on the walk's order.
fn load_dependencies(files: &[DependencyFile]) -> (Vec<Dependency>, Vec<String>) {
    let read = |f: &DependencyFile| -> Result<String, String> {
        let bytes = read_listed(&f.path, f.id, LOCKFILE_MAX_BYTES)
            .map_err(|e| format!("{}: {e}", f.rel))?
            .ok_or_else(|| {
                format!(
                    "{}: skipped, larger than {} MB",
                    f.rel,
                    LOCKFILE_MAX_BYTES >> 20
                )
            })?;
        String::from_utf8(bytes).map_err(|_| format!("{}: skipped, not valid UTF-8", f.rel))
    };
    parse_dependencies(files, read)
}

/// Parses each lockfile `read` gives; problems become warnings.
fn parse_dependencies(
    files: &[DependencyFile],
    read: impl Fn(&DependencyFile) -> Result<String, String>,
) -> (Vec<Dependency>, Vec<String>) {
    let started = Instant::now();
    let dir = |rel: &str| rel.rsplit_once('/').map_or("", |(d, _)| d).to_string();
    // A manifest (pyproject.toml, package.json) is read only next to a
    // lockfile that needs it.
    let needed: HashSet<(String, FileKind)> = files
        .iter()
        .filter_map(|f| deps::manifest_for(f.kind).map(|m| (dir(&f.rel), m)))
        .collect();
    let manifests: HashMap<(String, FileKind), String> = files
        .iter()
        .filter(|f| needed.contains(&(dir(&f.rel), f.kind)))
        .filter_map(|f| read(f).ok().map(|text| ((dir(&f.rel), f.kind), text)))
        .collect();

    let mut dependencies = Vec::new();
    let mut warnings = Vec::new();
    for f in files.iter().filter(|f| !deps::is_manifest(f.kind)) {
        // An unsupported lockfile is only reported, never read.
        let text = match f.kind {
            FileKind::Unsupported => String::new(),
            _ => match read(f) {
                Ok(t) => t,
                Err(w) => {
                    warnings.push(w);
                    continue;
                }
            },
        };
        let manifest = deps::manifest_for(f.kind)
            .and_then(|m| manifests.get(&(dir(&f.rel), m)))
            .map(String::as_str);
        match deps::parse(f.kind, &f.rel, &text, manifest) {
            Ok(parsed) => {
                dependencies.extend(parsed.dependencies);
                warnings.extend(parsed.notes.into_iter().map(|n| format!("{}: {n}", f.rel)));
            }
            Err(e) => warnings.push(format!("{}: skipped, {e}", f.rel)),
        }
    }
    dependencies.sort();
    info!(
        dependencies = dependencies.len(),
        elapsed_ms = ms(started),
        "read lockfiles"
    );
    (dependencies, warnings)
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
    paths.sort_by(|a, b| a.rel.cmp(&b.rel));
    let root = &opts.root;
    let coverage = load_coverage(&opts.coverage, root)?;
    // Saturating: the config may come from the analyzed repository.
    let max_bytes = cfg.scan.max_file_size_kb.saturating_mul(1024);
    let timeout = Duration::from_secs(cfg.scan.file_timeout_secs);

    let git_timeout = Duration::from_secs(cfg.scan.git_timeout_secs);
    let (reference, new_code_basis) =
        match opts.new_code_ref.as_deref().unwrap_or(&cfg.scan.new_code) {
            "none" => (
                None,
                Basis::WholeProject("new code is set to \"none\"".into()),
            ),
            "auto" => match git::auto_reference(
                root,
                &git::Ci::from_env(&|name| std::env::var(name).ok()),
                git_timeout,
            )? {
                Auto::Found(r, basis) => (Some(r), basis),
                Auto::Nothing(why) => (None, Basis::WholeProject(why)),
            },
            r => (Some(r.to_string()), Basis::Given(r.to_string())),
        };
    let new_code = match &reference {
        Some(r) => {
            let started = Instant::now();
            let contents = paths
                .iter()
                .map(|c| (c.rel.as_str(), read_capped(c, max_bytes).ok().flatten()));
            let new_code = git::new_code(root, r, max_bytes, git_timeout, contents)?;
            info!(reference = %r, basis = new_code_basis.kind(), elapsed_ms = ms(started), "computed new code");
            new_code
        }
        None => NewCode::Everything,
    };

    let started = Instant::now();
    let load = |c: &Candidate| load_source(c, max_bytes, &cfg.scan);
    // Same warning text in both modes, so reports do not depend on the mode.
    let results: Vec<Result<FileAnalysis, String>> = match &opts.isolation {
        Isolation::InProcess => {
            let threads = opts.jobs.map_or(0, NonZeroUsize::get); // 0: rayon's default
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .map_err(|e| Error::Internal(format!("thread pool: {e}")))?;
            pool.install(|| {
                paths
                    .par_iter()
                    .map(|c| {
                        let src = load(c)?;
                        let deadline = Instant::now() + timeout;
                        analysis::analyze(&c.rel, c.lang, &src, rules, cfg, deadline)
                            .map_err(|e| format!("{}: skipped, {e}", c.rel))
                    })
                    .collect()
            })
        }
        Isolation::Workers { program, sandbox } => {
            WorkerPool::new(program, cfg, timeout, opts.jobs, *sandbox)?
                .run(&paths, |c| load(c).map(|src| (c.rel.as_str(), c.lang, src)))?
        }
    };

    let mut files = Vec::with_capacity(results.len());
    for r in results {
        match r {
            Ok(f) => files.push(f),
            Err(w) => {
                debug!(warning = %w, "file not analyzed");
                warnings.push(w);
            }
        }
    }
    info!(
        analyzed = files.len(),
        skipped = paths.len() - files.len(),
        issues = files.iter().map(|f| f.issues.len()).sum::<usize>(),
        elapsed_ms = ms(started),
        "analyzed files"
    );
    // `paths` is sorted and rayon's collect keeps input order, so `files` is too.
    for f in &mut files {
        if f.has_syntax_errors {
            warnings.push(format!(
                "{}: contains syntax errors; results may be incomplete",
                f.path
            ));
        }
        if f.semantic_incomplete {
            warnings.push(format!(
                "{}: semantic analysis did not finish before the per-file timeout; \
                 rules such as unused variables found nothing in it",
                f.path
            ));
        }
        for issue in &mut f.issues {
            issue.is_new = new_code.is_new(&f.path, issue.line);
        }
    }

    let package_issues_before: Vec<usize> = files.iter().map(|f| f.issues.len()).collect();
    analysis::java_package_rules(&mut files, rules);
    for (f, before) in files.iter_mut().zip(package_issues_before) {
        for issue in &mut f.issues[before..] {
            issue.is_new = new_code.is_new(&f.path, issue.line);
        }
        f.issues
            .sort_by(|a, b| (a.line, a.column, a.rule).cmp(&(b.line, b.column, b.rule)));
    }

    let started = Instant::now();
    let tokens: Vec<&[analysis::Token]> = files.iter().map(|f| f.tokens.as_slice()).collect();
    let duplication = duplication::detect(
        &tokens,
        cfg.duplication.min_tokens,
        cfg.duplication.min_lines,
    );
    info!(
        tokens = tokens.iter().map(|t| t.len()).sum::<usize>(),
        blocks = duplication.blocks.len(),
        elapsed_ms = ms(started),
        "detected duplication"
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
        dependencies: Vec::new(),
        vulnerabilities: None,
        new_code_basis,
    })
}

/// A file found by the walk.
struct Candidate {
    path: PathBuf,
    /// Root-relative, with `/` separators.
    rel: String,
    lang: Lang,
    /// What the walk saw, to detect the file being swapped before it is read.
    id: Option<FileId>,
}

/// Device and inode, from metadata that does not follow symlinks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileId {
    dev: u64,
    ino: u64,
}

#[cfg(unix)]
fn file_id(meta: &std::fs::Metadata) -> Option<FileId> {
    use std::os::unix::fs::MetadataExt;
    Some(FileId {
        dev: meta.dev(),
        ino: meta.ino(),
    })
}

// Windows needs elevated rights to create symlinks, and std exposes no stable
// file identity there, so the swap check is Unix-only.
#[cfg(not(unix))]
fn file_id(_: &std::fs::Metadata) -> Option<FileId> {
    None
}

/// A lockfile or manifest found by the walk.
struct DependencyFile {
    path: PathBuf,
    rel: String,
    kind: FileKind,
    id: Option<FileId>,
}

/// What the walk found.
struct Found {
    files: Vec<Candidate>,
    dependency_files: Vec<DependencyFile>,
    warnings: Vec<String>,
}

/// Walks `root` honoring .gitignore and `scan.exclude`, keeping supported
/// languages, and lockfiles.
fn collect_files(root: &Path, cfg: &Config) -> Result<Found, Error> {
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
    let mut dependency_files = Vec::new();
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
        let dependency_kind = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(deps::file_kind);
        let lang = Lang::from_path(path);
        if lang.is_none() && dependency_kind.is_none() {
            continue;
        }
        let rel = relative(path, root);
        let Ok(meta) = entry.metadata() else {
            warnings.push(format!("{rel}: skipped, metadata unavailable"));
            continue;
        };
        let id = file_id(&meta);
        match (lang, dependency_kind) {
            (Some(lang), _) => files.push(Candidate {
                path: path.to_path_buf(),
                rel,
                lang,
                id,
            }),
            (None, Some(kind)) => dependency_files.push(DependencyFile {
                path: path.to_path_buf(),
                rel,
                kind,
                id,
            }),
            (None, None) => {}
        }
    }
    dependency_files.sort_by(|a, b| a.rel.cmp(&b.rel));
    Ok(Found {
        files,
        dependency_files,
        warnings,
    })
}

/// A candidate's source text, or the warning explaining why it is skipped.
fn load_source(c: &Candidate, max_bytes: u64, scan: &ScanConfig) -> Result<String, String> {
    let rel = &c.rel;
    let max_kb = scan.max_file_size_kb;
    let bytes = read_capped(c, max_bytes)
        .map_err(|e| format!("{rel}: {e}"))?
        .ok_or_else(|| format!("{rel}: skipped, larger than {max_kb} KB"))?;
    let src = String::from_utf8(bytes).map_err(|_| format!("{rel}: skipped, not valid UTF-8"))?;
    if scan.skip_minified && JS_TS.contains(&c.lang) && looks_minified(&src) {
        return Err(format!(
            "{rel}: skipped, looks minified (average line over \
             {MINIFIED_AVERAGE_LINE} characters; scan.skip_minified = false analyzes it)"
        ));
    }
    Ok(src)
}

/// The average line length above which a file counts as minified, as
/// SonarQube's JavaScript analyzer decides. Bundlers that keep newlines
/// between modules still land far above it; hand-written code far below.
const MINIFIED_AVERAGE_LINE: usize = 200;

fn looks_minified(src: &str) -> bool {
    let lines = src.lines().count().max(1);
    src.len() / lines > MINIFIED_AVERAGE_LINE
}

fn ms(since: Instant) -> u128 {
    since.elapsed().as_millis()
}

/// Reads at most `max_bytes` of a candidate; `None` if the file is larger.
/// Bounding the read itself (not a prior size check) keeps memory bounded
/// even if the file grows between listing and reading.
///
/// The opened file must be the one the walk listed: if it (or a directory on
/// its path) was swapped since, for instance for a symlink pointing outside
/// the root, the read is refused. On Unix the open is non-blocking, so a file
/// swapped for a FIFO cannot hang the scan before that check runs.
fn read_capped(c: &Candidate, max_bytes: u64) -> std::io::Result<Option<Vec<u8>>> {
    read_listed(&c.path, c.id, max_bytes)
}

/// [`read_capped`] for any file the walk listed with identity `id`.
fn read_listed(
    path: &Path,
    id: Option<FileId>,
    max_bytes: u64,
) -> std::io::Result<Option<Vec<u8>>> {
    let file = open_nonblocking(path)?;
    let meta = file.metadata()?;
    // Both checks are needed: a deleted file's inode can be reused at once
    // (ext4 does), so a FIFO created in its place can match the identity.
    // A symlink to an existing file outside the root cannot: that file's
    // inode was in use alongside the listed one.
    if !meta.is_file() || (id.is_some() && file_id(&meta) != id) {
        return Err(std::io::Error::other(
            "skipped, the file was replaced after it was listed",
        ));
    }
    let mut buf = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut buf)?;
    Ok((buf.len() as u64 <= max_bytes).then_some(buf))
}

#[cfg(unix)]
pub(crate) fn open_nonblocking(path: &Path) -> std::io::Result<File> {
    use rustix::fs::{Mode, OFlags};
    let flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC;
    Ok(File::from(rustix::fs::open(path, flags, Mode::empty())?))
}

#[cfg(not(unix))]
pub(crate) fn open_nonblocking(path: &Path) -> std::io::Result<File> {
    File::open(path)
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
    fn reads_lockfiles_outside_excluded_paths() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let write = |p: &str, s: &str| {
            let full = root.join(p);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, s).unwrap();
        };
        write(
            "web/package-lock.json",
            r#"{"lockfileVersion": 3, "packages": {"": {"dependencies": {"lodash": "^4"}},
               "node_modules/lodash": {"version": "4.17.20", "license": "MIT"}}}"#,
        );
        // A dependency's own lockfile, under the default exclude.
        write(
            "web/node_modules/lodash/package-lock.json",
            r#"{"lockfileVersion": 3, "packages": {"node_modules/x": {"version": "1.0.0"}}}"#,
        );
        write(
            "api/poetry.lock",
            "[[package]]\nname = \"flask\"\nversion = \"3.0.0\"\n",
        );
        write(
            "api/pyproject.toml",
            "[project]\ndependencies = [\"flask>=3\"]\n",
        );
        write("old/package-lock.json", r#"{"lockfileVersion": 1}"#);
        write("app/bun.lockb", "lockfileVersion: '9.0'\n");
        write("src/app.js", "let a = 1;\n");

        let cfg = Config::default();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let opts = ScanOptions {
            root: root.to_path_buf(),
            ..ScanOptions::default()
        };
        let r = scan(&opts, &cfg, &rules).unwrap();
        let got: Vec<(&str, &str, Option<bool>, &str)> = r
            .dependencies
            .iter()
            .map(|d| {
                (
                    d.name.as_str(),
                    d.version.as_str(),
                    d.direct,
                    d.source.as_str(),
                )
            })
            .collect();
        assert_eq!(
            got,
            [
                ("lodash", "4.17.20", Some(true), "web/package-lock.json"),
                ("flask", "3.0.0", Some(true), "api/poetry.lock"),
            ]
        );
        assert!(
            r.warnings
                .iter()
                .any(|w| w.starts_with("old/package-lock.json: skipped, lockfileVersion 1")),
            "{:?}",
            r.warnings
        );
        assert!(
            r.warnings
                .iter()
                .any(|w| w.starts_with("app/bun.lockb: skipped, not read")),
            "{:?}",
            r.warnings
        );
        // The same list without analyzing code.
        let (only, _) = dependencies(root, &cfg).unwrap();
        assert_eq!(only, r.dependencies);
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
            isolation: Isolation::InProcess,
            jobs: None,
            advisories: None,
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
    fn minified_scripts_are_skipped_with_a_warning() {
        let dir = tempfile::tempdir().unwrap();
        let bundle = format!("var a=[{}0];\n", "f(1),".repeat(300)).repeat(3);
        std::fs::write(dir.path().join("bundle.js"), &bundle).unwrap();
        std::fs::write(dir.path().join("app.js"), "var x = 1;\n").unwrap();
        // Only scripts: long lines elsewhere are not a minification sign.
        let long_py = format!("x = '{}'\n", "a".repeat(400));
        std::fs::write(dir.path().join("data.py"), long_py).unwrap();
        let analyzed = |skip_minified| {
            let cfg = Config {
                scan: crate::config::ScanConfig {
                    skip_minified,
                    ..Default::default()
                },
                ..Default::default()
            };
            let rules = RuleSet::new(&cfg.rules).unwrap();
            let opts = ScanOptions {
                root: dir.path().to_path_buf(),
                new_code_ref: None,
                coverage: vec![],
                isolation: Isolation::InProcess,
                jobs: None,
                advisories: None,
            };
            let r = scan(&opts, &cfg, &rules).unwrap();
            let paths: Vec<_> = r.files.iter().map(|f| f.path.clone()).collect();
            (paths, r.warnings)
        };
        let (paths, warnings) = analyzed(true);
        assert_eq!(paths, ["app.js", "data.py"]);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].starts_with("bundle.js: skipped, looks minified"));
        let (paths, warnings) = analyzed(false);
        assert_eq!(paths, ["app.js", "bundle.js", "data.py"]);
        assert!(warnings.is_empty());
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
            isolation: Isolation::InProcess,
            jobs: None,
            advisories: None,
        };
        let r = scan(&opts, &cfg, &rules).unwrap();
        assert_eq!(r.files.len(), 1);
        assert_eq!(r.warnings, vec!["big.py: skipped, larger than 1 KB"]);
    }

    #[test]
    fn java_packages_need_their_package_info() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for (rel, body) in [
            ("src/a/A.java", "package a; class A {}"),
            ("src/b/B.java", "package b; class B {}"),
            ("src/b/package-info.java", "package b;"),
            ("src/c/package-info.java", "package c;"),
        ] {
            let path = root.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, body).unwrap();
        }
        let mut cfg = Config::default();
        cfg.rules.enabled = ["java/package-info-missing".to_string()].to_vec();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let opts = ScanOptions {
            root: root.to_path_buf(),
            new_code_ref: None,
            coverage: vec![],
            isolation: Isolation::InProcess,
            jobs: None,
            advisories: None,
        };
        let r = scan(&opts, &cfg, &rules).unwrap();
        let hits: Vec<(&str, &str)> = r
            .files
            .iter()
            .flat_map(|f| f.issues.iter().map(|i| (f.path.as_str(), i.rule)))
            .filter(|(_, rule)| rule.starts_with("java/package-info"))
            .collect();
        assert_eq!(
            hits,
            [
                ("src/a/A.java", "java/package-info-missing"),
                ("src/c/package-info.java", "java/package-info-only"),
            ]
        );
    }

    #[test]
    fn spring_components_outside_the_scan_are_found() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for (rel, body) in [
            (
                "src/com/acme/App.java",
                "package com.acme;\n@SpringBootApplication\nclass App {}\n",
            ),
            (
                "src/com/acme/web/Ok.java",
                "package com.acme.web;\n@RestController\nclass Ok {}\n",
            ),
            (
                "src/com/other/Svc.java",
                "package com.other;\n\n@Service\nclass Svc {}\n",
            ),
        ] {
            let path = root.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, body).unwrap();
        }
        let mut cfg = Config::default();
        cfg.rules.enabled = ["java/component-not-scanned".to_string()].to_vec();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let opts = ScanOptions {
            root: root.to_path_buf(),
            new_code_ref: None,
            coverage: vec![],
            isolation: Isolation::InProcess,
            jobs: None,
            advisories: None,
        };
        let r = scan(&opts, &cfg, &rules).unwrap();
        let hits: Vec<(&str, usize)> = r
            .files
            .iter()
            .flat_map(|f| f.issues.iter().map(|i| (f.path.as_str(), i.line)))
            .collect();
        assert_eq!(hits, [("src/com/other/Svc.java", 3)]);
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
            isolation: Isolation::InProcess,
            jobs: None,
            advisories: None,
        };
        let mut paths = collect_files(root, cfg).unwrap().files;
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
            isolation: Isolation::InProcess,
            jobs: None,
            advisories: None,
        };
        let out = outcome(scan(&opts, &cfg, &rules).unwrap(), &cfg);
        let text = report::render(&report::build(&out, false), Format::Text);
        assert!(!text.contains('\x1b'), "{text}");
        assert!(text.contains("evil\\u{1b}[2J.js"), "{text}");
    }

    /// Regression (failed on Linux CI): ext4 reused a deleted file's inode
    /// for the FIFO created in its place, so the identity matched and the
    /// FIFO was read as an empty file. Without an identity, as here, only the
    /// file-type check stands between the scan and a non-regular file.
    #[cfg(unix)]
    #[test]
    fn only_regular_files_are_read() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("pipe.py");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(made.success());
        let candidate = Candidate {
            path: fifo,
            rel: "pipe.py".into(),
            lang: Lang::Python,
            id: None,
        };
        let err = read_capped(&candidate, 1024).unwrap_err();
        assert!(err.to_string().contains("replaced after it was listed"));
    }

    /// Regression: a file swapped for a symlink (or a parent directory
    /// swapped) between listing and reading was followed outside the root.
    /// The swaps are made after `collect_files`, as a race would.
    #[cfg(unix)]
    #[test]
    fn files_swapped_after_listing_are_not_read() {
        use std::os::unix::fs::symlink;
        let outside = tempfile::tempdir().unwrap();
        let secret = outside.path().join("secret.py");
        std::fs::write(&secret, "eval(secret)\n").unwrap();
        std::fs::create_dir(outside.path().join("dir")).unwrap();
        std::fs::write(outside.path().join("dir/b.py"), "eval(secret)\n").unwrap();

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("a.py"), "x = 1\n").unwrap();
        std::fs::create_dir(root.join("sub")).unwrap();
        std::fs::write(root.join("sub/b.py"), "x = 2\n").unwrap();
        std::fs::write(root.join("pipe.py"), "x = 3\n").unwrap();

        let cfg = Config::default();
        let found = collect_files(root, &cfg).unwrap();
        let (paths, warnings) = (found.files, found.warnings);
        assert_eq!(paths.len(), 3);

        std::fs::remove_file(root.join("a.py")).unwrap();
        symlink(&secret, root.join("a.py")).unwrap();
        std::fs::rename(root.join("sub"), root.join("sub-old")).unwrap();
        symlink(outside.path().join("dir"), root.join("sub")).unwrap();
        std::fs::remove_file(root.join("pipe.py")).unwrap();
        let made = std::process::Command::new("mkfifo")
            .arg(root.join("pipe.py"))
            .status()
            .unwrap();
        assert!(made.success());

        let rules = RuleSet::new(&cfg.rules).unwrap();
        let opts = ScanOptions {
            root: root.to_path_buf(),
            new_code_ref: None,
            coverage: vec![],
            isolation: Isolation::InProcess,
            jobs: None,
            advisories: None,
        };
        let r = scan_files(&opts, &cfg, &rules, paths, warnings).unwrap();
        assert!(r.files.is_empty(), "nothing outside the root was analyzed");
        assert_eq!(r.warnings.len(), 3, "{:?}", r.warnings);
        assert!(
            r.warnings
                .iter()
                .all(|w| w.contains("replaced after it was listed"))
        );
    }
}
