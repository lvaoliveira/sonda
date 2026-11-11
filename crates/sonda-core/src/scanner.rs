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
    let manifests = load_manifests(&found.dependency_files, cfg);
    // The Java version the code targets, when sonda.toml doesn't say.
    let detected;
    let cfg = match cfg.java.version {
        Some(_) => cfg,
        None => {
            let mut c = cfg.clone();
            c.java.version = java_version(&opts.root);
            if let Some(v) = c.java.version {
                info!(version = v, "Java version from the build file");
            }
            detected = c;
            &detected
        }
    };
    let mut analysis = scan_files(opts, cfg, rules, found.files, found.warnings, &manifests)?;
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

/// The Java version a project targets, from the build file at its root, as
/// SonarQube's Maven and Gradle scanners pass it: Maven's
/// `maven.compiler.release`, `<release>`, `maven.compiler.source`,
/// `<source>` or Spring Boot's `java.version`; Gradle's toolchain,
/// `jvmToolchain(N)` or `sourceCompatibility`. `1.8` is 8.
pub(crate) fn java_version(root: &Path) -> Option<u32> {
    let read = |name: &str| {
        let path = root.join(name);
        (std::fs::metadata(&path).ok()?.len() < 1 << 20)
            .then(|| std::fs::read_to_string(&path).ok())
            .flatten()
    };
    if let Some(pom) = read("pom.xml") {
        return maven_java_version(&pom);
    }
    ["build.gradle", "build.gradle.kts"]
        .iter()
        .find_map(|f| read(f))
        .and_then(|g| gradle_java_version(&g))
}

/// `1.8` -> 8, `17` -> 17, `"17"` -> 17.
fn parse_java_version(v: &str) -> Option<u32> {
    let v = v.trim().trim_matches(['"', '\'']);
    let v = v.strip_prefix("1.").unwrap_or(v);
    v.split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()
        .filter(|&n| n >= 5)
}

fn maven_java_version(pom: &str) -> Option<u32> {
    let tag = |name: &str| -> Option<String> {
        let open = format!("<{name}>");
        let start = pom.find(&open)? + open.len();
        let end = pom[start..].find('<')? + start;
        Some(pom[start..end].trim().to_string())
    };
    // A value can name a property: `${java.version}`.
    let resolve = |v: String| -> Option<u32> {
        match v.strip_prefix("${").and_then(|r| r.strip_suffix('}')) {
            Some(property) => tag(property).and_then(|p| parse_java_version(&p)),
            None => parse_java_version(&v),
        }
    };
    [
        "maven.compiler.release",
        "release",
        "maven.compiler.source",
        "source",
        "java.version",
    ]
    .iter()
    .find_map(|name| tag(name).and_then(resolve))
}

fn gradle_java_version(gradle: &str) -> Option<u32> {
    let after = |marker: &str| -> Option<u32> {
        let at = gradle.find(marker)? + marker.len();
        let rest = gradle[at..].trim_start_matches([' ', '=', '(', '\'', '"']);
        parse_java_version(rest.split([')', '\n', '\'', '"']).next()?)
    };
    after("JavaLanguageVersion.of")
        .or_else(|| after("jvmToolchain"))
        .or_else(|| {
            let at = gradle.find("sourceCompatibility")?;
            let line = gradle[at..].lines().next()?;
            line.find("VERSION_")
                .and_then(|v| parse_java_version(&line[v + 8..].replace('_', ".")))
                .or_else(|| parse_java_version(line.split('=').nth(1)?))
        })
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

/// The reference new code is measured against, if any, and why that one.
fn new_code_reference(
    opts: &ScanOptions,
    cfg: &Config,
    git_timeout: Duration,
) -> Result<(Option<String>, Basis), Error> {
    Ok(
        match opts.new_code_ref.as_deref().unwrap_or(&cfg.scan.new_code) {
            "none" => (
                None,
                Basis::WholeProject("new code is set to \"none\"".into()),
            ),
            "auto" => match git::auto_reference(
                &opts.root,
                &git::Ci::from_env(&|name| std::env::var(name).ok()),
                git_timeout,
            )? {
                Auto::Found(r, basis) => (Some(r), basis),
                Auto::Nothing(why) => (None, Basis::WholeProject(why)),
            },
            r => (Some(r.to_string()), Basis::Given(r.to_string())),
        },
    )
}

/// Each file's analysis, or the warning for why it has none: in this
/// process or in workers, with the same warning text in both modes, so
/// reports do not depend on the mode.
fn analyze_all(
    opts: &ScanOptions,
    cfg: &Config,
    rules: &RuleSet,
    paths: &[Candidate],
    max_bytes: u64,
    timeout: Duration,
) -> Result<Vec<Result<FileAnalysis, String>>, Error> {
    let load = |c: &Candidate| load_source(c, max_bytes, &cfg.scan);
    match &opts.isolation {
        Isolation::InProcess => {
            let threads = opts.jobs.map_or(0, NonZeroUsize::get); // 0: rayon's default
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .map_err(|e| Error::Internal(format!("thread pool: {e}")))?;
            Ok(pool.install(|| {
                paths
                    .par_iter()
                    .map(|c| {
                        let src = load(c)?;
                        let deadline = Instant::now() + timeout;
                        analysis::analyze(&c.rel, c.lang, &src, rules, cfg, deadline)
                            .map_err(|e| format!("{}: skipped, {e}", c.rel))
                    })
                    .collect()
            }))
        }
        Isolation::Workers { program, sandbox } => {
            WorkerPool::new(program, cfg, timeout, opts.jobs, *sandbox)?
                .run(paths, |c| load(c).map(|src| (c.rel.as_str(), c.lang, src)))
        }
    }
}

/// Everything after file discovery. Output must not depend on the order of
/// `paths` or `warnings`, which come from filesystem iteration.
fn scan_files(
    opts: &ScanOptions,
    cfg: &Config,
    rules: &RuleSet,
    mut paths: Vec<Candidate>,
    mut warnings: Vec<String>,
    manifests: &[(String, Vec<String>)],
) -> Result<ProjectAnalysis, Error> {
    // Every later stage (analysis order, duplication's "first occurrence")
    // relies on this sort.
    paths.sort_by(|a, b| a.rel.cmp(&b.rel));
    let root = &opts.root;
    let scanned: HashSet<&str> = paths.iter().map(|p| p.rel.as_str()).collect();
    let coverage = load_coverage(&opts.coverage, root, &scanned)?;
    // Saturating: the config may come from the analyzed repository.
    let max_bytes = cfg.scan.max_file_size_kb.saturating_mul(1024);
    let timeout = Duration::from_secs(cfg.scan.file_timeout_secs);

    let git_timeout = Duration::from_secs(cfg.scan.git_timeout_secs);
    let (reference, new_code_basis) = new_code_reference(opts, cfg, git_timeout)?;
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
    let results = analyze_all(opts, cfg, rules, &paths, max_bytes, timeout)?;

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
    analysis::js_dependency_rules(&mut files, rules, manifests);
    analysis::taint_project_rules(&mut files, rules);
    analysis::cs_project_rules(&mut files, rules);
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

/// A source file's text: UTF-8, or for Python the Latin-1 family a PEP 263
/// coding declaration on one of the first two lines names. `None` for any
/// other byte sequence that is not UTF-8.
pub(crate) fn decode_source(rel: &str, bytes: Vec<u8>) -> Option<String> {
    match String::from_utf8(bytes) {
        Ok(s) => Some(s),
        Err(e) => {
            let bytes = e.into_bytes();
            (rel.ends_with(".py") && declares_latin1(&bytes))
                .then(|| bytes.iter().map(|&b| char::from(b)).collect())
        }
    }
}

/// Whether line one or two is a `coding[:=] latin-1` style declaration.
fn declares_latin1(bytes: &[u8]) -> bool {
    bytes.split(|&b| b == b'\n').take(2).any(|line| {
        let line = String::from_utf8_lossy(line).to_ascii_lowercase();
        let Some(rest) = line.trim_start().strip_prefix('#') else {
            return false;
        };
        let Some(at) = rest.find("coding") else {
            return false;
        };
        let name: String = rest[at + "coding".len()..]
            .trim_start_matches([':', '=', ' ', '\t'])
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            .collect();
        matches!(
            name.replace('_', "-").as_str(),
            "latin-1" | "latin1" | "iso-8859-1" | "iso8859-1" | "l1" | "cp819" | "8859"
        )
    })
}

/// A candidate's source text, or the warning explaining why it is skipped.
fn load_source(c: &Candidate, max_bytes: u64, scan: &ScanConfig) -> Result<String, String> {
    let rel = &c.rel;
    let max_kb = scan.max_file_size_kb;
    let bytes = read_capped(c, max_bytes)
        .map_err(|e| format!("{rel}: {e}"))?
        .ok_or_else(|| format!("{rel}: skipped, larger than {max_kb} KB"))?;
    let src =
        decode_source(rel, bytes).ok_or_else(|| format!("{rel}: skipped, not valid UTF-8"))?;
    let src = if rel.ends_with(".vue") {
        vue_script_only(&src)
    } else {
        src
    };
    if scan.skip_minified && JS_TS.contains(&c.lang) && looks_minified(&src) {
        return Err(format!(
            "{rel}: skipped, looks minified (average line over \
             {MINIFIED_AVERAGE_LINE} characters; scan.skip_minified = false analyzes it)"
        ));
    }
    if scan.skip_generated
        && let Some(marker) = generated_marker(&src)
    {
        return Err(format!(
            "{rel}: skipped, says it's generated (\"{marker}\"; scan.skip_generated = false analyzes it)"
        ));
    }
    Ok(src)
}

/// Each `package.json`'s directory and every package name it declares (all
/// four dependency sections) or is called: what the dependency rule checks
/// imports against.
fn load_manifests(files: &[DependencyFile], cfg: &Config) -> Vec<(String, Vec<String>)> {
    let max_bytes = cfg.scan.max_file_size_kb.saturating_mul(1024);
    files
        .iter()
        .filter(|f| f.kind == FileKind::PackageJson)
        .filter_map(|f| {
            let bytes = read_listed(&f.path, f.id, max_bytes).ok().flatten()?;
            let json: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
            let mut names: Vec<String> = Vec::new();
            if let Some(n) = json.get("name").and_then(|n| n.as_str()) {
                names.push(n.to_string());
            }
            for section in [
                "dependencies",
                "devDependencies",
                "peerDependencies",
                "optionalDependencies",
            ] {
                if let Some(o) = json.get(section).and_then(|o| o.as_object()) {
                    names.extend(o.keys().cloned());
                }
            }
            let dir = f.rel.rsplit_once('/').map_or("", |(d, _)| d).to_string();
            Some((dir, names))
        })
        .collect()
}

/// A Vue single-file component with everything outside its `<script>`
/// blocks blanked: bytes become spaces, line breaks stay, so every line and
/// column of the script is where the editor shows it.
fn vue_script_only(src: &str) -> String {
    let lower = src.to_ascii_lowercase();
    let mut keep = vec![false; src.len()];
    let mut at = 0;
    while let Some(open) = lower[at..].find("<script") {
        let open = at + open;
        let after = lower.as_bytes().get(open + 7).copied();
        if !matches!(after, Some(b'>' | b' ' | b'\n' | b'\t' | b'\r')) {
            at = open + 7;
            continue;
        }
        let Some(tag_end) = lower[open..].find('>') else {
            break;
        };
        let start = open + tag_end + 1;
        let Some(close) = lower[start..].find("</script") else {
            keep[start..].fill(true);
            break;
        };
        keep[start..start + close].fill(true);
        at = start + close;
    }
    src.char_indices()
        .map(|(i, c)| {
            if keep[i] || c == '\n' || c == '\r' {
                c.to_string()
            } else {
                " ".repeat(c.len_utf8())
            }
        })
        .collect()
}

/// The average line length above which a file counts as minified, as
/// SonarQube's JavaScript analyzer decides. Bundlers that keep newlines
/// between modules still land far above it; hand-written code far below.
const MINIFIED_AVERAGE_LINE: usize = 200;

fn looks_minified(src: &str) -> bool {
    let lines = src.lines().count().max(1);
    src.len() / lines > MINIFIED_AVERAGE_LINE
}

/// How many lines a generated file's notice is looked for in.
const GENERATED_NOTICE_LINES: usize = 10;

/// The marker a generated file's notice carries, if `src` has one: in the
/// comments among its first lines, `@generated`, `<auto-generated`, or
/// `DO NOT EDIT` beside a word for generated, the conventions code
/// generators follow (Go's `Code generated ... DO NOT EDIT.`, protoc,
/// .NET). Its issues are fixed in what generates it, not in it, and
/// editing it is undone by the next build. Deliberately narrow: a looser
/// test would skip real code, so a lone "do not edit" doesn't count.
fn generated_marker(src: &str) -> Option<&'static str> {
    let notice: String = src
        .lines()
        .take(GENERATED_NOTICE_LINES)
        .map(str::trim_start)
        .filter(|l| {
            ["//", "#", "/*", "*", "<!--", "--", ";"]
                .iter()
                .any(|c| l.starts_with(c))
        })
        .collect::<Vec<_>>()
        .join("\n")
        .to_lowercase();
    if notice.contains("@generated") {
        Some("@generated")
    } else if notice.contains("<auto-generated") {
        Some("<auto-generated")
    } else if notice.contains("do not edit") && notice.contains("generat") {
        Some("DO NOT EDIT")
    } else {
        None
    }
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
///
/// Test runners write `SF:` paths relative to where they ran, which isn't
/// always the scan root: vitest in `node/` writes `src/a.js` for
/// `node/src/a.js`. A relative path is tried under the report's directory
/// and each of its parents, then the root, and the first that names a scanned
/// file is the one: tests ran nearer the report than the root.
fn load_coverage(
    paths: &[PathBuf],
    root: &Path,
    scanned: &HashSet<&str>,
) -> Result<Coverage, Error> {
    let canonical_root = root.canonicalize().ok();
    let mut roots = vec![root];
    roots.extend(canonical_root.as_deref());
    let mut coverage = Coverage::default();
    for path in paths {
        let text = std::fs::read_to_string(path).map_err(|source| Error::Io {
            path: path.clone(),
            source,
        })?;
        let bases = report_dirs(path, canonical_root.as_deref());
        coverage.merge_lcov_resolving(&text, &roots, |rel| {
            if Path::new(&rel).is_absolute() {
                return rel;
            }
            bases
                .iter()
                .filter_map(|base| normalize(&format!("{base}/{rel}")))
                .find(|candidate| scanned.contains(candidate.as_str()))
                .unwrap_or(rel)
        });
    }
    Ok(coverage)
}

/// The report's directory and its parents, root-relative, deepest first,
/// the root itself excluded; none when the report isn't under the root.
fn report_dirs(report: &Path, canonical_root: Option<&Path>) -> Vec<String> {
    let (Some(root), Ok(report)) = (canonical_root, report.canonicalize()) else {
        return Vec::new();
    };
    let Ok(rel) = report.strip_prefix(root) else {
        return Vec::new();
    };
    rel.ancestors()
        .skip(1)
        .filter(|dir| !dir.as_os_str().is_empty())
        .map(|dir| relative(dir, Path::new("")))
        .collect()
}

/// `a/b/../c` as `a/c`; none if it climbs above the root.
fn normalize(path: &str) -> Option<String> {
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

fn relative(path: &Path, root: &Path) -> String {
    let rel = path.strip_prefix(root).unwrap_or(path);
    rel.components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    #[test]
    fn latin1_python_is_decoded_when_declared() {
        let declared = b"# -*- coding: iso-8859-1 -*-\nx = '\xe9'\n".to_vec();
        assert_eq!(
            crate::scanner::decode_source("a.py", declared).as_deref(),
            Some("# -*- coding: iso-8859-1 -*-\nx = '\u{e9}'\n")
        );
        let undeclared = b"x = '\xe9'\n".to_vec();
        assert!(crate::scanner::decode_source("a.py", undeclared.clone()).is_none());
        assert!(crate::scanner::decode_source("a.js", undeclared).is_none());
        let utf8 = "x = 'é'\n".as_bytes().to_vec();
        assert!(crate::scanner::decode_source("a.py", utf8).is_some());
    }

    #[test]
    fn vue_components_keep_only_their_script_in_place() {
        let sfc = "<template>\n  <p>é</p>\n</template>\n<script setup lang=\"ts\">\nconst a = 1;\n</script>\n<style>p { }</style>\n";
        let out = vue_script_only(sfc);
        assert_eq!(out.len(), sfc.len());
        assert_eq!(out.lines().count(), sfc.lines().count());
        assert_eq!(out.lines().nth(4), Some("const a = 1;"));
        assert!(out.lines().take(4).all(|l| l.trim().is_empty()));
        assert!(!out.contains("template") && !out.contains("style"));
    }

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
            rules: cfg.rules.clone(),
            active_rules: crate::rules::RuleSet::new(&cfg.rules).unwrap().ids(),
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
    fn coverage_paths_are_found_from_where_the_tests_ran() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let write = |p: &str, s: &str| {
            let full = root.join(p);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, s).unwrap();
        };
        // Tests ran in node/ (vitest), so its report says src/a.js; a root
        // src/a.js exists too, and isn't the one.
        write("node/src/a.js", "var a = 1;\nvar b = 2;\n");
        write("node/lib/b.js", "var c = 3;\n");
        write("src/a.js", "var d = 4;\n");
        write("tools/t.js", "var e = 5;\n");
        write(
            "node/coverage/lcov.info",
            "SF:src/a.js\nDA:1,1\nDA:2,0\nend_of_record\n\
             SF:./lib/../lib/b.js\nDA:1,1\nend_of_record\n\
             SF:tools/t.js\nDA:1,0\nend_of_record\n\
             SF:../../escape.js\nDA:1,1\nend_of_record\n",
        );
        let cfg = Config::default();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let opts = ScanOptions {
            root: root.to_path_buf(),
            new_code_ref: None,
            coverage: vec![root.join("node/coverage/lcov.info")],
            isolation: Isolation::InProcess,
            jobs: None,
            advisories: None,
        };
        let r = scan(&opts, &cfg, &rules).unwrap();
        let covered: Vec<_> = r
            .files
            .iter()
            .map(|f| {
                let lines = r.coverage.files.get(&f.path).map(|hits| {
                    hits.iter()
                        .filter(|(_, h)| **h > 0)
                        .map(|(l, _)| *l)
                        .collect::<Vec<_>>()
                });
                (f.path.as_str(), lines)
            })
            .collect();
        assert_eq!(
            covered,
            vec![
                ("node/lib/b.js", Some(vec![1])),
                ("node/src/a.js", Some(vec![1])),
                ("src/a.js", None),
                // Not under node/: the root, as before.
                ("tools/t.js", Some(vec![])),
            ]
        );
        assert_eq!(normalize("a/../../b"), None);
        assert_eq!(normalize("./a/./b/../c"), Some("a/c".into()));
    }

    #[test]
    fn generated_files_are_recognized_by_their_notice() {
        for generated in [
            "// GENERATED from src/*.ts — do not edit. Rebuild with `bun run build`.\nvar a;\n",
            "// Code generated by protoc-gen-go. DO NOT EDIT.\npackage x\n",
            "#!/usr/bin/env python\n# @generated by tool\nx = 1\n",
            "/*\n * This file is auto-generated.\n * DO NOT EDIT\n */\nint x;\n",
            "// <auto-generated>\n//     This code was generated by a tool.\n// </auto-generated>\nclass A {}\n",
        ] {
            assert!(generated_marker(generated).is_some(), "{generated:?}");
        }
        for written in [
            "var a = 1;\n",
            // Not a comment, or past the first lines.
            "const msg = 'DO NOT EDIT';\n",
            &format!(
                "{}// @generated\n",
                "x = 1\n".repeat(GENERATED_NOTICE_LINES)
            ),
            // Generated once, then edited by hand, without the notice.
            "# Generated by Django 4.2 on 2026-01-01\nfrom django.db import migrations\n",
            // A warning to people, not a generator's notice.
            "// Do not edit without updating docs/rules.md.\nconst RULES = [];\n",
        ] {
            assert_eq!(generated_marker(written), None, "{written:?}");
        }
    }

    #[test]
    fn generated_files_are_skipped_with_a_warning() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("gen.js"), "// @generated\nvar a = 1;\n").unwrap();
        std::fs::write(dir.path().join("app.js"), "var x = 1;\n").unwrap();
        let analyzed = |skip_generated| {
            let cfg = Config {
                scan: crate::config::ScanConfig {
                    skip_generated,
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
        assert_eq!(paths, ["app.js"]);
        assert_eq!(
            warnings,
            [
                "gen.js: skipped, says it's generated (\"@generated\"; scan.skip_generated = false analyzes it)"
            ]
        );
        let (paths, _) = analyzed(false);
        assert_eq!(paths, ["app.js", "gen.js"]);
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
    fn imports_need_a_declaration_in_package_json() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for (rel, body) in [
            (
                "package.json",
                r#"{"name":"app","dependencies":{"express":"4"},"devDependencies":{"@scope/tool":"1"}}"#,
            ),
            (
                "src/a.js",
                "import e from 'express';\nimport fs from 'node:fs';\nimport p from 'path';\nimport x from 'lodash/get';\nimport t from '@scope/tool/x';\nimport r from './b';\nconst y = require('left-pad');\n",
            ),
        ] {
            let path = root.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, body).unwrap();
        }
        let mut cfg = Config::default();
        cfg.rules.enabled = ["js/dependency-not-declared".to_string()].to_vec();
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
        let lines: Vec<usize> = r
            .files
            .iter()
            .flat_map(|f| f.issues.iter())
            .filter(|i| i.rule == "js/dependency-not-declared")
            .map(|i| i.line)
            .collect();
        assert_eq!(lines, [4, 7]);
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

    #[test]
    fn csharp_partial_methods_and_resources_across_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for (rel, body) in [
            (
                "App/Gen.cs",
                "namespace App;\npartial class Form {\n  partial void OnLoaded();\n  partial void OnSaved();\n  public partial int Count();\n}\n",
            ),
            (
                "App/Form.cs",
                "namespace App;\npartial class Form {\n  partial void OnLoaded() { }\n  public partial int Count() => 1;\n}\n",
            ),
            (
                "App/Model.Designer.cs",
                "namespace App;\npartial class Model {\n  partial void OnCreated();\n}\n",
            ),
            (
                "App/Properties/AssemblyInfo.cs",
                "[assembly: AssemblyTitle(\"App\")]\n[assembly: AssemblyVersion(\"1.0.0.0\")]\n",
            ),
            (
                "App/Properties/Resources.Designer.cs",
                "namespace App.Properties;\nclass Resources { static System.Resources.ResourceManager rm; }\n",
            ),
            (
                "Lib/Properties/AssemblyInfo.cs",
                "[assembly: AssemblyTitle(\"Lib\")]\n[assembly: AssemblyVersion(\"1.0.0.0\")]\n",
            ),
        ] {
            let path = root.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, body).unwrap();
        }
        let mut cfg = Config::default();
        cfg.rules.enabled = ["cs/neutral-resources-language".to_string()].to_vec();
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
        let hits: Vec<(&str, &str, usize)> = r
            .files
            .iter()
            .flat_map(|f| f.issues.iter().map(|i| (i.rule, f.path.as_str(), i.line)))
            .filter(|(rule, _, _)| {
                matches!(
                    *rule,
                    "cs/partial-method-not-implemented" | "cs/neutral-resources-language"
                )
            })
            .collect();
        assert_eq!(
            hits,
            [
                ("cs/partial-method-not-implemented", "App/Gen.cs", 4),
                (
                    "cs/neutral-resources-language",
                    "App/Properties/AssemblyInfo.cs",
                    1
                ),
            ]
        );
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
            .install(|| scan_files(&opts, cfg, &rules, paths, walk_warnings, &[]))
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
        let r = scan_files(&opts, &cfg, &rules, paths, warnings, &[]).unwrap();
        assert!(r.files.is_empty(), "nothing outside the root was analyzed");
        assert_eq!(r.warnings.len(), 3, "{:?}", r.warnings);
        assert!(
            r.warnings
                .iter()
                .all(|w| w.contains("replaced after it was listed"))
        );
    }

    #[test]
    fn java_version_from_build_files() {
        assert_eq!(
            maven_java_version(
                "<properties><maven.compiler.source>1.8</maven.compiler.source></properties>"
            ),
            Some(8)
        );
        assert_eq!(
            maven_java_version(
                "<maven.compiler.release>17</maven.compiler.release><maven.compiler.source>1.8</maven.compiler.source>"
            ),
            Some(17)
        );
        assert_eq!(
            maven_java_version("<java.version>21</java.version><release>${java.version}</release>"),
            Some(21)
        );
        assert_eq!(maven_java_version("<project></project>"), None);
        assert_eq!(
            gradle_java_version(
                "java {\n    toolchain {\n        languageVersion = JavaLanguageVersion.of(17)\n    }\n}"
            ),
            Some(17)
        );
        assert_eq!(gradle_java_version("kotlin { jvmToolchain(21) }"), Some(21));
        assert_eq!(
            gradle_java_version("sourceCompatibility = JavaVersion.VERSION_1_8\n"),
            Some(8)
        );
        assert_eq!(
            gradle_java_version("sourceCompatibility = '11'\n"),
            Some(11)
        );
    }
}
