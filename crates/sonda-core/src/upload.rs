//! Infrastructure: prepares a report and its sources for `sonda server`
//! (ADR-0005). Sending them is the caller's job; this module does no
//! networking.
//!
//! The report file is input from outside this process, so nothing in it is
//! trusted: paths are confined to the root, and every source must match the
//! SHA-256 the scan recorded, so the server only ever receives the exact
//! bytes that were analyzed.

use crate::error::Error;
use crate::model::Sha256;
use crate::report::REPORT_VERSION;
use crate::scanner::open_nonblocking;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest as _;
use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Upper bound on all sources together, so a hostile report cannot make
/// the upload read without limit.
pub const MAX_SOURCE_BYTES: u64 = 512 << 20;

/// Which analysis an upload records.
#[derive(Debug, Clone)]
pub struct Meta {
    /// The project's key on the server: letters, digits, `.`, `_`, `-`.
    pub project: String,
    pub branch: String,
    /// The analyzed commit, as hex.
    pub commit: String,
    /// The project's version, such as `2.3.0`. On the main branch, a new
    /// version starts a new code period (ADR-0011).
    pub version: Option<String>,
    /// The pull request it belongs to, if any (ADR-0021).
    pub pull_request: Option<PullRequest>,
}

/// The pull request an analysis belongs to (ADR-0021). The server keeps its
/// analyses apart from branches, under [`pull_request_branch`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PullRequest {
    pub number: u64,
    /// The branch it merges into.
    pub base: String,
    /// The branch it merges from.
    pub head: String,
    /// The head commit, where GitHub shows checks. CI checks out a merge
    /// commit instead, so this comes from the event, not `--commit`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_sha: Option<String>,
    /// The repository it's in, as `owner/name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
}

/// The highest pull request number accepted; GitHub's are far below it.
pub const MAX_PULL_REQUEST: u64 = 1_000_000_000;

/// Where the server tracks a pull request's analyses and issues: a branch
/// key no git branch can have, since git refuses `:` in ref names.
pub fn pull_request_branch(number: u64) -> String {
    format!("pr:{number}")
}

/// Whether a branch name is one of those keys.
pub fn is_pull_request_branch(branch: &str) -> bool {
    branch
        .strip_prefix("pr:")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// The body of `POST /api/analyses`.
#[derive(Debug, Serialize)]
pub struct Upload {
    pub project: String,
    pub branch: String,
    pub commit: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pull_request: Option<PullRequest>,
    /// The commit's subject line, from git in `root` when it has the
    /// commit; shown with the analysis.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_message: Option<String>,
    /// How long the scan took, when `sonda scan --upload` ran it. Not in
    /// the report, which stays the same for the same inputs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_duration_ms: Option<u64>,
    /// The JSON report, forwarded as written; the server validates it fully.
    pub report: Value,
    pub sources: Vec<Source>,
    /// The repository's CODEOWNERS file, if it has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub codeowners: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Source {
    pub path: String,
    pub content: String,
}

/// Validates `meta` and `report_json`, then reads every file the report
/// lists from under `root`, and the commit's subject from git there.
pub fn prepare(report_json: &[u8], root: &Path, meta: Meta) -> Result<Upload, Error> {
    validate_meta(&meta)?;
    let report: Value = serde_json::from_slice(report_json)
        .map_err(|e| Error::Upload(format!("the report is not valid JSON: {e}")))?;
    let files = listed_files(&report)?;
    let mut budget = MAX_SOURCE_BYTES;
    let mut sources = Vec::with_capacity(files.len());
    for (path, sha256) in files {
        let content = read_source(root, &path, &sha256, &mut budget)?;
        sources.push(Source { path, content });
    }
    tracing::info!(
        files = sources.len(),
        bytes = MAX_SOURCE_BYTES - budget,
        "prepared upload"
    );
    Ok(Upload {
        project: meta.project,
        branch: meta.branch,
        commit_message: commit_message(root, &meta.commit),
        scan_duration_ms: None,
        commit: meta.commit.to_ascii_lowercase(),
        version: meta.version,
        pull_request: meta.pull_request,
        report,
        sources,
        codeowners: read_codeowners(root),
    })
}

/// Best effort: a report scanned outside git, or a commit not in this
/// clone, uploads without a message.
fn commit_message(root: &Path, commit: &str) -> Option<String> {
    match crate::git::commit_subject(root, commit, std::time::Duration::from_secs(10)) {
        Ok(subject) => subject,
        Err(e) => {
            tracing::info!(error = %e, "no commit message to upload");
            None
        }
    }
}

/// A project key: 1-100 letters, digits, `.`, `_` or `-`, not starting
/// with `.` or `-`. The server applies the same rule.
pub fn check_project_key(p: &str) -> Result<(), Error> {
    if p.is_empty()
        || p.len() > 100
        || p.starts_with(['.', '-'])
        || !p
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(Error::InvalidArgument(format!(
            "invalid project key {p:?}: use 1-100 letters, digits, '.', '_' or '-', \
             not starting with '.' or '-'"
        )));
    }
    Ok(())
}

/// Checks project, branch, commit and version; the server applies the same
/// rules.
pub fn validate_meta(meta: &Meta) -> Result<(), Error> {
    let bad = |msg: String| Err(Error::InvalidArgument(msg));
    check_project_key(&meta.project)?;
    check_branch(&meta.branch)?;
    if is_pull_request_branch(&meta.branch) {
        return bad(format!(
            "invalid branch {:?}: names like pr:12 are kept for pull requests; \
             use --pull-request instead",
            meta.branch
        ));
    }
    if let Some(pr) = &meta.pull_request {
        if !(1..=MAX_PULL_REQUEST).contains(&pr.number) {
            return bad(format!("invalid pull request number {}", pr.number));
        }
        check_branch(&pr.base)?;
        check_branch(&pr.head)?;
        if let Some(sha) = &pr.head_sha
            && !(matches!(sha.len(), 40 | 64) && sha.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return bad(format!(
                "invalid pull request head commit {sha:?}: expected 40 or 64 hex digits"
            ));
        }
        if let Some(r) = &pr.repository
            && !is_repository(r)
        {
            return bad(format!("invalid repository {r:?}: expected owner/name"));
        }
    }
    let c = &meta.commit;
    if !(7..=64).contains(&c.len()) || !c.bytes().all(|b| b.is_ascii_hexdigit()) {
        return bad(format!("invalid commit {c:?}: expected 7-64 hex digits"));
    }
    if let Some(v) = &meta.version
        && (v.trim().is_empty() || v.len() > 100 || v.chars().any(char::is_control))
    {
        return bad(format!(
            "invalid version {v:?}: use 1-100 characters, not only spaces, no control characters"
        ));
    }
    Ok(())
}

pub fn check_branch(b: &str) -> Result<(), Error> {
    if b.is_empty() || b.len() > 255 || b.chars().any(char::is_control) {
        return Err(Error::InvalidArgument(format!(
            "invalid branch {b:?}: use 1-255 characters, no control characters"
        )));
    }
    Ok(())
}

/// `owner/name`, as GitHub allows them.
pub fn is_repository(r: &str) -> bool {
    let part = |p: &str| {
        !p.is_empty()
            && p.len() <= 100
            && p.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    };
    matches!(r.split_once('/'), Some((owner, name)) if part(owner) && part(name))
}

/// What GitHub Actions says about the pull request being built.
#[derive(Debug, PartialEq, Eq)]
pub enum CiPullRequest {
    /// Not a `pull_request` event, or not GitHub Actions.
    None,
    PullRequest(PullRequest),
    /// From a fork, whose CI usually has no secrets: not uploaded
    /// (ADR-0021).
    Fork(u64),
}

/// The pull request of a GitHub Actions `pull_request` event, read through
/// `var`, from the event file.
pub fn github_pull_request(var: &dyn Fn(&str) -> Option<String>) -> CiPullRequest {
    if var("GITHUB_ACTIONS").as_deref() != Some("true")
        || var("GITHUB_EVENT_NAME").as_deref() != Some("pull_request")
    {
        return CiPullRequest::None;
    }
    let Some(event) = crate::git::github_event(var) else {
        return CiPullRequest::None;
    };
    let pr = &event["pull_request"];
    let (Some(number), Some(base), Some(head)) = (
        pr["number"].as_u64(),
        pr["base"]["ref"].as_str(),
        pr["head"]["ref"].as_str(),
    ) else {
        return CiPullRequest::None;
    };
    let repository = pr["base"]["repo"]["full_name"].as_str();
    // A deleted fork has no head repository.
    if pr["head"]["repo"]["full_name"].as_str() != repository {
        return CiPullRequest::Fork(number);
    }
    CiPullRequest::PullRequest(PullRequest {
        number,
        base: base.to_string(),
        head: head.to_string(),
        head_sha: pr["head"]["sha"].as_str().map(str::to_string),
        repository: repository.map(str::to_string),
    })
}

/// The `(path, sha256)` of every file in the report, checked.
fn listed_files(report: &Value) -> Result<Vec<(String, Sha256)>, Error> {
    let bad = |msg: &str| Error::Upload(format!("the report {msg}"));
    if report["tool"] != "sonda" {
        return Err(bad("was not written by sonda"));
    }
    match report["report_version"].as_u64() {
        Some(v) if v == u64::from(REPORT_VERSION) => {}
        Some(v) => {
            return Err(bad(&format!(
                "has format version {v}, but this sonda writes version \
                 {REPORT_VERSION}; scan again with this version"
            )));
        }
        None => return Err(bad("has no report_version; scan again with this version")),
    }
    let files = report["files"]
        .as_array()
        .ok_or_else(|| bad("has no files list"))?;
    let mut seen = HashSet::with_capacity(files.len());
    let mut out = Vec::with_capacity(files.len());
    for f in files {
        let path = f["path"]
            .as_str()
            .ok_or_else(|| bad("has a file without a path"))?;
        check_relative_path(path)?;
        if !seen.insert(path) {
            return Err(bad(&format!("lists {path:?} twice")));
        }
        let sha256 = f["sha256"]
            .as_str()
            .and_then(parse_sha256)
            .ok_or_else(|| bad(&format!("has no valid sha256 for {path:?}")))?;
        out.push((path.to_string(), sha256));
    }
    Ok(out)
}

/// Accepts only what the scanner writes: `/`-separated, relative, with no
/// empty, `.` or `..` components. Anything else could name a file outside
/// the root (`../../.ssh/id_rsa`, `/etc/passwd`, `C:\...`).
pub fn check_relative_path(path: &str) -> Result<(), Error> {
    let ok = !path.is_empty()
        && !path.contains(['\\', ':', '\0'])
        && path
            .split('/')
            .all(|c| !c.is_empty() && c != "." && c != "..");
    if ok {
        Ok(())
    } else {
        Err(Error::Upload(format!(
            "the report lists an unsafe path {path:?}"
        )))
    }
}

/// Lowercase or uppercase hex, exactly 64 digits.
pub fn parse_sha256(hex: &str) -> Option<Sha256> {
    // The digit check matters: `from_str_radix` alone accepts "+f".
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (byte, pair) in out.iter_mut().zip(hex.as_bytes().chunks(2)) {
        let pair = std::str::from_utf8(pair).ok()?;
        *byte = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(crate::model::Digest(out))
}

/// Reads `root/path`, refusing symlinks anywhere on the way (the scanner
/// never follows them, so a listed file never needs one) and anything that
/// does not hash to `expected`.
fn read_source(
    root: &Path,
    path: &str,
    expected: &Sha256,
    budget: &mut u64,
) -> Result<String, Error> {
    let (full, file) = open_in_root(root, path)?;
    let io = |source| Error::Io {
        path: full.clone(),
        source,
    };
    let mut bytes = Vec::new();
    file.take(budget.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(io)?;
    let len = bytes.len() as u64;
    if len > *budget {
        return Err(Error::Upload(format!(
            "the sources exceed {} MiB",
            MAX_SOURCE_BYTES >> 20
        )));
    }
    *budget -= len;
    let actual = crate::model::Digest(sha2::Sha256::digest(&bytes).into());
    if actual != *expected {
        return Err(Error::Upload(format!(
            "{path} changed since the scan; scan again before uploading"
        )));
    }
    // Cannot fail in practice: the scanner only hashes files it could decode.
    crate::scanner::decode_source(path, bytes)
        .ok_or_else(|| Error::Upload(format!("{path}: not valid UTF-8")))
}

/// Opens `root/path` for reading, refusing a symlink anywhere on the way
/// (the scanner never follows them, so a listed file never needs one) and
/// anything but a regular file.
fn open_in_root(root: &Path, path: &str) -> Result<(PathBuf, std::fs::File), Error> {
    let mut full = PathBuf::from(root);
    for component in path.split('/') {
        full.push(component);
        let meta = std::fs::symlink_metadata(&full).map_err(|source| Error::Io {
            path: full.clone(),
            source,
        })?;
        if meta.file_type().is_symlink() {
            return Err(Error::Upload(format!(
                "{path}: refusing to follow a symlink"
            )));
        }
    }
    let file = open_nonblocking(&full).map_err(|source| Error::Io {
        path: full.clone(),
        source,
    })?;
    let regular = file
        .metadata()
        .map(|m| m.is_file())
        .map_err(|source| Error::Io {
            path: full.clone(),
            source,
        })?;
    if !regular {
        return Err(Error::Upload(format!("{path}: not a regular file")));
    }
    Ok((full, file))
}

/// The repository's CODEOWNERS file, from the first of GitHub's locations
/// that has one. Like sources, it is read without following symlinks and
/// capped. A missing, unreadable or non-UTF-8 file is simply left out: owners
/// are a convenience, not part of the analysis.
fn read_codeowners(root: &Path) -> Option<String> {
    let path = crate::codeowners::LOCATIONS
        .iter()
        .find(|p| std::fs::symlink_metadata(root.join(p)).is_ok())?;
    let read = || -> Result<Option<String>, Error> {
        let (full, file) = open_in_root(root, path)?;
        let mut bytes = Vec::new();
        file.take(crate::codeowners::MAX_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|source| Error::Io { path: full, source })?;
        Ok((bytes.len() as u64 <= crate::codeowners::MAX_BYTES)
            .then(|| String::from_utf8(bytes).ok())
            .flatten())
    };
    match read() {
        Ok(Some(text)) => Some(text),
        Ok(None) => {
            tracing::warn!(path = %path, "CODEOWNERS is too large or not UTF-8; owners left out");
            None
        }
        Err(e) => {
            tracing::warn!(path = %path, error = %e, "CODEOWNERS not read; owners left out");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> Meta {
        Meta {
            project: "payments".into(),
            branch: "main".into(),
            commit: "ABCDEF1".into(),
            version: None,
            pull_request: None,
        }
    }

    fn pull_request() -> PullRequest {
        PullRequest {
            number: 12,
            base: "main".into(),
            head: "fix/login".into(),
            head_sha: Some("a".repeat(40)),
            repository: Some("acme/shop".into()),
        }
    }

    #[test]
    fn pull_request_metadata_is_checked_and_its_branch_key_is_reserved() {
        let with = |pr: PullRequest| Meta {
            pull_request: Some(pr),
            ..meta()
        };
        assert!(validate_meta(&with(pull_request())).is_ok());
        for bad in [
            PullRequest {
                number: 0,
                ..pull_request()
            },
            PullRequest {
                base: String::new(),
                ..pull_request()
            },
            PullRequest {
                head_sha: Some("abc".into()),
                ..pull_request()
            },
            PullRequest {
                repository: Some("shop".into()),
                ..pull_request()
            },
            PullRequest {
                repository: Some("acme/shop/x".into()),
                ..pull_request()
            },
        ] {
            assert!(validate_meta(&with(bad.clone())).is_err(), "{bad:?}");
        }
        // Git refuses ':' in branch names, so only these are taken.
        assert_eq!(pull_request_branch(12), "pr:12");
        for (branch, ok) in [
            ("pr:12", false),
            ("pr:", true),
            ("pr:1a", true),
            ("pr-12", true),
        ] {
            let m = Meta {
                branch: branch.into(),
                ..meta()
            };
            assert_eq!(validate_meta(&m).is_ok(), ok, "{branch}");
        }
    }

    #[test]
    fn github_pull_request_events_are_read_and_forks_recognized() {
        let dir = tempfile::tempdir().unwrap();
        let event = |head_repo: &str| {
            let path = dir
                .path()
                .join(format!("{}.json", head_repo.replace('/', "_")));
            std::fs::write(
                &path,
                serde_json::json!({"pull_request": {
                    "number": 12,
                    "base": {"ref": "main", "repo": {"full_name": "acme/shop"}},
                    "head": {"ref": "fix/login", "sha": "a".repeat(40), "repo": {"full_name": head_repo}},
                }})
                .to_string(),
            )
            .unwrap();
            path.to_string_lossy().into_owned()
        };
        let (own, fork) = (event("acme/shop"), event("someone/shop"));
        let env = |name: &'static str, path: &str| {
            let path = path.to_string();
            move |v: &str| match v {
                "GITHUB_ACTIONS" => Some("true".into()),
                "GITHUB_EVENT_NAME" => Some(name.into()),
                "GITHUB_EVENT_PATH" => Some(path.clone()),
                _ => None,
            }
        };
        assert_eq!(
            github_pull_request(&env("pull_request", &own)),
            CiPullRequest::PullRequest(pull_request())
        );
        assert_eq!(
            github_pull_request(&env("pull_request", &fork)),
            CiPullRequest::Fork(12)
        );
        assert_eq!(github_pull_request(&env("push", &own)), CiPullRequest::None);
        assert_eq!(github_pull_request(&|_| None), CiPullRequest::None);
    }

    fn report_for(files: &[(&str, &[u8])]) -> Vec<u8> {
        let files: Vec<Value> = files
            .iter()
            .map(|(path, content)| {
                let sha = crate::model::Digest::<32>(sha2::Sha256::digest(content).into());
                serde_json::json!({ "path": path, "sha256": sha.to_string() })
            })
            .collect();
        serde_json::to_vec(&serde_json::json!({
            "tool": "sonda",
            "report_version": REPORT_VERSION,
            "files": files,
        }))
        .unwrap()
    }

    #[test]
    fn reads_listed_sources_that_match_their_hash() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/a.js"), "var a;\n").unwrap();
        let report = report_for(&[("src/a.js", b"var a;\n")]);
        let up = prepare(&report, dir.path(), meta()).unwrap();
        assert_eq!(up.commit, "abcdef1");
        assert_eq!(up.sources.len(), 1);
        assert_eq!(up.sources[0].path, "src/a.js");
        assert_eq!(up.sources[0].content, "var a;\n");
    }

    #[test]
    fn codeowners_come_along_from_githubs_locations() {
        let dir = tempfile::tempdir().unwrap();
        let report = report_for(&[]);
        assert_eq!(
            prepare(&report, dir.path(), meta()).unwrap().codeowners,
            None
        );
        std::fs::write(dir.path().join("CODEOWNERS"), "* @root\n").unwrap();
        std::fs::create_dir(dir.path().join(".github")).unwrap();
        std::fs::write(dir.path().join(".github/CODEOWNERS"), "* @github\n").unwrap();
        // .github/ is looked at first, as GitHub does.
        let up = prepare(&report, dir.path(), meta()).unwrap();
        assert_eq!(up.codeowners.as_deref(), Some("* @github\n"));
        // Too large: left out, the upload still works.
        std::fs::write(dir.path().join(".github/CODEOWNERS"), "x".repeat(200_000)).unwrap();
        assert_eq!(
            prepare(&report, dir.path(), meta()).unwrap().codeowners,
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_codeowners_is_not_followed() {
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), "* @leaked\n").unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path().join("secret"), dir.path().join("CODEOWNERS"))
            .unwrap();
        assert_eq!(
            prepare(&report_for(&[]), dir.path(), meta())
                .unwrap()
                .codeowners,
            None
        );
    }

    #[test]
    fn a_file_changed_since_the_scan_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.js"), "var b;\n").unwrap();
        let report = report_for(&[("a.js", b"var a;\n")]);
        let err = prepare(&report, dir.path(), meta()).unwrap_err();
        assert!(err.to_string().contains("changed since the scan"), "{err}");
    }

    #[test]
    fn paths_that_could_leave_the_root_are_refused() {
        for path in [
            "../secret",
            "a/../../secret",
            "/etc/passwd",
            "C:/x",
            "a\\..\\b",
            "./a",
            "a//b",
            "",
        ] {
            let report = report_for(&[(path, b"")]);
            let err = prepare(&report, Path::new("."), meta()).unwrap_err();
            assert!(err.to_string().contains("unsafe path"), "{path:?}: {err}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_refused_even_with_a_matching_hash() {
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), "token\n").unwrap();
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("link")).unwrap();
        let report = report_for(&[("link/secret", b"token\n")]);
        let err = prepare(&report, dir.path(), meta()).unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err}");
    }

    #[test]
    fn reports_from_other_tools_or_versions_are_refused() {
        let other = br#"{"tool":"x","report_version":1,"files":[]}"#;
        assert!(prepare(other, Path::new("."), meta()).is_err());
        let old = br#"{"tool":"sonda","files":[]}"#;
        let err = prepare(old, Path::new("."), meta()).unwrap_err();
        assert!(err.to_string().contains("report_version"), "{err}");
        let dup = report_for(&[("a.js", b""), ("a.js", b"")]);
        assert!(
            prepare(&dup, Path::new("."), meta())
                .unwrap_err()
                .to_string()
                .contains("twice")
        );
    }

    #[test]
    fn sha256_must_be_64_hex_digits() {
        let ok = "ab".repeat(32);
        assert!(parse_sha256(&ok).is_some());
        assert!(parse_sha256(&ok.to_uppercase()).is_some());
        for bad in [
            &ok[2..],
            &format!("+f{}", &ok[2..]),
            &format!("zz{}", &ok[2..]),
        ] {
            assert!(parse_sha256(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn metadata_is_validated() {
        let with = |f: fn(&mut Meta)| {
            let mut m = meta();
            f(&mut m);
            prepare(&report_for(&[]), Path::new("."), m)
        };
        assert!(with(|_| {}).is_ok());
        assert!(with(|m| m.project = "-x".into()).is_err());
        assert!(with(|m| m.project = "a b".into()).is_err());
        assert!(with(|m| m.branch = "main\u{1b}[2J".into()).is_err());
        assert!(with(|m| m.branch = String::new()).is_err());
        assert!(with(|m| m.commit = "xyz1234".into()).is_err());
        assert!(with(|m| m.commit = "abc".into()).is_err());
        assert!(with(|m| m.version = Some("2.3.0-rc.1".into())).is_ok());
        assert!(with(|m| m.version = Some("  ".into())).is_err());
        assert!(with(|m| m.version = Some("1\n2".into())).is_err());
        assert!(with(|m| m.version = Some("9".repeat(101))).is_err());
    }
}
