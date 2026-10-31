//! Infrastructure: reads the merge base of a reference branch from git.
//!
//! Security: the analyzed repository is untrusted, `.git/config` included.
//! Git commands that read the working tree or refresh the index (`diff`,
//! `status`, `ls-files`) can run programs named in that config: fsmonitor,
//! clean filters, textconv, external diff. sonda therefore only asks git to
//! read the object database (`rev-parse`, `merge-base`, `ls-tree`, `cat-file`)
//! and diffs the working-tree files itself (see docs/adr/0002).

use crate::error::Error;
use crate::newcode::{Basis, Changed, NewCode, changed_lines};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Computes new code against the merge base of HEAD and `reference`.
/// `files` yields each scanned file's root-relative path and current content
/// (`None` when unreadable or too large; such files are skipped). Base-branch
/// blobs larger than `max_bytes` count as entirely changed. Each git process
/// is killed if it runs longer than `timeout`.
pub(crate) fn new_code<'a>(
    root: &Path,
    reference: &str,
    max_bytes: u64,
    timeout: Duration,
    files: impl IntoIterator<Item = (&'a str, Option<Vec<u8>>)>,
) -> Result<NewCode, Error> {
    let blobs = base_blobs(root, reference, timeout)?;
    let mut cat = CatFile::start(git_command(root).args(["cat-file", "--batch"]), timeout)?;
    let mut changed = HashMap::new();
    for (path, content) in files {
        let Some(new) = content.and_then(|c| String::from_utf8(c).ok()) else {
            continue;
        };
        let old = match blobs.get(path) {
            Some(oid) => cat.blob(oid, max_bytes)?,
            None => None,
        };
        let Some(old) = old.and_then(|o| String::from_utf8(o).ok()) else {
            changed.insert(path.to_string(), Changed::All);
            continue;
        };
        if old != new {
            changed.insert(path.to_string(), Changed::Lines(changed_lines(&old, &new)));
        }
    }
    cat.finish()?;
    Ok(NewCode::Changes {
        reference: reference.to_string(),
        files: changed,
    })
}

/// The files under `root` at the merge base of HEAD and `reference`, by
/// root-relative path, as blob ids.
fn base_blobs(
    root: &Path,
    reference: &str,
    timeout: Duration,
) -> Result<HashMap<String, String>, Error> {
    validate_ref(reference)?;
    let prefix = git(root, &["rev-parse", "--show-prefix"], timeout)?;
    let base = git(
        root,
        &["merge-base", "--end-of-options", "HEAD", reference],
        timeout,
    )?;
    let tree = git(
        root,
        &[
            "ls-tree",
            "-r",
            "-z",
            "--full-tree",
            "--end-of-options",
            base.trim(),
        ],
        timeout,
    )?;
    Ok(parse_ls_tree(&tree, prefix.trim_end_matches('\n')))
}

/// The contents of `paths` (root-relative) at the merge base of HEAD and
/// `reference`, as `new_code` compares against: the lockfiles a change
/// started from. Paths missing there, not UTF-8 or larger than `max_bytes`
/// are left out.
pub(crate) fn files_at(
    root: &Path,
    reference: &str,
    paths: &[&str],
    max_bytes: u64,
    timeout: Duration,
) -> Result<HashMap<String, String>, Error> {
    let blobs = base_blobs(root, reference, timeout)?;
    let mut cat = CatFile::start(git_command(root).args(["cat-file", "--batch"]), timeout)?;
    let mut out = HashMap::new();
    for path in paths {
        if let Some(oid) = blobs.get(*path)
            && let Some(text) = cat
                .blob(oid, max_bytes)?
                .and_then(|b| String::from_utf8(b).ok())
        {
            out.insert(path.to_string(), text);
        }
    }
    cat.finish()?;
    Ok(out)
}

/// What `auto` found to compare with (ADR-0010).
pub(crate) enum Auto {
    /// A reference for [`new_code`], and how it was chosen.
    Found(String, Basis),
    /// Nothing to compare with, and why.
    Nothing(String),
}

/// What a CI run says about the change it builds. GitHub Actions only, for
/// now.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Ci {
    /// A pull request's base branch (`GITHUB_BASE_REF`).
    pub(crate) pr_base: Option<String>,
    /// A push's previous head: the event's `before` commit.
    pub(crate) push_before: Option<String>,
}

/// The event file is a few kilobytes; this bounds a hostile one.
const MAX_EVENT_BYTES: u64 = 1 << 20;

impl Ci {
    /// From GitHub Actions' variables, read through `var`.
    pub(crate) fn from_env(var: &dyn Fn(&str) -> Option<String>) -> Ci {
        if var("GITHUB_ACTIONS").as_deref() != Some("true") {
            return Ci::default();
        }
        let pr_base = var("GITHUB_BASE_REF").filter(|b| validate_ref(b).is_ok());
        let push_before = (var("GITHUB_EVENT_NAME").as_deref() == Some("push"))
            .then(|| var("GITHUB_EVENT_PATH"))
            .flatten()
            .and_then(|path| {
                let mut text = String::new();
                std::fs::File::open(path)
                    .ok()?
                    .take(MAX_EVENT_BYTES)
                    .read_to_string(&mut text)
                    .ok()?;
                let event: serde_json::Value = serde_json::from_str(&text).ok()?;
                event["before"].as_str().map(str::to_string)
            })
            // All zeros: the push created the branch, so there's no before.
            .filter(|sha| {
                (sha.len() == 40 || sha.len() == 64)
                    && sha.bytes().all(|b| b.is_ascii_hexdigit())
                    && !sha.bytes().all(|b| b == b'0')
            });
        Ci {
            pr_base,
            push_before,
        }
    }
}

/// Picks the new-code reference when none is given (ADR-0010), first match
/// wins: a pull request's base branch; a push's previous head; the merge
/// base with the default branch, on a branch that has diverged from it;
/// otherwise HEAD, so uncommitted changes are new code. Reads refs and
/// commits only (ADR-0002).
pub(crate) fn auto_reference(root: &Path, ci: &Ci, timeout: Duration) -> Result<Auto, Error> {
    let Some(head) = git_ok(
        root,
        &["rev-parse", "--verify", "-q", "HEAD^{commit}"],
        timeout,
    )?
    else {
        return Ok(Auto::Nothing(
            "not a git repository with commits, or git is not installed".into(),
        ));
    };
    let head = head.trim();
    let exists = |reference: &str| -> Result<bool, Error> {
        let commit = format!("{reference}^{{commit}}");
        Ok(git_ok(root, &["rev-parse", "--verify", "-q", &commit], timeout)?.is_some())
    };
    if let Some(base) = &ci.pr_base {
        // actions/checkout fetches it as a remote branch.
        for candidate in [format!("origin/{base}"), base.clone()] {
            if exists(&candidate)? {
                return Ok(Auto::Found(candidate, Basis::PullRequest(base.clone())));
            }
        }
    }
    if let Some(before) = &ci.push_before
        && exists(before)?
    {
        return Ok(Auto::Found(before.clone(), Basis::Push(before.clone())));
    }
    if let Some(branch) = default_branch(root, timeout)?
        && let Some(base) = git_ok(
            root,
            &["merge-base", "--end-of-options", "HEAD", &branch],
            timeout,
        )?
        && base.trim() != head
    {
        return Ok(Auto::Found(branch.clone(), Basis::DefaultBranch(branch)));
    }
    Ok(Auto::Found("HEAD".into(), Basis::Uncommitted))
}

/// The branch others merge into: what `origin/HEAD` points at, else
/// `origin/main`, `origin/master`, `main` or `master`, whichever exists.
fn default_branch(root: &Path, timeout: Duration) -> Result<Option<String>, Error> {
    if let Some(r) = git_ok(
        root,
        &["symbolic-ref", "-q", "--short", "refs/remotes/origin/HEAD"],
        timeout,
    )? {
        let r = r.trim().to_string();
        if validate_ref(&r).is_ok() {
            return Ok(Some(r));
        }
    }
    for candidate in ["origin/main", "origin/master", "main", "master"] {
        let full = if candidate.starts_with("origin/") {
            format!("refs/remotes/{candidate}")
        } else {
            format!("refs/heads/{candidate}")
        };
        if git_ok(root, &["rev-parse", "--verify", "-q", &full], timeout)?.is_some() {
            return Ok(Some(candidate.to_string()));
        }
    }
    Ok(None)
}

/// Like [`git`], but a failing command (an unknown ref, not a repository)
/// is `None`; only a timeout or a missing git is an error.
fn git_ok(dir: &Path, args: &[&str], timeout: Duration) -> Result<Option<String>, Error> {
    tracing::debug!(?args, "running git");
    let out = match run_with_timeout(git_command(dir).args(args), timeout) {
        Ok(out) => out,
        // No git at all is like no repository: nothing to compare with.
        Err(Error::Git(e)) if e.starts_with("failed to run git") => return Ok(None),
        Err(e) => return Err(e),
    };
    Ok(out
        .status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned()))
}

/// Rejects anything git could read as an option. `--end-of-options` is also
/// passed; this check gives a clear error instead of a confusing git one.
fn validate_ref(reference: &str) -> Result<(), Error> {
    let ok = !reference.is_empty()
        && reference.len() <= 256
        && !reference.starts_with('-')
        && !reference
            .chars()
            .any(|c| c.is_control() || c.is_whitespace());
    if ok {
        Ok(())
    } else {
        Err(Error::InvalidArgument(format!(
            "invalid --new-code reference '{}'",
            reference.escape_debug()
        )))
    }
}

/// Parses `ls-tree -r -z --full-tree` into scan-root-relative path -> blob id,
/// keeping regular files under `prefix` (the scan root within the repository).
fn parse_ls_tree(out: &str, prefix: &str) -> HashMap<String, String> {
    out.split('\0')
        .filter_map(|entry| {
            let (meta, path) = entry.split_once('\t')?;
            let mut meta = meta.split(' ');
            let (mode, kind, oid) = (meta.next()?, meta.next()?, meta.next()?);
            let regular = kind == "blob" && matches!(mode, "100644" | "100755");
            let rel = path.strip_prefix(prefix)?;
            (regular && oid.bytes().all(|b| b.is_ascii_hexdigit()))
                .then(|| (rel.to_string(), oid.to_string()))
        })
        .collect()
}

fn git_command(dir: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(dir)
        // Defense in depth: none of our commands should consult these.
        .args(["-c", "core.fsmonitor=false"])
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null());
    cmd
}

fn git(dir: &Path, args: &[&str], timeout: Duration) -> Result<String, Error> {
    tracing::debug!(?args, "running git");
    let out = run_with_timeout(git_command(dir).args(args), timeout)?;
    if !out.status.success() {
        return Err(Error::Git(format!(
            "{} failed: {}",
            args.first().unwrap_or(&""),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Runs `cmd` to completion, killing it after `timeout`.
fn run_with_timeout(cmd: &mut Command, timeout: Duration) -> Result<Output, Error> {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::Git(format!("failed to run git: {e}")))?;
    let (Some(mut stdout), Some(mut stderr)) = (child.stdout.take(), child.stderr.take()) else {
        return Err(Error::Internal("git pipes missing".into()));
    };
    let watchdog = Watchdog::start(child, timeout);
    // Drain stderr concurrently: if either pipe fills up, git blocks forever.
    let stderr_reader = thread::spawn(move || {
        let mut buf = Vec::new();
        stderr.read_to_end(&mut buf).map(|_| buf)
    });
    let mut out = Vec::new();
    let read = stdout.read_to_end(&mut out);
    let err = stderr_reader
        .join()
        .map_err(|_| Error::Internal("git stderr reader panicked".into()))?;
    // A timeout explains any read failure, so check it first.
    let status = watchdog.finish()?;
    read.map_err(|e| Error::Git(format!("reading git output: {e}")))?;
    let err = err.map_err(|e| Error::Git(format!("reading git errors: {e}")))?;
    Ok(Output {
        status,
        stdout: out,
        stderr: err,
    })
}

/// Kills a process that outlives its deadline, so a pathological repository
/// cannot hang the scan. Reads from the killed process's pipes then end, and
/// `finish` reports the timeout.
struct Watchdog {
    done: mpsc::Sender<()>,
    killed: Arc<AtomicBool>,
    waiter: JoinHandle<std::io::Result<ExitStatus>>,
    timeout: Duration,
}

impl Watchdog {
    fn start(mut child: Child, timeout: Duration) -> Watchdog {
        let (done, finished) = mpsc::channel::<()>();
        let killed = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&killed);
        let waiter = thread::spawn(move || {
            if let Err(RecvTimeoutError::Timeout) = finished.recv_timeout(timeout) {
                flag.store(true, Ordering::SeqCst);
                // Fails only if the process already exited, which is fine.
                let _ = child.kill();
            }
            child.wait()
        });
        Watchdog {
            done,
            killed,
            waiter,
            timeout,
        }
    }

    fn timed_out(&self) -> bool {
        self.killed.load(Ordering::SeqCst)
    }

    fn timeout_error(&self) -> Error {
        Error::Git(format!(
            "timed out after {:?} (raise scan.git_timeout_secs for very large repositories)",
            self.timeout
        ))
    }

    /// Waits for the process to exit; call once its output is consumed.
    fn finish(self) -> Result<ExitStatus, Error> {
        // Ignored error: the waiter stopped listening because it timed out.
        let _ = self.done.send(());
        let timeout_error = self.timeout_error();
        let status = self
            .waiter
            .join()
            .map_err(|_| Error::Internal("git watchdog panicked".into()))?;
        // The waiter has exited, so the flag is final.
        if self.killed.load(Ordering::SeqCst) {
            return Err(timeout_error);
        }
        status.map_err(|e| Error::Git(format!("waiting for git: {e}")))
    }
}

/// A `git cat-file --batch` process: one request/response per object.
struct CatFile {
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    watchdog: Watchdog,
}

impl CatFile {
    fn start(cmd: &mut Command, timeout: Duration) -> Result<CatFile, Error> {
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| Error::Git(format!("failed to run git cat-file: {e}")))?;
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            return Err(Error::Internal("git cat-file pipes missing".into()));
        };
        Ok(CatFile {
            stdin,
            stdout: BufReader::new(stdout),
            watchdog: Watchdog::start(child, timeout),
        })
    }

    /// An error for a failed read or write, explained by the timeout when
    /// the watchdog killed the process.
    fn fail(&self, what: impl std::fmt::Display) -> Error {
        if self.watchdog.timed_out() {
            self.watchdog.timeout_error()
        } else {
            Error::Git(format!("git cat-file: {what}"))
        }
    }

    /// The blob's bytes, or `None` if it is missing or larger than `max_bytes`.
    fn blob(&mut self, oid: &str, max_bytes: u64) -> Result<Option<Vec<u8>>, Error> {
        if let Err(e) = writeln!(self.stdin, "{oid}").and_then(|()| self.stdin.flush()) {
            return Err(self.fail(e));
        }
        let mut header = String::new();
        match self.stdout.read_line(&mut header) {
            Ok(0) => return Err(self.fail("exited unexpectedly")),
            Ok(_) => {}
            Err(e) => return Err(self.fail(e)),
        }
        // "<oid> <type> <size>" or "<oid> missing"
        let mut parts = header.split_whitespace().skip(1);
        let (Some(kind), Some(size)) = (parts.next(), parts.next()) else {
            return Ok(None);
        };
        let Ok(size) = size.parse::<u64>() else {
            return Err(self.fail(format!("bad header {header:?}")));
        };
        // +1: every object is followed by a newline.
        let mut body = (&mut self.stdout).take(size.saturating_add(1));
        if kind != "blob" || size > max_bytes {
            let skipped = std::io::copy(&mut body, &mut std::io::sink());
            return match skipped {
                Ok(n) if n == size.saturating_add(1) => Ok(None),
                Ok(_) => Err(self.fail("truncated output")),
                Err(e) => Err(self.fail(e)),
            };
        }
        let mut buf = Vec::new();
        if let Err(e) = body.read_to_end(&mut buf) {
            return Err(self.fail(e));
        }
        if buf.pop() != Some(b'\n') || buf.len() as u64 != size {
            return Err(self.fail("truncated output"));
        }
        Ok(Some(buf))
    }

    fn finish(self) -> Result<(), Error> {
        drop(self.stdin); // EOF ends the batch
        self.watchdog.finish().map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TIMEOUT: Duration = Duration::from_secs(30);
    use crate::newcode::NewCode;
    use proptest::prelude::*;
    use std::path::PathBuf;

    struct Repo {
        _dir: tempfile::TempDir,
        root: PathBuf,
    }

    impl Repo {
        /// A repo with `a.py` committed on `main`, then a `feature` branch.
        fn new() -> Repo {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().to_path_buf();
            let repo = Repo { _dir: dir, root };
            repo.git(&["init", "-q", "-b", "main"]);
            repo.git(&["config", "user.email", "t@example.com"]);
            repo.git(&["config", "user.name", "t"]);
            repo.write("a.py", "a = 1\nb = 2\n");
            repo.git(&["add", "."]);
            repo.git(&["commit", "-qm", "init"]);
            repo.git(&["checkout", "-qb", "feature"]);
            repo
        }

        fn git(&self, args: &[&str]) {
            git(&self.root, args, TIMEOUT).unwrap();
        }

        fn write(&self, path: &str, content: &str) {
            let full = self.root.join(path);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, content).unwrap();
        }

        fn new_code(&self, root: &Path, files: &[&str]) -> Result<NewCode, Error> {
            let contents = files.iter().map(|f| (*f, std::fs::read(root.join(f)).ok()));
            new_code(root, "main", 1 << 20, TIMEOUT, contents)
        }
    }

    #[test]
    fn modified_and_untracked_lines_are_new() {
        let repo = Repo::new();
        repo.write("a.py", "a = 1\nb = 3\nc = 4\n");
        repo.write("new.py", "x = 1\n");
        let nc = repo.new_code(&repo.root, &["a.py", "new.py"]).unwrap();
        assert!(!nc.is_new("a.py", 1));
        assert!(nc.is_new("a.py", 2));
        assert!(nc.is_new("a.py", 3));
        assert!(nc.is_new("new.py", 1));
    }

    #[test]
    fn committed_changes_on_the_branch_are_new() {
        let repo = Repo::new();
        repo.write("a.py", "a = 1\nb = 2\nc = 3\n");
        repo.git(&["commit", "-qam", "more"]);
        let nc = repo.new_code(&repo.root, &["a.py"]).unwrap();
        assert!(!nc.is_new("a.py", 2));
        assert!(nc.is_new("a.py", 3));
    }

    #[test]
    fn scan_root_may_be_a_subdirectory() {
        let repo = Repo::new();
        repo.write("sub/m.py", "x = 1\n");
        repo.git(&["add", "."]);
        repo.git(&["commit", "-qm", "sub"]);
        repo.git(&["checkout", "-q", "main"]);
        repo.git(&["merge", "-q", "feature"]);
        repo.git(&["checkout", "-q", "feature"]);
        repo.write("sub/m.py", "x = 1\ny = 2\n");
        let nc = repo.new_code(&repo.root.join("sub"), &["m.py"]).unwrap();
        assert!(!nc.is_new("m.py", 1));
        assert!(nc.is_new("m.py", 2));
    }

    #[test]
    fn rejects_option_like_and_unknown_refs() {
        let repo = Repo::new();
        for bad in ["-x", "--output=/tmp/pwned", "", "main\nHEAD", "a b"] {
            let err = new_code(&repo.root, bad, 1024, TIMEOUT, []).unwrap_err();
            assert!(
                err.to_string().contains("invalid --new-code"),
                "{bad:?}: {err}"
            );
        }
        assert!(new_code(&repo.root, "no-such-branch", 1024, TIMEOUT, []).is_err());
    }

    fn auto_with(root: &Path, ci: &Ci) -> Auto {
        auto_reference(root, ci, TIMEOUT).unwrap()
    }

    fn auto(root: &Path) -> Auto {
        auto_with(root, &Ci::default())
    }

    fn found(a: Auto) -> (String, Basis) {
        match a {
            Auto::Found(r, b) => (r, b),
            Auto::Nothing(why) => panic!("nothing found: {why}"),
        }
    }

    #[test]
    fn auto_compares_a_branch_with_its_default_branch() {
        let repo = Repo::new();
        repo.write("a.py", "a = 1\nb = 2\nc = 3\n");
        repo.git(&["commit", "-qam", "on feature"]);
        let (reference, basis) = found(auto(&repo.root));
        assert_eq!(reference, "main");
        assert_eq!(basis, Basis::DefaultBranch("main".into()));
        // origin/HEAD, when there is one, names the default branch.
        repo.git(&["update-ref", "refs/remotes/origin/trunk", "main"]);
        repo.git(&[
            "symbolic-ref",
            "refs/remotes/origin/HEAD",
            "refs/remotes/origin/trunk",
        ]);
        assert_eq!(found(auto(&repo.root)).0, "origin/trunk");
    }

    #[test]
    fn auto_on_the_default_branch_judges_uncommitted_changes() {
        let repo = Repo::new();
        repo.git(&["checkout", "-q", "main"]);
        assert_eq!(found(auto(&repo.root)), ("HEAD".into(), Basis::Uncommitted));
        repo.write("a.py", "a = 1\nb = 3\n");
        let contents = [("a.py", std::fs::read(repo.root.join("a.py")).ok())];
        let nc = new_code(&repo.root, "HEAD", 1 << 20, TIMEOUT, contents).unwrap();
        assert!(!nc.is_new("a.py", 1));
        assert!(nc.is_new("a.py", 2));
    }

    #[test]
    fn auto_uses_a_pull_request_base_and_a_push_range_first() {
        let repo = Repo::new();
        repo.git(&["checkout", "-q", "main"]);
        let first = git(&repo.root, &["rev-parse", "HEAD"], TIMEOUT).unwrap();
        repo.write("b.py", "x = 1\n");
        repo.git(&["add", "."]);
        repo.git(&["commit", "-qm", "pushed"]);

        let pr = Ci {
            pr_base: Some("main".into()),
            push_before: None,
        };
        assert_eq!(
            found(auto_with(&repo.root, &pr)),
            ("main".into(), Basis::PullRequest("main".into()))
        );
        // As actions/checkout fetches it: a remote branch, preferred.
        repo.git(&["update-ref", "refs/remotes/origin/main", "main"]);
        assert_eq!(found(auto_with(&repo.root, &pr)).0, "origin/main");

        let push = Ci {
            pr_base: None,
            push_before: Some(first.trim().into()),
        };
        assert_eq!(
            found(auto_with(&repo.root, &push)),
            (first.trim().into(), Basis::Push(first.trim().into()))
        );
        // A base or a before that isn't in the clone falls through.
        let unknown = Ci {
            pr_base: Some("release".into()),
            push_before: Some("1".repeat(40)),
        };
        assert_eq!(found(auto_with(&repo.root, &unknown)).1, Basis::Uncommitted);
    }

    #[test]
    fn ci_context_comes_from_github_actions_only() {
        let dir = tempfile::tempdir().unwrap();
        let event = dir.path().join("event.json");
        let sha = "a".repeat(40);
        std::fs::write(
            &event,
            format!("{{\"before\": \"{sha}\", \"after\": \"b\"}}"),
        )
        .unwrap();
        let path = event.to_str().unwrap().to_string();
        let env = |pairs: &[(&str, &str)]| {
            let pairs: Vec<(String, String)> = pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            Ci::from_env(&move |name: &str| {
                pairs
                    .iter()
                    .find(|(k, _)| k == name)
                    .map(|(_, v)| v.clone())
            })
        };
        assert_eq!(
            env(&[("GITHUB_BASE_REF", "main")]),
            Ci::default(),
            "not in Actions"
        );
        assert_eq!(
            env(&[("GITHUB_ACTIONS", "true"), ("GITHUB_BASE_REF", "main")])
                .pr_base
                .as_deref(),
            Some("main")
        );
        let push = [
            ("GITHUB_ACTIONS", "true"),
            ("GITHUB_EVENT_NAME", "push"),
            ("GITHUB_EVENT_PATH", path.as_str()),
        ];
        assert_eq!(env(&push).push_before, Some(sha));
        // A new branch's push has no before; nor does another event.
        std::fs::write(&event, format!("{{\"before\": \"{}\"}}", "0".repeat(40))).unwrap();
        assert_eq!(env(&push).push_before, None);
        assert_eq!(
            env(&[
                ("GITHUB_ACTIONS", "true"),
                ("GITHUB_BASE_REF", "--upload-pack=x")
            ])
            .pr_base,
            None,
            "option-like refs are refused"
        );
    }

    #[test]
    fn auto_outside_a_repository_finds_nothing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(auto(dir.path()), Auto::Nothing(_)));
    }

    /// Regression: `git diff` against the working tree used to run the
    /// repository's own fsmonitor, clean filter, textconv and external diff.
    #[cfg(unix)]
    #[test]
    fn repository_config_cannot_run_programs() {
        use std::os::unix::fs::PermissionsExt;
        let repo = Repo::new();
        let marker = repo.root.join("PWNED");
        let script = repo.root.join("evil.sh");
        std::fs::write(
            &script,
            format!("#!/bin/sh\ntouch '{}'\ncat\n", marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let s = script.to_str().unwrap();
        for (key, value) in [
            ("core.fsmonitor", s),
            ("filter.evil.clean", s),
            ("filter.evil.smudge", s),
            ("diff.evil.textconv", s),
            ("diff.external", s),
        ] {
            repo.git(&["config", key, value]);
        }
        repo.write(".gitattributes", "*.py filter=evil diff=evil\n");
        repo.write("a.py", "a = 1\nb = 3\n");
        repo.write("other.py", "z = 1\n");

        let nc = repo.new_code(&repo.root, &["a.py", "other.py"]).unwrap();
        assert!(nc.is_new("a.py", 2));
        assert!(
            !marker.exists(),
            "a repository-configured program was executed"
        );
    }

    #[test]
    fn oversized_base_blob_counts_as_fully_changed() {
        let repo = Repo::new();
        repo.write("a.py", "a = 1\nb = 3\n");
        let files = [("a.py", std::fs::read(repo.root.join("a.py")).ok())];
        let nc = new_code(&repo.root, "main", 4, TIMEOUT, files).unwrap();
        assert!(nc.is_new("a.py", 1));
    }

    #[test]
    fn parses_ls_tree_entries() {
        let out = [
            "100644 blob abc123\tsub/a.py",
            "100755 blob def456\tsub/run.sh",
            "120000 blob 999\tsub/link.py",
            "160000 commit 111\tsub/module",
            "100644 blob 222\tother.py",
        ]
        .join("\0");
        let blobs = parse_ls_tree(&out, "sub/");
        assert_eq!(blobs.len(), 2);
        assert_eq!(blobs["a.py"], "abc123");
    }

    proptest! {
        #![proptest_config(crate::test_support::proptest_config(512))]

        #[test]
        fn accepted_refs_can_never_be_read_as_options(r in any::<String>()) {
            if validate_ref(&r).is_ok() {
                prop_assert!(!r.is_empty() && !r.starts_with('-'));
                prop_assert!(!r.chars().any(|c| c.is_whitespace() || c.is_control()));
            }
        }
    }

    #[test]
    fn run_with_timeout_returns_output() {
        let out = run_with_timeout(Command::new("git").arg("--version"), TIMEOUT).unwrap();
        assert!(out.status.success());
        assert!(String::from_utf8_lossy(&out.stdout).starts_with("git version"));
    }

    /// Regression: git calls had no timeout, so a pathological repository
    /// could hang the scan forever.
    #[cfg(unix)]
    #[test]
    fn hanging_process_is_killed_at_the_deadline() {
        let started = std::time::Instant::now();
        let err = run_with_timeout(Command::new("sleep").arg("30"), Duration::from_millis(200))
            .unwrap_err();
        assert!(err.to_string().contains("timed out"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    /// Both pipes are drained concurrently, so large output on stdout and
    /// stderr cannot deadlock.
    #[cfg(unix)]
    #[test]
    fn large_stdout_and_stderr_do_not_deadlock() {
        let script = "head -c 1000000 /dev/zero >&2; head -c 1000000 /dev/zero";
        let out = run_with_timeout(Command::new("sh").args(["-c", script]), TIMEOUT).unwrap();
        assert_eq!((out.stdout.len(), out.stderr.len()), (1_000_000, 1_000_000));
    }

    #[cfg(unix)]
    #[test]
    fn hanging_cat_file_times_out_instead_of_blocking() {
        let started = std::time::Instant::now();
        let mut cat =
            CatFile::start(Command::new("sleep").arg("30"), Duration::from_millis(200)).unwrap();
        let err = cat.blob("abc", 1024).unwrap_err();
        assert!(err.to_string().contains("timed out"), "{err}");
        assert!(cat.finish().is_err());
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    /// Regression: when cat-file died, its empty answer read as "blob
    /// missing", silently marking the file as entirely new code.
    #[cfg(unix)]
    #[test]
    fn cat_file_exiting_early_is_an_error() {
        let mut cat = CatFile::start(&mut Command::new("true"), TIMEOUT).unwrap();
        let err = cat.blob("abc", 1024).unwrap_err();
        assert!(!err.to_string().contains("timed out"), "{err}");
    }
}
