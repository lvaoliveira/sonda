//! Infrastructure: reads the merge base of a reference branch from git.
//!
//! Security: the analyzed repository is untrusted, `.git/config` included.
//! Git commands that read the working tree or refresh the index (`diff`,
//! `status`, `ls-files`) can run programs named in that config: fsmonitor,
//! clean filters, textconv, external diff. sonda therefore only asks git to
//! read the object database (`rev-parse`, `merge-base`, `ls-tree`, `cat-file`)
//! and diffs the working-tree files itself (see docs/adr/0002).

use crate::error::Error;
use crate::newcode::{BASELINE_TAG, Basis, Changed, NewCode, changed_lines};
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
    let blobs = parse_ls_tree(&tree, prefix.trim_end_matches('\n'));

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

/// What `auto` found to compare with (ADR-0010).
pub(crate) enum Auto {
    /// A reference for [`new_code`], and how it was chosen.
    Found(String, Basis),
    /// Nothing to compare with, and why.
    Nothing(String),
}

/// Picks the new-code reference when none is given: the default branch's
/// merge base on a branch that has diverged from it; on the default branch,
/// the latest tag before HEAD; without a tag, the last commit `days` or more
/// older than HEAD. Reads refs and commits only (ADR-0002).
pub(crate) fn auto_reference(root: &Path, days: u32, timeout: Duration) -> Result<Auto, Error> {
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
    // A baseline set at HEAD (as `sonda baseline` just did) applies as is.
    let baseline = format!("refs/tags/{BASELINE_TAG}^{{commit}}");
    if git_ok(root, &["rev-parse", "--verify", "-q", &baseline], timeout)?
        .is_some_and(|c| c.trim() == head)
    {
        return Ok(Auto::Found(
            BASELINE_TAG.into(),
            Basis::LatestTag(BASELINE_TAG.into()),
        ));
    }
    // HEAD^: on a release commit, its own tag would leave nothing new.
    if let Some(tag) = git_ok(
        root,
        &[
            "describe",
            "--tags",
            "--abbrev=0",
            "--end-of-options",
            "HEAD^",
        ],
        timeout,
    )? {
        let tag = tag.trim().to_string();
        if validate_ref(&tag).is_ok() {
            return Ok(Auto::Found(tag.clone(), Basis::LatestTag(tag)));
        }
    }
    if days > 0
        && let Some(time) = commit_time(root, head, timeout)?
    {
        let before = time.saturating_sub(i64::from(days) * 86_400);
        let found = git_ok(
            root,
            &[
                "rev-list",
                "-1",
                "--first-parent",
                &format!("--before={before}"),
                "HEAD",
            ],
            timeout,
        )?;
        if let Some(commit) = found
            .map(|c| c.trim().to_string())
            .filter(|c| !c.is_empty())
        {
            return Ok(Auto::Found(commit.clone(), Basis::Days { days, commit }));
        }
    }
    let window = if days > 0 {
        format!(", no commit {days} days older than HEAD")
    } else {
        String::new()
    };
    Ok(Auto::Nothing(format!(
        "no diverged default branch and no tag{window}; set a baseline with `sonda baseline`"
    )))
}

/// Tags HEAD as [`BASELINE_TAG`]; with `force`, moves an existing one.
/// Returns the commit. Hooks are off: tagging updates a ref, which runs the
/// repository's reference-transaction hook (ADR-0002).
pub(crate) fn tag_baseline(root: &Path, force: bool, timeout: Duration) -> Result<String, Error> {
    let head = git(root, &["rev-parse", "--verify", "HEAD^{commit}"], timeout)?;
    let head = head.trim().to_string();
    let existing = format!("refs/tags/{BASELINE_TAG}^{{commit}}");
    if let Some(at) = git_ok(root, &["rev-parse", "--verify", "-q", &existing], timeout)?
        && !force
    {
        return Err(Error::InvalidArgument(format!(
            "{BASELINE_TAG} already tags {}; --force moves it to HEAD",
            &at.trim()[..12.min(at.trim().len())]
        )));
    }
    let mut args = vec!["-c", "core.hooksPath=/dev/null", "tag"];
    if force {
        args.push("-f");
    }
    args.extend(["--end-of-options", BASELINE_TAG, &head]);
    git(root, &args, timeout)?;
    Ok(head)
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

/// A commit's committer time, in seconds, from the object itself: `git log`
/// would honor `log.showSignature` and run gpg.
fn commit_time(root: &Path, commit: &str, timeout: Duration) -> Result<Option<i64>, Error> {
    let Some(object) = git_ok(root, &["cat-file", "commit", commit], timeout)? else {
        return Ok(None);
    };
    Ok(object
        .lines()
        .take_while(|l| !l.is_empty())
        .find_map(|l| l.strip_prefix("committer "))
        .and_then(|l| l.rsplit(' ').nth(1))
        .and_then(|t| t.parse().ok()))
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

    /// `git` with fixed dates, so commits have known times.
    fn git_at(root: &Path, date: &str, args: &[&str]) {
        let out = git_command(root)
            .env("GIT_AUTHOR_DATE", date)
            .env("GIT_COMMITTER_DATE", date)
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn auto(root: &Path) -> Auto {
        auto_reference(root, 30, TIMEOUT).unwrap()
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
    fn auto_on_the_default_branch_uses_the_latest_tag_then_a_time_window() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        git(root, &["init", "-q", "-b", "main"], TIMEOUT).unwrap();
        git(root, &["config", "user.email", "t@example.com"], TIMEOUT).unwrap();
        git(root, &["config", "user.name", "t"], TIMEOUT).unwrap();
        // So `git log` here would run a program; auto must not use it.
        git(root, &["config", "log.showSignature", "true"], TIMEOUT).unwrap();
        let commit = |date: &str, msg: &str| {
            std::fs::write(root.join("a.py"), msg).unwrap();
            git_at(root, date, &["add", "."]);
            git_at(root, date, &["commit", "-qm", msg]);
        };
        commit("2026-01-01T00:00:00Z", "old");
        assert!(
            matches!(auto(root), Auto::Nothing(_)),
            "one commit: nothing before it"
        );
        commit("2026-03-01T00:00:00Z", "middle");
        commit("2026-03-20T00:00:00Z", "recent");
        let old = git(root, &["rev-parse", "HEAD~2"], TIMEOUT).unwrap();
        // No tag: the last commit 30 days or more before HEAD's date.
        let (reference, basis) = found(auto(root));
        assert_eq!(reference, old.trim());
        assert!(matches!(basis, Basis::Days { days: 30, .. }), "{basis:?}");
        assert!(
            matches!(auto_reference(root, 0, TIMEOUT).unwrap(), Auto::Nothing(_)),
            "0 days turns the window off"
        );
        // A tag before HEAD wins.
        git(root, &["tag", "v1.0", "HEAD~1"], TIMEOUT).unwrap();
        assert_eq!(
            found(auto(root)),
            ("v1.0".into(), Basis::LatestTag("v1.0".into()))
        );
        // On a release commit, its own tag would leave nothing: the one before.
        git(root, &["tag", "v1.1"], TIMEOUT).unwrap();
        assert_eq!(found(auto(root)).0, "v1.0");
    }

    #[cfg(unix)]
    #[test]
    fn a_baseline_tags_head_without_running_hooks_and_applies_at_once() {
        use std::os::unix::fs::PermissionsExt;
        let repo = Repo::new();
        repo.git(&["checkout", "-q", "main"]);
        // A hook that would run when the tag's ref is written.
        let hooks = repo.root.join("hooks");
        std::fs::create_dir_all(&hooks).unwrap();
        let marker = repo.root.join("PWNED");
        let hook = hooks.join("reference-transaction");
        std::fs::write(&hook, format!("#!/bin/sh\ntouch '{}'\n", marker.display())).unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
        repo.git(&["config", "core.hooksPath", hooks.to_str().unwrap()]);

        let head = git(&repo.root, &["rev-parse", "HEAD"], TIMEOUT).unwrap();
        assert_eq!(
            tag_baseline(&repo.root, false, TIMEOUT).unwrap(),
            head.trim()
        );
        assert!(!marker.exists(), "a hook ran");
        // Right away, on HEAD itself.
        assert_eq!(
            found(auto(&repo.root)),
            (
                BASELINE_TAG.to_string(),
                Basis::LatestTag(BASELINE_TAG.into())
            )
        );
        // Not moved by accident; moved on purpose.
        assert!(tag_baseline(&repo.root, false, TIMEOUT).is_err());
        repo.write("a.py", "a = 1\nb = 2\nc = 3\n");
        repo.git(&["commit", "-qam", "after the baseline"]);
        // That commit (the test's own git call) ran the hook; sonda's don't.
        let _ = std::fs::remove_file(&marker);
        assert_eq!(found(auto(&repo.root)).0, BASELINE_TAG, "found from HEAD^");
        let moved = tag_baseline(&repo.root, true, TIMEOUT).unwrap();
        assert_ne!(moved, head.trim());
        assert!(!marker.exists(), "a hook ran");
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
