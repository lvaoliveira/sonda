//! Decides which lines are "new code": lines that differ between the working
//! tree and the merge base with a reference branch, plus files that did not
//! exist there.
//!
//! Security: the analyzed repository is untrusted, `.git/config` included.
//! Git commands that read the working tree or refresh the index (`diff`,
//! `status`, `ls-files`) can run programs named in that config: fsmonitor,
//! clean filters, textconv, external diff. sonda therefore only asks git to
//! read the object database (`rev-parse`, `merge-base`, `ls-tree`, `cat-file`)
//! and diffs the working-tree files itself.

use anyhow::{Context, Result, bail};
use similar::{DiffTag, TextDiff};
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;

/// Past this, the line diff of a single file approximates (marks more lines
/// as changed) instead of searching for the minimal diff.
const DIFF_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug)]
pub enum NewCode {
    /// No reference given: the whole project counts as new code.
    Everything,
    Changes {
        reference: String,
        /// Only files that differ from the merge base are present.
        files: HashMap<String, Changed>,
    },
}

#[derive(Debug, PartialEq)]
pub enum Changed {
    All,
    /// 1-based line numbers.
    Lines(HashSet<usize>),
}

impl NewCode {
    /// `files` yields each scanned file's root-relative path and current
    /// content (`None` when unreadable or too large; such files are skipped).
    /// Base-branch blobs larger than `max_bytes` count as entirely changed.
    pub fn from_git<'a>(
        root: &Path,
        reference: &str,
        max_bytes: u64,
        files: impl IntoIterator<Item = (&'a str, Option<Vec<u8>>)>,
    ) -> Result<NewCode> {
        validate_ref(reference)?;
        let prefix = git(root, &["rev-parse", "--show-prefix"])?;
        let base = git(root, &["merge-base", "--end-of-options", "HEAD", reference])
            .with_context(|| format!("cannot find merge base with '{reference}'"))?;
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
        )?;
        let blobs = parse_ls_tree(&tree, prefix.trim_end_matches('\n'));

        let mut cat = CatFile::spawn(root)?;
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

    pub fn reference(&self) -> Option<&str> {
        match self {
            NewCode::Everything => None,
            NewCode::Changes { reference, .. } => Some(reference),
        }
    }

    pub fn is_new(&self, path: &str, line: usize) -> bool {
        match self {
            NewCode::Everything => true,
            NewCode::Changes { files, .. } => match files.get(path) {
                Some(Changed::All) => true,
                Some(Changed::Lines(lines)) => lines.contains(&line),
                None => false,
            },
        }
    }
}

/// Rejects anything git could read as an option. `--end-of-options` is also
/// passed; this check gives a clear error instead of a confusing git one.
fn validate_ref(reference: &str) -> Result<()> {
    let ok = !reference.is_empty()
        && reference.len() <= 256
        && !reference.starts_with('-')
        && !reference
            .chars()
            .any(|c| c.is_control() || c.is_whitespace());
    if !ok {
        bail!(
            "invalid --new-code reference '{}'",
            reference.escape_debug()
        );
    }
    Ok(())
}

/// Lines of `new` that were added or modified relative to `old`.
fn changed_lines(old: &str, new: &str) -> HashSet<usize> {
    let diff = TextDiff::configure()
        .timeout(DIFF_TIMEOUT)
        .diff_lines(old, new);
    diff.ops()
        .iter()
        .map(|op| op.as_tag_tuple())
        .filter(|(tag, _, _)| matches!(tag, DiffTag::Insert | DiffTag::Replace))
        .flat_map(|(_, _, new_range)| new_range.map(|i| i + 1))
        .collect()
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

fn git(dir: &Path, args: &[&str]) -> Result<String> {
    let out = git_command(dir)
        .args(args)
        .output()
        .context("failed to run git")?;
    if !out.status.success() {
        bail!(
            "git {} failed: {}",
            args.first().unwrap_or(&""),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// A `git cat-file --batch` process: one request/response per object.
struct CatFile {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl CatFile {
    fn spawn(dir: &Path) -> Result<CatFile> {
        let mut child = git_command(dir)
            .args(["cat-file", "--batch"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("failed to run git cat-file")?;
        let stdin = child.stdin.take().context("git cat-file stdin")?;
        let stdout = BufReader::new(child.stdout.take().context("git cat-file stdout")?);
        Ok(CatFile {
            child,
            stdin,
            stdout,
        })
    }

    /// The blob's bytes, or `None` if it is missing or larger than `max_bytes`.
    fn blob(&mut self, oid: &str, max_bytes: u64) -> Result<Option<Vec<u8>>> {
        writeln!(self.stdin, "{oid}")?;
        self.stdin.flush()?;
        let mut header = String::new();
        self.stdout.read_line(&mut header)?;
        // "<oid> <type> <size>" or "<oid> missing"
        let mut parts = header.split_whitespace().skip(1);
        let (Some(kind), Some(size)) = (parts.next(), parts.next()) else {
            return Ok(None);
        };
        let size: u64 = size
            .parse()
            .with_context(|| format!("bad cat-file header {header:?}"))?;
        let mut body = (&mut self.stdout).take(size + 1); // +1: trailing newline
        if kind != "blob" || size > max_bytes {
            std::io::copy(&mut body, &mut std::io::sink())?;
            return Ok(None);
        }
        let mut buf = Vec::with_capacity(size as usize + 1);
        body.read_to_end(&mut buf)?;
        if buf.pop() != Some(b'\n') || buf.len() as u64 != size {
            bail!("truncated output from git cat-file");
        }
        Ok(Some(buf))
    }

    fn finish(self) -> Result<()> {
        let CatFile {
            mut child, stdin, ..
        } = self;
        drop(stdin); // EOF ends the batch
        child.wait().context("waiting for git cat-file")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
            git(&self.root, args).unwrap();
        }

        fn write(&self, path: &str, content: &str) {
            let full = self.root.join(path);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, content).unwrap();
        }

        fn new_code(&self, root: &Path, files: &[&str]) -> Result<NewCode> {
            let contents = files.iter().map(|f| (*f, std::fs::read(root.join(f)).ok()));
            NewCode::from_git(root, "main", 1 << 20, contents)
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
            let err = NewCode::from_git(&repo.root, bad, 1024, []).unwrap_err();
            assert!(
                err.to_string().contains("invalid --new-code"),
                "{bad:?}: {err}"
            );
        }
        assert!(NewCode::from_git(&repo.root, "no-such-branch", 1024, []).is_err());
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
        let nc = NewCode::from_git(&repo.root, "main", 4, files).unwrap();
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
}
