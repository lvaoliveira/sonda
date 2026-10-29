//! Infrastructure: per-file analysis in worker processes (ADR-0003). A crash
//! in tree-sitter's C code kills one worker, not the scan: the file it was
//! analyzing becomes a warning and the worker is restarted.
//!
//! Protocol over the worker's stdin/stdout: frames of a little-endian `u64`
//! length followed by the payload. The first frame to a worker is the config
//! as JSON; then each request frame (one file) gets one response frame.
//! The parent reads files itself (size cap, swap checks) and sends only
//! source text, and it decodes responses defensively: a compromised worker
//! could send anything.

use crate::analysis::{self, FileAnalysis, FileError, Token};
use crate::config::Config;
use crate::error::Error;
use crate::lang::Lang;
use crate::model::{FileMetrics, Issue, Severity};
use crate::rules::{self, RuleSet};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::num::NonZeroUsize;
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

/// The hidden CLI subcommand that runs [`serve`].
pub const WORKER_COMMAND: &str = "__worker";

/// Extra time the parent allows beyond the per-file timeout before killing
/// a worker: the worker enforces the timeout itself and normally answers.
const GRACE: Duration = Duration::from_secs(5);

const MAX_CONFIG_FRAME: u64 = 1 << 20;

const SEVERITIES: [Severity; 5] = [
    Severity::Info,
    Severity::Minor,
    Severity::Major,
    Severity::Critical,
    Severity::Blocker,
];

// ---------------------------------------------------------------- framing

fn write_frame(w: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    w.write_all(&(payload.len() as u64).to_le_bytes())?;
    w.write_all(payload)?;
    w.flush()
}

/// The next frame, or `None` at a clean end of stream. Frames longer than
/// `max_len` are refused before anything is allocated for them.
fn read_frame(r: &mut impl Read, max_len: u64) -> io::Result<Option<Vec<u8>>> {
    let mut header = [0u8; 8];
    let mut got = 0;
    while got < header.len() {
        match r.read(&mut header[got..]) {
            Ok(0) if got == 0 => return Ok(None),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let len = u64::from_le_bytes(header);
    if len > max_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame of {len} bytes exceeds the {max_len}-byte limit"),
        ));
    }
    let mut payload = Vec::new();
    r.take(len).read_to_end(&mut payload)?;
    if payload.len() as u64 != len {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(Some(payload))
}

// --------------------------------------------------------------- encoding

#[derive(Default)]
struct Enc(Vec<u8>);

impl Enc {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }

    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }

    fn usize(&mut self, v: usize) {
        self.u64(v as u64);
    }

    fn str(&mut self, s: &str) {
        self.usize(s.len());
        self.0.extend_from_slice(s.as_bytes());
    }
}

/// Bounds-checked reader over an untrusted payload.
struct Dec<'a>(&'a [u8]);

type Malformed = String;

impl<'a> Dec<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Malformed> {
        if n > self.0.len() {
            return Err("truncated".into());
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, Malformed> {
        Ok(self.take(1)?[0])
    }

    fn u64(&mut self) -> Result<u64, Malformed> {
        let bytes: [u8; 8] = self.take(8)?.try_into().map_err(|_| "truncated")?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn usize(&mut self) -> Result<usize, Malformed> {
        usize::try_from(self.u64()?).map_err(|_| "integer too large".into())
    }

    fn u32(&mut self) -> Result<u32, Malformed> {
        u32::try_from(self.u64()?).map_err(|_| "integer too large".into())
    }

    fn str(&mut self) -> Result<&'a str, Malformed> {
        let len = self.usize()?;
        std::str::from_utf8(self.take(len)?).map_err(|_| "invalid UTF-8".into())
    }

    /// A count of items of at least `min_size` bytes each, checked against
    /// the remaining input so a bogus count cannot trigger a huge allocation.
    fn count(&mut self, min_size: usize) -> Result<usize, Malformed> {
        let n = self.usize()?;
        match n.checked_mul(min_size) {
            Some(bytes) if bytes <= self.0.len() => Ok(n),
            _ => Err("count exceeds the input".into()),
        }
    }

    fn finish(self) -> Result<(), Malformed> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err("trailing bytes".into())
        }
    }
}

fn encode_request(path: &str, lang: Lang, timeout: Duration, src: &str) -> Vec<u8> {
    let mut e = Enc::default();
    e.str(path);
    e.u8(lang.index());
    e.u64(u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX));
    e.str(src);
    e.0
}

fn decode_request(buf: &[u8]) -> Result<(&str, Lang, Duration, &str), Malformed> {
    let mut d = Dec(buf);
    let path = d.str()?;
    let lang = Lang::from_index(d.u8()?).ok_or("unknown language")?;
    let timeout = Duration::from_millis(d.u64()?);
    let src = d.str()?;
    d.finish()?;
    Ok((path, lang, timeout, src))
}

fn encode_response(result: &Result<FileAnalysis, FileError>) -> Vec<u8> {
    let mut e = Enc::default();
    let a = match result {
        Err(err) => {
            e.u8(1);
            e.str(&err.to_string());
            return e.0;
        }
        Ok(a) => a,
    };
    e.u8(0);
    e.usize(a.issues.len());
    for i in &a.issues {
        e.str(i.rule);
        let severity = SEVERITIES.iter().position(|&s| s == i.severity);
        e.u8(severity.unwrap_or(0) as u8);
        e.str(&i.message);
        for v in [i.line, i.column, i.end_line, i.end_column] {
            e.usize(v);
        }
        e.u64(u64::from(i.effort_minutes));
    }
    let m = &a.metrics;
    for v in [m.lines, m.ncloc, m.comment_lines, m.functions] {
        e.usize(v);
    }
    e.u64(u64::from(m.complexity));
    e.u64(u64::from(m.cognitive_complexity));
    e.usize(a.code_lines.len());
    for &l in &a.code_lines {
        e.usize(l);
    }
    e.usize(a.tokens.len());
    for t in &a.tokens {
        e.u64(t.hash);
        e.usize(t.line);
    }
    e.u8(u8::from(a.has_syntax_errors));
    e.0
}

/// Smallest encoded issue: two empty strings (8 bytes each), the severity
/// byte, four positions and the effort (8 bytes each).
const MIN_ISSUE_BYTES: usize = 8 + 1 + 8 + 4 * 8 + 8;

/// Outer `Err`: the payload is malformed. Inner `Err`: the worker reported
/// that the file could not be analyzed.
fn decode_response(
    buf: &[u8],
    path: &str,
    lang: Lang,
) -> Result<Result<FileAnalysis, String>, Malformed> {
    let mut d = Dec(buf);
    match d.u8()? {
        0 => {}
        1 => {
            let message = d.str()?.to_string();
            d.finish()?;
            return Ok(Err(message));
        }
        _ => return Err("unknown status".into()),
    }
    let mut issues = Vec::with_capacity(d.count(MIN_ISSUE_BYTES)?);
    for _ in 0..issues.capacity() {
        let id = d.str()?;
        // Only built-in rules exist; their category comes from the catalog,
        // not from the worker.
        let rule = rules::find(id).ok_or_else(|| format!("unknown rule {id:?}"))?;
        let severity = *SEVERITIES
            .get(usize::from(d.u8()?))
            .ok_or("unknown severity")?;
        let message = d.str()?.to_string();
        let (line, column, end_line, end_column) = (d.usize()?, d.usize()?, d.usize()?, d.usize()?);
        issues.push(Issue {
            rule: rule.id,
            severity,
            category: rule.category,
            message,
            path: path.to_string(),
            line,
            column,
            end_line,
            end_column,
            effort_minutes: d.u32()?,
            is_new: true,
        });
    }
    let metrics = FileMetrics {
        lines: d.usize()?,
        ncloc: d.usize()?,
        comment_lines: d.usize()?,
        functions: d.usize()?,
        complexity: d.u32()?,
        cognitive_complexity: d.u32()?,
    };
    let mut code_lines = Vec::with_capacity(d.count(8)?);
    for _ in 0..code_lines.capacity() {
        code_lines.push(d.usize()?);
    }
    let mut tokens = Vec::with_capacity(d.count(16)?);
    for _ in 0..tokens.capacity() {
        tokens.push(Token {
            hash: d.u64()?,
            line: d.usize()?,
        });
    }
    let has_syntax_errors = match d.u8()? {
        0 => false,
        1 => true,
        _ => return Err("invalid flag".into()),
    };
    d.finish()?;
    let analysis = FileAnalysis {
        path: path.to_string(),
        lang,
        issues,
        metrics,
        code_lines,
        tokens,
        has_syntax_errors,
    };
    // Positions out of range would corrupt measures and reports.
    analysis::check_invariants(&analysis)?;
    Ok(Ok(analysis))
}

fn max_request_bytes(config: &Config) -> u64 {
    // Source plus path and fixed fields.
    config
        .scan
        .max_file_size_kb
        .saturating_mul(1024)
        .saturating_add(1 << 16)
}

fn max_response_bytes(config: &Config) -> u64 {
    // Tokens are at most one per source byte (16 bytes each encoded), code
    // lines one per line (8 bytes); the rest is generous room for issues.
    config
        .scan
        .max_file_size_kb
        .saturating_mul(1024)
        .saturating_mul(32)
        .saturating_add(16 << 20)
}

// ----------------------------------------------------------- worker side

/// Runs a worker: reads the config, then answers one request per file until
/// the parent closes the input.
pub(crate) fn serve(input: impl Read, output: impl Write) -> Result<(), Error> {
    let io_error = |e: io::Error| Error::Internal(format!("worker I/O: {e}"));
    let (mut input, mut output) = (BufReader::new(input), BufWriter::new(output));
    let Some(frame) = read_frame(&mut input, MAX_CONFIG_FRAME).map_err(io_error)? else {
        return Ok(());
    };
    let config: Config = serde_json::from_slice(&frame)
        .map_err(|e| Error::Internal(format!("worker config: {e}")))?;
    let rules = RuleSet::new(&config.rules)?;
    let limit = max_request_bytes(&config);
    while let Some(frame) = read_frame(&mut input, limit).map_err(io_error)? {
        let (path, lang, timeout, src) =
            decode_request(&frame).map_err(|e| Error::Internal(format!("worker request: {e}")))?;
        abort_on_test_marker(src);
        let result = analysis::analyze(path, lang, src, &rules, &config, Instant::now() + timeout);
        write_frame(&mut output, &encode_response(&result)).map_err(io_error)?;
    }
    Ok(())
}

/// Test seam, debug builds only: a worker aborts on a file containing the
/// value of `SONDA_TEST_WORKER_ABORT`, standing in for a parser crash.
fn abort_on_test_marker(_src: &str) {
    #[cfg(debug_assertions)]
    if let Some(marker) = std::env::var_os("SONDA_TEST_WORKER_ABORT")
        && let Some(marker) = marker.to_str()
        && !marker.is_empty()
        && _src.contains(marker)
    {
        std::process::abort();
    }
}

// ----------------------------------------------------------- parent side

/// One file to analyze: its root-relative path, language and source.
pub(crate) type Job<'a> = (&'a str, Lang, String);

/// Runs analysis in worker processes, one per CPU.
pub(crate) struct WorkerPool<'a> {
    program: &'a Path,
    config_frame: Vec<u8>,
    max_response: u64,
    file_timeout: Duration,
    /// How long the parent waits for an answer before killing the worker.
    deadline: Duration,
    /// Workers (and threads driving them); `None` uses every CPU.
    jobs: Option<NonZeroUsize>,
}

impl<'a> WorkerPool<'a> {
    pub(crate) fn new(
        program: &'a Path,
        config: &Config,
        file_timeout: Duration,
        jobs: Option<NonZeroUsize>,
    ) -> Result<Self, Error> {
        let config_frame = serde_json::to_vec(config)
            .map_err(|e| Error::Internal(format!("serializing config for workers: {e}")))?;
        Ok(WorkerPool {
            program,
            config_frame,
            max_response: max_response_bytes(config),
            file_timeout,
            deadline: file_timeout.saturating_add(GRACE),
            jobs,
        })
    }

    /// Analyzes every item, in parallel. `prepare` reads an item's source
    /// (in this process) or explains why it cannot. Results keep the order
    /// of `items`.
    pub(crate) fn run<T: Sync>(
        &self,
        items: &[T],
        prepare: impl Fn(&T) -> Result<Job<'_>, String> + Sync,
    ) -> Result<Vec<Result<FileAnalysis, String>>, Error> {
        let threads = self
            .jobs
            .or_else(|| thread::available_parallelism().ok())
            .map_or(1, NonZeroUsize::get)
            .min(items.len())
            .max(1);
        let next = AtomicUsize::new(0);
        let per_thread = thread::scope(|scope| {
            let handles: Vec<_> = (0..threads)
                .map(|_| {
                    scope.spawn(|| {
                        let mut worker: Option<Worker> = None;
                        let mut done = Vec::new();
                        loop {
                            let i = next.fetch_add(1, Ordering::Relaxed);
                            let Some(item) = items.get(i) else { break };
                            let result = match prepare(item) {
                                Ok(job) => self.analyze(&mut worker, job)?,
                                Err(warning) => Err(warning),
                            };
                            done.push((i, result));
                        }
                        Ok::<_, Error>(done)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| {
                    h.join()
                        .map_err(|_| Error::Internal("worker pool thread panicked".into()))?
                })
                .collect::<Result<Vec<_>, Error>>()
        })?;
        let mut results: Vec<_> = per_thread.into_iter().flatten().collect();
        results.sort_by_key(|(i, _)| *i);
        Ok(results.into_iter().map(|(_, r)| r).collect())
    }

    /// One file on this thread's worker, starting or restarting it as needed.
    fn analyze(
        &self,
        slot: &mut Option<Worker>,
        (path, lang, src): Job<'_>,
    ) -> Result<Result<FileAnalysis, String>, Error> {
        let worker = match slot {
            Some(w) => w,
            None => slot.insert(Worker::start(
                self.program,
                &self.config_frame,
                self.max_response,
            )?),
        };
        let request = encode_request(path, lang, self.file_timeout, &src);
        let failure = match worker.ask(&request, self.deadline) {
            Ok(frame) => match decode_response(&frame, path, lang) {
                Ok(result) => return Ok(result.map_err(|e| format!("{path}: skipped, {e}"))),
                Err(e) => format!("invalid response from the analysis worker ({e})"),
            },
            Err(why) => why,
        };
        // Whatever happened, this worker is no longer trusted to continue.
        *slot = None;
        tracing::debug!(path, %failure, "restarting analysis worker");
        Ok(Err(format!("{path}: skipped, {failure}")))
    }
}

struct Worker {
    child: Child,
    stdin: ChildStdin,
    replies: Receiver<io::Result<Vec<u8>>>,
}

impl Worker {
    fn start(program: &Path, config_frame: &[u8], max_response: u64) -> Result<Worker, Error> {
        let mut child = Command::new(program)
            .arg(WORKER_COMMAND)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| {
                Error::Internal(format!(
                    "cannot start analysis worker {}: {e}",
                    program.display()
                ))
            })?;
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            return Err(Error::Internal("analysis worker pipes missing".into()));
        };
        // Replies arrive through a channel so the parent can stop waiting.
        let (tx, replies) = mpsc::channel();
        thread::spawn(move || {
            let mut stdout = BufReader::new(stdout);
            loop {
                match read_frame(&mut stdout, max_response) {
                    Ok(Some(frame)) => {
                        if tx.send(Ok(frame)).is_err() {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        let _ = tx.send(Err(e));
                        break;
                    }
                }
            }
        });
        let mut worker = Worker {
            child,
            stdin,
            replies,
        };
        if let Err(e) = write_frame(&mut worker.stdin, config_frame) {
            return Err(Error::Internal(format!(
                "analysis worker exited at startup: {}",
                worker.exit_reason().unwrap_or_else(|| e.to_string())
            )));
        }
        Ok(worker)
    }

    /// Sends one request and waits up to `deadline` for its answer.
    fn ask(&mut self, request: &[u8], deadline: Duration) -> Result<Vec<u8>, String> {
        let crashed = |w: &mut Worker| match w.exit_reason() {
            Some(status) => format!("the parser crashed ({status})"),
            None => "the parser crashed".to_string(),
        };
        if write_frame(&mut self.stdin, request).is_err() {
            return Err(crashed(self));
        }
        match self.replies.recv_timeout(deadline) {
            Ok(Ok(frame)) => Ok(frame),
            Ok(Err(e)) => Err(format!("invalid response from the analysis worker ({e})")),
            Err(RecvTimeoutError::Timeout) => {
                Err("analysis did not finish before the per-file timeout".into())
            }
            Err(RecvTimeoutError::Disconnected) => Err(crashed(self)),
        }
    }

    /// The exit status. Kills the process first: a worker that closed its
    /// output but kept running must not make the parent wait forever. If it
    /// already exited, the kill does nothing and its own status is reported.
    fn exit_reason(&mut self) -> Option<String> {
        let _ = self.child.kill();
        self.child.wait().ok().map(|s| s.to_string())
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        // Fails only if it already exited, which is fine.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::tests::far_deadline;
    use proptest::prelude::*;
    use std::sync::LazyLock;

    static CONFIG: LazyLock<Config> = LazyLock::new(Config::default);
    static RULES: LazyLock<RuleSet> = LazyLock::new(|| RuleSet::new(&CONFIG.rules).unwrap());

    fn analyzed(lang: Lang, src: &str) -> FileAnalysis {
        analysis::analyze("p/f", lang, src, &RULES, &CONFIG, far_deadline()).unwrap()
    }

    #[test]
    fn frames_round_trip_and_end_cleanly() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"hello").unwrap();
        write_frame(&mut buf, b"").unwrap();
        let mut r = buf.as_slice();
        assert_eq!(read_frame(&mut r, 100).unwrap(), Some(b"hello".to_vec()));
        assert_eq!(read_frame(&mut r, 100).unwrap(), Some(vec![]));
        assert_eq!(read_frame(&mut r, 100).unwrap(), None);
        // A partial header or payload is an error, not a clean end.
        assert!(read_frame(&mut &buf[..3], 100).is_err());
        assert!(read_frame(&mut &buf[..10], 100).is_err());
    }

    #[test]
    fn oversized_frames_are_refused_before_allocating() {
        let huge = u64::MAX.to_le_bytes();
        let err = read_frame(&mut huge.as_slice(), 1024).unwrap_err();
        assert!(err.to_string().contains("exceeds"));
    }

    #[test]
    fn requests_round_trip() {
        let frame = encode_request(
            "src/a.py",
            Lang::Python,
            Duration::from_millis(1500),
            "x = 1\n",
        );
        let (path, lang, timeout, src) = decode_request(&frame).unwrap();
        assert_eq!(
            (path, lang, timeout, src),
            (
                "src/a.py",
                Lang::Python,
                Duration::from_millis(1500),
                "x = 1\n"
            )
        );
    }

    #[test]
    fn analyses_round_trip_in_every_language() {
        let samples = [
            "function f(a) { if (a == 1) { eval(a); } var x = 2; } // TODO\n",
            "let x: any = 1;\nfunction g(a: number) { return a ? 1 : 2; }\n",
            "const C = () => <div onClick={() => go()}>x</div>;\n",
            "def f(a=[]):\n    try:\n        return eval(a)\n    except:\n        pass\n",
            "class A { void f(String s) { if (s == \"x\") { System.exit(1); } } }\n",
            "#include <stdio.h>\nvoid f(char *d) { gets(d); goto end; end: return; }\n",
            "#include <vector>\nint f(int x) { return x > 0 ? x : -x; }\n",
        ];
        for (&lang, src) in crate::lang::ALL.iter().zip(samples) {
            let original = analyzed(lang, src);
            assert!(!original.tokens.is_empty());
            let frame = encode_response(&Ok(analyzed(lang, src)));
            let decoded = decode_response(&frame, "p/f", lang).unwrap().unwrap();
            assert_eq!(decoded, original, "{lang:?}");
        }
    }

    #[test]
    fn errors_round_trip() {
        let frame = encode_response(&Err(FileError::ParseTimeout));
        let decoded = decode_response(&frame, "a.js", Lang::JavaScript).unwrap();
        assert_eq!(decoded.unwrap_err(), FileError::ParseTimeout.to_string());
    }

    #[test]
    fn hostile_responses_are_rejected() {
        let good = encode_response(&Ok(analyzed(Lang::JavaScript, "eval(x);\n")));
        // Unknown rule id: replace the first issue's rule string in place.
        let id_at = good.windows(10).position(|w| w == b"js/no-eval").unwrap();
        let mut unknown = good.clone();
        unknown[id_at..id_at + 10].copy_from_slice(b"js/no-evil");
        assert!(
            decode_response(&unknown, "a.js", Lang::JavaScript)
                .unwrap_err()
                .contains("unknown rule")
        );
        // An issue line far outside the file (the line field follows the
        // rule, severity and message).
        let mut e = Enc::default();
        e.u8(0);
        e.usize(1);
        e.str("js/no-eval");
        e.u8(4);
        e.str("m");
        for v in [999, 1, 999, 2, 30] {
            e.usize(v);
        }
        for _ in 0..6 {
            e.usize(1);
        }
        e.usize(0);
        e.usize(0);
        e.u8(0);
        assert!(
            decode_response(&e.0, "a.js", Lang::JavaScript)
                .unwrap_err()
                .contains("outside")
        );
        // A count promising more items than the payload holds.
        let mut huge = vec![0u8];
        huge.extend_from_slice(&u64::MAX.to_le_bytes());
        assert!(
            decode_response(&huge, "a.js", Lang::JavaScript)
                .unwrap_err()
                .contains("count")
        );
        // Trailing garbage.
        let mut trailing = good;
        trailing.push(0);
        assert!(decode_response(&trailing, "a.js", Lang::JavaScript).is_err());
    }

    #[test]
    fn config_survives_the_json_hop() {
        let custom =
            Config::parse("[thresholds]\nparameters = 3\n[rules]\ndisabled = [\"js/no-var\"]\n")
                .unwrap();
        for config in [Config::default(), custom] {
            let back: Config =
                serde_json::from_slice(&serde_json::to_vec(&config).unwrap()).unwrap();
            assert_eq!(back, config);
        }
    }

    proptest! {
        #![proptest_config(crate::test_support::proptest_config(512))]

        #[test]
        fn decoders_never_panic_on_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
            let _ = decode_request(&bytes);
            let _ = decode_response(&bytes, "a.js", Lang::JavaScript);
            let _ = read_frame(&mut bytes.as_slice(), 256);
        }
    }

    /// A stand-in worker program; `script` replaces the real protocol.
    #[cfg(unix)]
    fn fake_worker(dir: &Path, script: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("worker.sh");
        std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[cfg(unix)]
    fn run_pool(program: &Path, deadline: Duration) -> Vec<Result<FileAnalysis, String>> {
        let mut pool = WorkerPool::new(program, &CONFIG, Duration::from_secs(1), None).unwrap();
        pool.deadline = deadline;
        let items = ["a.js", "b.js", "c.js"];
        pool.run(&items, |p| {
            Ok((*p, Lang::JavaScript, "eval(x);\n".to_string()))
        })
        .unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn a_worker_that_crashes_only_loses_its_file() {
        let dir = tempfile::tempdir().unwrap();
        let program = fake_worker(dir.path(), "exit 3");
        let results = run_pool(&program, Duration::from_secs(10));
        assert_eq!(results.len(), 3);
        for (r, name) in results.iter().zip(["a.js", "b.js", "c.js"]) {
            let warning = r.as_ref().unwrap_err();
            assert!(
                warning.starts_with(&format!("{name}: skipped, the parser crashed")),
                "{warning}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn garbage_from_a_worker_is_a_warning_not_a_crash() {
        let dir = tempfile::tempdir().unwrap();
        // Reads the config, then answers with an absurd frame length.
        let program = fake_worker(
            dir.path(),
            "head -c 8 /dev/zero | tr '\\000' '\\377'; sleep 5",
        );
        let results = run_pool(&program, Duration::from_secs(10));
        for r in &results {
            let warning = r.as_ref().unwrap_err();
            assert!(
                warning.contains("invalid response from the analysis worker"),
                "{warning}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_hanging_worker_is_killed_at_the_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let program = fake_worker(dir.path(), "exec sleep 30");
        let started = Instant::now();
        let results = run_pool(&program, Duration::from_millis(300));
        assert!(started.elapsed() < Duration::from_secs(10));
        for r in &results {
            let warning = r.as_ref().unwrap_err();
            assert!(
                warning.contains("did not finish before the per-file timeout"),
                "{warning}"
            );
        }
    }

    #[test]
    fn a_missing_worker_program_fails_the_run() {
        let pool = WorkerPool::new(
            Path::new("/no/such/sonda"),
            &CONFIG,
            Duration::from_secs(1),
            None,
        )
        .unwrap();
        let err = pool
            .run(&["a.js"], |p| Ok((*p, Lang::JavaScript, String::new())))
            .unwrap_err();
        assert!(err.to_string().contains("cannot start analysis worker"));
    }
}
