//! `sonda upload`: sends a JSON report and its sources to a sonda server
//! (ADR-0005). Validation and reading happen in `sonda_core::upload`; this
//! module only handles the token and HTTP.

use anyhow::{Context, Result, bail};
use clap::Args;
use flate2::Compression;
use flate2::write::GzEncoder;
use sonda_core::config::RulesConfig;
use sonda_core::model::Severity;
use sonda_core::report::AppliedProfile;
use sonda_core::upload::{self, Meta};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;
use ureq::http::Uri;

/// A report bigger than this is not one sonda wrote.
const MAX_REPORT_BYTES: u64 = 256 << 20;
/// How much of a server's error answer to show.
const MAX_ERROR_BYTES: u64 = 4 << 10;
/// How much of a successful answer to read: counts and the gate's labels.
const MAX_ANSWER_BYTES: u64 = 64 << 10;
/// A profile lists at most every rule, with a severity each.
const MAX_PROFILE_BYTES: u64 = 1 << 20;

#[derive(Args)]
pub struct UploadArgs {
    /// JSON report written by `sonda scan --format json`.
    report: PathBuf,
    /// Server URL, e.g. https://sonda.example.com.
    #[arg(long, env = "SONDA_SERVER")]
    server: String,
    /// Project key on the server: letters, digits, '.', '_' or '-'.
    #[arg(long)]
    project: String,
    /// Branch the analysis belongs to.
    #[arg(long)]
    branch: String,
    /// Analyzed commit, as hex (in GitHub Actions: $GITHUB_SHA).
    #[arg(long)]
    commit: String,
    /// The project's version, such as 2.3.0. On the main branch, the server
    /// starts a new code period at the first analysis of each new version.
    #[arg(long)]
    project_version: Option<String>,
    /// The directory that was scanned: the report's paths are relative to it.
    #[arg(long, default_value = ".")]
    root: PathBuf,
    /// File holding the API token (or SONDA_TOKEN_FILE); without either, the
    /// SONDA_TOKEN variable is used, as the server reads its secrets. There
    /// is no flag for the token itself, because command lines are visible to
    /// other users and in CI logs.
    #[arg(long, value_name = "FILE", env = "SONDA_TOKEN_FILE")]
    token_file: Option<PathBuf>,
    /// Always exit 0, even when the server's quality gate fails.
    #[arg(long)]
    no_gate: bool,
}

pub fn run(args: UploadArgs) -> Result<ExitCode> {
    let target = Target {
        server: args.server,
        project: args.project,
        branch: args.branch,
        commit: args.commit,
        project_version: args.project_version,
        token_file: args.token_file,
    }
    .check()?;
    let report = read_capped(&args.report, MAX_REPORT_BYTES)?;
    // As SonarQube's sonar.qualitygate.wait: the server's gate decides.
    Ok(match target.send(&report, &args.root, None)? {
        Some(false) if !args.no_gate => ExitCode::from(1),
        _ => ExitCode::SUCCESS,
    })
}

/// Where an analysis goes and which one it is: `sonda upload`'s and
/// `sonda scan --upload`'s options.
pub struct Target {
    pub server: String,
    pub project: String,
    pub branch: String,
    pub commit: String,
    pub project_version: Option<String>,
    pub token_file: Option<PathBuf>,
}

/// A target whose URL, token and metadata passed the local checks.
pub struct Checked {
    url: String,
    token: String,
    server: String,
    meta: Meta,
}

/// The rule settings the server says a scan of the project applies
/// (ADR-0018): its profile with the project's own adjustments.
pub struct ServerRules {
    profile: String,
    revision: String,
    rules: Vec<ServerRule>,
}

struct ServerRule {
    rule: String,
    on: bool,
    severity: Option<Severity>,
}

impl ServerRules {
    /// Reads the server's answer, refusing anything malformed rather than
    /// guessing.
    fn parse(text: &str) -> Result<Self> {
        let v: serde_json::Value = serde_json::from_str(text)?;
        let text_field = |name: &str| {
            v[name]
                .as_str()
                .filter(|s| (1..=100).contains(&s.len()))
                .map(String::from)
                .with_context(|| format!("no valid {name:?}"))
        };
        let rules = v["rules"]
            .as_array()
            .context("no \"rules\" list")?
            .iter()
            .map(|r| {
                Ok(ServerRule {
                    rule: r["rule"]
                        .as_str()
                        .context("a rule without an id")?
                        .to_string(),
                    on: r["on"].as_bool().context("a rule without \"on\"")?,
                    severity: match &r["severity"] {
                        serde_json::Value::Null => None,
                        s => {
                            Some(serde_json::from_value(s.clone()).context("an unknown severity")?)
                        }
                    },
                })
            })
            .collect::<Result<_>>()?;
        Ok(ServerRules {
            profile: text_field("profile")?,
            revision: text_field("revision")?,
            rules,
        })
    }

    /// Applies the server's settings over `rules` (sonda.toml's): where the
    /// server sets a rule, it wins. Returns the ids this sonda doesn't
    /// know, which it skips: the server may be newer.
    pub fn apply(&self, rules: &mut RulesConfig) -> Vec<String> {
        let mut unknown = Vec::new();
        for s in &self.rules {
            let Some(rule) = sonda_core::rules::RULES.iter().find(|r| r.id == s.rule) else {
                unknown.push(s.rule.clone());
                continue;
            };
            rules.disabled.retain(|id| id != rule.id);
            rules.enabled.retain(|id| id != rule.id);
            if !s.on {
                rules.disabled.push(rule.id.to_string());
            } else if !rule.on_by_default() {
                rules.enabled.push(rule.id.to_string());
            }
            if let Some(severity) = s.severity {
                rules.severity.insert(rule.id.to_string(), severity);
            }
        }
        unknown
    }

    /// What the report records as applied.
    pub fn applied(&self) -> AppliedProfile {
        AppliedProfile {
            name: self.profile.clone(),
            revision: self.revision.clone(),
        }
    }

    /// For the scan's output, e.g. `"Strict": 3 rules set`.
    pub fn describe(&self) -> String {
        let n = self.rules.len();
        format!(
            "{:?}: {n} {} set",
            sonda_core::report::terminal_safe(&self.profile),
            if n == 1 { "rule" } else { "rules" }
        )
    }
}

fn agent(timeout: Duration) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(10)))
        .timeout_global(Some(timeout))
        // A redirect would carry the token somewhere the user did not name.
        .max_redirects(0)
        .http_status_as_error(false)
        .user_agent(concat!("sonda/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

impl Target {
    /// Everything that can fail locally fails here, before anything is
    /// scanned, read or sent.
    pub fn check(self) -> Result<Checked> {
        let url = endpoint(&self.server)?;
        let token = token(self.token_file.as_deref())?;
        let meta = Meta {
            project: self.project,
            branch: self.branch,
            commit: self.commit,
            version: self.project_version,
        };
        upload::validate_meta(&meta)?;
        Ok(Checked {
            url,
            token,
            server: self.server,
            meta,
        })
    }
}

impl Checked {
    /// The rule settings the server applies to this project, fetched before
    /// scanning (ADR-0018). `None` from an older server without rule
    /// profiles; any other failure is an error, like the upload's would be.
    pub fn fetch_rules(&self) -> Result<Option<ServerRules>> {
        // `url` ends in `/api/analyses`; the project key is URL-safe
        // (`validate_meta`).
        let base = self.url.trim_end_matches("/analyses");
        let url = format!("{base}/projects/{}/rule-profile", self.meta.project);
        let mut response = agent(Duration::from_secs(30))
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .call()
            .with_context(|| format!("fetching the project's rule settings from {url}"))?;
        let status = response.status();
        if status == 404 {
            return Ok(None);
        }
        let mut text = String::new();
        let limit = if status.is_success() {
            MAX_PROFILE_BYTES
        } else {
            MAX_ERROR_BYTES
        };
        response
            .body_mut()
            .as_reader()
            .take(limit)
            .read_to_string(&mut text)
            .with_context(|| format!("reading the rule settings from {url}"))?;
        if !status.is_success() {
            bail!(
                "fetching the project's rule settings, the server answered {status}: {}",
                text.trim()
            );
        }
        let rules = ServerRules::parse(&text)
            .with_context(|| format!("reading the rule settings from {url}"))?;
        Ok(Some(rules))
    }

    /// The server, as the user named it.
    pub fn server(&self) -> &str {
        &self.server
    }

    /// Sends `report` (JSON) and the sources under `root`. `scan_duration`
    /// is how long the scan took, when this process ran it.
    /// Returns whether the server's gate passed, when its answer says
    /// (ADR-0014): that gate knows the reviews people made on the server.
    pub fn send(
        self,
        report: &[u8],
        root: &Path,
        scan_duration: Option<Duration>,
    ) -> Result<Option<bool>> {
        let Checked {
            url,
            token,
            server,
            meta,
        } = self;
        let mut upload = upload::prepare(report, root, meta)?;
        upload.scan_duration_ms =
            scan_duration.map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let files = upload.sources.len();
        let body = gzip(&serde_json::to_vec(&upload)?)?;
        tracing::info!(url = %url, files, compressed_bytes = body.len(), "uploading");

        let mut response = agent(Duration::from_secs(300))
            .post(&url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .header("Content-Encoding", "gzip")
            .send(&body[..])
            .with_context(|| format!("sending to {url}"))?;
        let status = response.status();
        if !status.is_success() {
            let mut text = String::new();
            // Best effort: the status alone already says what went wrong.
            let _ = response
                .body_mut()
                .as_reader()
                .take(MAX_ERROR_BYTES)
                .read_to_string(&mut text);
            bail!("the server answered {status}: {}", text.trim());
        }
        let mut answer = String::new();
        // Best effort: the upload already succeeded; the summary is a bonus.
        let _ = response
            .body_mut()
            .as_reader()
            .take(MAX_ANSWER_BYTES)
            .read_to_string(&mut answer);
        eprintln!(
            "sonda: uploaded {} files for {}/{} to {}{}",
            files,
            upload.project,
            upload.branch,
            server,
            summary(&answer)
        );
        let gate = server_gate(&answer);
        if let Some((passed, failing)) = &gate {
            eprintln!(
                "sonda: quality gate on the server, reviews included: {}",
                if *passed {
                    "PASSED".to_string()
                } else {
                    format!("FAILED ({})", failing.join(", "))
                }
            );
        }
        Ok(gate.map(|(passed, _)| passed))
    }
}

/// The server's gate in its answer, and its failing conditions; `None`
/// from a server that doesn't send one.
fn server_gate(answer: &str) -> Option<(bool, Vec<String>)> {
    let json: serde_json::Value = serde_json::from_str(answer).ok()?;
    let passed = json["gate"]["passed"].as_bool()?;
    let failing = json["gate"]["failing"]
        .as_array()
        .map(|f| {
            f.iter()
                .filter_map(|c| c.as_str())
                // The server's text, shown in a terminal.
                .map(|c| sonda_core::report::terminal_safe(c).into_owned())
                .collect()
        })
        .unwrap_or_default();
    Some((passed, failing))
}

/// The server's issue counts, e.g. ": 331 open issues (61 new, 2 fixed)",
/// or nothing if the answer has none.
fn summary(answer: &str) -> String {
    let json: serde_json::Value = serde_json::from_str(answer).unwrap_or_default();
    let count = |k: &str| json["issues"][k].as_u64();
    match (
        count("open"),
        count("new"),
        count("reopened"),
        count("fixed"),
    ) {
        (Some(open), Some(new), Some(reopened), Some(fixed)) => {
            let mut s = format!(": {open} open issues ({new} new, {fixed} fixed");
            if reopened > 0 {
                s += &format!(", {reopened} reopened");
            }
            // Missing because the scan didn't run their rule (ADR-0018).
            if let Some(n) = count("set_aside").filter(|&n| n > 0) {
                s += &format!(", {n} set aside: their rules didn't run");
            }
            s + ")"
        }
        _ => String::new(),
    }
}

/// `<server>/api/analyses`, after checking the token cannot leak: plain
/// HTTP only to this machine, and no credentials, query or fragment in the
/// URL.
fn endpoint(server: &str) -> Result<String> {
    let uri: Uri = server
        .parse()
        .with_context(|| format!("invalid server URL {server:?}"))?;
    let host = uri.host().unwrap_or_default();
    let local = matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1");
    match uri.scheme_str() {
        Some("https") => {}
        Some("http") if local => {}
        Some("http") => bail!(
            "refusing to send the token over plain http to {host}; use https \
             (plain http is allowed only for localhost)"
        ),
        _ => bail!("invalid server URL {server:?}: expected https://host"),
    }
    if host.is_empty()
        || uri.authority().is_some_and(|a| a.as_str().contains('@'))
        || uri.query().is_some()
        || server.contains('#')
    {
        bail!("invalid server URL {server:?}: expected https://host[:port][/path]");
    }
    Ok(format!("{}/api/analyses", server.trim_end_matches('/')))
}

fn token(file: Option<&Path>) -> Result<String> {
    // As the server does: never guess which of two tokens is meant.
    if file.is_some() && std::env::var_os("SONDA_TOKEN").is_some() {
        bail!("set SONDA_TOKEN or a token file (--token-file or SONDA_TOKEN_FILE), not both");
    }
    let raw = match file {
        Some(path) => std::fs::read_to_string(path)
            .with_context(|| format!("reading the token from {}", path.display()))?,
        None => std::env::var("SONDA_TOKEN")
            .context("no token: set SONDA_TOKEN or SONDA_TOKEN_FILE, or pass --token-file")?,
    };
    let token = raw.trim();
    if token.is_empty() || token.chars().any(|c| c.is_control() || c == ' ') {
        bail!("the token is empty or contains spaces or control characters");
    }
    Ok(token.to_string())
}

fn read_capped(path: &Path, max: u64) -> Result<Vec<u8>> {
    let file = std::fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {}", path.display()))?;
    if bytes.len() as u64 > max {
        bail!("{} is larger than {} MiB", path.display(), max >> 20);
    }
    Ok(bytes)
}

fn gzip(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes)?;
    Ok(encoder.finish()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_and_local_http_are_accepted() {
        assert_eq!(
            endpoint("https://sonda.example.com/").unwrap(),
            "https://sonda.example.com/api/analyses"
        );
        assert_eq!(
            endpoint("https://example.com/sonda").unwrap(),
            "https://example.com/sonda/api/analyses"
        );
        for local in [
            "http://localhost:9000",
            "http://127.0.0.1:9000",
            "http://[::1]:9000",
        ] {
            assert!(endpoint(local).is_ok(), "{local}");
        }
    }

    #[test]
    fn urls_that_could_leak_the_token_are_refused() {
        for url in [
            "http://sonda.example.com",
            "http://10.0.0.5:9000",
            "http://localhost.evil.com",
            "ftp://example.com",
            "https://user:pw@example.com",
            "https://example.com/?a=b",
            "https://example.com/#x",
            "example.com",
            "",
        ] {
            assert!(endpoint(url).is_err(), "{url}");
        }
    }
}
