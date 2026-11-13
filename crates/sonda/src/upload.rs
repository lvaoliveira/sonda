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
use sonda_core::upload::{self, CiPullRequest, Meta, PullRequest};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;
use ureq::http::Uri;
use ureq::tls::{PemItem, RootCerts, TlsConfig};

/// A report bigger than this is not one sonda wrote.
const MAX_REPORT_BYTES: u64 = 256 << 20;
/// A saved upload, gzipped and unpacked: no more than the server accepts.
const MAX_SAVED_BYTES: u64 = 128 << 20;
const MAX_SAVED_JSON_BYTES: u64 = 800 << 20;
/// The fields of a saved upload (`upload::Upload`'s); any other means it
/// isn't one.
const SAVED_FIELDS: [&str; 10] = [
    "project",
    "branch",
    "commit",
    "version",
    "pull_request",
    "commit_message",
    "scan_duration_ms",
    "report",
    "sources",
    "codeowners",
];
/// How much of a server's error answer to show.
const MAX_ERROR_BYTES: u64 = 4 << 10;
/// How much of a successful answer to read: counts and the gate's labels.
const MAX_ANSWER_BYTES: u64 = 64 << 10;
/// A profile lists at most every rule, with a severity each.
const MAX_PROFILE_BYTES: u64 = 1 << 20;
/// A bundle of root certificates, generously.
const MAX_CA_CERT_BYTES: u64 = 1 << 20;

#[derive(Args)]
pub struct UploadArgs {
    /// JSON report written by `sonda scan --format json`.
    #[arg(required_unless_present = "saved", conflicts_with = "saved")]
    report: Option<PathBuf>,
    /// Send what `sonda scan --save-upload` wrote, instead of a report and
    /// its sources. Its project, branch, commit and pull request are this
    /// command's, never the file's: for a workflow that uploads a pull
    /// request's scan it didn't run (ADR-0028).
    #[arg(long, value_name = "FILE")]
    saved: Option<PathBuf>,
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
    /// PEM file of the certificate authorities to trust for the server, such
    /// as caddy-root.crt from `setup-server.sh --https`. They replace the
    /// public authorities for this upload, so the token goes only to a
    /// server they certify.
    #[arg(long, value_name = "FILE", env = "SONDA_CA_CERT")]
    ca_cert: Option<PathBuf>,
    /// The pull request the analysis belongs to, outside GitHub Actions
    /// (where it's read from the event); --branch is its head branch.
    #[arg(long, value_name = "NUMBER", requires = "pull_request_base")]
    pull_request: Option<u64>,
    /// The branch the pull request merges into.
    #[arg(long, value_name = "BRANCH", requires = "pull_request")]
    pull_request_base: Option<String>,
    /// The pull request's head commit, where GitHub shows the check
    /// (in a pull_request event, read from it).
    #[arg(long, value_name = "SHA", requires = "pull_request")]
    pull_request_head_sha: Option<String>,
    /// The pull request's repository, as owner/name (in a pull_request
    /// event, read from it).
    #[arg(long, value_name = "OWNER/NAME", requires = "pull_request")]
    repository: Option<String>,
    /// Always exit 0, even when the server's quality gate fails.
    #[arg(long)]
    no_gate: bool,
}

pub fn run(args: UploadArgs) -> Result<ExitCode> {
    let Some(target) = Target {
        server: args.server,
        project: args.project,
        branch: args.branch,
        commit: args.commit,
        project_version: args.project_version,
        token_file: args.token_file,
        ca_cert: args.ca_cert,
        pull_request: args.pull_request,
        pull_request_base: args.pull_request_base,
        pull_request_head_sha: args.pull_request_head_sha,
        repository: args.repository,
    }
    .check()?
    else {
        return Ok(ExitCode::SUCCESS);
    };
    let gate = match (&args.saved, &args.report) {
        (Some(saved), _) => target.send_saved(&read_capped(saved, MAX_SAVED_BYTES)?)?,
        (None, Some(report)) => {
            target.send(&read_capped(report, MAX_REPORT_BYTES)?, &args.root, None)?
        }
        (None, None) => unreachable!("clap requires one"),
    };
    // As SonarQube's sonar.qualitygate.wait: the server's gate decides.
    Ok(match gate {
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
    /// `--ca-cert`: the authorities to trust instead of the public ones.
    pub ca_cert: Option<PathBuf>,
    /// `--pull-request` and `--pull-request-base`, which clap requires
    /// together.
    pub pull_request: Option<u64>,
    pub pull_request_base: Option<String>,
    /// `sonda upload`'s `--pull-request-head-sha` and `--repository`.
    pub pull_request_head_sha: Option<String>,
    pub repository: Option<String>,
}

/// A target whose URL, token and metadata passed the local checks.
pub struct Checked {
    url: String,
    token: String,
    /// Mozilla's roots, or only `--ca-cert`'s.
    roots: RootCerts,
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

fn agent(timeout: Duration, roots: &RootCerts) -> ureq::Agent {
    ureq::Agent::config_builder()
        .tls_config(TlsConfig::builder().root_certs(roots.clone()).build())
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
    /// scanned, read or sent. `None` for a pull request from a fork, which
    /// isn't uploaded (ADR-0021): its CI usually has no secrets, so this
    /// says so and the scan goes on without the server.
    pub fn check(self) -> Result<Option<Checked>> {
        let pull_request = match (self.pull_request, self.pull_request_base) {
            (Some(number), Some(base)) => Some(PullRequest {
                number,
                base,
                head: self.branch.clone(),
                head_sha: self.pull_request_head_sha.map(|s| s.to_ascii_lowercase()),
                repository: self.repository,
            }),
            _ => match upload::github_pull_request(&|v| std::env::var(v).ok()) {
                CiPullRequest::PullRequest(pr) => Some(pr),
                CiPullRequest::Fork(number) => {
                    eprintln!(
                        "sonda: pull request #{number} comes from a fork, whose CI has no \
                         secrets to upload with; scanning without uploading"
                    );
                    return Ok(None);
                }
                CiPullRequest::None => None,
            },
        };
        let url = endpoint(&self.server)?;
        let token = token(self.token_file.as_deref())?;
        let roots = match &self.ca_cert {
            Some(path) => ca_roots(path)?,
            None => RootCerts::WebPki,
        };
        let meta = Meta {
            project: self.project,
            branch: self.branch,
            commit: self.commit,
            version: self.project_version,
            pull_request,
        };
        upload::validate_meta(&meta)?;
        Ok(Some(Checked {
            url,
            token,
            roots,
            server: self.server,
            meta,
        }))
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
        let mut response = agent(Duration::from_secs(30), &self.roots)
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .call()
            .map_err(|e| self.explain(e))
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

    /// A connection error, with what to do when it's the certificate's
    /// authority that isn't trusted.
    fn explain(&self, error: ureq::Error) -> anyhow::Error {
        explain(error, matches!(self.roots, RootCerts::Specific(_)))
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
        let mut upload = upload::prepare(report, root, self.meta.clone())?;
        upload.scan_duration_ms =
            scan_duration.map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let body = serde_json::to_value(&upload)?;
        self.deliver(body)
    }

    /// Sends a file `sonda scan --save-upload` wrote (`gz`), with this
    /// target's project, branch, commit, version and pull request in place
    /// of the file's (ADR-0028): the file comes from a pull request's own
    /// CI, so it says nothing about where it goes. The server validates the
    /// rest, as any upload.
    pub fn send_saved(self, gz: &[u8]) -> Result<Option<bool>> {
        let mut json = Vec::new();
        flate2::read::GzDecoder::new(gz)
            .take(MAX_SAVED_JSON_BYTES + 1)
            .read_to_end(&mut json)
            .context("the saved upload isn't gzip; write it with sonda scan --save-upload")?;
        if json.len() as u64 > MAX_SAVED_JSON_BYTES {
            bail!(
                "the saved upload is larger than {} MiB unpacked",
                MAX_SAVED_JSON_BYTES >> 20
            );
        }
        let mut body: serde_json::Value = serde_json::from_slice(&json)
            .context("the saved upload isn't JSON; write it with sonda scan --save-upload")?;
        let Some(fields) = body.as_object_mut() else {
            bail!("the saved upload isn't one sonda scan --save-upload wrote");
        };
        if let Some(unknown) = fields.keys().find(|k| !SAVED_FIELDS.contains(&k.as_str())) {
            bail!(
                "the saved upload has a field {:?} sonda doesn't write",
                sonda_core::report::terminal_safe(unknown)
            );
        }
        if !fields
            .get("report")
            .is_some_and(serde_json::Value::is_object)
            || !fields
                .get("sources")
                .is_some_and(serde_json::Value::is_array)
        {
            bail!("the saved upload has no report or sources");
        }
        let meta = &self.meta;
        fields.insert("project".into(), meta.project.clone().into());
        fields.insert("branch".into(), meta.branch.clone().into());
        fields.insert("commit".into(), meta.commit.to_ascii_lowercase().into());
        fields.remove("version");
        if let Some(v) = &meta.version {
            fields.insert("version".into(), v.clone().into());
        }
        fields.remove("pull_request");
        if let Some(pr) = &meta.pull_request {
            fields.insert("pull_request".into(), serde_json::to_value(pr)?);
        }
        self.deliver(body)
    }

    /// Posts an upload's body, and reads the server's answer.
    fn deliver(self, mut body: serde_json::Value) -> Result<Option<bool>> {
        let custom_roots = matches!(self.roots, RootCerts::Specific(_));
        let Checked {
            url,
            token,
            roots,
            server,
            meta,
        } = self;
        let files = body["sources"].as_array().map_or(0, Vec::len);
        let post = |body: &serde_json::Value| -> Result<ureq::http::Response<ureq::Body>> {
            let body = gzip(&serde_json::to_vec(body)?)?;
            tracing::info!(url = %url, files, compressed_bytes = body.len(), "uploading");
            agent(Duration::from_secs(300), &roots)
                .post(&url)
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .header("Content-Encoding", "gzip")
                .send(&body[..])
                .map_err(|e| explain(e, custom_roots))
                .with_context(|| format!("sending to {url}"))
        };
        let error_text = |response: &mut ureq::http::Response<ureq::Body>| {
            let mut text = String::new();
            // Best effort: the status alone already says what went wrong.
            let _ = response
                .body_mut()
                .as_reader()
                .take(MAX_ERROR_BYTES)
                .read_to_string(&mut text);
            text.trim().to_string()
        };

        let mut response = post(&body)?;
        let mut status = response.status();
        let mut pull_request = meta.pull_request.as_ref().map(|pr| pr.number);
        // A server older than pull requests (ADR-0021) refuses the field:
        // upload it as the branch it is, as before.
        if status == 400 && pull_request.is_some() {
            let text = error_text(&mut response);
            if !text.contains("pull_request") {
                bail!("the server answered {status}: {text}");
            }
            eprintln!(
                "sonda: {server} doesn't know pull requests yet; uploading to branch {} instead",
                sonda_core::report::terminal_safe(&meta.branch)
            );
            if let Some(fields) = body.as_object_mut() {
                fields.remove("pull_request");
            }
            pull_request = None;
            response = post(&body)?;
            status = response.status();
        }
        if !status.is_success() {
            bail!(
                "the server answered {status}: {}",
                error_text(&mut response)
            );
        }
        let mut answer = String::new();
        // Best effort: the upload already succeeded; the summary is a bonus.
        let _ = response
            .body_mut()
            .as_reader()
            .take(MAX_ANSWER_BYTES)
            .read_to_string(&mut answer);
        let what = match pull_request {
            Some(number) => format!("pull request #{number}"),
            None => meta.branch.clone(),
        };
        eprintln!(
            "sonda: uploaded {} files for {}/{} to {}{}",
            files,
            meta.project,
            what,
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

/// `sonda scan --save-upload`: the body `--upload` would send, gzipped,
/// written to a file for CI to keep as an artifact the server fetches
/// (ADR-0028). No server and no token: it works where CI has neither.
pub struct Saved {
    path: PathBuf,
    meta: Meta,
}

impl Saved {
    /// Checks what's known before scanning, as `Target::check` does. A
    /// pull request comes from the flags, else GitHub Actions' event; a
    /// fork's is left out, since the server takes it from GitHub anyway.
    pub fn check(path: PathBuf, target: Target) -> Result<Self> {
        let pull_request = match (target.pull_request, target.pull_request_base) {
            (Some(number), Some(base)) => Some(PullRequest {
                number,
                base,
                head: target.branch.clone(),
                head_sha: target.pull_request_head_sha,
                repository: target.repository,
            }),
            _ => match upload::github_pull_request(&|v| std::env::var(v).ok()) {
                CiPullRequest::PullRequest(pr) => Some(pr),
                CiPullRequest::Fork(_) | CiPullRequest::None => None,
            },
        };
        let meta = Meta {
            project: target.project,
            branch: target.branch,
            commit: target.commit,
            version: target.project_version,
            pull_request,
        };
        upload::validate_meta(&meta)?;
        Ok(Self { path, meta })
    }

    /// Writes `report` (JSON) and the sources under `root` to the file.
    pub fn write(self, report: &[u8], root: &Path, scan_duration: Option<Duration>) -> Result<()> {
        let mut upload = upload::prepare(report, root, self.meta)?;
        upload.scan_duration_ms =
            scan_duration.map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let body = gzip(&serde_json::to_vec(&upload)?)?;
        std::fs::write(&self.path, &body)
            .with_context(|| format!("writing {}", self.path.display()))?;
        eprintln!(
            "sonda: saved the upload of {} files for {} to {} ({} KiB)",
            upload.sources.len(),
            upload.project,
            self.path.display(),
            body.len().div_ceil(1024)
        );
        Ok(())
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

/// The certificate authorities in a PEM file, to trust instead of the public
/// ones. Each must parse as a root, since ureq would skip one that doesn't
/// and every connection would then fail as untrusted, which hides the cause;
/// a private key in the file is refused, as it was never meant to be shared.
fn ca_roots(path: &Path) -> Result<RootCerts> {
    let read = || {
        format!(
            "reading the certificate authorities from {}",
            path.display()
        )
    };
    let pem = read_capped(path, MAX_CA_CERT_BYTES).with_context(read)?;
    let mut certs = Vec::new();
    for item in ureq::tls::parse_pem(&pem) {
        match item.with_context(read)? {
            PemItem::Certificate(cert) => certs.push(cert),
            PemItem::PrivateKey(_) => bail!(
                "{} holds a private key: pass only the authority's certificate, \
                 and keep its key where it was",
                path.display()
            ),
            _ => {}
        }
    }
    if certs.is_empty() {
        bail!(
            "{} holds no PEM certificate (-----BEGIN CERTIFICATE-----)",
            path.display()
        );
    }
    let mut store = rustls::RootCertStore::empty();
    for (i, cert) in certs.iter().enumerate() {
        store
            .add(rustls::pki_types::CertificateDer::from(cert.der()))
            .with_context(|| {
                format!(
                    "certificate {} in {} isn't a valid authority",
                    i + 1,
                    path.display()
                )
            })?;
    }
    Ok(RootCerts::new_with_certs(&certs))
}

/// A connection error, with a hint when the server's certificate comes from
/// an authority this upload doesn't trust.
fn explain(error: ureq::Error, custom_roots: bool) -> anyhow::Error {
    use rustls::{CertificateError, Error as Tls};
    let unknown_issuer = |tls: &Tls| {
        matches!(
            tls,
            Tls::InvalidCertificate(CertificateError::UnknownIssuer)
        )
    };
    // During the handshake, ureq reports rustls's error inside an I/O error.
    let untrusted = match &error {
        ureq::Error::Rustls(tls) => unknown_issuer(tls),
        ureq::Error::Io(io) => io
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<Tls>())
            .is_some_and(unknown_issuer),
        _ => false,
    };
    let error = anyhow::Error::new(error);
    match (untrusted, custom_roots) {
        (false, _) => error,
        (true, false) => error.context(
            "the server's certificate isn't from a public authority; if it's your own, \
             such as Caddy's from `setup-server.sh --https`, pass its root with --ca-cert",
        ),
        (true, true) => {
            error.context("the server's certificate isn't signed by the --ca-cert authorities")
        }
    }
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
    use std::net::TcpListener;
    use std::sync::Arc;

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/tls")
            .join(name)
    }

    /// A TLS server on 127.0.0.1 with `server.crt` (signed by `ca.crt`),
    /// answering one request with 404, as a server without rule profiles
    /// answers `fetch_rules`.
    fn tls_server() -> String {
        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        let chain = vec![CertificateDer::from_pem_file(fixture("server.crt")).unwrap()];
        let key = PrivateKeyDer::from_pem_file(fixture("server.key")).unwrap();
        let config = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(chain, key)
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let Ok((socket, _)) = listener.accept() else {
                return;
            };
            let connection = rustls::ServerConnection::new(config).unwrap();
            let mut stream = rustls::StreamOwned::new(connection, socket);
            let mut request = Vec::new();
            let mut byte = [0];
            // A refused handshake ends here, as a read error.
            while !request.ends_with(b"\r\n\r\n") {
                match stream.read(&mut byte) {
                    Ok(1) => request.push(byte[0]),
                    _ => return,
                }
            }
            let _ = stream.write_all(
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
            stream.conn.send_close_notify();
            let _ = stream.flush();
        });
        format!("https://{address}")
    }

    fn checked(server: String, ca_cert: Option<PathBuf>, dir: &Path) -> Checked {
        let token_file = dir.join("token");
        std::fs::write(&token_file, "0123456789abcdef0123456789abcdef").unwrap();
        Target {
            server,
            project: "app".into(),
            branch: "main".into(),
            commit: "0123456789abcdef0123456789abcdef01234567".into(),
            project_version: None,
            token_file: Some(token_file),
            ca_cert,
            // Named, so a CI run's own pull request isn't read from the environment.
            pull_request: Some(1),
            pull_request_base: Some("main".into()),
            pull_request_head_sha: None,
            repository: None,
        }
        .check()
        .unwrap()
        .unwrap()
    }

    #[test]
    fn a_server_certified_by_the_ca_cert_authority_is_trusted() {
        let dir = tempfile::tempdir().unwrap();
        let target = checked(tls_server(), Some(fixture("ca.crt")), dir.path());
        assert!(target.fetch_rules().unwrap().is_none());
    }

    #[test]
    fn without_ca_cert_a_private_authority_is_refused_with_a_hint() {
        let dir = tempfile::tempdir().unwrap();
        let error = checked(tls_server(), None, dir.path())
            .fetch_rules()
            .err()
            .expect("refused");
        let message = format!("{error:#}");
        assert!(
            message.contains("pass its root with --ca-cert"),
            "{message}"
        );
        assert!(message.contains("UnknownIssuer"), "{message}");
    }

    #[test]
    fn another_authority_than_the_servers_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let target = checked(tls_server(), Some(fixture("other-ca.crt")), dir.path());
        let message = format!("{:#}", target.fetch_rules().err().expect("refused"));
        assert!(
            message.contains("isn't signed by the --ca-cert authorities"),
            "{message}"
        );
    }

    #[test]
    fn a_bundle_trusts_each_of_its_authorities() {
        let dir = tempfile::tempdir().unwrap();
        let bundle = dir.path().join("bundle.pem");
        let mut pem = std::fs::read(fixture("other-ca.crt")).unwrap();
        pem.extend(std::fs::read(fixture("ca.crt")).unwrap());
        std::fs::write(&bundle, pem).unwrap();
        let target = checked(tls_server(), Some(bundle), dir.path());
        assert!(target.fetch_rules().unwrap().is_none());
    }

    #[test]
    fn ca_cert_files_that_trust_nothing_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let write = |name: &str, text: &str| {
            let path = dir.path().join(name);
            std::fs::write(&path, text).unwrap();
            path
        };
        let cases = [
            (write("empty.pem", ""), "holds no PEM certificate"),
            (
                write("text.pem", "not a certificate\n"),
                "holds no PEM certificate",
            ),
            (fixture("server.key"), "holds a private key"),
            (
                write(
                    "junk.pem",
                    "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
                ),
                "isn't a valid authority",
            ),
            (dir.path().join("missing.pem"), "reading"),
        ];
        for (path, expected) in cases {
            let message = format!("{:#}", ca_roots(&path).unwrap_err());
            assert!(message.contains(expected), "{}: {message}", path.display());
        }
        // A certificate and a key together are refused too: the key is the point.
        let both = dir.path().join("both.pem");
        let mut pem = std::fs::read(fixture("ca.crt")).unwrap();
        pem.extend(std::fs::read(fixture("server.key")).unwrap());
        std::fs::write(&both, pem).unwrap();
        assert!(format!("{:#}", ca_roots(&both).unwrap_err()).contains("private key"));
    }

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
