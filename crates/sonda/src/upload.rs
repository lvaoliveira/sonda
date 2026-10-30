//! `sonda upload`: sends a JSON report and its sources to a sonda server
//! (ADR-0005). Validation and reading happen in `sonda_core::upload`; this
//! module only handles the token and HTTP.

use anyhow::{Context, Result, bail};
use clap::Args;
use flate2::Compression;
use flate2::write::GzEncoder;
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
}

pub fn run(args: UploadArgs) -> Result<ExitCode> {
    // Everything that can fail locally fails before any connection is made.
    let url = endpoint(&args.server)?;
    let token = token(args.token_file.as_deref())?;
    let report = read_capped(&args.report, MAX_REPORT_BYTES)?;
    let meta = Meta {
        project: args.project,
        branch: args.branch,
        commit: args.commit,
        version: args.project_version,
    };
    let upload = upload::prepare(&report, &args.root, meta)?;
    let files = upload.sources.len();
    let body = gzip(&serde_json::to_vec(&upload)?)?;
    tracing::info!(url = %url, files, compressed_bytes = body.len(), "uploading");

    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(10)))
        .timeout_global(Some(Duration::from_secs(300)))
        // A redirect would carry the token somewhere the user did not name.
        .max_redirects(0)
        .http_status_as_error(false)
        .user_agent(concat!("sonda/", env!("CARGO_PKG_VERSION")))
        .build()
        .into();
    let mut response = agent
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
        .take(MAX_ERROR_BYTES)
        .read_to_string(&mut answer);
    eprintln!(
        "sonda: uploaded {} files for {}/{} to {}{}",
        files,
        upload.project,
        upload.branch,
        args.server,
        summary(&answer)
    );
    Ok(ExitCode::SUCCESS)
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
