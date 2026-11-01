//! `POST /api/analyses`: decodes and validates what `sonda upload` sends
//! (ADR-0005). Everything in the request is untrusted. Category comes from
//! sonda's own rule catalog, and each source's hash is recomputed, never
//! taken from the client.

use crate::api::ApiError;
use crate::http::State;
use crate::store;
use axum::Json;
use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, header};
use flate2::read::GzDecoder;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sonda_core::model::Severity;
use sonda_core::report::REPORT_VERSION;
use sonda_core::upload::{Meta, check_relative_path, parse_sha256, validate_meta};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::Read;

/// The largest request body accepted, as sent (usually gzipped).
pub const MAX_BODY_BYTES: usize = 128 << 20;
/// The largest JSON accepted after decompression: the client's own caps
/// (512 MiB of sources, a 256 MiB report) plus room for the envelope.
pub const MAX_JSON_BYTES: u64 = 800 << 20;

const MAX_FILES: usize = 200_000;
const MAX_ISSUES: usize = 2_000_000;
const MAX_TEXT: usize = 4_000;
const MAX_DEPENDENCIES: usize = 200_000;
/// Far more than there are rules.
const MAX_RULE_SETTINGS: usize = 10_000;

// The envelope is sonda's own and fixed: unknown fields are mistakes.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Upload {
    project: String,
    branch: String,
    commit: String,
    /// The project's version; older clients don't send it.
    #[serde(default)]
    version: Option<String>,
    /// The commit's subject line; older clients, and scans outside git,
    /// don't send it.
    #[serde(default)]
    commit_message: Option<String>,
    /// How long the scan took, from `sonda scan --upload`.
    #[serde(default)]
    scan_duration_ms: Option<u64>,
    report: Report,
    sources: Vec<Source>,
    /// The repository's CODEOWNERS file; older clients don't send it.
    #[serde(default)]
    codeowners: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    path: String,
    content: String,
}

// The report is read tolerantly: a newer CLI may add fields without
// changing report_version (see `REPORT_VERSION`).
#[derive(Deserialize)]
struct Report {
    tool: String,
    version: String,
    report_version: u64,
    new_code_reference: Option<String>,
    measures: Value,
    gate: Value,
    files: Vec<File>,
    issues: Vec<Issue>,
    warnings: Vec<String>,
    /// Older CLIs don't send it (ADR-0009): absent, not empty.
    #[serde(default)]
    dependencies: Option<Vec<DependencyIn>>,
    /// The `[rules]` settings of sonda.toml (ADR-0016); older CLIs don't
    /// send them: absent, not empty.
    #[serde(default)]
    rule_settings: Option<RuleSettingsIn>,
    /// The server's rule profile the scan applied (ADR-0018); absent when
    /// it applied none.
    #[serde(default)]
    rule_profile: Option<RuleProfileIn>,
    /// The ids of the rules the scan ran; older CLIs don't send them, and
    /// then every missing issue is fixed, as before.
    #[serde(default)]
    active_rules: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct RuleProfileIn {
    name: String,
    revision: String,
}

#[derive(Deserialize)]
struct RuleSettingsIn {
    disabled: Vec<String>,
    enabled: Vec<String>,
    severity: BTreeMap<String, Severity>,
}

#[derive(Deserialize)]
struct DependencyIn {
    ecosystem: String,
    name: String,
    version: String,
    purl: String,
    direct: Option<bool>,
    source: String,
    license: Option<String>,
}

#[derive(Deserialize)]
struct File {
    path: String,
    language: String,
    sha256: String,
    /// Every other field (lines, ncloc, complexity, ...), stored as is.
    #[serde(flatten)]
    metrics: serde_json::Map<String, Value>,
}

#[derive(Deserialize)]
struct Issue {
    rule: String,
    severity: Severity,
    message: String,
    path: String,
    line: u32,
    column: u32,
    end_line: u32,
    end_column: u32,
    effort_minutes: u32,
    is_new: bool,
    fingerprint: String,
}

/// An upload that passed every check, ready to store.
pub struct Analysis {
    pub meta: Meta,
    pub commit_message: Option<String>,
    pub scan_duration_ms: Option<i64>,
    /// The user's token that uploaded it; `None` for `SONDA_TOKEN`.
    pub token_id: Option<i64>,
    pub tool_version: String,
    pub new_code_reference: Option<String>,
    pub measures: Value,
    pub gate: Value,
    pub gate_passed: bool,
    pub warnings: Vec<String>,
    pub files: Vec<StoredFile>,
    /// Distinct contents, keyed by SHA-256.
    pub sources: Vec<([u8; 32], String)>,
    pub issues: Vec<StoredIssue>,
    pub codeowners: Option<String>,
    pub dependencies: Vec<StoredDependency>,
    /// Whether the report carried dependency data, even none.
    pub dependencies_recorded: bool,
    /// sonda.toml's `[rules]`, normalized; `None` from an older CLI.
    pub rule_settings: Option<Value>,
    /// `{"name", "revision"}` of the profile the scan applied.
    pub rule_profile: Option<Value>,
    /// The rules the scan ran; `None` from an older CLI.
    pub active_rules: Option<Vec<String>>,
}

pub struct StoredDependency {
    pub ecosystem: &'static str,
    pub name: String,
    pub version: String,
    pub purl: String,
    pub direct: Option<bool>,
    pub lockfile: String,
    pub license: Option<String>,
}

pub struct StoredFile {
    pub path: String,
    pub language: String,
    pub sha256: [u8; 32],
    pub metrics: Value,
}

pub struct StoredIssue {
    pub fingerprint: [u8; 16],
    pub rule: &'static str,
    pub severity: &'static str,
    pub category: &'static str,
    pub message: String,
    pub path: String,
    pub line: i32,
    pub col: i32,
    pub end_line: i32,
    pub end_col: i32,
    pub effort_minutes: i32,
    pub is_new: bool,
}

pub async fn create(
    axum::extract::State(state): axum::extract::State<State>,
    axum::extract::Extension(caller): axum::extract::Extension<crate::api::Caller>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<store::Summary>), ApiError> {
    let gzip = match headers.get(header::CONTENT_ENCODING).map(|v| v.as_bytes()) {
        None | Some(b"identity") => false,
        Some(b"gzip") => true,
        Some(_) => {
            return Err(ApiError::UnsupportedMediaType(
                "Content-Encoding must be gzip or identity".into(),
            ));
        }
    };
    // Decompressing, parsing and hashing up to hundreds of MiB is CPU work:
    // keep it off the async workers.
    let mut analysis =
        tokio::task::spawn_blocking(move || decode(&body, gzip, MAX_JSON_BYTES).and_then(validate))
            .await
            .map_err(|e| ApiError::Internal(e.into()))??;
    // A project analysis token uploads its one project (ADR-0012).
    if let crate::api::Caller::UserToken(_, token) = &caller {
        if let Some(project) = &token.project
            && project != &analysis.meta.project
        {
            return Err(ApiError::Forbidden(format!(
                "this token uploads project {project:?} only, not {:?}",
                analysis.meta.project
            )));
        }
        analysis.token_id = Some(token.id);
    }
    let summary = store::ingest(&state.pool, analysis).await?;
    // On the main branch, new code is the project's period (ADR-0011).
    let main: Option<i64> = sqlx::query_scalar(
        "SELECT p.id FROM analyses a JOIN projects p ON p.id = a.project_id
         WHERE a.id = $1 AND a.branch = p.main_branch",
    )
    .bind(summary.analysis_id)
    .fetch_optional(&state.pool)
    .await?;
    match main {
        Some(project) => crate::new_code::refresh(&state.pool, project).await?,
        // Other branches keep the scan's new code; decided issues still
        // leave the counts (ADR-0014).
        None => {
            let (project, branch): (i64, String) =
                sqlx::query_as("SELECT project_id, branch FROM analyses WHERE id = $1")
                    .bind(summary.analysis_id)
                    .fetch_one(&state.pool)
                    .await?;
            crate::new_code::recount(&state.pool, project, &branch).await?;
        }
    }
    crate::dependencies::refresh_gates(
        &state.pool,
        crate::dependencies::GateScope::Analysis(summary.analysis_id),
    )
    .await?;
    tracing::info!(
        analysis = summary.analysis_id,
        new = summary.issues.new,
        fixed = summary.issues.fixed,
        "stored analysis"
    );
    let mut summary = summary;
    let (gate, passed): (Value, bool) =
        sqlx::query_as("SELECT gate, gate_passed FROM analyses WHERE id = $1")
            .bind(summary.analysis_id)
            .fetch_one(&state.pool)
            .await?;
    summary.gate = Some(store::ServerGate {
        passed,
        state: crate::health::gate_state(passed, &gate),
        failing: crate::health::conditions(&gate)
            .into_iter()
            .filter(|c| c.status == "error")
            .map(|c| c.label)
            .collect(),
    });
    Ok((StatusCode::CREATED, Json(summary)))
}

/// A file's coverage, which the new code period reads (ADR-0011):
/// `{"covered": [..], "uncovered": [..]}`, each strictly ascending lines.
fn check_coverage(c: &Value) -> Result<(), String> {
    let bad = || "coverage must be {\"covered\": [lines], \"uncovered\": [lines]}".to_string();
    let c = c.as_object().filter(|c| c.len() == 2).ok_or_else(bad)?;
    for key in ["covered", "uncovered"] {
        let lines = c.get(key).and_then(Value::as_array).ok_or_else(bad)?;
        let mut last = 0;
        for line in lines {
            match line.as_u64() {
                Some(n) if n > last && n <= u64::from(u32::MAX) => last = n,
                _ => return Err(format!("coverage {key} must be ascending line numbers")),
            }
        }
    }
    Ok(())
}

/// A positive line number, as the coverage fields carry them.
fn line_number(v: &Value) -> Option<u64> {
    v.as_u64().filter(|n| (1..=u64::from(u32::MAX)).contains(n))
}

/// `[{"line", "taken", "total"}]`, by ascending line, with
/// `0 <= taken <= total` and at least one branch per line.
fn check_branch_coverage(b: &Value) -> Result<(), String> {
    let bad = || "branch_coverage must be [{line, taken, total}] by ascending line".to_string();
    let mut last = 0;
    for entry in b.as_array().ok_or_else(bad)? {
        let e = entry.as_object().filter(|e| e.len() == 3).ok_or_else(bad)?;
        let line = e.get("line").and_then(line_number).ok_or_else(bad)?;
        let taken = e.get("taken").and_then(Value::as_u64).ok_or_else(bad)?;
        let total = e.get("total").and_then(Value::as_u64).ok_or_else(bad)?;
        if line <= last || total == 0 || taken > total || total > u64::from(u32::MAX) {
            return Err(bad());
        }
        last = line;
    }
    Ok(())
}

/// `[{"name", "line", "calls"}]`: names of 1-1000 characters without
/// control characters, positive lines.
fn check_function_coverage(c: &Value) -> Result<(), String> {
    let bad = || "function_coverage must be [{name, line, calls}]".to_string();
    for entry in c.as_array().ok_or_else(bad)? {
        let e = entry.as_object().filter(|e| e.len() == 3).ok_or_else(bad)?;
        let name = e.get("name").and_then(Value::as_str).ok_or_else(bad)?;
        if name.is_empty() || name.chars().count() > 1000 || name.chars().any(char::is_control) {
            return Err(bad());
        }
        e.get("line").and_then(line_number).ok_or_else(bad)?;
        e.get("calls").and_then(Value::as_u64).ok_or_else(bad)?;
    }
    Ok(())
}

fn decode(body: &[u8], gzip: bool, max_json: u64) -> Result<Upload, ApiError> {
    let json = if gzip {
        let mut out = Vec::new();
        GzDecoder::new(body)
            .take(max_json + 1)
            .read_to_end(&mut out)
            .map_err(|_| ApiError::BadRequest("the body is not valid gzip".into()))?;
        // A small body that inflates enormously (a "zip bomb") stops here.
        if out.len() as u64 > max_json {
            return Err(ApiError::PayloadTooLarge(format!(
                "the upload exceeds {} MiB uncompressed",
                max_json >> 20
            )));
        }
        out
    } else {
        body.to_vec()
    };
    serde_json::from_slice(&json)
        .map_err(|e| ApiError::BadRequest(format!("the body is not a sonda upload: {e}")))
}

fn validate(upload: Upload) -> Result<Analysis, ApiError> {
    let invalid = |m: String| ApiError::Unprocessable(m);
    if upload
        .codeowners
        .as_ref()
        .is_some_and(|c| c.len() as u64 > sonda_core::codeowners::MAX_BYTES)
    {
        return Err(invalid("the CODEOWNERS file is too large".into()));
    }
    let meta = Meta {
        project: upload.project,
        branch: upload.branch,
        commit: upload.commit.to_ascii_lowercase(),
        version: upload.version,
    };
    validate_meta(&meta).map_err(|e| invalid(e.to_string()))?;
    if upload.commit_message.as_ref().is_some_and(|m| {
        m.trim().is_empty() || m.chars().count() > 300 || m.chars().any(char::is_control)
    }) {
        return Err(invalid(
            "invalid commit message: use 1-300 characters, no control characters".into(),
        ));
    }
    // A week bounds what a scan could take.
    let scan_duration_ms = match upload.scan_duration_ms {
        Some(ms) if ms > 7 * 24 * 3_600_000 => {
            return Err(invalid("invalid scan duration: more than a week".into()));
        }
        ms => ms.map(|ms| ms as i64),
    };
    let r = upload.report;
    if r.tool != "sonda" {
        return Err(invalid("the report was not written by sonda".into()));
    }
    if r.report_version != u64::from(REPORT_VERSION) {
        return Err(invalid(format!(
            "report_version {} is not supported; this server reads version {REPORT_VERSION}",
            r.report_version
        )));
    }
    if r.version.len() > 64 || r.new_code_reference.as_ref().is_some_and(|s| s.len() > 255) {
        return Err(invalid(
            "the report's version or new-code reference is too long".into(),
        ));
    }
    if !r.measures.is_object() {
        return Err(invalid("the report's measures are not an object".into()));
    }
    let gate_passed = r.gate["passed"]
        .as_bool()
        .ok_or_else(|| invalid("the report's gate has no passed flag".into()))?;
    if r.files.len() > MAX_FILES || r.issues.len() > MAX_ISSUES {
        return Err(invalid("the report lists too many files or issues".into()));
    }

    let mut files = Vec::with_capacity(r.files.len());
    let mut by_path: HashMap<&str, [u8; 32]> = HashMap::with_capacity(r.files.len());
    for f in &r.files {
        check_relative_path(&f.path).map_err(|e| invalid(e.to_string()))?;
        if !sonda_core::lang::ALL
            .iter()
            .any(|l| serde_json::to_value(l).is_ok_and(|v| v == f.language.as_str()))
        {
            return Err(invalid(format!(
                "{}: unknown language {:?}",
                f.path, f.language
            )));
        }
        let sha256 = parse_sha256(&f.sha256)
            .ok_or_else(|| invalid(format!("{}: invalid sha256", f.path)))?
            .0;
        if by_path.insert(&f.path, sha256).is_some() {
            return Err(invalid(format!("{} is listed twice", f.path)));
        }
        if let Some(c) = f.metrics.get("coverage") {
            check_coverage(c).map_err(|e| invalid(format!("{}: {e}", f.path)))?;
        }
        if let Some(b) = f.metrics.get("branch_coverage") {
            check_branch_coverage(b).map_err(|e| invalid(format!("{}: {e}", f.path)))?;
        }
        if let Some(c) = f.metrics.get("function_coverage") {
            check_function_coverage(c).map_err(|e| invalid(format!("{}: {e}", f.path)))?;
        }
        files.push(StoredFile {
            path: f.path.clone(),
            language: f.language.clone(),
            sha256,
            metrics: Value::Object(f.metrics.clone()),
        });
    }

    // Exactly one source per file, matching the hash the scan recorded.
    if upload.sources.len() != files.len() {
        return Err(invalid(format!(
            "{} files but {} sources",
            files.len(),
            upload.sources.len()
        )));
    }
    let mut seen_sources = HashSet::with_capacity(upload.sources.len());
    let mut sources: HashMap<[u8; 32], String> = HashMap::new();
    for s in upload.sources {
        let expected = by_path
            .get(s.path.as_str())
            .ok_or_else(|| invalid(format!("source {} is not in the report", s.path)))?;
        let actual: [u8; 32] = Sha256::digest(s.content.as_bytes()).into();
        if actual != *expected {
            return Err(invalid(format!(
                "source {} does not match its sha256",
                s.path
            )));
        }
        if !seen_sources.insert(s.path) {
            return Err(invalid("a source is sent twice".into()));
        }
        sources.entry(actual).or_insert(s.content);
    }

    let mut issues = Vec::with_capacity(r.issues.len());
    let mut fingerprints = HashSet::with_capacity(r.issues.len());
    for i in r.issues {
        let rule = sonda_core::rules::find(&i.rule)
            .ok_or_else(|| invalid(format!("unknown rule {:?}", i.rule)))?;
        if !by_path.contains_key(i.path.as_str()) {
            return Err(invalid(format!(
                "issue in {}, which is not in the report",
                i.path
            )));
        }
        let fingerprint = parse_fingerprint(&i.fingerprint)
            .ok_or_else(|| invalid(format!("invalid fingerprint {:?}", i.fingerprint)))?;
        if !fingerprints.insert(fingerprint) {
            return Err(invalid(format!(
                "fingerprint {} appears twice",
                i.fingerprint
            )));
        }
        let pos = |v: u32| i32::try_from(v).ok().filter(|&v| v >= 1);
        let (Some(line), Some(col), Some(end_line), Some(end_col)) = (
            pos(i.line),
            pos(i.column),
            pos(i.end_line),
            pos(i.end_column),
        ) else {
            return Err(invalid(format!("{}: issue position out of range", i.path)));
        };
        if end_line < line || i.message.len() > MAX_TEXT {
            return Err(invalid(format!("{}:{line}: malformed issue", i.path)));
        }
        issues.push(StoredIssue {
            fingerprint,
            rule: rule.id,
            severity: i.severity.as_str(),
            category: rule.category.as_str(),
            message: i.message,
            path: i.path,
            line,
            col,
            end_line,
            end_col,
            effort_minutes: i32::try_from(i.effort_minutes)
                .map_err(|_| invalid("effort out of range".into()))?,
            is_new: i.is_new,
        });
    }

    if r.warnings.len() > MAX_FILES || r.warnings.iter().any(|w| w.len() > MAX_TEXT) {
        return Err(invalid("the report's warnings are too large".into()));
    }
    let rule_settings = r
        .rule_settings
        .map(validate_rule_settings)
        .transpose()
        .map_err(invalid)?;
    let rule_profile = match r.rule_profile {
        Some(p) if (1..=100).contains(&p.name.len()) && (1..=100).contains(&p.revision.len()) => {
            Some(serde_json::json!({ "name": p.name, "revision": p.revision }))
        }
        Some(_) => return Err(invalid("the report's rule profile is invalid".into())),
        None => None,
    };
    if r.active_rules.as_ref().is_some_and(|ids| {
        ids.len() > MAX_RULE_SETTINGS
            || ids
                .iter()
                .any(|id| !(1..=100).contains(&id.len()) || id.chars().any(char::is_control))
    }) {
        return Err(invalid("the report's active rules are invalid".into()));
    }
    let dependencies_recorded = r.dependencies.is_some();
    let dependencies =
        validate_dependencies(r.dependencies.unwrap_or_default()).map_err(invalid)?;
    Ok(Analysis {
        meta,
        commit_message: upload.commit_message,
        scan_duration_ms,
        token_id: None,
        tool_version: r.version,
        new_code_reference: r.new_code_reference,
        measures: r.measures,
        gate: r.gate,
        gate_passed,
        warnings: r.warnings,
        files,
        sources: sources.into_iter().collect(),
        issues,
        codeowners: upload.codeowners,
        dependencies,
        dependencies_recorded,
        rule_settings,
        rule_profile,
        active_rules: r.active_rules,
    })
}

/// Bounded, sorted and deduplicated, as stored and shown. Rule ids aren't
/// checked against this server's catalog: the CLI may be newer.
fn validate_rule_settings(s: RuleSettingsIn) -> Result<Value, String> {
    let ok = |id: &String| (1..=100).contains(&id.len()) && !id.chars().any(char::is_control);
    let total = s.disabled.len() + s.enabled.len() + s.severity.len();
    if total > MAX_RULE_SETTINGS
        || !s
            .disabled
            .iter()
            .chain(&s.enabled)
            .chain(s.severity.keys())
            .all(ok)
    {
        return Err("the report's rule settings are invalid".into());
    }
    let sorted = |v: Vec<String>| v.into_iter().collect::<BTreeSet<_>>();
    Ok(serde_json::json!({
        "disabled": sorted(s.disabled),
        "enabled": sorted(s.enabled),
        "severity": s.severity,
    }))
}

fn validate_dependencies(deps: Vec<DependencyIn>) -> Result<Vec<StoredDependency>, String> {
    if deps.len() > MAX_DEPENDENCIES {
        return Err("the report lists too many dependencies".into());
    }
    let mut seen = std::collections::HashSet::with_capacity(deps.len());
    let mut stored = Vec::with_capacity(deps.len());
    for d in deps {
        let ecosystem = sonda_core::deps::Ecosystem::ALL
            .iter()
            .map(|e| e.as_str())
            .find(|e| *e == d.ecosystem)
            .ok_or_else(|| {
                format!(
                    "dependency {:?}: unknown ecosystem {:?}",
                    d.name, d.ecosystem
                )
            })?;
        let bounded = |s: &str, max: usize| !s.is_empty() && s.len() <= max;
        if !bounded(&d.name, 512)
            || !bounded(&d.version, 256)
            || !(d.purl.len() <= 1024 && d.purl.starts_with("pkg:"))
            || d.license.as_ref().is_some_and(|l| !bounded(l, 512))
        {
            return Err(format!(
                "dependency {:?}: a field is empty, too long or malformed",
                d.name
            ));
        }
        check_relative_path(&d.source).map_err(|e| e.to_string())?;
        if !seen.insert((d.purl.clone(), d.source.clone())) {
            return Err(format!("{} is listed twice for {}", d.purl, d.source));
        }
        stored.push(StoredDependency {
            ecosystem,
            name: d.name,
            version: d.version,
            purl: d.purl,
            direct: d.direct,
            lockfile: d.source,
            license: d.license,
        });
    }
    Ok(stored)
}

fn parse_fingerprint(hex: &str) -> Option<[u8; 16]> {
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 16];
    for (byte, pair) in out.iter_mut().zip(hex.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    #[test]
    fn a_small_body_that_inflates_past_the_cap_is_refused() {
        // 64 MiB of spaces: valid JSON whitespace, about 64 KiB gzipped.
        let mut e = GzEncoder::new(Vec::new(), Compression::fast());
        let chunk = vec![b' '; 1 << 20];
        for _ in 0..64 {
            e.write_all(&chunk).unwrap();
        }
        let bomb = e.finish().unwrap();
        assert!(bomb.len() < 1 << 20, "{} bytes", bomb.len());
        let err = decode(&bomb, true, 32 << 20).err().unwrap();
        assert!(matches!(err, ApiError::PayloadTooLarge(_)), "{err:?}");
    }

    #[test]
    fn fingerprints_must_be_32_hex_digits() {
        assert!(parse_fingerprint("04d724dbbd800b9d4c64c4649cd55415").is_some());
        for bad in [
            "",
            "04d7",
            "04d724dbbd800b9d4c64c4649cd5541z",
            "+4d724dbbd800b9d4c64c4649cd55415",
        ] {
            assert!(parse_fingerprint(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn coverage_is_two_ascending_line_lists() {
        use serde_json::json;
        assert!(check_coverage(&json!({ "covered": [1, 4], "uncovered": [] })).is_ok());
        for bad in [
            json!([1, 2]),
            json!({ "covered": [1] }),
            json!({ "covered": [1], "uncovered": [2], "extra": [] }),
            json!({ "covered": [2, 1], "uncovered": [] }),
            json!({ "covered": [0], "uncovered": [] }),
            json!({ "covered": [1.5], "uncovered": [] }),
            json!({ "covered": ["1"], "uncovered": [] }),
            json!({ "covered": [], "uncovered": [5_000_000_000u64] }),
        ] {
            assert!(check_coverage(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn branch_and_function_coverage_are_checked() {
        use serde_json::json;
        assert!(
            check_branch_coverage(&json!([
                { "line": 1, "taken": 0, "total": 2 },
                { "line": 4, "taken": 2, "total": 2 }
            ]))
            .is_ok()
        );
        for bad in [
            json!({}),
            json!([{ "line": 1, "taken": 3, "total": 2 }]),
            json!([{ "line": 1, "taken": 0, "total": 0 }]),
            json!([{ "line": 0, "taken": 0, "total": 1 }]),
            json!([{ "line": 2, "taken": 0, "total": 1 }, { "line": 2, "taken": 0, "total": 1 }]),
            json!([{ "line": 1, "taken": 0, "total": 1, "x": 1 }]),
        ] {
            assert!(check_branch_coverage(&bad).is_err(), "{bad}");
        }
        assert!(check_function_coverage(&json!([{ "name": "f", "line": 3, "calls": 0 }])).is_ok());
        for bad in [
            json!([{ "name": "", "line": 3, "calls": 0 }]),
            json!([{ "name": "a\nb", "line": 3, "calls": 0 }]),
            json!([{ "name": "f", "line": 0, "calls": 0 }]),
            json!([{ "name": "f", "line": 3, "calls": -1 }]),
            json!([{ "name": "f", "line": 3 }]),
        ] {
            assert!(check_function_coverage(&bad).is_err(), "{bad}");
        }
    }
}
