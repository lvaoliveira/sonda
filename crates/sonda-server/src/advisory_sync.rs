//! Infrastructure: the opt-in sync of advisories from OSV (ADR-0009), the
//! server's only outbound connection. Off unless SONDA_ADVISORY_SYNC=true.
//!
//! Per ecosystem, OSV publishes `modified_id.csv`, newest first. The sync
//! reads it down to the last time it fully imported, then fetches only the
//! records modified since, from databases sonda imports. If any fetch
//! fails, the ecosystem's watermark stays put and the next run retries.

use crate::advisories::{self, ImportSummary, MAX_RECORD_BYTES};
use sonda_core::advisories::Source;
use sqlx::PgPool;
use std::io::Read;
use std::sync::Mutex;
use std::time::Duration;

/// OSV's bulk exports.
pub const DEFAULT_BASE_URL: &str = "https://osv-vulnerabilities.storage.googleapis.com";
/// OSV's directory names for the ecosystems sonda reads.
const ECOSYSTEMS: &[&str] = &["npm", "PyPI", "crates.io"];
/// npm's index lists every record (most are malicious-package reports
/// sonda skips): tens of megabytes.
const MAX_INDEX_BYTES: u64 = 256 << 20;
/// Records fetched at once.
const CONCURRENCY: usize = 8;
pub const INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Checks a base URL: HTTPS, or HTTP to this machine only (for tests and
/// local mirrors).
pub fn check_base_url(url: &str) -> Result<String, String> {
    let url = url.trim_end_matches('/');
    let local = ["http://127.0.0.1", "http://localhost", "http://[::1]"]
        .iter()
        .any(|p| {
            url.strip_prefix(p)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with([':', '/']))
        });
    if url.starts_with("https://") || local {
        Ok(url.to_string())
    } else {
        Err(format!("{url} is not an https:// URL"))
    }
}

/// One sync of every ecosystem.
pub async fn sync_once(pool: &PgPool, base_url: &str) -> anyhow::Result<ImportSummary> {
    let mut summary = ImportSummary::default();
    for &ecosystem in ECOSYSTEMS {
        let since: Option<String> =
            sqlx::query_scalar("SELECT synced_until FROM advisory_sync WHERE ecosystem = $1")
                .bind(ecosystem)
                .fetch_optional(pool)
                .await?;
        let base = base_url.to_string();
        let (newest, records, failures) =
            tokio::task::spawn_blocking(move || fetch_changes(&base, ecosystem, since.as_deref()))
                .await??;
        let failed = failures.len();
        for f in failures {
            summary.read += 1;
            summary.error(f);
        }
        for (url, text) in records {
            summary.read += 1;
            advisories::record(pool, &url, &text, &mut summary).await;
        }
        // Only a complete pass moves the watermark; storage errors count too.
        if failed == 0
            && summary.errors == 0
            && let Some(newest) = newest
        {
            sqlx::query(
                "INSERT INTO advisory_sync (ecosystem, synced_until) VALUES ($1, $2)
                 ON CONFLICT (ecosystem) DO UPDATE
                     SET synced_until = EXCLUDED.synced_until, synced_at = now()",
            )
            .bind(ecosystem)
            .bind(newest)
            .execute(pool)
            .await?;
        }
    }
    advisories::finish(pool, &summary).await?;
    Ok(summary)
}

/// (newest modified time listed, fetched (url, record) pairs, failures)
type Changes = (Option<String>, Vec<(String, String)>, Vec<String>);

/// Blocking: reads the ecosystem's index and fetches the records changed
/// after `since`.
fn fetch_changes(base: &str, ecosystem: &str, since: Option<&str>) -> anyhow::Result<Changes> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(10)))
        .timeout_global(Some(Duration::from_secs(600)))
        .max_redirects(0)
        .user_agent(concat!("sonda-server/", env!("CARGO_PKG_VERSION")))
        .build()
        .into();
    let index_url = format!("{base}/{ecosystem}/modified_id.csv");
    let index = get(&agent, &index_url, MAX_INDEX_BYTES)?;
    let changed = changed_since(&index, since);
    let newest = changed.newest;
    let urls: Vec<String> = changed
        .ids
        .into_iter()
        .map(|id| format!("{base}/{ecosystem}/{id}.json"))
        .collect();

    let queue = Mutex::new(urls.into_iter());
    let results = Mutex::new((Vec::new(), Vec::new()));
    std::thread::scope(|scope| {
        for _ in 0..CONCURRENCY {
            scope.spawn(|| {
                // The guard is dropped inside `and_then`, not held across the fetch.
                while let Some(url) = queue.lock().ok().and_then(|mut q| q.next()) {
                    let outcome = get(&agent, &url, MAX_RECORD_BYTES);
                    if let Ok(mut r) = results.lock() {
                        match outcome {
                            Ok(text) => r.0.push((url, text)),
                            Err(e) => r.1.push(format!("{url}: {e}")),
                        }
                    }
                }
            });
        }
    });
    let (mut records, mut failures) = results.into_inner().unwrap_or_default();
    records.sort();
    failures.sort();
    Ok((
        newest.or_else(|| since.map(str::to_string)),
        records,
        failures,
    ))
}

fn get(agent: &ureq::Agent, url: &str, max: u64) -> anyhow::Result<String> {
    let mut response = agent.get(url).call()?;
    let mut text = String::new();
    response
        .body_mut()
        .as_reader()
        .take(max + 1)
        .read_to_string(&mut text)?;
    anyhow::ensure!(text.len() as u64 <= max, "larger than {} MB", max >> 20);
    Ok(text)
}

struct Changed {
    /// The index's newest modified time, if it listed anything newer.
    newest: Option<String>,
    /// Ids from databases sonda imports, modified after `since`.
    ids: Vec<String>,
}

/// Reads `modified_id.csv` (`<RFC 3339 time>,<id>` or
/// `<time>,<ecosystem>/<id>`, newest first) down to `since`.
fn changed_since(index: &str, since: Option<&str>) -> Changed {
    let since = since.and_then(time_key);
    let mut newest = None;
    let mut ids = Vec::new();
    for line in index.lines() {
        let Some((time, id)) = line.trim().split_once(',') else {
            continue;
        };
        let Some(key) = time_key(time) else {
            continue;
        };
        if since.as_ref().is_some_and(|s| key <= *s) {
            break;
        }
        if newest.is_none() {
            newest = Some(time.to_string());
        }
        let id = id.rsplit('/').next().unwrap_or(id);
        if Source::of(id).is_some() && safe_id(id) {
            ids.push(id.to_string());
        }
    }
    Changed { newest, ids }
}

/// An OSV time (`2026-10-17T02:55:38.085813876Z`) as a comparable key:
/// whole seconds, then nanoseconds. UTC only, as OSV writes them.
fn time_key(t: &str) -> Option<(String, u32)> {
    let t = t.trim().strip_suffix('Z')?;
    let (seconds, fraction) = t.split_once('.').unwrap_or((t, ""));
    if seconds.len() != 19 || !fraction.bytes().all(|b| b.is_ascii_digit()) || fraction.len() > 9 {
        return None;
    }
    let nanos = format!("{fraction:0<9}").parse().ok()?;
    Some((seconds.to_string(), nanos))
}

/// Ids become URL path segments: letters, digits, `-`, `_` and `.` only.
fn safe_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && !id.starts_with('.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_index_down_to_the_watermark() {
        let index = "2026-10-17T02:55:38.5Z,GHSA-aaaa-bbbb-cccc\n\
                     2026-10-17T02:55:38Z,MAL-2026-1\n\
                     2026-10-16T00:00:00Z,npm/RUSTSEC-2020-0071\n\
                     2026-10-15T00:00:00Z,GHSA-../../etc\n\
                     2026-10-14T00:00:00Z,GHSA-old\n";
        let all = changed_since(index, None);
        assert_eq!(all.newest.as_deref(), Some("2026-10-17T02:55:38.5Z"));
        assert_eq!(
            all.ids,
            ["GHSA-aaaa-bbbb-cccc", "RUSTSEC-2020-0071", "GHSA-old"]
        );
        // Fractions compare as numbers, not text.
        let some = changed_since(index, Some("2026-10-17T02:55:38Z"));
        assert_eq!(some.ids, ["GHSA-aaaa-bbbb-cccc"]);
        let none = changed_since(index, Some("2026-10-17T02:55:38.500Z"));
        assert_eq!((none.newest, none.ids.len()), (None, 0));
    }

    #[test]
    fn base_urls_must_be_https_or_local() {
        assert!(check_base_url(DEFAULT_BASE_URL).is_ok());
        assert_eq!(
            check_base_url("http://127.0.0.1:8080/").unwrap(),
            "http://127.0.0.1:8080"
        );
        assert!(check_base_url("http://mirror.example.com").is_err());
        assert!(check_base_url("http://localhost.example.com").is_err());
        assert!(check_base_url("ftp://x").is_err());
    }
}
