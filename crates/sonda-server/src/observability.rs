//! Request ids, request logs and metrics (ADR-0019).

use axum::extract::{MatchedPath, Request, State};
use axum::http::{HeaderName, HeaderValue, Method};
use axum::middleware::Next;
use axum::response::Response;
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::{Registry, Unit};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{Instant, SystemTime};
use tracing::Instrument;

/// The header that carries a request's id, both in and out.
pub const REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

const MAX_REQUEST_ID_LEN: usize = 64;

/// Request durations, in seconds: up to the 30-second request timeout.
const DURATION_BUCKETS: [f64; 12] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
];

/// Upload durations, in seconds: an upload also refreshes new code and
/// gates, and has the same 30-second timeout.
const UPLOAD_BUCKETS: [f64; 10] = [0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 20.0, 30.0];

/// What the server counts, served by `GET /metrics` on the metrics listener.
/// Labels are bounded: route templates, a fixed set of methods, status
/// codes and results, never project keys, branches or users.
pub struct Metrics {
    registry: Registry,
    requests: Family<RequestLabels, Counter>,
    durations: Family<RouteLabels, Histogram>,
    uploads: Family<ResultLabels, Counter>,
    upload_durations: Histogram,
    pool_connections: Family<PoolLabels, Gauge>,
    pool_max_connections: Gauge,
    advisory_syncs: Family<ResultLabels, Counter>,
    advisory_sync_last_success: Gauge<f64, AtomicU64>,
    advisories_imported: Counter,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct RequestLabels {
    method: &'static str,
    route: String,
    status: u16,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct RouteLabels {
    method: &'static str,
    route: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ResultLabels {
    result: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct PoolLabels {
    state: &'static str,
}

/// How an upload ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UploadResult {
    Stored,
    /// Refused as sent: invalid, too large, a token for another project.
    Rejected,
    /// An internal error.
    Failed,
}

impl UploadResult {
    fn label(self) -> &'static str {
        match self {
            Self::Stored => "stored",
            Self::Rejected => "rejected",
            Self::Failed => "failed",
        }
    }
}

const UPLOAD_RESULTS: [&str; 4] = ["stored", "rejected", "failed", "cancelled"];
const SYNC_RESULTS: [&str; 3] = ["ok", "record_errors", "failed"];

/// An upload being handled. Dropped without `finish`, it counts as
/// `cancelled`: the request timed out, or the client went away.
pub struct Upload {
    metrics: Arc<Metrics>,
    started: Instant,
    finished: bool,
}

impl Upload {
    pub fn finish(mut self, result: UploadResult) {
        self.finished = true;
        self.metrics.count(&self.metrics.uploads, result.label());
        if result == UploadResult::Stored {
            self.metrics
                .upload_durations
                .observe(self.started.elapsed().as_secs_f64());
        }
    }
}

impl Drop for Upload {
    fn drop(&mut self) {
        if !self.finished {
            self.metrics.count(&self.metrics.uploads, "cancelled");
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        let mut registry = Registry::with_prefix("sonda");
        let requests = Family::<RequestLabels, Counter>::default();
        let durations = Family::<RouteLabels, Histogram>::new_with_constructor(
            (|| Histogram::new(DURATION_BUCKETS)) as fn() -> Histogram,
        );
        let uploads = Family::<ResultLabels, Counter>::default();
        let upload_durations = Histogram::new(UPLOAD_BUCKETS);
        let pool_connections = Family::<PoolLabels, Gauge>::default();
        let pool_max_connections = Gauge::default();
        let advisory_syncs = Family::<ResultLabels, Counter>::default();
        let advisory_sync_last_success = Gauge::<f64, AtomicU64>::default();
        let advisories_imported = Counter::default();
        // Every result from the start, at zero, so rate() and alerts on a
        // result work before it first happens.
        for result in UPLOAD_RESULTS {
            drop(uploads.get_or_create(&ResultLabels { result }));
        }
        for result in SYNC_RESULTS {
            drop(advisory_syncs.get_or_create(&ResultLabels { result }));
        }
        registry.register(
            "http_requests",
            "HTTP requests completed, by method, route template and status",
            requests.clone(),
        );
        registry.register_with_unit(
            "http_request_duration",
            "Time to answer an HTTP request, by method and route template",
            Unit::Seconds,
            durations.clone(),
        );
        registry.register(
            "uploads",
            "Analyses uploaded, by result: stored, rejected, failed, or cancelled (timed out or the client went away)",
            uploads.clone(),
        );
        registry.register_with_unit(
            "upload_duration",
            "Time to store an analysis, for uploads stored",
            Unit::Seconds,
            upload_durations.clone(),
        );
        registry.register(
            "db_pool_connections",
            "Database connections open, idle or in use",
            pool_connections.clone(),
        );
        registry.register(
            "db_pool_max_connections",
            "The most database connections the pool opens",
            pool_max_connections.clone(),
        );
        registry.register(
            "advisory_sync_runs",
            "Daily advisory syncs, by result: ok, record_errors (some records failed), or failed",
            advisory_syncs.clone(),
        );
        registry.register(
            "advisory_sync_last_success_timestamp_seconds",
            "When an advisory sync last completed, as a Unix time; 0 before the first",
            advisory_sync_last_success.clone(),
        );
        registry.register(
            "advisory_sync_advisories_imported",
            "Advisories new or updated by the daily sync",
            advisories_imported.clone(),
        );
        Self {
            registry,
            requests,
            durations,
            uploads,
            upload_durations,
            pool_connections,
            pool_max_connections,
            advisory_syncs,
            advisory_sync_last_success,
            advisories_imported,
        }
    }
}

impl Metrics {
    fn record_request(&self, method: &Method, route: &str, status: u16, seconds: f64) {
        let method = method_label(method);
        let route = route.to_owned();
        self.durations
            .get_or_create(&RouteLabels {
                method,
                route: route.clone(),
            })
            .observe(seconds);
        self.requests
            .get_or_create(&RequestLabels {
                method,
                route,
                status,
            })
            .inc();
    }

    fn count(&self, family: &Family<ResultLabels, Counter>, result: &'static str) {
        family.get_or_create(&ResultLabels { result }).inc();
    }

    /// Starts timing an upload; see `Upload`.
    pub fn start_upload(self: &Arc<Self>) -> Upload {
        Upload {
            metrics: self.clone(),
            started: Instant::now(),
            finished: false,
        }
    }

    /// The database pool as it is now; read when metrics are scraped.
    pub fn observe_pool(&self, open: u32, idle: usize, max: u32) {
        let idle = i64::try_from(idle).unwrap_or(i64::MAX);
        let in_use = (i64::from(open) - idle).max(0);
        self.pool_connections
            .get_or_create(&PoolLabels { state: "idle" })
            .set(idle);
        self.pool_connections
            .get_or_create(&PoolLabels { state: "in_use" })
            .set(in_use);
        self.pool_max_connections.set(i64::from(max));
    }

    /// One run of the server's daily advisory sync: its summary, or `None`
    /// when it failed.
    pub fn record_advisory_sync(&self, summary: Option<&crate::advisories::ImportSummary>) {
        let Some(summary) = summary else {
            self.count(&self.advisory_syncs, "failed");
            return;
        };
        let result = if summary.errors == 0 {
            "ok"
        } else {
            "record_errors"
        };
        self.count(&self.advisory_syncs, result);
        self.advisories_imported.inc_by(summary.imported as u64);
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0.0, |d| d.as_secs_f64());
        self.advisory_sync_last_success.set(now);
    }

    /// The OpenMetrics text format, which Prometheus reads.
    pub fn encode(&self) -> Result<String, std::fmt::Error> {
        let mut text = String::new();
        prometheus_client::encoding::text::encode(&mut text, &self.registry)?;
        Ok(text)
    }
}

/// A client can send any method token; anything but the standard ones
/// becomes `other`, so they can't create series without limit.
fn method_label(method: &Method) -> &'static str {
    match *method {
        Method::GET => "GET",
        Method::HEAD => "HEAD",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::PATCH => "PATCH",
        Method::DELETE => "DELETE",
        Method::OPTIONS => "OPTIONS",
        _ => "other",
    }
}

/// Middleware: runs the request in a `request` span with its id, method and
/// route template, logs one line when it completes, counts it in `metrics`,
/// and returns the id in `x-request-id`. Never logs the path, query or
/// headers, which carry project keys, search text and tokens.
pub async fn log_request(
    State(metrics): State<Arc<Metrics>>,
    request: Request,
    next: Next,
) -> Response {
    let id = request
        .headers()
        .get(&REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .filter(|v| valid_request_id(v))
        .map_or_else(new_request_id, str::to_owned);
    let method = request.method().clone();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map_or_else(|| "-".to_owned(), |p| p.as_str().to_owned());
    let quiet = !request.uri().path().starts_with("/api/") || route == "/api/health";
    // At error level, so the span (and with it the id on every line) stays
    // enabled whenever errors are logged, even with RUST_LOG=sonda=warn.
    let span = tracing::error_span!(
        "request",
        id = %id,
        method = %method,
        route = %route,
    );
    let started = Instant::now();
    let mut response = next.run(request).instrument(span.clone()).await;
    let failed = response.status().is_server_error();
    let status = response.status().as_u16();
    let seconds = started.elapsed().as_secs_f64();
    metrics.record_request(&method, &route, status, seconds);
    let duration_ms = (seconds * 10_000.0).round() / 10.0;
    span.in_scope(|| {
        if failed {
            tracing::warn!(status, duration_ms, "request failed");
        } else if quiet {
            tracing::debug!(status, duration_ms, "request");
        } else {
            tracing::info!(status, duration_ms, "request");
        }
    });
    // Checked by valid_request_id or made of hex digits, so always a valid
    // header value; the fallback only guards that invariant.
    let value = HeaderValue::from_str(&id).unwrap_or(HeaderValue::from_static("-"));
    response.headers_mut().insert(REQUEST_ID, value);
    response
}

/// An incoming id worth keeping: short, and only characters that can't
/// break a log line or a header.
fn valid_request_id(id: &str) -> bool {
    (1..=MAX_REQUEST_ID_LEN).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn new_request_id() -> String {
    let mut bytes = [0u8; 16];
    // The OS random source; failing it is not recoverable.
    getrandom::fill(&mut bytes).expect("the operating system's random source");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::http::StatusCode;
    use axum::routing::get;
    use std::sync::Mutex;
    use tower::ServiceExt;

    #[derive(Clone, Default)]
    struct Logs(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Logs {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn app() -> Router {
        app_with(Arc::new(Metrics::default()))
    }

    fn app_with(metrics: Arc<Metrics>) -> Router {
        Router::new()
            .route("/api/projects/{key}", get(|| async { "ok" }))
            .route("/api/health", get(|| async { "ok" }))
            .route(
                "/api/boom",
                get(|| async {
                    tracing::error!("internal error");
                    StatusCode::INTERNAL_SERVER_ERROR
                }),
            )
            .layer(axum::middleware::from_fn_with_state(metrics, log_request))
    }

    /// Sends one request through `app` and returns the response's request
    /// id and what was logged at `level`.
    async fn send(request: axum::http::Request<Body>, level: tracing::Level) -> (String, String) {
        let logs = Logs::default();
        let writer = logs.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(level)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let response = app().oneshot(request).await.unwrap();
        let id = response.headers()[&REQUEST_ID].to_str().unwrap().to_owned();
        let logs = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
        (id, logs)
    }

    fn request(path: &str) -> axum::http::request::Builder {
        axum::http::Request::get(path)
    }

    #[tokio::test]
    async fn logs_the_route_template_never_the_path_query_or_headers() {
        let (id, logs) = send(
            request("/api/projects/payments?q=secret-search")
                .header("authorization", "Bearer sonda_token_value")
                .body(Body::empty())
                .unwrap(),
            tracing::Level::INFO,
        )
        .await;
        assert_eq!(id.len(), 32, "{id}");
        assert!(id.bytes().all(|b| b.is_ascii_hexdigit()), "{id}");
        assert!(logs.contains(&format!("id={id}")), "{logs}");
        assert!(logs.contains("method=GET"), "{logs}");
        assert!(logs.contains("route=/api/projects/{key}"), "{logs}");
        assert!(logs.contains("status=200"), "{logs}");
        assert!(logs.contains("duration_ms="), "{logs}");
        for leaked in ["payments", "secret-search", "sonda_token_value"] {
            assert!(!logs.contains(leaked), "{leaked} in {logs}");
        }
    }

    #[tokio::test]
    async fn a_well_formed_incoming_id_is_kept() {
        let (id, logs) = send(
            request("/api/projects/p")
                .header("x-request-id", "nginx-4f2a.b_9")
                .body(Body::empty())
                .unwrap(),
            tracing::Level::INFO,
        )
        .await;
        assert_eq!(id, "nginx-4f2a.b_9");
        assert!(logs.contains("id=nginx-4f2a.b_9"), "{logs}");
    }

    #[tokio::test]
    async fn other_incoming_ids_are_replaced() {
        let too_long = "a".repeat(MAX_REQUEST_ID_LEN + 1);
        for bad in ["", "two words", "a\"b", "id%0A", too_long.as_str()] {
            let (id, logs) = send(
                request("/api/projects/p")
                    .header("x-request-id", bad)
                    .body(Body::empty())
                    .unwrap(),
                tracing::Level::INFO,
            )
            .await;
            assert_eq!(id.len(), 32, "{bad:?} gave {id}");
            assert_ne!(id, bad);
            assert!(!logs.contains(&format!("id={bad} ")), "{logs}");
        }
    }

    #[tokio::test]
    async fn errors_inside_a_request_carry_its_id() {
        let (id, logs) = send(
            request("/api/boom").body(Body::empty()).unwrap(),
            tracing::Level::WARN,
        )
        .await;
        let lines: Vec<&str> = logs.lines().collect();
        assert_eq!(lines.len(), 2, "{logs}");
        assert!(lines[0].contains("ERROR") && lines[0].contains("internal error"));
        assert!(lines[1].contains("WARN") && lines[1].contains("status=500"));
        for line in lines {
            assert!(line.contains(&format!("id={id}")), "{line}");
        }
    }

    #[tokio::test]
    async fn health_checks_and_unmatched_paths_log_at_debug() {
        for path in ["/api/health", "/assets/index.js"] {
            let (_, logs) = send(
                request(path).body(Body::empty()).unwrap(),
                tracing::Level::INFO,
            )
            .await;
            assert_eq!(logs, "", "{path}");
            let (_, logs) = send(
                request(path).body(Body::empty()).unwrap(),
                tracing::Level::DEBUG,
            )
            .await;
            assert!(logs.contains("DEBUG"), "{path}: {logs}");
        }
        let (_, logs) = send(
            request("/no/such/page").body(Body::empty()).unwrap(),
            tracing::Level::DEBUG,
        )
        .await;
        assert!(
            logs.contains("route=-") && logs.contains("status=404"),
            "{logs}"
        );
        assert!(!logs.contains("/no/such/page"), "{logs}");
    }

    #[tokio::test]
    async fn requests_are_counted_by_method_route_template_and_status() {
        let metrics = Arc::new(Metrics::default());
        for (method, path) in [
            ("GET", "/api/projects/payments"),
            ("GET", "/api/projects/billing"),
            ("GET", "/api/boom"),
            ("BREW", "/api/projects/payments"),
            ("GET", "/no/such/page"),
        ] {
            let request = axum::http::Request::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .unwrap();
            app_with(metrics.clone()).oneshot(request).await.unwrap();
        }
        let text = metrics.encode().unwrap();
        for line in [
            r#"sonda_http_requests_total{method="GET",route="/api/projects/{key}",status="200"} 2"#,
            r#"sonda_http_requests_total{method="GET",route="/api/boom",status="500"} 1"#,
            r#"sonda_http_requests_total{method="other",route="/api/projects/{key}",status="405"} 1"#,
            r#"sonda_http_requests_total{method="GET",route="-",status="404"} 1"#,
            r#"sonda_http_request_duration_seconds_count{method="GET",route="/api/projects/{key}"} 2"#,
            r#"sonda_http_request_duration_seconds_bucket{le="30.0",method="GET",route="/api/projects/{key}"} 2"#,
        ] {
            assert!(text.contains(line), "{line} not in\n{text}");
        }
        for leaked in ["payments", "billing", "BREW", "/no/such/page"] {
            assert!(!text.contains(leaked), "{leaked} in\n{text}");
        }
    }

    fn lines(metrics: &Metrics) -> String {
        metrics.encode().unwrap()
    }

    #[test]
    fn every_upload_and_sync_result_starts_at_zero() {
        let text = lines(&Metrics::default());
        for result in UPLOAD_RESULTS {
            let line = format!("sonda_uploads_total{{result=\"{result}\"}} 0");
            assert!(text.contains(&line), "{line} not in\n{text}");
        }
        for result in SYNC_RESULTS {
            let line = format!("sonda_advisory_sync_runs_total{{result=\"{result}\"}} 0");
            assert!(text.contains(&line), "{line} not in\n{text}");
        }
        assert!(
            text.contains("sonda_advisory_sync_last_success_timestamp_seconds 0.0"),
            "{text}"
        );
    }

    #[test]
    fn an_upload_dropped_before_it_finishes_counts_as_cancelled() {
        let metrics = Arc::new(Metrics::default());
        metrics.start_upload().finish(UploadResult::Stored);
        metrics.start_upload().finish(UploadResult::Rejected);
        metrics.start_upload().finish(UploadResult::Failed);
        drop(metrics.start_upload());
        let text = lines(&metrics);
        for result in UPLOAD_RESULTS {
            let line = format!("sonda_uploads_total{{result=\"{result}\"}} 1");
            assert!(text.contains(&line), "{line} not in\n{text}");
        }
        // Only stored uploads are timed.
        assert!(
            text.contains("sonda_upload_duration_seconds_count 1"),
            "{text}"
        );
    }

    #[test]
    fn the_pool_is_split_into_idle_and_in_use() {
        let metrics = Metrics::default();
        metrics.observe_pool(7, 3, 10);
        let text = lines(&metrics);
        for line in [
            r#"sonda_db_pool_connections{state="idle"} 3"#,
            r#"sonda_db_pool_connections{state="in_use"} 4"#,
            "sonda_db_pool_max_connections 10",
        ] {
            assert!(text.contains(line), "{line} not in\n{text}");
        }
        // The pool's counts are read one after the other, so idle can
        // briefly exceed open; in use never goes negative.
        metrics.observe_pool(2, 3, 10);
        assert!(lines(&metrics).contains(r#"sonda_db_pool_connections{state="in_use"} 0"#));
    }

    #[test]
    fn advisory_syncs_are_counted_by_result() {
        use crate::advisories::ImportSummary;
        let metrics = Metrics::default();
        metrics.record_advisory_sync(Some(&ImportSummary {
            imported: 5,
            ..ImportSummary::default()
        }));
        metrics.record_advisory_sync(Some(&ImportSummary {
            imported: 2,
            errors: 1,
            ..ImportSummary::default()
        }));
        metrics.record_advisory_sync(None);
        let text = lines(&metrics);
        for line in [
            r#"sonda_advisory_sync_runs_total{result="ok"} 1"#,
            r#"sonda_advisory_sync_runs_total{result="record_errors"} 1"#,
            r#"sonda_advisory_sync_runs_total{result="failed"} 1"#,
            "sonda_advisory_sync_advisories_imported_total 7",
        ] {
            assert!(text.contains(line), "{line} not in\n{text}");
        }
        assert!(
            !text.contains("sonda_advisory_sync_last_success_timestamp_seconds 0.0"),
            "{text}"
        );
    }
}
