//! Request ids and request logs (ADR-0019).

use axum::extract::{MatchedPath, Request};
use axum::http::{HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;
use std::time::Instant;
use tracing::Instrument;

/// The header that carries a request's id, both in and out.
pub const REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

const MAX_REQUEST_ID_LEN: usize = 64;

/// Middleware: runs the request in a `request` span with its id, method and
/// route template, logs one line when it completes, and returns the id in
/// `x-request-id`. Never logs the path, query or headers, which carry
/// project keys, search text and tokens.
pub async fn log_request(request: Request, next: Next) -> Response {
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
        .map(|p| p.as_str().to_owned());
    let quiet =
        !request.uri().path().starts_with("/api/") || route.as_deref() == Some("/api/health");
    // At error level, so the span (and with it the id on every line) stays
    // enabled whenever errors are logged, even with RUST_LOG=sonda=warn.
    let span = tracing::error_span!(
        "request",
        id = %id,
        method = %method,
        route = %route.as_deref().unwrap_or("-"),
    );
    let started = Instant::now();
    let mut response = next.run(request).instrument(span.clone()).await;
    let failed = response.status().is_server_error();
    let status = response.status().as_u16();
    let duration_ms = (started.elapsed().as_secs_f64() * 10_000.0).round() / 10.0;
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
    use std::sync::{Arc, Mutex};
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
            .layer(axum::middleware::from_fn(log_request))
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
}
