# ADR-0019: Observability for the server

- Status: **proposed**
- Date: 2026-11-01
- Builds on ADR-0005 (the sonda server) and ADR-0009 (the advisory sync)

## Context

`sonda-server` writes plain-text `tracing` logs, filtered by `RUST_LOG`, and
has `GET /api/health`, which pings PostgreSQL (two-second timeout) and
answers 503 when it doesn't answer. Docker Compose and load balancers use
it.

Nothing else is visible from outside the process:

- No request is logged unless it fails with an internal error, and that
  error line can't be tied to the request that caused it, nor to the
  response a user saw.
- Logs are text only, which log collectors (Loki, CloudWatch, Elastic)
  have to parse with a regex.
- There are no numbers: how many uploads, how long they take, how close the
  database pool is to full, whether the daily advisory sync last succeeded.

So a slow upload or an advisory sync that keeps failing is noticed only
when someone reads the logs or a user complains.

## Decision

### Request ids

Every request gets an id, returned in the `x-request-id` response header.
An incoming `x-request-id` is kept when it is 1 to 64 characters from
`A-Z a-z 0-9 . _ -`, so a reverse proxy's id (nginx's `$request_id`, a
load balancer's trace header) ties its logs to sonda's. Anything else is
replaced by 16 random bytes in hex, so a client can't put newlines,
control characters or a megabyte of text into the logs. A client can still
reuse another request's id. That only confuses log correlation, which is
all the id is for: it is never an authorization input.

### Request logs

Each request runs inside a `request` span with `id`, `method` and `route`,
so every log line written while handling it, including `internal error`,
carries the id. When it completes, one line records `status` and
`duration_ms`.

- **The route is the template, never the path**: `/api/projects/{key}`,
  not `/api/projects/payments`. Paths and query strings carry project keys,
  file paths and search text. The template carries none of that. Unmatched
  paths log as `-`.
- **Headers are never logged.** They carry tokens and session cookies.
- **Levels:** `warn` for 5xx, `info` for other API requests, `debug` for
  the web app's static files and for `/api/health`, which a load balancer
  calls every few seconds.

This is a short axum middleware, not `tower-http`'s
`TraceLayer` and `RequestIdLayer`. Those need two more `tower-http`
features and the `uuid` crate, and still need custom code for the route
template, the id rules and the levels above. So the middleware is no
bigger than configuring them would be.

### JSON logs, opt-in

`SONDA_LOG_FORMAT=json` writes one JSON object per line: the event's
fields at the top level, plus the current span's (`id`, `method`,
`route`). `text`, the default, keeps today's format. Any other value is a
startup error, as with every other setting. This needs `tracing-subscriber`'s
`json` feature, which adds only `tracing-serde` (tokio-rs, MIT). `serde` and
`serde_json` are already dependencies.

### Health stays as it is

`GET /api/health` is already a readiness check. There's no separate
liveness endpoint. A Kubernetes liveness probe that fails while PostgreSQL
is down would restart a healthy server, but sonda ships for Docker
Compose, and a liveness probe can use the TCP port instead.

### Prometheus metrics, on their own listener

`SONDA_METRICS_LISTEN` (unset by default, so off) starts a second listener
that serves `GET /metrics` in the Prometheus text format, and nothing else.

- **Not on the API port.** On the public listener, metrics would need
  authentication, or would show anyone the request rates and project
  activity. A separate address, `127.0.0.1:9090` or a port only the
  compose network sees, needs neither, as with PostgreSQL itself.
- **Metrics:**
  - `sonda_http_requests_total{method, route, status}` and
    `sonda_http_request_duration_seconds{method, route}` (histogram), from
    the request middleware above.
  - `sonda_uploads_total{result}` and `sonda_upload_duration_seconds`
    (histogram), from parsing the upload to storing the analysis.
  - `sonda_db_pool_connections{state="idle"|"in_use"}` and
    `sonda_db_pool_max_connections`, read from the pool at scrape time.
  - `sonda_advisory_sync_runs_total{result}`,
    `sonda_advisory_sync_last_success_timestamp_seconds` and
    `sonda_advisory_sync_advisories_imported_total`.
- **Labels are bounded.** `route` is the template and `status` the code,
  so the number of time series has a fixed upper bound. Project keys,
  branches and users never become labels: projects are created by
  uploads, so labels from them could grow without limit.
- **The crate:** `prometheus-client`, the Prometheus project's own Rust
  client (Apache-2.0). It is small, with no HTTP stack of its own. sonda
  already has axum, so it only needs the text encoder. `metrics` with
  `metrics-exporter-prometheus` was the alternative. It brings its own
  hyper server and global registry, and its default features add more
  dependencies than the crate saves.

### Not now: OpenTelemetry traces

The server is one process with one dependency, PostgreSQL. A trace would
show the same spans as the request logs with their ids, plus `sqlx`'s
queries, which `RUST_LOG=sqlx=info` already logs. The OpenTelemetry SDK
and OTLP exporter are the biggest dependency tree considered here
(`opentelemetry`, `opentelemetry_sdk`, `opentelemetry-otlp` with `tonic`
or an HTTP client). They also make the server connect out by default,
which the advisory sync (ADR-0009) is careful never to do. Revisit when
sonda-server calls other services of its own, or when someone running it
needs to see its spans in an existing tracing backend.

## Increments

1. Request ids, request logs, `SONDA_LOG_FORMAT`.
2. The metrics listener, with the request metrics.
3. Upload, pool and advisory sync metrics.

Each ships with its docs in `docs/server.md` (Configuration) and a
changelog entry.

## Consequences

- An error a user reports can be found in the logs by the `x-request-id`
  their browser received.
- Log volume grows by one `info` line per API request. `RUST_LOG=sonda=warn`
  removes the request lines and keeps 5xx and errors.
- Metrics cost nothing unless `SONDA_METRICS_LISTEN` is set. When it is, the
  operator decides who can reach that address.
- Request logs and labels use route templates, so adding a route changes
  what appears in logs and metrics. Renaming one breaks dashboards that
  query it by name, as renaming an API path breaks clients.
