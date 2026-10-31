//! Helpers shared by the server's integration tests. Each test binary uses
//! a different subset.
#![allow(dead_code)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use flate2::Compression;
use flate2::write::GzEncoder;
use serde_json::Value;
use sonda_core::upload::{self, Meta};
use sonda_core::{Isolation, ScanOptions, report};
use sonda_server::config::Token;
use sonda_server::http;
use sqlx::Connection;
use sqlx::postgres::{PgConnectOptions, PgConnection, PgPool, PgPoolOptions};
use std::io::Write;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use tower::ServiceExt;

/// A database of its own for one test, dropped when the test ends, failed
/// tests included.
pub struct TestDb {
    pub pool: PgPool,
    url: String,
    name: String,
}

impl TestDb {
    pub async fn new() -> Option<Self> {
        let Ok(url) = std::env::var("SONDA_TEST_DATABASE_URL") else {
            assert!(
                std::env::var_os("SONDA_REQUIRE_DB_TESTS").is_none(),
                "SONDA_REQUIRE_DB_TESTS is set but SONDA_TEST_DATABASE_URL is not"
            );
            eprintln!("skipped: set SONDA_TEST_DATABASE_URL to run database tests");
            return None;
        };
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let name = format!(
            "sonda_test_{}_{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let mut admin = PgConnection::connect(&url)
            .await
            .expect("test database server");
        // Safe to splice: `name` is built above from the process id and a
        // counter only. (Identifiers cannot be bound as parameters.)
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&mut admin)
            .await
            .unwrap();
        let options = PgConnectOptions::from_str(&url).unwrap().database(&name);
        let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
        Some(Self { pool, url, name })
    }
}

impl Drop for TestDb {
    /// `Drop` can't await, and the pool's connections belong to the test's
    /// runtime, which this blocks: drop the database from a thread with a
    /// runtime and a connection of its own. `WITH (FORCE)` ends the pool's
    /// connections. Errors are ignored, since this also runs while a failed
    /// test unwinds.
    fn drop(&mut self) {
        let (url, name) = (self.url.clone(), self.name.clone());
        let _ = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            runtime.block_on(async {
                let mut admin = PgConnection::connect(&url).await?;
                sqlx::query(sqlx::AssertSqlSafe(format!(
                    "DROP DATABASE IF EXISTS {name} WITH (FORCE)"
                )))
                .execute(&mut admin)
                .await?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            })
        })
        .join();
    }
}

/// Reads open, as on a loopback-only server.
pub fn state(pool: PgPool) -> http::State {
    state_with(pool, false)
}

pub fn state_with(pool: PgPool, reads_require_auth: bool) -> http::State {
    http::State {
        pool,
        token: Some(Arc::new(Token::new(TOKEN).unwrap())),
        reads_require_auth,
    }
}

pub async fn get(app: axum::Router, path: &str) -> (StatusCode, String) {
    let response = app
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

/// A pool that never connects: for tests that need no database.
pub fn unreachable_pool() -> PgPool {
    let options = PgConnectOptions::new().host("127.0.0.1").port(1);
    PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(200))
        .connect_lazy_with(options)
}

pub const TOKEN: &str = "0123456789abcdef0123456789abcdef";

/// What `sonda upload` would send for `files`, as plain JSON.
pub fn upload_json(dir: &Path, files: &[(&str, &str)], branch: &str) -> Value {
    upload_json_for(dir, files, "payments", branch)
}

/// As `upload_json`, for any project. An `lcov.info` among `files` is
/// passed as `--coverage`.
pub fn upload_json_for(dir: &Path, files: &[(&str, &str)], project: &str, branch: &str) -> Value {
    for (path, content) in files {
        let full = dir.join(path);
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(full, content).unwrap();
    }
    let options = ScanOptions {
        root: dir.to_path_buf(),
        isolation: Isolation::InProcess,
        coverage: files
            .iter()
            .filter(|(p, _)| p.ends_with("lcov.info"))
            .map(|(p, _)| dir.join(p))
            .collect(),
        ..Default::default()
    };
    let config = sonda_core::config::Config::default();
    let outcome = sonda_core::run(&options, &config).unwrap();
    let json = report::render(&report::build(&outcome, false), report::Format::Json);
    let meta = Meta {
        project: project.into(),
        branch: branch.into(),
        commit: "0123abc".into(),
        version: None,
    };
    serde_json::to_value(upload::prepare(json.as_bytes(), dir, meta).unwrap()).unwrap()
}

pub fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut e = GzEncoder::new(Vec::new(), Compression::fast());
    e.write_all(bytes).unwrap();
    e.finish().unwrap()
}

pub async fn post(app: axum::Router, token: Option<&str>, body: Vec<u8>) -> (StatusCode, Value) {
    let mut request = Request::post("/api/analyses")
        .header("Content-Type", "application/json")
        .header("Content-Encoding", "gzip");
    if let Some(t) = token {
        request = request.header("Authorization", format!("Bearer {t}"));
    }
    let response = app
        .oneshot(request.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

pub async fn upload(db: &TestDb, body: &Value) -> (StatusCode, Value) {
    let app = http::router(state(db.pool.clone()), None);
    post(app, Some(TOKEN), gzip(&serde_json::to_vec(body).unwrap())).await
}

/// The password every test user gets.
pub const PASSWORD: &str = "correct horse battery";

pub async fn create_user(db: &TestDb, username: &str, role: &str) -> i64 {
    sonda_server::users::create(&db.pool, username, username, role, Some(PASSWORD))
        .await
        .unwrap()
        .id
}

/// Signs in; returns the session cookie as a browser sends it back.
pub async fn sign_in(app: &axum::Router, username: &str, password: &str) -> Option<String> {
    let request = Request::post("/api/session")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "username": username, "password": password }).to_string(),
        ))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    response
        .headers()
        .get("set-cookie")
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_string())
}
