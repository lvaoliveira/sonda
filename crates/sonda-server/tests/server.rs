//! Server tests. Those that need PostgreSQL run against a fresh database
//! created on the server named by SONDA_TEST_DATABASE_URL, and are skipped
//! when it is unset, unless SONDA_REQUIRE_DB_TESTS is set (as in CI), which
//! turns a missing database into a failure instead of a silent skip.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use sonda_server::config::Token;
use sonda_server::{db, http};
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use tower::ServiceExt;

struct TestDb {
    pool: PgPool,
    admin: PgPool,
    name: String,
}

impl TestDb {
    async fn new() -> Option<Self> {
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
        let admin = PgPool::connect(&url).await.expect("test database server");
        // Safe to splice: `name` is built above from the process id and a
        // counter only. (Identifiers cannot be bound as parameters.)
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&admin)
            .await
            .unwrap();
        let options = PgConnectOptions::from_str(&url).unwrap().database(&name);
        let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
        Some(Self { pool, admin, name })
    }

    async fn drop(self) {
        self.pool.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP DATABASE {} WITH (FORCE)",
            self.name
        )))
        .execute(&self.admin)
        .await
        .unwrap();
    }
}

fn state(pool: PgPool) -> http::State {
    http::State {
        pool,
        token: Arc::new(Token::new("0123456789abcdef0123456789abcdef").unwrap()),
    }
}

async fn get(app: axum::Router, path: &str) -> (StatusCode, String) {
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
fn unreachable_pool() -> PgPool {
    let options = PgConnectOptions::new().host("127.0.0.1").port(1);
    PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(200))
        .connect_lazy_with(options)
}

#[tokio::test]
async fn migrations_create_the_schema_and_rerun_cleanly() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    db::migrate(&db.pool).await.unwrap();
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT table_name::text FROM information_schema.tables
         WHERE table_schema = 'public' AND table_name NOT LIKE '\\_sqlx%'
         ORDER BY table_name",
    )
    .fetch_all(&db.pool)
    .await
    .unwrap();
    assert_eq!(
        tables,
        [
            "analyses",
            "analysis_files",
            "issue_events",
            "issues",
            "projects",
            "sources"
        ]
    );
    db.drop().await;
}

#[tokio::test]
async fn the_schema_rejects_invalid_data() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    for key in ["../x", "-x", "", "a b"] {
        let insert = sqlx::query("INSERT INTO projects (key) VALUES ($1)")
            .bind(key)
            .execute(&db.pool)
            .await;
        assert!(insert.is_err(), "accepted project key {key:?}");
    }
    let bad_digest = sqlx::query("INSERT INTO sources (sha256, content) VALUES ($1, '')")
        .bind(vec![0u8; 31])
        .execute(&db.pool)
        .await;
    assert!(bad_digest.is_err(), "accepted a 31-byte sha256");
    db.drop().await;
}

#[tokio::test]
async fn health_is_ok_when_the_database_answers() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    let (status, body) = get(http::router(state(db.pool.clone()), None), "/api/health").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("ok"), "{body}");
    db.drop().await;
}

#[tokio::test]
async fn health_is_503_when_the_database_is_down() {
    let (status, _) = get(http::router(state(unreachable_pool()), None), "/api/health").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn the_web_app_is_served_but_never_for_api_paths() {
    let web = tempfile::tempdir().unwrap();
    std::fs::write(web.path().join("index.html"), "<!doctype html>app").unwrap();
    std::fs::write(web.path().join("app.js"), "console.log(1)").unwrap();
    let app = || http::router(state(unreachable_pool()), Some(web.path()));

    assert_eq!(
        get(app(), "/app.js").await,
        (StatusCode::OK, "console.log(1)".into())
    );
    // Client-side routes get index.html.
    let (status, body) = get(app(), "/issues").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("app"), "{body}");
    // A mistyped API path must not look like success.
    let (status, body) = get(app(), "/api/isues").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(!body.contains("doctype"), "{body}");
    // Paths cannot escape the web directory.
    let (status, _) = get(app(), "/../Cargo.toml").await;
    assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR);
    let (_, body) = get(app(), "/..%2fCargo.toml").await;
    assert!(!body.contains("[package]"), "{body}");
}
