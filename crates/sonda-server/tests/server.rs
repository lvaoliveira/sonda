//! Server tests. Those that need PostgreSQL run against a fresh database
//! created on the server named by SONDA_TEST_DATABASE_URL, and are skipped
//! when it is unset, unless SONDA_REQUIRE_DB_TESTS is set (as in CI), which
//! turns a missing database into a failure instead of a silent skip.

mod common;

use axum::http::StatusCode;
use common::{TestDb, get, state, unreachable_pool};
use sonda_server::{db, http};

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
            "advisories",
            "advisory_imports",
            "advisory_packages",
            "advisory_sync",
            "analyses",
            "analysis_dependencies",
            "analysis_files",
            "api_tokens",
            "dependency_review_events",
            "dependency_reviews",
            "issue_events",
            "issues",
            "new_code_resets",
            "project_rule_settings",
            "projects",
            "rule_settings",
            "sessions",
            "sign_in_failures",
            "sources",
            "users"
        ]
    );
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
}

#[tokio::test]
async fn health_is_ok_when_the_database_answers() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    let (status, body) = get(http::router(state(db.pool.clone()), None), "/api/health").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("ok"), "{body}");
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
