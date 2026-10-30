//! The opt-in advisory sync, against a fake OSV served on localhost.
//! Database tests skip without SONDA_TEST_DATABASE_URL (see server.rs).

mod common;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::get;
use common::TestDb;
use serde_json::json;
use sonda_server::{advisory_sync, db};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct FakeOsv {
    /// "npm/modified_id.csv", "npm/GHSA-x.json", ...
    files: HashMap<String, String>,
    requests: Vec<String>,
}

type Shared = Arc<Mutex<FakeOsv>>;

async fn serve(
    State(osv): State<Shared>,
    Path((dir, file)): Path<(String, String)>,
) -> (StatusCode, String) {
    let key = format!("{dir}/{file}");
    let mut osv = osv.lock().unwrap();
    osv.requests.push(key.clone());
    match osv.files.get(&key) {
        Some(body) => (StatusCode::OK, body.clone()),
        None => (StatusCode::NOT_FOUND, String::new()),
    }
}

fn record(id: &str, modified: &str, ecosystem: &str, name: &str) -> String {
    json!({
        "id": id, "modified": modified, "summary": format!("{name} is vulnerable"),
        "affected": [{ "package": { "ecosystem": ecosystem, "name": name },
                       "ranges": [{ "type": "ECOSYSTEM", "events": [{ "introduced": "0" }, { "fixed": "9.0.0" }] }] }]
    })
    .to_string()
}

#[tokio::test]
async fn syncs_what_changed_and_retries_failures() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let osv: Shared = Arc::default();
    {
        let mut o = osv.lock().unwrap();
        o.files.insert(
            "npm/modified_id.csv".into(),
            "2026-10-02T00:00:00Z,GHSA-aaaa-aaaa-aaaa\n2026-10-01T00:00:00Z,MAL-2026-1\n".into(),
        );
        o.files.insert(
            "npm/GHSA-aaaa-aaaa-aaaa.json".into(),
            record(
                "GHSA-aaaa-aaaa-aaaa",
                "2026-10-02T00:00:00Z",
                "npm",
                "left-pad",
            ),
        );
        o.files.insert(
            "PyPI/modified_id.csv".into(),
            "2026-10-03T00:00:00Z,PYSEC-2026-1\n".into(),
        );
        o.files.insert(
            "PyPI/PYSEC-2026-1.json".into(),
            record("PYSEC-2026-1", "2026-10-03T00:00:00Z", "PyPI", "flask"),
        );
        o.files
            .insert("crates.io/modified_id.csv".into(), String::new());
    }
    let app = Router::new()
        .route("/{dir}/{file}", get(serve))
        .with_state(osv.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let s = advisory_sync::sync_once(&db.pool, &base).await.unwrap();
    assert_eq!((s.read, s.imported, s.errors), (2, 2, 0), "{s:?}");
    assert!(
        !osv.lock()
            .unwrap()
            .requests
            .iter()
            .any(|r| r.contains("MAL-")),
        "skipped databases' records aren't fetched"
    );
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM advisories")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(stored, 2);

    // Nothing new: nothing fetched.
    osv.lock().unwrap().requests.clear();
    let s = advisory_sync::sync_once(&db.pool, &base).await.unwrap();
    assert_eq!(s.read, 0);
    assert!(
        osv.lock()
            .unwrap()
            .requests
            .iter()
            .all(|r| r.ends_with("modified_id.csv"))
    );

    // A new record that can't be fetched yet: the watermark stays.
    osv.lock().unwrap().files.insert(
        "npm/modified_id.csv".into(),
        "2026-10-04T00:00:00Z,GHSA-bbbb-bbbb-bbbb\n2026-10-02T00:00:00Z,GHSA-aaaa-aaaa-aaaa\n"
            .into(),
    );
    let s = advisory_sync::sync_once(&db.pool, &base).await.unwrap();
    assert_eq!((s.read, s.errors), (1, 1), "{s:?}");
    let until: String =
        sqlx::query_scalar("SELECT synced_until FROM advisory_sync WHERE ecosystem = 'npm'")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(until, "2026-10-02T00:00:00Z");

    // Available on the next run.
    osv.lock().unwrap().files.insert(
        "npm/GHSA-bbbb-bbbb-bbbb.json".into(),
        record(
            "GHSA-bbbb-bbbb-bbbb",
            "2026-10-04T00:00:00Z",
            "npm",
            "debug",
        ),
    );
    let s = advisory_sync::sync_once(&db.pool, &base).await.unwrap();
    assert_eq!((s.read, s.imported, s.errors), (1, 1, 0), "{s:?}");
}
