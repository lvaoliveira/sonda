//! `GET /api/security`. Database tests skip without SONDA_TEST_DATABASE_URL
//! (see server.rs).

mod common;

use axum::http::StatusCode;
use common::{TestDb, get, state, upload, upload_json_for};
use serde_json::Value;
use sonda_server::{db, http};

#[tokio::test]
async fn security_summarizes_open_vulnerabilities() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    // First analysis: a clean file. Second: eval (a critical vulnerability)
    // in api/, plus a code smell that the screen ignores.
    for files in [
        &[("api/a.js", "let x = 1;\n")][..],
        &[("api/a.js", "var x = 1;\neval(x);\n")][..],
    ] {
        let (status, summary) =
            upload(&db, &upload_json_for(dir.path(), files, "payments", "main")).await;
        assert_eq!(status, StatusCode::CREATED, "{summary}");
    }
    let (status, body) = get(http::router(state(db.pool.clone()), None), "/api/security").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let s: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(s["open"], 1);
    assert_eq!(s["openBySeverity"]["critical"], 1);
    assert_eq!(s["newThisWeek"], 1);
    assert_eq!(s["projectsAffected"], 1);
    assert_eq!(s["focus"][0]["rule"], "js/no-eval");
    assert_eq!(s["focus"][0]["component"], "api");
    assert_eq!(s["projects"][0]["severe"], 1);
    assert_eq!(s["components"][0]["path"], "api");
    assert_eq!(s["rules"][0]["rule"], "js/no-eval");
    let trend = s["trend"].as_array().unwrap();
    assert_eq!(trend.len(), 12);
    assert_eq!(trend[11]["open"], 1);
    assert_eq!(trend[11]["weighted"], 5);
    assert_eq!(trend[11]["introduced"], 1);
    assert!(s["remediation"]["medianDaysSevere"].is_null());
    db.drop().await;
}
