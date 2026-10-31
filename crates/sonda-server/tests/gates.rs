//! `GET /api/gates`. Database tests skip without SONDA_TEST_DATABASE_URL
//! (see server.rs).

mod common;

use axum::http::StatusCode;
use common::{TestDb, get, state, upload, upload_json_for};
use serde_json::Value;
use sonda_server::{db, http};

#[tokio::test]
async fn projects_on_the_default_gate_are_recognized() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    // payments' first analysis is clean and starts its new code period
    // (ADR-0011); its second adds a vulnerability, which is then new.
    for (project, src) in [
        ("payments", "let x = 1;\n"),
        ("payments", "eval(x);\n"),
        ("docs", "let y = 1;\n"),
    ] {
        let (status, summary) = upload(
            &db,
            &upload_json_for(dir.path(), &[("a.js", src)], project, "main"),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{summary}");
    }
    let (status, body) = get(http::router(state(db.pool.clone()), None), "/api/gates").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let g: Value = serde_json::from_str(&body).unwrap();
    let gates = g["gates"].as_array().unwrap();
    // The uploads used sonda's default sonda.toml gate: one gate, recognized.
    assert_eq!(gates.len(), 1, "{g}");
    assert_eq!(gates[0]["name"], "Default");
    assert_eq!(gates[0]["isDefault"], true);
    assert_eq!(gates[0]["projects"].as_array().unwrap().len(), 2);
    assert_eq!(gates[0]["conditions"].as_array().unwrap().len(), 5);
    let vulns = gates[0]["conditions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["metric"] == "new_vulnerabilities")
        .unwrap();
    assert_eq!(vulns["failing"], 1);
    assert_eq!(gates[0]["evaluations"].as_array().unwrap().len(), 3);
    assert_eq!(gates[0]["mostCommonFailure"], "New vulnerabilities > 0");
}
