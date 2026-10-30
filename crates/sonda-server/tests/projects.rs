//! `GET /api/projects` and `GET /api/projects/{key}`. Database tests skip
//! without SONDA_TEST_DATABASE_URL (see server.rs).

mod common;

use axum::http::StatusCode;
use common::{TestDb, get, state, upload, upload_json_for};
use serde_json::Value;
use sonda_server::{db, http};

async fn analysis(
    db: &TestDb,
    dir: &std::path::Path,
    project: &str,
    branch: &str,
    files: &[(&str, &str)],
) {
    let (status, summary) = upload(db, &upload_json_for(dir, files, project, branch)).await;
    assert_eq!(status, StatusCode::CREATED, "{summary}");
}

async fn api(db: &TestDb, path: &str) -> (StatusCode, Value) {
    let (status, body) = get(http::router(state(db.pool.clone()), None), path).await;
    (status, serde_json::from_str(&body).unwrap_or(Value::Null))
}

#[tokio::test]
async fn projects_are_listed_and_detailed_from_their_analyses() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let (pay, docs) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    // payments: a clean first analysis on main, then a critical
    // vulnerability (eval) in api/, which fails the default gate.
    analysis(
        &db,
        pay.path(),
        "payments",
        "main",
        &[("api/a.js", "let x = 1;\n"), ("web/b.py", "y = 2\n")],
    )
    .await;
    analysis(
        &db,
        pay.path(),
        "payments",
        "main",
        &[
            ("api/a.js", "let x = 1;\neval(x);\n"),
            ("web/b.py", "y = 2\n"),
        ],
    )
    .await;
    analysis(
        &db,
        pay.path(),
        "payments",
        "feature",
        &[("api/a.js", "let x = 1;\n")],
    )
    .await;
    analysis(&db, docs.path(), "docs", "main", &[("a.py", "z = 3\n")]).await;

    let (status, list) = api(&db, "/api/projects").await;
    assert_eq!(status, StatusCode::OK, "{list}");
    let rows = list["projects"].as_array().unwrap();
    assert_eq!(
        rows.iter()
            .map(|r| r["key"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["docs", "payments"]
    );
    let pay_row = &rows[1];
    assert_eq!(pay_row["mainBranch"], "main");
    assert_eq!(pay_row["gate"], "failed");
    assert_eq!(pay_row["security"], 2, "critical vulnerability: {pay_row}");
    assert_eq!(pay_row["reliability"], 5);
    assert_eq!(pay_row["issues"], 1);
    assert_eq!(
        pay_row["languages"],
        serde_json::json!(["javascript", "python"])
    );
    // No coverage uploaded, but a small project: coverage on new code is
    // ignored (fewer than 20 new lines) rather than missing.
    assert_eq!(rows[0]["gate"], "passed");
    assert!(pay_row["analyzedAt"].as_str().unwrap().ends_with('Z'));
    assert_eq!(
        list["languages"],
        serde_json::json!(["javascript", "python"])
    );

    let (status, p) = api(&db, "/api/projects/payments").await;
    assert_eq!(status, StatusCode::OK, "{p}");
    assert_eq!(p["branch"], "main");
    assert_eq!(
        p["branches"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b["name"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["main", "feature"]
    );
    assert_eq!(p["gate"]["state"], "failed");
    assert!(
        p["gate"]["conditions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["status"] == "error" && c["label"] == "New vulnerabilities > 0")
    );
    assert_eq!(p["history"].as_array().unwrap().len(), 2);
    assert_eq!(p["history"][1]["gate"], "failed");
    assert_eq!(p["measures"]["overall"]["vulnerabilities"], 1.0);
    let components = p["components"].as_array().unwrap();
    assert_eq!(components[0]["path"], "api");
    assert_eq!(components[0]["issues"], 1);
    assert_eq!(components[1]["path"], "web");

    let (status, f) = api(&db, "/api/projects/payments?branch=feature").await;
    assert_eq!(status, StatusCode::OK, "{f}");
    assert_eq!(f["branch"], "feature");
    assert_eq!(f["history"].as_array().unwrap().len(), 1);

    let (status, _) = api(&db, "/api/projects/nope").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, err) = api(&db, "/api/projects/payments?branch=gone").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        err["error"].as_str().unwrap().contains("main, feature"),
        "{err}"
    );
    db.drop().await;
}
