//! `GET /api/components` and `GET /api/projects/{key}/components/{c}`.
//! Database tests skip without SONDA_TEST_DATABASE_URL (see server.rs).

mod common;

use axum::http::StatusCode;
use common::{TestDb, get, state, upload, upload_json_for};
use serde_json::{Value, json};
use sonda_server::{db, http};

async fn api(db: &TestDb, path: &str) -> (StatusCode, Value) {
    let (status, body) = get(http::router(state(db.pool.clone()), None), path).await;
    (status, serde_json::from_str(&body).unwrap_or(Value::Null))
}

#[tokio::test]
async fn components_are_listed_and_detailed() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let files = [
        ("api/a.js", "var x = 1;\neval(x);\n"),
        ("api/b.js", "let y = 2;\n"),
        ("web/c.py", "z = 3\n"),
        ("setup.py", "w = 4\n"),
    ];
    let mut body = upload_json_for(dir.path(), &files, "payments", "main");
    body["codeowners"] = json!("/api/ @team-api\n/api/b.js @team-api @alice\n");
    let (status, summary) = upload(&db, &body).await;
    assert_eq!(status, StatusCode::CREATED, "{summary}");
    // Backdate the analysis, and so its issues, by two weeks for the trend.
    sqlx::query("UPDATE analyses SET received_at = now() - interval '14 days'")
        .execute(&db.pool)
        .await
        .unwrap();

    let (status, list) = api(&db, "/api/components").await;
    assert_eq!(status, StatusCode::OK, "{list}");
    let rows = list["components"].as_array().unwrap();
    let api_row = rows.iter().find(|r| r["path"] == "api").unwrap();
    assert_eq!(api_row["project"], "payments");
    assert_eq!(api_row["issues"], 2, "var and eval: {api_row}");
    assert_eq!(api_row["owner"], "@team-api");
    assert_eq!(api_row["files"], 2);
    assert!(rows.iter().any(|r| r["path"] == "."));
    assert_eq!(list["owners"], json!(["@team-api"]));
    let (_, none) = api(&db, "/api/components?project=nope").await;
    assert_eq!(none["components"], json!([]));

    let (status, c) = api(&db, "/api/projects/payments/components/api").await;
    assert_eq!(status, StatusCode::OK, "{c}");
    assert_eq!(c["path"], "api");
    assert_eq!(c["files"], 2);
    assert_eq!(
        c["owners"],
        json!([{ "owner": "@team-api", "files": 2 }, { "owner": "@alice", "files": 1 }])
    );
    assert_eq!(c["issues"]["total"], 2);
    assert_eq!(c["issues"]["bySeverity"]["critical"], 1);
    assert_eq!(c["issues"]["byCategory"]["vulnerability"], 1);
    assert_eq!(c["fileList"][0]["path"], "api/a.js");
    assert_eq!(c["fileList"][0]["worst"], "critical");
    assert_eq!(c["fileList"][1]["issues"], 0);
    let trend: Vec<i64> = c["trend"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["open"].as_i64().unwrap())
        .collect();
    assert_eq!(trend.len(), 8);
    assert_eq!(trend[..5], [0, 0, 0, 0, 0], "{trend:?}");
    assert_eq!(trend[6..], [2, 2], "{trend:?}");
    assert_eq!(c["siblings"].as_array().unwrap().len(), 3);

    let (status, root) = api(&db, "/api/projects/payments/components/.").await;
    assert_eq!(status, StatusCode::OK, "{root}");
    assert_eq!(root["fileList"][0]["path"], "setup.py");
    let (status, _) = api(&db, "/api/projects/payments/components/nope").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = api(&db, "/api/projects/payments/components/api?branch=gone").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
