//! Gate conditions on vulnerable dependencies, kept current by the server.
//! Database tests skip without SONDA_TEST_DATABASE_URL (see server.rs).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{TOKEN, TestDb, state_with, upload, upload_json_for};
use serde_json::{Value, json};
use sonda_server::{advisories, db, http};
use tower::ServiceExt;

async fn send(app: &axum::Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 4 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn gate(app: &axum::Router) -> (String, Value) {
    let bearer = format!("Bearer {TOKEN}");
    let request = Request::get("/api/projects/shop")
        .header(header::AUTHORIZATION, bearer)
        .body(Body::empty())
        .unwrap();
    let (status, p) = send(app, request).await;
    assert_eq!(status, StatusCode::OK, "{p}");
    let condition = p["gate"]["conditions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["metric"] == "vulnerable_dependencies")
        .cloned()
        .unwrap();
    (p["gate"]["state"].as_str().unwrap().to_string(), condition)
}

/// An upload of the project, its gate failing only on vulnerable
/// dependencies (as if the CLI had no advisories: no data).
fn analysis(dir: &std::path::Path) -> Value {
    let lock = r#"{"lockfileVersion": 3, "packages": {"": {"dependencies": {"lodash": "^4"}},
        "node_modules/lodash": {"version": "4.17.20"}}}"#;
    let mut body = upload_json_for(dir, &[("package-lock.json", lock)], "shop", "main");
    body["report"]["gate"] = json!({ "passed": true, "conditions": [
        { "metric": "vulnerable_dependencies", "op": "gt", "threshold": 0.0, "actual": null, "status": "no_data" }
    ]});
    body
}

#[tokio::test]
async fn gates_follow_advisories_and_reviews() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let app = http::router(state_with(db.pool.clone(), true), None);
    let project = tempfile::tempdir().unwrap();
    assert_eq!(
        upload(&db, &analysis(project.path())).await.0,
        StatusCode::CREATED
    );

    // No advisory data yet: the CLI's "no data" stands.
    let (state, c) = gate(&app).await;
    assert_eq!(c["status"], "no_data");
    assert_eq!(state, "partial", "a condition without data");

    // An advisory arrives: the stored gate fails without a new analysis.
    let osv = tempfile::tempdir().unwrap();
    std::fs::write(
        osv.path().join("a.json"),
        json!({
            "id": "GHSA-35jh-r3h4-6jhm", "modified": "2024-01-01T00:00:00Z", "summary": "Command Injection in lodash",
            "database_specific": { "severity": "HIGH" },
            "affected": [{ "package": { "ecosystem": "npm", "name": "lodash" },
                           "ranges": [{ "type": "SEMVER", "events": [{ "introduced": "0" }, { "fixed": "4.17.21" }] }] }]
        })
        .to_string(),
    )
    .unwrap();
    advisories::import(&db.pool, &[osv.path().to_path_buf()])
        .await
        .unwrap();
    let (state, c) = gate(&app).await;
    assert_eq!(
        (state.as_str(), c["status"].as_str(), c["actual"].as_f64()),
        ("failed", Some("error"), Some(1.0))
    );

    // Accepting the finding passes the gate.
    let bearer = format!("Bearer {TOKEN}");
    let accept = Request::patch("/api/projects/shop/dependencies/reviews")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, &bearer)
        .body(Body::from(
            json!({ "ecosystem": "npm", "name": "lodash", "advisory": "GHSA-35jh-r3h4-6jhm",
                    "status": "accepted", "reason": "Build-time only." })
            .to_string(),
        ))
        .unwrap();
    assert_eq!(send(&app, accept).await.0, StatusCode::OK);
    let (state, c) = gate(&app).await;
    assert_eq!(
        (state.as_str(), c["status"].as_str(), c["actual"].as_f64()),
        ("passed", Some("ok"), Some(0.0))
    );

    // A new analysis is evaluated as it arrives, review included.
    let (status, s) = upload(&db, &analysis(project.path())).await;
    assert_eq!(status, StatusCode::CREATED);
    let (passed, measure): (bool, Value) = sqlx::query_as(
        "SELECT gate_passed, measures->'vulnerable_dependencies' FROM analyses WHERE id = $1",
    )
    .bind(s["analysis_id"].as_i64().unwrap())
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!((passed, measure), (true, json!(0.0)));
}
