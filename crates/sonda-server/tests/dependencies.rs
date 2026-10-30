//! `GET /api/projects/{key}/dependencies`, and dependencies at ingestion.
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

fn lock(packages: &str) -> String {
    format!(
        r#"{{"lockfileVersion": 3, "packages": {{"": {{"dependencies": {{"lodash": "^4"}}}}, {packages}}}}}"#
    )
}

#[tokio::test]
async fn dependencies_are_stored_listed_and_diffed() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let first = lock(
        r#""node_modules/lodash": {"version": "4.17.20", "license": "MIT"},
           "node_modules/debug": {"version": "2.6.9"}"#,
    );
    let body = upload_json_for(
        dir.path(),
        &[
            ("app.js", "let a = 1;\n"),
            ("package-lock.json", &first),
            ("web/package-lock.json", &first),
            ("requirements.txt", "flask==3.0.0\n"),
        ],
        "payments",
        "main",
    );
    let (status, summary) = upload(&db, &body).await;
    assert_eq!(status, StatusCode::CREATED, "{summary}");

    let (status, d) = api(&db, "/api/projects/payments/dependencies").await;
    assert_eq!(status, StatusCode::OK, "{d}");
    assert_eq!(d["branch"], "main");
    assert_eq!(d["summary"]["total"], 3, "{d}");
    assert_eq!(d["summary"]["direct"], 1);
    assert_eq!(
        d["summary"]["ecosystems"],
        json!([{ "id": "npm", "count": 2 }, { "id": "pypi", "count": 1 }])
    );
    let lodash = d["dependencies"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "lodash")
        .unwrap();
    assert_eq!(
        lodash["lockfiles"],
        json!(["package-lock.json", "web/package-lock.json"])
    );
    assert_eq!(lodash["license"], "MIT");
    assert_eq!(d["changes"], Value::Null, "first analysis");
    assert_eq!(
        d["lockfiles"],
        json!([
            { "id": "package-lock.json", "count": 2 },
            { "id": "requirements.txt", "count": 1 },
            { "id": "web/package-lock.json", "count": 2 }
        ])
    );

    let (_, project) = api(&db, "/api/projects/payments").await;
    assert_eq!(project["dependencies"]["total"], 3, "{project}");

    // Upgrade lodash, drop debug, add ms.
    let second = lock(
        r#""node_modules/lodash": {"version": "4.17.21", "license": "MIT"},
           "node_modules/ms": {"version": "2.1.3"}"#,
    );
    let body = upload_json_for(
        dir.path(),
        &[
            ("package-lock.json", &second),
            ("web/package-lock.json", &second),
        ],
        "payments",
        "main",
    );
    let (status, _) = upload(&db, &body).await;
    assert_eq!(status, StatusCode::CREATED);
    let (_, d) = api(&db, "/api/projects/payments/dependencies").await;
    let changes = &d["changes"];
    assert_eq!(
        changes["updated"],
        json!([{ "ecosystem": "npm", "name": "lodash", "from": ["4.17.20"], "to": ["4.17.21"] }])
    );
    assert_eq!(
        changes["added"],
        json!([{ "ecosystem": "npm", "name": "ms", "versions": ["2.1.3"] }])
    );
    assert_eq!(changes["removed"][0]["name"], "debug");

    let (status, _) = api(&db, "/api/projects/payments/dependencies?branch=nope").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = api(&db, "/api/projects/nope/dependencies").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn reports_without_dependencies_and_malformed_ones() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut body = upload_json_for(dir.path(), &[("app.js", "let a = 1;\n")], "old-cli", "main");
    // As an older CLI sends it.
    body["report"]
        .as_object_mut()
        .unwrap()
        .remove("dependencies");
    let (status, summary) = upload(&db, &body).await;
    assert_eq!(status, StatusCode::CREATED, "{summary}");
    let (_, project) = api(&db, "/api/projects/old-cli").await;
    assert_eq!(project["dependencies"], Value::Null);
    let (_, d) = api(&db, "/api/projects/old-cli/dependencies").await;
    assert_eq!(d["summary"]["total"], 0);

    let dep = json!({
        "ecosystem": "npm", "name": "a", "version": "1.0.0", "purl": "pkg:npm/a@1.0.0",
        "direct": true, "source": "package-lock.json", "license": null
    });
    let bad = |patch: Value| {
        let mut d = dep.clone();
        for (k, v) in patch.as_object().unwrap() {
            d[k] = v.clone();
        }
        d
    };
    for deps in [
        json!([bad(json!({ "ecosystem": "maven" }))]),
        json!([bad(json!({ "source": "../outside/package-lock.json" }))]),
        json!([bad(json!({ "purl": "npm/a@1.0.0" }))]),
        json!([bad(json!({ "name": "" }))]),
        json!([dep.clone(), dep.clone()]),
    ] {
        let mut b = body.clone();
        b["report"]["dependencies"] = deps.clone();
        let (status, err) = upload(&db, &b).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{deps} → {err}");
    }
}
