//! Triage of known vulnerabilities in dependencies, and the Security
//! screen's summary of them. Database tests skip without
//! SONDA_TEST_DATABASE_URL (see server.rs).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{PASSWORD, TestDb, create_user, sign_in, state_with, upload, upload_json_for};
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

fn review(body: Value, auth: &[(&str, &str)]) -> Request<Body> {
    let mut r = Request::patch("/api/projects/shop/dependencies/reviews")
        .header(header::CONTENT_TYPE, "application/json");
    for (k, v) in auth {
        r = r.header(*k, *v);
    }
    r.body(Body::from(body.to_string())).unwrap()
}

async fn read(app: &axum::Router, path: &str, auth: &[(&str, &str)]) -> Value {
    let mut r = Request::get(path);
    for (k, v) in auth {
        r = r.header(*k, *v);
    }
    let (status, body) = send(app, r.body(Body::empty()).unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

fn osv(id: &str, ecosystem: &str, name: &str, fixed: &str) -> String {
    json!({
        "id": id, "modified": "2024-01-01T00:00:00Z", "summary": format!("{name} is vulnerable"),
        "database_specific": { "severity": "HIGH" },
        "affected": [{ "package": { "ecosystem": ecosystem, "name": name },
                       "ranges": [{ "type": "ECOSYSTEM", "events": [{ "introduced": "0" }, { "fixed": fixed }] }] }]
    })
    .to_string()
}

#[tokio::test]
async fn findings_are_triaged_with_reasons_and_audited() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let project = tempfile::tempdir().unwrap();
    let lock = r#"{"lockfileVersion": 3, "packages": {"": {"dependencies": {"lodash": "^4"}},
        "node_modules/lodash": {"version": "4.17.20"}}}"#;
    let body = upload_json_for(
        project.path(),
        &[
            ("package-lock.json", lock),
            ("requirements.txt", "Requests==2.30.0\n"),
        ],
        "shop",
        "main",
    );
    assert_eq!(upload(&db, &body).await.0, StatusCode::CREATED);
    let osv_dir = tempfile::tempdir().unwrap();
    std::fs::write(
        osv_dir.path().join("a.json"),
        osv("GHSA-aaaa-aaaa-aaaa", "npm", "lodash", "4.17.21"),
    )
    .unwrap();
    std::fs::write(
        osv_dir.path().join("b.json"),
        osv("GHSA-bbbb-bbbb-bbbb", "PyPI", "requests", "2.31.0"),
    )
    .unwrap();
    advisories::import(&db.pool, &[osv_dir.path().to_path_buf()])
        .await
        .unwrap();

    let app = http::router(state_with(db.pool.clone(), true), None);
    let accept = json!({
        "ecosystem": "npm", "name": "lodash", "advisory": "GHSA-aaaa-aaaa-aaaa",
        "status": "accepted", "reason": "Only used in build scripts, never on user input."
    });
    assert_eq!(
        send(&app, review(accept.clone(), &[])).await.0,
        StatusCode::UNAUTHORIZED
    );

    create_user(&db, "ann", "member").await;
    let session = sign_in(&app, "ann", PASSWORD).await.unwrap();
    let csrf = [("cookie", session.as_str()), ("sonda-csrf", "1")];
    for (bad, expected) in [
        (json!({ "reason": null }), StatusCode::UNPROCESSABLE_ENTITY),
        (json!({ "reason": "   " }), StatusCode::UNPROCESSABLE_ENTITY),
        (
            json!({ "status": "fixed" }),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            json!({ "ecosystem": "maven" }),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (json!({ "advisory": "GHSA-nope" }), StatusCode::NOT_FOUND),
    ] {
        let mut b = accept.clone();
        for (k, v) in bad.as_object().unwrap() {
            b[k] = v.clone();
        }
        assert_eq!(
            send(&app, review(b.clone(), &csrf)).await.0,
            expected,
            "{b}"
        );
    }

    let (status, r) = send(&app, review(accept, &csrf)).await;
    assert_eq!(status, StatusCode::OK, "{r}");
    assert_eq!(
        (r["status"].as_str(), r["reviewedBy"].as_str()),
        (Some("accepted"), Some("ann"))
    );

    // Listed with its review, but no longer counted.
    let d = read(&app, "/api/projects/shop/dependencies", &csrf).await;
    assert_eq!(d["summary"]["vulnerable"], 1, "{d}");
    let lodash = d["dependencies"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "lodash")
        .unwrap();
    assert_eq!(lodash["advisories"][0]["review"]["status"], "accepted");
    assert_eq!(
        lodash["advisories"][0]["review"]["reason"],
        "Only used in build scripts, never on user input."
    );

    // The Security screen counts what's left: requests, open.
    let s = read(&app, "/api/security", &csrf).await;
    let deps = &s["dependencies"];
    assert_eq!(deps["vulnerablePackages"], 1, "{deps}");
    assert_eq!(deps["projectsAffected"], 1);
    assert_eq!(deps["bySeverity"], json!({ "critical": 1 }));
    assert_eq!(deps["top"][0]["package"], "Requests");
    assert_eq!(deps["top"][0]["fixedIn"], "2.31.0");

    // Names match as PyPI normalizes them; reopening counts it again.
    let confirm = json!({ "ecosystem": "pypi", "name": "requests", "advisory": "GHSA-bbbb-bbbb-bbbb", "status": "confirmed" });
    assert_eq!(send(&app, review(confirm, &csrf)).await.0, StatusCode::OK);
    let reopen = json!({ "ecosystem": "npm", "name": "lodash", "advisory": "GHSA-aaaa-aaaa-aaaa", "status": "open" });
    assert_eq!(send(&app, review(reopen, &csrf)).await.0, StatusCode::OK);
    let d = read(&app, "/api/projects/shop/dependencies", &csrf).await;
    assert_eq!(d["summary"]["vulnerable"], 2);

    let events: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT actor, old_status, new_status FROM dependency_review_events ORDER BY id",
    )
    .fetch_all(&db.pool)
    .await
    .unwrap();
    assert_eq!(
        events,
        [
            ("ann".into(), "open".into(), "accepted".into()),
            ("ann".into(), "open".into(), "confirmed".into()),
            ("ann".into(), "accepted".into(), "open".into()),
        ]
    );
}
