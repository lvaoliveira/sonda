//! The security review of issues (ADR-0014): reasons, false positives,
//! decided issues leaving the counts and the gate, and the review queue.
//! Database tests skip without SONDA_TEST_DATABASE_URL (see server.rs).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{TOKEN, TestDb, state, upload, upload_json_for};
use serde_json::{Value, json};
use sonda_server::{db, http};
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

async fn get(app: &axum::Router, path: &str) -> Value {
    let (status, body) = send(app, Request::get(path).body(Body::empty()).unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

async fn triage(app: &axum::Router, id: i64, body: Value) -> (StatusCode, Value) {
    let request = Request::patch(format!("/api/issues/{id}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .body(Body::from(body.to_string()))
        .unwrap();
    send(app, request).await
}

async fn issue_id(db: &TestDb, rule: &str, branch: &str) -> i64 {
    sqlx::query_scalar("SELECT id FROM issues WHERE rule = $1 AND branch = $2")
        .bind(rule)
        .bind(branch)
        .fetch_one(&db.pool)
        .await
        .unwrap()
}

/// The latest analysis of `branch`: a measure, and whether its gate passed.
async fn latest(db: &TestDb, branch: &str, measure: &str) -> (i64, bool) {
    sqlx::query_as(
        "SELECT (measures->>$2)::float8::bigint, gate_passed FROM analyses
         WHERE branch = $1 ORDER BY id DESC LIMIT 1",
    )
    .bind(branch)
    .bind(measure)
    .fetch_one(&db.pool)
    .await
    .unwrap()
}

const CLEAN: &[(&str, &str)] = &[("api/a.js", "let x = 1;\n")];
const EVAL: &[(&str, &str)] = &[("api/a.js", "let x = 1;\neval(x);\n")];

#[tokio::test]
async fn a_decision_needs_a_reason_and_clears_the_gate() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let app = http::router(state(db.pool.clone()), None);
    let body = |files| upload_json_for(dir.path(), files, "shop", "main");
    upload(&db, &body(CLEAN)).await;
    // The upload answers with the server's gate, which CI follows.
    let (status, summary) = upload(&db, &body(EVAL)).await;
    assert_eq!(status, StatusCode::CREATED, "{summary}");
    assert_eq!(summary["gate"]["passed"], false, "{summary}");
    assert_eq!(summary["gate"]["state"], "failed");
    assert!(
        summary["gate"]["failing"]
            .as_array()
            .unwrap()
            .contains(&json!("New vulnerabilities > 0")),
        "{summary}"
    );
    assert_eq!(latest(&db, "main", "new_vulnerabilities").await, (1, false));

    let id = issue_id(&db, "js/no-eval", "main").await;
    for bad in [
        json!({ "status": "accepted" }),
        json!({ "status": "false_positive" }),
        json!({ "status": "accepted", "reason": "" }),
        json!({ "status": "accepted", "reason": "x".repeat(501) }),
        json!({ "status": "accepted", "reason": "a\u{7}b" }),
        json!({ "status": "open", "reason": "why not" }),
        json!({ "reason": "no status" }),
    ] {
        let (status, body) = triage(&app, id, bad.clone()).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{bad} {body}");
    }

    let reason = "x is a constant, never user input";
    let (status, issue) = triage(
        &app,
        id,
        json!({ "status": "false_positive", "reason": reason }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{issue}");
    assert_eq!(issue["status"], "false_positive");
    assert_eq!(issue["reason"], reason);
    assert_eq!(issue["history"][0]["newValue"], "false_positive");
    assert_eq!(issue["history"][0]["reason"], reason);
    // The decision leaves the counts, and the stored gate passes.
    assert_eq!(latest(&db, "main", "new_vulnerabilities").await, (0, true));
    assert_eq!(latest(&db, "main", "vulnerabilities").await.0, 0);

    // A later analysis keeps it out.
    let (_, summary) = upload(&db, &body(EVAL)).await;
    assert_eq!(summary["gate"]["passed"], true, "{summary}");

    // Reopening counts it again.
    let (status, issue) = triage(&app, id, json!({ "status": "open" })).await;
    assert_eq!(status, StatusCode::OK, "{issue}");
    assert_eq!(issue["reason"], Value::Null);
    assert_eq!(latest(&db, "main", "new_vulnerabilities").await, (1, false));
}

#[tokio::test]
async fn a_branch_recounts_on_review() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let app = http::router(state(db.pool.clone()), None);
    upload(&db, &upload_json_for(dir.path(), CLEAN, "shop", "main")).await;
    let (status, summary) =
        upload(&db, &upload_json_for(dir.path(), EVAL, "shop", "feature")).await;
    assert_eq!(status, StatusCode::CREATED, "{summary}");
    assert_eq!(latest(&db, "feature", "vulnerabilities").await.0, 1);

    let id = issue_id(&db, "js/no-eval", "feature").await;
    let (status, _) = triage(
        &app,
        id,
        json!({ "status": "accepted", "reason": "Behind a feature flag." }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(latest(&db, "feature", "vulnerabilities").await.0, 0);
    // Main is untouched.
    assert_eq!(latest(&db, "main", "vulnerabilities").await.0, 0);
}

#[tokio::test]
async fn the_review_queue_orders_filters_and_counts() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let app = http::router(state(db.pool.clone()), None);
    // A major vulnerability (inner-html), two critical ones (eval), and a
    // code smell (var) the queue leaves out.
    let files = [
        ("web/a.js", "document.body.innerHTML = location.hash;\n"),
        ("api/b.js", "var y = 2;\neval(y);\neval(y + 1);\n"),
    ];
    let (status, summary) = upload(&db, &upload_json_for(dir.path(), &files, "shop", "main")).await;
    assert_eq!(status, StatusCode::CREATED, "{summary}");
    // Another project's branch is out of scope without a branch.
    let blog = tempfile::tempdir().unwrap();
    upload(&db, &upload_json_for(blog.path(), CLEAN, "blog", "main")).await;
    upload(&db, &upload_json_for(blog.path(), EVAL, "blog", "feature")).await;

    let queue = get(&app, "/api/security/review").await;
    let items = queue["items"].as_array().unwrap();
    let rules: Vec<&str> = items.iter().map(|i| i["rule"].as_str().unwrap()).collect();
    assert_eq!(
        rules,
        ["js/no-eval", "js/no-eval", "js/inner-html"],
        "{queue}"
    );
    assert_eq!(queue["total"], 3);
    assert_eq!(items[0]["line"], 2);
    assert_eq!(items[0]["project"], "shop");
    assert_eq!(items[0]["severity"], "critical");
    assert!(items[0]["ruleName"].is_string());
    assert!(items[0]["detectedAt"].as_str().unwrap().ends_with('Z'));
    assert!(!items[2]["cwe"].as_array().unwrap().is_empty(), "{queue}");
    let owasp = items[2]["owasp"][0]["id"].as_str().unwrap().to_string();
    assert_eq!(queue["progress"]["open"], 3);
    assert_eq!(queue["progress"]["reviewed"], 0);

    let first = items[0]["id"].as_i64().unwrap();
    triage(&app, first, json!({ "status": "confirmed" })).await;
    let second = items[1]["id"].as_i64().unwrap();
    triage(
        &app,
        second,
        json!({ "status": "accepted", "reason": "Test fixture." }),
    )
    .await;

    let queue = get(&app, "/api/security/review").await;
    assert_eq!(queue["total"], 1);
    let p = &queue["progress"];
    assert_eq!(
        (&p["open"], &p["confirmed"], &p["accepted"], &p["reviewed"]),
        (&json!(1), &json!(1), &json!(1), &json!(66))
    );
    let all = get(&app, "/api/security/review?status=all").await;
    assert_eq!(all["total"], 3);
    let accepted = get(&app, "/api/security/review?status=accepted").await;
    assert_eq!(accepted["items"][0]["reason"], "Test fixture.");
    let critical = get(&app, "/api/security/review?status=all&severity=critical").await;
    assert_eq!(critical["total"], 2);
    let by_owasp = get(&app, &format!("/api/security/review?owasp={owasp}")).await;
    assert_eq!(by_owasp["items"][0]["rule"], "js/inner-html", "{by_owasp}");
    let nobody = get(&app, "/api/security/review?status=all&assignee=ann").await;
    assert_eq!(nobody["total"], 0);

    let blog = get(&app, "/api/security/review?project=blog&branch=feature").await;
    assert_eq!(blog["total"], 1);
    assert_eq!(blog["items"][0]["branch"], "feature");
    for bad in [
        "?status=fixed",
        "?edition=2017",
        "?branch=feature",
        "?unknown=1",
    ] {
        let path = format!("/api/security/review{bad}");
        let (status, _) = send(&app, Request::get(&path).body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    }
}
