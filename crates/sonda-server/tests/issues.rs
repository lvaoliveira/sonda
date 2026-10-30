//! The issues API: filtering, pagination, facets, an issue with its code,
//! and triage with its authorization and audit trail. Database tests skip
//! without SONDA_TEST_DATABASE_URL (see server.rs).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{TOKEN, TestDb, state, state_with, upload, upload_json};
use serde_json::{Value, json};
use sonda_server::{db, http};
use tower::ServiceExt;

async fn send(app: &axum::Router, request: Request<Body>) -> (StatusCode, Value, Option<String>) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_string());
    let bytes = axum::body::to_bytes(response.into_body(), 4 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        cookie,
    )
}

async fn get(app: &axum::Router, path: &str) -> (StatusCode, Value) {
    let (status, body, _) = send(app, Request::get(path).body(Body::empty()).unwrap()).await;
    (status, body)
}

fn patch(id: i64, body: Value, auth: &[(&str, &str)]) -> Request<Body> {
    let mut r = Request::patch(format!("/api/issues/{id}"))
        .header(header::CONTENT_TYPE, "application/json");
    for (k, v) in auth {
        r = r.header(*k, *v);
    }
    r.body(Body::from(body.to_string())).unwrap()
}

/// A project with three issues: two in src/ (minor js/no-var, critical
/// js/no-eval) and one in lib/ (critical py/no-eval).
async fn seeded() -> Option<(TestDb, tempfile::TempDir)> {
    let db = TestDb::new().await?;
    db::migrate(&db.pool).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let files = [
        ("src/a.js", "var x = 1;\neval(x);\n"),
        ("lib/b.py", "eval(input())\n"),
    ];
    let (status, _) = upload(&db, &upload_json(dir.path(), &files, "main")).await;
    assert_eq!(status, StatusCode::CREATED);
    Some((db, dir))
}

fn rules(page: &Value) -> Vec<&str> {
    page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["rule"].as_str().unwrap())
        .collect()
}

#[tokio::test]
async fn the_list_filters_paginates_and_counts_facets() {
    let Some((db, dir)) = seeded().await else {
        return;
    };
    let app = http::router(state(db.pool.clone()), None);

    let (status, all) = get(&app, "/api/issues").await;
    assert_eq!(status, StatusCode::OK, "{all}");
    assert_eq!(all["total"], 3);
    // Most severe first, then by project, path and line.
    assert_eq!(rules(&all), ["py/no-eval", "js/no-eval", "js/no-var"]);
    let first = &all["items"][0];
    assert_eq!(first["component"], "lib");
    assert_eq!(first["file"], "lib/b.py");
    assert_eq!(first["language"], "python");
    assert_eq!(first["status"], "open");
    assert!(first["key"].as_str().unwrap().len() == 32);
    assert!(first["detectedAt"].as_str().unwrap().ends_with('Z'));
    assert_eq!(all["facets"]["component"], json!({ "lib": 1, "src": 2 }));
    assert_eq!(
        all["facets"]["severity"],
        json!({ "critical": 2, "minor": 1 })
    );

    // A facet's own selection does not zero out its other values.
    let (_, critical) = get(&app, "/api/issues?severity=critical").await;
    assert_eq!(critical["total"], 2);
    assert_eq!(critical["facets"]["severity"], all["facets"]["severity"]);
    assert_eq!(
        critical["facets"]["component"],
        json!({ "lib": 1, "src": 1 })
    );

    let (_, page) = get(&app, "/api/issues?limit=1&offset=1").await;
    assert_eq!(
        (page["total"].clone(), rules(&page)),
        (json!(3), vec!["js/no-eval"])
    );
    let (_, by_file) = get(&app, "/api/issues?file=b.py&component=lib,src").await;
    assert_eq!(rules(&by_file), ["py/no-eval"]);

    // Fixed issues are a status like any other.
    let fixed_eval = [
        ("src/a.js", "var x = 1;\n"),
        ("lib/b.py", "eval(input())\n"),
    ];
    upload(&db, &upload_json(dir.path(), &fixed_eval, "main")).await;
    let (_, fixed) = get(&app, "/api/issues?status=fixed").await;
    assert_eq!(rules(&fixed), ["js/no-eval"]);
    assert_eq!(fixed["items"][0]["status"], "fixed");

    // Other branches only when asked for.
    upload(
        &db,
        &upload_json(dir.path(), &[("src/c.js", "var y;\n")], "feature"),
    )
    .await;
    assert_eq!(get(&app, "/api/issues?status=open").await.1["total"], 2);
    let (_, feature) = get(&app, "/api/issues?project=payments&branch=feature").await;
    assert_eq!(feature["total"], 3);

    // Mistakes are errors, not empty results.
    for bad in [
        "severity=fatal",
        "status=closed",
        "limit=500",
        "offset=-1",
        "colour=red",
    ] {
        let (status, _) = get(&app, &format!("/api/issues?{bad}")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    }
    db.drop().await;
}

#[tokio::test]
async fn an_issue_comes_with_highlighted_code_and_its_rule() {
    let Some((db, _dir)) = seeded().await else {
        return;
    };
    let app = http::router(state(db.pool.clone()), None);
    let (_, all) = get(&app, "/api/issues?file=a.js&severity=minor").await;
    let id = all["items"][0]["id"].as_i64().unwrap();

    let (status, issue) = get(&app, &format!("/api/issues/{id}")).await;
    assert_eq!(status, StatusCode::OK, "{issue}");
    assert_eq!(issue["rule"], "js/no-var");
    assert!(issue["ruleName"].is_string() && issue["noncompliant"].is_string());
    let line1 = &issue["code"][0];
    assert_eq!(line1["number"], 1);
    let text: String = line1["tokens"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["text"].as_str().unwrap())
        .collect();
    assert_eq!(text, "var x = 1;");
    assert_eq!(
        line1["tokens"][0],
        json!({ "text": "var", "role": "keyword" })
    );
    assert_eq!(issue["history"], json!([]));

    assert_eq!(
        get(&app, "/api/issues/999999").await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(&app, "/api/issues/abc").await.0,
        StatusCode::BAD_REQUEST
    );
    db.drop().await;
}

#[tokio::test]
async fn triage_needs_authorization_and_is_audited() {
    let Some((db, _dir)) = seeded().await else {
        return;
    };
    let app = http::router(state_with(db.pool.clone(), true), None);
    let bearer = format!("Bearer {TOKEN}");
    let id: i64 = sqlx::query_scalar("SELECT id FROM issues WHERE rule = 'js/no-var'")
        .fetch_one(&db.pool)
        .await
        .unwrap();

    let confirm = json!({ "status": "confirmed" });
    assert_eq!(
        send(&app, patch(id, confirm.clone(), &[])).await.0,
        StatusCode::UNAUTHORIZED
    );

    let sign_in = Request::post("/api/session")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json!({ "token": TOKEN }).to_string()))
        .unwrap();
    let session = send(&app, sign_in).await.2.unwrap();
    // A session alone, as a cross-site form would send it, changes nothing.
    let (status, body, _) = send(&app, patch(id, confirm.clone(), &[("cookie", &session)])).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let csrf = [("cookie", session.as_str()), ("sonda-csrf", "1")];
    let (status, issue, _) = send(&app, patch(id, confirm, &csrf)).await;
    assert_eq!(status, StatusCode::OK, "{issue}");
    assert_eq!(issue["status"], "confirmed");

    let (_, issue, _) = send(
        &app,
        patch(
            id,
            json!({ "assignee": "alice" }),
            &[("authorization", &bearer)],
        ),
    )
    .await;
    assert_eq!(issue["assignee"], "alice");
    let (status, _, _) = send(&app, patch(id, json!({ "status": "fixed" }), &csrf)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let (status, _, _) = send(&app, patch(id, json!({ "priority": 1 }), &csrf)).await;
    assert!(status.is_client_error());
    // Setting the same value again records nothing.
    send(&app, patch(id, json!({ "status": "confirmed" }), &csrf)).await;
    let (_, issue, _) = send(&app, patch(id, json!({ "assignee": "" }), &csrf)).await;
    assert_eq!(issue["assignee"], Value::Null);

    let history: Vec<(String, Option<String>, Option<String>)> = issue["history"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            assert!(e["at"].as_str().unwrap().ends_with('Z'));
            (
                e["field"].as_str().unwrap().to_string(),
                e["oldValue"].as_str().map(String::from),
                e["newValue"].as_str().map(String::from),
            )
        })
        .collect();
    let s = |v: &str| Some(v.to_string());
    assert_eq!(
        history,
        [
            ("status".into(), s("open"), s("confirmed")),
            ("assignee".into(), None, s("alice")),
            ("assignee".into(), s("alice"), None),
        ]
    );
    assert_eq!(
        send(&app, patch(999999, json!({}), &csrf)).await.0,
        StatusCode::NOT_FOUND
    );
    db.drop().await;
}
