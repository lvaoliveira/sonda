//! The main branch's new code period (ADR-0011). Database tests skip
//! without SONDA_TEST_DATABASE_URL (see server.rs).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{TOKEN, TestDb, state_with, upload, upload_json_for};
use serde_json::{Value, json};
use sonda_server::{db, http, session};
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

/// A signed-in user, without a password: sessions straight from the store.
async fn session_for(db: &TestDb, username: &str, role: &str) -> String {
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO users (username, display_name, role) VALUES ($1, $1, $2::user_role) RETURNING id",
    )
    .bind(username)
    .bind(role)
    .fetch_one(&db.pool)
    .await
    .unwrap();
    let token = session::create(&db.pool, id).await.unwrap();
    format!("{}={token}", session::COOKIE)
}

async fn project(app: &axum::Router, auth: &[(&str, &str)], branch: Option<&str>) -> Value {
    let path = match branch {
        Some(b) => format!("/api/projects/shop?branch={b}"),
        None => "/api/projects/shop".into(),
    };
    let mut r = Request::get(path);
    for (k, v) in auth {
        r = r.header(*k, *v);
    }
    let (status, p) = send(app, r.body(Body::empty()).unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{p}");
    p
}

fn condition<'a>(p: &'a Value, metric: &str) -> &'a Value {
    p["gate"]["conditions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["metric"] == metric)
        .unwrap()
}

fn reset(analysis: Value, auth: &[(&str, &str)]) -> Request<Body> {
    let mut r = Request::put("/api/projects/shop/new-code")
        .header(header::CONTENT_TYPE, "application/json");
    for (k, v) in auth {
        r = r.header(*k, *v);
    }
    r.body(Body::from(json!({ "analysis": analysis }).to_string()))
        .unwrap()
}

#[tokio::test]
async fn the_main_branch_judges_new_code_since_its_period() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let app = http::router(state_with(db.pool.clone(), true), None);
    let bearer = format!("Bearer {TOKEN}");
    let token = [("authorization", bearer.as_str())];
    let dir = tempfile::tempdir().unwrap();

    // The first analysis: its debt is accepted, so nothing is new. (The
    // scan itself saw no git, so it called everything new.)
    let old = ("old.js", "var x = 1;\neval(x);\n");
    let (status, first) = upload(&db, &upload_json_for(dir.path(), &[old], "shop", "main")).await;
    assert_eq!(status, StatusCode::CREATED, "{first}");
    let p = project(&app, &token, None).await;
    assert_eq!(p["newCodePeriod"]["analysis"], first["analysis_id"]);
    assert_eq!(p["newCodePeriod"]["reset"], false);
    assert_eq!(condition(&p, "new_vulnerabilities")["actual"], 0.0);
    assert_eq!(p["measures"]["newCode"]["issues"], 0.0);

    // A later analysis adds a file: only its issue is new, and the gate fails.
    let new = ("new.js", "\nlet y = 2;\neval(y);\n");
    let (_, second) = upload(
        &db,
        &upload_json_for(dir.path(), &[old, new], "shop", "main"),
    )
    .await;
    let p = project(&app, &token, None).await;
    assert_eq!(condition(&p, "new_vulnerabilities")["actual"], 1.0);
    assert_eq!(condition(&p, "new_vulnerabilities")["status"], "error");
    assert_eq!(p["gate"]["state"], "failed");
    assert_eq!(
        p["measures"]["newCode"]["lines"], 2.0,
        "new.js's non-blank lines"
    );
    let new_rules: Vec<String> = sqlx::query_scalar(
        "SELECT path FROM issues WHERE is_new AND fixed_analysis_id IS NULL ORDER BY path",
    )
    .fetch_all(&db.pool)
    .await
    .unwrap();
    assert_eq!(new_rules, ["new.js"]);

    // A rule added to sonda finds issues in old code: first seen now, but on
    // unchanged lines, so old debt. Simulated by moving old.js's issue's
    // first sighting. An issue on an edited line is new.
    sqlx::query("UPDATE issues SET first_analysis_id = $1 WHERE path = 'old.js'")
        .bind(second["analysis_id"].as_i64())
        .execute(&db.pool)
        .await
        .unwrap();
    let edited = ("old.js", "var x = 1;\neval(x);\neval(x + 1);\n");
    let (_, second) = upload(
        &db,
        &upload_json_for(dir.path(), &[edited, new], "shop", "main"),
    )
    .await;
    let new_issues: Vec<(String, i32)> = sqlx::query_as(
        "SELECT path, line FROM issues WHERE is_new AND fixed_analysis_id IS NULL ORDER BY path, line",
    )
    .fetch_all(&db.pool)
    .await
    .unwrap();
    assert_eq!(new_issues, [("new.js".into(), 3), ("old.js".into(), 3)]);
    let p = project(&app, &token, None).await;
    assert_eq!(condition(&p, "new_vulnerabilities")["actual"], 2.0);

    // Only an admin moves the period.
    let latest = second["analysis_id"].clone();
    assert_eq!(
        send(&app, reset(latest.clone(), &[])).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(&app, reset(latest.clone(), &token)).await.0,
        StatusCode::FORBIDDEN
    );
    let member = session_for(&db, "max", "member").await;
    let as_member = [("cookie", member.as_str()), ("sonda-csrf", "1")];
    assert_eq!(
        send(&app, reset(latest.clone(), &as_member)).await.0,
        StatusCode::FORBIDDEN
    );
    let admin = session_for(&db, "ada", "admin").await;
    let as_admin = [("cookie", admin.as_str()), ("sonda-csrf", "1")];

    // Starting at the latest analysis accepts new.js too.
    let (status, period) = send(&app, reset(latest.clone(), &as_admin)).await;
    assert_eq!(status, StatusCode::OK, "{period}");
    assert_eq!(
        (period["analysis"].clone(), period["reset"].clone()),
        (latest.clone(), json!(true))
    );
    let p = project(&app, &token, None).await;
    assert_eq!(condition(&p, "new_vulnerabilities")["actual"], 0.0);
    assert_eq!(
        p["gate"]["state"], "partial",
        "only coverage without data is left"
    );

    // Back to the first analysis.
    assert_eq!(
        send(&app, reset(Value::Null, &as_admin)).await.0,
        StatusCode::OK
    );
    let p = project(&app, &token, None).await;
    assert_eq!(p["newCodePeriod"]["reset"], false);
    assert_eq!(condition(&p, "new_vulnerabilities")["actual"], 2.0);

    // Another branch's analysis can't start the main branch's period, and
    // other branches keep the scan's own new code.
    let (_, feature) = upload(
        &db,
        &upload_json_for(dir.path(), &[old, new], "shop", "feature"),
    )
    .await;
    let (status, _) = send(&app, reset(feature["analysis_id"].clone(), &as_admin)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let p = project(&app, &token, Some("feature")).await;
    assert_eq!(p["newCodePeriod"], Value::Null);
    assert_eq!(
        condition(&p, "new_vulnerabilities")["actual"],
        2.0,
        "the scan's whole-project view"
    );

    let resets: Vec<(String, Option<i64>, Option<i64>)> =
        sqlx::query_as("SELECT actor, old_since, new_since FROM new_code_resets ORDER BY id")
            .fetch_all(&db.pool)
            .await
            .unwrap();
    let latest = latest.as_i64();
    assert_eq!(
        resets,
        [("ada".into(), None, latest), ("ada".into(), latest, None)]
    );
}

#[tokio::test]
async fn a_new_version_starts_a_new_period() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let app = http::router(state_with(db.pool.clone(), true), None);
    let bearer = format!("Bearer {TOKEN}");
    let token = [("authorization", bearer.as_str())];
    let dir = tempfile::tempdir().unwrap();
    let analyze = async |files: &[(&str, &str)], version: Option<&str>| {
        let mut body = upload_json_for(dir.path(), files, "shop", "main");
        if let Some(v) = version {
            body["version"] = json!(v);
        }
        let (status, s) = upload(&db, &body).await;
        assert_eq!(status, StatusCode::CREATED, "{s}");
        s["analysis_id"].clone()
    };
    let a = ("a.js", "var x = 1;\neval(x);\n");
    let b = ("b.js", "let y = 2;\neval(y);\n");
    let c = ("c.js", "let z = 3;\neval(z);\n");

    // Versions that only start being sent don't move the period, and
    // neither do uploads without one.
    let first = analyze(&[a], None).await;
    analyze(&[a, b], Some("1.0")).await;
    analyze(&[a, b], None).await;
    let p = project(&app, &token, None).await;
    assert_eq!(
        (
            p["newCodePeriod"]["analysis"].clone(),
            p["newCodePeriod"]["version"].clone()
        ),
        (first.clone(), Value::Null)
    );
    assert_eq!(condition(&p, "new_vulnerabilities")["actual"], 1.0);

    // A new version starts it again at its first analysis.
    let v2 = analyze(&[a, b], Some("2.0")).await;
    let p = project(&app, &token, None).await;
    assert_eq!(
        (
            p["newCodePeriod"]["analysis"].clone(),
            p["newCodePeriod"]["version"].clone()
        ),
        (v2.clone(), json!("2.0"))
    );
    assert_eq!(condition(&p, "new_vulnerabilities")["actual"], 0.0);
    assert_eq!(p["analysis"]["version"], "2.0");
    analyze(&[a, b, c], Some("2.0")).await;
    let p = project(&app, &token, None).await;
    assert_eq!(p["newCodePeriod"]["analysis"], v2);
    assert_eq!(condition(&p, "new_vulnerabilities")["actual"], 1.0);
    let versions: Vec<Value> = p["history"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["version"].clone())
        .collect();
    assert_eq!(
        versions,
        [
            Value::Null,
            json!("1.0"),
            Value::Null,
            json!("2.0"),
            json!("2.0")
        ]
    );

    // An admin's start wins over versions until it's cleared.
    let admin = session_for(&db, "ada", "admin").await;
    let as_admin = [("cookie", admin.as_str()), ("sonda-csrf", "1")];
    let (_, period) = send(&app, reset(first.clone(), &as_admin)).await;
    assert_eq!(
        (
            period["analysis"].clone(),
            period["reset"].clone(),
            period["version"].clone()
        ),
        (first, json!(true), Value::Null)
    );
    analyze(&[a, b, c], Some("3.0")).await;
    let p = project(&app, &token, None).await;
    assert_eq!(p["newCodePeriod"]["reset"], true);
    assert_eq!(condition(&p, "new_vulnerabilities")["actual"], 2.0);
    let (_, period) = send(&app, reset(Value::Null, &as_admin)).await;
    assert_eq!(
        (period["reset"].clone(), period["version"].clone()),
        (json!(false), json!("3.0"))
    );

    // The server checks versions as the CLI does.
    let mut body = upload_json_for(dir.path(), &[a], "shop", "main");
    body["version"] = json!("1\n2");
    assert_eq!(upload(&db, &body).await.0, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn coverage_on_new_code_comes_from_per_file_coverage() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let app = http::router(state_with(db.pool.clone(), true), None);
    let bearer = format!("Bearer {TOKEN}");
    let token = [("authorization", bearer.as_str())];
    let dir = tempfile::tempdir().unwrap();
    let a = ("a.js", "let a = 1;\nlet b = 2;\n");
    let b = ("b.js", "let c = 3;\nlet d = 4;\n");

    // Without per-file coverage, the scan's value stands.
    upload(&db, &upload_json_for(dir.path(), &[a], "shop", "main")).await;
    let p = project(&app, &token, None).await;
    assert_eq!(
        p["newCodePeriod"]["fromScan"],
        json!(["new_coverage", "new_duplicated_lines_density"])
    );

    // b.js is new and half covered; a.js is covered but old. The scan saw
    // no git, so it called both new: 75%.
    let lcov = (
        "lcov.info",
        "SF:a.js\nDA:1,1\nDA:2,1\nend_of_record\nSF:b.js\nDA:1,2\nDA:2,0\nend_of_record\n",
    );
    let body = upload_json_for(dir.path(), &[a, b, lcov], "shop", "main");
    assert_eq!(body["report"]["measures"]["new_coverage"], 75.0);
    upload(&db, &body).await;
    let p = project(&app, &token, None).await;
    assert_eq!(p["measures"]["newCode"]["coverage"], 50.0);
    assert_eq!(
        p["newCodePeriod"]["fromScan"],
        json!(["new_duplicated_lines_density"])
    );
    assert_eq!(condition(&p, "new_coverage")["actual"], 50.0);
    assert_eq!(condition(&p, "new_coverage")["status"], "error");

    // The Overview's drill-down lists the least covered files.
    let (status, drill) = send(
        &app,
        Request::get("/api/drill/coverage")
            .header(header::AUTHORIZATION, &bearer)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{drill}");
    let shop = &drill["items"][0];
    assert_eq!(
        (shop["component"].as_str(), shop["value"].as_f64()),
        (Some("shop"), Some(75.0))
    );
    assert_eq!(
        shop["files"],
        json!([{ "dir": "", "base": "b.js", "value": "50.0%" }])
    );
}
