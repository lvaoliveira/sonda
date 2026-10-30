//! `POST /api/analyses`: auth, validation, and issue tracking across
//! analyses. Upload bodies are built by sonda-core exactly as `sonda upload`
//! builds them: scan a project, render the JSON report, `upload::prepare`.
//! Database tests skip without SONDA_TEST_DATABASE_URL (see server.rs).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::{TOKEN, TestDb, gzip, post, state, unreachable_pool, upload, upload_json};
use serde_json::Value;
use sonda_server::{db, http};
use tower::ServiceExt;

#[tokio::test]
async fn uploads_need_the_token() {
    let app = || http::router(state(unreachable_pool()), None);
    let body = gzip(b"{}");
    for token in [None, Some("wrong"), Some(&TOKEN[1..])] {
        let (status, json) = post(app(), token, body.clone()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{token:?}");
        assert_eq!(json["error"], "sign in or send the API token");
    }
}

#[tokio::test]
async fn malformed_bodies_are_rejected() {
    let app = || http::router(state(unreachable_pool()), None);
    let (status, _) = post(app(), Some(TOKEN), b"not gzip".to_vec()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = post(app(), Some(TOKEN), gzip(b"{\"project\": 1}")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let request = Request::post("/api/analyses")
        .header("Authorization", format!("Bearer {TOKEN}"))
        .header("Content-Encoding", "br")
        .body(Body::from("x"))
        .unwrap();
    let response = app().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn issues_are_tracked_across_analyses() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let dir = tempfile::tempdir().unwrap();

    // 1. Two issues: js/no-var and js/no-eval.
    let first = upload_json(dir.path(), &[("a.js", "var x = 1;\neval(x);\n")], "main");
    let (status, summary) = upload(&db, &first).await;
    assert_eq!(status, StatusCode::CREATED, "{summary}");
    assert_eq!(
        summary["issues"],
        serde_json::json!({ "open": 2, "new": 2, "reopened": 0, "fixed": 0 })
    );
    let var_id: i64 = sqlx::query_scalar("SELECT id FROM issues WHERE rule = 'js/no-var'")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    // A human accepts the var issue. (The API for this comes next.)
    sqlx::query("UPDATE issues SET status = 'accepted' WHERE id = $1")
        .bind(var_id)
        .execute(&db.pool)
        .await
        .unwrap();

    // 2. eval removed, and the var line moved down: one fixed, the other
    //    kept, at its new line, still accepted.
    let second = upload_json(dir.path(), &[("a.js", "// moved\n\nvar x = 1;\n")], "main");
    let (_, summary) = upload(&db, &second).await;
    assert_eq!(
        summary["issues"],
        serde_json::json!({ "open": 1, "new": 0, "reopened": 0, "fixed": 1 })
    );
    let (line, status): (i32, String) =
        sqlx::query_as("SELECT line, status::text FROM issues WHERE id = $1")
            .bind(var_id)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!((line, status.as_str()), (3, "accepted"));

    // 3. eval comes back: the same issue reopens; nothing is new.
    let third = upload_json(
        dir.path(),
        &[("a.js", "// moved\n\nvar x = 1;\neval(x);\n")],
        "main",
    );
    let (_, summary) = upload(&db, &third).await;
    assert_eq!(
        summary["issues"],
        serde_json::json!({ "open": 2, "new": 0, "reopened": 1, "fixed": 0 })
    );
    let tracked: i64 = sqlx::query_scalar("SELECT count(*) FROM issues")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(tracked, 2, "reopened, not duplicated");

    // Another branch tracks its issues separately.
    let (_, summary) = upload(&db, &upload_json(dir.path(), &[], "feature/x")).await;
    assert_eq!(summary["issues"]["new"], 2);

    // Unchanged files are stored once however many analyses include them.
    let (analyses, sources): (i64, i64) =
        sqlx::query_as("SELECT (SELECT count(*) FROM analyses), (SELECT count(*) FROM sources)")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!((analyses, sources), (4, 3));
    db.drop().await;
}

/// Changes a valid upload into an invalid one.
type Tamper = Box<dyn Fn(&mut Value)>;

#[tokio::test]
async fn tampered_uploads_are_rejected_and_store_nothing() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let good = upload_json(dir.path(), &[("src/a.js", "var x = 1;\n")], "main");

    let cases: Vec<(&str, Tamper)> = vec![
        (
            "does not match its sha256",
            Box::new(|b| b["sources"][0]["content"] = "var y;\n".into()),
        ),
        (
            "unknown rule",
            Box::new(|b| b["report"]["issues"][0]["rule"] = "js/evil".into()),
        ),
        (
            "unsafe path",
            Box::new(|b| {
                b["report"]["files"][0]["path"] = "../etc/passwd".into();
            }),
        ),
        (
            "not in the report",
            Box::new(|b| b["sources"][0]["path"] = "other.js".into()),
        ),
        (
            "which is not in the report",
            Box::new(|b| b["report"]["issues"][0]["path"] = "x.js".into()),
        ),
        (
            "invalid fingerprint",
            Box::new(|b| b["report"]["issues"][0]["fingerprint"] = "zz".into()),
        ),
        (
            "invalid project key",
            Box::new(|b| b["project"] = "../x".into()),
        ),
        (
            "report_version",
            Box::new(|b| b["report"]["report_version"] = 99.into()),
        ),
        (
            "files but",
            Box::new(|b| b["sources"] = Value::Array(vec![])),
        ),
        (
            "CODEOWNERS file is too large",
            Box::new(|b| b["codeowners"] = "x".repeat(200_000).into()),
        ),
    ];
    for (expected, tamper) in cases {
        let mut body = good.clone();
        tamper(&mut body);
        let (status, json) = upload(&db, &body).await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{expected}: {json}"
        );
        let error = json["error"].as_str().unwrap();
        assert!(
            error.contains(expected),
            "expected {expected:?} in {error:?}"
        );
    }
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM projects")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(stored, 0);
    db.drop().await;
}
