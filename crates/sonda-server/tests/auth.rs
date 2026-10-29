//! Signing in, sessions, and who may read and change what (ADR-0005), plus
//! the read-only rules catalog. Database tests skip without
//! SONDA_TEST_DATABASE_URL (see server.rs).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{TOKEN, TestDb, state, state_with, upload, upload_json};
use serde_json::{Value, json};
use sonda_server::{db, http};
use tower::ServiceExt;

/// Sends a request; returns the status, the `Set-Cookie` header and the
/// JSON body.
async fn send(app: &axum::Router, request: Request<Body>) -> (StatusCode, Option<String>, Value) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .map(|v| v.to_str().unwrap().to_string());
    let bytes = axum::body::to_bytes(response.into_body(), 4 << 20)
        .await
        .unwrap();
    (
        status,
        cookie,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn get(path: &str, cookie: Option<&str>) -> Request<Body> {
    let mut r = Request::get(path);
    if let Some(c) = cookie {
        r = r.header(header::COOKIE, c);
    }
    r.body(Body::empty()).unwrap()
}

fn sign_in(token: &str) -> Request<Body> {
    Request::post("/api/session")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json!({ "token": token }).to_string()))
        .unwrap()
}

/// "name=value" from a `Set-Cookie` header, as a browser would send it back.
fn cookie_pair(set_cookie: &str) -> String {
    set_cookie.split(';').next().unwrap().to_string()
}

#[tokio::test]
async fn a_browser_signs_in_reads_and_signs_out() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let app = http::router(state_with(db.pool.clone(), true), None);

    let (_, _, status) = send(&app, get("/api/session", None)).await;
    assert_eq!(
        status,
        json!({ "authenticated": false, "readsRequireAuth": true })
    );
    assert_eq!(
        send(&app, get("/api/rules", None)).await.0,
        StatusCode::UNAUTHORIZED
    );

    let (code, cookie, _) = send(&app, sign_in("wrong")).await;
    assert_eq!((code, cookie), (StatusCode::UNAUTHORIZED, None));

    let (code, cookie, _) = send(&app, sign_in(TOKEN)).await;
    assert_eq!(code, StatusCode::NO_CONTENT);
    let set_cookie = cookie.unwrap();
    for attribute in [
        "__Host-sonda_session=",
        "HttpOnly",
        "Secure",
        "SameSite=Strict",
        "Path=/",
    ] {
        assert!(set_cookie.contains(attribute), "{set_cookie}");
    }
    assert!(
        !set_cookie.contains(TOKEN),
        "the API token must never reach the browser"
    );
    let session = cookie_pair(&set_cookie);

    let (_, _, status) = send(&app, get("/api/session", Some(&session))).await;
    assert_eq!(status["authenticated"], true);
    assert_eq!(
        send(&app, get("/api/rules", Some(&session))).await.0,
        StatusCode::OK
    );

    let sign_out = Request::delete("/api/session")
        .header(header::COOKIE, &session)
        .body(Body::empty())
        .unwrap();
    let (code, cleared, _) = send(&app, sign_out).await;
    assert_eq!(code, StatusCode::NO_CONTENT);
    assert!(cleared.unwrap().contains("Max-Age=0"));
    // The old cookie is dead even if a browser kept it.
    assert_eq!(
        send(&app, get("/api/rules", Some(&session))).await.0,
        StatusCode::UNAUTHORIZED
    );
    db.drop().await;
}

#[tokio::test]
async fn expired_and_forged_sessions_are_rejected() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let app = http::router(state_with(db.pool.clone(), true), None);
    let session = cookie_pair(&send(&app, sign_in(TOKEN)).await.1.unwrap());
    sqlx::query("UPDATE sessions SET expires_at = now() - interval '1 second'")
        .execute(&db.pool)
        .await
        .unwrap();
    assert_eq!(
        send(&app, get("/api/rules", Some(&session))).await.0,
        StatusCode::UNAUTHORIZED
    );

    let forged = format!("__Host-sonda_session={}", "ab".repeat(32));
    assert_eq!(
        send(&app, get("/api/rules", Some(&forged))).await.0,
        StatusCode::UNAUTHORIZED
    );
    // Only a hash is stored: the database never holds a usable session.
    let stored: Vec<u8> = sqlx::query_scalar("SELECT token_sha256 FROM sessions")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert!(
        !session.contains(
            &stored
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        )
    );
    db.drop().await;
}

#[tokio::test]
async fn the_token_reads_too_and_loopback_servers_read_openly() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let protected = http::router(state_with(db.pool.clone(), true), None);
    let with_token = Request::get("/api/rules")
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&protected, with_token).await.0, StatusCode::OK);

    let open = http::router(state(db.pool.clone()), None);
    assert_eq!(send(&open, get("/api/rules", None)).await.0, StatusCode::OK);
    db.drop().await;
}

#[tokio::test]
async fn rules_report_live_counts_on_main_branches() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    // main is analyzed first, so it is the project's main branch...
    upload(
        &db,
        &upload_json(dir.path(), &[("a.js", "var a;\nvar b;\n")], "main"),
    )
    .await;
    // ...and a feature branch's issues are not counted.
    upload(
        &db,
        &upload_json(
            dir.path(),
            &[("a.js", "var a;\nvar b;\nvar c;\n")],
            "feature",
        ),
    )
    .await;

    let app = http::router(state(db.pool.clone()), None);
    let (code, _, catalog) = send(&app, get("/api/rules", None)).await;
    assert_eq!(code, StatusCode::OK);
    let rule = |id: &str| {
        catalog["rules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == id)
            .unwrap()
            .clone()
    };
    let no_var = rule("js/no-var");
    assert_eq!(
        (no_var["openIssues"].as_i64(), no_var["projects"].as_i64()),
        (Some(2), Some(1))
    );
    // Stable ids, as in reports; the web app chooses display names.
    assert_eq!(
        no_var["languages"],
        json!(["javascript", "typescript", "tsx"])
    );
    assert!(no_var["noncompliant"].is_string() && no_var["compliant"].is_string());
    assert_eq!(rule("js/no-eval")["openIssues"], 0);
    assert_eq!(
        catalog["total"].as_u64(),
        Some(catalog["rules"].as_array().unwrap().len() as u64)
    );
    let main: String = sqlx::query_scalar("SELECT main_branch FROM projects")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(main, "main");
    db.drop().await;
}
