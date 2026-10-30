//! Users, sign-in, sessions and roles (ADR-0006), who may read and change
//! what, and the read-only rules catalog. Database tests skip without
//! SONDA_TEST_DATABASE_URL (see server.rs).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{
    PASSWORD, TOKEN, TestDb, create_user, sign_in, state, state_with, upload, upload_json,
};
use serde_json::{Value, json};
use sonda_server::{db, http, users};
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

/// A request with optional cookie and JSON body. Changes carry the CSRF
/// header, as the web app sends it.
fn request(method: &str, path: &str, cookie: Option<&str>, body: Option<Value>) -> Request<Body> {
    let mut r = Request::builder().method(method).uri(path);
    if let Some(c) = cookie {
        r = r.header(header::COOKIE, c);
    }
    if method != "GET" {
        r = r.header("sonda-csrf", "1");
    }
    match body {
        Some(b) => r
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(b.to_string()))
            .unwrap(),
        None => r.body(Body::empty()).unwrap(),
    }
}

async fn migrated() -> Option<TestDb> {
    let db = TestDb::new().await?;
    db::migrate(&db.pool).await.unwrap();
    Some(db)
}

#[tokio::test]
async fn a_user_signs_in_reads_and_signs_out() {
    let Some(db) = migrated().await else { return };
    create_user(&db, "ann", "member").await;
    let app = http::router(state_with(db.pool.clone(), true), None);

    let (_, _, status) = send(&app, request("GET", "/api/session", None, None)).await;
    assert_eq!(
        status,
        json!({ "user": null, "authenticated": false, "readsRequireAuth": true })
    );
    assert_eq!(
        send(&app, request("GET", "/api/rules", None, None)).await.0,
        StatusCode::UNAUTHORIZED
    );

    // A wrong password and an unknown user get the very same answer.
    let attempt = |username: &str, password: &str| {
        request(
            "POST",
            "/api/session",
            None,
            Some(json!({ "username": username, "password": password })),
        )
    };
    let wrong = send(&app, attempt("ann", "not the password")).await;
    let unknown = send(&app, attempt("nobody", PASSWORD)).await;
    assert_eq!(wrong.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        (wrong.1.clone(), wrong.2.clone()),
        (None, json!({ "error": "invalid username or password" }))
    );
    assert_eq!(
        (wrong.0, wrong.1, wrong.2),
        (unknown.0, unknown.1, unknown.2)
    );
    // The API token is no longer a browser credential.
    let token = request(
        "POST",
        "/api/session",
        None,
        Some(json!({ "token": TOKEN })),
    );
    assert!(send(&app, token).await.0.is_client_error());

    let (code, set_cookie, _) = send(&app, attempt("ANN ", PASSWORD)).await;
    assert_eq!(
        code,
        StatusCode::NO_CONTENT,
        "usernames are case-insensitive and trimmed"
    );
    let set_cookie = set_cookie.unwrap();
    for attribute in [
        "__Host-sonda_session=",
        "HttpOnly",
        "Secure",
        "SameSite=Strict",
        "Path=/",
    ] {
        assert!(set_cookie.contains(attribute), "{set_cookie}");
    }
    let session = set_cookie.split(';').next().unwrap().to_string();
    let (_, _, status) = send(&app, request("GET", "/api/session", Some(&session), None)).await;
    assert_eq!(status["user"]["username"], "ann");
    assert_eq!(status["user"]["role"], "member");
    assert_eq!(
        send(&app, request("GET", "/api/rules", Some(&session), None))
            .await
            .0,
        StatusCode::OK
    );
    let last_login: Option<String> =
        sqlx::query_scalar("SELECT last_login_at::text FROM users WHERE username = 'ann'")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert!(last_login.is_some());

    let (code, cleared, _) = send(
        &app,
        request("DELETE", "/api/session", Some(&session), None),
    )
    .await;
    assert_eq!(code, StatusCode::NO_CONTENT);
    assert!(cleared.unwrap().contains("Max-Age=0"));
    assert_eq!(
        send(&app, request("GET", "/api/rules", Some(&session), None))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    db.drop().await;
}

#[tokio::test]
async fn the_first_admin_comes_from_the_secret_once() {
    let Some(db) = migrated().await else { return };
    users::bootstrap_admin(&db.pool, None).await.unwrap();
    let count = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM users")
            .fetch_one(&db.pool)
            .await
            .unwrap()
    };
    assert_eq!(count().await, 0, "no secret, no admin");

    users::bootstrap_admin(&db.pool, Some(("admin".into(), "first password!".into())))
        .await
        .unwrap();
    // A changed secret never resets the password once users exist.
    users::bootstrap_admin(&db.pool, Some(("admin".into(), "second password!".into())))
        .await
        .unwrap();
    assert_eq!(count().await, 1);
    let app = http::router(state(db.pool.clone()), None);
    assert!(sign_in(&app, "admin", "second password!").await.is_none());
    let session = sign_in(&app, "admin", "first password!").await.unwrap();
    let (_, _, status) = send(&app, request("GET", "/api/session", Some(&session), None)).await;
    assert_eq!(status["user"]["role"], "admin");
    // Stored as Argon2id, never in clear.
    let hash: String = sqlx::query_scalar("SELECT password_hash FROM users")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert!(hash.starts_with("$argon2id$") && !hash.contains("first password"));
    db.drop().await;
}

#[tokio::test]
async fn admins_manage_users_and_cannot_lock_everyone_out() {
    let Some(db) = migrated().await else { return };
    let admin_id = create_user(&db, "root", "admin").await;
    create_user(&db, "ann", "member").await;
    let app = http::router(state(db.pool.clone()), None);
    let admin = sign_in(&app, "root", PASSWORD).await.unwrap();
    let member = sign_in(&app, "ann", PASSWORD).await.unwrap();

    // Members and the API token cannot manage users.
    assert_eq!(
        send(&app, request("GET", "/api/users", Some(&member), None))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let with_token = Request::get("/api/users")
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&app, with_token).await.0, StatusCode::FORBIDDEN);

    let new = json!({ "username": "bob", "displayName": "Bob Builder", "role": "member", "password": "a long enough one" });
    let (code, _, bob) = send(
        &app,
        request("POST", "/api/users", Some(&admin), Some(new.clone())),
    )
    .await;
    assert_eq!(code, StatusCode::CREATED, "{bob}");
    assert_eq!(
        (bob["username"].as_str(), bob["displayName"].as_str()),
        (Some("bob"), Some("Bob Builder"))
    );
    assert!(
        bob.get("passwordHash").is_none(),
        "hashes never leave the server"
    );
    let (code, _, _) = send(&app, request("POST", "/api/users", Some(&admin), Some(new))).await;
    assert_eq!(code, StatusCode::UNPROCESSABLE_ENTITY, "username taken");
    let weak =
        json!({ "username": "eve", "displayName": "Eve", "role": "member", "password": "short" });
    assert_eq!(
        send(
            &app,
            request("POST", "/api/users", Some(&admin), Some(weak))
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    // Changes need the CSRF header, even from an admin.
    let no_csrf = Request::post("/api/users")
        .header(header::COOKIE, &admin)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json!({ "username": "x1", "displayName": "X", "role": "member", "password": "a long enough one" }).to_string()))
        .unwrap();
    assert_eq!(send(&app, no_csrf).await.0, StatusCode::FORBIDDEN);

    let (_, _, list) = send(&app, request("GET", "/api/users", Some(&admin), None)).await;
    let names: Vec<&str> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["username"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["ann", "bob", "root"]);

    // Disabling bob ends his sessions; he cannot sign in again.
    let bob_id = bob["id"].as_i64().unwrap();
    let bob_session = sign_in(&app, "bob", "a long enough one").await.unwrap();
    let disable = request(
        "PATCH",
        &format!("/api/users/{bob_id}"),
        Some(&admin),
        Some(json!({ "disabled": true })),
    );
    assert_eq!(send(&app, disable).await.0, StatusCode::OK);
    let (_, _, status) = send(
        &app,
        request("GET", "/api/session", Some(&bob_session), None),
    )
    .await;
    assert_eq!(status["user"], Value::Null, "disabled: the session is gone");
    assert!(sign_in(&app, "bob", "a long enough one").await.is_none());

    // A password reset signs the user out everywhere.
    let ann_id: i64 = sqlx::query_scalar("SELECT id FROM users WHERE username = 'ann'")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    let reset = request(
        "PATCH",
        &format!("/api/users/{ann_id}"),
        Some(&admin),
        Some(json!({ "password": "a brand new password" })),
    );
    assert_eq!(send(&app, reset).await.0, StatusCode::OK);
    assert_eq!(
        send(&app, request("GET", "/api/session", Some(&member), None))
            .await
            .2["user"],
        Value::Null
    );
    assert!(sign_in(&app, "ann", "a brand new password").await.is_some());

    // The last active admin can be neither disabled nor demoted.
    for change in [json!({ "disabled": true }), json!({ "role": "member" })] {
        let req = request(
            "PATCH",
            &format!("/api/users/{admin_id}"),
            Some(&admin),
            Some(change),
        );
        let (code, _, body) = send(&app, req).await;
        assert_eq!(code, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    }
    // With a second admin, the first may step down.
    let promote = request(
        "PATCH",
        &format!("/api/users/{ann_id}"),
        Some(&admin),
        Some(json!({ "role": "admin" })),
    );
    assert_eq!(send(&app, promote).await.0, StatusCode::OK);
    let step_down = request(
        "PATCH",
        &format!("/api/users/{admin_id}"),
        Some(&admin),
        Some(json!({ "role": "member" })),
    );
    assert_eq!(send(&app, step_down).await.0, StatusCode::OK);
    db.drop().await;
}

#[tokio::test]
async fn users_change_their_own_password() {
    let Some(db) = migrated().await else { return };
    create_user(&db, "ann", "member").await;
    let app = http::router(state(db.pool.clone()), None);
    let here = sign_in(&app, "ann", PASSWORD).await.unwrap();
    let elsewhere = sign_in(&app, "ann", PASSWORD).await.unwrap();
    let change = |current: &str| json!({ "current": current, "new": "an even better password" });

    let (code, _, _) = send(
        &app,
        request(
            "PUT",
            "/api/me/password",
            Some(&here),
            Some(change("wrong")),
        ),
    )
    .await;
    assert_eq!(code, StatusCode::FORBIDDEN);
    let short = json!({ "current": PASSWORD, "new": "short" });
    let (code, _, body) = send(
        &app,
        request("PUT", "/api/me/password", Some(&here), Some(short)),
    )
    .await;
    assert_eq!(code, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    let (code, _, _) = send(
        &app,
        request(
            "PUT",
            "/api/me/password",
            Some(&here),
            Some(change(PASSWORD)),
        ),
    )
    .await;
    assert_eq!(code, StatusCode::NO_CONTENT);

    // This session stays; the others end.
    let user = |s: &str| request("GET", "/api/session", Some(s), None);
    assert_eq!(send(&app, user(&here)).await.2["user"]["username"], "ann");
    assert_eq!(send(&app, user(&elsewhere)).await.2["user"], Value::Null);
    assert!(sign_in(&app, "ann", PASSWORD).await.is_none());
    assert!(
        sign_in(&app, "ann", "an even better password")
            .await
            .is_some()
    );
    db.drop().await;
}

#[tokio::test]
async fn expired_and_forged_sessions_are_rejected() {
    let Some(db) = migrated().await else { return };
    create_user(&db, "ann", "member").await;
    let app = http::router(state_with(db.pool.clone(), true), None);
    let session = sign_in(&app, "ann", PASSWORD).await.unwrap();
    sqlx::query("UPDATE sessions SET expires_at = now() - interval '1 second'")
        .execute(&db.pool)
        .await
        .unwrap();
    assert_eq!(
        send(&app, request("GET", "/api/rules", Some(&session), None))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );

    let forged = format!("__Host-sonda_session={}", "ab".repeat(32));
    assert_eq!(
        send(&app, request("GET", "/api/rules", Some(&forged), None))
            .await
            .0,
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
    let Some(db) = migrated().await else { return };
    let protected = http::router(state_with(db.pool.clone(), true), None);
    let with_token = Request::get("/api/rules")
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&protected, with_token).await.0, StatusCode::OK);
    let open = http::router(state(db.pool.clone()), None);
    assert_eq!(
        send(&open, request("GET", "/api/rules", None, None))
            .await
            .0,
        StatusCode::OK
    );
    db.drop().await;
}

#[tokio::test]
async fn rules_report_live_counts_on_main_branches() {
    let Some(db) = migrated().await else { return };
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
    let (code, _, catalog) = send(&app, request("GET", "/api/rules", None, None)).await;
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
    db.drop().await;
}
