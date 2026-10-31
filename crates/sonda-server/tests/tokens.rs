//! User and analysis tokens (ADR-0012). Database tests skip without
//! SONDA_TEST_DATABASE_URL (see server.rs).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{TOKEN, TestDb, gzip, post, state_with, upload_json_for};
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

/// A signed-in user, without a password: a session straight from the store.
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

fn as_session(r: axum::http::request::Builder, cookie: &str) -> axum::http::request::Builder {
    r.header(header::COOKIE, cookie).header("sonda-csrf", "1")
}

fn bearer(r: axum::http::request::Builder, token: &str) -> axum::http::request::Builder {
    r.header(header::AUTHORIZATION, format!("Bearer {token}"))
}

fn json_body(body: Value) -> Body {
    Body::from(body.to_string())
}

async fn generate(app: &axum::Router, cookie: &str, body: Value) -> (StatusCode, Value) {
    let r = as_session(Request::post("/api/me/tokens"), cookie)
        .header(header::CONTENT_TYPE, "application/json");
    send(app, r.body(json_body(body)).unwrap()).await
}

async fn upload_as(app: &axum::Router, token: &str, body: &Value) -> StatusCode {
    post(
        app.clone(),
        Some(token),
        gzip(&serde_json::to_vec(body).unwrap()),
    )
    .await
    .0
}

#[tokio::test]
async fn tokens_act_for_their_owner_within_their_type() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let app = http::router(state_with(db.pool.clone(), true), None);
    let max = session_for(&db, "max", "member").await;
    let ada = session_for(&db, "ada", "admin").await;
    let dir = tempfile::tempdir().unwrap();
    let analysis = |project: &str| {
        upload_json_for(
            dir.path(),
            &[("a.js", "var x = 1;\neval(x);\n")],
            project,
            "main",
        )
    };

    // Generating: each type, with its expiry.
    let (status, user) = generate(
        &app,
        &max,
        json!({ "name": "scripts", "type": "user", "expiresInDays": 30 }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{user}");
    let user_token = user["token"].as_str().unwrap().to_string();
    assert!(user_token.starts_with("sonda_u_"));
    assert_eq!(user["prefix"], &user_token[..12]);
    assert_eq!(user["status"], "active");
    assert!(user["expiresAt"].is_string());
    let (_, project) = generate(
        &app,
        &max,
        json!({ "name": "ci-shop", "type": "project_analysis", "project": "shop", "expiresInDays": null }),
    )
    .await;
    let project_token = project["token"].as_str().unwrap().to_string();
    assert!(project_token.starts_with("sonda_p_"));
    assert_eq!(project["expiresAt"], Value::Null);
    let (_, global) = generate(
        &app,
        &max,
        json!({ "name": "ci-all", "type": "global_analysis", "expiresInDays": 60 }),
    )
    .await;
    let global_token = global["token"].as_str().unwrap().to_string();
    assert!(global_token.starts_with("sonda_a_"));

    for bad in [
        json!({ "name": "x", "type": "admin", "expiresInDays": 30 }),
        json!({ "name": "x", "type": "project_analysis", "expiresInDays": 30 }),
        json!({ "name": "x", "type": "user", "project": "shop", "expiresInDays": 30 }),
        json!({ "name": "x", "type": "project_analysis", "project": "-bad", "expiresInDays": 30 }),
        json!({ "name": "x", "type": "user", "expiresInDays": 45 }),
        json!({ "name": " ", "type": "user", "expiresInDays": 30 }),
        json!({ "name": "scripts", "type": "user", "expiresInDays": 30 }),
    ] {
        assert_eq!(
            generate(&app, &max, bad.clone()).await.0,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{bad}"
        );
    }

    // Uploads: a project analysis token uploads its project only.
    assert_eq!(
        upload_as(&app, &project_token, &analysis("shop")).await,
        StatusCode::CREATED
    );
    assert_eq!(
        upload_as(&app, &project_token, &analysis("other")).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        upload_as(&app, &global_token, &analysis("other")).await,
        StatusCode::CREATED
    );
    assert_eq!(
        upload_as(&app, &user_token, &analysis("shop")).await,
        StatusCode::CREATED
    );
    // A browser session doesn't upload.
    let session_upload = as_session(Request::post("/api/analyses"), &max)
        .header(header::CONTENT_TYPE, "application/json")
        .body(json_body(analysis("shop")))
        .unwrap();
    assert_eq!(send(&app, session_upload).await.0, StatusCode::FORBIDDEN);

    // Who uploaded each analysis.
    let (_, list) = send(
        &app,
        bearer(Request::get("/api/analyses"), &user_token)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let uploaders: Vec<&str> = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["uploadedBy"].as_str().unwrap())
        .collect();
    assert_eq!(
        uploaders,
        [
            "max (token scripts)",
            "max (token ci-all)",
            "max (token ci-shop)"
        ]
    );

    // Reads and triage: user tokens, as their owner; analysis tokens don't.
    let read = |token: &str| {
        bearer(Request::get("/api/projects"), token)
            .body(Body::empty())
            .unwrap()
    };
    assert_eq!(send(&app, read(&user_token)).await.0, StatusCode::OK);
    assert_eq!(
        send(&app, read(&project_token)).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(&app, read(&global_token)).await.0,
        StatusCode::FORBIDDEN
    );
    let issue: i64 = sqlx::query_scalar("SELECT min(id) FROM issues")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    let triage = |token: &str| {
        bearer(Request::patch(format!("/api/issues/{issue}")), token)
            .header(header::CONTENT_TYPE, "application/json")
            .body(json_body(json!({ "status": "confirmed" })))
            .unwrap()
    };
    assert_eq!(
        send(&app, triage(&global_token)).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(send(&app, triage(&user_token)).await.0, StatusCode::OK);
    let actor: String =
        sqlx::query_scalar("SELECT actor FROM issue_events ORDER BY id DESC LIMIT 1")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(actor, "max (token scripts)");

    // Tokens can't manage tokens or users; a session can.
    let mine = |r: axum::http::request::Builder| r.body(Body::empty()).unwrap();
    assert_eq!(
        send(
            &app,
            mine(bearer(Request::get("/api/me/tokens"), &user_token))
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let (status, own) = send(&app, mine(as_session(Request::get("/api/me/tokens"), &max))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(own.as_array().unwrap().len(), 3);
    // Lists never carry a secret.
    assert!(!own.to_string().contains(&user_token));
    // Only admins list everyone's.
    assert_eq!(
        send(&app, mine(as_session(Request::get("/api/tokens"), &max)))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let (_, all) = send(&app, mine(as_session(Request::get("/api/tokens"), &ada))).await;
    assert_eq!(all[0]["owner"], "max");

    // Revoking: by the owner, or by an admin; it's immediate and kept.
    let revoke = |path: String, cookie: &str| {
        as_session(Request::delete(path), cookie)
            .body(Body::empty())
            .unwrap()
    };
    let global_id = global["id"].as_i64().unwrap();
    assert_eq!(
        send(&app, revoke(format!("/api/me/tokens/{global_id}"), &max))
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        upload_as(&app, &global_token, &analysis("other")).await,
        StatusCode::UNAUTHORIZED
    );
    let project_id = project["id"].as_i64().unwrap();
    // Another member can't revoke it; an admin can.
    let other = session_for(&db, "eve", "member").await;
    assert_eq!(
        send(&app, revoke(format!("/api/me/tokens/{project_id}"), &other))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        send(&app, revoke(format!("/api/tokens/{project_id}"), &ada))
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        upload_as(&app, &project_token, &analysis("shop")).await,
        StatusCode::UNAUTHORIZED
    );
    let (_, own) = send(&app, mine(as_session(Request::get("/api/me/tokens"), &max))).await;
    let revoked: Vec<(&str, &str, Value)> = own
        .as_array()
        .unwrap()
        .iter()
        .map(|t| {
            (
                t["name"].as_str().unwrap(),
                t["status"].as_str().unwrap(),
                t["revokedBy"].clone(),
            )
        })
        .collect();
    assert_eq!(
        revoked,
        [
            ("ci-all", "revoked", json!("max")),
            ("ci-shop", "revoked", json!("ada")),
            ("scripts", "active", Value::Null),
        ]
    );
    // A revoked token's name can be used again.
    assert_eq!(
        generate(
            &app,
            &max,
            json!({ "name": "ci-all", "type": "global_analysis", "expiresInDays": 30 })
        )
        .await
        .0,
        StatusCode::CREATED
    );

    // Used tokens record it.
    let used: bool = sqlx::query_scalar(
        "SELECT last_used_at IS NOT NULL FROM api_tokens WHERE name = 'scripts'",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert!(used);

    // Expired tokens stop, and so do a disabled owner's.
    sqlx::query(
        "UPDATE api_tokens SET expires_at = now() - interval '1 second' WHERE name = 'scripts'",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    assert_eq!(
        send(&app, read(&user_token)).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (_, fresh) = generate(
        &app,
        &max,
        json!({ "name": "fresh", "type": "user", "expiresInDays": 90 }),
    )
    .await;
    let fresh = fresh["token"].as_str().unwrap().to_string();
    assert_eq!(send(&app, read(&fresh)).await.0, StatusCode::OK);
    sqlx::query("UPDATE users SET disabled = true WHERE username = 'max'")
        .execute(&db.pool)
        .await
        .unwrap();
    assert_eq!(send(&app, read(&fresh)).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn sonda_token_is_optional() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let mut state = state_with(db.pool.clone(), true);
    state.token = None;
    let app = http::router(state, None);
    let ada = session_for(&db, "ada", "admin").await;
    let dir = tempfile::tempdir().unwrap();
    let body = upload_json_for(dir.path(), &[("a.js", "let a;\n")], "shop", "main");
    // Without SONDA_TOKEN, the old shared secret is just a wrong token.
    assert_eq!(
        upload_as(&app, TOKEN, &body).await,
        StatusCode::UNAUTHORIZED
    );
    let (_, token) = generate(
        &app,
        &ada,
        json!({ "name": "ci", "type": "project_analysis", "project": "shop", "expiresInDays": 30 }),
    )
    .await;
    assert_eq!(
        upload_as(&app, token["token"].as_str().unwrap(), &body).await,
        StatusCode::CREATED
    );
}
