//! Creating the GitHub App from the web app (ADR-0024), against a fake
//! GitHub. Database tests skip without SONDA_TEST_DATABASE_URL (see
//! server.rs); these also need `openssl` to make the App's key.

mod common;

use axum::Json;
use axum::body::Body;
use axum::extract::Path as UrlPath;
use axum::http::HeaderMap;
use axum::http::{Request, StatusCode, header};
use axum::routing::{get, post};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::{PASSWORD, TestDb, create_user, sign_in, state_with};
use serde_json::{Value, json};
use sonda_server::github::App;
use sonda_server::github_app::Connection;
use sonda_server::stored_secrets::SecretKey;
use sonda_server::{db, http};
use std::sync::Arc;
use tower::ServiceExt;

const ORIGIN: &str = "http://192.168.1.254:9300";

/// A fresh RSA key, PEM, from `openssl`; `None` where it's missing.
fn generate_key() -> Option<String> {
    let out = std::process::Command::new("openssl")
        .args(["genrsa", "2048"])
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8(out.stdout).unwrap())
}

fn secret_key(byte: u8) -> SecretKey {
    SecretKey::new(&STANDARD.encode([byte; 32])).unwrap()
}

/// GitHub converts the code `good`, once, into the App with `pem`.
async fn fake_github(pem: String) -> String {
    let used = Arc::new(std::sync::Mutex::new(false));
    let router = axum::Router::new().route(
        "/app-manifests/{code}/conversions",
        post(move |UrlPath(code): UrlPath<String>| async move {
            let mut used = used.lock().unwrap();
            if code != "good" || *used {
                return (StatusCode::NOT_FOUND, Json(json!({"message": "Not Found"})));
            }
            *used = true;
            (
                StatusCode::CREATED,
                Json(json!({
                    "id": 77, "slug": "sonda-test",
                    "html_url": "https://github.com/apps/sonda-test",
                    "pem": pem, "webhook_secret": "w", "client_secret": "c",
                })),
            )
        }),
    );
    // Installed on some of one account's repositories, and all of another's.
    let router = router
        .route(
            "/app/installations",
            get(|headers: HeaderMap| async move {
                assert!(bearer(&headers).starts_with("ey"), "the App's JWT");
                Json(json!([
                    {"id": 1, "account": {"login": "lvaoliveira"}, "repository_selection": "selected",
                     "html_url": "https://github.com/settings/installations/1"},
                    {"id": 2, "account": {"login": "acme"}, "repository_selection": "all",
                     "html_url": "https://github.com/organizations/acme/settings/installations/2"},
                ]))
            }),
        )
        .route(
            "/app/installations/1/access_tokens",
            post(|Json(body): Json<Value>| async move {
                assert_eq!(body, json!({"permissions": {"metadata": "read"}}));
                (StatusCode::CREATED, Json(json!({"token": "ghs_1"})))
            }),
        )
        .route(
            "/installation/repositories",
            get(|headers: HeaderMap| async move {
                assert_eq!(bearer(&headers), "ghs_1");
                Json(json!({"total_count": 1, "repositories": [{"full_name": "lvaoliveira/arandu"}]}))
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(axum::serve(listener, router).into_future());
    api
}

fn bearer(headers: &HeaderMap) -> String {
    headers[header::AUTHORIZATION]
        .to_str()
        .unwrap()
        .trim_start_matches("Bearer ")
        .to_string()
}

async fn send(
    app: &axum::Router,
    method: &str,
    path: &str,
    cookie: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut r = Request::builder()
        .method(method)
        .uri(path)
        .header(header::COOKIE, cookie)
        .header(header::ORIGIN, ORIGIN);
    if method != "GET" {
        r = r.header("sonda-csrf", "1");
    }
    let request = match body {
        Some(b) => r
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(b.to_string())),
        None => r.body(Body::empty()),
    }
    .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&bytes);
    assert!(!text.contains("PRIVATE KEY"), "{path}: {text}");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// The `state` in a manifest form's action.
fn state_of(form: &Value) -> String {
    let action = form["action"].as_str().unwrap();
    action.split_once("?state=").unwrap().1.to_string()
}

#[tokio::test]
async fn an_admin_creates_the_app_from_the_web_app() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    let Some(pem) = generate_key() else {
        eprintln!("skipped: needs openssl to make a GitHub App key");
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let api = fake_github(pem.clone()).await;
    let connection = Arc::new(Connection::new(
        None,
        Some(secret_key(1)),
        api.clone(),
        None,
    ));
    let mut state = state_with(db.pool.clone(), true);
    state.github = connection.clone();
    let server = http::router(state, None);
    create_user(&db, "ada", "admin").await;
    create_user(&db, "bob", "member").await;
    let ada = sign_in(&server, "ada", PASSWORD).await.unwrap();
    let bob = sign_in(&server, "bob", PASSWORD).await.unwrap();
    let new_app = json!({"owner": null, "name": "sonda-n100"});

    let (status, s) = send(&server, "GET", "/api/github/app", &ada, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        (s["source"].clone(), s["secretKey"].clone()),
        (Value::Null, json!(true))
    );
    for (method, path) in [
        ("GET", "/api/github/app"),
        ("POST", "/api/github/app/manifest"),
    ] {
        let (status, _) = send(&server, method, path, &bob, Some(new_app.clone())).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}");
    }

    // The manifest: GitHub's page, sonda's address from the browser's Origin.
    let (status, form) = send(
        &server,
        "POST",
        "/api/github/app/manifest",
        &ada,
        Some(new_app.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{form}");
    assert!(
        form["action"]
            .as_str()
            .unwrap()
            .starts_with(&format!("{api}/settings/apps/new?state="))
    );
    let manifest: Value = serde_json::from_str(form["manifest"].as_str().unwrap()).unwrap();
    assert_eq!(manifest["name"], "sonda-n100");
    assert_eq!(manifest["url"], ORIGIN);
    assert_eq!(
        manifest["redirect_url"],
        format!("{ORIGIN}/admin/github/created")
    );
    assert_eq!(manifest["public"], false);
    assert_eq!(
        manifest["default_permissions"],
        json!({"checks": "write", "pull_requests": "write", "metadata": "read"})
    );
    assert!(manifest.get("hook_attributes").is_none() && manifest.get("default_events").is_none());
    let (_, org) = send(
        &server,
        "POST",
        "/api/github/app/manifest",
        &ada,
        Some(json!({"owner": "acme", "name": "sonda"})),
    )
    .await;
    assert!(org["action"].as_str().unwrap().starts_with(&format!(
        "{api}/organizations/acme/settings/apps/new?state="
    )));
    for bad in [
        json!({"owner": "-acme", "name": "x"}),
        json!({"owner": null, "name": " "}),
        json!({"owner": null, "name": "x".repeat(35)}),
    ] {
        let (status, _) = send(
            &server,
            "POST",
            "/api/github/app/manifest",
            &ada,
            Some(bad.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{bad}");
    }

    // A state that's unknown, or already used by a code GitHub refused.
    let complete = |code: &str, state: &str| json!({"code": code, "state": state});
    let (status, _) = send(
        &server,
        "POST",
        "/api/github/app",
        &ada,
        Some(complete("good", "nope")),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let used = state_of(&form);
    let (status, e) = send(
        &server,
        "POST",
        "/api/github/app",
        &ada,
        Some(complete("bad", &used)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        e["error"]
            .as_str()
            .unwrap()
            .contains("didn't accept the code"),
        "{e}"
    );
    let (status, _) = send(
        &server,
        "POST",
        "/api/github/app",
        &ada,
        Some(complete("good", &used)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "a state works once");
    assert!(connection.app().is_none());
    let (status, _) = send(&server, "GET", "/api/github/app/installations", &ada, None).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "no App yet");

    // Created: decorating with it at once, its key stored encrypted.
    let (_, form) = send(
        &server,
        "POST",
        "/api/github/app/manifest",
        &ada,
        Some(new_app.clone()),
    )
    .await;
    let (status, s) = send(
        &server,
        "POST",
        "/api/github/app",
        &ada,
        Some(complete("good", &state_of(&form))),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{s}");
    assert_eq!(s["source"], "stored");
    assert_eq!(s["id"], "77");
    assert_eq!(s["slug"], "sonda-test");
    assert_eq!(
        s["installUrl"],
        "https://github.com/apps/sonda-test/installations/new"
    );
    assert_eq!(s["createdBy"], "ada");
    assert_eq!(connection.app().unwrap().id(), "77");
    let (status, installed) =
        send(&server, "GET", "/api/github/app/installations", &ada, None).await;
    assert_eq!(status, StatusCode::OK, "{installed}");
    assert_eq!(
        installed,
        json!([
            {"account": "lvaoliveira", "settingsUrl": "https://github.com/settings/installations/1",
             "repositories": ["lvaoliveira/arandu"]},
            {"account": "acme", "settingsUrl": "https://github.com/organizations/acme/settings/installations/2",
             "repositories": null},
        ])
    );
    let ciphertext: Vec<u8> = sqlx::query_scalar("SELECT ciphertext FROM encrypted_secrets")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert!(!ciphertext.windows(11).any(|w| w == b"PRIVATE KEY"));
    let (status, e) = send(
        &server,
        "POST",
        "/api/github/app/manifest",
        &ada,
        Some(new_app.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        e["error"].as_str().unwrap().contains("already connected"),
        "{e}"
    );

    // After a restart: read back with the same key; unreadable without it.
    let restarted = Connection::new(None, Some(secret_key(1)), api.clone(), None);
    restarted.load(&db.pool).await.unwrap();
    assert_eq!(restarted.app().unwrap().id(), "77");
    for key in [Some(secret_key(2)), None] {
        let restarted = Arc::new(Connection::new(None, key, api.clone(), None));
        restarted.load(&db.pool).await.unwrap();
        assert!(restarted.app().is_none());
        let mut state = state_with(db.pool.clone(), true);
        state.github = restarted.clone();
        let server = http::router(state, None);
        let (_, s) = send(&server, "GET", "/api/github/app", &ada, None).await;
        assert_eq!(s["source"], "unreadable");
        assert_eq!(s["slug"], "sonda-test");
    }

    // Disconnected: gone from the database, and decorating stops.
    let (status, s) = send(&server, "DELETE", "/api/github/app", &ada, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(s["source"], Value::Null);
    assert!(connection.app().is_none());
    let rows: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM github_app) + (SELECT count(*) FROM encrypted_secrets)",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(rows, 0);
}

#[tokio::test]
async fn a_configured_app_or_a_missing_secret_key_leaves_nothing_to_create() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    let Some(pem) = generate_key() else {
        eprintln!("skipped: needs openssl to make a GitHub App key");
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    create_user(&db, "ada", "admin").await;
    let new_app = json!({"owner": null, "name": "sonda"});
    let app = Arc::new(App::new("123".into(), &pem, "https://api.github.com".into()).unwrap());
    let server_with = |connection: Connection| {
        let mut state = state_with(db.pool.clone(), true);
        state.github = Arc::new(connection);
        http::router(state, None)
    };

    let configured = server_with(Connection::new(
        Some(app),
        Some(secret_key(1)),
        "https://api.github.com".into(),
        None,
    ));
    let ada = sign_in(&configured, "ada", PASSWORD).await.unwrap();
    let (_, s) = send(&configured, "GET", "/api/github/app", &ada, None).await;
    assert_eq!(
        (s["source"].clone(), s["id"].clone()),
        (json!("config"), json!("123"))
    );
    let (status, _) = send(
        &configured,
        "POST",
        "/api/github/app/manifest",
        &ada,
        Some(new_app.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let (status, e) = send(&configured, "DELETE", "/api/github/app", &ada, None).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        e["error"].as_str().unwrap().contains("SONDA_GITHUB_APP_ID"),
        "{e}"
    );

    let keyless = server_with(Connection::new(
        None,
        None,
        "https://api.github.com".into(),
        None,
    ));
    let (_, s) = send(&keyless, "GET", "/api/github/app", &ada, None).await;
    assert_eq!(s["secretKey"], false);
    let (status, e) = send(
        &keyless,
        "POST",
        "/api/github/app/manifest",
        &ada,
        Some(new_app.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        e["error"].as_str().unwrap().contains("SONDA_SECRET_KEY"),
        "{e}"
    );

    // SONDA_PUBLIC_URL, when set, is the address GitHub sends back to.
    let public = server_with(Connection::new(
        None,
        Some(secret_key(1)),
        "https://api.github.com".into(),
        Some("https://sonda.example.com".into()),
    ));
    let (_, form) = send(
        &public,
        "POST",
        "/api/github/app/manifest",
        &ada,
        Some(new_app),
    )
    .await;
    assert!(
        form["action"]
            .as_str()
            .unwrap()
            .starts_with("https://github.com/settings/apps/new?state=")
    );
    let manifest: Value = serde_json::from_str(form["manifest"].as_str().unwrap()).unwrap();
    assert_eq!(
        manifest["redirect_url"],
        "https://sonda.example.com/admin/github/created"
    );
}
