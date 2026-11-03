//! Decorating pull requests on GitHub (ADR-0021), against a fake GitHub.
//! Database tests skip without SONDA_TEST_DATABASE_URL (see server.rs);
//! this one also needs `openssl` to make the App's key, so none is checked
//! in.

mod common;

use axum::Json;
use axum::extract::{Path as UrlPath, State as Shared};
use axum::http::{HeaderMap, StatusCode, header};
use axum::routing::{get, patch, post};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{PASSWORD, TestDb, create_user, sign_in, state_with, upload_json_for};
use serde_json::{Value, json};
use sonda_server::{db, decorations, github::App, github_app::Connection, http};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

/// What the fake GitHub saw, and whether it answers.
#[derive(Default)]
struct Fake {
    down: bool,
    tokens_issued: usize,
    check_runs: Vec<Value>,
    /// (id, body)
    comments: Vec<(u64, String)>,
    /// The App's public key, to check each JWT.
    public_key: Vec<u8>,
}

type Github = Arc<Mutex<Fake>>;

fn checked_jwt(fake: &Fake, headers: &HeaderMap) -> bool {
    let Some(jwt) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    else {
        return false;
    };
    let Some((message, signature)) = jwt.rsplit_once('.') else {
        return false;
    };
    let key = ring::signature::UnparsedPublicKey::new(
        &ring::signature::RSA_PKCS1_2048_8192_SHA256,
        &fake.public_key,
    );
    let claims: Value = message
        .split('.')
        .nth(1)
        .and_then(|c| URL_SAFE_NO_PAD.decode(c).ok())
        .and_then(|c| serde_json::from_slice(&c).ok())
        .unwrap_or_default();
    key.verify(
        message.as_bytes(),
        &URL_SAFE_NO_PAD.decode(signature).unwrap_or_default(),
    )
    .is_ok()
        && claims["iss"] == "123"
}

fn installation_token(headers: &HeaderMap) -> bool {
    headers
        .get(header::AUTHORIZATION)
        .is_some_and(|v| v == "Bearer ghs_test")
}

/// A 503 while GitHub is down.
fn refuse(g: &Fake) -> Option<(StatusCode, Json<Value>)> {
    g.down.then(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"message": "down"})),
        )
    })
}

fn fake_github(github: Github) -> axum::Router {
    axum::Router::new()
        .route(
            "/repos/{owner}/{repo}/installation",
            get(|Shared(g): Shared<Github>, headers: HeaderMap| async move {
                let g = g.lock().unwrap();
                if let Some(down) = refuse(&g) {
                    return down;
                }
                if !checked_jwt(&g, &headers) {
                    return (StatusCode::UNAUTHORIZED, Json(json!({"message": "bad JWT"})));
                }
                (StatusCode::OK, Json(json!({"id": 99})))
            }),
        )
        .route(
            "/app/installations/99/access_tokens",
            post(|Shared(g): Shared<Github>, headers: HeaderMap, Json(body): Json<Value>| async move {
                let mut g = g.lock().unwrap();
                assert!(checked_jwt(&g, &headers));
                assert_eq!(body, json!({"repositories": ["shop"]}));
                g.tokens_issued += 1;
                (StatusCode::CREATED, Json(json!({"token": "ghs_test"})))
            }),
        )
        .route(
            "/repos/acme/shop/check-runs",
            post(|Shared(g): Shared<Github>, headers: HeaderMap, Json(body): Json<Value>| async move {
                let mut g = g.lock().unwrap();
                if let Some(down) = refuse(&g) {
                    return down;
                }
                assert!(installation_token(&headers));
                g.check_runs.push(body);
                (StatusCode::CREATED, Json(json!({"id": 1})))
            }),
        )
        .route(
            "/repos/acme/shop/issues/12/comments",
            get(|Shared(g): Shared<Github>, headers: HeaderMap| async move {
                assert!(installation_token(&headers));
                let g = g.lock().unwrap();
                let list: Vec<Value> = g.comments.iter().map(|(id, body)| json!({"id": id, "body": body})).collect();
                Json(Value::from(list))
            })
            .post(|Shared(g): Shared<Github>, headers: HeaderMap, Json(body): Json<Value>| async move {
                assert!(installation_token(&headers));
                let mut g = g.lock().unwrap();
                let id = 500 + g.comments.len() as u64;
                g.comments.push((id, body["body"].as_str().unwrap().to_string()));
                (StatusCode::CREATED, Json(json!({"id": id})))
            }),
        )
        .route(
            "/repos/acme/shop/issues/comments/{id}",
            patch(
                |Shared(g): Shared<Github>, UrlPath(id): UrlPath<u64>, headers: HeaderMap, Json(body): Json<Value>| async move {
                    assert!(installation_token(&headers));
                    let mut g = g.lock().unwrap();
                    let c = g.comments.iter_mut().find(|c| c.0 == id).unwrap();
                    c.1 = body["body"].as_str().unwrap().to_string();
                    Json(json!({"id": id}))
                },
            ),
        )
        .with_state(github)
}

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

async fn send(
    app: &axum::Router,
    request: axum::http::Request<axum::body::Body>,
) -> (StatusCode, Value) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 8 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// In a directory of its own: a scan reads every file there.
fn pull_request(files: &[(&str, &str)], repository: &str) -> Value {
    let dir = tempfile::tempdir().unwrap();
    let mut body = upload_json_for(dir.path(), files, "shop", "fix/login");
    body["pull_request"] = json!({
        "number": 12, "base": "main", "head": "fix/login",
        "head_sha": "c".repeat(40), "repository": repository,
    });
    body
}

#[tokio::test]
async fn pull_requests_get_a_check_and_one_comment_on_github() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    let Some(key) = generate_key() else {
        eprintln!("skipped: needs openssl to make a GitHub App key");
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let github: Github = Arc::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(axum::serve(listener, fake_github(github.clone())).into_future());
    let app_client = Arc::new(App::new("123".into(), &key, api.clone()).unwrap());
    github.lock().unwrap().public_key = app_client.public_key();

    let mut state = state_with(db.pool.clone(), true);
    state.github = Arc::new(Connection::new(Some(app_client.clone()), None, api, None));
    let server = http::router(state, None);
    create_user(&db, "ada", "admin").await;
    let ada = sign_in(&server, "ada", PASSWORD).await.unwrap();
    let upload = |body: Value| {
        axum::http::Request::post("/api/analyses")
            .header(header::AUTHORIZATION, format!("Bearer {}", common::TOKEN))
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap()
    };
    let decoration = |analysis: i64| {
        let server = server.clone();
        let ada = ada.clone();
        async move {
            let (_, a) = send(
                &server,
                axum::http::Request::get(format!("/api/analyses/{analysis}"))
                    .header(header::COOKIE, ada)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await;
            a["decoration"].clone()
        }
    };
    let post_due =
        || decorations::post_due(&db.pool, &app_client, Some("https://sonda.example.com"));
    let dir = tempfile::tempdir().unwrap();
    let clean = [("a.js", "const a = 1;\nexport { a };\n")];
    let eval = [
        ("a.js", "const a = 1;\nexport { a };\n"),
        ("b.js", "eval(input);\n"),
    ];
    send(
        &server,
        upload(upload_json_for(dir.path(), &clean, "shop", "main")),
    )
    .await;

    // Not linked to a repository yet: nothing posted, and the analysis says why.
    let (status, answer) = send(&server, upload(pull_request(&eval, "acme/shop"))).await;
    assert_eq!(status, StatusCode::CREATED, "{answer}");
    let first = answer["analysis_id"].as_i64().unwrap();
    let d = decoration(first).await;
    assert_eq!(d["state"], "not_posted");
    assert!(
        d["lastError"].as_str().unwrap().contains("isn't linked"),
        "{d}"
    );

    // Linked: the next upload is posted, a failing check and one comment.
    let (status, s) = send(
        &server,
        axum::http::Request::patch("/api/projects/shop/settings")
            .header(header::COOKIE, &ada)
            .header("sonda-csrf", "1")
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                json!({"githubRepository": "acme/shop"}).to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(
        (status, &s["githubRepository"], &s["githubApp"]),
        (StatusCode::OK, &json!("acme/shop"), &json!(true))
    );
    let (_, answer) = send(&server, upload(pull_request(&eval, "acme/shop"))).await;
    let second = answer["analysis_id"].as_i64().unwrap();
    assert_eq!(decoration(second).await["state"], "pending");
    assert_eq!(post_due().await.unwrap(), 1);
    assert_eq!(decoration(second).await["state"], "posted");
    {
        let g = github.lock().unwrap();
        let run = &g.check_runs[0];
        assert_eq!(
            (&run["name"], &run["head_sha"]),
            (&json!("sonda"), &json!("c".repeat(40)))
        );
        assert_eq!(
            run["details_url"],
            format!("https://sonda.example.com/analyses/{second}")
        );
        let annotations = run["output"]["annotations"].as_array().unwrap();
        assert!(
            annotations
                .iter()
                .any(|a| a["path"] == "b.js" && a["start_line"] == 1),
            "{run}"
        );
        assert_eq!(g.comments.len(), 1);
        assert!(g.comments[0].1.starts_with("<!-- sonda:project=shop -->"));
    }

    // Fixed: the same comment is edited, not another added, and the
    // installation token is reused.
    let (_, answer) = send(&server, upload(pull_request(&clean, "acme/shop"))).await;
    let third = answer["analysis_id"].as_i64().unwrap();
    assert_eq!(post_due().await.unwrap(), 1);
    {
        let g = github.lock().unwrap();
        assert_eq!(g.check_runs.len(), 2);
        assert_eq!(g.check_runs[1]["output"]["annotations"], json!([]));
        assert_eq!(g.comments.len(), 1);
        assert!(
            g.comments[0].1.contains("No new issues."),
            "{}",
            g.comments[0].1
        );
        assert_eq!(g.tokens_issued, 1);
    }
    assert_eq!(decoration(third).await["state"], "posted");

    // From another repository: not posted.
    let (_, answer) = send(&server, upload(pull_request(&clean, "someone/shop"))).await;
    let d = decoration(answer["analysis_id"].as_i64().unwrap()).await;
    assert_eq!(d["state"], "not_posted");
    assert!(
        d["lastError"]
            .as_str()
            .unwrap()
            .contains("uploaded from someone/shop"),
        "{d}"
    );

    // GitHub down: the upload still succeeds, and the decoration waits to
    // be retried with the error shown; a newer one supersedes it.
    github.lock().unwrap().down = true;
    let (status, answer) = send(&server, upload(pull_request(&eval, "acme/shop"))).await;
    assert_eq!(status, StatusCode::CREATED);
    let down = answer["analysis_id"].as_i64().unwrap();
    assert_eq!(post_due().await.unwrap(), 0);
    let d = decoration(down).await;
    assert_eq!(
        (&d["state"], &d["attempts"]),
        (&json!("pending"), &json!(1))
    );
    assert!(d["lastError"].as_str().unwrap().contains("503"), "{d}");
    assert_eq!(post_due().await.unwrap(), 0, "not due again yet");
    github.lock().unwrap().down = false;
    let (_, answer) = send(&server, upload(pull_request(&clean, "acme/shop"))).await;
    let latest = answer["analysis_id"].as_i64().unwrap();
    assert_eq!(decoration(down).await["state"], "superseded");
    assert_eq!(post_due().await.unwrap(), 1);
    assert_eq!(decoration(latest).await["state"], "posted");
}

#[test]
fn the_apps_jwt_is_signed_with_its_key_in_either_pem_format() {
    let Some(pkcs) = generate_key() else {
        return;
    };
    // Whichever format this openssl writes, make the other too.
    let other = std::process::Command::new("openssl")
        .args(if pkcs.contains("BEGIN RSA PRIVATE KEY") {
            vec!["pkcs8", "-topk8", "-nocrypt"]
        } else {
            vec!["rsa", "-traditional"]
        })
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.take().unwrap().write_all(pkcs.as_bytes())?;
            child.wait_with_output()
        })
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8(o.stdout).unwrap());
    for pem in std::iter::once(pkcs).chain(other) {
        let app = App::new("123".into(), &pem, "https://api.github.com".into()).unwrap();
        let jwt = app.jwt(1_000_000).unwrap();
        let fake = Fake {
            public_key: app.public_key(),
            ..Fake::default()
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {jwt}").parse().unwrap(),
        );
        assert!(checked_jwt(&fake, &headers));
        let claims: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(jwt.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            claims,
            json!({"iat": 999_940, "exp": 1_000_540, "iss": "123"})
        );
        assert!(!format!("{app:?}").contains("PRIVATE"));
    }
    assert!(App::new("abc".into(), "x", String::new()).is_err());
    assert!(
        App::new(
            "123".into(),
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----",
            String::new()
        )
        .is_err()
    );
}
