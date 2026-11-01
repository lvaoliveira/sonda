//! Project settings (ADR-0017): display name and main branch. Database
//! tests skip without SONDA_TEST_DATABASE_URL (see server.rs).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{PASSWORD, TestDb, create_user, sign_in, state_with, upload, upload_json_for};
use serde_json::{Value, json};
use sonda_server::{db, http};
use tower::ServiceExt;

async fn send(app: &axum::Router, request: Request<Body>) -> (StatusCode, Value) {
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

fn with_body(method: &str, path: &str, cookie: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::COOKIE, cookie)
        .header("sonda-csrf", "1")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn get_as(path: &str, cookie: &str) -> Request<Body> {
    Request::get(path)
        .header(header::COOKIE, cookie)
        .body(Body::empty())
        .unwrap()
}

async fn ok(app: &axum::Router, request: Request<Body>) -> Value {
    let (status, body) = send(app, request).await;
    assert!(status.is_success(), "{status}: {body}");
    body
}

#[tokio::test]
async fn admins_name_a_project_and_choose_its_main_branch() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let app = http::router(state_with(db.pool.clone(), true), None);
    create_user(&db, "ada", "admin").await;
    create_user(&db, "max", "member").await;
    let ada = sign_in(&app, "ada", PASSWORD).await.unwrap();
    let max = sign_in(&app, "max", PASSWORD).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let (_, s) = upload(
        &db,
        &upload_json_for(dir.path(), &[("a.js", "eval(x);\n")], "shop", "main"),
    )
    .await;
    let on_main = s["analysis_id"].as_i64().unwrap();
    let mut develop = 0;
    for content in ["var a = 1;\n", "var a = 2;\n"] {
        let (_, s) = upload(
            &db,
            &upload_json_for(dir.path(), &[("a.js", content)], "shop", "develop"),
        )
        .await;
        if develop == 0 {
            develop = s["analysis_id"].as_i64().unwrap();
        }
    }
    // An admin's start of the period, on the old main branch.
    ok(
        &app,
        with_body(
            "PUT",
            "/api/projects/shop/new-code",
            &ada,
            json!({"analysis": on_main}),
        ),
    )
    .await;

    // Members read the settings, and can't change them.
    let s = ok(&app, get_as("/api/projects/shop/settings", &max)).await;
    assert_eq!(
        (&s["name"], &s["mainBranch"]),
        (&Value::Null, &json!("main"))
    );
    let branches: Vec<(&str, i64)> = s["branches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| (b["name"].as_str().unwrap(), b["analyses"].as_i64().unwrap()))
        .collect();
    assert_eq!(branches, [("main", 1), ("develop", 2)]);
    let patch =
        |cookie: &str, body: Value| with_body("PATCH", "/api/projects/shop/settings", cookie, body);
    let (status, _) = send(&app, patch(&max, json!({"name": "Shop"}))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // A name, trimmed, shown beside the key.
    let s = ok(&app, patch(&ada, json!({"name": "  Shop front  "}))).await;
    assert_eq!(s["name"], "Shop front");
    assert_eq!(s["changes"][0]["setting"], "name");
    assert_eq!(
        (&s["changes"][0]["old"], &s["changes"][0]["new"]),
        (&Value::Null, &json!("Shop front"))
    );
    assert_eq!(s["changes"][0]["by"], "ada");
    let list = ok(&app, get_as("/api/projects", &max)).await;
    assert_eq!(list["projects"][0]["name"], "Shop front");
    let (status, _) = send(&app, patch(&ada, json!({"name": "x".repeat(101)}))).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let (status, _) = send(&app, patch(&ada, json!({"mainBranch": "nope"}))).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let (status, _) = send(
        &app,
        with_body("PATCH", "/api/projects/nope/settings", &ada, json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Another main branch: screens count it, and new code starts over on
    // it, from its first analysis.
    let s = ok(&app, patch(&ada, json!({"mainBranch": "develop"}))).await;
    assert_eq!(s["mainBranch"], "develop");
    assert_eq!(s["branches"][0]["name"], "develop");
    assert_eq!(s["changes"][0]["setting"], "main_branch");
    assert_eq!(
        (&s["changes"][0]["old"], &s["changes"][0]["new"]),
        (&json!("main"), &json!("develop"))
    );
    let p = ok(&app, get_as("/api/projects/shop", &max)).await;
    assert_eq!(
        (&p["branch"], &p["name"]),
        (&json!("develop"), &json!("Shop front"))
    );
    assert_eq!(p["newCodePeriod"]["analysis"], develop);
    assert_eq!(p["newCodePeriod"]["reset"], false);
    let list = ok(&app, get_as("/api/projects", &max)).await;
    assert_eq!(list["projects"][0]["mainBranch"], "develop");

    // Null shows the key alone again; nothing changed records nothing.
    let s = ok(&app, patch(&ada, json!({"name": null}))).await;
    assert_eq!(s["name"], Value::Null);
    let s = ok(
        &app,
        patch(&ada, json!({"name": null, "mainBranch": "develop"})),
    )
    .await;
    assert_eq!(s["changes"].as_array().unwrap().len(), 3);
}
