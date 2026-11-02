//! Creating a project ahead of its first upload, to connect its repository
//! from the web app. Database tests skip without SONDA_TEST_DATABASE_URL
//! (see server.rs).

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

#[tokio::test]
async fn an_admin_creates_a_project_that_waits_for_its_first_upload() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let app = http::router(state_with(db.pool.clone(), true), None);
    create_user(&db, "ada", "admin").await;
    create_user(&db, "max", "member").await;
    let ada = sign_in(&app, "ada", PASSWORD).await.unwrap();
    let max = sign_in(&app, "max", PASSWORD).await.unwrap();
    let create = |cookie: &str, key: &str| {
        with_body(
            "POST",
            "/api/projects",
            cookie,
            json!({"key": key, "mainBranch": "trunk"}),
        )
    };

    // Members can't; a bad key is refused.
    assert_eq!(
        send(&app, create(&max, "shop")).await.0,
        StatusCode::FORBIDDEN
    );
    let (status, body) = send(&app, create(&ada, "no spaces")).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    for branch in ["pr:12", ""] {
        let request = with_body(
            "POST",
            "/api/projects",
            &ada,
            json!({"key": "shop", "mainBranch": branch}),
        );
        let (status, body) = send(&app, request).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{branch}: {body}");
    }

    let (status, body) = send(&app, create(&ada, "shop")).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body, json!({"key": "shop"}));
    let (status, body) = send(&app, create(&ada, "shop")).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        body["error"].as_str().unwrap().contains("already exists"),
        "{body}"
    );

    // Linked to its repository before any upload; its main branch is set.
    let (status, body) = send(
        &app,
        with_body(
            "PATCH",
            "/api/projects/shop/settings",
            &ada,
            json!({"githubRepository": "acme/shop"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["mainBranch"], "trunk");

    // It waits, out of the projects list.
    let (_, list) = send(&app, get_as("/api/projects", &max)).await;
    assert_eq!(list["projects"], json!([]));
    assert_eq!(
        list["waiting"],
        json!([{"key": "shop", "name": null, "githubRepository": "acme/shop"}])
    );

    // A branch upload doesn't take over its main branch; the main one fills it.
    let dir = tempfile::tempdir().unwrap();
    let files = [("a.js", "eval(x);\n")];
    let feature = upload_json_for(dir.path(), &files, "shop", "feature");
    assert_eq!(upload(&db, &feature).await.0, StatusCode::CREATED);
    let (_, list) = send(&app, get_as("/api/projects", &max)).await;
    assert_eq!(list["waiting"][0]["key"], "shop");
    let trunk = upload_json_for(dir.path(), &files, "shop", "trunk");
    assert_eq!(upload(&db, &trunk).await.0, StatusCode::CREATED);
    let (_, list) = send(&app, get_as("/api/projects", &max)).await;
    assert_eq!(list["waiting"], json!([]));
    assert_eq!(list["projects"][0]["key"], "shop");
    assert_eq!(list["projects"][0]["mainBranch"], "trunk");
}

#[tokio::test]
async fn a_deleted_projects_key_cant_be_created_again_until_allowed() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let app = http::router(state_with(db.pool.clone(), true), None);
    create_user(&db, "ada", "admin").await;
    let ada = sign_in(&app, "ada", PASSWORD).await.unwrap();
    // Without a main branch, it's main.
    let create = || with_body("POST", "/api/projects", &ada, json!({"key": "shop"}));
    assert_eq!(send(&app, create()).await.0, StatusCode::CREATED);
    let (_, settings) = send(&app, get_as("/api/projects/shop/settings", &ada)).await;
    assert_eq!(settings["mainBranch"], "main");
    let (status, body) = send(
        &app,
        with_body(
            "DELETE",
            "/api/projects/shop",
            &ada,
            json!({"confirm": "shop"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = send(&app, create()).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        body["error"].as_str().unwrap().contains("was deleted"),
        "{body}"
    );
}
