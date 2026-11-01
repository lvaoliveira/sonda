//! Deleting a project (ADR-0017). Database tests skip without
//! SONDA_TEST_DATABASE_URL (see server.rs).

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

async fn count(db: &TestDb, sql: &'static str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(&db.pool).await.unwrap()
}

#[tokio::test]
async fn deleting_a_project_removes_it_and_refuses_its_key_until_allowed() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let app = http::router(state_with(db.pool.clone(), true), None);
    create_user(&db, "ada", "admin").await;
    create_user(&db, "max", "member").await;
    let ada = sign_in(&app, "ada", PASSWORD).await.unwrap();
    let max = sign_in(&app, "max", PASSWORD).await.unwrap();
    // `shared.js` is in both projects; `only.js` in shop alone.
    let (shop_dir, blog_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let shared = ("shared.js", "var shared = 1;\n");
    let shop_files = [shared, ("only.js", "eval(onlyInShop);\n")];
    let shop = upload_json_for(shop_dir.path(), &shop_files, "shop", "main");
    assert_eq!(upload(&db, &shop).await.0, StatusCode::CREATED);
    let develop = upload_json_for(shop_dir.path(), &shop_files, "shop", "develop");
    assert_eq!(upload(&db, &develop).await.0, StatusCode::CREATED);
    let blog = upload_json_for(blog_dir.path(), &[shared], "blog", "main");
    assert_eq!(upload(&db, &blog).await.0, StatusCode::CREATED);
    let token = ok(
        &app,
        with_body(
            "POST",
            "/api/me/tokens",
            &ada,
            json!({"name": "shop-ci", "type": "project_analysis", "project": "shop", "expiresInDays": 30}),
        ),
    )
    .await;
    let sources_before = count(&db, "SELECT count(*) FROM sources").await;

    // Admins only, and only with the key typed again.
    let delete = |cookie: &str, confirm: &str| {
        with_body(
            "DELETE",
            "/api/projects/shop",
            cookie,
            json!({"confirm": confirm}),
        )
    };
    assert_eq!(
        send(&app, delete(&max, "shop")).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send(&app, delete(&ada, "Shop")).await.0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let d = ok(&app, delete(&ada, "shop")).await;
    assert_eq!((&d["key"], &d["analyses"]), (&json!("shop"), &json!(2)));
    assert_eq!(
        (&d["deletedBy"], &d["allowedAt"]),
        (&json!("ada"), &Value::Null)
    );
    assert_eq!(
        send(&app, delete(&ada, "shop")).await.0,
        StatusCode::NOT_FOUND
    );

    // Gone, with everything of its own; blog keeps the content they shared.
    let (status, _) = send(&app, get_as("/api/projects/shop", &max)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        count(&db, "SELECT count(*) FROM issues i JOIN projects p ON p.id = i.project_id WHERE p.key = 'shop'").await,
        0
    );
    assert_eq!(count(&db, "SELECT count(*) FROM analyses").await, 1);
    assert_eq!(
        count(&db, "SELECT count(*) FROM sources").await,
        sources_before - 1
    );
    let blog_files = ok(&app, get_as("/api/projects/blog", &max)).await;
    assert_eq!(blog_files["key"], "blog");
    let revoked: (Option<String>,) =
        sqlx::query_as("SELECT revoked_by FROM api_tokens WHERE id = $1")
            .bind(token["id"].as_i64().unwrap())
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(revoked.0.as_deref(), Some("ada"));

    // Its key is refused: uploads, the scan's settings, and new tokens.
    let (status, body) = upload(&db, &shop).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let why = body["error"].as_str().unwrap();
    assert!(why.contains("\"shop\" was deleted by ada"), "{why}");
    assert!(
        why.contains("allow its key again on the Admin page"),
        "{why}"
    );
    let (status, _) = send(&app, get_as("/api/projects/shop/rule-profile", &ada)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = send(
        &app,
        with_body(
            "POST",
            "/api/me/tokens",
            &ada,
            json!({"name": "again", "type": "project_analysis", "project": "shop", "expiresInDays": 30}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    // The Admin page lists it, for admins only; allowing it lets the next
    // upload start a new project.
    let (status, _) = send(&app, get_as("/api/deleted-projects", &max)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let list = ok(&app, get_as("/api/deleted-projects", &ada)).await;
    assert_eq!(list.as_array().unwrap().len(), 1);
    let id = list[0]["id"].as_i64().unwrap();
    let allow = |cookie: &str| {
        with_body(
            "POST",
            &format!("/api/deleted-projects/{id}/allow"),
            cookie,
            json!({}),
        )
    };
    assert_eq!(send(&app, allow(&max)).await.0, StatusCode::FORBIDDEN);
    let a = ok(&app, allow(&ada)).await;
    assert_eq!(a["allowedBy"], "ada");
    assert_eq!(ok(&app, allow(&ada)).await["allowedAt"], a["allowedAt"]);
    assert_eq!(upload(&db, &shop).await.0, StatusCode::CREATED);
    let p = ok(&app, get_as("/api/projects/shop", &max)).await;
    assert_eq!(p["history"].as_array().unwrap().len(), 1);

    // Deleted again: a second record, newest first.
    ok(&app, delete(&ada, "shop")).await;
    let list = ok(&app, get_as("/api/deleted-projects", &ada)).await;
    let states: Vec<bool> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["allowedAt"].is_null())
        .collect();
    assert_eq!(states, [true, false]);
}
