//! Quality gates on the server (ADR-0017). Database tests skip without
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

/// A gate on lines of code: `gt 0` always fails, `lt 0` never does.
fn on_lines(op: &str) -> Value {
    json!([{"metric": "ncloc", "op": op, "threshold": 0}])
}

#[tokio::test]
async fn a_server_gate_judges_its_projects_instead_of_sonda_toml() {
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
    let files = [("a.js", "var a = 1;\n")];
    for branch in ["main", "develop"] {
        let body = upload_json_for(dir.path(), &files, "shop", branch);
        assert_eq!(upload(&db, &body).await.0, StatusCode::CREATED);
    }
    let gate_of = |p: &Value| {
        (
            p["gate"]["state"].clone(),
            p["gate"]["serverGate"]["name"].clone(),
        )
    };
    let scan = ok(&app, get_as("/api/projects/shop", &max)).await;
    assert_eq!(gate_of(&scan), (json!("passed"), Value::Null));

    // Admins create gates, with sonda.toml's metrics and operators.
    let new = |body: Value| with_body("POST", "/api/quality-gates", &ada, body);
    let (status, _) = send(
        &app,
        with_body(
            "POST",
            "/api/quality-gates",
            &max,
            json!({"name": "x", "conditions": on_lines("gt")}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let strict = ok(
        &app,
        new(json!({"name": " Strict ", "conditions": on_lines("gt")})),
    )
    .await;
    let id = strict["id"].as_i64().unwrap();
    assert_eq!(strict["name"], "Strict");
    for bad in [
        json!({"name": "Strict", "conditions": on_lines("lt")}),
        json!({"name": "None", "conditions": []}),
        json!({"name": "Typo", "conditions": [{"metric": "nloc", "op": "gt", "threshold": 0}]}),
        json!({"name": "Op", "conditions": [{"metric": "ncloc", "op": "ge", "threshold": 0}]}),
    ] {
        let (status, body) = send(&app, new(bad.clone())).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{bad}: {body}");
    }
    let gates = ok(&app, get_as("/api/gates", &max)).await;
    let listed = gates["gates"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["server"]["id"] == id)
        .unwrap();
    assert_eq!(
        (&listed["name"], &listed["projects"]),
        (&json!("Strict"), &json!([]))
    );

    // Chosen for shop: every branch's latest analysis is judged by it now,
    // and so are uploads, whose answer CI follows.
    let settings = |body: Value| with_body("PATCH", "/api/projects/shop/settings", &ada, body);
    let s = ok(&app, settings(json!({"qualityGate": id}))).await;
    assert_eq!(s["qualityGate"], json!({"id": id, "name": "Strict"}));
    assert_eq!(
        (
            &s["changes"][0]["setting"],
            &s["changes"][0]["old"],
            &s["changes"][0]["new"]
        ),
        (&json!("quality_gate"), &Value::Null, &json!("Strict"))
    );
    let p = ok(&app, get_as("/api/projects/shop", &max)).await;
    assert_eq!(gate_of(&p), (json!("failed"), json!("Strict")));
    let d = ok(&app, get_as("/api/projects/shop?branch=develop", &max)).await;
    assert_eq!(gate_of(&d), (json!("failed"), json!("Strict")));
    let body = upload_json_for(dir.path(), &files, "shop", "main");
    let (_, answer) = upload(&db, &body).await;
    assert_eq!(answer["gate"]["passed"], false, "{answer}");
    assert_eq!(
        answer["gate"]["failing"].as_array().unwrap().len(),
        1,
        "{answer}"
    );

    // Editing it judges its projects again at once.
    let edited = ok(
        &app,
        with_body(
            "PUT",
            &format!("/api/quality-gates/{id}"),
            &ada,
            json!({"name": "Strict", "conditions": on_lines("lt")}),
        ),
    )
    .await;
    assert_eq!(edited["projects"], json!(["shop"]));
    let p = ok(&app, get_as("/api/projects/shop", &max)).await;
    assert_eq!(gate_of(&p), (json!("passed"), json!("Strict")));

    // In use, it can't be deleted; back on sonda.toml's gate, it can.
    let delete = || {
        with_body(
            "DELETE",
            &format!("/api/quality-gates/{id}"),
            &ada,
            json!({}),
        )
    };
    let (status, body) = send(&app, delete()).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body["error"].as_str().unwrap().contains("shop"), "{body}");
    let (status, _) = send(&app, settings(json!({"qualityGate": 999}))).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    let s = ok(&app, settings(json!({"qualityGate": null}))).await;
    assert_eq!(s["qualityGate"], Value::Null);
    let p = ok(&app, get_as("/api/projects/shop", &max)).await;
    assert_eq!(gate_of(&p), (json!("passed"), Value::Null));
    assert_eq!(
        p["gate"]["conditions"].as_array().unwrap().len(),
        scan["gate"]["conditions"].as_array().unwrap().len(),
        "the scan's own conditions again"
    );
    assert_eq!(send(&app, delete()).await.0, StatusCode::NO_CONTENT);
    assert_eq!(send(&app, delete()).await.0, StatusCode::NOT_FOUND);
}
