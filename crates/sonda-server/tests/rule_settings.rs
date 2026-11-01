//! Rule settings on the server (ADR-0016). Database tests skip without
//! SONDA_TEST_DATABASE_URL (see server.rs).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{PASSWORD, TOKEN, TestDb, create_user, sign_in, state_with, upload, upload_json_for};
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

fn put(path: &str, cookie: &str, body: Value) -> Request<Body> {
    Request::put(path)
        .header(header::COOKIE, cookie)
        .header("sonda-csrf", "1")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn get(app: &axum::Router, cookie: &str, path: &str) -> Value {
    let request = Request::get(path)
        .header(header::COOKIE, cookie)
        .body(Body::empty())
        .unwrap();
    let (status, body) = send(app, request).await;
    assert_eq!(status, StatusCode::OK, "{path}: {body}");
    body
}

fn rules(page: &Value) -> Vec<String> {
    let mut r: Vec<String> = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["rule"].as_str().unwrap().to_string())
        .collect();
    r.sort();
    r
}

async fn latest(db: &TestDb, project: &str, measure: &str) -> (i64, bool) {
    sqlx::query_as(
        "SELECT (a.measures->>$2)::float8::bigint, a.gate_passed FROM analyses a
         JOIN projects p ON p.id = a.project_id WHERE p.key = $1 ORDER BY a.id DESC LIMIT 1",
    )
    .bind(project)
    .bind(measure)
    .fetch_one(&db.pool)
    .await
    .unwrap()
}

fn rule<'a>(catalog: &'a Value, id: &str) -> &'a Value {
    catalog["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == id)
        .unwrap()
}

fn state<'a>(settings: &'a Value, id: &str) -> Option<&'a Value> {
    settings["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["rule"] == id)
}

#[tokio::test]
async fn admins_turn_rules_off_globally_or_per_project() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let app = http::router(state_with(db.pool.clone(), true), None);
    create_user(&db, "ada", "admin").await;
    create_user(&db, "max", "member").await;
    let ada = sign_in(&app, "ada", PASSWORD).await.unwrap();
    let max = sign_in(&app, "max", PASSWORD).await.unwrap();
    let (shop_dir, blog_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let clean = [("a.js", "let x = 1;\n")];
    let eval = [("a.js", "var x = 1;\neval(x);\n")];
    for (dir, project) in [(&shop_dir, "shop"), (&blog_dir, "blog")] {
        upload(&db, &upload_json_for(dir.path(), &clean, project, "main")).await;
        let (status, s) = upload(&db, &upload_json_for(dir.path(), &eval, project, "main")).await;
        assert_eq!(status, StatusCode::CREATED, "{s}");
        assert_eq!(s["gate"]["passed"], false, "a new vulnerability fails it");
    }

    // Admins only, signed in; the rule must exist.
    let off = json!({ "rule": "js/no-eval", "off": true, "note": "Reviewed by security." });
    let (status, _) = send(&app, put("/api/rule-settings", &max, off.clone())).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let by_token = Request::put("/api/rule-settings")
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(off.to_string()))
        .unwrap();
    assert_eq!(send(&app, by_token).await.0, StatusCode::FORBIDDEN);
    let unknown = json!({ "rule": "js/nope", "off": true });
    let (status, _) = send(&app, put("/api/rule-settings", &ada, unknown)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    // Off globally: gone from lists, measures and the gate, everywhere.
    let (status, body) = send(&app, put("/api/rule-settings", &ada, off)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let issues = get(&app, &max, "/api/issues?project=shop").await;
    assert_eq!(rules(&issues), ["js/no-var"]);
    assert_eq!(latest(&db, "shop", "vulnerabilities").await, (0, true));
    assert_eq!(latest(&db, "blog", "new_vulnerabilities").await, (0, true));
    // An upload while it's off answers with that gate, which CI follows.
    let (_, s) = upload(
        &db,
        &upload_json_for(shop_dir.path(), &eval, "shop", "main"),
    )
    .await;
    assert_eq!(s["gate"]["passed"], true, "{s}");
    let catalog = get(&app, &max, "/api/rules").await;
    let eval_rule = rule(&catalog, "js/no-eval");
    assert_eq!(eval_rule["serverOff"]["changedBy"], "ada");
    assert_eq!(eval_rule["serverOff"]["note"], "Reviewed by security.");
    assert_eq!(eval_rule["offIn"], json!({ "sondaToml": 0, "server": 2 }));
    assert_eq!(eval_rule["openIssues"], 0);

    // A project turns it back on, over the global setting.
    let on = json!({ "rule": "js/no-eval", "state": "on" });
    let (status, _) = send(
        &app,
        put("/api/projects/blog/rule-settings", &max, on.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = send(&app, put("/api/projects/blog/rule-settings", &ada, on)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let blog = get(&app, &max, "/api/issues?project=blog").await;
    assert_eq!(rules(&blog), ["js/no-eval", "js/no-var"]);
    assert_eq!(latest(&db, "blog", "vulnerabilities").await.0, 1);
    assert_eq!(latest(&db, "shop", "vulnerabilities").await.0, 0);
    let catalog = get(&app, &max, "/api/rules").await;
    assert_eq!(
        rule(&catalog, "js/no-eval")["offIn"],
        json!({ "sondaToml": 0, "server": 1 })
    );

    // Each project's view says what decided each rule.
    let shop = get(&app, &max, "/api/projects/shop/rule-settings").await;
    let s = state(&shop, "js/no-eval").unwrap();
    assert_eq!((&s["on"], &s["setBy"]), (&json!(false), &json!("server")));
    assert_eq!(s["change"]["changedBy"], "ada");
    assert_eq!(s["hiddenIssues"], 1);
    let blog = get(&app, &max, "/api/projects/blog/rule-settings").await;
    let s = state(&blog, "js/no-eval").unwrap();
    assert_eq!(
        (&s["on"], &s["setBy"], &s["projectSetting"]),
        (&json!(true), &json!("project"), &json!("on"))
    );
    for bad in [
        json!({ "rule": "js/no-eval", "state": "maybe" }),
        json!({ "rule": "js/no-eval", "state": "off", "note": "x".repeat(501) }),
    ] {
        let (status, _) = send(&app, put("/api/projects/blog/rule-settings", &ada, bad)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }
    let missing = json!({ "rule": "js/no-eval", "state": "off" });
    let (status, _) = send(&app, put("/api/projects/nope/rule-settings", &ada, missing)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Following the global setting again, then turning it back on globally.
    let inherit = json!({ "rule": "js/no-eval", "state": "inherit" });
    send(&app, put("/api/projects/blog/rule-settings", &ada, inherit)).await;
    assert_eq!(latest(&db, "blog", "vulnerabilities").await.0, 0);
    let back = json!({ "rule": "js/no-eval", "off": false });
    send(&app, put("/api/rule-settings", &ada, back)).await;
    assert_eq!(latest(&db, "shop", "vulnerabilities").await.0, 1);
    let catalog = get(&app, &max, "/api/rules").await;
    assert_eq!(rule(&catalog, "js/no-eval")["serverOff"], Value::Null);
    assert_eq!(rule(&catalog, "js/no-eval")["offIn"], Value::Null);
}

#[tokio::test]
async fn the_repositorys_settings_show_with_conflicts_and_changes() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let app = http::router(state_with(db.pool.clone(), true), None);
    create_user(&db, "ada", "admin").await;
    let ada = sign_in(&app, "ada", PASSWORD).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let files = [("a.js", "var x = 1;\n")];
    let with = |settings: Value| {
        let mut body = upload_json_for(dir.path(), &files, "shop", "main");
        body["report"]["rule_settings"] = settings;
        body
    };
    upload(
        &db,
        &with(json!({ "disabled": [], "enabled": [], "severity": {} })),
    )
    .await;
    let (status, s) = upload(
        &db,
        &with(json!({
            "disabled": ["js/no-var"],
            "enabled": ["js/prefer-const"],
            "severity": { "js/no-eval": "minor" }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{s}");

    let view = get(&app, &ada, "/api/projects/shop/rule-settings").await;
    assert_eq!(view["sondaToml"]["disabled"], json!(["js/no-var"]));
    let no_var = state(&view, "js/no-var").unwrap();
    assert_eq!(
        (&no_var["on"], &no_var["setBy"], &no_var["conflict"]),
        (&json!(false), &json!("sonda_toml"), &json!(false))
    );
    let prefer = state(&view, "js/prefer-const").unwrap();
    assert_eq!(
        (&prefer["on"], &prefer["setBy"]),
        (&json!(true), &json!("sonda_toml"))
    );
    assert_eq!(state(&view, "js/no-eval").unwrap()["severity"], "minor");
    // Rules at their default aren't listed.
    assert!(state(&view, "js/eqeqeq").is_none());
    let changes: Vec<(String, String)> = view["tomlChanges"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                c["rule"].as_str().unwrap().into(),
                c["change"].as_str().unwrap().into(),
            )
        })
        .collect();
    assert_eq!(
        changes,
        [
            ("js/no-var".into(), "disabled".into()),
            ("js/prefer-const".into(), "enabled".into()),
            ("js/no-eval".into(), "severity".into()),
        ]
    );
    let catalog = get(&app, &ada, "/api/rules").await;
    assert_eq!(
        rule(&catalog, "js/no-var")["offIn"],
        json!({ "sondaToml": 1, "server": 0 })
    );

    // The server can't turn on what the scanner never ran: shown, not hidden.
    let on = json!({ "rule": "js/no-var", "state": "on" });
    send(&app, put("/api/projects/shop/rule-settings", &ada, on)).await;
    let view = get(&app, &ada, "/api/projects/shop/rule-settings").await;
    let no_var = state(&view, "js/no-var").unwrap();
    assert_eq!(
        (&no_var["on"], &no_var["setBy"], &no_var["conflict"]),
        (&json!(false), &json!("sonda_toml"), &json!(true))
    );

    // From an older sonda, the repository's part is unknown.
    let mut older = upload_json_for(dir.path(), &files, "shop", "main");
    older["report"]
        .as_object_mut()
        .unwrap()
        .remove("rule_settings");
    upload(&db, &older).await;
    let view = get(&app, &ada, "/api/projects/shop/rule-settings").await;
    assert_eq!(view["sondaToml"], Value::Null);
}
