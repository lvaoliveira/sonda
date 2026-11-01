//! Rule profiles (ADR-0018). Database tests skip without
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

fn get_as(path: &str, auth: (&'static str, String)) -> Request<Body> {
    Request::get(path)
        .header(auth.0, auth.1)
        .body(Body::empty())
        .unwrap()
}

async fn ok(app: &axum::Router, request: Request<Body>) -> Value {
    let (status, body) = send(app, request).await;
    assert!(status.is_success(), "{status}: {body}");
    body
}

async fn issue_rules(db: &TestDb, project: &str) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT DISTINCT i.rule FROM issues i JOIN projects p ON p.id = i.project_id
         WHERE p.key = $1 AND i.fixed_analysis_id IS NULL AND NOT rule_off(i.project_id, i.rule)
         ORDER BY 1",
    )
    .bind(project)
    .fetch_all(&db.pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn admins_manage_profiles_and_scans_get_their_projects() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let app = http::router(state_with(db.pool.clone(), true), None);
    create_user(&db, "ada", "admin").await;
    create_user(&db, "max", "member").await;
    let ada = sign_in(&app, "ada", PASSWORD).await.unwrap();
    let max = sign_in(&app, "max", PASSWORD).await.unwrap();
    let as_max = || (header::COOKIE.as_str(), max.clone());
    let dir = tempfile::tempdir().unwrap();
    for project in ["shop", "blog"] {
        let files = [("a.js", "var x = 1;\neval(x);\n")];
        upload(&db, &upload_json_for(dir.path(), &files, project, "main")).await;
    }

    // "sonda way" is built in, the default, and read-only.
    let list = ok(&app, get_as("/api/rule-profiles", as_max())).await;
    assert_eq!(list[0]["name"], "sonda way");
    assert_eq!(
        (&list[0]["builtin"], &list[0]["isDefault"]),
        (&json!(true), &json!(true))
    );
    assert_eq!(list[0]["projects"], json!(["blog", "shop"]));
    let way = list[0]["id"].as_i64().unwrap();
    for (method, path, body) in [
        (
            "PATCH",
            format!("/api/rule-profiles/{way}"),
            json!({ "name": "mine" }),
        ),
        (
            "PUT",
            format!("/api/rule-profiles/{way}/rules"),
            json!({ "rule": "js/no-var", "state": "off" }),
        ),
        ("DELETE", format!("/api/rule-profiles/{way}"), json!({})),
    ] {
        let (status, _) = send(&app, with_body(method, &path, &ada, body)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{method} {path}");
    }

    // Admins create and edit profiles; members can't.
    let new = json!({ "name": "Strict", "copyFrom": way });
    let (status, _) = send(
        &app,
        with_body("POST", "/api/rule-profiles", &max, new.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let strict = ok(
        &app,
        with_body("POST", "/api/rule-profiles", &ada, new.clone()),
    )
    .await["id"]
        .as_i64()
        .unwrap();
    let (status, _) = send(&app, with_body("POST", "/api/rule-profiles", &ada, new)).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "duplicate name");
    let rules = format!("/api/rule-profiles/{strict}/rules");
    for bad in [
        json!({ "rule": "js/nope", "state": "off" }),
        json!({ "rule": "js/no-var", "state": "maybe" }),
        json!({ "rule": "js/no-var", "state": "on", "severity": "fatal" }),
    ] {
        let (status, _) = send(&app, with_body("PUT", &rules, &ada, bad.clone())).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{bad}");
    }
    // Off-by-default turned on with a severity, and a rule turned off.
    let prefer = json!({ "rule": "js/prefer-const", "state": "on", "severity": "major", "note": "Team style." });
    ok(&app, with_body("PUT", &rules, &ada, prefer)).await;
    ok(
        &app,
        with_body(
            "PUT",
            &rules,
            &ada,
            json!({ "rule": "js/no-var", "state": "off" }),
        ),
    )
    .await;
    let detail = ok(
        &app,
        get_as(&format!("/api/rule-profiles/{strict}"), as_max()),
    )
    .await;
    assert_eq!(detail["rules"], 2);
    assert_eq!(detail["rulesSet"][1]["rule"], "js/prefer-const");
    assert_eq!(detail["rulesSet"][1]["severity"], "major");
    assert_eq!(detail["rulesSet"][1]["change"]["note"], "Team style.");

    // A project uses its profile: what a scan applies, and what counts.
    let before = ok(&app, get_as("/api/projects/shop/rule-profile", as_max())).await;
    assert_eq!(before["profile"], "sonda way");
    assert_eq!(before["rules"], json!([]));
    ok(
        &app,
        with_body(
            "PUT",
            "/api/projects/shop/rule-profile",
            &ada,
            json!({ "profile": strict }),
        ),
    )
    .await;
    let effective = ok(&app, get_as("/api/projects/shop/rule-profile", as_max())).await;
    assert_eq!(effective["profile"], "Strict");
    assert_eq!(
        effective["rules"],
        json!([
            { "rule": "js/no-var", "on": false },
            { "rule": "js/prefer-const", "on": true, "severity": "major" }
        ])
    );
    assert_ne!(effective["revision"], before["revision"]);
    assert_eq!(issue_rules(&db, "shop").await, ["js/no-eval"]);
    assert_eq!(issue_rules(&db, "blog").await, ["js/no-eval", "js/no-var"]);
    // The project's own adjustment goes on top.
    let adjust = json!({ "rule": "js/no-var", "state": "on" });
    ok(
        &app,
        with_body("PUT", "/api/projects/shop/rule-settings", &ada, adjust),
    )
    .await;
    let adjusted = ok(&app, get_as("/api/projects/shop/rule-profile", as_max())).await;
    assert_eq!(
        adjusted["rules"][0],
        json!({ "rule": "js/no-var", "on": true })
    );
    assert_ne!(adjusted["revision"], effective["revision"]);
    let view = ok(&app, get_as("/api/projects/shop/rule-settings", as_max())).await;
    assert_eq!(view["profile"]["name"], "Strict");
    assert_eq!(view["profile"]["chosen"], true);

    // Analysis tokens read their project's settings, and nothing else.
    let token = |kind: &str, project: Option<&str>| {
        let mut body = json!({ "name": format!("{kind}-{}", project.unwrap_or("all")), "type": kind, "expiresInDays": 30, "user": "ada" });
        if let Some(p) = project {
            body["project"] = json!(p);
        }
        with_body("POST", "/api/tokens", &ada, body)
    };
    let shop_token = ok(&app, token("project_analysis", Some("shop"))).await["token"]
        .as_str()
        .unwrap()
        .to_string();
    let bearer = |t: &str| (header::AUTHORIZATION.as_str(), format!("Bearer {t}"));
    ok(
        &app,
        get_as("/api/projects/shop/rule-profile", bearer(&shop_token)),
    )
    .await;
    let (status, _) = send(
        &app,
        get_as("/api/projects/blog/rule-profile", bearer(&shop_token)),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = send(&app, get_as("/api/rule-profiles", bearer(&shop_token))).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "analysis tokens read nothing else"
    );
    let all = ok(&app, token("global_analysis", None)).await["token"]
        .as_str()
        .unwrap()
        .to_string();
    // A project not uploaded yet gets the default profile's settings.
    let fresh = ok(
        &app,
        get_as("/api/projects/new-one/rule-profile", bearer(&all)),
    )
    .await;
    assert_eq!(fresh["profile"], "sonda way");

    // The default profile applies to every project without a choice.
    ok(
        &app,
        with_body(
            "PATCH",
            &format!("/api/rule-profiles/{strict}"),
            &ada,
            json!({ "isDefault": true }),
        ),
    )
    .await;
    assert_eq!(issue_rules(&db, "blog").await, ["js/no-eval"]);
    let (status, body) = send(
        &app,
        with_body(
            "DELETE",
            &format!("/api/rule-profiles/{strict}"),
            &ada,
            json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    ok(
        &app,
        with_body(
            "PATCH",
            &format!("/api/rule-profiles/{way}"),
            &ada,
            json!({ "isDefault": true }),
        ),
    )
    .await;
    let (_, body) = send(
        &app,
        with_body(
            "DELETE",
            &format!("/api/rule-profiles/{strict}"),
            &ada,
            json!({}),
        ),
    )
    .await;
    assert!(body["error"].as_str().unwrap().contains("shop"), "{body}");
    ok(
        &app,
        with_body(
            "PUT",
            "/api/projects/shop/rule-profile",
            &ada,
            json!({ "profile": null }),
        ),
    )
    .await;
    let (status, _) = send(
        &app,
        with_body(
            "DELETE",
            &format!("/api/rule-profiles/{strict}"),
            &ada,
            json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn analyses_record_whether_they_applied_the_current_settings() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let app = http::router(state_with(db.pool.clone(), true), None);
    create_user(&db, "ada", "admin").await;
    let ada = sign_in(&app, "ada", PASSWORD).await.unwrap();
    let cookie = || (header::COOKIE.as_str(), ada.clone());
    let dir = tempfile::tempdir().unwrap();
    let files = [("a.js", "var x = 1;\n")];
    upload(&db, &upload_json_for(dir.path(), &files, "shop", "main")).await;
    let view = ok(&app, get_as("/api/projects/shop/rule-settings", cookie())).await;
    assert_eq!(view["profileApplied"], false, "an older scan applied none");

    let effective = ok(&app, get_as("/api/projects/shop/rule-profile", cookie())).await;
    let mut body = upload_json_for(dir.path(), &files, "shop", "main");
    body["report"]["rule_profile"] =
        json!({ "name": effective["profile"], "revision": effective["revision"] });
    let (status, s) = upload(&db, &body).await;
    assert_eq!(status, StatusCode::CREATED, "{s}");
    let view = ok(&app, get_as("/api/projects/shop/rule-settings", cookie())).await;
    assert_eq!(view["profileApplied"], true);

    // A change makes it stale until the next scan.
    let off = json!({ "rule": "js/no-var", "state": "off" });
    ok(
        &app,
        with_body("PUT", "/api/projects/shop/rule-settings", &ada, off),
    )
    .await;
    let view = ok(&app, get_as("/api/projects/shop/rule-settings", cookie())).await;
    assert_eq!(view["profileApplied"], false);

    let mut bad = upload_json_for(dir.path(), &files, "shop", "main");
    bad["report"]["rule_profile"] = json!({ "name": "", "revision": "1.1.1" });
    let (status, _) = upload(&db, &bad).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}
