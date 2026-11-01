//! `GET /api/analyses` and `GET /api/analyses/{id}`. Database tests skip
//! without SONDA_TEST_DATABASE_URL (see server.rs).

mod common;

use axum::http::StatusCode;
use common::{TestDb, get, state, upload, upload_json_for};
use serde_json::Value;
use sonda_server::{db, http};

async fn analysis(
    db: &TestDb,
    dir: &std::path::Path,
    project: &str,
    branch: &str,
    files: &[(&str, &str)],
) -> i64 {
    let (status, summary) = upload(db, &upload_json_for(dir, files, project, branch)).await;
    assert_eq!(status, StatusCode::CREATED, "{summary}");
    summary["analysis_id"].as_i64().unwrap()
}

async fn api(db: &TestDb, path: &str) -> (StatusCode, Value) {
    let (status, body) = get(http::router(state(db.pool.clone()), None), path).await;
    (status, serde_json::from_str(&body).unwrap_or(Value::Null))
}

#[tokio::test]
async fn analyses_are_listed_and_show_what_changed() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let (pay, docs) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    // First: a code smell (var) is the baseline. Second: eval comes in (a
    // critical vulnerability), the var goes away.
    let first = analysis(
        &db,
        pay.path(),
        "payments",
        "main",
        &[("api/a.js", "var x = 1;\n")],
    )
    .await;
    let second = analysis(
        &db,
        pay.path(),
        "payments",
        "main",
        &[
            ("api/a.js", "let x = 1;\neval(x);\n"),
            ("web/b.py", "y = 2\n"),
        ],
    )
    .await;
    let other = analysis(&db, docs.path(), "docs", "main", &[("a.py", "z = 3\n")]).await;

    let (status, page) = api(&db, "/api/analyses").await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["total"], 3);
    let ids: Vec<i64> = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["id"].as_i64().unwrap())
        .collect();
    assert_eq!(ids, [other, second, first], "newest first");
    let (_, failed) = api(&db, "/api/analyses?gate=failed").await;
    assert_eq!(failed["total"], 1);
    assert_eq!(failed["items"][0]["id"], second);
    assert!(
        failed["items"][0]["failing"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l == "New vulnerabilities > 0")
    );
    let (_, payments) = api(&db, "/api/analyses?project=payments&branch=main&limit=1").await;
    assert_eq!(
        (
            payments["total"].as_i64(),
            payments["items"].as_array().unwrap().len()
        ),
        (Some(2), 1)
    );
    let (status, _) = api(&db, "/api/analyses?gate=maybe").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, a) = api(&db, &format!("/api/analyses/{second}")).await;
    assert_eq!(status, StatusCode::OK, "{a}");
    assert_eq!(a["project"], "payments");
    assert_eq!(a["gate"]["state"], "failed");
    assert_eq!(a["baseline"], false);
    assert_eq!(a["files"], 2);
    assert_eq!(a["components"], 2);
    assert_eq!(a["introduced"]["total"], 1);
    assert_eq!(a["introduced"]["bySeverity"]["critical"], 1);
    assert_eq!(a["introduced"]["items"][0]["rule"], "js/no-eval");
    assert_eq!(a["fixed"]["total"], 1);
    assert_eq!(a["fixed"]["items"][0]["rule"], "js/no-var");
    assert_eq!(a["previous"]["id"], first);
    assert!(a["next"].is_null());

    let (_, b) = api(&db, &format!("/api/analyses/{first}")).await;
    assert_eq!(b["baseline"], true);
    assert_eq!(b["next"]["id"], second);
    let (status, _) = api(&db, "/api/analyses/999999").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn commit_messages_and_durations_are_stored_and_shown() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let files = [("a.js", "let a = 1;\n")];
    let mut body = upload_json_for(dir.path(), &files, "shop", "main");
    body["commit_message"] = serde_json::json!("Fix refunds rounding");
    body["scan_duration_ms"] = serde_json::json!(192_400);
    let (status, summary) = upload(&db, &body).await;
    assert_eq!(status, StatusCode::CREATED, "{summary}");
    let id = summary["analysis_id"].as_i64().unwrap();
    // An older CLI, or a scan outside git, sends none.
    let without = analysis(&db, dir.path(), "shop", "main", &files).await;

    let (_, detail) = api(&db, &format!("/api/analyses/{id}")).await;
    assert_eq!(detail["message"], "Fix refunds rounding");
    assert_eq!(detail["duration"], "3m 12s");
    let (_, list) = api(&db, "/api/analyses?project=shop").await;
    let messages: Vec<(i64, Value)> = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| (a["id"].as_i64().unwrap(), a["message"].clone()))
        .collect();
    assert_eq!(
        messages,
        [(without, Value::Null), (id, "Fix refunds rounding".into())]
    );
    assert_eq!(list["items"][1]["duration"], "3m 12s");
    assert_eq!(list["items"][0]["duration"], Value::Null);
    let (status, overview) = api(&db, "/api/overview").await;
    assert_eq!(status, StatusCode::OK, "{overview}");
    let recent: Vec<Value> = overview["recent"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["message"].clone())
        .collect();
    assert_eq!(recent, [Value::Null, "Fix refunds rounding".into()]);
    assert_eq!(overview["recent"][1]["duration"], "3m 12s");

    body["scan_duration_ms"] = serde_json::json!(8 * 24 * 3_600_000u64);
    assert_eq!(upload(&db, &body).await.0, StatusCode::UNPROCESSABLE_ENTITY);
    body["scan_duration_ms"] = serde_json::json!(1000);

    for bad in ["", "  ", "line\nbreak", &"x".repeat(301)] {
        body["commit_message"] = serde_json::json!(bad);
        assert_eq!(
            upload(&db, &body).await.0,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{bad:?}"
        );
    }
}

#[tokio::test]
async fn rule_settings_from_sonda_toml_are_stored_and_shown() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let files = [("a.js", "let a = 1;\n")];
    let mut body = upload_json_for(dir.path(), &files, "shop", "main");
    // As the CLI sends them, but unsorted: the server normalizes.
    body["report"]["rule_settings"] = serde_json::json!({
        "disabled": ["js/no-var", "js/eqeqeq", "js/no-var"],
        "enabled": ["js/prefer-const"],
        "severity": { "js/no-eval": "minor" }
    });
    let (status, summary) = upload(&db, &body).await;
    assert_eq!(status, StatusCode::CREATED, "{summary}");
    let id = summary["analysis_id"].as_i64().unwrap();
    let (_, detail) = api(&db, &format!("/api/analyses/{id}")).await;
    assert_eq!(
        detail["ruleSettings"],
        serde_json::json!({
            "disabled": ["js/eqeqeq", "js/no-var"],
            "enabled": ["js/prefer-const"],
            "severity": { "js/no-eval": "minor" }
        })
    );

    // From a CLI that sends none: unknown, not empty.
    let mut older = upload_json_for(dir.path(), &files, "shop", "main");
    older["report"]
        .as_object_mut()
        .unwrap()
        .remove("rule_settings");
    let (_, summary) = upload(&db, &older).await;
    let id = summary["analysis_id"].as_i64().unwrap();
    let (_, detail) = api(&db, &format!("/api/analyses/{id}")).await;
    assert_eq!(detail["ruleSettings"], Value::Null);

    // Bounded: it's untrusted input.
    let mut bad = upload_json_for(dir.path(), &files, "shop", "main");
    bad["report"]["rule_settings"]["disabled"] = serde_json::json!(["x".repeat(101)]);
    let (status, _) = upload(&db, &bad).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}
