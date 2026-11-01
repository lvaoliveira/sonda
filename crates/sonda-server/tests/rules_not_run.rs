//! A finding missing because the scan didn't run its rule isn't fixed
//! (ADR-0018). Database tests skip without SONDA_TEST_DATABASE_URL (see
//! server.rs).

mod common;

use axum::http::StatusCode;
use common::{TestDb, get, state, upload, upload_json_for};
use serde_json::{Value, json};
use sonda_server::{db, http};

/// What the CLI would send for `files`, as if its scan ran every rule
/// except `not_run`: their findings are absent, and so are their ids.
fn without(body: &Value, not_run: &str) -> Value {
    let mut b = body.clone();
    let issues = b["report"]["issues"].as_array_mut().unwrap();
    issues.retain(|i| i["rule"] != not_run);
    let active = b["report"]["active_rules"].as_array_mut().unwrap();
    active.retain(|r| r != not_run);
    b
}

async fn eval_issue(db: &TestDb) -> (Option<i64>, bool) {
    sqlx::query_as("SELECT fixed_analysis_id, rule_not_run FROM issues WHERE rule = 'js/no-eval'")
        .fetch_one(&db.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_finding_whose_rule_didnt_run_is_set_aside_not_fixed() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let full = upload_json_for(
        dir.path(),
        &[("a.js", "var x = 1;\neval(x);\n")],
        "shop",
        "main",
    );
    assert!(
        full["report"]["active_rules"]
            .as_array()
            .unwrap()
            .contains(&json!("js/no-eval")),
        "the report lists the rules the scan ran"
    );
    let (status, s) = upload(&db, &full).await;
    assert_eq!(status, StatusCode::CREATED, "{s}");

    // The rule didn't run: set aside, not fixed.
    let (_, s) = upload(&db, &without(&full, "js/no-eval")).await;
    assert_eq!(
        (&s["issues"]["fixed"], &s["issues"]["set_aside"]),
        (&json!(0), &json!(1)),
        "{s}"
    );
    let aside = s["analysis_id"].as_i64().unwrap();
    assert_eq!(eval_issue(&db).await, (Some(aside), true));
    let app = http::router(state(db.pool.clone()), None);
    let (_, detail) = get(app.clone(), &format!("/api/analyses/{aside}")).await;
    let detail: Value = serde_json::from_str(&detail).unwrap();
    assert_eq!(detail["fixed"]["total"], 0, "not listed as fixed");

    // It runs again and finds it: back, but not "reopened".
    let (_, s) = upload(&db, &full).await;
    assert_eq!(
        (&s["issues"]["reopened"], &s["issues"]["new"]),
        (&json!(0), &json!(0)),
        "{s}"
    );
    assert_eq!(eval_issue(&db).await, (None, false));

    // Set aside again, then it runs and it's gone: fixed now, by that scan.
    upload(&db, &without(&full, "js/no-eval")).await;
    let clean = upload_json_for(dir.path(), &[("a.js", "var x = 1;\n")], "shop", "main");
    let (_, s) = upload(&db, &clean).await;
    assert_eq!(s["issues"]["fixed"], 1, "{s}");
    let fixed_by = s["analysis_id"].as_i64().unwrap();
    assert_eq!(eval_issue(&db).await, (Some(fixed_by), false));
}

#[tokio::test]
async fn without_the_list_a_missing_finding_is_fixed_as_before() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let full = upload_json_for(
        dir.path(),
        &[("a.js", "var x = 1;\neval(x);\n")],
        "shop",
        "main",
    );
    upload(&db, &full).await;
    // An older CLI: no list of rules.
    let mut older = without(&full, "js/no-eval");
    older["report"]
        .as_object_mut()
        .unwrap()
        .remove("active_rules");
    let (_, s) = upload(&db, &older).await;
    assert_eq!(s["issues"]["fixed"], 1, "{s}");
    assert!(s["issues"].get("set_aside").is_none(), "{s}");
    assert!(!eval_issue(&db).await.1);

    let mut bad = full.clone();
    bad["report"]["active_rules"] = json!(["x".repeat(101)]);
    assert_eq!(upload(&db, &bad).await.0, StatusCode::UNPROCESSABLE_ENTITY);
}
