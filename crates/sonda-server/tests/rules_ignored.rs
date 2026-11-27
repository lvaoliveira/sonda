//! A finding missing because `[[rules.ignore]]` leaves it out of its path isn't
//! fixed (ADR-0034), as one whose rule didn't run isn't (ADR-0018). Database
//! tests skip without SONDA_TEST_DATABASE_URL (see server.rs).

mod common;

use axum::http::StatusCode;
use common::{TestDb, analysis_detail, get, state, upload, upload_json_for};
use serde_json::{Value, json};
use sonda_server::{db, http};

/// What the CLI would send for `body` with `[[rules.ignore]]` of `paths` and
/// `rules`: the `js/no-eval` finding of `a.js` that they match is absent, and
/// the settings say so.
fn ignoring(body: &Value, paths: &[&str], rules: &[&str]) -> Value {
    let mut b = body.clone();
    let issues = b["report"]["issues"].as_array_mut().unwrap();
    issues.retain(|i| i["rule"] != "js/no-eval");
    b["report"]["rule_settings"]["ignore"] = json!([{ "paths": paths, "rules": rules }]);
    b
}

async fn eval_issue(db: &TestDb) -> (Option<i64>, bool) {
    sqlx::query_as("SELECT fixed_analysis_id, rule_not_run FROM issues WHERE rule = 'js/no-eval'")
        .fetch_one(&db.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_finding_left_out_of_its_path_is_set_aside_not_fixed() {
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
    let (status, s) = upload(&db, &full).await;
    assert_eq!(status, StatusCode::CREATED, "{s}");

    // Ignored there: set aside, and the settings are kept for the analysis.
    let ignored = ignoring(&full, &["a.js"], &["js/no-eval"]);
    let (status, s) = upload(&db, &ignored).await;
    assert_eq!(status, StatusCode::CREATED, "{s}");
    assert_eq!(
        (&s["issues"]["fixed"], &s["issues"]["set_aside"]),
        (&json!(0), &json!(1)),
        "{s}"
    );
    let aside = s["analysis_id"].as_i64().unwrap();
    assert_eq!(eval_issue(&db).await, (Some(aside), true));
    let detail = analysis_detail(&db, aside).await;
    assert_eq!(detail["fixed"]["total"], 0, "not listed as fixed");
    assert_eq!(
        detail["ruleSettings"]["ignore"],
        json!([{ "paths": ["a.js"], "rules": ["js/no-eval"] }])
    );

    // The entry goes and the finding is back: not "reopened".
    let (_, s) = upload(&db, &full).await;
    assert_eq!(
        (&s["issues"]["reopened"], &s["issues"]["new"]),
        (&json!(0), &json!(0)),
        "{s}"
    );
    assert_eq!(eval_issue(&db).await, (None, false));
}

#[tokio::test]
async fn it_is_fixed_when_nothing_leaves_it_out_any_more() {
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
    upload(&db, &ignoring(&full, &["a.js"], &["js/no-eval"])).await;

    // Still ignored by another entry: still set aside.
    let (_, s) = upload(&db, &ignoring(&full, &["*.js"], &["js/*"])).await;
    assert_eq!(s["issues"]["fixed"], 0, "{s}");
    assert!(eval_issue(&db).await.1);

    // The entry is gone, the rule runs, and the finding is not there: fixed.
    let mut clean = full.clone();
    clean["report"]["issues"]
        .as_array_mut()
        .unwrap()
        .retain(|i| i["rule"] != "js/no-eval");
    let (_, s) = upload(&db, &clean).await;
    assert_eq!(s["issues"]["fixed"], 1, "{s}");
    let fixed_by = s["analysis_id"].as_i64().unwrap();
    assert_eq!(eval_issue(&db).await, (Some(fixed_by), false));

    // An entry for another path leaves nothing out: a missing finding is fixed.
    upload(&db, &full).await;
    let mut elsewhere = clean.clone();
    elsewhere["report"]["rule_settings"]["ignore"] =
        json!([{ "paths": ["other/**"], "rules": ["js/no-eval"] }]);
    let (_, s) = upload(&db, &elsewhere).await;
    assert_eq!(s["issues"]["fixed"], 1, "{s}");
}

#[tokio::test]
async fn entries_that_cannot_be_matched_are_refused() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let full = upload_json_for(dir.path(), &[("a.js", "var x = 1;\n")], "shop", "main");
    for ignore in [
        json!([{ "paths": [], "rules": ["js/no-var"] }]),
        json!([{ "paths": ["a/**"], "rules": [] }]),
        json!([{ "paths": ["[z-a]"], "rules": ["js/no-var"] }]),
        json!([{ "paths": ["a/**"], "rules": ["x".repeat(501)] }]),
        json!(
            (0..201)
                .map(|n| json!({ "paths": [format!("p{n}/**")], "rules": ["js/no-var"] }))
                .collect::<Vec<_>>()
        ),
    ] {
        let mut bad = full.clone();
        bad["report"]["rule_settings"]["ignore"] = ignore.clone();
        assert_eq!(
            upload(&db, &bad).await.0,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{ignore}"
        );
    }
    // A key that isn't `paths` or `rules` is a body that doesn't parse.
    let mut bad = full.clone();
    bad["report"]["rule_settings"]["ignore"] =
        json!([{ "paths": ["a/**"], "rules": ["js/no-var"], "extra": 1 }]);
    assert_eq!(upload(&db, &bad).await.0, StatusCode::BAD_REQUEST);
    // Entries are stored sorted, and each list too.
    let mut ok = full.clone();
    ok["report"]["rule_settings"]["ignore"] = json!([
        { "paths": ["z/**", "a/**", "a/**"], "rules": ["js/no-var"] },
        { "paths": ["b/**"], "rules": ["js/eqeqeq", "common/*"] },
    ]);
    let (status, s) = upload(&db, &ok).await;
    assert_eq!(status, StatusCode::CREATED, "{s}");
    let app = http::router(state(db.pool.clone()), None);
    let (_, detail) = get(
        app,
        &format!("/api/analyses/{}", s["analysis_id"].as_i64().unwrap()),
    )
    .await;
    let detail: Value = serde_json::from_str(&detail).unwrap();
    assert_eq!(
        detail["ruleSettings"]["ignore"],
        json!([
            { "paths": ["b/**"], "rules": ["common/*", "js/eqeqeq"] },
            { "paths": ["a/**", "z/**"], "rules": ["js/no-var"] },
        ])
    );
}
