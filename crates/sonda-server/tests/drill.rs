//! `GET /api/drill/{metric}`: what is behind each Overview metric, by
//! component and file. Database tests skip without SONDA_TEST_DATABASE_URL
//! (see server.rs).

mod common;

use axum::http::StatusCode;
use common::{TestDb, get, state, upload, upload_json};
use serde_json::Value;
use sonda_server::{db, http};

/// A block long enough to count as duplicated (100 tokens, 10 lines).
fn block(name: &str) -> String {
    let mut s = format!("function {name}(a, b, c) {{\n");
    for i in 0..14 {
        s += &format!("  let v{i} = a * {i} + b - c / {i};\n");
    }
    s += "  return a;\n}\n";
    s
}

async fn drill(db: &TestDb, query: &str) -> (StatusCode, Value) {
    let (status, body) = get(
        http::router(state(db.pool.clone()), None),
        &format!("/api/drill/{query}"),
    )
    .await;
    (status, serde_json::from_str(&body).unwrap_or(Value::Null))
}

#[tokio::test]
async fn each_metric_drills_into_components_and_files() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let shared = block("same");
    let files = [
        ("src/api/a.js", format!("var x = 1;\neval(x);\n{shared}")),
        ("src/api/b.js", format!("eval(y);\n{shared}")),
        ("lib/c.py", "eval(input())\n".to_string()),
    ];
    let files: Vec<(&str, &str)> = files.iter().map(|(p, c)| (*p, c.as_str())).collect();
    // A first, clean analysis starts the main branch's new code period
    // (ADR-0011), so the issues uploaded next are new.
    upload(
        &db,
        &upload_json(dir.path(), &[("src/api/keep.js", "let k = 1;\n")], "main"),
    )
    .await;
    upload(&db, &upload_json(dir.path(), &files, "main")).await;

    // Critical issues: three eval() calls, src/ first (two of them).
    let (status, critical) = drill(&db, "critical").await;
    assert_eq!(status, StatusCode::OK, "{critical}");
    assert_eq!(critical["title"], "3 blocker & critical issues");
    assert_eq!(critical["items"][0]["component"], "src");
    assert_eq!(critical["items"][0]["project"], "payments");
    assert_eq!(
        critical["items"][0]["owner"],
        Value::Null,
        "owners are not recorded"
    );
    assert_eq!(critical["items"][0]["value"], 2.0);
    let file = &critical["items"][0]["files"][0];
    assert_eq!(
        (file["dir"].as_str(), file["value"].as_str()),
        (Some("src/api/"), Some("1 issue"))
    );
    assert_eq!(file["issue"]["severity"], "critical");
    assert_eq!(critical["items"][1]["component"], "lib");

    let (_, vulns) = drill(&db, "vulns").await;
    assert_eq!(vulns["title"], "3 open vulnerabilities");
    assert_eq!(vulns["sub"], "3 critical.");

    let (_, debt) = drill(&db, "debt").await;
    assert_eq!(debt["unit"], "h");
    assert!(debt["items"][0]["value"].as_f64().unwrap() > 0.0);

    // The gate fails on new vulnerabilities; its files hold new issues.
    let (_, gate) = drill(&db, "gate").await;
    assert_eq!(gate["title"], "1 project failing its gate");
    assert_eq!(gate["items"][0]["component"], "payments");
    assert!(
        gate["items"][0]["project"]
            .as_str()
            .unwrap()
            .contains("failing condition")
    );
    assert!(!gate["items"][0]["files"].as_array().unwrap().is_empty());

    let (_, dup) = drill(&db, "dup").await;
    assert_eq!(dup["items"][0]["component"], "src");
    assert!(
        dup["items"][0]["files"][0]["value"]
            .as_str()
            .unwrap()
            .ends_with('%')
    );

    // No coverage uploaded: said plainly, nothing invented.
    let (_, coverage) = drill(&db, "coverage").await;
    assert_eq!(coverage["title"], "No coverage uploaded");
    assert_eq!(coverage["invert"], true);
    assert_eq!(coverage["items"], serde_json::json!([]));

    // Accepted issues no longer count.
    sqlx::query("UPDATE issues SET status = 'accepted' WHERE path = 'lib/c.py'")
        .execute(&db.pool)
        .await
        .unwrap();
    assert_eq!(
        drill(&db, "critical").await.1["title"],
        "2 blocker & critical issues"
    );

    // With a CODEOWNERS file in the next upload, owners appear: each
    // directory's majority owner, and the project's for project rows.
    std::fs::create_dir_all(dir.path().join(".github")).unwrap();
    std::fs::write(
        dir.path().join(".github/CODEOWNERS"),
        "src/ @web\nlib/ @py @data\n",
    )
    .unwrap();
    upload(&db, &upload_json(dir.path(), &files, "main")).await;
    let (_, critical) = drill(&db, "critical").await;
    let owner = |c: &str| {
        critical["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["component"] == c)
            .map(|i| i["owner"].clone())
    };
    assert_eq!(owner("src"), Some("@web".into()));
    // lib/ is gone: its only issue was accepted above.
    assert_eq!(owner("lib"), None);
    let (_, gate) = drill(&db, "gate").await;
    assert_eq!(
        gate["items"][0]["owner"], "@web",
        "two of the project's three files"
    );

    for bad in ["nonsense", "critical?scope=mine", "critical?colour=red"] {
        assert_eq!(drill(&db, bad).await.0, StatusCode::BAD_REQUEST, "{bad}");
    }
    db.drop().await;
}
