//! Pull request analyses (ADR-0021). Database tests skip without
//! SONDA_TEST_DATABASE_URL (see server.rs).

mod common;

use axum::http::StatusCode;
use common::{TestDb, get, state, upload, upload_json_for};
use serde_json::{Value, json};
use sonda_server::{db, http, pull_requests};

/// An upload of `files` for pull request 12 of `project`, fix/login into
/// main.
fn pull_request(dir: &std::path::Path, files: &[(&str, &str)], project: &str) -> Value {
    let mut body = upload_json_for(dir, files, project, "fix/login");
    body["pull_request"] = json!({
        "number": 12,
        "base": "main",
        "head": "fix/login",
        "head_sha": "A".repeat(40),
        "repository": "acme/shop",
    });
    body
}

async fn count(db: &TestDb, sql: &'static str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(&db.pool).await.unwrap()
}

async fn json(app: &axum::Router, path: &str) -> Value {
    let (status, body) = get(app.clone(), path).await;
    assert_eq!(status, StatusCode::OK, "{path}: {body}");
    serde_json::from_str(&body).unwrap()
}

#[tokio::test]
async fn pull_requests_are_analyses_of_their_own_kept_out_of_branches() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let app = http::router(state(db.pool.clone()), None);
    let dir = tempfile::tempdir().unwrap();
    let main = [("a.js", "var a = 1;\n")];
    let (status, _) = upload(&db, &upload_json_for(dir.path(), &main, "shop", "main")).await;
    assert_eq!(status, StatusCode::CREATED);
    let changed = [("a.js", "var a = 1;\n"), ("b.js", "eval(input);\n")];
    let (status, answer) = upload(&db, &pull_request(dir.path(), &changed, "shop")).await;
    assert_eq!(status, StatusCode::CREATED, "{answer}");
    let pr_analysis = answer["analysis_id"].as_i64().unwrap();

    // Stored under its own key, its head commit lowercased.
    let stored: (String, i64, String, String, String) = sqlx::query_as(
        "SELECT branch, pull_request, pull_request_head, pull_request_head_sha,
                pull_request_repository FROM analyses WHERE id = $1",
    )
    .bind(pr_analysis)
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(
        stored,
        (
            "pr:12".into(),
            12,
            "fix/login".into(),
            "a".repeat(40),
            "acme/shop".into()
        )
    );

    // The project page lists it apart; the branches and main's issues don't
    // have it.
    let p = json(&app, "/api/projects/shop").await;
    let branches: Vec<&str> = p["branches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["name"].as_str().unwrap())
        .collect();
    assert_eq!(branches, ["main"]);
    let prs = p["pullRequests"].as_array().unwrap();
    assert_eq!(prs.len(), 1);
    assert_eq!(
        (
            &prs[0]["number"],
            &prs[0]["base"],
            &prs[0]["head"],
            &prs[0]["analysis"]
        ),
        (
            &json!(12),
            &json!("main"),
            &json!("fix/login"),
            &json!(pr_analysis)
        )
    );
    assert!(prs[0]["newIssues"].as_f64().unwrap() >= 1.0, "{}", prs[0]);
    let main_issues = json(&app, "/api/issues?project=shop&branch=main").await;
    let pr_issues = json(&app, "/api/issues?project=shop&branch=pr:12").await;
    assert!(
        pr_issues["total"].as_i64().unwrap() > main_issues["total"].as_i64().unwrap(),
        "{pr_issues}"
    );
    let settings = json(&app, "/api/projects/shop/settings").await;
    assert_eq!(settings["branches"].as_array().unwrap().len(), 1);

    // The analyses say which pull request they're for.
    let detail = json(&app, &format!("/api/analyses/{pr_analysis}")).await;
    assert_eq!(
        detail["pullRequest"],
        json!({"number": 12, "base": "main", "head": "fix/login"})
    );
    let list = json(&app, "/api/analyses?project=shop").await;
    let kinds: Vec<&Value> = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| &a["pullRequest"])
        .collect();
    assert_eq!(kinds[0]["number"], 12);
    assert_eq!(kinds[1], &Value::Null);

    // Its key is no branch name, and a pull request is checked.
    let mut posing = upload_json_for(dir.path(), &main, "shop", "main");
    posing["branch"] = json!("pr:12");
    assert_eq!(
        upload(&db, &posing).await.0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    posing["branch"] = json!("main");
    posing["pull_request"] = json!({"number": 0, "base": "main", "head": "x"});
    assert_eq!(
        upload(&db, &posing).await.0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    posing["pull_request"] = json!({"number": 1, "base": "main", "head": "x", "unknown": 1});
    assert_eq!(upload(&db, &posing).await.0, StatusCode::BAD_REQUEST);

    // A project first seen through a pull request: its base is the main
    // branch.
    let (status, _) = upload(&db, &pull_request(dir.path(), &changed, "blog")).await;
    assert_eq!(status, StatusCode::CREATED);
    let main_branch: String =
        sqlx::query_scalar("SELECT main_branch FROM projects WHERE key = 'blog'")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(main_branch, "main");

    // Kept while recent; removed, with what only it had, once old.
    assert_eq!(pull_requests::remove_stale(&db.pool).await.unwrap(), 0);
    let sources = count(&db, "SELECT count(*) FROM sources").await;
    sqlx::query(
        "UPDATE analyses SET received_at = now() - interval '31 days'
         WHERE pull_request IS NOT NULL AND project_id = (SELECT id FROM projects WHERE key = 'shop')",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    assert_eq!(pull_requests::remove_stale(&db.pool).await.unwrap(), 1);
    assert_eq!(
        count(&db, "SELECT count(*) FROM analyses WHERE branch = 'pr:12'").await,
        1,
        "blog's is recent"
    );
    assert_eq!(
        count(
            &db,
            "SELECT count(*) FROM issues i JOIN projects p ON p.id = i.project_id
               WHERE p.key = 'shop' AND i.branch = 'pr:12'"
        )
        .await,
        0
    );
    // b.js stays: blog's pull request has it too.
    assert_eq!(count(&db, "SELECT count(*) FROM sources").await, sources);
    let p = json(&app, "/api/projects/shop").await;
    assert_eq!(p["pullRequests"], json!([]));
    assert_eq!(p["branches"][0]["name"], "main");
}
