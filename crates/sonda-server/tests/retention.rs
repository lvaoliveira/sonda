//! Thinning old branch analyses (docs/release-1.0.md, M2). Database tests
//! skip without SONDA_TEST_DATABASE_URL (see server.rs).

mod common;

use axum::http::StatusCode;
use common::{TestDb, get, state, upload, upload_json_for};
use sonda_server::{db, http, retention};

const CLEAN: &str = "function f() { return 1; }\n";
const WITH_G: &str = "function f() { return 1; }\nfunction g(a) { return eval(a); }\n";
const WITH_G_AND_H: &str = "function f() { return 1; }\nfunction g(a) { return eval(a); }\nfunction h(b) { return eval(b); }\n";

/// Uploads `source` as the next analysis of `payments`' `branch`, then
/// moves it to `hours_ago`. Returns its id.
async fn analysis(db: &TestDb, branch: &str, source: &str, hours_ago: i64) -> i64 {
    let dir = tempfile::tempdir().unwrap();
    let body = upload_json_for(dir.path(), &[("app.js", source)], "payments", branch);
    let (status, answer) = upload(db, &body).await;
    assert_eq!(status, StatusCode::CREATED, "{answer}");
    let id = answer["analysis_id"].as_i64().unwrap();
    sqlx::query(
        "UPDATE analyses SET received_at = now() - make_interval(hours => $2::int) WHERE id = $1",
    )
    .bind(id)
    .bind(hours_ago as i32)
    .execute(&db.pool)
    .await
    .unwrap();
    id
}

async fn ids(db: &TestDb) -> Vec<i64> {
    sqlx::query_scalar("SELECT id FROM analyses ORDER BY id")
        .fetch_all(&db.pool)
        .await
        .unwrap()
}

/// An issue's (first, last, fixed) analyses, by the line of its message's
/// function: `g` and `h` sit on lines 2 and 3.
async fn lifetime(db: &TestDb, line: i32) -> (i64, i64, Option<i64>, String) {
    sqlx::query_as(
        "SELECT first_analysis_id, last_analysis_id, fixed_analysis_id, status::text
         FROM issues WHERE line = $1",
    )
    .bind(line)
    .fetch_one(&db.pool)
    .await
    .unwrap()
}

const DAYS: i32 = 90;
const DAY: i64 = 24;

#[tokio::test]
async fn old_analyses_are_thinned_to_one_a_day_and_issues_move_to_the_ones_that_stay() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let a1 = analysis(&db, "main", CLEAN, 200 * DAY).await;
    // Two the same day, 150 days ago: only the later one stays.
    analysis(&db, "main", WITH_G_AND_H, 150 * DAY + 9).await;
    let a3 = analysis(&db, "main", WITH_G, 150 * DAY).await;
    let a4 = analysis(&db, "main", &format!("{WITH_G}// edit\n"), 100 * DAY).await;
    let a5 = analysis(&db, "main", CLEAN, 1).await;
    sqlx::query("UPDATE issues SET status = 'accepted' WHERE line = 2")
        .execute(&db.pool)
        .await
        .unwrap();
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM sources")
        .fetch_one(&db.pool)
        .await
        .unwrap();

    assert_eq!(retention::thin(&db.pool, DAYS).await.unwrap(), 1);
    assert_eq!(
        ids(&db).await,
        [a1, a3, a4, a5],
        "the first, each day's last, the latest"
    );

    // `g` was first seen in a2, which went: it moves to the next that stays.
    // It was fixed by a5, and its triage is intact.
    assert_eq!(
        lifetime(&db, 2).await,
        (a3, a4, Some(a5), "accepted".into())
    );
    // `h` lived only in a2: it can't end before it begins.
    assert_eq!(lifetime(&db, 3).await, (a3, a3, Some(a3), "open".into()));

    // The content only a2 had is gone; what others share stays.
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM sources")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(after, before - 1);

    // Nothing to do the second time, and it all still reads.
    assert_eq!(retention::thin(&db.pool, DAYS).await.unwrap(), 0);
    for path in [
        format!("/api/analyses/{a3}"),
        format!("/api/analyses/{a5}"),
        "/api/issues".into(),
        "/api/projects/payments".into(),
    ] {
        let (status, body) = get(http::router(state(db.pool.clone()), None), &path).await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
    }
}

#[tokio::test]
async fn what_the_new_code_period_starts_from_stays() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let a1 = analysis(&db, "main", CLEAN, 200 * DAY).await;
    // The first of version 1.0, then two more that day.
    let a2 = analysis(&db, "main", WITH_G, 150 * DAY + 3).await;
    let a3 = analysis(&db, "main", WITH_G_AND_H, 150 * DAY + 2).await;
    let a4 = analysis(&db, "main", CLEAN, 150 * DAY).await;
    let a5 = analysis(&db, "main", CLEAN, 1).await;
    sqlx::query("UPDATE analyses SET project_version = '1.0' WHERE id = ANY($1)")
        .bind([a2, a3, a4])
        .execute(&db.pool)
        .await
        .unwrap();

    // An admin's start is kept, as is the first of a version.
    sqlx::query("UPDATE projects SET new_code_since = $1")
        .bind(a3)
        .execute(&db.pool)
        .await
        .unwrap();
    assert_eq!(retention::thin(&db.pool, DAYS).await.unwrap(), 0);
    sqlx::query("UPDATE projects SET new_code_since = NULL")
        .execute(&db.pool)
        .await
        .unwrap();
    assert_eq!(retention::thin(&db.pool, DAYS).await.unwrap(), 1);
    assert_eq!(ids(&db).await, [a1, a2, a4, a5]);
}

#[tokio::test]
async fn pull_requests_and_recent_analyses_are_left_alone() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    analysis(&db, "main", CLEAN, 5 * DAY).await;
    analysis(&db, "main", WITH_G, 4 * DAY + 5).await;
    analysis(&db, "main", WITH_G, 4 * DAY).await;
    analysis(&db, "main", WITH_G, 3 * DAY).await;
    assert_eq!(
        retention::thin(&db.pool, DAYS).await.unwrap(),
        0,
        "all younger than 90 days"
    );
    // Old, but a pull request's: its own cleanup removes whole pull requests.
    for hours in [150 * DAY + 5, 150 * DAY + 4, 150 * DAY] {
        let id = analysis(&db, "feature", WITH_G, hours).await;
        sqlx::query("UPDATE analyses SET branch = 'pr:7', pull_request = 7, pull_request_base = 'main', pull_request_head = 'feature' WHERE id = $1")
            .bind(id)
            .execute(&db.pool)
            .await
            .unwrap();
    }
    assert_eq!(retention::thin(&db.pool, DAYS).await.unwrap(), 0);
}
