//! `GET /api/overview`, built from analyses spread over time: uploads are
//! backdated in the database. Database tests skip without
//! SONDA_TEST_DATABASE_URL (see server.rs).

mod common;

use axum::http::StatusCode;
use common::{TestDb, get, state, upload, upload_json_for};
use serde_json::{Value, json};
use sonda_server::{db, http};

/// Uploads `files` for `project` and backdates that analysis by `days`.
async fn analysis(
    db: &TestDb,
    dir: &std::path::Path,
    project: &str,
    files: &[(&str, &str)],
    days: i32,
) {
    let (status, summary) = upload(db, &upload_json_for(dir, files, project, "main")).await;
    assert_eq!(status, StatusCode::CREATED, "{summary}");
    sqlx::query(
        "UPDATE analyses SET received_at = now() - make_interval(days => $2) WHERE id = $1",
    )
    .bind(summary["analysis_id"].as_i64().unwrap())
    .bind(days)
    .execute(&db.pool)
    .await
    .unwrap();
}

async fn overview(db: &TestDb, query: &str) -> (StatusCode, Value) {
    let (status, body) = get(
        http::router(state(db.pool.clone()), None),
        &format!("/api/overview{query}"),
    )
    .await;
    (status, serde_json::from_str(&body).unwrap_or(Value::Null))
}

fn kpi<'a>(o: &'a Value, metric: &str) -> &'a Value {
    o["kpis"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["metric"] == metric)
        .unwrap()
}

#[tokio::test]
async fn the_overview_is_built_from_analysis_history() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let (pay, bill) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    // payments: a code smell 20 days ago; a critical vulnerability since 10
    // days ago, which fails the default gate (new vulnerabilities > 0).
    analysis(
        &db,
        pay.path(),
        "payments",
        &[("src/a.js", "var x = 1;\n")],
        20,
    )
    .await;
    analysis(
        &db,
        pay.path(),
        "payments",
        &[("src/a.js", "var x = 1;\neval(x);\n")],
        10,
    )
    .await;
    analysis(
        &db,
        pay.path(),
        "payments",
        &[("src/a.js", "var x = 1;\neval(x);\n")],
        0,
    )
    .await;
    // billing: clean; its gate passes, but coverage has no data.
    analysis(&db, bill.path(), "billing", &[("app.py", "x = 1\n")], 2).await;

    let (status, o) = overview(&db, "?range=30d").await;
    assert_eq!(status, StatusCode::OK, "{o}");
    assert_eq!(o["teams"], false);
    assert_eq!(o["summary"]["projects"], 2);
    assert_eq!(o["summary"]["components"], Value::Null);
    assert_eq!(o["summary"]["lastSounding"], "0m ago");

    // KPIs are snapshots over time: one point a day for 30 days.
    let vulns = kpi(&o, "vulns");
    assert_eq!(vulns["value"], "1");
    let series = vulns["series"].as_array().unwrap();
    // Daily points from the first analysis on (20 days ago), never from
    // before any project existed.
    assert_eq!(series.len(), 21);
    assert_eq!(
        (series[0].as_f64(), series[20].as_f64()),
        (Some(0.0), Some(1.0))
    );
    assert_eq!(
        (vulns["delta"].as_str(), vulns["improving"].as_bool()),
        (Some("+1"), Some(false))
    );
    let gate = kpi(&o, "gate");
    assert_eq!(
        (gate["value"].as_str(), gate["unit"].as_str()),
        (Some("50"), Some("%"))
    );
    assert_eq!(gate["sub"], "1 of 2 projects pass");
    let coverage = kpi(&o, "coverage");
    assert_eq!(coverage["value"], "—");
    assert!(coverage["sub"].as_str().unwrap().contains("None uploaded"));

    // Ratings: no coverage means no coverage level, not a guess.
    let dim = |label: &str| {
        o["health"]["dimensions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["label"] == label)
            .unwrap()
            .clone()
    };
    assert!(dim("Security")["level"].as_u64().unwrap() < 5);
    assert_eq!(dim("Reliability")["level"], 5);
    assert_eq!(dim("Coverage")["level"], Value::Null);
    assert_eq!(o["health"]["delta"], Value::Null);

    // Focus: the failing gate first, then the new critical issue.
    let focus = o["focus"].as_array().unwrap();
    assert_eq!(focus[0]["title"], "payments is failing its quality gate");
    assert_eq!(focus[0]["tag"], "Blocks main · 2 analyses");
    assert_eq!(focus[0]["drill"], "vulns");
    assert_eq!(focus[1]["title"], "1 new critical issue in payments");
    assert_eq!(o["focusTotal"], 2);

    // Issue flow and severities come from when issues appeared.
    let introduced: u64 = o["flow"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["introduced"].as_u64().unwrap())
        .sum();
    assert_eq!(introduced, 1, "baseline issues are open, not introduced");
    assert_eq!(o["flow"].as_array().unwrap().last().unwrap()["open"], 2);
    let critical = o["severities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["severity"] == "critical")
        .unwrap();
    assert_eq!(
        critical,
        &json!({ "severity": "critical", "open": 1, "newThisPeriod": 1 })
    );

    // Lowest score first; billing passes but lacks coverage data.
    let projects = o["projects"].as_array().unwrap();
    assert_eq!(projects[0]["name"], "payments");
    assert_eq!(projects[0]["gate"], "failed");
    assert_eq!(projects[1]["gate"], "partial");
    assert_eq!(projects[0]["trend"].as_array().unwrap().len(), 30);

    let recent = o["recent"].as_array().unwrap();
    assert_eq!(recent[0]["state"], "failed");
    assert_eq!(recent[0]["note"], "Gate failed: New vulnerabilities > 0");
    assert_eq!(recent[0]["message"], Value::Null);
    let billing = recent.iter().find(|r| r["project"] == "billing").unwrap();
    assert_eq!(billing["state"], "partial");
    assert_eq!(billing["note"], "No data for: Coverage on new code < 80%");

    let history = &o["gateHistory"];
    assert_eq!(history["days"].as_array().unwrap().len(), 30);
    assert_eq!(history["rate"], 50, "2 of 4 analyses in 30 days passed");
    assert_eq!(
        history["failing"][0],
        json!({ "label": "New vulnerabilities > 0", "failures": 2 })
    );

    // A shorter range: weekly points become daily, and the vulnerability is
    // no longer new this period.
    let (_, week) = overview(&db, "?range=7d").await;
    assert_eq!(kpi(&week, "vulns")["series"].as_array().unwrap().len(), 7);
    let critical = week["severities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["severity"] == "critical")
        .unwrap();
    assert_eq!(critical["newThisPeriod"], 0);
    // 90 days: weekly points, again only those with data (14 and 7 days ago,
    // and now).
    let (_, quarter) = overview(&db, "").await;
    assert_eq!(
        kpi(&quarter, "vulns")["series"].as_array().unwrap().len(),
        3
    );
    db.drop().await;
}

#[tokio::test]
async fn an_empty_server_and_bad_queries() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let (status, o) = overview(&db, "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(o["summary"]["projects"], 0);
    assert_eq!(o["summary"]["lastSounding"], "never");
    for bad in ["?range=1y", "?scope=mine", "?colour=red"] {
        assert_eq!(overview(&db, bad).await.0, StatusCode::BAD_REQUEST, "{bad}");
    }
    db.drop().await;
}
