//! Importing OSV advisories and matching them against dependencies.
//! Database tests skip without SONDA_TEST_DATABASE_URL (see server.rs).

mod common;

use axum::http::StatusCode;
use common::{TestDb, get, state, upload, upload_json_for};
use serde_json::{Value, json};
use sonda_server::{advisories, db, http};
use std::path::Path;

async fn api(db: &TestDb, path: &str) -> Value {
    let (status, body) = get(http::router(state(db.pool.clone()), None), path).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    serde_json::from_str(&body).unwrap()
}

fn osv(id: &str, modified: &str, ecosystem: &str, name: &str, fixed: &str, extra: Value) -> Value {
    let mut v = json!({
        "id": id,
        "modified": modified,
        "summary": format!("{name} is vulnerable"),
        "affected": [{
            "package": { "ecosystem": ecosystem, "name": name },
            "ranges": [{ "type": "ECOSYSTEM", "events": [{ "introduced": "0" }, { "fixed": fixed }] }]
        }]
    });
    for (k, val) in extra.as_object().unwrap() {
        v[k] = val.clone();
    }
    v
}

fn write(dir: &Path, name: &str, v: &Value) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join(name), serde_json::to_string(v).unwrap()).unwrap();
}

#[tokio::test]
async fn advisories_are_imported_and_flag_vulnerable_dependencies() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let project = tempfile::tempdir().unwrap();
    let lock = r#"{"lockfileVersion": 3, "packages": {"": {"dependencies": {"lodash": "^4"}},
        "node_modules/lodash": {"version": "4.17.20"},
        "node_modules/debug": {"version": "2.6.8"}}}"#;
    let body = upload_json_for(
        project.path(),
        &[
            ("package-lock.json", lock),
            ("requirements.txt", "Requests==2.30.0\nflask==3.0.3\n"),
        ],
        "shop",
        "main",
    );
    let (status, s) = upload(&db, &body).await;
    assert_eq!(status, StatusCode::CREATED, "{s}");

    let before = api(&db, "/api/projects/shop/dependencies").await;
    assert_eq!(before["advisoryData"], Value::Null, "no import yet");
    assert_eq!(before["summary"]["vulnerable"], 0);

    let osv_dir = tempfile::tempdir().unwrap();
    let npm = osv_dir.path().join("npm");
    let pypi = osv_dir.path().join("PyPI");
    write(
        &npm,
        "GHSA-35jh-r3h4-6jhm.json",
        &osv(
            "GHSA-35jh-r3h4-6jhm",
            "2024-01-01T00:00:00Z",
            "npm",
            "lodash",
            "4.17.21",
            json!({
                "aliases": ["CVE-2021-23337"],
                "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" }],
                "database_specific": { "cwe_ids": ["CWE-94"] }
            }),
        ),
    );
    // Withdrawn: matches nothing.
    write(
        &npm,
        "GHSA-gone-0000-0000.json",
        &osv(
            "GHSA-gone-0000-0000",
            "2024-01-01T00:00:00Z",
            "npm",
            "debug",
            "9.0.0",
            json!({ "withdrawn": "2024-02-01T00:00:00Z" }),
        ),
    );
    // Another database: not imported.
    write(
        &npm,
        "MAL-2024-1.json",
        &osv(
            "MAL-2024-1",
            "2024-01-01T00:00:00Z",
            "npm",
            "debug",
            "9.0.0",
            json!({}),
        ),
    );
    // The same vulnerability from PyPA and GitHub: one finding.
    write(
        &pypi,
        "PYSEC-2023-74.json",
        &osv(
            "PYSEC-2023-74",
            "2024-01-01T00:00:00Z",
            "PyPI",
            "requests",
            "2.31.0",
            json!({ "aliases": ["CVE-2023-32681", "GHSA-j8r2-6x86-q33q"] }),
        ),
    );
    write(
        &pypi,
        "GHSA-j8r2-6x86-q33q.json",
        &osv(
            "GHSA-j8r2-6x86-q33q",
            "2024-01-01T00:00:00Z",
            "PyPI",
            "requests",
            "2.31.0",
            json!({ "aliases": ["CVE-2023-32681"], "database_specific": { "severity": "MODERATE" } }),
        ),
    );
    std::fs::write(npm.join("broken.json"), "{").unwrap();
    std::fs::write(npm.join("README.md"), "not a record").unwrap();

    let s = advisories::import(&db.pool, &[osv_dir.path().to_path_buf()])
        .await
        .unwrap();
    assert_eq!(
        (s.read, s.imported, s.skipped, s.errors),
        (6, 4, 1, 1),
        "{s:?}"
    );

    let d = api(&db, "/api/projects/shop/dependencies").await;
    assert!(d["advisoryData"]["importedAt"].is_string(), "{d}");
    assert_eq!(
        d["advisoryData"]["advisories"], 3,
        "the withdrawn one isn't counted"
    );
    assert_eq!(d["summary"]["vulnerable"], 2, "{d}");
    let row = |name: &str| {
        d["dependencies"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == name)
            .unwrap()
            .clone()
    };
    let lodash = row("lodash");
    assert_eq!(lodash["advisories"][0]["id"], "GHSA-35jh-r3h4-6jhm");
    assert_eq!(lodash["advisories"][0]["severity"], "critical", "CVSS 7.2");
    assert_eq!(lodash["advisories"][0]["fixedIn"], "4.17.21");
    assert_eq!(lodash["advisories"][0]["cwe"], json!([94]));
    assert_eq!(
        lodash["advisories"][0]["url"],
        "https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm"
    );
    assert!(
        lodash["advisories"][0]["source"]
            .as_str()
            .unwrap()
            .contains("GitHub")
    );
    let requests = row("Requests");
    let ids: Vec<&str> = requests["advisories"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["GHSA-j8r2-6x86-q33q"], "one finding, GitHub's");
    assert_eq!(row("debug")["advisories"], json!([]));
    assert_eq!(row("flask")["advisories"], json!([]));

    let p = api(&db, "/api/projects/shop").await;
    assert_eq!(p["dependencies"]["vulnerable"], 2);

    // Re-importing changes nothing; a newer record replaces the old one.
    let s = advisories::import(&db.pool, &[osv_dir.path().to_path_buf()])
        .await
        .unwrap();
    assert_eq!((s.imported, s.unchanged), (0, 4));
    write(
        &npm,
        "GHSA-35jh-r3h4-6jhm.json",
        &osv(
            "GHSA-35jh-r3h4-6jhm",
            "2025-01-01T00:00:00Z",
            "npm",
            "lodash",
            "4.17.19",
            json!({}),
        ),
    );
    let s = advisories::import(&db.pool, &[npm.join("GHSA-35jh-r3h4-6jhm.json")])
        .await
        .unwrap();
    assert_eq!(s.imported, 1);
    let d = api(&db, "/api/projects/shop/dependencies").await;
    assert_eq!(
        d["summary"]["vulnerable"], 1,
        "lodash 4.17.20 is no longer affected"
    );
}
