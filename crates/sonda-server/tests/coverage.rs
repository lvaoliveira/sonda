//! Line coverage per file, and one file's covered and uncovered lines.
//! Database tests skip without SONDA_TEST_DATABASE_URL (see server.rs).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use common::{TOKEN, TestDb, state_with, upload, upload_json_for};
use serde_json::{Value, json};
use sonda_server::{db, http};
use tower::ServiceExt;

async fn get(app: &axum::Router, path: &str) -> (StatusCode, Value) {
    let request = Request::get(path)
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .body(Body::empty())
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 4 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn coverage_per_file_and_per_line() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    let app = http::router(state_with(db.pool.clone(), true), None);
    let dir = tempfile::tempdir().unwrap();
    let files = [
        ("src/a.js", "let a = 1;\nif (a) {\n  a++;\n}\n"),
        ("src/b.js", "let b = 2;\n"),
        (
            "lcov.info",
            "SF:src/a.js\nFN:2,bump\nFNDA:0,bump\nBRDA:2,0,0,1\nBRDA:2,0,1,0\n\
             DA:1,1\nDA:2,1\nDA:3,0\nend_of_record\n",
        ),
    ];
    let (status, _) = upload(&db, &upload_json_for(dir.path(), &files, "shop", "main")).await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, list) = get(&app, "/api/projects/shop/coverage").await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert_eq!(list["branch"], "main");
    assert_eq!(list["coverage"], 66.7);
    assert_eq!(
        list["files"],
        json!([
            { "path": "src/a.js", "language": "javascript", "covered": 2, "uncovered": 1,
              "branches": { "covered": 1, "total": 2 }, "functions": { "covered": 0, "total": 1 } },
            { "path": "src/b.js", "language": "javascript", "covered": null, "uncovered": null,
              "branches": null, "functions": null },
        ])
    );

    let (status, file) = get(&app, "/api/projects/shop/coverage/file?path=src/a.js").await;
    assert_eq!(status, StatusCode::OK, "{file}");
    assert_eq!(
        (&file["covered"], &file["uncovered"], &file["truncated"]),
        (&json!([1, 2]), &json!([3]), &json!(false))
    );
    assert_eq!(file["lines"].as_array().unwrap().len(), 4);
    assert_eq!(
        (&file["branches"], &file["functions"]),
        (
            &json!([{ "line": 2, "taken": 1, "total": 2 }]),
            &json!([{ "name": "bump", "line": 2, "calls": 0 }])
        )
    );
    assert_eq!(file["lines"][2]["number"], 3);

    // A file without data says so; unknown files and branches don't exist.
    let (_, b) = get(&app, "/api/projects/shop/coverage/file?path=src/b.js").await;
    assert_eq!(
        (&b["covered"], &b["uncovered"]),
        (&Value::Null, &Value::Null)
    );
    assert_eq!(
        (&b["branches"], &b["functions"]),
        (&Value::Null, &Value::Null)
    );
    for (path, expected) in [
        (
            "/api/projects/shop/coverage/file?path=nope.js",
            StatusCode::NOT_FOUND,
        ),
        ("/api/projects/nope/coverage", StatusCode::NOT_FOUND),
        (
            "/api/projects/shop/coverage?branch=dev",
            StatusCode::BAD_REQUEST,
        ),
        (
            "/api/projects/shop/coverage?bogus=1",
            StatusCode::BAD_REQUEST,
        ),
    ] {
        assert_eq!(get(&app, path).await.0, expected, "{path}");
    }
}
