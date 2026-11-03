//! A migration that fails leaves the database as it was (docs/release-1.0.md,
//! M2): each runs in a transaction, and the server stops with the reason
//! instead of serving on a half-migrated schema. Database tests skip without
//! SONDA_TEST_DATABASE_URL (see server.rs).

mod common;

use common::TestDb;
use sonda_server::db;
use sqlx::migrate::Migrator;
use sqlx::postgres::PgPoolOptions;
use std::path::Path;

/// The real migrations plus one more that does some work, then fails.
async fn migrator_with_a_bad_one(dir: &Path) -> Migrator {
    for entry in std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations")).unwrap() {
        let path = entry.unwrap().path();
        std::fs::copy(&path, dir.join(path.file_name().unwrap())).unwrap();
    }
    std::fs::write(
        dir.join("9999_bad.sql"),
        "CREATE TABLE half_done (id int);
         ALTER TABLE projects ADD COLUMN half_done text;
         UPDATE projects SET key = key || '-changed';
         SELECT 1 / 0;",
    )
    .unwrap();
    Migrator::new(dir).await.unwrap()
}

#[tokio::test]
async fn a_failed_migration_leaves_the_database_as_it_was() {
    let Some(db) = TestDb::new().await else {
        return;
    };
    db::migrate(&db.pool).await.unwrap();
    sqlx::query("INSERT INTO projects (key) VALUES ('payments')")
        .execute(&db.pool)
        .await
        .unwrap();
    let applied = |pool| async move {
        sqlx::query_scalar::<_, i64>("SELECT max(version) FROM _sqlx_migrations WHERE success")
            .fetch_one(&pool)
            .await
            .unwrap()
    };
    let before = applied(db.pool.clone()).await;

    let dir = tempfile::tempdir().unwrap();
    let error = migrator_with_a_bad_one(dir.path())
        .await
        .run(&db.pool)
        .await
        .expect_err("the bad migration must fail");
    assert!(
        error.to_string().contains("9999"),
        "names the migration: {error}"
    );

    // Nothing the failed migration did is left.
    let tables: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.tables WHERE table_name = 'half_done'",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    let columns: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.columns
         WHERE table_name = 'projects' AND column_name = 'half_done'",
    )
    .fetch_one(&db.pool)
    .await
    .unwrap();
    let keys: Vec<String> = sqlx::query_scalar("SELECT key FROM projects")
        .fetch_all(&db.pool)
        .await
        .unwrap();
    assert_eq!((tables, columns), (0, 0));
    assert_eq!(keys, ["payments"]);
    assert_eq!(applied(db.pool.clone()).await, before);

    // And the server's own migrations still run after a restart. A restart is
    // new connections: sqlx keeps its advisory lock on the failed one until
    // it closes, as the exiting process does.
    let options = (*db.pool.connect_options()).clone();
    db.pool.close().await;
    let restarted = PgPoolOptions::new().connect_with(options).await.unwrap();
    db::migrate(&restarted).await.unwrap();
    assert_eq!(applied(restarted).await, before);
}
