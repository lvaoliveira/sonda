//! Helpers shared by the server's integration tests. Each test binary uses
//! a different subset.
#![allow(dead_code)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use sonda_server::config::Token;
use sonda_server::http;
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use tower::ServiceExt;

pub struct TestDb {
    pub pool: PgPool,
    admin: PgPool,
    name: String,
}

impl TestDb {
    pub async fn new() -> Option<Self> {
        let Ok(url) = std::env::var("SONDA_TEST_DATABASE_URL") else {
            assert!(
                std::env::var_os("SONDA_REQUIRE_DB_TESTS").is_none(),
                "SONDA_REQUIRE_DB_TESTS is set but SONDA_TEST_DATABASE_URL is not"
            );
            eprintln!("skipped: set SONDA_TEST_DATABASE_URL to run database tests");
            return None;
        };
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let name = format!(
            "sonda_test_{}_{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let admin = PgPool::connect(&url).await.expect("test database server");
        // Safe to splice: `name` is built above from the process id and a
        // counter only. (Identifiers cannot be bound as parameters.)
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&admin)
            .await
            .unwrap();
        let options = PgConnectOptions::from_str(&url).unwrap().database(&name);
        let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
        Some(Self { pool, admin, name })
    }

    pub async fn drop(self) {
        self.pool.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP DATABASE {} WITH (FORCE)",
            self.name
        )))
        .execute(&self.admin)
        .await
        .unwrap();
    }
}

pub fn state(pool: PgPool) -> http::State {
    http::State {
        pool,
        token: Arc::new(Token::new(TOKEN).unwrap()),
    }
}

pub async fn get(app: axum::Router, path: &str) -> (StatusCode, String) {
    let response = app
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

/// A pool that never connects: for tests that need no database.
pub fn unreachable_pool() -> PgPool {
    let options = PgConnectOptions::new().host("127.0.0.1").port(1);
    PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(200))
        .connect_lazy_with(options)
}

pub const TOKEN: &str = "0123456789abcdef0123456789abcdef";
