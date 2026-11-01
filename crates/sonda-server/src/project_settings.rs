//! A project's settings (ADR-0017): its display name and main branch, with
//! who changed them. Members read them; admins change them.

use crate::api::{ApiError, Caller};
use crate::health::{ago, rfc3339};
use crate::http::State;
use axum::Json;
use axum::extract::{Extension, Path};
use serde::{Deserialize, Deserializer, Serialize};
use sqlx::PgPool;

/// How many changes the settings show, newest first.
const CHANGES: i64 = 50;

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    pub key: String,
    pub name: Option<String>,
    pub main_branch: String,
    /// Every branch with analyses, the main one first, then by name.
    pub branches: Vec<Branch>,
    /// Newest first.
    pub changes: Vec<Change>,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Branch {
    pub name: String,
    pub analyses: i64,
    pub analyzed_at: String,
    pub ago: String,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Change {
    /// `name` or `main_branch`.
    pub setting: String,
    pub old: Option<String>,
    pub new: Option<String>,
    pub by: String,
    pub at: String,
}

/// A `project_changes` row: setting, old, new, actor, when.
type ChangeRow = (String, Option<String>, Option<String>, String, f64);

async fn project(pool: &PgPool, key: &str) -> Result<(i64, Option<String>, String), ApiError> {
    sqlx::query_as("SELECT id, name, main_branch FROM projects WHERE key = $1")
        .bind(key)
        .fetch_optional(pool)
        .await?
        .ok_or(ApiError::NotFound)
}

async fn load(pool: &PgPool, key: String) -> Result<Settings, ApiError> {
    let (id, name, main_branch) = project(pool, &key).await?;
    let now: f64 = sqlx::query_scalar("SELECT extract(epoch FROM now())::float8")
        .fetch_one(pool)
        .await?;
    let rows: Vec<(String, i64, f64)> = sqlx::query_as(
        "SELECT branch, count(*), extract(epoch FROM max(received_at))::float8
         FROM analyses WHERE project_id = $1 GROUP BY branch",
    )
    .bind(id)
    .fetch_all(pool)
    .await?;
    let mut branches: Vec<Branch> = rows
        .into_iter()
        .map(|(name, analyses, at)| Branch {
            name,
            analyses,
            analyzed_at: rfc3339(at),
            ago: ago(now - at),
        })
        .collect();
    branches.sort_by_key(|b| (b.name != main_branch, b.name.clone()));
    let changes: Vec<ChangeRow> = sqlx::query_as(
        "SELECT setting, old_value, new_value, actor, extract(epoch FROM at)::float8
         FROM project_changes WHERE project_id = $1 ORDER BY id DESC LIMIT $2",
    )
    .bind(id)
    .bind(CHANGES)
    .fetch_all(pool)
    .await?;
    Ok(Settings {
        key,
        name,
        main_branch,
        branches,
        changes: changes
            .into_iter()
            .map(|(setting, old, new, by, at)| Change {
                setting,
                old,
                new,
                by,
                at: rfc3339(at),
            })
            .collect(),
    })
}

/// `GET /api/projects/{key}/settings`.
pub async fn get(
    axum::extract::State(state): axum::extract::State<State>,
    Path(key): Path<String>,
) -> Result<Json<Settings>, ApiError> {
    load(&state.pool, key).await.map(Json)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Patch {
    /// A new name, or null to show the key alone; absent leaves it.
    #[serde(default, deserialize_with = "present")]
    name: Option<Option<String>>,
    main_branch: Option<String>,
}

/// Tells an explicit null (`Some(None)`) from an absent field (`None`).
fn present<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Option<String>>, D::Error> {
    Option::<String>::deserialize(d).map(Some)
}

/// `PATCH /api/projects/{key}/settings`, admins only. Changing the main
/// branch changes what every screen counts at once, and starts the new
/// code period over on it (ADR-0011): from its first analysis, or its
/// version's, since a start an admin set was an analysis of the old one.
pub async fn patch(
    axum::extract::State(state): axum::extract::State<State>,
    Extension(caller): Extension<Caller>,
    Path(key): Path<String>,
    Json(patch): Json<Patch>,
) -> Result<Json<Settings>, ApiError> {
    let pool = &state.pool;
    let (id, old_name, old_main) = project(pool, &key).await?;
    let name = match patch.name {
        None => old_name.clone(),
        Some(n) => {
            let n = n.map(|n| n.trim().to_string()).filter(|n| !n.is_empty());
            if n.as_ref().is_some_and(|n| n.chars().count() > 100) {
                return Err(ApiError::Unprocessable(
                    "a project name is at most 100 characters".into(),
                ));
            }
            n
        }
    };
    let main = patch.main_branch.unwrap_or_else(|| old_main.clone());
    if main != old_main {
        let analyzed: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM analyses WHERE project_id = $1 AND branch = $2)",
        )
        .bind(id)
        .bind(&main)
        .fetch_one(pool)
        .await?;
        if !analyzed {
            return Err(ApiError::Unprocessable(format!(
                "branch {main:?} has no analyses; the main branch must be one that does"
            )));
        }
    }

    let mut tx = pool.begin().await?;
    for (setting, old, new) in [
        ("name", old_name.clone(), name.clone()),
        ("main_branch", Some(old_main.clone()), Some(main.clone())),
    ] {
        if old != new {
            sqlx::query(
                "INSERT INTO project_changes (project_id, actor, setting, old_value, new_value)
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(id)
            .bind(caller.name())
            .bind(setting)
            .bind(old)
            .bind(new)
            .execute(&mut *tx)
            .await?;
        }
    }
    sqlx::query("UPDATE projects SET name = $2 WHERE id = $1")
        .bind(id)
        .bind(&name)
        .execute(&mut *tx)
        .await?;
    if main != old_main {
        sqlx::query("UPDATE projects SET main_branch = $2, new_code_since = NULL WHERE id = $1")
            .bind(id)
            .bind(&main)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    if main != old_main {
        crate::new_code::refresh(pool, id).await?;
        crate::dependencies::refresh_gates(pool, crate::dependencies::GateScope::Project(id))
            .await?;
    }
    load(pool, key).await.map(Json)
}
