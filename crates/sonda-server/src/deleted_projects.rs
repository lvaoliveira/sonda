//! Deleting a project (ADR-0017): permanent, confirmed by typing its key,
//! and its key refused afterwards until an admin allows it again, so a
//! forgotten pipeline can't bring the project back empty.

use crate::api::{ApiError, Caller};
use crate::health::rfc3339;
use crate::http::State;
use axum::Json;
use axum::extract::{Extension, Path};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};

/// A deleted key, as the Admin page lists it.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Deleted {
    pub id: i64,
    pub key: String,
    pub name: Option<String>,
    /// How many analyses it had.
    pub analyses: i64,
    pub deleted_by: String,
    pub deleted_at: String,
    /// Who allowed the key again, and when; null while it's refused.
    pub allowed_by: Option<String>,
    pub allowed_at: Option<String>,
}

type DeletedRow = (
    i64,
    String,
    Option<String>,
    i64,
    String,
    f64,
    Option<String>,
    Option<f64>,
);

// A constant, never input: `AssertSqlSafe` below is sound.
const COLUMNS: &str = "id, key, name, analyses, deleted_by, extract(epoch FROM deleted_at)::float8,
     allowed_by, extract(epoch FROM allowed_at)::float8";

fn deleted(r: DeletedRow) -> Deleted {
    Deleted {
        id: r.0,
        key: r.1,
        name: r.2,
        analyses: r.3,
        deleted_by: r.4,
        deleted_at: rfc3339(r.5),
        allowed_by: r.6,
        allowed_at: r.7.map(rfc3339),
    }
}

/// Serializes deleting a key with uploads to it, until the transaction
/// ends: an upload in flight either lands before the project is deleted,
/// or sees its key refused.
pub(crate) async fn lock_key(tx: &mut Transaction<'_, Postgres>, key: &str) -> sqlx::Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('project-key' || E'\\n' || $1, 0))")
        .bind(key)
        .execute(&mut **tx)
        .await
        .map(|_| ())
}

/// Why uploads to `key` are refused, if they are.
pub(crate) async fn refused<'e, E: sqlx::PgExecutor<'e>>(
    db: E,
    key: &str,
) -> sqlx::Result<Option<String>> {
    let row: Option<(String, f64)> = sqlx::query_as(
        "SELECT deleted_by, extract(epoch FROM deleted_at)::float8 FROM deleted_projects
         WHERE key = $1 AND allowed_at IS NULL",
    )
    .bind(key)
    .fetch_optional(db)
    .await?;
    Ok(row.map(|(by, at)| {
        format!(
            "project {key:?} was deleted by {by} on {}; an admin can allow its key again on the Admin page",
            &rfc3339(at)[..10]
        )
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Confirm {
    /// The project's key, typed again.
    confirm: String,
}

/// `DELETE /api/projects/{key}`, admins only, with `{"confirm": key}`.
/// Removes its analyses, issues and their history, settings and reviews
/// (all cascade from the project), the file contents no other analysis
/// uses, and revokes its project analysis tokens.
pub async fn delete(
    axum::extract::State(state): axum::extract::State<State>,
    Extension(caller): Extension<Caller>,
    Path(key): Path<String>,
    Json(c): Json<Confirm>,
) -> Result<Json<Deleted>, ApiError> {
    if c.confirm != key {
        return Err(ApiError::Unprocessable(
            "type the project's key to confirm deleting it".into(),
        ));
    }
    let actor = caller.name();
    let mut tx = state.pool.begin().await?;
    lock_key(&mut tx, &key).await?;
    let (id, name): (i64, Option<String>) =
        sqlx::query_as("SELECT id, name FROM projects WHERE key = $1")
            .bind(&key)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(ApiError::NotFound)?;
    let analyses: i64 = sqlx::query_scalar("SELECT count(*) FROM analyses WHERE project_id = $1")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    let contents: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT DISTINCT f.sha256 FROM analysis_files f JOIN analyses a ON a.id = f.analysis_id
         WHERE a.project_id = $1",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE api_tokens SET revoked_at = now(), revoked_by = $2
         WHERE type = 'project_analysis' AND project_key = $1 AND revoked_at IS NULL",
    )
    .bind(&key)
    .bind(&actor)
    .execute(&mut *tx)
    .await?;
    let row: DeletedRow = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "INSERT INTO deleted_projects (key, name, analyses, deleted_by) VALUES ($1, $2, $3, $4)
         RETURNING {COLUMNS}"
    )))
    .bind(&key)
    .bind(&name)
    .bind(analyses)
    .bind(&actor)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM projects WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    // Contents another project's analysis also has stay. Lock them first,
    // so an upload now referencing one waits, and the check after sees it.
    sqlx::query("SELECT 1 FROM sources WHERE sha256 = ANY($1) FOR UPDATE")
        .bind(&contents)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "DELETE FROM sources s WHERE s.sha256 = ANY($1)
           AND NOT EXISTS (SELECT 1 FROM analysis_files f WHERE f.sha256 = s.sha256)",
    )
    .bind(&contents)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    tracing::info!(project = %key, by = %actor, analyses, "deleted project");
    Ok(Json(deleted(row)))
}

/// `GET /api/deleted-projects`, admins only: newest first.
pub async fn list(
    axum::extract::State(state): axum::extract::State<State>,
) -> Result<Json<Vec<Deleted>>, ApiError> {
    let rows: Vec<DeletedRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM deleted_projects ORDER BY id DESC"
    )))
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(rows.into_iter().map(deleted).collect()))
}

/// `POST /api/deleted-projects/{id}/allow`, admins only: uploads to the key
/// work again, and the next one starts a new project.
pub async fn allow(
    axum::extract::State(state): axum::extract::State<State>,
    Extension(caller): Extension<Caller>,
    Path(id): Path<i64>,
) -> Result<Json<Deleted>, ApiError> {
    let row: Option<DeletedRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "UPDATE deleted_projects SET allowed_by = $2, allowed_at = now()
         WHERE id = $1 AND allowed_at IS NULL RETURNING {COLUMNS}"
    )))
    .bind(id)
    .bind(caller.name())
    .fetch_optional(&state.pool)
    .await?;
    if let Some(row) = row {
        return Ok(Json(deleted(row)));
    }
    // Already allowed: nothing to do.
    let row: DeletedRow = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM deleted_projects WHERE id = $1"
    )))
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    Ok(Json(deleted(row)))
}
