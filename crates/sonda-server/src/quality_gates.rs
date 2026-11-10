//! Quality gates on the server (ADR-0017): named sets of conditions, on
//! the same metrics and with the same rules as sonda.toml's
//! `[[gate.conditions]]`. A project that uses one is judged by it instead of
//! the gate its scans bring, on its latest analyses at once and on every
//! upload; the upload's answer carries it, so CI follows (ADR-0014).

use crate::api::{ApiError, Caller};
use crate::http::State;
use axum::Json;
use axum::extract::{Extension, Path};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sonda_core::model::Condition;
use sqlx::PgPool;

/// At most this many conditions in a gate.
const MAX_CONDITIONS: usize = 50;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewGate {
    name: String,
    /// As in sonda.toml: `metric`, `op` (`gt` or `lt`) and `threshold`.
    conditions: Vec<Condition>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Saved {
    pub id: i64,
    pub name: String,
    /// The projects whose latest analyses were judged again.
    pub projects: Vec<String>,
}

/// The name, trimmed, and the conditions as stored, or why not.
fn check(new: NewGate) -> Result<(String, Value), ApiError> {
    let name = new.name.trim().to_string();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(ApiError::Unprocessable(
            "a gate's name has 1-100 characters".into(),
        ));
    }
    if new.conditions.is_empty() || new.conditions.len() > MAX_CONDITIONS {
        return Err(ApiError::Unprocessable(format!(
            "a gate has 1-{MAX_CONDITIONS} conditions"
        )));
    }
    if let Some(c) = new.conditions.iter().find(|c| !c.threshold.is_finite()) {
        return Err(ApiError::Unprocessable(format!(
            "the threshold for {} must be a number",
            c.metric.as_str()
        )));
    }
    let conditions =
        serde_json::to_value(&new.conditions).map_err(|e| ApiError::Internal(e.into()))?;
    Ok((name, conditions))
}

fn name_taken(e: &sqlx::Error, name: &str) -> Option<ApiError> {
    e.as_database_error()
        .filter(|d| d.is_unique_violation())
        .map(|_| ApiError::Unprocessable(format!("a gate named {name:?} already exists")))
}

/// The keys of the projects using gate `id`, by key.
async fn projects_using(pool: &PgPool, id: i64) -> sqlx::Result<Vec<(i64, String)>> {
    sqlx::query_as("SELECT id, key FROM projects WHERE quality_gate_id = $1 ORDER BY key")
        .bind(id)
        .fetch_all(pool)
        .await
}

/// Judges the projects' latest analyses again, on every branch: after
/// their gate changed, or a gate they use did.
pub(crate) async fn rejudge(pool: &PgPool, projects: &[i64]) -> sqlx::Result<()> {
    if projects.is_empty() {
        return Ok(());
    }
    crate::rule_settings::recount(pool, Some(projects)).await?;
    for p in projects {
        crate::dependencies::refresh_gates(pool, crate::dependencies::GateScope::Project(*p))
            .await?;
    }
    Ok(())
}

/// The gate to evaluate for a project's analysis: its server gate's
/// conditions, marked with which gate it is, or the scan's own.
pub(crate) async fn gate_for<'e>(
    db: impl sqlx::PgExecutor<'e>,
    project: i64,
    scan_gate: Value,
) -> sqlx::Result<Value> {
    let server: Option<(i64, String, Value)> = sqlx::query_as(
        "SELECT g.id, g.name, g.conditions FROM projects p
         JOIN quality_gates g ON g.id = p.quality_gate_id WHERE p.id = $1",
    )
    .bind(project)
    .fetch_optional(db)
    .await?;
    let mut gate = if scan_gate.is_object() {
        scan_gate
    } else {
        json!({ "conditions": [] })
    };
    match server {
        Some((id, name, conditions)) => {
            gate["conditions"] = conditions;
            gate["server_gate"] = json!({ "id": id, "name": name });
        }
        None => {
            if let Some(o) = gate.as_object_mut() {
                o.remove("server_gate");
            }
        }
    }
    Ok(gate)
}

/// `POST /api/quality-gates`, admins only.
pub async fn post(
    axum::extract::State(state): axum::extract::State<State>,
    Extension(caller): Extension<Caller>,
    Json(new): Json<NewGate>,
) -> Result<Json<Saved>, ApiError> {
    let (name, conditions) = check(new)?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO quality_gates (name, conditions, changed_by) VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(&name)
    .bind(&conditions)
    .bind(caller.name())
    .fetch_one(&state.pool)
    .await
    .map_err(|e| name_taken(&e, &name).unwrap_or_else(|| e.into()))?;
    Ok(Json(Saved {
        id,
        name,
        projects: vec![],
    }))
}

/// `PUT /api/quality-gates/{id}`, admins only: its name and conditions,
/// which judge its projects' latest analyses again at once.
pub async fn put(
    axum::extract::State(state): axum::extract::State<State>,
    Extension(caller): Extension<Caller>,
    Path(id): Path<i64>,
    Json(new): Json<NewGate>,
) -> Result<Json<Saved>, ApiError> {
    let pool = &state.pool;
    let (name, conditions) = check(new)?;
    let updated = sqlx::query(
        "UPDATE quality_gates SET name = $2, conditions = $3, changed_by = $4, changed_at = now()
         WHERE id = $1",
    )
    .bind(id)
    .bind(&name)
    .bind(&conditions)
    .bind(caller.name())
    .execute(pool)
    .await
    .map_err(|e| name_taken(&e, &name).unwrap_or_else(|| e.into()))?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    let using = projects_using(pool, id).await?;
    rejudge(pool, &using.iter().map(|p| p.0).collect::<Vec<_>>()).await?;
    Ok(Json(Saved {
        id,
        name,
        projects: using.into_iter().map(|p| p.1).collect(),
    }))
}

/// `DELETE /api/quality-gates/{id}`, admins only; a gate a project uses
/// can't be deleted.
pub async fn delete(
    axum::extract::State(state): axum::extract::State<State>,
    Path(id): Path<i64>,
) -> Result<axum::http::StatusCode, ApiError> {
    let pool = &state.pool;
    let using = projects_using(pool, id).await?;
    if !using.is_empty() {
        let keys: Vec<String> = using.into_iter().map(|p| p.1).collect();
        return Err(ApiError::Unprocessable(format!(
            "projects use this gate: {}; choose another for them first",
            keys.join(", ")
        )));
    }
    let deleted = sqlx::query("DELETE FROM quality_gates WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await;
    match deleted {
        Ok(r) if r.rows_affected() == 0 => Err(ApiError::NotFound),
        Ok(_) => Ok(axum::http::StatusCode::NO_CONTENT),
        // A project chose it in the meantime.
        Err(e)
            if e.as_database_error()
                .is_some_and(|d| d.is_foreign_key_violation()) =>
        {
            Err(ApiError::Unprocessable(
                "a project uses this gate now; reload and try again".into(),
            ))
        }
        Err(e) => Err(e.into()),
    }
}
