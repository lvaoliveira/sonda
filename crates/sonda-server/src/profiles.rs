//! Rule profiles (ADR-0018): named sets of rule settings, one of them the
//! default, that `sonda scan --upload` downloads and applies.

use crate::api::{ApiError, Caller};
use crate::http::State;
use crate::rule_settings::{
    Change, checked_note, checked_rule, load_profiles, project_id, project_settings, recount,
};
use axum::Json;
use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{PgPool, Postgres, Transaction};

const SEVERITIES: &[&str] = &["info", "minor", "major", "critical", "blocker"];

/// A profile as lists show it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileSummary {
    pub id: i64,
    pub name: String,
    /// "sonda way": the catalog's defaults, read-only.
    pub builtin: bool,
    pub is_default: bool,
    /// Rules it sets.
    pub rules: usize,
    /// Projects using it, by choice or as the default.
    pub projects: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileRuleView {
    pub rule: String,
    pub name: Option<&'static str>,
    pub on: bool,
    pub severity: Option<String>,
    pub change: Change,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileDetail {
    #[serde(flatten)]
    pub summary: ProfileSummary,
    /// Sorted by rule id.
    pub rules_set: Vec<ProfileRuleView>,
}

/// Project keys by the profile they use.
async fn users_of(pool: &PgPool) -> Result<Vec<(String, i64)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT p.key, coalesce(p.rule_profile_id, (SELECT id FROM rule_profiles WHERE is_default))
         FROM projects p ORDER BY p.key",
    )
    .fetch_all(pool)
    .await
}

/// `GET /api/rule-profiles`: every profile, the default first.
pub async fn list(
    axum::extract::State(state): axum::extract::State<State>,
) -> Result<Json<Vec<ProfileSummary>>, ApiError> {
    let profiles = load_profiles(&state.pool).await?;
    let users = users_of(&state.pool).await?;
    let mut list: Vec<ProfileSummary> = profiles
        .by_id
        .iter()
        .map(|(&id, p)| ProfileSummary {
            id,
            name: p.name.clone(),
            builtin: p.builtin,
            is_default: p.is_default,
            rules: p.rules.len(),
            projects: users
                .iter()
                .filter(|(_, u)| *u == id)
                .map(|(k, _)| k.clone())
                .collect(),
        })
        .collect();
    list.sort_by(|a, b| b.is_default.cmp(&a.is_default).then(a.name.cmp(&b.name)));
    Ok(Json(list))
}

/// `GET /api/rule-profiles/{id}`: one profile and the rules it sets.
pub async fn get(
    axum::extract::State(state): axum::extract::State<State>,
    Path(id): Path<i64>,
) -> Result<Json<ProfileDetail>, ApiError> {
    let profiles = load_profiles(&state.pool).await?;
    let p = profiles.by_id.get(&id).ok_or(ApiError::NotFound)?;
    let users = users_of(&state.pool).await?;
    let mut rules_set: Vec<ProfileRuleView> = p
        .rules
        .iter()
        .map(|(rule, r)| ProfileRuleView {
            rule: rule.clone(),
            name: crate::rule_settings::find(rule).map(|r| r.name),
            on: r.on,
            severity: r.severity.clone(),
            change: r.change.clone(),
        })
        .collect();
    rules_set.sort_by(|a, b| a.rule.cmp(&b.rule));
    Ok(Json(ProfileDetail {
        summary: ProfileSummary {
            id,
            name: p.name.clone(),
            builtin: p.builtin,
            is_default: p.is_default,
            rules: p.rules.len(),
            projects: users
                .iter()
                .filter(|(_, u)| *u == id)
                .map(|(k, _)| k.clone())
                .collect(),
        },
        rules_set,
    }))
}

fn checked_name(name: &str) -> Result<&str, ApiError> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 100 || name.chars().any(char::is_control) {
        return Err(ApiError::Unprocessable(
            "a profile's name has 1-100 characters".into(),
        ));
    }
    Ok(name)
}

/// Creates a profile, empty or as a copy of `from`'s rules.
pub(crate) async fn create(
    tx: &mut Transaction<'_, Postgres>,
    name: &str,
    from: Option<i64>,
    by: &str,
) -> Result<i64, ApiError> {
    let id: Option<i64> = sqlx::query_scalar(
        "INSERT INTO rule_profiles (name, changed_by) VALUES ($1, $2)
         ON CONFLICT (name) DO NOTHING RETURNING id",
    )
    .bind(name)
    .bind(by)
    .fetch_optional(&mut **tx)
    .await?;
    let id =
        id.ok_or_else(|| ApiError::Unprocessable(format!("a profile named {name:?} exists")))?;
    if let Some(from) = from {
        sqlx::query(
            "INSERT INTO rule_profile_rules (profile_id, rule, enabled, severity, note, changed_by, changed_at)
             SELECT $1, rule, enabled, severity, note, changed_by, changed_at
             FROM rule_profile_rules WHERE profile_id = $2",
        )
        .bind(id)
        .bind(from)
        .execute(&mut **tx)
        .await?;
    }
    Ok(id)
}

/// Makes `id` the default profile.
pub(crate) async fn make_default(
    tx: &mut Transaction<'_, Postgres>,
    id: i64,
) -> Result<(), sqlx::Error> {
    // Two steps: the unique index allows one default at any moment.
    sqlx::query("UPDATE rule_profiles SET is_default = false WHERE is_default AND id <> $1")
        .bind(id)
        .execute(&mut **tx)
        .await?;
    sqlx::query("UPDATE rule_profiles SET is_default = true WHERE id = $1")
        .bind(id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Sets `rule` in profile `id`: `on` Some(on/off), or None to remove it.
pub(crate) async fn set_rule(
    tx: &mut Transaction<'_, Postgres>,
    id: i64,
    rule: &str,
    on: Option<bool>,
    severity: Option<&str>,
    note: Option<&str>,
    by: &str,
) -> Result<(), sqlx::Error> {
    match on {
        Some(on) => {
            sqlx::query(
                "INSERT INTO rule_profile_rules (profile_id, rule, enabled, severity, note, changed_by)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (profile_id, rule) DO UPDATE
                 SET enabled = EXCLUDED.enabled, severity = EXCLUDED.severity,
                     note = EXCLUDED.note, changed_by = EXCLUDED.changed_by, changed_at = now()",
            )
            .bind(id)
            .bind(rule)
            .bind(on)
            .bind(severity)
            .bind(note)
            .bind(by)
            .execute(&mut **tx)
            .await?;
        }
        None => {
            sqlx::query("DELETE FROM rule_profile_rules WHERE profile_id = $1 AND rule = $2")
                .bind(id)
                .bind(rule)
                .execute(&mut **tx)
                .await?;
        }
    }
    sqlx::query(
        "UPDATE rule_profiles SET revision = revision + 1, changed_by = $2, changed_at = now()
         WHERE id = $1",
    )
    .bind(id)
    .bind(by)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// The projects using profile `id`, by choice or as the default.
async fn projects_using(pool: &PgPool, id: i64) -> Result<Vec<i64>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT p.id FROM projects p
         WHERE coalesce(p.rule_profile_id, (SELECT d.id FROM rule_profiles d WHERE d.is_default)) = $1",
    )
    .bind(id)
    .fetch_all(pool)
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NewProfile {
    name: String,
    /// A profile whose rules to copy.
    #[serde(default)]
    copy_from: Option<i64>,
}

/// `POST /api/rule-profiles`: admins create a profile, empty or as a copy.
pub async fn post(
    axum::extract::State(state): axum::extract::State<State>,
    Extension(caller): Extension<Caller>,
    Json(new): Json<NewProfile>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let name = checked_name(&new.name)?;
    let by = caller.name();
    let mut tx = state.pool.begin().await?;
    if let Some(from) = new.copy_from {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM rule_profiles WHERE id = $1)")
                .bind(from)
                .fetch_one(&mut *tx)
                .await?;
        if !exists {
            return Err(ApiError::Unprocessable(format!(
                "no profile {from} to copy"
            )));
        }
    }
    let id = create(&mut tx, name, new.copy_from, &by).await?;
    tx.commit().await?;
    tracing::info!(by, id, name, "created a rule profile");
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "id": id, "name": name })),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProfilePatch {
    #[serde(default)]
    name: Option<String>,
    /// `true` makes it the default.
    #[serde(default)]
    is_default: Option<bool>,
}

/// `PATCH /api/rule-profiles/{id}`: admins rename a profile or make it the
/// default.
pub async fn patch(
    axum::extract::State(state): axum::extract::State<State>,
    Extension(caller): Extension<Caller>,
    Path(id): Path<i64>,
    Json(patch): Json<ProfilePatch>,
) -> Result<Json<Value>, ApiError> {
    let by = caller.name();
    let mut tx = state.pool.begin().await?;
    let builtin: Option<bool> =
        sqlx::query_scalar("SELECT builtin FROM rule_profiles WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    let builtin = builtin.ok_or(ApiError::NotFound)?;
    if let Some(name) = &patch.name {
        if builtin {
            return Err(ApiError::Unprocessable("sonda way can't be renamed".into()));
        }
        let name = checked_name(name)?;
        let renamed = sqlx::query(
            "UPDATE rule_profiles SET name = $2, changed_by = $3, changed_at = now() WHERE id = $1",
        )
        .bind(id)
        .bind(name)
        .bind(&by)
        .execute(&mut *tx)
        .await;
        match renamed {
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                return Err(ApiError::Unprocessable(format!(
                    "a profile named {name:?} exists"
                )));
            }
            r => {
                r?;
            }
        }
    }
    let became_default = match patch.is_default {
        Some(true) => {
            make_default(&mut tx, id).await?;
            true
        }
        Some(false) => {
            return Err(ApiError::Unprocessable(
                "make another profile the default instead".into(),
            ));
        }
        None => false,
    };
    tx.commit().await?;
    tracing::info!(by, id, "changed a rule profile");
    if became_default {
        // Projects without a choice now use it.
        recount(&state.pool, None).await?;
    }
    Ok(Json(serde_json::json!({ "id": id })))
}

/// `DELETE /api/rule-profiles/{id}`: admins delete a profile no project
/// uses, other than the default and "sonda way".
pub async fn delete(
    axum::extract::State(state): axum::extract::State<State>,
    Extension(caller): Extension<Caller>,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let row: Option<(bool, bool)> =
        sqlx::query_as("SELECT builtin, is_default FROM rule_profiles WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.pool)
            .await?;
    let (builtin, is_default) = row.ok_or(ApiError::NotFound)?;
    if builtin || is_default {
        return Err(ApiError::Unprocessable(
            "sonda way and the default profile can't be deleted".into(),
        ));
    }
    let users: Vec<String> =
        sqlx::query_scalar("SELECT key FROM projects WHERE rule_profile_id = $1 ORDER BY key")
            .bind(id)
            .fetch_all(&state.pool)
            .await?;
    if !users.is_empty() {
        return Err(ApiError::Unprocessable(format!(
            "projects use this profile: {}",
            users.join(", ")
        )));
    }
    sqlx::query("DELETE FROM rule_profiles WHERE id = $1")
        .bind(id)
        .execute(&state.pool)
        .await?;
    tracing::info!(by = caller.name(), id, "deleted a rule profile");
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulePatch {
    rule: String,
    /// `on`, `off`, or `inherit` to leave the rule at its catalog default.
    state: String,
    /// A severity for the rule; null keeps the catalog's.
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    note: Option<String>,
}

/// `PUT /api/rule-profiles/{id}/rules`: admins set a rule in a profile.
pub async fn put_rule(
    axum::extract::State(state): axum::extract::State<State>,
    Extension(caller): Extension<Caller>,
    Path(id): Path<i64>,
    Json(patch): Json<RulePatch>,
) -> Result<Json<Value>, ApiError> {
    let rule = checked_rule(&patch.rule)?;
    let note = checked_note(patch.note)?;
    let on = match patch.state.as_str() {
        "on" => Some(true),
        "off" => Some(false),
        "inherit" => None,
        _ => {
            return Err(ApiError::Unprocessable(
                "state is on, off or inherit".into(),
            ));
        }
    };
    if let Some(s) = &patch.severity
        && !SEVERITIES.contains(&s.as_str())
    {
        return Err(ApiError::Unprocessable(
            "severity is info, minor, major, critical or blocker".into(),
        ));
    }
    let by = caller.name();
    let mut tx = state.pool.begin().await?;
    let builtin: Option<bool> =
        sqlx::query_scalar("SELECT builtin FROM rule_profiles WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    if builtin.ok_or(ApiError::NotFound)? {
        return Err(ApiError::Unprocessable(
            "sonda way is the catalog's defaults and can't change; copy it".into(),
        ));
    }
    set_rule(
        &mut tx,
        id,
        rule.id,
        on,
        patch.severity.as_deref(),
        note.as_deref(),
        &by,
    )
    .await?;
    tx.commit().await?;
    tracing::info!(
        by,
        id,
        rule = rule.id,
        state = patch.state,
        "changed a rule in a profile"
    );
    let users = projects_using(&state.pool, id).await?;
    recount(&state.pool, Some(&users)).await?;
    Ok(Json(serde_json::json!({ "id": id, "rule": rule.id })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectProfile {
    /// A profile id, or null for the default.
    profile: Option<i64>,
}

/// `PUT /api/projects/{key}/rule-profile`: admins choose the profile a
/// project uses, or null for the default.
pub async fn put_project(
    axum::extract::State(state): axum::extract::State<State>,
    Extension(caller): Extension<Caller>,
    Path(key): Path<String>,
    Json(choice): Json<ProjectProfile>,
) -> Result<Json<Value>, ApiError> {
    let (project, _) = project_id(&state.pool, &key).await?;
    if let Some(id) = choice.profile {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM rule_profiles WHERE id = $1)")
                .bind(id)
                .fetch_one(&state.pool)
                .await?;
        if !exists {
            return Err(ApiError::Unprocessable(format!("no profile {id}")));
        }
    }
    sqlx::query("UPDATE projects SET rule_profile_id = $2 WHERE id = $1")
        .bind(project)
        .bind(choice.profile)
        .execute(&state.pool)
        .await?;
    tracing::info!(by = caller.name(), project = key, profile = ?choice.profile, "chose a rule profile");
    recount(&state.pool, Some(&[project])).await?;
    Ok(Json(
        serde_json::json!({ "project": key, "profile": choice.profile }),
    ))
}

/// What `sonda scan --upload` applies: one rule's server setting.
#[derive(Serialize)]
pub struct EffectiveRule {
    pub rule: String,
    pub on: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
}

#[derive(Serialize)]
pub struct Effective {
    /// The profile's name, for the scan's output and its report.
    pub profile: String,
    /// What the scan records as applied, compared later with the current.
    pub revision: String,
    /// Sorted by rule id.
    pub rules: Vec<EffectiveRule>,
}

/// `GET /api/projects/{key}/rule-profile`: the rule settings a scan of the
/// project applies (ADR-0018): its profile with its own adjustments on top.
/// A project that doesn't exist yet gets the default profile's. Analysis
/// tokens may read it, for their project only.
pub async fn get_effective(
    axum::extract::State(state): axum::extract::State<State>,
    Extension(caller): Extension<Caller>,
    Path(key): Path<String>,
) -> Result<Json<Effective>, ApiError> {
    if let Caller::UserToken(_, t) = &caller
        && t.project.as_deref().is_some_and(|p| p != key)
    {
        return Err(ApiError::Forbidden(format!(
            "this token reads project {:?}'s settings only",
            t.project.as_deref().unwrap_or_default()
        )));
    }
    let pool = &state.pool;
    let project: Option<i64> = sqlx::query_scalar("SELECT id FROM projects WHERE key = $1")
        .bind(&key)
        .fetch_optional(pool)
        .await?;
    let profiles = load_profiles(pool).await?;
    let profile = &profiles.by_id[&profiles.of(project)];
    let own = match project {
        Some(p) => project_settings(pool).await?.remove(&p).unwrap_or_default(),
        None => Default::default(),
    };
    let mut rules: std::collections::BTreeMap<String, EffectiveRule> = profile
        .rules
        .iter()
        .map(|(rule, r)| {
            (
                rule.clone(),
                EffectiveRule {
                    rule: rule.clone(),
                    on: r.on,
                    severity: r.severity.clone(),
                },
            )
        })
        .collect();
    for (rule, (on, _)) in own {
        rules
            .entry(rule.clone())
            .and_modify(|r| r.on = on)
            .or_insert(EffectiveRule {
                rule,
                on,
                severity: None,
            });
    }
    Ok(Json(Effective {
        profile: profile.name.clone(),
        revision: profiles.revision(project),
        rules: rules.into_values().collect(),
    }))
}
