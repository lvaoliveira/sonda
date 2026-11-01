//! Rule settings on the server (ADR-0016): admins turn a rule off for every
//! project or for one, and every screen shows each rule's state with what
//! set it, the repository's `sonda.toml` included.
//!
//! The server never runs rules. A rule that's off keeps its findings
//! stored, and `rule_off()` (migration 0019) leaves them out of every list,
//! measure and gate; changing a setting recounts the latest analyses.

use crate::api::{ApiError, Caller};
use crate::health::rfc3339;
use crate::http::State;
use axum::Json;
use axum::extract::{Extension, Path};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sonda_core::rules::{RULES, Rule};
use sqlx::PgPool;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Who changed a setting, when, and why.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Change {
    pub note: Option<String>,
    pub changed_by: String,
    pub changed_at: String,
}

/// The repository's `[rules]`, as an analysis recorded them.
#[derive(Deserialize, Default)]
struct Toml {
    #[serde(default)]
    disabled: BTreeSet<String>,
    #[serde(default)]
    enabled: BTreeSet<String>,
    #[serde(default)]
    severity: BTreeMap<String, String>,
}

/// What a rule's state comes from.
#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum SetBy {
    /// The catalog: on, or off by default.
    Default,
    /// The repository's `sonda.toml`.
    SondaToml,
    /// The server, for every project.
    Server,
    /// The server, for this project.
    Project,
}

/// One rule's state for a project, and what decided it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleState {
    pub rule: &'static str,
    pub name: &'static str,
    pub on: bool,
    pub set_by: SetBy,
    /// The note, author and time of the server setting that decided it.
    pub change: Option<Change>,
    /// The severity `sonda.toml` gives it, when it changes the default.
    pub severity: Option<String>,
    /// The server says on, but the scanner never runs it: `sonda.toml`
    /// (or the catalog default) turns it off, so nothing reaches the server.
    pub conflict: bool,
    /// Open findings on the main branch that the server leaves out.
    pub hidden_issues: i64,
    /// This project's own server setting, if any: `on` or `off`.
    pub project_setting: Option<&'static str>,
}

/// A change of the repository's settings between two analyses.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TomlChange {
    pub analysis_id: i64,
    pub sha: String,
    pub at: String,
    pub rule: String,
    /// `disabled`, `re-enabled` (no longer disabled), `enabled` (an
    /// off-by-default rule turned on), `unset` (no longer enabled) or
    /// `severity`.
    pub change: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectRules {
    pub project: String,
    pub main_branch: String,
    /// `sonda.toml`'s `[rules]` in the main branch's latest analysis; null
    /// when that analysis came from a sonda that didn't send them, or there
    /// is none.
    pub sonda_toml: Option<Value>,
    /// Every rule whose state differs from its default for this project,
    /// or that has a server setting, sorted by rule id.
    pub rules: Vec<RuleState>,
    /// When the repository's settings changed, newest first.
    pub toml_changes: Vec<TomlChange>,
}

fn find(id: &str) -> Option<&'static Rule> {
    RULES.iter().copied().find(|r| r.id == id)
}

/// The state of `rule` given the repository's settings (`None`: unknown),
/// the global server setting and the project's.
fn rule_state(
    rule: &Rule,
    toml: Option<&Toml>,
    global: Option<&Change>,
    project: Option<&(bool, Change)>,
) -> (bool, SetBy, Option<Change>, bool) {
    let (scanner_on, scanner_by) = match toml {
        Some(t) if t.disabled.contains(rule.id) => (false, SetBy::SondaToml),
        Some(t) if t.enabled.contains(rule.id) => (true, SetBy::SondaToml),
        _ => (rule.on_by_default(), SetBy::Default),
    };
    let server = match (project, global) {
        (Some((on, c)), _) => Some((*on, SetBy::Project, c.clone())),
        (None, Some(c)) => Some((false, SetBy::Server, c.clone())),
        (None, None) => None,
    };
    match server {
        // Nothing reaches the server, whatever it says.
        _ if !scanner_on => {
            let conflict = matches!(server, Some((true, ..)));
            (false, scanner_by, server.map(|s| s.2), conflict)
        }
        Some((false, by, c)) => (false, by, Some(c), false),
        Some((true, by, c)) => (true, by, Some(c), false),
        None => (true, scanner_by, None, false),
    }
}

async fn project_id(pool: &PgPool, key: &str) -> Result<(i64, String), ApiError> {
    let row: Option<(i64, Option<String>)> =
        sqlx::query_as("SELECT id, main_branch FROM projects WHERE key = $1")
            .bind(key)
            .fetch_optional(pool)
            .await?;
    let (id, main) = row.ok_or(ApiError::NotFound)?;
    Ok((id, main.unwrap_or_default()))
}

async fn global_settings(pool: &PgPool) -> Result<HashMap<String, Change>, sqlx::Error> {
    let rows: Vec<(String, Option<String>, String, f64)> = sqlx::query_as(
        "SELECT rule, note, changed_by, extract(epoch FROM changed_at)::float8 FROM rule_settings",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(rule, note, by, at)| {
            (
                rule,
                Change {
                    note,
                    changed_by: by,
                    changed_at: rfc3339(at),
                },
            )
        })
        .collect())
}

/// Every project's own settings: project id → rule → (on, change).
type ProjectSettings = HashMap<i64, HashMap<String, (bool, Change)>>;

async fn project_settings(pool: &PgPool) -> Result<ProjectSettings, sqlx::Error> {
    let rows: Vec<(i64, String, bool, Option<String>, String, f64)> = sqlx::query_as(
        "SELECT project_id, rule, enabled, note, changed_by, extract(epoch FROM changed_at)::float8
         FROM project_rule_settings",
    )
    .fetch_all(pool)
    .await?;
    let mut map: ProjectSettings = HashMap::new();
    for (project, rule, on, note, by, at) in rows {
        let change = Change {
            note,
            changed_by: by,
            changed_at: rfc3339(at),
        };
        map.entry(project).or_default().insert(rule, (on, change));
    }
    Ok(map)
}

/// Each project's `sonda.toml` settings from its main branch's latest
/// analysis; `None` when unknown.
async fn latest_toml(pool: &PgPool) -> Result<HashMap<i64, Option<Toml>>, sqlx::Error> {
    let rows: Vec<(i64, Option<Value>)> = sqlx::query_as(
        "SELECT DISTINCT ON (a.project_id) a.project_id, a.rule_settings
         FROM analyses a JOIN projects p ON p.id = a.project_id AND a.branch = p.main_branch
         ORDER BY a.project_id, a.id DESC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(p, v)| (p, v.and_then(|v| serde_json::from_value(v).ok())))
        .collect())
}

/// `GET /api/projects/{key}/rule-settings`: every rule whose state differs
/// from its default for the project, with what set it.
pub async fn get_project(
    axum::extract::State(state): axum::extract::State<State>,
    Path(key): Path<String>,
) -> Result<Json<ProjectRules>, ApiError> {
    let pool = &state.pool;
    let (project, main_branch) = project_id(pool, &key).await?;
    let global = global_settings(pool).await?;
    let own = project_settings(pool)
        .await?
        .remove(&project)
        .unwrap_or_default();
    // The main branch's analyses with their settings, oldest first.
    let history: Vec<(i64, String, f64, Option<Value>)> = sqlx::query_as(
        "SELECT id, commit_sha, extract(epoch FROM received_at)::float8, rule_settings
         FROM analyses WHERE project_id = $1 AND branch = $2 ORDER BY id",
    )
    .bind(project)
    .bind(&main_branch)
    .fetch_all(pool)
    .await?;
    let sonda_toml = history.last().and_then(|h| h.3.clone());
    let toml: Option<Toml> = sonda_toml
        .clone()
        .and_then(|v| serde_json::from_value(v).ok());
    let hidden: HashMap<String, i64> = sqlx::query_as(
        "SELECT rule, count(*) FROM issues
         WHERE project_id = $1 AND branch = $2 AND fixed_analysis_id IS NULL
           AND status IN ('open', 'confirmed') AND rule_off(project_id, rule)
         GROUP BY rule",
    )
    .bind(project)
    .bind(&main_branch)
    .fetch_all(pool)
    .await?
    .into_iter()
    .collect();

    let rules = RULES
        .iter()
        .filter_map(|r| {
            let own_setting = own.get(r.id);
            let (on, set_by, change, conflict) =
                rule_state(r, toml.as_ref(), global.get(r.id), own_setting);
            let severity = toml
                .as_ref()
                .and_then(|t| t.severity.get(r.id).cloned())
                .filter(|s| s != r.severity.as_str());
            let differs = set_by != SetBy::Default || own_setting.is_some() || conflict;
            (differs || severity.is_some() || global.contains_key(r.id)).then(|| RuleState {
                rule: r.id,
                name: r.name,
                on,
                set_by,
                change,
                severity,
                conflict,
                hidden_issues: hidden.get(r.id).copied().unwrap_or(0),
                project_setting: own_setting.map(|(on, _)| if *on { "on" } else { "off" }),
            })
        })
        .collect();

    // Changes between consecutive analyses that recorded settings, grouped
    // by analysis so the newest analysis comes first, each in rule order.
    let mut by_analysis: Vec<Vec<TomlChange>> = Vec::new();
    let mut previous: Option<Toml> = None;
    for (id, sha, at, value) in &history {
        let Some(t) = value
            .clone()
            .and_then(|v| serde_json::from_value::<Toml>(v).ok())
        else {
            continue;
        };
        if let Some(p) = &previous {
            let mut changes = Vec::new();
            let mut push = |rule: &str, change: &'static str| {
                changes.push(TomlChange {
                    analysis_id: *id,
                    sha: sha.clone(),
                    at: rfc3339(*at),
                    rule: rule.to_string(),
                    change,
                });
            };
            for r in t.disabled.difference(&p.disabled) {
                push(r, "disabled");
            }
            for r in p.disabled.difference(&t.disabled) {
                push(r, "re-enabled");
            }
            for r in t.enabled.difference(&p.enabled) {
                push(r, "enabled");
            }
            for r in p.enabled.difference(&t.enabled) {
                push(r, "unset");
            }
            let rules: BTreeSet<&String> = t.severity.keys().chain(p.severity.keys()).collect();
            for r in rules {
                if t.severity.get(r) != p.severity.get(r) {
                    push(r, "severity");
                }
            }
            by_analysis.push(changes);
        }
        previous = Some(t);
    }
    let toml_changes = by_analysis.into_iter().rev().flatten().collect();
    Ok(Json(ProjectRules {
        project: key,
        main_branch,
        sonda_toml,
        rules,
        toml_changes,
    }))
}

/// For the Rules page: in how many projects each rule is off, by what
/// turned it off. Only rules off somewhere are listed.
pub(crate) async fn off_counts(
    pool: &PgPool,
) -> Result<(HashMap<String, Change>, HashMap<&'static str, OffIn>), sqlx::Error> {
    let global = global_settings(pool).await?;
    let own = project_settings(pool).await?;
    let tomls = latest_toml(pool).await?;
    let projects: Vec<i64> = sqlx::query_scalar("SELECT id FROM projects")
        .fetch_all(pool)
        .await?;
    let mut counts: HashMap<&'static str, OffIn> = HashMap::new();
    let none = HashMap::new();
    for p in projects {
        let toml = tomls.get(&p).and_then(Option::as_ref);
        let mine = own.get(&p).unwrap_or(&none);
        for r in RULES.iter() {
            let (on, set_by, ..) = rule_state(r, toml, global.get(r.id), mine.get(r.id));
            if on {
                continue;
            }
            let entry = counts.entry(r.id).or_default();
            match set_by {
                SetBy::SondaToml => entry.sonda_toml += 1,
                SetBy::Server | SetBy::Project => entry.server += 1,
                SetBy::Default => {}
            }
        }
    }
    counts.retain(|_, c| c.sonda_toml + c.server > 0);
    Ok((global, counts))
}

#[derive(Serialize, Default, Clone, Copy)]
#[serde(rename_all = "camelCase")]
pub struct OffIn {
    pub sonda_toml: usize,
    pub server: usize,
}

fn checked_note(note: Option<String>) -> Result<Option<String>, ApiError> {
    let note = note.map(|n| n.trim().to_string()).filter(|n| !n.is_empty());
    if note
        .as_ref()
        .is_some_and(|n| n.chars().count() > 500 || n.chars().any(|c| c.is_control() && c != '\n'))
    {
        return Err(ApiError::Unprocessable(
            "a note has at most 500 characters".into(),
        ));
    }
    Ok(note)
}

fn checked_rule(rule: &str) -> Result<&'static Rule, ApiError> {
    find(rule).ok_or_else(|| {
        ApiError::Unprocessable(format!("unknown rule {rule:?} (see GET /api/rules)"))
    })
}

/// Recounts the latest analysis of every branch of `project`, or of every
/// project.
async fn recount(pool: &PgPool, project: Option<i64>) -> Result<(), sqlx::Error> {
    let branches: Vec<(i64, String)> = sqlx::query_as(
        "SELECT DISTINCT project_id, branch FROM analyses
         WHERE $1::bigint IS NULL OR project_id = $1",
    )
    .bind(project)
    .fetch_all(pool)
    .await?;
    for (p, branch) in branches {
        crate::new_code::recount(pool, p, &branch).await?;
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GlobalPatch {
    rule: String,
    /// True turns the rule off for every project; false turns it back on.
    off: bool,
    #[serde(default)]
    note: Option<String>,
}

/// `PUT /api/rule-settings`: admins turn a rule off, or back on, for every
/// project that doesn't set it itself.
pub async fn put_global(
    axum::extract::State(state): axum::extract::State<State>,
    Extension(caller): Extension<Caller>,
    Json(patch): Json<GlobalPatch>,
) -> Result<Json<Value>, ApiError> {
    let rule = checked_rule(&patch.rule)?;
    let note = checked_note(patch.note)?;
    let by = caller.name();
    if patch.off {
        sqlx::query(
            "INSERT INTO rule_settings (rule, note, changed_by) VALUES ($1, $2, $3)
             ON CONFLICT (rule) DO UPDATE
             SET note = EXCLUDED.note, changed_by = EXCLUDED.changed_by, changed_at = now()",
        )
        .bind(rule.id)
        .bind(&note)
        .bind(&by)
        .execute(&state.pool)
        .await?;
    } else {
        sqlx::query("DELETE FROM rule_settings WHERE rule = $1")
            .bind(rule.id)
            .execute(&state.pool)
            .await?;
    }
    tracing::info!(
        by,
        rule = rule.id,
        off = patch.off,
        "changed a global rule setting"
    );
    recount(&state.pool, None).await?;
    Ok(Json(
        serde_json::json!({ "rule": rule.id, "off": patch.off }),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectPatch {
    rule: String,
    /// `on`, `off`, or `inherit` to follow the global setting again.
    state: String,
    #[serde(default)]
    note: Option<String>,
}

/// `PUT /api/projects/{key}/rule-settings`: admins set a rule on or off for
/// one project, over the global setting, or make it follow that again.
pub async fn put_project(
    axum::extract::State(state): axum::extract::State<State>,
    Extension(caller): Extension<Caller>,
    Path(key): Path<String>,
    Json(patch): Json<ProjectPatch>,
) -> Result<Json<Value>, ApiError> {
    let rule = checked_rule(&patch.rule)?;
    let note = checked_note(patch.note)?;
    let (project, _) = project_id(&state.pool, &key).await?;
    let by = caller.name();
    let enabled = match patch.state.as_str() {
        "on" => Some(true),
        "off" => Some(false),
        "inherit" => None,
        _ => {
            return Err(ApiError::Unprocessable(
                "state is on, off or inherit".into(),
            ));
        }
    };
    match enabled {
        Some(on) => {
            sqlx::query(
                "INSERT INTO project_rule_settings (project_id, rule, enabled, note, changed_by)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (project_id, rule) DO UPDATE
                 SET enabled = EXCLUDED.enabled, note = EXCLUDED.note,
                     changed_by = EXCLUDED.changed_by, changed_at = now()",
            )
            .bind(project)
            .bind(rule.id)
            .bind(on)
            .bind(&note)
            .bind(&by)
            .execute(&state.pool)
            .await?;
        }
        None => {
            sqlx::query("DELETE FROM project_rule_settings WHERE project_id = $1 AND rule = $2")
                .bind(project)
                .bind(rule.id)
                .execute(&state.pool)
                .await?;
        }
    }
    tracing::info!(
        by,
        project = key,
        rule = rule.id,
        state = patch.state,
        "changed a project rule setting"
    );
    recount(&state.pool, Some(project)).await?;
    Ok(Json(
        serde_json::json!({ "project": key, "rule": rule.id, "state": patch.state }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn change() -> Change {
        Change {
            note: None,
            changed_by: "ada".into(),
            changed_at: "2026-11-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn states_say_what_decided_them() {
        let rule = find("js/no-var").unwrap();
        let toml_off = Toml {
            disabled: ["js/no-var".to_string()].into(),
            ..Default::default()
        };
        let c = change();
        let on = (true, change());
        let off = (false, change());
        // Default, repository, global, project.
        let s = rule_state(rule, None, None, None);
        assert_eq!((s.0, s.1), (true, SetBy::Default));
        let s = rule_state(rule, Some(&toml_off), None, None);
        assert_eq!((s.0, s.1, s.3), (false, SetBy::SondaToml, false));
        let s = rule_state(rule, None, Some(&c), None);
        assert_eq!((s.0, s.1), (false, SetBy::Server));
        // A project's setting wins over the global one.
        let s = rule_state(rule, None, Some(&c), Some(&on));
        assert_eq!((s.0, s.1), (true, SetBy::Project));
        let s = rule_state(rule, None, None, Some(&off));
        assert_eq!((s.0, s.1), (false, SetBy::Project));
        // The server can't turn on what the scanner never ran.
        let s = rule_state(rule, Some(&toml_off), None, Some(&on));
        assert_eq!((s.0, s.1, s.3), (false, SetBy::SondaToml, true));
        // An off-by-default rule turned on in sonda.toml.
        let prefer = find("js/prefer-const").unwrap();
        assert!(!rule_state(prefer, None, None, None).0);
        let toml_on = Toml {
            enabled: ["js/prefer-const".to_string()].into(),
            ..Default::default()
        };
        let s = rule_state(prefer, Some(&toml_on), None, None);
        assert_eq!((s.0, s.1), (true, SetBy::SondaToml));
    }
}
