//! Rule settings on the server: profiles (ADR-0018) and each project's own
//! adjustments (ADR-0016), and every rule's state per project with what set
//! it, the repository's `sonda.toml` included.
//!
//! `sonda scan --upload` applies the project's settings before scanning. For
//! findings already stored, `rule_off()` (migration 0020) leaves a rule
//! that's off out of every list, measure and gate; changing a setting
//! recounts the latest analyses.

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
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Change {
    pub note: Option<String>,
    pub changed_by: String,
    pub changed_at: String,
}

/// The repository's `[rules]`, as an analysis recorded them.
#[derive(Deserialize, Default)]
pub(crate) struct Toml {
    #[serde(default)]
    disabled: BTreeSet<String>,
    #[serde(default)]
    enabled: BTreeSet<String>,
    #[serde(default)]
    severity: BTreeMap<String, String>,
}

/// What a rule's state, or severity, comes from.
#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum SetBy {
    /// The catalog: on, or off by default.
    Default,
    /// The repository's `sonda.toml`.
    SondaToml,
    /// The project's rule profile (ADR-0018).
    Profile,
    /// The project's own adjustment, over its profile (ADR-0016).
    Project,
}

/// A profile's setting for one rule.
#[derive(Clone, Debug)]
pub(crate) struct ProfileRule {
    pub on: bool,
    pub severity: Option<String>,
    pub change: Change,
}

/// A profile: name, whether it's built in, revision, and its rules.
pub(crate) struct Profile {
    pub name: String,
    pub builtin: bool,
    pub is_default: bool,
    pub revision: i64,
    pub rules: HashMap<String, ProfileRule>,
}

/// Every profile, and which one each project uses.
pub(crate) struct Profiles {
    pub by_id: BTreeMap<i64, Profile>,
    pub default: i64,
    /// Project id → (the profile it chose, if any; its adjustments' revision).
    pub projects: HashMap<i64, (Option<i64>, i64)>,
}

impl Profiles {
    /// The profile `project` uses: its own choice, or the default.
    pub fn of(&self, project: Option<i64>) -> i64 {
        project
            .and_then(|p| self.projects.get(&p))
            .and_then(|(chosen, _)| *chosen)
            .unwrap_or(self.default)
    }

    /// What a scan records as applied: the profile, its revision, and the
    /// revision of the project's adjustments. An opaque string to clients.
    pub fn revision(&self, project: Option<i64>) -> String {
        let id = self.of(project);
        let own = project
            .and_then(|p| self.projects.get(&p))
            .map_or(0, |(_, r)| *r);
        format!("{id}.{}.{own}", self.by_id[&id].revision)
    }
}

/// (profile, rule, on, severity, note, changed by, changed at in epoch seconds).
type ProfileRuleRow = (
    i64,
    String,
    bool,
    Option<String>,
    Option<String>,
    String,
    f64,
);

pub(crate) async fn load_profiles(pool: &PgPool) -> Result<Profiles, sqlx::Error> {
    let heads: Vec<(i64, String, bool, bool, i64)> = sqlx::query_as(
        "SELECT id, name, builtin, is_default, revision FROM rule_profiles ORDER BY id",
    )
    .fetch_all(pool)
    .await?;
    let mut by_id: BTreeMap<i64, Profile> = heads
        .into_iter()
        .map(|(id, name, builtin, is_default, revision)| {
            (
                id,
                Profile {
                    name,
                    builtin,
                    is_default,
                    revision,
                    rules: HashMap::new(),
                },
            )
        })
        .collect();
    let rows: Vec<ProfileRuleRow> = sqlx::query_as(
        "SELECT profile_id, rule, enabled, severity, note, changed_by,
                    extract(epoch FROM changed_at)::float8
             FROM rule_profile_rules",
    )
    .fetch_all(pool)
    .await?;
    for (profile, rule, on, severity, note, by, at) in rows {
        if let Some(p) = by_id.get_mut(&profile) {
            let change = Change {
                note,
                changed_by: by,
                changed_at: rfc3339(at),
            };
            p.rules.insert(
                rule,
                ProfileRule {
                    on,
                    severity,
                    change,
                },
            );
        }
    }
    // Migration 0020 creates "sonda way" as the default, and the unique
    // index keeps exactly one.
    let default = by_id
        .iter()
        .find(|(_, p)| p.is_default)
        .map_or(0, |(id, _)| *id);
    let projects: HashMap<i64, (Option<i64>, i64)> = sqlx::query_as::<_, (i64, Option<i64>, i64)>(
        "SELECT id, rule_profile_id, rule_settings_revision FROM projects",
    )
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|(id, chosen, revision)| (id, (chosen, revision)))
    .collect();
    Ok(Profiles {
        by_id,
        default,
        projects,
    })
}

/// One rule's state for a project, and what decided it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleState {
    pub on: bool,
    pub set_by: SetBy,
    /// The note, author and time of the server setting that decided it.
    pub change: Option<Change>,
    /// Its severity when the profile or `sonda.toml` changes it.
    pub severity: Option<String>,
    /// What changed the severity: `profile` or `sonda_toml`.
    pub severity_by: Option<SetBy>,
    /// The server says on, but the latest scan didn't apply the server's
    /// settings and `sonda.toml` (or the catalog) leaves it off, so nothing
    /// reached the server.
    pub conflict: bool,
    /// This project's own adjustment, if any: `on` or `off`.
    pub project_setting: Option<&'static str>,
}

/// A rule for one project: the catalog's description, its state there, and
/// its findings on the main branch.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectRule {
    #[serde(flatten)]
    pub info: crate::rules::RuleInfo,
    pub state: RuleState,
    /// Open or confirmed findings that count.
    pub open_issues: i64,
    /// Open findings the server leaves out, since the rule is off.
    pub hidden_issues: i64,
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
pub struct ProfileRef {
    pub id: i64,
    pub name: String,
    /// Whether it's the default profile rather than the project's choice.
    pub is_default: bool,
    /// Whether the project chose it.
    pub chosen: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectRules {
    pub project: String,
    pub main_branch: String,
    /// The profile the project uses (ADR-0018).
    pub profile: ProfileRef,
    /// Whether the main branch's latest analysis applied the server's
    /// current settings; null without an analysis.
    pub profile_applied: Option<bool>,
    /// `sonda.toml`'s `[rules]` in the main branch's latest analysis; null
    /// when that analysis came from a sonda that didn't send them, or there
    /// is none.
    pub sonda_toml: Option<Value>,
    /// The languages of the main branch's latest analysis, as in reports.
    pub languages: Vec<String>,
    /// Every rule for those languages, in catalog order.
    pub rules: Vec<ProjectRule>,
    /// When the repository's settings changed, newest first.
    pub toml_changes: Vec<TomlChange>,
}

pub(crate) fn find(id: &str) -> Option<&'static Rule> {
    RULES.iter().copied().find(|r| r.id == id)
}

/// A rule's state for a project: on/off with what decided it and that
/// setting's change, its severity with what changed it, and whether it's a
/// conflict. Where the server sets a rule, the server wins (ADR-0018), then
/// the repository's `sonda.toml` (`None`: unknown), then the catalog.
/// `applied`: whether the latest scan applied the server's settings.
pub(crate) struct Decided {
    pub on: bool,
    pub set_by: SetBy,
    pub change: Option<Change>,
    pub severity: Option<(String, SetBy)>,
    pub conflict: bool,
}

pub(crate) fn rule_state(
    rule: &Rule,
    toml: Option<&Toml>,
    profile: Option<&ProfileRule>,
    project: Option<&(bool, Change)>,
    applied: bool,
) -> Decided {
    let (scanner_on, scanner_by) = match toml {
        Some(t) if t.disabled.contains(rule.id) => (false, SetBy::SondaToml),
        Some(t) if t.enabled.contains(rule.id) => (true, SetBy::SondaToml),
        _ => (rule.on_by_default(), SetBy::Default),
    };
    let server = match (project, profile) {
        (Some((on, c)), _) => Some((*on, SetBy::Project, c.clone())),
        (None, Some(p)) => Some((p.on, SetBy::Profile, p.change.clone())),
        (None, None) => None,
    };
    let severity = match (profile.and_then(|p| p.severity.clone()), toml) {
        (Some(s), _) => Some((s, SetBy::Profile)),
        (None, Some(t)) => t
            .severity
            .get(rule.id)
            .filter(|s| *s != rule.severity.as_str())
            .map(|s| (s.clone(), SetBy::SondaToml)),
        (None, None) => None,
    };
    match server {
        // A scan that applied the server's settings runs what they say; one
        // that didn't ran only what `sonda.toml` asked for.
        Some((true, _, c)) if !applied && !scanner_on => Decided {
            on: false,
            set_by: scanner_by,
            change: Some(c),
            severity,
            conflict: true,
        },
        Some((on, by, c)) => Decided {
            on,
            set_by: by,
            change: Some(c),
            severity,
            conflict: false,
        },
        None => Decided {
            on: scanner_on,
            set_by: scanner_by,
            change: None,
            severity,
            conflict: false,
        },
    }
}

pub(crate) async fn project_id(pool: &PgPool, key: &str) -> Result<(i64, String), ApiError> {
    let row: Option<(i64, Option<String>)> =
        sqlx::query_as("SELECT id, main_branch FROM projects WHERE key = $1")
            .bind(key)
            .fetch_optional(pool)
            .await?;
    let (id, main) = row.ok_or(ApiError::NotFound)?;
    Ok((id, main.unwrap_or_default()))
}

/// Every project's own adjustments: project id → rule → (on, change).
pub(crate) type ProjectSettings = HashMap<i64, HashMap<String, (bool, Change)>>;

pub(crate) async fn project_settings(pool: &PgPool) -> Result<ProjectSettings, sqlx::Error> {
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

/// Each project's main branch's latest analysis: its `sonda.toml` settings
/// (`None` when unknown) and the server settings' revision it applied.
async fn latest_scans(
    pool: &PgPool,
) -> Result<HashMap<i64, (Option<Toml>, Option<String>)>, sqlx::Error> {
    let rows: Vec<(i64, Option<Value>, Option<Value>)> = sqlx::query_as(
        "SELECT DISTINCT ON (a.project_id) a.project_id, a.rule_settings, a.rule_profile
         FROM analyses a JOIN projects p ON p.id = a.project_id AND a.branch = p.main_branch
         ORDER BY a.project_id, a.id DESC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(p, toml, profile)| {
            let toml = toml.and_then(|v| serde_json::from_value(v).ok());
            let revision = profile.and_then(|v| v["revision"].as_str().map(String::from));
            (p, (toml, revision))
        })
        .collect())
}

/// (analysis, commit, received at in epoch seconds, sonda.toml's settings,
/// the profile applied).
type ScanRow = (i64, String, f64, Option<Value>, Option<Value>);

/// `GET /api/projects/{key}/rules`: the rules for the project's languages,
/// each with its state there and what set it, and its findings.
pub async fn get_project(
    axum::extract::State(state): axum::extract::State<State>,
    Path(key): Path<String>,
) -> Result<Json<ProjectRules>, ApiError> {
    let pool = &state.pool;
    let (project, main_branch) = project_id(pool, &key).await?;
    let profiles = load_profiles(pool).await?;
    let profile_id = profiles.of(Some(project));
    let profile = &profiles.by_id[&profile_id];
    let own = project_settings(pool)
        .await?
        .remove(&project)
        .unwrap_or_default();
    // The main branch's analyses with their settings, oldest first.
    let history: Vec<ScanRow> = sqlx::query_as(
        "SELECT id, commit_sha, extract(epoch FROM received_at)::float8, rule_settings, rule_profile
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
    let expected = profiles.revision(Some(project));
    let profile_applied = history
        .last()
        .map(|h| h.4.as_ref().and_then(|p| p["revision"].as_str()) == Some(expected.as_str()));
    // Open findings per rule: (counted, left out).
    let findings: HashMap<String, (i64, i64)> = sqlx::query_as::<_, (String, i64, i64)>(
        "SELECT rule, count(*) FILTER (WHERE NOT rule_off(project_id, rule)),
                count(*) FILTER (WHERE rule_off(project_id, rule))
         FROM issues
         WHERE project_id = $1 AND branch = $2 AND fixed_analysis_id IS NULL
           AND status IN ('open', 'confirmed')
         GROUP BY rule",
    )
    .bind(project)
    .bind(&main_branch)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|(rule, counted, hidden)| (rule, (counted, hidden)))
    .collect();
    let languages: Vec<String> =
        match history.last() {
            Some(latest) => sqlx::query_scalar(
                "SELECT DISTINCT language FROM analysis_files WHERE analysis_id = $1 ORDER BY 1",
            )
            .bind(latest.0)
            .fetch_all(pool)
            .await?,
            None => Vec::new(),
        };

    let rules = RULES
        .iter()
        .filter(|r| {
            r.langs()
                .iter()
                .any(|l| languages.iter().any(|p| p == l.name()))
        })
        .map(|r| {
            let own_setting = own.get(r.id);
            let d = rule_state(
                r,
                toml.as_ref(),
                profile.rules.get(r.id),
                own_setting,
                profile_applied == Some(true),
            );
            let (open_issues, hidden_issues) = findings.get(r.id).copied().unwrap_or_default();
            ProjectRule {
                info: crate::rules::info(r),
                state: RuleState {
                    on: d.on,
                    set_by: d.set_by,
                    change: d.change,
                    severity_by: d.severity.as_ref().map(|s| s.1),
                    severity: d.severity.map(|s| s.0),
                    conflict: d.conflict,
                    project_setting: own_setting.map(|(on, _)| if *on { "on" } else { "off" }),
                },
                open_issues,
                hidden_issues,
            }
        })
        .collect();

    // Changes between consecutive analyses that recorded settings, grouped
    // by analysis so the newest analysis comes first, each in rule order.
    let mut by_analysis: Vec<Vec<TomlChange>> = Vec::new();
    let mut previous: Option<Toml> = None;
    for (id, sha, at, value, _) in &history {
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
        profile: ProfileRef {
            id: profile_id,
            name: profile.name.clone(),
            is_default: profile.is_default,
            chosen: profiles
                .projects
                .get(&project)
                .is_some_and(|(c, _)| c.is_some()),
        },
        profile_applied,
        sonda_toml,
        languages,
        rules,
        toml_changes,
    }))
}

/// A profile that sets a rule, for the Rules page.
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct InProfile {
    pub id: i64,
    pub name: String,
    pub on: bool,
    pub severity: Option<String>,
}

/// For the Rules page: the default profile's settings, in how many projects
/// each rule is off by what turned it off, and the profiles that set it.
pub(crate) struct RuleOverview {
    pub default_off: HashMap<String, Change>,
    pub off_in: HashMap<&'static str, OffIn>,
    pub in_profiles: HashMap<String, Vec<InProfile>>,
}

pub(crate) async fn rule_overview(pool: &PgPool) -> Result<RuleOverview, sqlx::Error> {
    let profiles = load_profiles(pool).await?;
    let own = project_settings(pool).await?;
    let scans = latest_scans(pool).await?;
    let mut off_in: HashMap<&'static str, OffIn> = HashMap::new();
    let none = HashMap::new();
    for &p in profiles.projects.keys() {
        let (toml, applied) = scans
            .get(&p)
            .map(|(t, r)| {
                (
                    t.as_ref(),
                    r.as_deref() == Some(profiles.revision(Some(p)).as_str()),
                )
            })
            .unwrap_or((None, false));
        let profile = &profiles.by_id[&profiles.of(Some(p))];
        let mine = own.get(&p).unwrap_or(&none);
        for r in RULES.iter() {
            let d = rule_state(r, toml, profile.rules.get(r.id), mine.get(r.id), applied);
            if d.on {
                continue;
            }
            let entry = off_in.entry(r.id).or_default();
            match d.set_by {
                SetBy::SondaToml => entry.sonda_toml += 1,
                SetBy::Profile | SetBy::Project => entry.server += 1,
                SetBy::Default => {}
            }
        }
    }
    off_in.retain(|_, c| c.sonda_toml + c.server > 0);
    let default_off = profiles.by_id[&profiles.default]
        .rules
        .iter()
        .filter(|(_, r)| !r.on)
        .map(|(id, r)| (id.clone(), r.change.clone()))
        .collect();
    let mut in_profiles: HashMap<String, Vec<InProfile>> = HashMap::new();
    for (&id, p) in &profiles.by_id {
        for (rule, r) in &p.rules {
            in_profiles
                .entry(rule.clone())
                .or_default()
                .push(InProfile {
                    id,
                    name: p.name.clone(),
                    on: r.on,
                    severity: r.severity.clone(),
                });
        }
    }
    Ok(RuleOverview {
        default_off,
        off_in,
        in_profiles,
    })
}

#[derive(Serialize, Default, Clone, Copy)]
#[serde(rename_all = "camelCase")]
pub struct OffIn {
    pub sonda_toml: usize,
    pub server: usize,
}

pub(crate) fn checked_note(note: Option<String>) -> Result<Option<String>, ApiError> {
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

pub(crate) fn checked_rule(rule: &str) -> Result<&'static Rule, ApiError> {
    find(rule).ok_or_else(|| {
        ApiError::Unprocessable(format!("unknown rule {rule:?} (see GET /api/rules)"))
    })
}

/// Recounts the latest analysis of every branch of the given projects, or
/// of every project.
pub(crate) async fn recount(pool: &PgPool, projects: Option<&[i64]>) -> Result<(), sqlx::Error> {
    let branches: Vec<(i64, String)> = sqlx::query_as(
        "SELECT DISTINCT project_id, branch FROM analyses
         WHERE $1::bigint[] IS NULL OR project_id = ANY($1)",
    )
    .bind(projects)
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

/// `PUT /api/rule-settings` (ADR-0016): admins turn a rule off, or back on,
/// in the default profile (ADR-0018). The built-in "sonda way" can't change,
/// so when it's the default, a "Server settings" profile takes its place.
pub async fn put_global(
    axum::extract::State(state): axum::extract::State<State>,
    Extension(caller): Extension<Caller>,
    Json(patch): Json<GlobalPatch>,
) -> Result<Json<Value>, ApiError> {
    let rule = checked_rule(&patch.rule)?;
    let note = checked_note(patch.note)?;
    let by = caller.name();
    let mut tx = state.pool.begin().await?;
    let (mut profile, builtin): (i64, bool) =
        sqlx::query_as("SELECT id, builtin FROM rule_profiles WHERE is_default FOR UPDATE")
            .fetch_one(&mut *tx)
            .await?;
    if builtin {
        let existing: Option<i64> =
            sqlx::query_scalar("SELECT id FROM rule_profiles WHERE name = 'Server settings'")
                .fetch_optional(&mut *tx)
                .await?;
        profile = match existing {
            Some(id) => id,
            None => crate::profiles::create(&mut tx, "Server settings", None, &by).await?,
        };
        crate::profiles::make_default(&mut tx, profile).await?;
    }
    crate::profiles::set_rule(
        &mut tx,
        profile,
        rule.id,
        if patch.off { Some(false) } else { None },
        None,
        note.as_deref(),
        &by,
    )
    .await?;
    tx.commit().await?;
    tracing::info!(
        by,
        rule = rule.id,
        off = patch.off,
        "changed a rule in the default profile"
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
    /// `on`, `off`, or `inherit` to follow the project's profile again.
    state: String,
    #[serde(default)]
    note: Option<String>,
}

/// `PUT /api/projects/{key}/rule-settings`: admins set a rule on or off for
/// one project, over its profile, or make it follow the profile again.
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
    let mut tx = state.pool.begin().await?;
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
            .execute(&mut *tx)
            .await?;
        }
        None => {
            sqlx::query("DELETE FROM project_rule_settings WHERE project_id = $1 AND rule = $2")
                .bind(project)
                .bind(rule.id)
                .execute(&mut *tx)
                .await?;
        }
    }
    // Scans record the revision they applied, so this one is now stale.
    sqlx::query(
        "UPDATE projects SET rule_settings_revision = rule_settings_revision + 1 WHERE id = $1",
    )
    .bind(project)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    tracing::info!(
        by,
        project = key,
        rule = rule.id,
        state = patch.state,
        "changed a project rule setting"
    );
    recount(&state.pool, Some(&[project])).await?;
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

    fn profile(on: bool, severity: Option<&str>) -> ProfileRule {
        ProfileRule {
            on,
            severity: severity.map(String::from),
            change: change(),
        }
    }

    #[test]
    fn states_say_what_decided_them() {
        let rule = find("js/no-var").unwrap();
        let toml_off = Toml {
            disabled: ["js/no-var".to_string()].into(),
            ..Default::default()
        };
        let (on, off) = ((true, change()), (false, change()));
        let state = |t, p, o, applied| {
            let d = rule_state(rule, t, p, o, applied);
            (d.on, d.set_by, d.conflict)
        };
        assert_eq!(state(None, None, None, true), (true, SetBy::Default, false));
        assert_eq!(
            state(Some(&toml_off), None, None, true),
            (false, SetBy::SondaToml, false)
        );
        // Where the server sets a rule, it wins over sonda.toml.
        let p_off = profile(false, None);
        assert_eq!(
            state(None, Some(&p_off), None, true),
            (false, SetBy::Profile, false)
        );
        let p_on = profile(true, None);
        assert_eq!(
            state(Some(&toml_off), Some(&p_on), None, true),
            (true, SetBy::Profile, false)
        );
        // A project's adjustment wins over its profile.
        assert_eq!(
            state(None, Some(&p_off), Some(&on), true),
            (true, SetBy::Project, false)
        );
        assert_eq!(
            state(None, None, Some(&off), true),
            (false, SetBy::Project, false)
        );
        // A scan that didn't apply the server's settings never ran it.
        assert_eq!(
            state(Some(&toml_off), Some(&p_on), None, false),
            (false, SetBy::SondaToml, true)
        );

        // An off-by-default rule, turned on by a profile or by sonda.toml.
        let prefer = find("js/prefer-const").unwrap();
        let d = rule_state(prefer, None, None, None, true);
        assert_eq!((d.on, d.set_by), (false, SetBy::Default));
        let d = rule_state(prefer, None, Some(&p_on), None, true);
        assert_eq!((d.on, d.set_by), (true, SetBy::Profile));
        let toml_on = Toml {
            enabled: ["js/prefer-const".to_string()].into(),
            ..Default::default()
        };
        let d = rule_state(prefer, Some(&toml_on), None, None, true);
        assert_eq!((d.on, d.set_by), (true, SetBy::SondaToml));
    }

    #[test]
    fn a_profiles_severity_wins_over_sonda_tomls() {
        let rule = find("js/no-eval").unwrap();
        let toml = Toml {
            severity: [("js/no-eval".to_string(), "minor".to_string())].into(),
            ..Default::default()
        };
        let d = rule_state(rule, Some(&toml), None, None, true);
        assert_eq!(d.severity, Some(("minor".into(), SetBy::SondaToml)));
        let p = profile(true, Some("blocker"));
        let d = rule_state(rule, Some(&toml), Some(&p), None, true);
        assert_eq!(d.severity, Some(("blocker".into(), SetBy::Profile)));
    }
}
