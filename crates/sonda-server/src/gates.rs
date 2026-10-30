//! `GET /api/gates`: the quality gates projects use, read-only. A gate is
//! defined in each repository's sonda.toml and stored with every analysis,
//! so projects whose latest main-branch analysis used the same conditions
//! share a gate. The one equal to sonda's built-in default is "Default".

use crate::api::ApiError;
use crate::health::{condition_label, gate_state, rfc3339};
use crate::http::State;
use axum::Json;
use serde::Serialize;
use serde_json::Value;
use sonda_core::config::GateConfig;
use std::collections::{BTreeMap, HashMap};

/// Evaluations per gate in the pass-rate history.
const EVALUATIONS: usize = 40;

#[derive(Serialize)]
pub struct Gates {
    /// The default gate first, then by how many projects use each.
    pub gates: Vec<Gate>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Gate {
    /// Stable for the same conditions: a short hash of them.
    pub id: String,
    pub name: String,
    pub is_default: bool,
    pub conditions: Vec<GateCondition>,
    pub projects: Vec<GateProject>,
    /// The latest evaluations of this gate on its projects' main branches,
    /// newest first.
    pub evaluations: Vec<Evaluation>,
    /// Percent of `evaluations` that passed (partial counts as passing).
    pub pass_rate: Option<u32>,
    /// The condition that failed most often in `evaluations`.
    pub most_common_failure: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GateCondition {
    pub label: String,
    pub metric: String,
    /// `gt` or `lt`: the gate fails when `metric op threshold` holds.
    pub op: String,
    pub threshold: f64,
    /// Projects whose latest analysis fails it now.
    pub failing: usize,
    /// Projects whose latest analysis had no value for it.
    pub no_data: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GateProject {
    pub project: String,
    pub state: &'static str,
    pub analyzed_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Evaluation {
    pub analysis: i64,
    pub project: String,
    pub state: &'static str,
    pub analyzed_at: String,
}

/// A gate's conditions, comparable: metric, op, and the threshold's bits.
type Signature = Vec<(String, String, u64)>;

fn signature(gate: &Value) -> Signature {
    let mut s: Signature = gate["conditions"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|c| {
            (
                c["metric"].as_str().unwrap_or_default().to_string(),
                c["op"].as_str().unwrap_or_default().to_string(),
                c["threshold"].as_f64().unwrap_or_default().to_bits(),
            )
        })
        .collect();
    s.sort();
    s
}

fn default_signature() -> Signature {
    let mut s: Signature = GateConfig::default()
        .conditions
        .iter()
        .map(|c| {
            (
                c.metric.as_str().to_string(),
                // As stored with analyses: serde's lowercase name.
                serde_json::to_value(c.op)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_default(),
                c.threshold.to_bits(),
            )
        })
        .collect();
    s.sort();
    s
}

/// FNV-1a over the signature: short, stable ids for URLs.
fn gate_id(s: &Signature) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for (metric, op, threshold) in s {
        for b in metric
            .bytes()
            .chain([0])
            .chain(op.bytes())
            .chain([0])
            .chain(threshold.to_le_bytes())
        {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    }
    format!("{:08x}", h >> 32)
}

/// A main-branch analysis: id, project, when, gate, passed.
type Row = (i64, String, f64, Value, bool);

pub async fn list_gates(
    axum::extract::State(state): axum::extract::State<State>,
) -> Result<Json<Gates>, ApiError> {
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT a.id, p.key, extract(epoch FROM a.received_at)::float8, a.gate, a.gate_passed
         FROM analyses a JOIN projects p ON p.id = a.project_id AND a.branch = p.main_branch
         ORDER BY a.id DESC",
    )
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(build(&rows)))
}

fn build(rows: &[Row]) -> Gates {
    // `rows` is newest first, so a project's first row is its latest.
    let mut latest: BTreeMap<&str, &Row> = BTreeMap::new();
    for r in rows {
        latest.entry(r.1.as_str()).or_insert(r);
    }
    let mut groups: HashMap<Signature, Vec<&Row>> = HashMap::new();
    for r in latest.values() {
        groups.entry(signature(&r.3)).or_default().push(r);
    }
    let default = default_signature();
    let mut custom = 0;
    let mut gates: Vec<(bool, usize, Gate)> = groups
        .into_iter()
        .map(|(sig, current)| {
            let is_default = sig == default;
            let template = &current[0].3;
            let conditions = template["conditions"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|c| {
                    let metric = c["metric"].as_str().unwrap_or_default();
                    let count = |status: &str| {
                        current
                            .iter()
                            .filter(|r| {
                                r.3["conditions"]
                                    .as_array()
                                    .into_iter()
                                    .flatten()
                                    .any(|x| x["metric"] == metric && x["status"] == status)
                            })
                            .count()
                    };
                    GateCondition {
                        label: condition_label(c),
                        metric: metric.to_string(),
                        op: c["op"].as_str().unwrap_or_default().to_string(),
                        threshold: c["threshold"].as_f64().unwrap_or_default(),
                        failing: count("error"),
                        no_data: count("no_data"),
                    }
                })
                .collect();
            let projects: Vec<GateProject> = current
                .iter()
                .map(|r| GateProject {
                    project: r.1.clone(),
                    state: gate_state(r.4, &r.3),
                    analyzed_at: rfc3339(r.2),
                })
                .collect();
            let members: Vec<&str> = current.iter().map(|r| r.1.as_str()).collect();
            let history: Vec<&Row> = rows
                .iter()
                .filter(|r| members.contains(&r.1.as_str()) && signature(&r.3) == sig)
                .take(EVALUATIONS)
                .collect();
            let passed = history.iter().filter(|r| r.4).count();
            let mut failures: BTreeMap<String, usize> = BTreeMap::new();
            for r in &history {
                for c in r.3["conditions"].as_array().into_iter().flatten() {
                    if c["status"] == "error" {
                        *failures.entry(condition_label(c)).or_default() += 1;
                    }
                }
            }
            let most_common_failure = failures
                .into_iter()
                .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(&a.0)))
                .map(|(label, _)| label);
            let gate = Gate {
                id: gate_id(&sig),
                name: String::new(),
                is_default,
                conditions,
                projects,
                pass_rate: (!history.is_empty()).then(|| (passed * 100 / history.len()) as u32),
                evaluations: history
                    .iter()
                    .map(|r| Evaluation {
                        analysis: r.0,
                        project: r.1.clone(),
                        state: gate_state(r.4, &r.3),
                        analyzed_at: rfc3339(r.2),
                    })
                    .collect(),
                most_common_failure,
            };
            (is_default, current.len(), gate)
        })
        .collect();
    gates.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then(b.1.cmp(&a.1))
            .then_with(|| a.2.id.cmp(&b.2.id))
    });
    let gates = gates
        .into_iter()
        .map(|(is_default, _, mut g)| {
            g.name = if is_default {
                "Default".into()
            } else {
                custom += 1;
                format!("Custom gate {custom}")
            };
            g
        })
        .collect();
    Gates { gates }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn gate(conditions: &[(&str, &str, f64, &str)]) -> Value {
        json!({ "conditions": conditions.iter().map(|(m, op, t, status)| json!({
            "metric": m, "op": op, "threshold": t, "actual": 1.0, "status": status
        })).collect::<Vec<_>>() })
    }

    fn default_gate(vulns: &str) -> Value {
        gate(&[
            ("new_bugs", "gt", 0.0, "ok"),
            ("new_vulnerabilities", "gt", 0.0, vulns),
            ("new_coverage", "lt", 80.0, "ok"),
            ("new_duplicated_lines_density", "gt", 3.0, "ok"),
        ])
    }

    #[test]
    fn projects_with_the_same_conditions_share_a_gate() {
        let strict = gate(&[("new_coverage", "lt", 90.0, "error")]);
        let rows: Vec<Row> = vec![
            (5, "a".into(), 50.0, default_gate("error"), false),
            (4, "b".into(), 40.0, strict.clone(), false),
            (3, "a".into(), 30.0, default_gate("ok"), true),
            (2, "c".into(), 20.0, default_gate("ok"), true),
            // b used the default before switching: not part of its history now.
            (1, "b".into(), 10.0, default_gate("ok"), true),
        ];
        let g = build(&rows).gates;
        assert_eq!(g.len(), 2);
        assert_eq!((g[0].name.as_str(), g[0].is_default), ("Default", true));
        assert_eq!(
            g[0].projects
                .iter()
                .map(|p| p.project.as_str())
                .collect::<Vec<_>>(),
            ["a", "c"]
        );
        let vulns = g[0]
            .conditions
            .iter()
            .find(|c| c.metric == "new_vulnerabilities")
            .unwrap();
        assert_eq!(vulns.failing, 1);
        assert_eq!(
            g[0].evaluations
                .iter()
                .map(|e| e.analysis)
                .collect::<Vec<_>>(),
            [5, 3, 2]
        );
        assert_eq!(g[0].pass_rate, Some(66));
        assert_eq!(
            g[0].most_common_failure.as_deref(),
            Some("New vulnerabilities > 0")
        );
        assert_eq!(g[1].name, "Custom gate 1");
        assert_eq!(g[1].evaluations.len(), 1);
        assert_eq!(g[1].id, gate_id(&signature(&strict)));
        assert_eq!(g[1].id.len(), 8);
    }

    #[test]
    fn condition_order_does_not_make_a_new_gate() {
        let a = gate(&[
            ("new_bugs", "gt", 0.0, "ok"),
            ("coverage", "lt", 50.0, "ok"),
        ]);
        let b = gate(&[
            ("coverage", "lt", 50.0, "ok"),
            ("new_bugs", "gt", 0.0, "ok"),
        ]);
        assert_eq!(signature(&a), signature(&b));
        assert_eq!(signature(&default_gate("ok")), default_signature());
    }
}
