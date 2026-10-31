//! What several endpoints compute the same way from stored analyses:
//! ratings (ADR-0005), gate states, condition labels, and formats.

use serde::Serialize;
use serde_json::Value;

pub(crate) const DAY: f64 = 86_400.0;

/// ADR-0005's level for the worst open bug or vulnerability: none is 5,
/// minor 4, major 3, critical 2, blocker 1.
pub(crate) fn severity_level(worst: Option<&str>) -> u8 {
    match worst {
        Some("blocker") => 1,
        Some("critical") => 2,
        Some("major") => 3,
        Some("minor") => 4,
        _ => 5,
    }
}

/// Passed, failed, or partial: passed with some condition lacking data.
pub(crate) fn gate_state(passed: bool, gate: &Value) -> &'static str {
    let no_data = gate["conditions"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|c| c["status"] == "no_data");
    match (passed, no_data) {
        (false, _) => "failed",
        (true, false) => "passed",
        (true, true) => "partial",
    }
}

/// The web app's project score (`projectScore` in web/src/lib/visual.ts):
/// ratings weigh 70% and coverage 30%, or ratings alone without coverage.
pub(crate) fn project_score(levels: [u8; 3], coverage: Option<f64>) -> f64 {
    let ratings = f64::from(levels.iter().map(|&l| u32::from(l)).sum::<u32>()) / 15.0;
    match coverage {
        Some(c) => ratings * 70.0 + c * 0.3,
        None => ratings * 100.0,
    }
}

/// A path's top-level directory, or `.` for files at the root: what the
/// drill-downs and the project page call a component.
pub(crate) fn component_of(path: &str) -> &str {
    path.split_once('/').map_or(".", |(c, _)| c)
}

pub(crate) fn debt_level(ratio: f64) -> u8 {
    match ratio {
        r if r <= 0.05 => 5,
        r if r <= 0.10 => 4,
        r if r <= 0.20 => 3,
        r if r <= 0.50 => 2,
        _ => 1,
    }
}

pub(crate) fn coverage_level(pct: f64) -> u8 {
    match pct {
        p if p >= 80.0 => 5,
        p if p >= 70.0 => 4,
        p if p >= 60.0 => 3,
        p if p >= 50.0 => 2,
        _ => 1,
    }
}

/// Debt in working days (8 hours) or hours: "12d", "5h", "40min".
pub(crate) fn debt_text(minutes: f64) -> String {
    if minutes >= 480.0 {
        format!("{:.0}d", minutes / 480.0)
    } else if minutes >= 60.0 {
        format!("{:.0}h", minutes / 60.0)
    } else {
        format!("{minutes:.0}min")
    }
}

/// "New vulnerabilities > 0", from a stored gate condition.
/// Re-evaluates a stored gate's conditions against `measures`, as the CLI
/// does (`gt`/`lt`; no value is "no data", which doesn't fail), and sets
/// `passed`. Returns whether it passes. For values the server computes
/// itself (ADR-0009, ADR-0011).
pub(crate) fn evaluate_gate(gate: &mut Value, measures: &Value) -> bool {
    // As the CLI does: a small change ignores coverage and duplication of
    // new code, and no advisory data ignores dependencies.
    let new_lines = measures["new_lines"].as_f64();
    for c in gate["conditions"].as_array_mut().into_iter().flatten() {
        let Some(metric) = c["metric"].as_str() else {
            continue;
        };
        let actual = measures[metric].as_f64();
        let threshold = c["threshold"].as_f64().unwrap_or(0.0);
        let reason = sonda_core::model::Metric::ALL
            .iter()
            .find(|m| m.as_str() == metric)
            .and_then(|m| sonda_core::ignored_because(*m, actual, new_lines));
        match reason {
            Some(r) => c["reason"] = Value::from(r),
            None => {
                if let Some(o) = c.as_object_mut() {
                    o.remove("reason");
                }
            }
        }
        let status = match (actual, c["op"].as_str()) {
            _ if reason.is_some() => "ignored",
            (None, _) => "no_data",
            (Some(v), Some("gt")) if v > threshold => "error",
            (Some(v), Some("lt")) if v < threshold => "error",
            _ => "ok",
        };
        c["actual"] = actual.map_or(Value::Null, Value::from);
        c["status"] = Value::from(status);
    }
    let passed = gate["conditions"]
        .as_array()
        .into_iter()
        .flatten()
        .all(|c| c["status"] != "error");
    gate["passed"] = Value::from(passed);
    passed
}

/// A scan's duration as people read it: `850ms`, `42s`, `3m 12s`,
/// `1h 5m`.
pub(crate) fn duration_text(ms: i64) -> String {
    let s = ms / 1000;
    match ms {
        ms if ms < 1000 => format!("{}ms", ms.max(0)),
        _ if s < 60 => format!("{s}s"),
        _ if s < 3600 => format!("{}m {}s", s / 60, s % 60),
        _ => format!("{}h {}m", s / 3600, s % 3600 / 60),
    }
}

pub(crate) fn condition_label(c: &Value) -> String {
    let metric = c["metric"].as_str().unwrap_or("?");
    let name = match metric {
        "new_coverage" => "Coverage on new code".to_string(),
        "new_duplicated_lines_density" => "Duplication on new code".to_string(),
        "duplicated_lines_density" => "Duplication".to_string(),
        m => {
            let words = m.replace('_', " ");
            let mut chars = words.chars();
            chars.next().map_or_else(String::new, |f| {
                f.to_uppercase().collect::<String>() + chars.as_str()
            })
        }
    };
    let op = match c["op"].as_str().unwrap_or("") {
        "gt" => ">",
        "lt" => "<",
        "ge" | "gte" => "≥",
        "le" | "lte" => "≤",
        "eq" => "=",
        other => other,
    };
    let threshold = c["threshold"].as_f64().map_or_else(String::new, |t| {
        if t.fract() == 0.0 {
            format!("{t:.0}")
        } else {
            format!("{t}")
        }
    });
    let unit = if metric.contains("coverage") || metric.contains("density") {
        "%"
    } else {
        ""
    };
    format!("{name} {op} {threshold}{unit}")
}

pub(crate) fn plural<'a>(n: usize, one: &'a str, many: &'a str) -> &'a str {
    if n == 1 { one } else { many }
}

/// Compact age, as the web app's `formatAge`: "12m", "3h", "2d", "3w", "4mo", "2y".
pub(crate) fn ago(seconds: f64) -> String {
    let minutes = (seconds.max(0.0) / 60.0) as u64;
    let (hours, days) = (minutes / 60, minutes / 1440);
    match () {
        _ if minutes < 60 => format!("{minutes}m"),
        _ if hours < 24 => format!("{hours}h"),
        _ if days < 14 => format!("{days}d"),
        _ if days < 60 => format!("{}w", days / 7),
        _ if days < 365 => format!("{}mo", days / 30),
        _ => format!("{}y", days / 365),
    }
}

/// The UTC date of `epoch` as midnight in ISO 8601, e.g.
/// `2026-10-30T00:00:00.000Z` (civil-from-days, Howard Hinnant's algorithm).
pub(crate) fn iso_date(epoch: f64) -> String {
    let days = (epoch / DAY).floor() as i64;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T00:00:00.000Z")
}

// ------------------------------------------------- a stored analysis

#[derive(Serialize)]
pub struct GateDetail {
    pub state: &'static str,
    pub conditions: Vec<ConditionRow>,
}

#[derive(Serialize)]
pub struct ConditionRow {
    /// "New vulnerabilities > 0".
    pub label: String,
    pub metric: String,
    pub actual: Option<f64>,
    /// `ok`, `error`, `no_data` or `ignored` (see `reason`).
    pub status: String,
    /// Why an ignored condition is: "fewer than 20 new lines", "no
    /// advisory data". Older analyses' ignored conditions have none.
    pub reason: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Measures {
    pub overall: MeasureSet,
    pub new_code: MeasureSet,
}

/// Null where the analysis has no value (coverage not uploaded, no new code).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MeasureSet {
    pub lines: Option<f64>,
    pub issues: Option<f64>,
    pub bugs: Option<f64>,
    pub vulnerabilities: Option<f64>,
    pub code_smells: Option<f64>,
    pub coverage: Option<f64>,
    pub duplication: Option<f64>,
    pub debt_minutes: Option<f64>,
}

pub(crate) fn conditions(gate: &Value) -> Vec<ConditionRow> {
    gate["conditions"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|c| ConditionRow {
            label: condition_label(c),
            metric: c["metric"].as_str().unwrap_or_default().to_string(),
            actual: c["actual"].as_f64(),
            status: c["status"].as_str().unwrap_or("no_data").to_string(),
            reason: c["reason"].as_str().map(str::to_string),
        })
        .collect()
}

pub(crate) fn measure_set(m: &Value, prefix: &str) -> MeasureSet {
    let get = |name: &str| m[format!("{prefix}{name}")].as_f64();
    MeasureSet {
        lines: if prefix.is_empty() {
            m["ncloc"].as_f64()
        } else {
            get("lines")
        },
        issues: get("issues"),
        bugs: get("bugs"),
        vulnerabilities: get("vulnerabilities"),
        code_smells: get("code_smells"),
        coverage: get("coverage"),
        duplication: get("duplicated_lines_density"),
        debt_minutes: get("debt_minutes"),
    }
}

/// RFC 3339 in UTC with milliseconds, as `Date.toISOString()` writes it.
pub(crate) fn rfc3339(epoch: f64) -> String {
    let day = iso_date(epoch);
    let seconds = epoch.rem_euclid(DAY);
    let (h, m, s) = (
        (seconds / 3600.0) as u32,
        (seconds % 3600.0 / 60.0) as u32,
        seconds % 60.0,
    );
    format!("{}T{h:02}:{m:02}:{s:06.3}Z", &day[..10])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_read_like_iso_strings() {
        assert_eq!(rfc3339(0.0), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            rfc3339(1_793_318_400.0 + 3_723.5),
            "2026-10-30T01:02:03.500Z"
        );
    }
    use serde_json::json;

    #[test]
    fn dates_and_ages() {
        assert_eq!(iso_date(0.0), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            iso_date(1_793_318_400.0 + 3600.0),
            "2026-10-30T00:00:00.000Z"
        );
        assert_eq!(iso_date(951_782_400.0), "2000-02-29T00:00:00.000Z");
        assert_eq!(
            [
                30.0,
                7_200.0,
                3.0 * DAY,
                20.0 * DAY,
                100.0 * DAY,
                800.0 * DAY
            ]
            .map(ago),
            ["0m", "2h", "3d", "2w", "3mo", "2y"]
        );
    }

    #[test]
    fn rating_bands_follow_adr_0005() {
        assert_eq!(
            [0.05, 0.051, 0.10, 0.2, 0.5, 0.51].map(debt_level),
            [5, 4, 4, 3, 2, 1]
        );
        assert_eq!(
            [80.0, 79.9, 70.0, 60.0, 50.0, 49.9].map(coverage_level),
            [5, 4, 4, 3, 2, 1]
        );
    }

    #[test]
    fn gate_conditions_read_like_the_design() {
        let c =
            |metric: &str, op: &str, t: f64| json!({ "metric": metric, "op": op, "threshold": t });
        assert_eq!(
            condition_label(&c("new_vulnerabilities", "gt", 0.0)),
            "New vulnerabilities > 0"
        );
        assert_eq!(
            condition_label(&c("new_coverage", "lt", 80.0)),
            "Coverage on new code < 80%"
        );
        assert_eq!(
            condition_label(&c("new_duplicated_lines_density", "gt", 3.0)),
            "Duplication on new code > 3%"
        );
    }

    #[test]
    fn debt_reads_in_days_or_hours() {
        assert_eq!(debt_text(4094.0), "9d");
        assert_eq!(debt_text(90.0), "2h");
    }

    #[test]
    fn durations_read_like_people_say_them() {
        let got: Vec<String> = [850, 42_400, 192_000, 3_900_000]
            .into_iter()
            .map(duration_text)
            .collect();
        assert_eq!(got, ["850ms", "42s", "3m 12s", "1h 5m"]);
    }

    #[test]
    fn gate_states_and_scores() {
        let gate = |status: &str| json!({ "conditions": [{ "status": status }] });
        assert_eq!(gate_state(false, &gate("error")), "failed");
        assert_eq!(gate_state(true, &gate("ok")), "passed");
        assert_eq!(gate_state(true, &gate("no_data")), "partial");
        assert_eq!(project_score([5, 5, 5], None), 100.0);
        assert_eq!(project_score([5, 5, 5], Some(50.0)), 85.0);
        assert_eq!(severity_level(Some("critical")), 2);
        assert_eq!(severity_level(None), 5);
        assert_eq!(component_of("src/a.rs"), "src");
        assert_eq!(component_of("main.rs"), ".");
    }
}
