use crate::measures::Measures;
use crate::model::{Condition, Metric, Op};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    Error,
    /// The metric has no value (e.g. coverage without a report); not counted as failing.
    NoData,
    /// Not evaluated, for the `reason` the result gives (see
    /// [`ignored_because`]); not counted as failing.
    Ignored,
}

/// SonarQube's rule: below this many new lines, conditions on coverage and
/// duplication of new code are ignored. A two-line change with one
/// uncovered line is 50% coverage, which says little about the change and
/// would fail most gates.
pub const MIN_NEW_LINES: f64 = 20.0;

/// The conditions `MIN_NEW_LINES` applies to.
pub fn ignored_on_small_changes(metric: Metric) -> bool {
    matches!(
        metric,
        Metric::NewCoverage | Metric::NewDuplicatedLines | Metric::NewDuplicatedLinesDensity
    )
}

/// Metrics that have data only when dependencies were checked against
/// advisories (ADR-0009).
pub fn needs_advisories(metric: Metric) -> bool {
    matches!(
        metric,
        Metric::VulnerableDependencies
            | Metric::SevereVulnerableDependencies
            | Metric::NewVulnerableDependencies
            | Metric::NewSevereVulnerableDependencies
    )
}

/// Why a condition isn't evaluated, if it isn't: a small change (for
/// coverage and duplication of new code), or no advisory data (for
/// dependencies), which says nothing about the project, unlike coverage
/// that wasn't uploaded ("no data"). The CLI and the server share it.
pub fn ignored_because(
    metric: Metric,
    actual: Option<f64>,
    new_lines: Option<f64>,
) -> Option<&'static str> {
    if ignored_on_small_changes(metric) && new_lines.is_some_and(|n| n < MIN_NEW_LINES) {
        Some("fewer than 20 new lines")
    } else if needs_advisories(metric) && actual.is_none() {
        Some("no advisory data")
    } else {
        None
    }
}

#[derive(Debug, Serialize)]
pub struct ConditionResult {
    #[serde(flatten)]
    pub condition: Condition,
    pub actual: Option<f64>,
    pub status: Status,
    /// Why it's ignored, when it is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct GateResult {
    pub passed: bool,
    pub conditions: Vec<ConditionResult>,
}

pub(crate) fn evaluate(conditions: &[Condition], measures: &Measures) -> GateResult {
    let new_lines = measures.get(&Metric::NewLines).copied().flatten();
    let results: Vec<ConditionResult> = conditions
        .iter()
        .map(|c| {
            let actual = measures.get(&c.metric).copied().flatten();
            let reason = ignored_because(c.metric, actual, new_lines);
            let status = match actual {
                _ if reason.is_some() => Status::Ignored,
                None => Status::NoData,
                Some(v)
                    if (c.op == Op::Gt && v > c.threshold)
                        || (c.op == Op::Lt && v < c.threshold) =>
                {
                    Status::Error
                }
                Some(_) => Status::Ok,
            };
            ConditionResult {
                condition: c.clone(),
                actual,
                status,
                reason,
            }
        })
        .collect();
    GateResult {
        passed: results.iter().all(|r| r.status != Status::Error),
        conditions: results,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluates_conditions() {
        let measures = Measures::from([
            (Metric::NewBugs, Some(2.0)),
            (Metric::NewCoverage, None),
            (Metric::Coverage, Some(90.0)),
        ]);
        let cond = |metric, op, threshold| Condition {
            metric,
            op,
            threshold,
        };
        let r = evaluate(
            &[
                cond(Metric::NewBugs, Op::Gt, 0.0),
                cond(Metric::NewCoverage, Op::Lt, 80.0),
                cond(Metric::Coverage, Op::Lt, 80.0),
            ],
            &measures,
        );
        assert!(!r.passed);
        let statuses: Vec<_> = r.conditions.iter().map(|c| c.status).collect();
        assert_eq!(statuses, vec![Status::Error, Status::NoData, Status::Ok]);
    }

    #[test]
    fn small_changes_ignore_coverage_and_duplication() {
        let cond = |metric, op, threshold| Condition {
            metric,
            op,
            threshold,
        };
        let conditions = [
            cond(Metric::NewBugs, Op::Gt, 0.0),
            cond(Metric::NewCoverage, Op::Lt, 80.0),
            cond(Metric::NewDuplicatedLinesDensity, Op::Gt, 3.0),
        ];
        let at = |lines: f64| {
            let measures = Measures::from([
                (Metric::NewLines, Some(lines)),
                (Metric::NewBugs, Some(0.0)),
                (Metric::NewCoverage, Some(50.0)),
                (Metric::NewDuplicatedLinesDensity, None),
            ]);
            let r = evaluate(&conditions, &measures);
            let statuses: Vec<_> = r.conditions.iter().map(|c| c.status).collect();
            (r.passed, statuses)
        };
        assert_eq!(
            at(19.0),
            (true, vec![Status::Ok, Status::Ignored, Status::Ignored])
        );
        assert_eq!(
            at(20.0),
            (false, vec![Status::Ok, Status::Error, Status::NoData])
        );
    }

    #[test]
    fn dependency_conditions_without_advisories_are_ignored() {
        let condition = Condition {
            metric: Metric::NewSevereVulnerableDependencies,
            op: Op::Gt,
            threshold: 0.0,
        };
        let at = |value: Option<f64>| {
            let measures = Measures::from([(Metric::NewSevereVulnerableDependencies, value)]);
            let r = evaluate(std::slice::from_ref(&condition), &measures);
            (r.passed, r.conditions[0].status, r.conditions[0].reason)
        };
        assert_eq!(at(None), (true, Status::Ignored, Some("no advisory data")));
        assert_eq!(at(Some(0.0)), (true, Status::Ok, None));
        assert_eq!(at(Some(1.0)), (false, Status::Error, None));
    }
}
