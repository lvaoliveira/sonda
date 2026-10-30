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
    /// A condition on coverage or duplication of new code, when there are
    /// fewer than `MIN_NEW_LINES` new lines; not counted as failing.
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

#[derive(Debug, Serialize)]
pub struct ConditionResult {
    #[serde(flatten)]
    pub condition: Condition,
    pub actual: Option<f64>,
    pub status: Status,
}

#[derive(Debug, Serialize)]
pub struct GateResult {
    pub passed: bool,
    pub conditions: Vec<ConditionResult>,
}

pub(crate) fn evaluate(conditions: &[Condition], measures: &Measures) -> GateResult {
    let small = measures
        .get(&Metric::NewLines)
        .copied()
        .flatten()
        .is_some_and(|n| n < MIN_NEW_LINES);
    let results: Vec<ConditionResult> = conditions
        .iter()
        .map(|c| {
            let actual = measures.get(&c.metric).copied().flatten();
            let status = match actual {
                _ if small && ignored_on_small_changes(c.metric) => Status::Ignored,
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
}
