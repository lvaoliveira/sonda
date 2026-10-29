use crate::measures::Measures;
use crate::model::{Condition, Op};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    Error,
    /// The metric has no value (e.g. coverage without a report); not counted as failing.
    NoData,
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
    let results: Vec<ConditionResult> = conditions
        .iter()
        .map(|c| {
            let actual = measures.get(&c.metric).copied().flatten();
            let status = match actual {
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
    use crate::model::Metric;

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
}
