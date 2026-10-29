use crate::measures::Measures;
use serde::{Deserialize, Serialize};

/// The gate fails when `metric <op> threshold` holds.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    pub metric: String,
    pub op: Op,
    pub threshold: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Op {
    Gt,
    Lt,
}

impl Op {
    pub fn symbol(self) -> &'static str {
        match self {
            Op::Gt => ">",
            Op::Lt => "<",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
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

pub fn evaluate(conditions: &[Condition], measures: &Measures) -> GateResult {
    let results: Vec<ConditionResult> = conditions
        .iter()
        .map(|c| {
            let actual = measures.get(c.metric.as_str()).copied().flatten();
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

    #[test]
    fn evaluates_conditions() {
        let measures = Measures::from([
            ("new_bugs", Some(2.0)),
            ("new_coverage", None),
            ("coverage", Some(90.0)),
        ]);
        let cond = |metric: &str, op, threshold| Condition {
            metric: metric.into(),
            op,
            threshold,
        };
        let r = evaluate(
            &[
                cond("new_bugs", Op::Gt, 0.0),
                cond("new_coverage", Op::Lt, 80.0),
                cond("coverage", Op::Lt, 80.0),
            ],
            &measures,
        );
        assert!(!r.passed);
        let statuses: Vec<_> = r.conditions.iter().map(|c| c.status).collect();
        assert_eq!(statuses, vec![Status::Error, Status::NoData, Status::Ok]);
    }
}
