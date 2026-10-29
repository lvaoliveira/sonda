mod catalog;

use crate::config::RulesConfig;
use crate::lang::Lang;
use crate::model::{Category, Severity};
use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use tree_sitter::{Node, Query};

pub use catalog::RULES;

pub const COGNITIVE_COMPLEXITY: &str = "common/cognitive-complexity";
pub const FUNCTION_LENGTH: &str = "common/function-length";
pub const TOO_MANY_PARAMETERS: &str = "common/too-many-parameters";
pub const TODO_COMMENT: &str = "common/todo-comment";

/// Extra check on the node captured as `@match`; the issue is reported
/// only when the filter returns true.
pub type Filter = fn(Node, &[u8]) -> bool;

pub enum Check {
    /// A tree-sitter query; every `@match` capture becomes an issue.
    Query {
        langs: &'static [Lang],
        query: &'static str,
        filter: Option<Filter>,
    },
    /// Implemented in `analysis.rs`, applies to every language.
    Structural,
}

/// Snippets that the rule must flag (`bad`) and must leave alone (`good`).
/// Every query rule has one; the test suite runs them all.
pub struct Example {
    pub lang: Lang,
    pub bad: &'static str,
    pub good: &'static str,
}

pub struct Rule {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    /// Issue message for query rules; structural rules build their own.
    pub message: &'static str,
    pub category: Category,
    pub severity: Severity,
    /// Estimated time to fix one occurrence, summed into technical debt.
    pub effort_minutes: u32,
    pub check: Check,
    pub example: Option<Example>,
}

impl Rule {
    pub fn langs(&self) -> &'static [Lang] {
        match self.check {
            Check::Query { langs, .. } => langs,
            Check::Structural => crate::lang::ALL,
        }
    }
}

pub fn find(id: &str) -> Option<&'static Rule> {
    RULES.iter().find(|r| r.id == id)
}

pub struct ActiveRule {
    pub rule: &'static Rule,
    pub severity: Severity,
}

pub struct CompiledQuery {
    pub active: usize,
    pub query: Query,
    pub match_capture: u32,
    pub filter: Option<Filter>,
}

/// The enabled rules with their effective severity and compiled queries.
pub struct RuleSet {
    pub active: Vec<ActiveRule>,
    queries: HashMap<Lang, Vec<CompiledQuery>>,
}

impl RuleSet {
    pub fn new(cfg: &RulesConfig) -> Result<Self> {
        for id in cfg.disabled.iter().chain(cfg.severity.keys()) {
            if find(id).is_none() {
                bail!("unknown rule '{id}' in config (run `sonda rules` to list them)");
            }
        }
        let active: Vec<ActiveRule> = RULES
            .iter()
            .filter(|r| !cfg.disabled.iter().any(|d| d == r.id))
            .map(|rule| ActiveRule {
                rule,
                severity: cfg.severity.get(rule.id).copied().unwrap_or(rule.severity),
            })
            .collect();

        let mut queries: HashMap<Lang, Vec<CompiledQuery>> = HashMap::new();
        for (idx, a) in active.iter().enumerate() {
            if let Check::Query {
                langs,
                query,
                filter,
            } = a.rule.check
            {
                for &lang in langs {
                    let compiled = compile(a.rule.id, lang, query, idx, filter)?;
                    queries.entry(lang).or_default().push(compiled);
                }
            }
        }
        Ok(RuleSet { active, queries })
    }

    pub fn queries(&self, lang: Lang) -> &[CompiledQuery] {
        self.queries.get(&lang).map(Vec::as_slice).unwrap_or(&[])
    }

    pub fn get(&self, id: &str) -> Option<&ActiveRule> {
        self.active.iter().find(|a| a.rule.id == id)
    }
}

fn compile(
    id: &str,
    lang: Lang,
    source: &str,
    active: usize,
    filter: Option<Filter>,
) -> Result<CompiledQuery> {
    let query = Query::new(&lang.grammar(), source)
        .with_context(|| format!("rule {id}: query does not compile for {}", lang.name()))?;
    let match_capture = query
        .capture_index_for_name("match")
        .with_context(|| format!("rule {id}: query has no @match capture"))?;
    Ok(CompiledQuery {
        active,
        query,
        match_capture,
        filter,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::analyze;
    use crate::analysis::tests::far_deadline;
    use crate::config::Config;

    #[test]
    fn rule_ids_are_unique_and_prefixed() {
        let mut ids: Vec<_> = RULES.iter().map(|r| r.id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), RULES.len(), "duplicate rule id");
        for r in RULES {
            assert!(r.id.contains('/'), "{} needs a family prefix", r.id);
        }
    }

    #[test]
    fn every_query_rule_has_an_example_in_one_of_its_languages() {
        for r in RULES {
            if let Check::Query { langs, .. } = r.check {
                let ex = r
                    .example
                    .as_ref()
                    .unwrap_or_else(|| panic!("{} has no example", r.id));
                assert!(
                    langs.contains(&ex.lang),
                    "{}: example language not covered",
                    r.id
                );
            }
        }
    }

    #[test]
    fn examples_flag_bad_code_and_accept_good_code() {
        let cfg = Config::default();
        let rules = RuleSet::new(&cfg.rules).expect("all queries compile");
        for r in RULES {
            let Some(ex) = &r.example else { continue };
            let bad = analyze("bad", ex.lang, ex.bad, &rules, &cfg, far_deadline()).unwrap();
            assert!(
                bad.issues.iter().any(|i| i.rule == r.id),
                "{} did not flag its bad example:\n{}\nissues: {:?}",
                r.id,
                ex.bad,
                bad.issues.iter().map(|i| i.rule).collect::<Vec<_>>()
            );
            let good = analyze("good", ex.lang, ex.good, &rules, &cfg, far_deadline()).unwrap();
            assert!(
                !good.issues.iter().any(|i| i.rule == r.id),
                "{} flagged its good example:\n{}",
                r.id,
                ex.good
            );
        }
    }

    #[test]
    fn unknown_rule_in_config_fails_loudly() {
        let cfg = RulesConfig {
            disabled: vec!["js/does-not-exist".into()],
            ..Default::default()
        };
        assert!(RuleSet::new(&cfg).is_err());
    }
}
