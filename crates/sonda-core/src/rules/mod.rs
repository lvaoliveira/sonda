mod catalog;

use crate::config::RulesConfig;
use crate::error::Error;
use crate::lang::Lang;
use crate::model::{Category, Severity};
use std::sync::OnceLock;
use tree_sitter::{Node, Query};

pub use catalog::RULES;

pub(crate) const COGNITIVE_COMPLEXITY: &str = "common/cognitive-complexity";
pub(crate) const FUNCTION_LENGTH: &str = "common/function-length";
pub(crate) const TOO_MANY_PARAMETERS: &str = "common/too-many-parameters";
pub(crate) const TODO_COMMENT: &str = "common/todo-comment";

/// Extra check on the node captured as `@match`; the issue is reported
/// only when the filter returns true.
pub(crate) type Filter = fn(Node, &[u8]) -> bool;

pub(crate) enum Check {
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
    /// Noncompliant code.
    pub bad: &'static str,
    /// Compliant code.
    pub good: &'static str,
}

/// A SonarQube rule this one corresponds to, by its key without the
/// language prefix (`S3776`). Keys are references only: no SonarSource text
/// or code is used (ADR-0007).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SonarRef {
    pub key: &'static str,
    /// Same intent and scope. False when the rules overlap but differ, for
    /// example a syntactic check for what SonarQube does with taint analysis.
    pub exact: bool,
}

pub(crate) const fn exact(key: &'static str) -> SonarRef {
    SonarRef { key, exact: true }
}

pub(crate) const fn related(key: &'static str) -> SonarRef {
    SonarRef { key, exact: false }
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
    /// The SonarQube rules this one corresponds to, in the languages it covers.
    pub sonar: &'static [SonarRef],
    pub(crate) check: Check,
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
    RULES.iter().find(|r| r.id == id).copied()
}

pub(crate) struct ActiveRule {
    pub(crate) rule: &'static Rule,
    pub(crate) severity: Severity,
}

pub(crate) struct CompiledQuery {
    pub(crate) active: usize,
    pub(crate) query: Query,
    pub(crate) match_capture: u32,
    pub(crate) filter: Option<Filter>,
}

/// The enabled rules with their effective severity. Queries are compiled
/// per language on first use: compiling all of them costs ~70 ms, mostly for
/// TypeScript and C++, which many projects never contain (and every worker
/// process would pay it again).
pub(crate) struct RuleSet {
    pub(crate) active: Vec<ActiveRule>,
    /// Indexed by `Lang::index`.
    queries: Vec<OnceLock<Result<Vec<CompiledQuery>, String>>>,
}

impl RuleSet {
    pub(crate) fn new(cfg: &RulesConfig) -> Result<Self, Error> {
        // Sorted, so the reported unknown id does not depend on HashMap order.
        let mut ids: Vec<&String> = cfg.disabled.iter().chain(cfg.severity.keys()).collect();
        ids.sort();
        if let Some(id) = ids.into_iter().find(|id| find(id).is_none()) {
            return Err(Error::Config(format!(
                "unknown rule '{id}' (run `sonda rules` to list them)"
            )));
        }
        let active: Vec<ActiveRule> = RULES
            .iter()
            .filter(|r| !cfg.disabled.iter().any(|d| d == r.id))
            .map(|&rule| ActiveRule {
                rule,
                severity: cfg.severity.get(rule.id).copied().unwrap_or(rule.severity),
            })
            .collect();

        let queries = crate::lang::ALL.iter().map(|_| OnceLock::new()).collect();
        Ok(RuleSet { active, queries })
    }

    /// The compiled queries of the active rules for `lang`. An error means a
    /// built-in query does not compile: a bug, which tests guard against.
    pub(crate) fn queries(&self, lang: Lang) -> Result<&[CompiledQuery], String> {
        let slot = &self.queries[usize::from(lang.index())];
        slot.get_or_init(|| self.compile_for(lang))
            .as_deref()
            .map_err(Clone::clone)
    }

    fn compile_for(&self, lang: Lang) -> Result<Vec<CompiledQuery>, String> {
        let mut compiled = Vec::new();
        for (idx, a) in self.active.iter().enumerate() {
            if let Check::Query {
                langs,
                query,
                filter,
            } = a.rule.check
                && langs.contains(&lang)
            {
                compiled
                    .push(compile(a.rule.id, lang, query, idx, filter).map_err(|e| e.to_string())?);
            }
        }
        Ok(compiled)
    }

    pub(crate) fn get(&self, id: &str) -> Option<&ActiveRule> {
        self.active.iter().find(|a| a.rule.id == id)
    }
}

fn compile(
    id: &str,
    lang: Lang,
    source: &str,
    active: usize,
    filter: Option<Filter>,
) -> Result<CompiledQuery, Error> {
    let query = Query::new(&lang.grammar(), source).map_err(|e| {
        Error::Internal(format!(
            "rule {id}: query does not compile for {}: {e}",
            lang.name()
        ))
    })?;
    let match_capture = query
        .capture_index_for_name("match")
        .ok_or_else(|| Error::Internal(format!("rule {id}: query has no @match capture")))?;
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

    /// ADR-0007: keys are bare (`S3504`, not `javascript:S3504`), and a rule
    /// names each one once.
    #[test]
    fn sonar_references_are_well_formed() {
        for r in RULES.iter() {
            let mut seen = std::collections::HashSet::new();
            for s in r.sonar {
                assert!(
                    !s.key.is_empty()
                        && !s.key.contains(':')
                        && s.key.chars().all(|c| c.is_ascii_alphanumeric()),
                    "{}: bad SonarQube key {:?}",
                    r.id,
                    s.key
                );
                assert!(seen.insert(s.key), "{}: {} listed twice", r.id, s.key);
            }
        }
    }

    #[test]
    fn rule_ids_are_unique_and_prefixed() {
        let mut ids: Vec<_> = RULES.iter().map(|r| r.id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), RULES.len(), "duplicate rule id");
        for r in RULES.iter() {
            assert!(r.id.contains('/'), "{} needs a family prefix", r.id);
        }
    }

    #[test]
    fn every_query_rule_has_an_example_in_one_of_its_languages() {
        for r in RULES.iter() {
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
        for r in RULES.iter() {
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

    /// Queries compile lazily, so nothing at startup proves they compile:
    /// this does, for every language each rule claims.
    #[test]
    fn every_query_compiles_for_every_language() {
        let rules = RuleSet::new(&RulesConfig::default()).unwrap();
        for &lang in crate::lang::ALL {
            let compiled = rules
                .queries(lang)
                .unwrap_or_else(|e| panic!("{lang:?}: {e}"));
            let expected = RULES
                .iter()
                .filter(|r| matches!(r.check, Check::Query { langs, .. } if langs.contains(&lang)))
                .count();
            assert_eq!(compiled.len(), expected, "{lang:?}");
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
