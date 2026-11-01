//! The rule catalog, one module per language. Each rule records the
//! SonarQube rules it corresponds to (ADR-0007).

mod c;
mod common;
mod cs;
mod cs_bugs;
mod cs_classes;
mod cs_extra;
mod cs_final;
mod cs_more;
mod cs_opt;
mod cs_opt2;
mod cs_opt3;
mod cs_security;
mod cs_smells;
mod cs_tail;
mod cs_typed;
mod cs_types;
mod java;
mod java_bugs;
mod java_close;
mod java_end;
mod java_extra;
mod java_final;
mod java_final2;
mod java_flow;
mod java_last;
mod java_last2;
mod java_more;
mod java_regex;
mod java_rest;
mod java_security;
mod java_smells;
mod java_tail;
mod java_tests;
mod js;
mod js_a11y;
mod js_extra;
mod js_modern;
mod js_more;
mod js_security;
mod js_semantic;
mod js_syntax;
mod js_syntax2;
mod py;
mod py_cdk;
mod py_extra;
mod py_last;
mod py_more;
mod py_quality;
mod py_regex;
mod py_security;
mod regex_checks;
pub(super) mod standards;

pub(super) use super::Filter::{Find, Keep};
pub(super) use super::{Check, Example, Rule, exact, related};
pub(super) use crate::lang::{C_CPP, C_ONLY, CSHARP, JAVA, JS_TS, JSX, Lang, PYTHON, TS};
pub(super) use crate::model::Category::{Bug, CodeSmell, Vulnerability};
pub(super) use crate::model::Severity::{Blocker, Critical, Info, Major, Minor};
use std::sync::LazyLock;
pub(super) use tree_sitter::Node;

/// Every catalog module, in a fixed order (structural rules first, then by
/// language), so reports and docs/rules.md stay deterministic: its rules,
/// and which of them are off by default. A module lists its own
/// off-by-default rules next to their definitions, so a new module only
/// adds its line here.
static MODULES: &[(&[Rule], &[&str])] = &[
    (common::RULES, common::OFF_BY_DEFAULT),
    (js::RULES, &[]),
    (js_security::RULES, &[]),
    (js_modern::RULES, &[]),
    (js_a11y::RULES, &[]),
    (js_extra::RULES, &[]),
    (js_more::RULES, &[]),
    (js_semantic::RULES, js_semantic::OFF_BY_DEFAULT),
    (js_syntax::RULES, js_syntax::OFF_BY_DEFAULT),
    (js_syntax2::RULES, js_syntax2::OFF_BY_DEFAULT),
    (py::RULES, &[]),
    (py_security::RULES, &[]),
    (py_quality::RULES, &[]),
    (py_more::RULES, &[]),
    (py_extra::RULES, py_extra::OFF_BY_DEFAULT),
    (py_cdk::RULES, &[]),
    (py_regex::RULES, &[]),
    (py_last::RULES, py_last::OFF_BY_DEFAULT),
    (java::RULES, &[]),
    (java_security::RULES, &[]),
    (java_bugs::RULES, &[]),
    (java_smells::RULES, java_smells::OFF_BY_DEFAULT),
    (java_more::RULES, &[]),
    (java_tests::RULES, &[]),
    (java_extra::RULES, java_extra::OFF_BY_DEFAULT),
    (java_regex::RULES, java_regex::OFF_BY_DEFAULT),
    (java_last::RULES, java_last::OFF_BY_DEFAULT),
    (java_final::RULES, java_final::OFF_BY_DEFAULT),
    (java_tail::RULES, java_tail::OFF_BY_DEFAULT),
    (java_rest::RULES, &[]),
    (java_flow::RULES, java_flow::OFF_BY_DEFAULT),
    (java_end::RULES, java_end::OFF_BY_DEFAULT),
    (java_close::RULES, java_close::OFF_BY_DEFAULT),
    (java_last2::RULES, java_last2::OFF_BY_DEFAULT),
    (java_final2::RULES, java_final2::OFF_BY_DEFAULT),
    (c::RULES, &[]),
    (cs::RULES, cs::OFF_BY_DEFAULT),
    (cs_security::RULES, &[]),
    (cs_bugs::RULES, &[]),
    (cs_smells::RULES, cs_smells::OFF_BY_DEFAULT),
    (cs_more::RULES, cs_more::OFF_BY_DEFAULT),
    (cs_extra::RULES, cs_extra::OFF_BY_DEFAULT),
    (cs_final::RULES, cs_final::OFF_BY_DEFAULT),
    (cs_tail::RULES, cs_tail::OFF_BY_DEFAULT),
    (cs_opt::RULES, cs_opt::OFF_BY_DEFAULT),
    (cs_opt2::RULES, cs_opt2::OFF_BY_DEFAULT),
    (cs_opt3::RULES, cs_opt3::OFF_BY_DEFAULT),
    (cs_typed::RULES, cs_typed::OFF_BY_DEFAULT),
    (cs_classes::RULES, cs_classes::OFF_BY_DEFAULT),
];

/// Every rule, in `MODULES` order.
pub static RULES: LazyLock<Vec<&'static Rule>> =
    LazyLock::new(|| MODULES.iter().flat_map(|(rules, _)| rules.iter()).collect());

/// CWE ids and OWASP categories by rule id.
pub(super) fn standards(id: &str) -> super::Standards {
    // The 2025 categories, derived once from each rule's CWE ids.
    static DERIVED: LazyLock<Vec<Vec<super::Owasp>>> = LazyLock::new(|| {
        standards::STANDARDS
            .iter()
            .map(|(_, cwe, _)| super::owasp::from_cwe_2025(cwe))
            .collect()
    });
    match standards::STANDARDS
        .iter()
        .position(|(rule, ..)| *rule == id)
    {
        Some(i) => {
            let (_, cwe, owasp_2021) = standards::STANDARDS[i];
            super::Standards {
                cwe,
                owasp_2021,
                owasp_2025: &DERIVED[i],
            }
        }
        None => super::Standards::default(),
    }
}

/// Rules that are off unless `rules.enabled` lists them: those outside
/// SonarQube's default profile that report style choices many codebases
/// make on purpose. Each module lists its own (`OFF_BY_DEFAULT`).
pub(super) static OFF_BY_DEFAULT: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    MODULES
        .iter()
        .flat_map(|(_, off)| off.iter().copied())
        .collect()
});

// ---------------------------------------------------- shared filters

pub(super) fn empty_block(node: Node, _: &[u8]) -> bool {
    // Comments are named nodes, so a block holding only a comment is not empty.
    node.named_child_count() == 0
}

pub(super) fn not_nullish_comparison(operator: Node, src: &[u8]) -> bool {
    let Some(expr) = operator.parent() else {
        return true;
    };
    let nullish = |field: &str| {
        expr.child_by_field_name(field).is_some_and(|n| {
            matches!(n.kind(), "null" | "undefined") || n.utf8_text(src) == Ok("undefined")
        })
    };
    !nullish("left") && !nullish("right")
}

pub(super) fn bare_except(node: Node, _: &[u8]) -> bool {
    node.named_child(0).is_some_and(|c| c.kind() == "block")
}

pub(super) fn has_equality_operator(node: Node, _: &[u8]) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .any(|c| matches!(c.kind(), "==" | "!="))
}

pub(super) fn has_string_literal_operand(node: Node, _: &[u8]) -> bool {
    ["left", "right"].iter().any(|f| {
        node.child_by_field_name(f)
            .is_some_and(|n| n.kind() == "string_literal")
    })
}

pub(super) fn no_arguments(node: Node, _: &[u8]) -> bool {
    node.child_by_field_name("arguments")
        .is_some_and(|a| a.named_child_count() == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A module lists only its own rules as off by default, so the list
    /// stays next to the rules it describes.
    #[test]
    fn modules_list_only_their_own_rules_as_off_by_default() {
        for (rules, off) in MODULES {
            for id in *off {
                assert!(
                    rules.iter().any(|r| r.id == *id),
                    "{id} is off by default in a module that doesn't define it"
                );
            }
        }
    }
}
