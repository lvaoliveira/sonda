//! The rule catalog, one module per language. Each rule records the
//! SonarQube rules it corresponds to (ADR-0007).

mod c;
mod common;
mod java;
mod js;
mod js_a11y;
mod js_modern;
mod js_security;
mod js_semantic;
mod py;
pub(super) mod standards;

pub(super) use super::Filter::{Find, Keep};
pub(super) use super::{Check, Example, Rule, exact, related};
pub(super) use crate::lang::{C_CPP, C_ONLY, JAVA, JS_TS, JSX, Lang, PYTHON, TS};
pub(super) use crate::model::Category::{Bug, CodeSmell, Vulnerability};
pub(super) use crate::model::Severity::{Blocker, Critical, Info, Major, Minor};
use std::sync::LazyLock;
pub(super) use tree_sitter::Node;

/// Every rule, in a fixed order (structural rules first, then by language),
/// so reports and docs/rules.md stay deterministic.
pub static RULES: LazyLock<Vec<&'static Rule>> = LazyLock::new(|| {
    [
        common::RULES,
        js::RULES,
        js_security::RULES,
        js_modern::RULES,
        js_a11y::RULES,
        js_semantic::RULES,
        py::RULES,
        java::RULES,
        c::RULES,
    ]
    .into_iter()
    .flatten()
    .collect()
});

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
/// make on purpose.
pub(super) static OFF_BY_DEFAULT: &[&str] = &[
    "js/unused-parameter",
    "js/shadowed-variable",
    "js/prefer-const",
];

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
