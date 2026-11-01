//! The rule catalog, one module per language. Each rule records the
//! SonarQube rules it corresponds to (ADR-0007).

mod c;
mod common;
mod cs;
mod cs_security;
mod java;
mod java_bugs;
mod java_extra;
mod java_final;
mod java_last;
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

/// Every rule, in a fixed order (structural rules first, then by language),
/// so reports and docs/rules.md stay deterministic.
pub static RULES: LazyLock<Vec<&'static Rule>> = LazyLock::new(|| {
    [
        common::RULES,
        js::RULES,
        js_security::RULES,
        js_modern::RULES,
        js_a11y::RULES,
        js_extra::RULES,
        js_more::RULES,
        js_semantic::RULES,
        py::RULES,
        py_security::RULES,
        py_quality::RULES,
        py_more::RULES,
        py_extra::RULES,
        py_cdk::RULES,
        py_regex::RULES,
        py_last::RULES,
        java::RULES,
        java_security::RULES,
        java_bugs::RULES,
        java_smells::RULES,
        java_more::RULES,
        java_tests::RULES,
        java_extra::RULES,
        java_regex::RULES,
        java_last::RULES,
        java_final::RULES,
        java_tail::RULES,
        java_rest::RULES,
        c::RULES,
        cs::RULES,
        cs_security::RULES,
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
    // Pattern matching for instanceof and Stream.toList() need Java 16, and
    // sonda cannot see which version a project targets.
    "java/instanceof-then-cast",
    "java/collectors-to-list",
    // Style rules that fire on most real Python: every method that skips
    // self, every untyped signature, every trailing comment. Python 3.14
    // moved the compression modules, which most projects don't target yet.
    "py/method-could-be-static",
    "py/hint-missing-return",
    "py/hint-missing-parameter",
    "py/compression-namespace",
    // Documentation and licence-header policies are a project decision.
    "py/missing-docstring",
    "py/missing-license-header",
    // Formatting rules a formatter or editor config already enforces.
    "common/trailing-whitespace",
    "common/line-length",
    "common/file-length",
    "common/final-newline",
    "common/tab-character",
    "common/trailing-comment",
    // Java style rules outside SonarQube's default profile that fire on most
    // real code: escaped Unicode, suppressions, public fields, boolean
    // parameters, legacy collections, brace and else conventions.
    "java/unicode-escape",
    "java/suppress-warnings",
    "java/boolean-selector",
    "java/public-field",
    "java/synchronized-collections",
    "java/if-else-if-without-else",
    "java/missing-braces",
    // High-volume conventions outside SonarQube's default profile: test
    // names, missing Javadoc, ternaries, number formatting, varargs, size
    // and complexity limits, static imports and pattern compilation.
    "java/test-method-name",
    "java/public-api-undocumented",
    "java/ternary-operator",
    "java/large-number-underscores",
    "java/varargs-declared",
    "java/inner-class-too-long",
    "java/too-many-returns",
    "java/private-method-not-static",
    "java/pattern-compiled-in-method",
    "java/static-imports-many",
    "java/method-complexity",
    "java/too-many-methods",
    "java/nesting-depth",
    "java/expression-complexity",
    // Conventions outside SonarQube's default profile (batch 13): they fire
    // on nearly every file of a typical code base.
    "java/exact-alarm",
    "java/redundant-explicit-type",
    "java/clock-in-test",
    "java/collect-with-add",
    "java/throws-many-checked",
    "java/throws-checked",
    "java/qualified-name",
    "java/one-type-per-file",
    "java/package-private-field",
    "java/boolean-method-name",
    "java/local-constant-name",
    "java/junit4-import",
    "java/operator-precedence",
    "java/increment-in-expression",
    "java/magic-number",
    "java/test-assertion-message",
    // Java 22 syntax: older code bases cannot adopt it.
    "java/unused-exception-parameter",
    // Brace layout, member order, licence headers and similar policies: a
    // project picks one convention (several of these contradict each other).
    "java/brace-on-its-own-line",
    "java/brace-at-line-end",
    "java/else-on-another-line",
    "java/else-on-the-same-line",
    "java/closing-brace-not-first",
    "java/member-order",
    "java/missing-license-header",
    "java/functional-interface-redefined",
    "java/get-class-loader",
    "java/loops-over-same-collection",
    "java/lambda-explicit-types",
    "java/inner-class-static",
    // Outside SonarQube's default C# profile.
    "cs/protected-in-sealed",
    "cs/redundant-constructor",
    "cs/empty-string-comparison",
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
