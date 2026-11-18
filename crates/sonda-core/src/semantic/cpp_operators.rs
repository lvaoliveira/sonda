//! Binary operators a C++ file defines outside any class, for the rule
//! that asks for them as hidden friends (`cpp/operator-hidden-friend`):
//! whether a parameter's type is one of the project's classes, rather than
//! an enumeration or a library's type, takes the project's index.

use super::cpp_index::{compact_text, named, node_text, span_of, without_template_arguments};
use super::cs_index::Span;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tree_sitter::Node;

/// A free binary operator and the types of its parameters that could be a
/// class of the project.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub(crate) struct OperatorSite {
    pub(crate) span: Span,
    /// The namespaces it's defined in, to resolve `types` from.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) scope: Vec<String>,
    /// Its parameters' types as written, without `const`, references and
    /// template arguments: `Box`, `ns::Color`.
    pub(crate) types: Vec<String>,
}

/// How many operators a file may record.
const MAX_SITES: usize = 1_000;

/// Operators C++ lets a class's friend define, two operands each. Not `!=`,
/// which C++20 derives from `==`.
const BINARY: &[&str] = &[
    "==", "<", ">", "<=", ">=", "<=>", "+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>",
];

/// The free binary operators the file defines, outside any class.
pub(crate) fn sites(root: Node, src: &[u8], deadline: Instant) -> Vec<OperatorSite> {
    let mut found = Vec::new();
    walk(root, src, deadline, &mut Vec::new(), &mut found);
    found
}

fn walk(
    n: Node,
    src: &[u8],
    deadline: Instant,
    scope: &mut Vec<String>,
    found: &mut Vec<OperatorSite>,
) {
    if found.len() >= MAX_SITES || Instant::now() > deadline {
        return;
    }
    match n.kind() {
        // A member, or a friend already.
        "class_specifier" | "struct_specifier" | "union_specifier" | "compound_statement" => {}
        "namespace_definition" => {
            let depth = scope.len();
            match n.child_by_field_name("name") {
                Some(name) => scope.extend(
                    node_text(src, name)
                        .split("::")
                        .map(|s| s.trim().to_string()),
                ),
                None => scope.push(String::new()),
            }
            for c in named(n) {
                walk(c, src, deadline, scope, found);
            }
            scope.truncate(depth);
        }
        "function_definition" => {
            if let Some(site) = operator_site(n, src, scope) {
                found.push(site);
            }
        }
        _ => {
            for c in named(n) {
                walk(c, src, deadline, scope, found);
            }
        }
    }
}

/// A binary operator taking two parameters, with the types among them that
/// could be a class: neither built in nor the standard library's.
fn operator_site(function: Node, src: &[u8], scope: &[String]) -> Option<OperatorSite> {
    // Through the `&` or `*` of the type it returns.
    let mut d = function.child_by_field_name("declarator")?;
    while d.kind() != "function_declarator" {
        d = d
            .child_by_field_name("declarator")
            .or_else(|| named(d).into_iter().last())?;
    }
    let name = d.child_by_field_name("declarator")?;
    if name.kind() != "operator_name" {
        return None;
    }
    let op = compact_text(src, name);
    if !op
        .strip_prefix("operator")
        .is_some_and(|o| BINARY.contains(&o))
    {
        return None;
    }
    let params: Vec<Node> = named(d.child_by_field_name("parameters")?)
        .into_iter()
        .filter(|p| p.kind() == "parameter_declaration")
        .collect();
    if params.len() != 2 {
        return None;
    }
    let types: Vec<String> = params
        .iter()
        .filter_map(|p| p.child_by_field_name("type"))
        .filter(|t| {
            matches!(
                t.kind(),
                "type_identifier" | "qualified_identifier" | "template_type"
            )
        })
        .map(|t| without_template_arguments(&compact_text(src, t)))
        .filter(|t| !t.starts_with("std::"))
        .collect();
    (!types.is_empty()).then(|| OperatorSite {
        span: span_of(function),
        scope: scope.to_vec(),
        types,
    })
}
