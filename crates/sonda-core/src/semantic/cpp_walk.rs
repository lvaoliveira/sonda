//! Walking a C++ file to its function definitions, with the class each is
//! a member of, for the parts of the file's summary (`cpp_index`) that look
//! into function bodies: byte operations (`cpp_bytes`), what member
//! functions change (`cpp_const`).

use super::cpp_index::{compact_text, named, node_text, without_template_arguments};
use std::time::Instant;
use tree_sitter::Node;

/// The class a function is a member of, as written, with the scope to
/// resolve that from.
#[derive(Clone)]
pub(super) struct Owner {
    pub(super) class: String,
    pub(super) scope: Vec<String>,
    /// The fields the class's body declares, with their types, when the
    /// function is defined in it: they need no index.
    pub(super) fields: Vec<(String, String)>,
}

/// Calls `visit` with each function definition and the class it's a member
/// of, if any, until `visit` returns false or the deadline passes.
pub(super) fn functions(
    root: Node,
    src: &[u8],
    deadline: Instant,
    visit: &mut dyn FnMut(Node, Option<&Owner>) -> bool,
) {
    let mut w = Walker {
        src,
        deadline,
        visit,
        go_on: true,
    };
    w.walk(root, &mut Vec::new(), None);
}

struct Walker<'s, 'v> {
    src: &'s [u8],
    deadline: Instant,
    visit: &'v mut dyn FnMut(Node, Option<&Owner>) -> bool,
    go_on: bool,
}

impl Walker<'_, '_> {
    fn walk(&mut self, n: Node, scope: &mut Vec<String>, class: Option<&Owner>) {
        if !self.go_on || Instant::now() > self.deadline {
            return;
        }
        match n.kind() {
            "namespace_definition" => {
                let depth = scope.len();
                match n.child_by_field_name("name") {
                    Some(name) => scope.extend(
                        node_text(self.src, name)
                            .split("::")
                            .map(|s| s.trim().to_string()),
                    ),
                    None => scope.push(String::new()),
                }
                for c in named(n) {
                    self.walk(c, scope, class);
                }
                scope.truncate(depth);
            }
            "class_specifier" | "struct_specifier" => self.class(n, scope, class),
            "function_definition" => {
                let owner = owner(self.src, n, scope, class);
                self.go_on = (self.visit)(n, owner.as_ref());
            }
            _ => {
                for c in named(n) {
                    self.walk(c, scope, class);
                }
            }
        }
    }

    fn class(&mut self, n: Node, scope: &mut Vec<String>, class: Option<&Owner>) {
        let Some(name) = n.child_by_field_name("name") else {
            for c in named(n) {
                self.walk(c, scope, class);
            }
            return;
        };
        let simple = match name.kind() {
            "template_type" | "qualified_identifier" => {
                name.child_by_field_name("name").unwrap_or(name)
            }
            _ => name,
        };
        let context = Owner {
            class: node_text(self.src, simple).to_string(),
            scope: scope.clone(),
            fields: n
                .child_by_field_name("body")
                .map(|body| fields(self.src, body))
                .unwrap_or_default(),
        };
        scope.push(context.class.clone());
        for c in named(n) {
            self.walk(c, scope, Some(&context));
        }
        scope.pop();
    }
}

/// The class a function is a member of: the one it's defined in, or the
/// one its name qualifies (`void Spec::draw()`).
fn owner(src: &[u8], function: Node, scope: &[String], class: Option<&Owner>) -> Option<Owner> {
    let d = function_declarator(function)?;
    let name = d.child_by_field_name("declarator")?;
    if name.kind() == "qualified_identifier" {
        let scope_text = compact_text(src, name.child_by_field_name("scope")?);
        return Some(Owner {
            class: without_template_arguments(&scope_text),
            scope: scope.to_vec(),
            fields: Vec::new(),
        });
    }
    class.cloned()
}

/// A function definition's declarator, through the `*` and `&` of its
/// return type.
pub(super) fn function_declarator(function: Node) -> Option<Node> {
    let mut d = function.child_by_field_name("declarator")?;
    for _ in 0..8 {
        if d.kind() == "function_declarator" {
            return Some(d);
        }
        if !matches!(d.kind(), "pointer_declarator" | "reference_declarator") {
            return None;
        }
        d = d
            .child_by_field_name("declarator")
            .or_else(|| named(d).into_iter().last())?;
    }
    None
}

/// The data members a class body declares, with their types.
fn fields(src: &[u8], body: Node) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for member in named(body) {
        if member.kind() != "field_declaration" {
            continue;
        }
        let Some(ty) = member.child_by_field_name("type") else {
            continue;
        };
        let before: String = String::from_utf8_lossy(&src[member.start_byte()..ty.end_byte()])
            .split_whitespace()
            .collect();
        let mut cursor = member.walk();
        for d in member.children_by_field_name("declarator", &mut cursor) {
            if let (Some(name), suffix) = declared(d) {
                out.push((node_text(src, name).to_string(), before.clone() + &suffix));
            }
        }
    }
    out
}

/// The name a declarator declares, and what it adds to the type: `*`, `&`,
/// `[]`.
pub(super) fn declared(d: Node) -> (Option<Node>, String) {
    let mut suffix = String::new();
    let mut d = d;
    for _ in 0..8 {
        match d.kind() {
            "identifier" | "field_identifier" => return (Some(d), suffix),
            "pointer_declarator" => suffix.push('*'),
            "reference_declarator" => suffix.push('&'),
            "array_declarator" => suffix.push_str("[]"),
            "init_declarator" => {}
            _ => return (None, suffix),
        }
        match d
            .child_by_field_name("declarator")
            .or_else(|| named(d).into_iter().next())
        {
            Some(next) => d = next,
            None => return (None, suffix),
        }
    }
    (None, suffix)
}
