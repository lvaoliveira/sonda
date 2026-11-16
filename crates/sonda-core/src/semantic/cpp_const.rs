//! What a C++ member function's body does to its object, for whether it
//! could be `const`: the names it writes that aren't its own locals, the
//! functions it calls on the object, the calls it makes on other objects,
//! and whether `this` or a member's address escapes. Part of the file's
//! summary (`cpp_index`): which of those names are fields, and which of
//! those functions are `const`, is the index's to say (ADR-0020), since the
//! class is usually declared in a header.

use super::cpp_index::{named, node_text, span_of};
use super::cpp_walk::{declared, function_declarator, functions};
use super::cs_index::Span;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tree_sitter::Node;

/// A non-static, non-const member function's body, summarized.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub(crate) struct MemberBody {
    /// The class it's a member of, as written, and the scope to resolve
    /// that from.
    pub(crate) class: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) scope: Vec<String>,
    pub(crate) name: String,
    /// The name, where an issue is reported.
    pub(crate) span: Span,
    /// Names it assigns or increments, through `.` and `[]` (`a_.x = 1`
    /// writes `a_`), that aren't its parameters or locals.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) writes: Vec<String>,
    /// Functions it calls unqualified or on `this`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) calls: Vec<String>,
    /// `x.f()` or `x->f()` on a name that isn't a parameter or local:
    /// (x, f).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) member_calls: Vec<(String, String)>,
    /// Non-local names passed to a call, which may change them through a
    /// pointer or reference parameter.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) passed: Vec<String>,
    /// `this` used other than as `this->`, a non-local's address taken, or
    /// a non-local returned by non-const reference: nothing more to tell.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) escapes: bool,
}

/// How many bodies a file may summarize.
const MAX_BODIES: usize = 5_000;

/// The file's member functions that might be const, summarized.
pub(crate) fn bodies(root: Node, src: &[u8], deadline: Instant) -> Vec<MemberBody> {
    let mut out = Vec::new();
    functions(root, src, deadline, &mut |function, owner| {
        if let Some(owner) = owner
            && let Some(body) = summarize(src, function, &owner.class, &owner.scope)
        {
            out.push(body);
        }
        out.len() < MAX_BODIES
    });
    out
}

/// The summary of `function`, a member of `class`, unless it can't be
/// `const` whatever it does: static, already const, virtual, a constructor
/// or destructor, without a body.
fn summarize(src: &[u8], function: Node, class: &str, scope: &[String]) -> Option<MemberBody> {
    let body = function.child_by_field_name("body")?;
    // A friend defined in the class isn't a member.
    if function
        .parent()
        .is_some_and(|p| p.kind() == "friend_declaration")
    {
        return None;
    }
    // Inside a parse error, what's a member is a guess.
    let mut up = function.parent();
    while let Some(p) = up {
        if p.is_error() {
            return None;
        }
        up = p.parent();
    }
    let returns_reference = function
        .child_by_field_name("declarator")
        .is_some_and(|d| d.kind() == "reference_declarator");
    let d = function_declarator(function)?;
    let name_node = d.child_by_field_name("declarator")?;
    let name = node_text(src, name_node);
    let simple = name.rsplit("::").next().unwrap_or(name);
    let class_simple = class.rsplit("::").next().unwrap_or(class);
    let words = |n: Node| -> Vec<&str> {
        let mut c = n.walk();
        n.children(&mut c).map(|w| node_text(src, w)).collect()
    };
    let own = words(function);
    let specifiers = words(d);
    let macro_name = simple.len() > 1
        && simple
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    if simple == class_simple
        || macro_name
        || simple.starts_with('~')
        || own
            .iter()
            .any(|w| matches!(*w, "static" | "virtual" | "friend"))
        || specifiers
            .iter()
            .any(|w| matches!(*w, "const" | "override" | "final"))
        || own.contains(&"=")
    {
        return None;
    }
    let return_type = function
        .child_by_field_name("type")
        .map_or("", |t| node_text(src, t));
    let mut summary = MemberBody {
        class: class.to_string(),
        scope: scope.to_vec(),
        name: simple.to_string(),
        span: span_of(name_node),
        ..MemberBody::default()
    };
    let locals = locals(src, function);
    let aliases = aliases(src, body, &locals);
    let mut stack = vec![body];
    while let Some(n) = stack.pop() {
        visit(src, n, &locals, &mut summary);
        stack.extend(named(n));
    }
    // Writing through a local that points into the object writes the
    // object: `roo::byte* p = buffer_; *p = 0;`.
    for (local, root) in aliases {
        if written_through(src, body, local) {
            summary.writes.push(root);
        }
    }
    // A non-const reference to something it holds.
    if returns_reference && !return_type.contains("const") {
        summary.escapes = true;
    }
    summary.writes.sort();
    summary.writes.dedup();
    summary.calls.sort();
    summary.calls.dedup();
    summary.member_calls.sort();
    summary.member_calls.dedup();
    summary.passed.sort();
    summary.passed.dedup();
    Some(summary)
}

/// Locals declared as pointers or references and initialized from a
/// non-local: (local, the non-local's name).
fn aliases<'s>(src: &'s [u8], body: Node, locals: &[&str]) -> Vec<(&'s str, String)> {
    let mut out = Vec::new();
    let mut stack = vec![body];
    while let Some(n) = stack.pop() {
        if n.kind() == "init_declarator"
            && let Some(d) = n.child_by_field_name("declarator")
            && matches!(d.kind(), "pointer_declarator" | "reference_declarator")
            && let (Some(name), _) = declared(d)
            && let Some(root) = n
                .child_by_field_name("value")
                .and_then(|v| written(src, v, locals))
        {
            out.push((node_text(src, name), root));
        }
        // `for (T& x : member_)`.
        if n.kind() == "for_range_loop"
            && let Some(d) = n.child_by_field_name("declarator")
            && d.kind() == "reference_declarator"
            && let (Some(name), _) = declared(d)
            && let Some(root) = n
                .child_by_field_name("right")
                .and_then(|v| written(src, v, locals))
        {
            out.push((node_text(src, name), root));
        }
        stack.extend(named(n));
    }
    out
}

/// Whether the body writes through `local`: assigns or increments `*local`,
/// `local[i]` or `local->x`.
fn written_through(src: &[u8], body: Node, local: &str) -> bool {
    let target = |n: Node| match n.kind() {
        "pointer_expression" | "subscript_expression" | "field_expression" => n
            .child_by_field_name("argument")
            .is_some_and(|a| node_text(src, a) == local),
        _ => false,
    };
    let mut stack = vec![body];
    while let Some(n) = stack.pop() {
        let lvalue = match n.kind() {
            "assignment_expression" => n.child_by_field_name("left"),
            "update_expression" => n.child_by_field_name("argument"),
            _ => None,
        };
        if lvalue.is_some_and(target) {
            return true;
        }
        // A call on it, `x.update()`: may change it.
        if n.kind() == "call_expression"
            && n.child_by_field_name("function").is_some_and(|f| {
                f.kind() == "field_expression"
                    && f.child_by_field_name("argument")
                        .is_some_and(|a| node_text(src, a) == local)
            })
        {
            return true;
        }
        stack.extend(named(n));
    }
    false
}

/// The names a function's parameters and locals declare.
fn locals<'s>(src: &'s [u8], function: Node) -> Vec<&'s str> {
    let mut out = Vec::new();
    let mut stack = vec![function];
    while let Some(n) = stack.pop() {
        if matches!(
            n.kind(),
            "declaration" | "parameter_declaration" | "optional_parameter_declaration"
        ) {
            let mut c = n.walk();
            for d in n.children_by_field_name("declarator", &mut c) {
                if let (Some(name), _) = declared(d) {
                    out.push(node_text(src, name));
                }
            }
        }
        // A structured binding, a range-for's variable, a lambda's
        // parameters and captures.
        if matches!(n.kind(), "for_range_loop" | "structured_binding_declarator")
            && let Some(d) = n.child_by_field_name("declarator")
            && let (Some(name), _) = declared(d)
        {
            out.push(node_text(src, name));
        }
        if n.kind() == "structured_binding_declarator" {
            out.extend(
                named(n)
                    .into_iter()
                    .filter(|c| c.kind() == "identifier")
                    .map(|c| node_text(src, c)),
            );
        }
        stack.extend(named(n));
    }
    out
}

/// What one node of the body does to the object.
fn visit(src: &[u8], n: Node, locals: &[&str], s: &mut MemberBody) {
    match n.kind() {
        "assignment_expression" => {
            if let Some(name) = n
                .child_by_field_name("left")
                .and_then(|l| written(src, l, locals))
            {
                s.writes.push(name);
            }
        }
        "update_expression" => {
            if let Some(name) = n
                .child_by_field_name("argument")
                .and_then(|a| written(src, a, locals))
            {
                s.writes.push(name);
            }
        }
        "call_expression" => call(src, n, locals, s),
        "this" => {
            let as_arrow = n.parent().is_some_and(|p| {
                p.kind() == "field_expression" && p.child_by_field_name("argument") == Some(n)
            });
            if !as_arrow {
                s.escapes = true;
            }
        }
        "pointer_expression" => {
            // `&member_`: its address may be written through.
            if n.child_by_field_name("operator")
                .is_some_and(|o| node_text(src, o) == "&")
                && n.child_by_field_name("argument")
                    .and_then(|a| written(src, a, locals))
                    .is_some()
            {
                s.escapes = true;
            }
        }
        _ => {}
    }
}

/// A call: on the object (`f()`, `this->f()`) or on a non-local (`x.f()`).
fn call(src: &[u8], n: Node, locals: &[&str], s: &mut MemberBody) {
    if let Some(args) = n.child_by_field_name("arguments") {
        s.passed.extend(
            named(args)
                .into_iter()
                .filter_map(|a| written(src, a, locals)),
        );
    }
    let Some(f) = n.child_by_field_name("function") else {
        return;
    };
    match f.kind() {
        "identifier" => {
            let name = node_text(src, f);
            if !locals.contains(&name) {
                s.calls.push(name.to_string());
            }
        }
        "field_expression" => {
            let (Some(object), Some(field)) = (
                f.child_by_field_name("argument"),
                f.child_by_field_name("field"),
            ) else {
                return;
            };
            let method = node_text(src, field).to_string();
            if object.kind() == "this" {
                s.calls.push(method);
                return;
            }
            // Through a pointer too, `p_->f()`: what a member points to
            // counts as the object's.
            if let Some(root) = written(src, object, locals) {
                s.member_calls.push((root, method));
            }
        }
        _ => {}
    }
}

/// The non-local name an lvalue writes: `a_` for `a_`, `a_.x`, `a_[i]`,
/// `a_->x`, `*a_`, `this->a_`; what a member points to counts as the
/// object's. Nothing for a local.
fn written(src: &[u8], lvalue: Node, locals: &[&str]) -> Option<String> {
    match lvalue.kind() {
        "identifier" => {
            let name = node_text(src, lvalue);
            (!locals.contains(&name)).then(|| name.to_string())
        }
        "field_expression" => {
            let object = lvalue.child_by_field_name("argument")?;
            if object.kind() == "this" {
                return lvalue
                    .child_by_field_name("field")
                    .map(|f| node_text(src, f).to_string());
            }
            written(src, object, locals)
        }
        "subscript_expression" | "pointer_expression" => {
            written(src, lvalue.child_by_field_name("argument")?, locals)
        }
        "parenthesized_expression" => written(src, lvalue.named_child(0)?, locals),
        // `member_.buffer()[i] = x`: through what a member returns.
        "call_expression" => {
            let f = lvalue.child_by_field_name("function")?;
            (f.kind() == "field_expression")
                .then(|| written(src, f.child_by_field_name("argument")?, locals))
                .flatten()
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summarized(src: &str) -> Vec<MemberBody> {
        let mut p = tree_sitter::Parser::new();
        p.set_language(&tree_sitter_cpp::LANGUAGE.into()).unwrap();
        let tree = p.parse(src, None).unwrap();
        let far = Instant::now() + std::time::Duration::from_secs(60);
        bodies(tree.root_node(), src.as_bytes(), far)
    }

    #[test]
    fn summarizes_member_bodies() {
        let src = "class A {\n public:\n  A() { n_ = 0; }\n  int get() const { return n_; }\n  void set(int v) { n_ = v; ++count_; }\n  int sum(int k) { int t = k; t += n_; return helper(t) + p_->size() + v_.size(); }\n  int& ref() { return n_; }\n  void reg() { connect(this); }\n  static int s() { return 1; }\n  virtual void v() {}\n private:\n  int n_, count_;\n};\nint A::out(int x) { x = 1; buf_[0] = x; return x; }\nvoid A::fill() { int* p = data_; *p = 0; }";
        let got = summarized(src);
        let names: Vec<&str> = got.iter().map(|b| b.name.as_str()).collect();
        assert_eq!(names, ["set", "sum", "ref", "reg", "out", "fill"]);
        assert_eq!(got[5].writes, ["data_"]);
        assert_eq!(got[0].writes, ["count_", "n_"]);
        assert!(got[1].writes.is_empty() && !got[1].escapes);
        assert_eq!(got[1].calls, ["helper"]);
        assert_eq!(
            got[1].member_calls,
            [
                ("p_".to_string(), "size".to_string()),
                ("v_".to_string(), "size".to_string())
            ]
        );
        assert!(got[2].escapes);
        assert!(got[3].escapes);
        assert_eq!(
            (got[4].class.as_str(), got[4].writes.clone()),
            ("A", vec!["buf_".to_string()])
        );
    }
}
