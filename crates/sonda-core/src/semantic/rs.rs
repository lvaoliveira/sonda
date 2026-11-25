//! Scopes and symbols for Rust (ADR-0008, S1; tree-sitter-rust).
//!
//! Rust's names are order-sensitive, unlike the other binders': a `let` binds
//! its names from the end of the statement on, so `let line = line.trim();`
//! reads the `line` before it, and a later `let` of the same name in the same
//! block shadows the earlier one from there. Every declaration therefore
//! records where it takes effect, and a reference resolves, after the walk, to
//! the last declaration of its name that has taken effect before it, in the
//! nearest scope that has one. Items (`fn`, `struct`, `const`) are visible in
//! their whole scope.
//!
//! What binds: `let` (and `let ... else`), function and closure parameters, the
//! arms of a `match`, `if let` and `while let` (in the block they guard), and
//! `for` patterns (in the loop's body). What opens a scope: modules, functions
//! and closures, blocks, `match` arms and `for` loops, `impl` and `trait`
//! bodies. A pattern's lowercase identifiers bind; an uppercase one is a
//! variant or a constant (`None`, `Ok`), as the language's own style has it.
//!
//! Iterative and bounded by the file's deadline, like the other binders.

use super::walk::{Binder, Opened};
use super::{DeclId, DeclKind, Function, Model, ScopeId, ScopeKind};
use std::time::Instant;
use tree_sitter::Node;

/// The binder of Rust: the shared one, and where each declaration takes
/// effect, by its id.
struct Rs<'t, 's> {
    b: Binder<'t, 's>,
    effect: Vec<usize>,
}

impl<'t, 's> std::ops::Deref for Rs<'t, 's> {
    type Target = Binder<'t, 's>;
    fn deref(&self) -> &Self::Target {
        &self.b
    }
}

impl std::ops::DerefMut for Rs<'_, '_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.b
    }
}

pub(super) fn build<'t>(root: Node<'t>, src: &[u8], deadline: Instant) -> Option<Model<'t>> {
    let mut rs = Rs {
        b: Binder::new(src),
        effect: Vec::new(),
    };
    let done = super::walk::run(root, deadline, |node, ancestors, field, scope, _| {
        rs.visit(node, ancestors, field, scope)
    });
    if !done {
        return None;
    }
    rs.b.m.root = Some(root);
    rs.resolve();
    Some(rs.b.m)
}

impl<'t> Rs<'t, '_> {
    /// Handles one node; returns the scope it opens for its children.
    fn visit(
        &mut self,
        node: Node<'t>,
        ancestors: &[Node<'t>],
        field: Option<&str>,
        scope: ScopeId,
    ) -> Opened {
        match node.kind() {
            "function_item" => Some((self.function(node, scope), false)),
            "closure_expression" => Some((self.closure(node, scope), false)),
            "struct_item" | "enum_item" | "trait_item" | "type_item" | "union_item" => {
                self.item_name(node, scope, DeclKind::Class);
                // A trait's methods are declared in a scope of their own.
                (node.kind() == "trait_item").then(|| (self.type_scope(scope), true))
            }
            "impl_item" => Some((self.type_scope(scope), true)),
            "const_item" | "static_item" => {
                self.item_name(node, scope, DeclKind::Const);
                None
            }
            "mod_item" => {
                self.item_name(node, scope, DeclKind::Class);
                Some((self.b.m.push_scope(scope, ScopeKind::Module), false))
            }
            "let_declaration" => {
                self.let_declaration(node, scope);
                None
            }
            "let_condition" => {
                // Bound in the block it guards; not references meanwhile.
                if let Some(p) = node.child_by_field_name("pattern") {
                    for n in pattern_bindings(p, self.b.src) {
                        self.b.not_refs.insert(n.id());
                    }
                }
                None
            }
            "match_arm" => Some((self.match_arm(node, scope), false)),
            "for_expression" => Some((self.for_expression(node, scope), false)),
            "block" => Some((self.block(node, ancestors, field, scope), false)),
            "identifier" | "self" => {
                self.reference(node, ancestors, scope);
                None
            }
            // `format!("{id}")`: a name inside the text is a use of the variable.
            "string_literal" if ancestors.last().is_some_and(|p| p.kind() == "token_tree") => {
                self.captures(node, scope);
                None
            }
            _ => None,
        }
    }

    fn type_scope(&mut self, scope: ScopeId) -> ScopeId {
        self.b.m.push_scope(scope, ScopeKind::Type)
    }

    /// A name an item declares, visible in its whole scope.
    fn item_name(&mut self, node: Node<'t>, scope: ScopeId, kind: DeclKind) {
        if let Some(name) = node.child_by_field_name("name") {
            self.b
                .declare_at(&mut self.effect, scope, name, kind, None, 0);
        }
    }

    /// A function's name, in its scope, and its parameters in a scope of their
    /// own.
    fn function(&mut self, node: Node<'t>, scope: ScopeId) -> ScopeId {
        self.item_name(node, scope, DeclKind::Function);
        let inner = self.b.m.push_scope(scope, ScopeKind::Function);
        let from = node.start_byte();
        let mut params: Vec<Vec<DeclId>> = Vec::new();
        if let Some(list) = node.child_by_field_name("parameters") {
            let mut c = list.walk();
            for p in list.named_children(&mut c) {
                match p.kind() {
                    "self_parameter" => {
                        if let Some(s) =
                            p.named_children(&mut p.walk()).find(|k| k.kind() == "self")
                        {
                            self.b.declare_at(
                                &mut self.effect,
                                inner,
                                s,
                                DeclKind::Param,
                                None,
                                from,
                            );
                        }
                    }
                    "parameter" => {
                        let ty = p.child_by_field_name("type");
                        params.push(self.parameter(inner, p, ty, from));
                    }
                    _ => {}
                }
            }
        }
        self.b.m.functions.push(Function {
            node,
            scope: inner,
            params,
        });
        inner
    }

    /// A closure: its parameters, in a scope of their own.
    fn closure(&mut self, node: Node<'t>, scope: ScopeId) -> ScopeId {
        let inner = self.b.m.push_scope(scope, ScopeKind::Function);
        let from = node.start_byte();
        let mut params: Vec<Vec<DeclId>> = Vec::new();
        if let Some(list) = node.child_by_field_name("parameters") {
            let mut c = list.walk();
            for p in list.named_children(&mut c) {
                if p.kind() == "parameter" {
                    let ty = p.child_by_field_name("type");
                    params.push(self.parameter(inner, p, ty, from));
                } else {
                    params.push(self.bind_pattern(inner, p, None, from));
                }
            }
        }
        self.b.m.functions.push(Function {
            node,
            scope: inner,
            params,
        });
        inner
    }

    /// The names a parameter's pattern binds.
    fn parameter(
        &mut self,
        scope: ScopeId,
        param: Node<'t>,
        ty: Option<Node<'t>>,
        from: usize,
    ) -> Vec<DeclId> {
        match param.child_by_field_name("pattern") {
            Some(p) => self.bind_pattern(scope, p, ty, from),
            None => Vec::new(),
        }
    }

    /// Declares each name `pattern` binds as a parameter or a local; the
    /// declared ids.
    fn bind_pattern(
        &mut self,
        scope: ScopeId,
        pattern: Node<'t>,
        ty: Option<Node<'t>>,
        from: usize,
    ) -> Vec<DeclId> {
        let first = self.b.m.decls.len();
        for n in pattern_bindings(pattern, self.b.src) {
            self.b
                .declare_at(&mut self.effect, scope, n, DeclKind::Let, ty, from);
        }
        (first..self.b.m.decls.len()).collect()
    }

    /// `let pattern: T = value;`, bound from the statement's end.
    fn let_declaration(&mut self, node: Node<'t>, scope: ScopeId) {
        if let Some(p) = node.child_by_field_name("pattern") {
            let ty = node.child_by_field_name("type");
            let ids = self.bind_pattern(scope, p, ty, node.end_byte());
            for d in ids {
                self.b.m.decls[d].declarator = Some(node);
                // An initializer writes the variable.
                self.b.m.decls[d].writes += u32::from(node.child_by_field_name("value").is_some());
            }
        }
    }

    /// A `match` arm's scope, holding what its pattern binds. A guard
    /// (`if cond`) is an expression.
    fn match_arm(&mut self, node: Node<'t>, scope: ScopeId) -> ScopeId {
        let arm = self.b.m.push_scope(scope, ScopeKind::Block);
        if let Some(p) = node.child_by_field_name("pattern") {
            let guard = p.child_by_field_name("condition").map(|g| g.id());
            let mut c = p.walk();
            let patterns: Vec<Node<'t>> = p
                .named_children(&mut c)
                .filter(|x| Some(x.id()) != guard)
                .collect();
            for pat in patterns {
                self.bind_pattern(arm, pat, None, p.start_byte());
            }
        }
        arm
    }

    /// A `for` loop's scope; its pattern is bound in the body.
    fn for_expression(&mut self, node: Node<'t>, scope: ScopeId) -> ScopeId {
        let inner = self.b.m.push_scope(scope, ScopeKind::Block);
        if let (Some(p), Some(body)) = (
            node.child_by_field_name("pattern"),
            node.child_by_field_name("body"),
        ) {
            self.bind_pattern(inner, p, None, body.start_byte());
        }
        inner
    }

    /// A block's scope. The block of an `if let` or `while let` binds what its
    /// condition's patterns do.
    fn block(
        &mut self,
        node: Node<'t>,
        ancestors: &[Node<'t>],
        field: Option<&str>,
        scope: ScopeId,
    ) -> ScopeId {
        let inner = self.b.m.push_scope(scope, ScopeKind::Block);
        let Some(&parent) = ancestors.last() else {
            return inner;
        };
        if matches!(
            (parent.kind(), field),
            ("if_expression", Some("consequence")) | ("while_expression", Some("body"))
        ) && let Some(cond) = parent.child_by_field_name("condition")
        {
            for lc in let_conditions(cond) {
                if let Some(p) = lc.child_by_field_name("pattern") {
                    self.bind_pattern(inner, p, None, node.start_byte());
                }
            }
        }
        inner
    }

    /// The names a format string captures, `{id}` and `{id:?}`: references
    /// that sit on the literal itself.
    fn captures(&mut self, literal: Node<'t>, scope: ScopeId) {
        let text = literal
            .utf8_text(self.b.src)
            .unwrap_or_default()
            .to_string();
        for name in format_captures(&text) {
            self.b.m.refs.push(super::Ref {
                name,
                node: literal,
                scope,
                read: true,
                write: false,
                decl: None,
            });
        }
    }

    fn reference(&mut self, node: Node<'t>, ancestors: &[Node<'t>], scope: ScopeId) {
        if self.b.not_refs.contains(&node.id()) {
            return;
        }
        let Some(&parent) = ancestors.last() else {
            return;
        };
        // A path's segments, a name in an attribute or a `use`, a label.
        if (parent.kind() == "macro_invocation"
            && parent.child_by_field_name("macro") == Some(node))
            || matches!(
                parent.kind(),
                "scoped_identifier" | "scoped_use_list" | "use_list" | "use_as_clause"
            )
            || ancestors.iter().any(|a| {
                matches!(
                    a.kind(),
                    "attribute_item" | "use_declaration" | "inner_attribute_item"
                )
            })
        {
            return;
        }
        let (read, write) = access(node, parent);
        self.b.add_ref(node, scope, read, write);
    }

    /// Links each reference to the declaration of its name that has taken
    /// effect before it, nearest scope first, and counts reads and writes.
    fn resolve(&mut self) {
        self.b.m.resolve_in_order(&self.effect);
    }
}

/// The names a format string captures: `{id}`, `{id:?}`, `{0}` is no name.
pub(super) fn format_captures(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'{' {
            if b.get(i + 1) == Some(&b'{') {
                i += 2;
                continue;
            }
            let rest = &text[i + 1..];
            let end = rest.find(['}', ':']).unwrap_or(rest.len());
            let name = rest[..end].trim();
            if !name.is_empty()
                && name
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_alphabetic() || c == '_')
                && name.chars().all(|c| c.is_alphanumeric() || c == '_')
            {
                out.push(name.to_string());
            }
            i += 1 + end;
        } else {
            i += 1;
        }
    }
    out
}

/// The `let` conditions of an `if` or `while` condition, through `&&` chains.
fn let_conditions(cond: Node) -> Vec<Node> {
    let mut out = Vec::new();
    let mut stack = vec![cond];
    while let Some(n) = stack.pop() {
        match n.kind() {
            "let_condition" => out.push(n),
            "let_chain" | "binary_expression" => {
                let mut c = n.walk();
                stack.extend(n.named_children(&mut c));
            }
            _ => {}
        }
    }
    out
}

/// The names a pattern binds: its lowercase identifiers, and the shorthand
/// fields of a struct pattern. `Some(x)` binds `x`, not `Some`; `Point { x, y: z }`
/// binds `x` and `z`.
pub(super) fn pattern_bindings<'t>(pattern: Node<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let mut out = Vec::new();
    let mut stack = vec![pattern];
    while let Some(n) = stack.pop() {
        match n.kind() {
            "identifier" => {
                let t = n.utf8_text(src).unwrap_or_default();
                if t.chars().next().is_some_and(|c| !c.is_uppercase()) {
                    out.push(n);
                }
            }
            "shorthand_field_identifier" => out.push(n),
            // The type's path isn't a binding, nor are literals and ranges.
            "tuple_struct_pattern" | "struct_pattern" => {
                let ty = n.child_by_field_name("type").map(|t| t.id());
                let mut c = n.walk();
                stack.extend(n.named_children(&mut c).filter(|x| Some(x.id()) != ty));
            }
            "field_pattern" => {
                // `x` alone is a shorthand; `y: z` binds what `z` binds.
                let mut c = n.walk();
                stack.extend(
                    n.named_children(&mut c)
                        .filter(|x| x.kind() != "field_identifier"),
                );
            }
            "scoped_identifier" | "string_literal" | "integer_literal" | "float_literal"
            | "boolean_literal" | "char_literal" | "range_pattern" => {}
            _ => {
                let mut c = n.walk();
                stack.extend(n.named_children(&mut c));
            }
        }
    }
    out.reverse();
    out
}

/// Whether the reference `node` reads its variable and whether it writes it.
fn access(node: Node, parent: Node) -> (bool, bool) {
    match parent.kind() {
        "assignment_expression" if parent.child_by_field_name("left") == Some(node) => {
            (false, true)
        }
        "compound_assignment_expr" if parent.child_by_field_name("left") == Some(node) => {
            (true, true)
        }
        _ => (true, false),
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_model::{count, decl, with_model};
    use super::super::{DeclKind, Model};
    use crate::lang::Lang;

    fn rust(src: &str, check: impl FnOnce(&Model)) {
        with_model(Lang::Rust, src, check);
    }

    #[test]
    fn a_let_shadows_from_the_end_of_its_statement() {
        let src = "fn f(line: &str) {\n    let line = line.trim();\n    let n = line.len();\n    let line = n;\n    use_it(line);\n}";
        rust(src, |m| {
            assert_eq!(count(m, "line"), 3);
            // The parameter is read by the first `let`'s initializer; the
            // first `let`'s line by `line.len()`; the last by `use_it`.
            assert_eq!(decl(m, "line", 0).1, 1);
            assert_eq!(decl(m, "line", 1).1, 1);
            assert_eq!(decl(m, "line", 2).1, 1);
        });
    }

    #[test]
    fn parameters_patterns_and_closures() {
        let src = "fn h(Query(params): Query<P>, (a, b): (i32, i32), &mut c: &mut u8) {\n    let f = |x, (y, z)| x + y + z + a;\n    let g = |p: String| p;\n}";
        rust(src, |m| {
            for n in ["params", "a", "b", "c", "x", "y", "z", "p", "f", "g"] {
                assert_eq!(count(m, n), 1, "{n}");
            }
            assert_eq!(count(m, "Query"), 0, "a type's name binds nothing");
            assert_eq!(decl(m, "a", 0).1, 1, "read by the closure");
            assert_eq!(m.functions.len(), 3, "h and two closures");
            assert_eq!(m.functions[0].params.len(), 3);
        });
    }

    #[test]
    fn match_if_let_while_let_and_for() {
        let src = "fn f(o: Option<String>, v: Vec<u8>) {\n    match o {\n        Some(s) if s.len() > 1 => use_it(s),\n        None => {}\n        other => use_it(other),\n    }\n    if let Some(t) = pick() { use_it(t); } else { use_it(t); }\n    while let Some(w) = next() { use_it(w); }\n    for item in v.iter() { use_it(item); }\n}";
        rust(src, |m| {
            assert_eq!(decl(m, "s", 0).1, 2, "the guard and the arm");
            assert_eq!(count(m, "None"), 0);
            assert_eq!(decl(m, "other", 0).1, 1);
            // `t` in the else branch isn't the pattern's.
            assert_eq!(decl(m, "t", 0).1, 1);
            assert_eq!(decl(m, "w", 0).1, 1);
            assert_eq!(decl(m, "item", 0).1, 1);
            assert_eq!(decl(m, "v", 0).1, 1, "the loop's iterable");
        });
    }

    #[test]
    fn items_are_visible_everywhere_and_self_resolves() {
        let src = "struct S { n: u32 }\nimpl S {\n    fn a(&self) -> u32 { self.n + helper() }\n}\nfn helper() -> u32 { 1 }\nconst LIMIT: u32 = 5;\nfn g() -> u32 { LIMIT + helper() }";
        rust(src, |m| {
            assert_eq!(decl(m, "helper", 0).0, DeclKind::Function);
            assert_eq!(decl(m, "helper", 0).1, 2);
            assert_eq!(decl(m, "LIMIT", 0).1, 1);
            assert_eq!(decl(m, "self", 0).1, 1);
        });
    }

    #[test]
    fn paths_fields_attributes_and_macros() {
        let src = "use std::fs::read;\n#[get(\"/<id>\")]\nfn f(id: String) {\n    let s = format!(\"{}-{id}\", id);\n    let p = std::path::Path::new(&id);\n    println!(\"{}\", s);\n    let t = Thing { id, name: s };\n}";
        rust(src, |m| {
            let names: Vec<&str> = m.refs.iter().map(|r| r.name.as_str()).collect();
            assert!(!names.contains(&"std"), "{names:?}");
            assert!(!names.contains(&"get"), "{names:?}");
            // `id`: the macro's token and its `{id}`, `&id`, and the shorthand field.
            assert_eq!(decl(m, "id", 0).1, 4);
            assert_eq!(decl(m, "s", 0).1, 2);
        });
    }
}
