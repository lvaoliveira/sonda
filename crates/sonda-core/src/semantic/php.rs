//! Scopes and symbols for PHP (ADR-0008, S1; tree-sitter-php), the model
//! the taint engine of ADR-0027 reads.
//!
//! PHP's variables are the function's, whatever block they're in, and a
//! function sees nothing outside it: not the file's variables (those take a
//! `global $x`), not the function around it. So the first binding of a name in
//! a function declares it and every later occurrence is that variable, as
//! `Model::resolve` does for hoisted names, and a function's scope has no
//! parent to climb to:
//! - an anonymous function imports what its `use ($a, &$b)` lists, each one
//!   a variable of its own that holds the value it was created with;
//! - an arrow function (`fn($x) => $x + $y`) takes the whole scope around it
//!   by value, so what it doesn't declare resolves outward;
//! - a method's `$this` is no variable, and the superglobals (`$_GET`,
//!   `$GLOBALS`) are every function's without declaring: both resolve to
//!   nothing here, and the taint engine reads them by name.
//!
//! What binds: the targets of an assignment (`$a = ..`, `$a[] = ..`,
//! `[$a, $b] = ..`, `list($a) = ..`), a `foreach`'s key and value, a `catch`'s
//! variable, `global` and `static`, a closure's `use`, and parameters.
//!
//! Iterative and bounded by the file's deadline, like the other binders.

use super::walk::{Binder, Opened};
use super::{DeclKind, Function, Model, ScopeId, ScopeKind};
use std::time::Instant;
use tree_sitter::Node;

/// The variables every function has without declaring them.
const SUPERGLOBALS: &[&str] = &[
    "$this",
    "$GLOBALS",
    "$_GET",
    "$_POST",
    "$_REQUEST",
    "$_COOKIE",
    "$_FILES",
    "$_SERVER",
    "$_ENV",
    "$_SESSION",
];

struct Php<'t, 's> {
    b: Binder<'t, 's>,
    /// The parent of a function's scope: one that declares nothing, so
    /// a lookup from a function finds only the function's own variables.
    isolated: ScopeId,
}

pub(super) fn build<'t>(root: Node<'t>, src: &[u8], deadline: Instant) -> Option<Model<'t>> {
    let mut b = Binder::new(src);
    let isolated = b.m.push_scope(0, ScopeKind::Block);
    // Nothing above it: a lookup that reaches it is over.
    b.m.scopes[isolated].parent = None;
    let mut php = Php { b, isolated };
    let done = super::walk::run(root, deadline, |node, ancestors, _, scope, _| {
        php.visit(node, ancestors, scope)
    });
    if !done {
        return None;
    }
    php.b.m.root = Some(root);
    php.b.m.resolve();
    Some(php.b.m)
}

impl<'t> Php<'t, '_> {
    fn visit(&mut self, node: Node<'t>, ancestors: &[Node<'t>], scope: ScopeId) -> Opened {
        match node.kind() {
            "function_definition" | "method_declaration" | "anonymous_function" => {
                Some((self.function(node, self.isolated), false))
            }
            "arrow_function" => Some((self.function(node, scope), false)),
            "anonymous_function_use_clause" => {
                for v in variables(node) {
                    self.declare(scope, v, DeclKind::Let, None, 1);
                }
                None
            }
            "assignment_expression" | "augmented_assignment_expression" => {
                if let Some(left) = node.child_by_field_name("left") {
                    let first = self.b.m.decls.len();
                    self.bind_target(left, scope);
                    // What a variable was declared by: its type, where it
                    // isn't written.
                    for d in &mut self.b.m.decls[first..] {
                        d.declarator = Some(node);
                    }
                }
                None
            }
            "foreach_statement" => {
                self.foreach(node, scope);
                None
            }
            "catch_clause" => {
                if let Some(name) = node.child_by_field_name("name") {
                    self.declare(scope, name, DeclKind::CatchParam, None, 1);
                }
                None
            }
            "global_declaration" => {
                for v in variables(node) {
                    self.declare(scope, v, DeclKind::Var, None, 0);
                }
                None
            }
            "static_variable_declaration" => {
                if let Some(name) = node.child_by_field_name("name") {
                    self.declare(scope, name, DeclKind::Var, None, 1);
                }
                None
            }
            "variable_name" => {
                self.reference(node, ancestors, scope);
                None
            }
            _ => None,
        }
    }

    /// Declares `name` in `scope` unless the function already has it.
    fn declare(
        &mut self,
        scope: ScopeId,
        name: Node<'t>,
        kind: DeclKind,
        ty: Option<Node<'t>>,
        writes: u32,
    ) {
        let text = self.b.text(name);
        if !self.b.m.decls_named(scope, &text).is_empty() {
            self.b.not_refs.insert(name.id());
            return;
        }
        self.b.declare(scope, name, kind, ty, false);
        if let Some(d) = self.b.m.decls.last_mut() {
            d.writes += writes;
        }
    }

    /// A function's scope, holding its parameters. Each parameter is one
    /// name; a promoted constructor property (`public $x`) is one too.
    fn function(&mut self, node: Node<'t>, parent: ScopeId) -> ScopeId {
        let inner = self.b.m.push_scope(parent, ScopeKind::Function);
        let mut params = Vec::new();
        if let Some(list) = node.child_by_field_name("parameters") {
            let mut c = list.walk();
            for p in list.named_children(&mut c) {
                if !matches!(
                    p.kind(),
                    "simple_parameter" | "variadic_parameter" | "property_promotion_parameter"
                ) {
                    continue;
                }
                let ty = p.child_by_field_name("type");
                let name = p.child_by_field_name("name").and_then(|n| {
                    // A by-reference promoted parameter wraps its name.
                    if n.kind() == "variable_name" {
                        Some(n)
                    } else {
                        variables(n).into_iter().next()
                    }
                });
                let Some(name) = name else {
                    params.push(Vec::new());
                    continue;
                };
                let first = self.b.m.decls.len();
                self.declare(inner, name, DeclKind::Param, ty, 0);
                if let Some(d) = self.b.m.decls.get_mut(first) {
                    d.declarator = Some(p);
                }
                params.push((first..self.b.m.decls.len()).collect());
            }
        }
        self.b.m.functions.push(Function {
            node,
            scope: inner,
            params,
        });
        inner
    }

    /// What an assignment's left side binds: a variable, the variable an
    /// element or a property is set on (`$a['k'] = ..`), or every variable of
    /// a destructuring (`[$a, [$b]] = ..`).
    fn bind_target(&mut self, left: Node<'t>, scope: ScopeId) {
        match left.kind() {
            "variable_name" => self.bind(left, scope),
            "subscript_expression" | "member_access_expression" => {
                if let Some(base) = left.named_child(0) {
                    self.bind_target(base, scope);
                }
            }
            "list_literal" | "array_creation_expression" => {
                for v in variables(left) {
                    self.bind(v, scope);
                }
            }
            _ => {}
        }
    }

    /// A variable written: declared if the function hasn't seen it, else a
    /// write of the one it has.
    fn bind(&mut self, v: Node<'t>, scope: ScopeId) {
        if SUPERGLOBALS.contains(&self.b.text(v).as_str()) {
            self.b.not_refs.insert(v.id());
            return;
        }
        let text = self.b.text(v);
        if self.b.m.decls_named(scope, &text).is_empty() {
            self.declare(scope, v, DeclKind::Var, None, 1);
        }
    }

    /// `foreach ($xs as $k => $v)`: the key and the value, bound in the
    /// function.
    fn foreach(&mut self, node: Node<'t>, scope: ScopeId) {
        let body = node.child_by_field_name("body");
        let mut c = node.walk();
        let parts: Vec<Node<'t>> = node
            .named_children(&mut c)
            .filter(|n| body.is_none_or(|b| b.id() != n.id()) && n.kind() != "comment")
            .collect();
        // The first is what's iterated; the rest are what it's bound to.
        for binding in parts.iter().skip(1) {
            for v in variables(*binding) {
                self.declare(scope, v, DeclKind::Let, None, 1);
            }
        }
    }

    fn reference(&mut self, node: Node<'t>, ancestors: &[Node<'t>], scope: ScopeId) {
        if self.b.not_refs.contains(&node.id())
            || SUPERGLOBALS.contains(&self.b.text(node).as_str())
        {
            return;
        }
        let (read, write) = access(node, ancestors);
        self.b.add_ref(node, scope, read, write);
    }
}

/// The variables in a node, in source order, not looking into a function.
fn variables<'t>(n: Node<'t>) -> Vec<Node<'t>> {
    let mut out = Vec::new();
    let mut stack = vec![n];
    while let Some(x) = stack.pop() {
        if x.kind() == "variable_name" {
            out.push(x);
            continue;
        }
        if matches!(
            x.kind(),
            "anonymous_function" | "arrow_function" | "function_definition"
        ) {
            continue;
        }
        let mut c = x.walk();
        let kids: Vec<Node<'t>> = x.named_children(&mut c).collect();
        stack.extend(kids.into_iter().rev());
    }
    out
}

/// Whether the reference `node` reads its variable and whether it writes it.
fn access(node: Node, ancestors: &[Node]) -> (bool, bool) {
    let Some(&parent) = ancestors.last() else {
        return (true, false);
    };
    match parent.kind() {
        "assignment_expression"
            if parent
                .child_by_field_name("left")
                .is_some_and(|l| l.id() == node.id()) =>
        {
            (false, true)
        }
        "augmented_assignment_expression"
            if parent
                .child_by_field_name("left")
                .is_some_and(|l| l.id() == node.id()) =>
        {
            (true, true)
        }
        "update_expression" => (true, true),
        _ => (true, false),
    }
}

#[cfg(test)]
mod tests {
    use super::super::{DeclKind, Model};
    use crate::lang::Lang;
    use std::time::{Duration, Instant};

    fn php(src: &str, check: impl FnOnce(&Model)) {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&Lang::Php.grammar()).unwrap();
        let tree = parser.parse(src, None).unwrap();
        let model = super::build(
            tree.root_node(),
            src.as_bytes(),
            Instant::now() + Duration::from_secs(10),
        )
        .unwrap();
        check(&model);
    }

    /// The `n`th declaration called `name`, as (kind, reads, writes).
    fn decl(m: &Model, name: &str, n: usize) -> (DeclKind, u32, u32) {
        let d = m.decls.iter().filter(|d| d.name == name).nth(n).unwrap();
        (d.kind, d.reads, d.writes)
    }

    fn count(m: &Model, name: &str) -> usize {
        m.decls.iter().filter(|d| d.name == name).count()
    }

    #[test]
    fn the_first_binding_declares_and_the_rest_are_that_variable() {
        let src = "<?php\nfunction f($a) {\n    $x = 1;\n    $x = $x + $a;\n    $x .= 'z';\n    return $x;\n}\n";
        php(src, |m| {
            assert_eq!(count(m, "$x"), 1);
            // One write that declares it, one `=`, one `.=` (which reads too).
            assert_eq!(decl(m, "$x", 0), (DeclKind::Var, 3, 3));
            assert_eq!(decl(m, "$a", 0), (DeclKind::Param, 1, 0));
        });
    }

    #[test]
    fn a_function_sees_nothing_outside_it_but_what_it_imports() {
        let src = "<?php\n$outer = 1;\nfunction f() {\n    return $outer;\n}\nfunction g() {\n    global $outer;\n    return $outer;\n}\n$h = function () use ($outer, &$ref) {\n    return $outer + $ref;\n};\n";
        php(src, |m| {
            // `f`'s `$outer` resolves to nothing; `g`'s to its `global`; the
            // closure's to what `use` imported, not the file's.
            assert_eq!(
                decl(m, "$outer", 0).1,
                0,
                "the file's: no function reads it"
            );
            assert_eq!(decl(m, "$outer", 1).1, 1, "g's global");
            assert_eq!(decl(m, "$outer", 2).1, 1, "the closure's");
            assert_eq!(count(m, "$ref"), 1);
        });
    }

    #[test]
    fn an_arrow_function_takes_the_scope_around_it() {
        let src =
            "<?php\nfunction f($base) {\n    return array_map(fn($x) => $x + $base, [1, 2]);\n}\n";
        php(src, |m| {
            assert_eq!(
                decl(m, "$base", 0).1,
                1,
                "read from inside the arrow function"
            );
            assert_eq!(decl(m, "$x", 0), (DeclKind::Param, 1, 0));
            assert_eq!(m.functions.len(), 2);
        });
    }

    #[test]
    fn what_binds_besides_assignment() {
        let src = "<?php\nfunction f($xs) {\n    foreach ($xs as $k => $v) { echo $k . $v; }\n    foreach ($xs as &$r) { $r = 1; }\n    try { g(); } catch (Exception $e) { echo $e; }\n    [$a, [$b]] = $xs;\n    list($c, $d) = $xs;\n    static $n = 0;\n    $arr['k'] = 1;\n    return [$a, $b, $c, $d, $n, $arr];\n}\n";
        php(src, |m| {
            for n in ["$k", "$v", "$r", "$e", "$a", "$b", "$c", "$d", "$n", "$arr"] {
                assert_eq!(count(m, n), 1, "{n}");
            }
            assert_eq!(decl(m, "$v", 0).0, DeclKind::Let);
            assert_eq!(decl(m, "$e", 0).0, DeclKind::CatchParam);
            assert_eq!(decl(m, "$arr", 0).2, 1, "an element set is a write");
        });
    }

    #[test]
    fn parameters_by_position_and_what_is_never_a_variable() {
        let src = "<?php\nclass A {\n    public function __construct(private string $name, int ...$rest) {}\n    public function run(Request $req, $x = 3) {\n        return $this->name . $_GET['q'] . $req->id . $x;\n    }\n}\n";
        php(src, |m| {
            let params: Vec<usize> = m.functions.iter().map(|f| f.params.len()).collect();
            assert_eq!(params, [2, 2]);
            assert_eq!(
                decl(m, "$name", 0).0,
                DeclKind::Param,
                "a promoted property"
            );
            assert_eq!(count(m, "$this"), 0);
            assert!(
                m.refs
                    .iter()
                    .all(|r| r.name != "$this" && r.name != "$_GET")
            );
            assert!(
                m.decls
                    .iter()
                    .find(|d| d.name == "$req")
                    .unwrap()
                    .ty
                    .is_some()
            );
            assert_eq!(decl(m, "$req", 0).1, 1);
        });
    }

    #[test]
    fn variables_in_strings_are_references() {
        let src = "<?php\nfunction f($id, $row) {\n    return \"SELECT * FROM t WHERE id = $id AND n = {$row['n']}\";\n}\n";
        php(src, |m| {
            assert_eq!(decl(m, "$id", 0).1, 1);
            assert_eq!(decl(m, "$row", 0).1, 1);
        });
    }
}
