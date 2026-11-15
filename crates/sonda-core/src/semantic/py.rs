//! Scopes and symbols for Python (ADR-0008, S1), from tree-sitter-python.
//!
//! Python has no declarations: a name bound anywhere in a function is that
//! function's, for the whole function. So the first binding of a name in a
//! scope declares it, later ones are writes, and references resolve after
//! the walk, the way `Model::resolve` already does for hoisting.
//!
//! What binds: assignment targets (`x = …`, `a, b = …`, `x += …`), `for`
//! and comprehension targets, `with … as x`, `except … as e`, `x := …`,
//! imports, `def` and `class` names, and parameters. What opens a scope:
//! modules, functions and lambdas, classes, and comprehensions.
//!
//! Python's own rules:
//! - a class body's names aren't visible in its methods: a method's scope
//!   has the class's enclosing scope as its parent;
//! - `global x` and `nonlocal x` make a binding of `x` the outer one's;
//! - `x := …` in a comprehension binds in the function around it;
//! - a comprehension's first iterable is evaluated outside it.
//!
//! Iterative and bounded by the file's deadline, like the other binders.

use super::{DeclKind, Function, Model, Ref, ScopeId, ScopeKind};
use std::collections::{HashMap, HashSet};
use std::time::Instant;
use tree_sitter::Node;

/// Nodes between deadline checks.
const CHECK_EVERY: u32 = 4096;

const COMPREHENSIONS: &[&str] = &[
    "list_comprehension",
    "set_comprehension",
    "dictionary_comprehension",
    "generator_expression",
];

struct Binder<'t, 's> {
    m: Model<'t>,
    src: &'s [u8],
    /// Scopes that are comprehensions, which `:=` binds through.
    comprehensions: HashSet<ScopeId>,
    /// Names each scope declares `global` or `nonlocal`.
    globals: HashMap<ScopeId, HashSet<String>>,
    nonlocals: HashMap<ScopeId, HashSet<String>>,
}

pub(super) fn build<'t>(root: Node<'t>, src: &[u8], deadline: Instant) -> Option<Model<'t>> {
    let mut b = Binder {
        m: Model::new(),
        src,
        comprehensions: HashSet::new(),
        globals: HashMap::new(),
        nonlocals: HashMap::new(),
    };
    // Each node to visit, with the scope it's evaluated in. Children are
    // pushed in reverse, so nodes are visited in source order: a `global`
    // statement comes before the bindings it governs.
    let mut stack: Vec<(Node<'t>, ScopeId)> = vec![(root, 0)];
    let mut visited = 0u32;
    while let Some((node, scope)) = stack.pop() {
        visited += 1;
        if visited.is_multiple_of(CHECK_EVERY) && Instant::now() >= deadline {
            return None;
        }
        let mut next: Vec<(Node<'t>, ScopeId)> = Vec::new();
        b.visit(node, scope, &mut next);
        stack.extend(next.into_iter().rev());
    }
    b.m.root = Some(root);
    b.m.resolve();
    Some(b.m)
}

fn children(n: Node) -> Vec<Node> {
    let mut c = n.walk();
    n.named_children(&mut c)
        .filter(|x| x.kind() != "comment")
        .collect()
}

impl<'t> Binder<'t, '_> {
    fn text(&self, n: Node) -> String {
        n.utf8_text(self.src).unwrap_or_default().to_string()
    }

    /// Handles one node, and lists the nodes below it to visit, each with
    /// the scope it's in.
    fn visit(&mut self, node: Node<'t>, scope: ScopeId, next: &mut Vec<(Node<'t>, ScopeId)>) {
        let field = |name: &str| node.child_by_field_name(name);
        match node.kind() {
            "function_definition" => self.function(node, scope, next),
            "lambda" => self.function(node, scope, next),
            "class_definition" => self.visit_class(node, scope, next),
            k if COMPREHENSIONS.contains(&k) => self.visit_comprehension(node, scope, next),
            "assignment" => self.visit_assignment(node, scope, next),
            "augmented_assignment" => self.visit_augmented_assignment(node, scope, next),
            "for_statement" => {
                if let Some(left) = field("left") {
                    self.bind_target(left, scope, DeclKind::Var, next);
                }
                for f in ["right", "body", "alternative"] {
                    next.extend(field(f).map(|x| (x, scope)));
                }
            }
            "named_expression" => {
                if let Some(name) = field("name") {
                    let target = self.walrus_scope(scope);
                    self.bind(target, name, DeclKind::Var);
                }
                next.extend(field("value").map(|v| (v, scope)));
            }
            // `with open(p) as f`, and `case X() as y`.
            "as_pattern" => self.visit_as_pattern(node, scope, next),
            "except_clause" => self.visit_except_clause(node, scope, next),
            "global_statement" | "nonlocal_statement" => self.visit_scope_statement(node, scope),
            "import_statement" | "import_from_statement" => self.import(node, scope),
            // `obj.attr`: `attr` is no variable.
            "attribute" => next.extend(field("object").map(|o| (o, scope))),
            // `f(key=value)`: `key` is a parameter's name.
            "keyword_argument" => next.extend(field("value").map(|v| (v, scope))),
            "identifier" => self.reference(node, scope),
            _ => next.extend(children(node).into_iter().map(|c| (c, scope))),
        }
    }

    /// A class: its name, then its body in a scope of its own.
    fn visit_class(&mut self, node: Node<'t>, scope: ScopeId, next: &mut Vec<(Node<'t>, ScopeId)>) {
        let field = |name: &str| node.child_by_field_name(name);
        if let Some(name) = field("name") {
            self.bind(scope, name, DeclKind::Class);
        }
        next.extend(field("superclasses").map(|s| (s, scope)));
        next.extend(field("type_parameters").map(|s| (s, scope)));
        if let Some(body) = field("body") {
            let class = self.m.push_scope(scope, ScopeKind::Type);
            next.push((body, class));
        }
    }

    /// A comprehension, a scope of its own: its targets are bound inside
    /// it, and its first iterable is evaluated where the comprehension is,
    /// the rest inside it.
    fn visit_comprehension(
        &mut self,
        node: Node<'t>,
        scope: ScopeId,
        next: &mut Vec<(Node<'t>, ScopeId)>,
    ) {
        let inner = self.m.push_scope(scope, ScopeKind::Function);
        self.comprehensions.insert(inner);
        let mut first = true;
        for c in children(node) {
            if c.kind() != "for_in_clause" {
                next.push((c, inner));
                continue;
            }
            if let Some(left) = c.child_by_field_name("left") {
                self.bind_target(left, inner, DeclKind::Var, next);
            }
            let iterable_scope = if first { scope } else { inner };
            first = false;
            let mut cursor = c.walk();
            next.extend(
                c.children_by_field_name("right", &mut cursor)
                    .filter(|r| r.is_named())
                    .map(|r| (r, iterable_scope)),
            );
        }
    }

    fn visit_assignment(
        &mut self,
        node: Node<'t>,
        scope: ScopeId,
        next: &mut Vec<(Node<'t>, ScopeId)>,
    ) {
        let field = |name: &str| node.child_by_field_name(name);
        if let Some(left) = field("left") {
            let before = self.m.decls.len();
            self.bind_target(left, scope, DeclKind::Var, next);
            // `x = value`: the declaration's value, for rules that follow
            // what a name was set to.
            if left.kind() == "identifier"
                && self.m.decls.len() > before
                && let Some(d) = self.m.decls.last_mut()
            {
                d.declarator = Some(node);
            }
        }
        next.extend(field("type").map(|t| (t, scope)));
        next.extend(field("right").map(|r| (r, scope)));
    }

    /// `x += 1`: read, then written.
    fn visit_augmented_assignment(
        &mut self,
        node: Node<'t>,
        scope: ScopeId,
        next: &mut Vec<(Node<'t>, ScopeId)>,
    ) {
        if let Some(left) = node.child_by_field_name("left") {
            if left.kind() == "identifier" {
                self.reference(left, scope);
            }
            self.bind_target(left, scope, DeclKind::Var, next);
        }
        next.extend(node.child_by_field_name("right").map(|r| (r, scope)));
    }

    fn visit_as_pattern(
        &mut self,
        node: Node<'t>,
        scope: ScopeId,
        next: &mut Vec<(Node<'t>, ScopeId)>,
    ) {
        for c in children(node) {
            if c.kind() == "as_pattern_target" {
                self.bind_target(c, scope, DeclKind::Var, next);
            } else {
                next.push((c, scope));
            }
        }
    }

    /// `except E as e`: `e` is bound; the rest visited.
    fn visit_except_clause(
        &mut self,
        node: Node<'t>,
        scope: ScopeId,
        next: &mut Vec<(Node<'t>, ScopeId)>,
    ) {
        let alias = node.child_by_field_name("alias");
        if let Some(alias) = alias {
            self.bind_target(alias, scope, DeclKind::Var, next);
        }
        next.extend(
            children(node)
                .into_iter()
                .filter(|c| Some(*c) != alias)
                .map(|c| (c, scope)),
        );
    }

    /// `global x` or `nonlocal x`: the names this scope refers elsewhere.
    fn visit_scope_statement(&mut self, node: Node<'t>, scope: ScopeId) {
        let names: HashSet<String> = children(node)
            .into_iter()
            .filter(|c| c.kind() == "identifier")
            .map(|c| self.text(c))
            .collect();
        let set = if node.kind() == "global_statement" {
            self.globals.entry(scope).or_default()
        } else {
            self.nonlocals.entry(scope).or_default()
        };
        set.extend(names);
    }

    /// A function or a lambda: its name binds where it's defined; its
    /// defaults, annotations and decorators are evaluated there too; its
    /// parameters and body are in a scope of its own, whose parent skips
    /// the classes around it.
    fn function(&mut self, node: Node<'t>, scope: ScopeId, next: &mut Vec<(Node<'t>, ScopeId)>) {
        if node.kind() == "function_definition"
            && let Some(name) = node.child_by_field_name("name")
        {
            self.bind(scope, name, DeclKind::Function);
        }
        let mut outer = scope;
        while self.m.scopes[outer].kind == ScopeKind::Type {
            outer = self.m.scopes[outer].parent.unwrap_or(0);
        }
        let inner = self.m.push_scope(outer, ScopeKind::Function);
        let mut params = Vec::new();
        if let Some(list) = node.child_by_field_name("parameters") {
            for p in children(list) {
                let first = self.m.decls.len();
                for name in param_names(p) {
                    self.bind(inner, name, DeclKind::Param);
                }
                params.push((first..self.m.decls.len()).collect());
                // Defaults and annotations are the enclosing scope's.
                for f in ["value", "type"] {
                    next.extend(p.child_by_field_name(f).map(|v| (v, scope)));
                }
            }
        }
        self.m.functions.push(Function {
            node,
            scope: inner,
            params,
        });
        next.extend(node.child_by_field_name("return_type").map(|t| (t, scope)));
        next.extend(
            node.child_by_field_name("type_parameters")
                .map(|t| (t, scope)),
        );
        next.extend(node.child_by_field_name("body").map(|b| (b, inner)));
    }

    /// The names an assignment's target binds; attributes and subscripts
    /// in it are expressions, visited for their reads.
    fn bind_target(
        &mut self,
        target: Node<'t>,
        scope: ScopeId,
        kind: DeclKind,
        next: &mut Vec<(Node<'t>, ScopeId)>,
    ) {
        let mut stack = vec![target];
        while let Some(n) = stack.pop() {
            match n.kind() {
                "identifier" => self.bind(scope, n, kind),
                "pattern_list"
                | "tuple_pattern"
                | "list_pattern"
                | "tuple"
                | "list"
                | "list_splat_pattern"
                | "list_splat"
                | "parenthesized_expression"
                | "as_pattern_target"
                | "expression_list" => {
                    stack.extend(children(n));
                }
                _ => next.push((n, scope)),
            }
        }
    }

    /// Binds a name in `scope`: the scope's first binding declares it,
    /// later ones write it. `global` and `nonlocal` names write the outer
    /// one instead.
    fn bind(&mut self, scope: ScopeId, name: Node<'t>, kind: DeclKind) {
        let text = self.text(name);
        if self.globals.get(&scope).is_some_and(|g| g.contains(&text)) {
            if self.m.decls_named(0, &text).is_empty() {
                self.m.declare(0, text, kind, name);
            } else {
                self.write(0, name, text);
            }
            return;
        }
        if self
            .nonlocals
            .get(&scope)
            .is_some_and(|n| n.contains(&text))
        {
            let parent = self.m.scopes[scope].parent.unwrap_or(0);
            self.write(parent, name, text);
            return;
        }
        if self.m.decls_named(scope, &text).is_empty() {
            self.m.declare(scope, text, kind, name);
        } else {
            self.write(scope, name, text);
        }
    }

    fn write(&mut self, scope: ScopeId, name: Node<'t>, text: String) {
        self.m.refs.push(Ref {
            name: text,
            node: name,
            scope,
            read: false,
            write: true,
            decl: None,
        });
    }

    /// A name read where it's written.
    fn reference(&mut self, node: Node<'t>, scope: ScopeId) {
        self.m.refs.push(Ref {
            name: self.text(node),
            node,
            scope,
            read: true,
            write: false,
            decl: None,
        });
    }

    /// Where `x := …` binds: the nearest scope that isn't a comprehension.
    fn walrus_scope(&self, mut scope: ScopeId) -> ScopeId {
        while self.comprehensions.contains(&scope) {
            scope = self.m.scopes[scope].parent.unwrap_or(0);
        }
        scope
    }

    /// `import a.b` binds `a`; `import a.b as c` and `from m import x as c`
    /// bind `c`; `from m import x` binds `x`. Module names are no variables.
    fn import(&mut self, node: Node<'t>, scope: ScopeId) {
        let module = node.child_by_field_name("module_name");
        for c in children(node) {
            if Some(c) == module {
                continue;
            }
            match c.kind() {
                "aliased_import" => {
                    if let Some(alias) = c.child_by_field_name("alias") {
                        self.bind(scope, alias, DeclKind::Import);
                    }
                }
                "dotted_name" => {
                    if let Some(first) = c.named_child(0) {
                        self.bind(scope, first, DeclKind::Import);
                    }
                }
                _ => {}
            }
        }
    }
}

/// The names a parameter binds: `x`, `x: int`, `x=1`, `*args`, `**kwargs`.
fn param_names(p: Node) -> Vec<Node> {
    match p.kind() {
        "identifier" => vec![p],
        "default_parameter" | "typed_default_parameter" => {
            p.child_by_field_name("name").into_iter().collect()
        }
        "typed_parameter" | "list_splat_pattern" | "dictionary_splat_pattern" => children(p)
            .into_iter()
            .filter(|c| c.kind() != "type")
            .flat_map(param_names)
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::{DeclKind, Model};
    use crate::lang::Lang;
    use std::time::{Duration, Instant};

    fn with_model(src: &str, check: impl FnOnce(&Model)) {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&Lang::Python.grammar()).unwrap();
        let tree = parser.parse(src, None).unwrap();
        let model = super::super::build(
            Lang::Python,
            tree.root_node(),
            src.as_bytes(),
            Instant::now() + Duration::from_secs(10),
        )
        .unwrap();
        check(&model);
    }

    /// The declaration each reference named `name` resolves to, by the
    /// line of its declaration (1-based), or 0 when it resolves to none.
    fn resolved(m: &Model, name: &str) -> Vec<usize> {
        m.refs
            .iter()
            .filter(|r| r.name == name && r.read)
            .map(|r| {
                r.decl
                    .map_or(0, |d| m.decls[d].node.start_position().row + 1)
            })
            .collect()
    }

    fn decl(m: &Model, name: &str) -> (DeclKind, u32, u32) {
        let d = m.decls.iter().find(|d| d.name == name).unwrap();
        (d.kind, d.reads, d.writes)
    }

    #[test]
    fn a_function_binds_a_name_anywhere_in_it() {
        let src = "x = 1\ndef f():\n    print(x)\n    x = 2\n    return x\nprint(x)\n";
        with_model(src, |m| {
            // Both reads in `f` are its own `x`, even the one before the
            // assignment; the module's read is the module's.
            assert_eq!(resolved(m, "x"), [4, 4, 1]);
        });
    }

    #[test]
    fn parameters_imports_and_targets_bind() {
        let src = "import os.path\nfrom m import a as b, c\n\
                   def f(p, q: int = 1, *args, k=2, **kw):\n    \
                   for i, (j, *rest) in enumerate(p):\n        pass\n    \
                   with open(q) as fh:\n        pass\n    \
                   try:\n        pass\n    except E as err:\n        pass\n    \
                   return os, b, c, args, kw, k, i, j, rest, fh, err\n";
        with_model(src, |m| {
            for name in ["os", "b", "c"] {
                assert_eq!(decl(m, name).0, DeclKind::Import, "{name}");
            }
            for name in ["p", "q", "args", "kw", "k"] {
                assert_eq!(decl(m, name).0, DeclKind::Param, "{name}");
            }
            for name in ["i", "j", "rest", "fh", "err"] {
                assert_eq!(decl(m, name).0, DeclKind::Var, "{name}");
                assert_eq!(decl(m, name).1, 1, "{name} is read once");
            }
            // Module names and imported names aren't references.
            assert!(
                m.refs
                    .iter()
                    .all(|r| r.name != "path" && r.name != "a" && r.name != "m")
            );
        });
    }

    #[test]
    fn a_class_body_is_not_visible_in_its_methods() {
        let src = "y = 0\nclass C:\n    y = 1\n    z = y\n    def m(self):\n        return y\n";
        with_model(src, |m| {
            // The class body reads its own `y`; the method reads the module's.
            assert_eq!(resolved(m, "y"), [3, 1]);
        });
    }

    #[test]
    fn global_nonlocal_and_walrus() {
        let src = "n = 0\ndef f():\n    global n\n    n = 1\n    \
                   def g():\n        nonlocal t\n        t = 2\n    t = 0\n    \
                   ys = [(w := v) for v in range(3)]\n    return w\n";
        with_model(src, |m| {
            // One `n`, the module's, written by `f`.
            assert_eq!(m.decls.iter().filter(|d| d.name == "n").count(), 1);
            assert_eq!(decl(m, "n").2, 1);
            // `t` is `f`'s, written by `g`.
            assert_eq!(m.decls.iter().filter(|d| d.name == "t").count(), 1);
            // `w` binds in `f`, not in the comprehension.
            assert_eq!(resolved(m, "w"), [9]);
        });
    }

    #[test]
    fn comprehensions_and_lambdas_have_scopes() {
        let src = "x = 9\nsq = [x * x for x in range(x)]\nf = lambda a: a + x\nprint(x)\n";
        with_model(src, |m| {
            // In the comprehension `x` is its own; `range(x)` and the
            // lambda's and the module's `x` are the module's.
            assert_eq!(resolved(m, "x"), [2, 2, 1, 1, 1]);
            assert_eq!(m.functions.len(), 1, "the lambda");
        });
    }

    #[test]
    fn attributes_and_keywords_are_not_names() {
        let src = "def f(o):\n    o.name = 1\n    g(name=o.value)\n";
        with_model(src, |m| {
            assert!(m.refs.iter().all(|r| r.name != "name" && r.name != "value"));
            assert_eq!(decl(m, "o").1, 2);
        });
    }

    #[test]
    fn an_assignment_keeps_its_value() {
        let src = "q = 'SELECT ' + x\n";
        with_model(src, |m| {
            let d = m.decls.iter().find(|d| d.name == "q").unwrap();
            assert_eq!(d.declarator.map(|n| n.kind()), Some("assignment"));
        });
    }

    #[test]
    fn running_out_of_time_gives_no_model() {
        let src = "x = 1\n".repeat(20_000);
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&Lang::Python.grammar()).unwrap();
        let tree = parser.parse(&src, None).unwrap();
        assert!(
            super::super::build(
                Lang::Python,
                tree.root_node(),
                src.as_bytes(),
                Instant::now()
            )
            .is_none()
        );
    }
}
