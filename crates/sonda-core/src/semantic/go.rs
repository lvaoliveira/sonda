//! Scopes and symbols for Go (ADR-0008, S1; tree-sitter-go), the model
//! rules over names and the taint engine of ADR-0027 read.
//!
//! Go resolves names in two ways, and this follows both. At package level
//! (functions, methods, types, `var`, `const`, imports) a name is visible in
//! the whole file whatever its order. Inside a function a declaration takes
//! effect where its statement ends, so `x := x + 1` reads the outer `x`, as
//! the language has it; the order-sensitive resolution Rust's and C's
//! binders use.
//!
//! What opens a scope: the file, functions and function literals (whose body
//! block shares the function's scope, so a `:=` that names a parameter or a
//! named result assigns it), blocks, the statements that declare in their
//! head (`if`, `for`, `switch`, `select`), each `case` clause, and a generic
//! type's parameters. What declares: `:=` (a name already declared in the
//! same scope is assigned, not declared again: `a, err := f()` after an
//! earlier `err`), `var`, `const`, types, parameters, a method's receiver,
//! named results, a `range` or type switch's variables, a `select` receive,
//! type parameters and imports (by their alias, or the path's last element).
//!
//! A struct's fields and a package's other files aren't known here: a name
//! no declaration of the file explains resolves to nothing. Iterative and
//! bounded by the file's deadline, like the other binders.

use super::walk::{Binder, Opened};
use super::{DeclId, DeclKind, Function, Model, ScopeId, ScopeKind};
use std::time::Instant;
use tree_sitter::Node;

struct Go<'t, 's> {
    b: Binder<'t, 's>,
    /// Where each declaration takes effect, by its id.
    effect: Vec<usize>,
}

pub(super) fn build<'t>(root: Node<'t>, src: &[u8], deadline: Instant) -> Option<Model<'t>> {
    let mut go = Go {
        b: Binder::new(src),
        effect: Vec::new(),
    };
    let done = super::walk::run(root, deadline, |node, ancestors, _, scope, _| {
        go.visit(node, ancestors, scope)
    });
    if !done {
        return None;
    }
    go.b.m.root = Some(root);
    go.b.m.resolve_in_order(&go.effect);
    Some(go.b.m)
}

impl<'t> Go<'t, '_> {
    /// Declares `name` as written at `node`, taking effect at `from`.
    fn declare_at(
        &mut self,
        scope: ScopeId,
        name: Node<'t>,
        kind: DeclKind,
        ty: Option<Node<'t>>,
        from: usize,
    ) -> DeclId {
        self.b.declare(scope, name, kind, ty, false);
        self.effect.push(from);
        self.b.m.decls.len() - 1
    }

    fn visit(&mut self, node: Node<'t>, ancestors: &[Node<'t>], scope: ScopeId) -> Opened {
        match node.kind() {
            "function_declaration" => {
                if let Some(name) = node.child_by_field_name("name") {
                    self.declare_at(scope, name, DeclKind::Function, None, 0);
                }
                Some((self.function(node, scope), false))
            }
            "method_declaration" => {
                if let Some(name) = node.child_by_field_name("name") {
                    self.declare_at(scope, name, DeclKind::Method, None, 0);
                }
                Some((self.function(node, scope), false))
            }
            "func_literal" => Some((self.function(node, scope), false)),
            // A function's body shares the scope of its parameters.
            "block" if is_function(ancestors.last()) => None,
            "block"
            | "if_statement"
            | "for_statement"
            | "expression_switch_statement"
            | "select_statement"
            | "expression_case"
            | "default_case"
            | "type_case"
            | "communication_case" => Some((self.b.m.push_scope(scope, ScopeKind::Block), false)),
            "type_switch_statement" => Some((self.type_switch(node, scope), false)),
            "short_var_declaration" => {
                self.short_declaration(node, scope);
                None
            }
            "var_spec" | "const_spec" => {
                self.spec(node, scope);
                None
            }
            "range_clause" => {
                self.range(node, ancestors, scope);
                None
            }
            "receive_statement" => {
                self.receive(node, scope);
                None
            }
            "type_spec" | "type_alias" => self.type_name(node, scope).map(|s| (s, false)),
            "type_parameter_declaration" => {
                self.type_parameters(node, scope);
                None
            }
            "import_spec" => {
                self.import(node, scope);
                None
            }
            "identifier" => {
                self.reference(node, ancestors, scope);
                None
            }
            "type_identifier" => {
                self.type_reference(node, ancestors, scope);
                None
            }
            _ => None,
        }
    }

    // ------------------------------------------------------------ functions

    /// A function's scope, holding its receiver, its parameters and its named
    /// results. Each parameter name is one parameter, as a call counts them
    /// (`a, b int` is two); one with no name holds its place with no names.
    fn function(&mut self, node: Node<'t>, scope: ScopeId) -> ScopeId {
        let inner = self.b.m.push_scope(scope, ScopeKind::Function);
        let from = node.start_byte();
        if let Some(receiver) = node.child_by_field_name("receiver") {
            self.parameters(inner, receiver, from);
        }
        let params = node
            .child_by_field_name("parameters")
            .map(|list| self.parameters(inner, list, from))
            .unwrap_or_default();
        if let Some(result) = node
            .child_by_field_name("result")
            .filter(|r| r.kind() == "parameter_list")
        {
            for names in self.parameters(inner, result, from) {
                for id in names {
                    self.b.m.decls[id].kind = DeclKind::Var;
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

    /// The names a parameter list declares, per parameter.
    fn parameters(&mut self, scope: ScopeId, list: Node<'t>, from: usize) -> Vec<Vec<DeclId>> {
        let mut out = Vec::new();
        let mut c = list.walk();
        let declarations: Vec<Node<'t>> = list
            .named_children(&mut c)
            .filter(|p| {
                matches!(
                    p.kind(),
                    "parameter_declaration" | "variadic_parameter_declaration"
                )
            })
            .collect();
        for p in declarations {
            let ty = p.child_by_field_name("type");
            let mut nc = p.walk();
            let names: Vec<Node<'t>> = p.children_by_field_name("name", &mut nc).collect();
            if names.is_empty() {
                out.push(Vec::new());
            }
            for name in names {
                if self.b.text(name) == "_" {
                    self.b.not_refs.insert(name.id());
                    out.push(Vec::new());
                    continue;
                }
                let id = self.declare_at(scope, name, DeclKind::Param, ty, from);
                self.b.m.decls[id].declarator = Some(p);
                out.push(vec![id]);
            }
        }
        out
    }

    // ------------------------------------------------------------ statements

    /// `switch v := x.(type)`: `v`, visible in the clauses, after the value.
    fn type_switch(&mut self, node: Node<'t>, scope: ScopeId) -> ScopeId {
        let inner = self.b.m.push_scope(scope, ScopeKind::Block);
        if let Some(alias) = node.child_by_field_name("alias") {
            let from = node
                .child_by_field_name("value")
                .map_or(alias.end_byte(), |v| v.end_byte());
            for name in identifiers(alias) {
                let id = self.declare_at(inner, name, DeclKind::Let, None, from);
                self.b.m.decls[id].writes += 1;
            }
        }
        inner
    }

    /// `a, b := ...`: each name new to the scope is declared, from the end of
    /// the statement; one it already has is assigned, which the walk reads as
    /// a reference.
    fn short_declaration(&mut self, node: Node<'t>, scope: ScopeId) {
        let Some(left) = node.child_by_field_name("left") else {
            return;
        };
        for name in identifiers(left) {
            let text = self.b.text(name);
            if text == "_" {
                self.b.not_refs.insert(name.id());
            } else if self.b.m.decls_named(scope, &text).is_empty() {
                let id = self.declare_at(scope, name, DeclKind::Var, None, node.end_byte());
                self.b.m.decls[id].writes += 1;
                self.b.m.decls[id].declarator = Some(node);
            }
        }
    }

    /// A `var` or a `const` spec: each name, with the type written for it.
    /// At package level a name is visible everywhere; in a function, from the
    /// end of the spec.
    fn spec(&mut self, node: Node<'t>, scope: ScopeId) {
        let ty = node.child_by_field_name("type");
        let is_const = node.kind() == "const_spec";
        let initialized = node.child_by_field_name("value").is_some();
        let from = if scope == 0 { 0 } else { node.end_byte() };
        let mut c = node.walk();
        let names: Vec<Node<'t>> = node.children_by_field_name("name", &mut c).collect();
        for name in names {
            if self.b.text(name) == "_" {
                self.b.not_refs.insert(name.id());
                continue;
            }
            let kind = if is_const {
                DeclKind::Const
            } else {
                DeclKind::Var
            };
            let id = self.declare_at(scope, name, kind, ty, from);
            self.b.m.decls[id].writes += u32::from(initialized || is_const);
            self.b.m.decls[id].declarator = Some(node);
        }
    }

    /// `for k, v := range xs`: the variables, bound in the body. With `=`
    /// they're assigned, not declared.
    fn range(&mut self, node: Node<'t>, ancestors: &[Node<'t>], scope: ScopeId) {
        let declares = {
            let mut c = node.walk();
            node.children(&mut c).any(|k| k.kind() == ":=")
        };
        let (Some(left), true) = (node.child_by_field_name("left"), declares) else {
            return;
        };
        let from = ancestors
            .last()
            .and_then(|f| f.child_by_field_name("body"))
            .map_or(node.end_byte(), |b| b.start_byte());
        for name in identifiers(left) {
            if self.b.text(name) == "_" {
                self.b.not_refs.insert(name.id());
                continue;
            }
            let id = self.declare_at(scope, name, DeclKind::Let, None, from);
            self.b.m.decls[id].writes += 1;
        }
    }

    /// `case v := <-ch:`: `v`, for the clause.
    fn receive(&mut self, node: Node<'t>, scope: ScopeId) {
        let declares = {
            let mut c = node.walk();
            node.children(&mut c).any(|k| k.kind() == ":=")
        };
        let (Some(left), true) = (node.child_by_field_name("left"), declares) else {
            return;
        };
        for name in identifiers(left) {
            if self.b.text(name) == "_" {
                self.b.not_refs.insert(name.id());
                continue;
            }
            let id = self.declare_at(scope, name, DeclKind::Let, None, node.end_byte());
            self.b.m.decls[id].writes += 1;
        }
    }

    // ------------------------------------------------------------ names

    /// A type's name, visible in its own definition; a generic type's
    /// parameters get a scope of their own.
    fn type_name(&mut self, node: Node<'t>, scope: ScopeId) -> Option<ScopeId> {
        let name = node.child_by_field_name("name")?;
        let from = if scope == 0 { 0 } else { node.start_byte() };
        self.declare_at(scope, name, DeclKind::Class, None, from);
        node.child_by_field_name("type_parameters")
            .map(|_| self.b.m.push_scope(scope, ScopeKind::Block))
    }

    fn type_parameters(&mut self, node: Node<'t>, scope: ScopeId) {
        let mut c = node.walk();
        let names: Vec<Node<'t>> = node.children_by_field_name("name", &mut c).collect();
        for name in names {
            self.declare_at(scope, name, DeclKind::Type, None, node.start_byte());
        }
    }

    /// An import, by its alias or the last element of its path. A blank or
    /// dot import names nothing. The package's own name can differ from its
    /// path (`gopkg.in/yaml.v3` is `yaml`): the usual suffixes are dropped,
    /// and a name a path doesn't give resolves to nothing.
    fn import(&mut self, node: Node<'t>, scope: ScopeId) {
        let Some(path) = node.child_by_field_name("path") else {
            return;
        };
        let alias = node.child_by_field_name("name");
        let (text, at) = match alias {
            Some(a) => (self.b.text(a), a),
            None => (package_name(&self.b.text(path)), path),
        };
        self.b.not_refs.insert(at.id());
        if text.is_empty() || text == "_" || text == "." {
            return;
        }
        self.b.m.declare(scope, text, DeclKind::Import, at);
        self.effect.push(0);
    }

    // ------------------------------------------------------------ references

    fn reference(&mut self, node: Node<'t>, ancestors: &[Node<'t>], scope: ScopeId) {
        if self.b.not_refs.contains(&node.id()) || self.b.text(node) == "_" {
            return;
        }
        let (read, write) = access(ancestors, &self.b);
        self.b.add_ref(node, scope, read, write);
    }

    /// A type's name used: not the `T` of `pkg.T`, which names a member.
    fn type_reference(&mut self, node: Node<'t>, ancestors: &[Node<'t>], scope: ScopeId) {
        if self.b.not_refs.contains(&node.id())
            || ancestors
                .last()
                .is_some_and(|p| p.kind() == "qualified_type")
        {
            return;
        }
        self.b.add_ref(node, scope, true, false);
    }
}

/// Whether a node is a function's, so its `block` is the function's body.
fn is_function(node: Option<&Node>) -> bool {
    node.is_some_and(|n| {
        matches!(
            n.kind(),
            "function_declaration" | "method_declaration" | "func_literal"
        )
    })
}

/// The names in an expression list.
fn identifiers<'t>(list: Node<'t>) -> Vec<Node<'t>> {
    let mut c = list.walk();
    list.named_children(&mut c)
        .filter(|n| n.kind() == "identifier")
        .collect()
}

/// What a package's path says its name is: the last element, without a
/// major-version element (`/v2`) or a `.v3` suffix.
fn package_name(literal: &str) -> String {
    let path = literal.trim_matches(['"', '`']);
    let mut parts = path.rsplit('/');
    let mut last = parts.next().unwrap_or(path);
    if last.len() > 1 && last.starts_with('v') && last[1..].bytes().all(|b| b.is_ascii_digit()) {
        last = parts.next().unwrap_or(last);
    }
    let last = match last.rsplit_once(".v") {
        Some((name, version)) if version.bytes().all(|b| b.is_ascii_digit()) => name,
        _ => last,
    };
    last.to_string()
}

/// Whether the reference `node` reads its variable and whether it writes it.
fn access(ancestors: &[Node], b: &Binder) -> (bool, bool) {
    let Some(&parent) = ancestors.last() else {
        return (true, false);
    };
    match parent.kind() {
        "inc_statement" | "dec_statement" => (true, true),
        "expression_list" => {
            let Some(&holder) = ancestors
                .len()
                .checked_sub(2)
                .and_then(|i| ancestors.get(i))
            else {
                return (true, false);
            };
            let on_left = holder
                .child_by_field_name("left")
                .is_some_and(|l| l.id() == parent.id());
            match holder.kind() {
                "assignment_statement" if on_left => {
                    let plain = holder
                        .child_by_field_name("operator")
                        .is_some_and(|o| b.text(o) == "=");
                    (!plain, true)
                }
                "short_var_declaration" | "range_clause" | "receive_statement" if on_left => {
                    (false, true)
                }
                _ => (true, false),
            }
        }
        _ => (true, false),
    }
}

#[cfg(test)]
mod tests {
    use super::super::{DeclKind, Model};
    use crate::lang::Lang;
    use std::time::{Duration, Instant};

    fn go(src: &str, check: impl FnOnce(&Model)) {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&Lang::Go.grammar()).unwrap();
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
    fn a_declaration_takes_effect_where_its_statement_ends() {
        let src =
            "package p\n\nvar x = 1\n\nfunc f() int {\n\tx = 2\n\tx := x + 1\n\treturn x\n}\n";
        go(src, |m| {
            assert_eq!(count(m, "x"), 2);
            // The package's `x` is written by `x = 2` and read by `x + 1`;
            // the local one is read by `return x`.
            assert_eq!(decl(m, "x", 0), (DeclKind::Var, 1, 2));
            assert_eq!(decl(m, "x", 1), (DeclKind::Var, 1, 1));
        });
    }

    #[test]
    fn a_short_declaration_assigns_a_name_the_scope_already_has() {
        let src = "package p\n\nfunc f() (err error) {\n\ta, err := g()\n\tif a > 0 {\n\t\tb, err := g()\n\t\t_ = b\n\t}\n\treturn err\n}\n\nfunc g() (int, error) { return 0, nil }\n";
        go(src, |m| {
            // The named result, assigned by the first `:=`; and the inner
            // block's own `err`, which shadows it.
            assert_eq!(count(m, "err"), 2);
            assert_eq!(decl(m, "err", 0).2, 1, "assigned, not declared again");
            assert_eq!(decl(m, "err", 0).1, 1, "`return err`");
            assert_eq!(decl(m, "err", 1), (DeclKind::Var, 0, 1));
        });
    }

    #[test]
    fn parameters_are_one_per_name_and_receivers_are_not_parameters() {
        let src = "package p\n\ntype T struct{}\n\nfunc (t *T) m(a, b int, c ...string) (n int) { return a + b + n }\n\nfunc g(int, string) {}\n";
        go(src, |m| {
            let params: Vec<usize> = m.functions.iter().map(|f| f.params.len()).collect();
            assert_eq!(params, [3, 2]);
            assert_eq!(decl(m, "a", 0), (DeclKind::Param, 1, 0));
            assert_eq!(decl(m, "t", 0).0, DeclKind::Param, "the receiver");
            assert_eq!(decl(m, "n", 0).0, DeclKind::Var, "a named result");
            assert!(m.functions[1].params.iter().all(Vec::is_empty));
            assert_eq!(decl(m, "m", 0).0, DeclKind::Method);
        });
    }

    #[test]
    fn statements_that_declare_in_their_head() {
        let src = "package p\n\nfunc f(xs []int, ch chan int, v interface{}) {\n\tfor i := 0; i < 3; i++ {\n\t\t_ = i\n\t}\n\tfor k, x := range xs {\n\t\t_, _ = k, x\n\t}\n\tif n := len(xs); n > 0 {\n\t\t_ = n\n\t} else {\n\t\t_ = n\n\t}\n\tselect {\n\tcase m := <-ch:\n\t\t_ = m\n\t}\n\tswitch t := v.(type) {\n\tcase int:\n\t\t_ = t\n\tcase string:\n\t\t_ = t\n\t}\n}\n";
        go(src, |m| {
            assert_eq!(decl(m, "i", 0).1, 3, "the condition, the update, the body");
            assert_eq!(decl(m, "k", 0).1, 1);
            assert_eq!(decl(m, "x", 0).1, 1);
            assert_eq!(decl(m, "n", 0).1, 3, "the condition, both branches");
            assert_eq!(decl(m, "m", 0).1, 1);
            assert_eq!(decl(m, "t", 0).1, 2, "both clauses");
            assert_eq!(decl(m, "xs", 0).1, 2, "`len(xs)` and the range");
        });
    }

    #[test]
    fn access_assignments_updates_and_struct_writes() {
        let src = "package p\n\ntype P struct{ n int }\n\nfunc f(p *P) {\n\tvar x, y int\n\tx = 1\n\ty += 2\n\tx++\n\tp.n = 3\n}\n";
        go(src, |m| {
            assert_eq!(
                decl(m, "x", 0),
                (DeclKind::Var, 1, 2),
                "`x++` reads and writes"
            );
            assert_eq!(decl(m, "y", 0).1, 1, "`+=` reads");
            assert_eq!(decl(m, "y", 0).2, 1);
            assert_eq!(
                decl(m, "p", 0).2,
                0,
                "a write through a field isn't a write of it"
            );
        });
    }

    #[test]
    fn imports_package_level_names_and_function_literals() {
        let src = "package p\n\nimport (\n\t\"fmt\"\n\tyaml \"gopkg.in/yaml.v3\"\n\t_ \"net/http/pprof\"\n\t\"math/rand/v2\"\n)\n\nconst limit = 3\n\ntype Item struct{ name string }\n\nfunc run(items []Item) {\n\tf := func(i Item) { fmt.Println(i.name, limit, rand.IntN(2)) }\n\tf(items[0])\n\t_ = yaml.Marshal\n}\n";
        go(src, |m| {
            assert_eq!(decl(m, "fmt", 0), (DeclKind::Import, 1, 0));
            assert_eq!(decl(m, "yaml", 0).1, 1, "an alias");
            assert_eq!(decl(m, "rand", 0).1, 1, "a major version path");
            assert_eq!(count(m, "pprof"), 0, "a blank import names nothing");
            assert_eq!(decl(m, "limit", 0), (DeclKind::Const, 1, 1));
            assert_eq!(decl(m, "Item", 0).1, 2, "the parameter types");
            assert_eq!(m.functions.len(), 2, "run and the literal");
            assert_eq!(m.functions[1].params.len(), 1);
            assert_eq!(decl(m, "f", 0).1, 1);
        });
    }

    #[test]
    fn generic_functions_and_types_declare_their_type_parameters() {
        let src = "package p\n\ntype List[T any] struct{ items []T }\n\nfunc First[T any](l List[T]) T { return l.items[0] }\n";
        go(src, |m| {
            assert_eq!(count(m, "T"), 2, "one per generic declaration");
            assert!(
                m.decls
                    .iter()
                    .filter(|d| d.name == "T")
                    .all(|d| d.kind == DeclKind::Type)
            );
            assert_eq!(decl(m, "List", 0).1, 1);
        });
    }
}
