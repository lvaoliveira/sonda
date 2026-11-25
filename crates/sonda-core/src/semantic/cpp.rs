//! Scopes and symbols for C and C++ (ADR-0008, S1; tree-sitter-c and
//! tree-sitter-cpp), the model the taint engine of ADR-0027 reads.
//!
//! A declaration takes effect where its declarator ends, so `int x = x;`
//! reads the new `x` and `x = 1; int x;` the one outside, as the languages
//! have it: the order-sensitive resolution Rust's binder uses. Functions,
//! methods, enumerators and classes are visible in their whole scope.
//!
//! What opens a scope: namespaces, classes (a type scope, which an
//! out-of-line `C::f` defined after the class in the same file joins), functions
//! and lambdas, blocks, and the statements that declare in their head (`if`,
//! `while`, `switch`, `for`, a range `for`, `catch`). What declares: variables
//! (every declarator of a declaration, through pointers, references, arrays
//! and `auto [a, b]`), function prototypes, parameters, the fields and
//! methods of a class, enumerators, and a lambda's captures with an
//! initializer.
//!
//! The syntax tree alone can't settle what a macro expands to, or which
//! `#if` branch the build compiles: every branch is read, a macro is a
//! call, and a name no declaration in the file explains resolves to nothing.
//!
//! Iterative and bounded by the file's deadline, like the other binders.

use super::walk::{Binder, Opened};
use super::{DeclId, DeclKind, Function, Model, ScopeId, ScopeKind};
use std::collections::HashMap;
use std::time::Instant;
use tree_sitter::Node;

/// The binder of C and C++: the shared one, where each declaration takes
/// effect, by its id, and the scope of each class the file declares.
struct Cpp<'t, 's> {
    b: Binder<'t, 's>,
    effect: Vec<usize>,
    classes: HashMap<String, ScopeId>,
}

pub(super) fn build<'t>(root: Node<'t>, src: &[u8], deadline: Instant) -> Option<Model<'t>> {
    let mut cpp = Cpp {
        b: Binder::new(src),
        effect: Vec::new(),
        classes: HashMap::new(),
    };
    let done = super::walk::run(root, deadline, |node, ancestors, field, scope, _| {
        cpp.visit(node, ancestors, field, scope)
    });
    if !done {
        return None;
    }
    cpp.b.m.root = Some(root);
    cpp.b.m.resolve_in_order(&cpp.effect);
    Some(cpp.b.m)
}

/// What a declarator declares.
enum Declared<'t> {
    /// A variable, a field, or a parameter.
    Name(Node<'t>),
    /// A function or a method's name: a prototype.
    Function(Node<'t>),
    /// `auto [a, b] = ..`.
    Bindings(Vec<Node<'t>>),
}

impl<'t> Cpp<'t, '_> {
    fn visit(
        &mut self,
        node: Node<'t>,
        ancestors: &[Node<'t>],
        field: Option<&str>,
        scope: ScopeId,
    ) -> Opened {
        let _ = field;
        match node.kind() {
            "function_definition" => Some((self.function(node, scope), false)),
            "lambda_expression" => Some((self.lambda(node, scope), false)),
            "namespace_definition" => Some((self.b.m.push_scope(scope, ScopeKind::Module), false)),
            "class_specifier" | "struct_specifier" | "union_specifier" => {
                self.class(node, scope).map(|s| (s, true))
            }
            "compound_statement" | "if_statement" | "while_statement" | "switch_statement"
            | "for_statement" => Some((self.b.m.push_scope(scope, ScopeKind::Block), false)),
            "for_range_loop" => Some((self.range_for(node, scope), false)),
            "catch_clause" => Some((self.catch(node, scope), false)),
            "declaration" => {
                self.declaration(node, scope);
                None
            }
            "field_declaration" => {
                self.field(node, scope);
                None
            }
            "enumerator" => {
                if let Some(name) = node.child_by_field_name("name") {
                    self.b
                        .declare_at(&mut self.effect, scope, name, DeclKind::Const, None, 0);
                }
                None
            }
            "lambda_capture_initializer" => {
                if let Some(name) = node.child_by_field_name("left") {
                    self.b.declare_at(
                        &mut self.effect,
                        scope,
                        name,
                        DeclKind::Let,
                        None,
                        node.start_byte(),
                    );
                }
                None
            }
            "identifier" | "this" => {
                self.reference(node, ancestors, scope);
                None
            }
            _ => None,
        }
    }

    // ------------------------------------------------------------ declarators

    /// What a declarator declares, through pointers, references, arrays,
    /// parentheses and an initializer.
    fn declared(&self, d: Node<'t>) -> Option<Declared<'t>> {
        let mut d = d;
        let mut function = false;
        loop {
            match d.kind() {
                "identifier" | "field_identifier" => {
                    return Some(if function {
                        Declared::Function(d)
                    } else {
                        Declared::Name(d)
                    });
                }
                "function_declarator" => {
                    let inner = d.child_by_field_name("declarator")?;
                    // `f(int)` declares a function; `(*cb)(int)` a variable.
                    function = !matches!(inner.kind(), "parenthesized_declarator");
                    d = inner;
                }
                "init_declarator"
                | "pointer_declarator"
                | "reference_declarator"
                | "array_declarator"
                | "parenthesized_declarator"
                | "attributed_declarator" => {
                    d = d
                        .child_by_field_name("declarator")
                        .or_else(|| d.named_child(0))?;
                }
                "structured_binding_declarator" => {
                    let mut c = d.walk();
                    return Some(Declared::Bindings(
                        d.named_children(&mut c)
                            .filter(|n| n.kind() == "identifier")
                            .collect(),
                    ));
                }
                _ => return None,
            }
        }
    }

    /// Declares what `d` does, a variable by default; the ids.
    fn bind(
        &mut self,
        scope: ScopeId,
        d: Node<'t>,
        kind: DeclKind,
        ty: Option<Node<'t>>,
        holder: Node<'t>,
        from: usize,
    ) -> Vec<DeclId> {
        let ids: Vec<DeclId> = match self.declared(d) {
            Some(Declared::Name(n)) => {
                vec![
                    self.b
                        .declare_at(&mut self.effect, scope, n, kind, ty, from),
                ]
            }
            Some(Declared::Function(n)) => {
                vec![
                    self.b
                        .declare_at(&mut self.effect, scope, n, DeclKind::Function, ty, 0),
                ]
            }
            Some(Declared::Bindings(names)) => names
                .into_iter()
                .map(|n| {
                    self.b
                        .declare_at(&mut self.effect, scope, n, kind, ty, from)
                })
                .collect(),
            None => Vec::new(),
        };
        for &id in &ids {
            self.b.m.decls[id].declarator = Some(holder);
        }
        ids
    }

    /// A declaration's variables: each declarator, bound from its end. A
    /// condition's (`if (auto r = f())`) has its initializer in `value`.
    fn declaration(&mut self, node: Node<'t>, scope: ScopeId) {
        let ty = node.child_by_field_name("type");
        let is_static = {
            let mut c = node.walk();
            node.children(&mut c)
                .any(|k| k.kind() == "storage_class_specifier" && self.b.text(k) == "static")
        };
        let first = self.b.m.decls.len();
        let mut c = node.walk();
        let declarators: Vec<Node<'t>> =
            node.children_by_field_name("declarator", &mut c).collect();
        for d in declarators {
            let initialized =
                d.kind() == "init_declarator" || node.child_by_field_name("value").is_some();
            // Visible in its own initializer: from the end of the declarator.
            let from = d.child_by_field_name("declarator").unwrap_or(d).end_byte();
            let ids = self.bind(scope, d, DeclKind::Var, ty, d, from);
            for id in ids {
                self.b.m.decls[id].writes += u32::from(initialized);
            }
        }
        for id in first..self.b.m.decls.len() {
            self.b.m.decls[id].is_static = is_static;
        }
    }

    /// A field or a method declared in a class's body.
    fn field(&mut self, node: Node<'t>, scope: ScopeId) {
        let ty = node.child_by_field_name("type");
        let mut c = node.walk();
        let declarators: Vec<Node<'t>> =
            node.children_by_field_name("declarator", &mut c).collect();
        for d in declarators {
            let kind = match self.declared(d) {
                Some(Declared::Function(_)) => DeclKind::Method,
                _ => DeclKind::Field,
            };
            if let Some(Declared::Function(n) | Declared::Name(n)) = self.declared(d) {
                self.b.declare_at(&mut self.effect, scope, n, kind, ty, 0);
            }
        }
    }

    // ------------------------------------------------------------ scopes

    /// A class's name, and its body's scope.
    fn class(&mut self, node: Node<'t>, scope: ScopeId) -> Option<ScopeId> {
        node.child_by_field_name("body")?;
        let inner = self.b.m.push_scope(scope, ScopeKind::Type);
        if let Some(name) = node.child_by_field_name("name") {
            self.b
                .declare_at(&mut self.effect, scope, name, DeclKind::Class, None, 0);
            self.classes.insert(self.b.text(name), inner);
            self.b.m.type_scopes.push((node, inner));
        }
        Some(inner)
    }

    /// The function declarator of a definition, through the pointers and
    /// references of a return type that the declarator carries.
    fn function_declarator(d: Node<'t>) -> Option<Node<'t>> {
        let mut d = d;
        loop {
            match d.kind() {
                "function_declarator" => return Some(d),
                "pointer_declarator"
                | "reference_declarator"
                | "parenthesized_declarator"
                | "attributed_declarator" => {
                    d = d
                        .child_by_field_name("declarator")
                        .or_else(|| d.named_child(0))?;
                }
                _ => return None,
            }
        }
    }

    /// A function's name, in its scope, and its parameters in a scope of
    /// their own (a method's inside its class's, with `this`).
    fn function(&mut self, node: Node<'t>, scope: ScopeId) -> ScopeId {
        let fd = node
            .child_by_field_name("declarator")
            .and_then(Self::function_declarator);
        let name = fd.and_then(|f| f.child_by_field_name("declarator"));
        let mut parent = scope;
        let mut method = self.b.m.scopes[scope].kind == ScopeKind::Type;
        if let Some(name) = name {
            match name.kind() {
                "identifier" => {
                    self.b
                        .declare_at(&mut self.effect, scope, name, DeclKind::Function, None, 0);
                }
                "field_identifier" => {
                    self.b
                        .declare_at(&mut self.effect, scope, name, DeclKind::Method, None, 0);
                }
                // `C::f`: a member of a class defined earlier in the file.
                "qualified_identifier" => {
                    method = true;
                    if let Some(class) = name
                        .child_by_field_name("scope")
                        .and_then(|s| self.classes.get(&self.b.text(s)))
                    {
                        parent = *class;
                    }
                }
                _ => method |= matches!(name.kind(), "destructor_name" | "operator_name"),
            }
        }
        let inner = self.b.m.push_scope(parent, ScopeKind::Function);
        let from = node.start_byte();
        if method {
            self.declare_this(inner, node, from);
        }
        let params = fd
            .and_then(|f| f.child_by_field_name("parameters"))
            .map(|list| self.parameters(inner, list, from))
            .unwrap_or_default();
        self.b.m.functions.push(Function {
            node,
            scope: inner,
            params,
        });
        inner
    }

    /// `this`, a method's implicit parameter; its node is the function's.
    fn declare_this(&mut self, scope: ScopeId, function: Node<'t>, from: usize) {
        self.b
            .m
            .declare(scope, "this".to_string(), DeclKind::Param, function);
        self.effect.push(from);
    }

    /// A lambda: its parameters, in a scope of their own.
    fn lambda(&mut self, node: Node<'t>, scope: ScopeId) -> ScopeId {
        let inner = self.b.m.push_scope(scope, ScopeKind::Function);
        let params = node
            .child_by_field_name("declarator")
            .and_then(|d| d.child_by_field_name("parameters"))
            .map(|list| self.parameters(inner, list, node.start_byte()))
            .unwrap_or_default();
        self.b.m.functions.push(Function {
            node,
            scope: inner,
            params,
        });
        inner
    }

    /// A parameter list's names, per parameter. `(void)` has none, and an
    /// unnamed parameter holds a place with no names.
    fn parameters(&mut self, scope: ScopeId, list: Node<'t>, from: usize) -> Vec<Vec<DeclId>> {
        let mut out = Vec::new();
        let mut c = list.walk();
        let params: Vec<Node<'t>> = list
            .named_children(&mut c)
            .filter(|p| {
                matches!(
                    p.kind(),
                    "parameter_declaration" | "optional_parameter_declaration"
                )
            })
            .collect();
        for p in &params {
            let declarator = p.child_by_field_name("declarator");
            if params.len() == 1
                && declarator.is_none()
                && p.child_by_field_name("type")
                    .is_some_and(|t| self.b.text(t) == "void")
            {
                break;
            }
            let ty = p.child_by_field_name("type");
            out.push(match declarator {
                Some(d) => self.bind(scope, d, DeclKind::Param, ty, *p, from),
                None => Vec::new(),
            });
        }
        out
    }

    /// A range `for`: its variable, bound in the body.
    fn range_for(&mut self, node: Node<'t>, scope: ScopeId) -> ScopeId {
        let inner = self.b.m.push_scope(scope, ScopeKind::Block);
        if let (Some(d), Some(body)) = (
            node.child_by_field_name("declarator"),
            node.child_by_field_name("body"),
        ) {
            let ty = node.child_by_field_name("type");
            let ids = self.bind(inner, d, DeclKind::Let, ty, node, body.start_byte());
            for id in ids {
                self.b.m.decls[id].writes += 1;
            }
        }
        inner
    }

    /// A `catch`'s parameter, bound in its body.
    fn catch(&mut self, node: Node<'t>, scope: ScopeId) -> ScopeId {
        let inner = self.b.m.push_scope(scope, ScopeKind::Block);
        if let Some(list) = node.child_by_field_name("parameters") {
            self.parameters(inner, list, node.start_byte());
        }
        inner
    }

    // ------------------------------------------------------------ references

    fn reference(&mut self, node: Node<'t>, ancestors: &[Node<'t>], scope: ScopeId) {
        if self.b.not_refs.contains(&node.id()) {
            return;
        }
        let Some(&parent) = ancestors.last() else {
            return;
        };
        // `ns::f`'s parts, and the names of the preprocessor.
        if parent.kind() == "qualified_identifier"
            || parent.kind().starts_with("preproc_")
            || in_condition(node, ancestors)
        {
            return;
        }
        let (read, write) = self.access(node, parent);
        self.b.add_ref(node, scope, read, write);
    }

    /// Whether the reference `node` reads its variable and whether it
    /// writes it.
    fn access(&self, node: Node, parent: Node) -> (bool, bool) {
        match parent.kind() {
            "assignment_expression" if parent.child_by_field_name("left") == Some(node) => {
                let plain = parent
                    .child_by_field_name("operator")
                    .is_some_and(|o| self.b.text(o) == "=");
                (!plain, true)
            }
            "update_expression" => (true, true),
            _ => (true, false),
        }
    }
}

/// Whether `node` is in the condition of a preprocessor `#if`.
fn in_condition(node: Node, ancestors: &[Node]) -> bool {
    ancestors.iter().any(|a| {
        matches!(a.kind(), "preproc_if" | "preproc_elif")
            && a.child_by_field_name("condition").is_some_and(|c| {
                c.start_byte() <= node.start_byte() && node.end_byte() <= c.end_byte()
            })
    })
}

#[cfg(test)]
mod tests {
    use super::super::test_model::{count, decl, with_model};
    use super::super::{DeclKind, Model, ScopeKind};
    use crate::lang::Lang;

    fn cpp(src: &str, check: impl FnOnce(&Model)) {
        with_model(Lang::Cpp, src, check);
    }

    #[test]
    fn declarators_through_pointers_arrays_and_initializers() {
        let src = "void f() {\n    int x = 1, *y = &x, z[3];\n    char buf[10] = {0};\n    auto [p, q] = pair();\n    void (*cb)(int) = nullptr;\n    use(x, y, z, buf, p, q, cb);\n}";
        cpp(src, |m| {
            for n in ["x", "y", "z", "buf", "p", "q", "cb"] {
                assert_eq!(count(m, n), 1, "{n}");
            }
            assert_eq!(decl(m, "x", 0), (DeclKind::Var, 2, 1), "`&x` and the call");
            assert_eq!(decl(m, "z", 0).2, 0, "no initializer");
            assert_eq!(decl(m, "cb", 0).0, DeclKind::Var, "a function pointer");
        });
    }

    #[test]
    fn a_declaration_takes_effect_where_its_declarator_ends() {
        let src = "int x;\nvoid f() {\n    x = 1;\n    int x = x + 1;\n    use(x);\n}";
        cpp(src, |m| {
            assert_eq!(count(m, "x"), 2);
            // The global is written by `x = 1`; the local reads itself.
            assert_eq!(decl(m, "x", 0).2, 1);
            assert_eq!(decl(m, "x", 1).1, 2);
        });
    }

    #[test]
    fn parameters_by_position() {
        let src = "int main(int argc, char **argv) { return argc; }\nvoid g(void) {}\nvoid h(int, const char *s, ...) { use(s); }\nint k(int a = 3) { return a; }";
        cpp(src, |m| {
            let params: Vec<usize> = m.functions.iter().map(|f| f.params.len()).collect();
            assert_eq!(params, [2, 0, 2, 1]);
            assert_eq!(decl(m, "argv", 0).0, DeclKind::Param);
            assert_eq!(decl(m, "argc", 0).1, 1);
            // The unnamed one holds its place.
            assert!(m.functions[2].params[0].is_empty());
            assert_eq!(m.functions[2].params[1].len(), 1);
        });
    }

    #[test]
    fn statements_that_declare_in_their_head() {
        let src = "void f(Vec v) {\n    for (int i = 0; i < 3; i++) use(i);\n    for (auto &e : v) use(e);\n    if (auto r = g(); r > 0) use(r); else use(r);\n    while (char *p = next()) use(p);\n    try { } catch (const E &ex) { use(ex); }\n}";
        cpp(src, |m| {
            assert_eq!(decl(m, "i", 0).1, 3, "the condition, the update, the body");
            assert_eq!(decl(m, "e", 0).1, 1);
            assert_eq!(decl(m, "r", 0).1, 3, "the condition, both branches");
            assert_eq!(decl(m, "p", 0).1, 1);
            assert_eq!(decl(m, "ex", 0).1, 1);
            assert_eq!(decl(m, "v", 0).1, 1, "the loop's range");
        });
    }

    #[test]
    fn lambdas_with_captures() {
        let src =
            "void f() {\n    int x = 1;\n    auto l = [&x, k = 2](int m) { return m + x + k; };\n}";
        cpp(src, |m| {
            assert_eq!(m.functions.len(), 2, "f and the lambda");
            assert_eq!(m.functions[1].params.len(), 1);
            assert_eq!(decl(m, "m", 0).1, 1);
            assert_eq!(decl(m, "k", 0).1, 1, "a capture with an initializer");
            assert_eq!(decl(m, "x", 0).1, 2, "the capture list and the body");
        });
    }

    #[test]
    fn classes_methods_fields_and_this() {
        let src = "class C {\n    int fld;\npublic:\n    C(int a) : fld(a) {}\n    int get() const { return fld + this->fld; }\n    static int g();\n};\nint C::g() { return 1; }\nvoid C::set(int v) { fld = v; }\n";
        cpp(src, |m| {
            assert_eq!(decl(m, "fld", 0).0, DeclKind::Field);
            assert_eq!(decl(m, "get", 0).0, DeclKind::Method);
            assert_eq!(
                decl(m, "g", 0).0,
                DeclKind::Method,
                "a prototype in the class"
            );
            // The constructor's initializer reads its parameter; `get` reads
            // the field twice, and `set`, defined outside the class, writes it.
            assert_eq!(decl(m, "a", 0).1, 1);
            assert_eq!(
                decl(m, "fld", 0).1,
                1,
                "`this->fld` names a member, not a variable"
            );
            assert_eq!(decl(m, "fld", 0).2, 1);
            // One `this` per method with a body: the constructor, `get`, `C::g` and `C::set`.
            assert_eq!(count(m, "this"), 4);
            assert_eq!(decl(m, "this", 1).1, 1, "`this->fld` reads it");
            assert_eq!(m.type_scopes.len(), 1);
            assert!(m.scopes.iter().any(|s| s.kind == ScopeKind::Type));
        });
    }

    #[test]
    fn namespaces_enumerators_qualified_names_and_the_preprocessor() {
        let src = "#define LIMIT 5\n#if LIMIT > 3 && defined(X)\nint on;\n#endif\nnamespace ns { int g(int a) { return a; } enum E { A, B = 2 }; int h() { return A; } }\nvoid f() {\n    ns::g(1);\n    std::move(x);\n    use(on);\n}";
        cpp(src, |m| {
            assert_eq!(decl(m, "A", 0), (DeclKind::Const, 1, 0));
            let names: Vec<&str> = m.refs.iter().map(|r| r.name.as_str()).collect();
            assert!(!names.contains(&"LIMIT"), "{names:?}");
            assert!(!names.contains(&"ns"), "{names:?}");
            assert!(!names.contains(&"move"), "{names:?}");
            assert_eq!(decl(m, "on", 0).1, 1, "a declaration under #if is read");
            assert_eq!(decl(m, "g", 0).0, DeclKind::Function);
        });
    }

    #[test]
    fn access_assignments_updates_and_pointer_writes() {
        let src = "void f(int *p, int a[]) {\n    int x, y = 0;\n    x = 1;\n    y += 2;\n    x++;\n    *p = 3;\n    a[0] = 4;\n}";
        cpp(src, |m| {
            assert_eq!(
                decl(m, "x", 0),
                (DeclKind::Var, 1, 2),
                "`x++` reads and writes"
            );
            assert_eq!(decl(m, "y", 0).2, 2);
            assert_eq!(
                decl(m, "p", 0).2,
                0,
                "a write through a pointer isn't a write of it"
            );
        });
    }

    #[test]
    fn c_files_bind_too() {
        let src = "#include <stdio.h>\nstatic int n;\nstruct node { struct node *next; int v; };\nint main(int argc, char **argv) {\n    char *s = argv[1];\n    for (int i = 0; i < argc; i++) n += i;\n    printf(\"%s\", s);\n    return 0;\n}";
        with_model(Lang::C, src, |m| {
            assert_eq!(decl(m, "s", 0), (DeclKind::Var, 1, 1));
            assert_eq!(decl(m, "argv", 0).1, 1);
            assert!(m.decls.iter().find(|d| d.name == "n").unwrap().is_static);
            assert_eq!(decl(m, "i", 0).1, 3);
            assert_eq!(m.functions[0].params.len(), 2);
        });
    }
}
