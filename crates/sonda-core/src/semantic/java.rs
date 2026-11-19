//! Scopes and symbols for Java (ADR-0008, S1; tree-sitter-java).
//!
//! One iterative pass over the tree, built like C#'s. Types (classes,
//! interfaces, enums, records, annotation types, and the body of an
//! anonymous class) open a scope holding their fields, enum constants,
//! record components and methods; methods, constructors and lambdas open
//! one for their parameters; blocks, loops, `switch` bodies, `catch` and
//! `try`-with-resources open one for their locals. Pattern variables
//! (`x instanceof String s`, `case Circle c`, record patterns) go to the
//! scope they're written in. Every other name in an expression is a
//! reference, and `this.x` refers to the enclosing type's member.
//!
//! References are resolved after the pass, so a name is visible in its
//! whole scope: Java forbids using a local before its declaration, and
//! forbids a local shadowing another local, so this finds the declaration
//! the compiler does. The one place it can differ is a local declared
//! later in a method under the name of a field the method used earlier.
//! Inherited members are declared in other types, often other files:
//! references to them resolve to nothing.
//!
//! Each declaration keeps the type written where it's declared (none for
//! `var`), which taint rules use to tell a request from any other value.

use super::walk::{Binder, Param};
use super::{DeclKind, Model, ScopeId, ScopeKind};
use std::time::Instant;
use tree_sitter::Node;

const TYPES: &[&str] = &[
    "class_declaration",
    "interface_declaration",
    "enum_declaration",
    "record_declaration",
    "annotation_type_declaration",
];

/// Parents whose identifiers name packages, imports, annotations, labels or
/// members, never a variable.
const NOT_EXPRESSIONS: &[&str] = &[
    "scoped_identifier",
    "package_declaration",
    "import_declaration",
    "annotation",
    "marker_annotation",
    "labeled_statement",
    "break_statement",
    "continue_statement",
    "type_parameter",
    "module_declaration",
    "scoped_type_identifier",
    "record_pattern",
];

/// The binder of Java: the shared one, and the rules of the language.
struct Java<'t, 's>(Binder<'t, 's>);

impl<'t, 's> std::ops::Deref for Java<'t, 's> {
    type Target = Binder<'t, 's>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Java<'_, '_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub(super) fn build<'t>(root: Node<'t>, src: &[u8], deadline: Instant) -> Option<Model<'t>> {
    let mut b = Java(Binder::new(src));
    let done = super::walk::run(
        root,
        deadline,
        |node, ancestors, field, scope, type_scope| {
            let opened = b.visit(node, ancestors, field, scope, type_scope)?;
            Some((opened, b.m.type_scopes.last().is_some_and(|t| t.0 == node)))
        },
    );
    if !done {
        return None;
    }
    b.m.root = Some(root);
    b.m.resolve();
    Some(b.0.m)
}

fn has_modifier(declaration: Node, word: &str, src: &[u8]) -> bool {
    let mut cursor = declaration.walk();
    declaration
        .named_children(&mut cursor)
        .find(|c| c.kind() == "modifiers")
        .is_some_and(|m| {
            let mut c = m.walk();
            m.children(&mut c)
                .any(|k| k.utf8_text(src).is_ok_and(|t| t == word))
        })
}

impl<'t> Java<'t, '_> {
    /// Handles one node; returns the scope it opens for its children.
    fn visit(
        &mut self,
        node: Node<'t>,
        ancestors: &[Node<'t>],
        field: Option<&str>,
        scope: ScopeId,
        type_scope: Option<ScopeId>,
    ) -> Option<ScopeId> {
        match node.kind() {
            k if TYPES.contains(&k) => Some(self.type_declaration(node, scope)),
            // An anonymous class's or an enum constant's body.
            "class_body"
                if ancestors.last().is_some_and(|p| {
                    matches!(p.kind(), "object_creation_expression" | "enum_constant")
                }) =>
            {
                let members = self.m.push_scope(scope, ScopeKind::Type);
                self.m.type_scopes.push((node, members));
                Some(members)
            }
            "enum_constant" => {
                if let Some(name) = node.child_by_field_name("name") {
                    // Enum constants are the enum's static fields; the
                    // scope above is the enum's members.
                    self.declare(scope, name, DeclKind::Field, None, true);
                }
                None
            }
            "method_declaration"
            | "constructor_declaration"
            | "compact_constructor_declaration"
            | "lambda_expression" => Some(self.function(node, scope)),
            "field_declaration" => {
                self.fields(node, scope);
                None
            }
            "local_variable_declaration" => {
                self.variables(scope, node, DeclKind::Let, false);
                None
            }
            "block" | "constructor_body" | "switch_block" | "for_statement" => {
                Some(self.block(scope))
            }
            "enhanced_for_statement" => Some(self.foreach(node, scope)),
            "catch_clause" => Some(self.catch(node, scope)),
            "try_with_resources_statement" => Some(self.resources(node, scope)),
            "instanceof_expression" => {
                if let Some(name) = node.child_by_field_name("name") {
                    self.declare_written(scope, name, node.child_by_field_name("right"), node);
                }
                None
            }
            "type_pattern" | "record_pattern_component" => {
                self.pattern(node, scope);
                None
            }
            "identifier" => {
                self.reference(node, ancestors, field, scope, type_scope);
                None
            }
            _ => None,
        }
    }

    /// A class, interface, enum, record or annotation type: its name, and
    /// the scope of its members. A record's components are its fields.
    fn type_declaration(&mut self, node: Node<'t>, scope: ScopeId) -> ScopeId {
        if let Some(name) = node.child_by_field_name("name") {
            self.declare(scope, name, DeclKind::Class, None, false);
        }
        let members = self.m.push_scope(scope, ScopeKind::Type);
        self.m.type_scopes.push((node, members));
        if node.kind() == "record_declaration" {
            for (name, ty, declarator) in Self::parameter_list(node) {
                self.declare(members, name, DeclKind::Field, ty, false);
                if let Some(d) = self.m.decls.last_mut() {
                    d.declarator = Some(declarator);
                    d.writes += 1;
                }
            }
        }
        members
    }

    fn fields(&mut self, node: Node<'t>, scope: ScopeId) {
        let is_static = has_modifier(node, "static", self.src);
        self.variables(scope, node, DeclKind::Field, is_static);
    }

    /// A block's, `switch` body's or `for`'s scope. The walk declares a
    /// `for`'s init variables in it as it reaches them.
    fn block(&mut self, scope: ScopeId) -> ScopeId {
        self.m.push_scope(scope, ScopeKind::Block)
    }

    /// Declares `name`, written once by `declarator` (a `for-each` or a
    /// pattern).
    fn declare_written(
        &mut self,
        scope: ScopeId,
        name: Node<'t>,
        ty: Option<Node<'t>>,
        declarator: Node<'t>,
    ) {
        if name.kind() != "identifier" {
            return;
        }
        let ty = ty.filter(|t| !self.is_var(*t));
        self.declare(scope, name, DeclKind::Let, ty, false);
        if let Some(d) = self.m.decls.last_mut() {
            d.declarator = Some(declarator);
            d.writes += 1;
        }
    }

    /// `var`, which Java parses as a type named `var`.
    fn is_var(&self, ty: Node) -> bool {
        ty.utf8_text(self.src).is_ok_and(|t| t == "var")
    }

    fn foreach(&mut self, node: Node<'t>, scope: ScopeId) -> ScopeId {
        let block = self.m.push_scope(scope, ScopeKind::Block);
        if let Some(name) = node.child_by_field_name("name") {
            self.declare_written(block, name, node.child_by_field_name("type"), node);
        }
        block
    }

    fn catch(&mut self, node: Node<'t>, scope: ScopeId) -> ScopeId {
        let block = self.m.push_scope(scope, ScopeKind::Block);
        let mut cursor = node.walk();
        let parameter = node
            .named_children(&mut cursor)
            .find(|c| c.kind() == "catch_formal_parameter");
        if let Some(p) = parameter
            && let Some(name) = p.child_by_field_name("name")
            && name.kind() == "identifier"
        {
            let mut c = p.walk();
            let ty = p.named_children(&mut c).find(|c| c.kind() == "catch_type");
            self.declare(block, name, DeclKind::CatchParam, ty, false);
        }
        block
    }

    /// `try (var in = open(); out)`: each named resource is a local of the
    /// statement.
    fn resources(&mut self, node: Node<'t>, scope: ScopeId) -> ScopeId {
        let block = self.m.push_scope(scope, ScopeKind::Block);
        let mut cursor = node.walk();
        let specification = node
            .named_children(&mut cursor)
            .find(|c| c.kind() == "resource_specification");
        if let Some(spec) = specification {
            let mut c = spec.walk();
            let resources: Vec<Node<'t>> = spec
                .named_children(&mut c)
                .filter(|r| r.kind() == "resource")
                .collect();
            for r in resources {
                if let Some(name) = r.child_by_field_name("name") {
                    self.declare_written(block, name, r.child_by_field_name("type"), r);
                }
            }
        }
        block
    }

    /// `case Circle c`, `o instanceof Point(int x, int y)`: the variable of
    /// a type pattern or of a record pattern's component.
    fn pattern(&mut self, node: Node<'t>, scope: ScopeId) {
        let mut cursor = node.walk();
        let children: Vec<Node<'t>> = node.named_children(&mut cursor).collect();
        if let Some(name) = children.iter().rev().find(|c| c.kind() == "identifier") {
            let ty = children.iter().find(|c| c.kind() != "identifier").copied();
            self.declare_written(scope, *name, ty, node);
        }
    }

    fn function(&mut self, node: Node<'t>, scope: ScopeId) -> ScopeId {
        if let Some(name) = node.child_by_field_name("name") {
            if node.kind() == "method_declaration" {
                let is_static = has_modifier(node, "static", self.src);
                self.declare(
                    scope,
                    name,
                    DeclKind::Method,
                    node.child_by_field_name("type"),
                    is_static,
                );
                if let Some(d) = self.m.decls.last_mut() {
                    d.declarator = Some(node);
                }
            } else {
                // A constructor's name is its type's.
                self.not_refs.insert(name.id());
            }
        }
        self.0.function(node, scope, Self::parameter_list(node))
    }

    /// (name, type, declaring node) per parameter of a method, a
    /// constructor, a record or a lambda. `String... rest` has its type
    /// beside its declarator; a lambda's lone parameter (`x -> ...`) is
    /// the list.
    fn parameter_list(node: Node<'t>) -> Vec<Param<'t>> {
        let mut list = Vec::new();
        let Some(p) = node.child_by_field_name("parameters") else {
            return list;
        };
        if p.kind() == "identifier" {
            list.push((p, None, p));
            return list;
        }
        let mut cursor = p.walk();
        for c in p.named_children(&mut cursor) {
            match c.kind() {
                // Lambda `(a, b) -> ...`.
                "identifier" => list.push((c, None, c)),
                "formal_parameter" => {
                    if let Some(name) = c.child_by_field_name("name")
                        && name.kind() == "identifier"
                    {
                        list.push((name, c.child_by_field_name("type"), c));
                    }
                }
                "spread_parameter" => {
                    let mut k = c.walk();
                    let kids: Vec<Node<'t>> = c.named_children(&mut k).collect();
                    let name = kids
                        .iter()
                        .find(|k| k.kind() == "variable_declarator")
                        .and_then(|d| d.child_by_field_name("name"));
                    let ty = kids.iter().find(|k| {
                        !matches!(
                            k.kind(),
                            "variable_declarator"
                                | "modifiers"
                                | "annotation"
                                | "marker_annotation"
                        )
                    });
                    if let Some(name) = name {
                        list.push((name, ty.copied(), c));
                    }
                }
                _ => {}
            }
        }
        list
    }

    /// Declares each variable of a local or field declaration.
    fn variables(
        &mut self,
        scope: ScopeId,
        declaration: Node<'t>,
        kind: DeclKind,
        is_static: bool,
    ) {
        let ty = declaration
            .child_by_field_name("type")
            .filter(|t| !self.is_var(*t));
        let mut cursor = declaration.walk();
        let declarators: Vec<Node<'t>> = declaration
            .children_by_field_name("declarator", &mut cursor)
            .collect();
        for declarator in declarators {
            let Some(name) = declarator.child_by_field_name("name") else {
                continue;
            };
            if name.kind() != "identifier" {
                continue;
            }
            self.declare(scope, name, kind, ty, is_static);
            if let Some(d) = self.m.decls.last_mut() {
                d.declarator = Some(declarator);
                // An initializer writes the variable.
                d.writes += u32::from(declarator.child_by_field_name("value").is_some());
            }
        }
    }

    fn reference(
        &mut self,
        node: Node<'t>,
        ancestors: &[Node<'t>],
        field: Option<&str>,
        scope: ScopeId,
        type_scope: Option<ScopeId>,
    ) {
        if self.not_refs.contains(&node.id()) {
            return;
        }
        let Some(&parent) = ancestors.last() else {
            return;
        };
        let Some(scope) = self.reference_scope(node, parent, field, scope, type_scope) else {
            return;
        };
        let (read, write) = self.access(node, parent, ancestors, field);
        self.add_ref(node, scope, read, write);
    }

    /// The scope an identifier under `parent` refers into, or None when
    /// it's no reference: a name in a package, an import or an annotation,
    /// a method's name in a call, `x.name` other than after `this.`
    /// (`name` is a member of x's type), or a method reference's method.
    fn reference_scope(
        &self,
        node: Node<'t>,
        parent: Node<'t>,
        field: Option<&str>,
        scope: ScopeId,
        type_scope: Option<ScopeId>,
    ) -> Option<ScopeId> {
        let pk = parent.kind();
        if NOT_EXPRESSIONS.contains(&pk) {
            return None;
        }
        match (pk, field) {
            ("method_invocation", Some("name")) => return None,
            ("element_value_pair", Some("key")) => return None,
            ("field_access", Some("field")) => {
                let on_this = parent
                    .child_by_field_name("object")
                    .is_some_and(|o| o.kind() == "this");
                return if on_this { type_scope } else { None };
            }
            ("method_reference", _) => {
                let last = parent.child(parent.child_count().saturating_sub(1));
                if last == Some(node) {
                    return None;
                }
            }
            _ => {}
        }
        Some(scope)
    }

    /// Whether the reference `node` reads its variable and whether it
    /// writes it. `this.x = 1` and `this.x++` write x through the field
    /// access.
    fn access(
        &self,
        node: Node<'t>,
        parent: Node<'t>,
        ancestors: &[Node<'t>],
        field: Option<&str>,
    ) -> (bool, bool) {
        let (target, holder, holder_field) = if parent.kind() == "field_access" {
            let grandparent = ancestors.len().checked_sub(2).map(|i| ancestors[i]);
            let left_of = grandparent.filter(|g| g.child_by_field_name("left") == Some(parent));
            (
                parent,
                grandparent.unwrap_or(parent),
                left_of.map(|_| "left"),
            )
        } else {
            (node, parent, field)
        };
        match holder.kind() {
            "assignment_expression" if holder_field == Some("left") => {
                let op = holder
                    .child_by_field_name("operator")
                    .and_then(|o| o.utf8_text(self.src).ok())
                    .unwrap_or("=");
                (op != "=", true)
            }
            "update_expression" if holder.named_child(0) == Some(target) => (true, true),
            _ => (true, false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{DeclKind, Model};
    use crate::lang::Lang;
    use std::time::{Duration, Instant};

    fn with_model(src: &str, check: impl FnOnce(&Model)) {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&Lang::Java.grammar()).unwrap();
        let tree = parser.parse(src, None).unwrap();
        let model = super::build(
            tree.root_node(),
            src.as_bytes(),
            Instant::now() + Duration::from_secs(10),
        )
        .unwrap();
        check(&model);
    }

    /// (kind, reads, writes) of the only declaration called `name`.
    fn decl(m: &Model, name: &str) -> (DeclKind, u32, u32) {
        let found: Vec<_> = m.decls.iter().filter(|d| d.name == name).collect();
        assert_eq!(found.len(), 1, "declarations of {name}");
        (found[0].kind, found[0].reads, found[0].writes)
    }

    fn ty(m: &Model, src: &str, name: &str) -> Option<String> {
        let d = m.decls.iter().find(|d| d.name == name).unwrap();
        d.ty.map(|t| t.utf8_text(src.as_bytes()).unwrap().to_string())
    }

    #[test]
    fn members_locals_and_parameters() {
        let src = "class A {\n  private String q;\n  static int n = 1;\n  void f(String id, int... rest) {\n    String s = id;\n    var t = s;\n    this.q = t;\n    n++;\n  }\n}";
        with_model(src, |m| {
            assert_eq!(decl(m, "q"), (DeclKind::Field, 0, 1));
            assert_eq!(decl(m, "n"), (DeclKind::Field, 1, 2));
            assert_eq!(decl(m, "f").0, DeclKind::Method);
            assert_eq!(decl(m, "id"), (DeclKind::Param, 1, 0));
            assert_eq!(decl(m, "rest").0, DeclKind::Param);
            assert_eq!(decl(m, "s"), (DeclKind::Let, 1, 1));
            assert_eq!(decl(m, "t"), (DeclKind::Let, 1, 1));
            assert_eq!(ty(m, src, "s").as_deref(), Some("String"));
            assert_eq!(ty(m, src, "t"), None, "var has no written type");
            assert_eq!(ty(m, src, "rest").as_deref(), Some("int"));
            assert!(m.decls.iter().find(|d| d.name == "n").unwrap().is_static);
            assert_eq!(m.functions.len(), 1);
            assert_eq!(m.functions[0].params.len(), 2);
        });
    }

    #[test]
    fn nearest_declaration_and_this() {
        let src =
            "class A {\n  String x;\n  A(String x) { this.x = x; }\n  String g() { return x; }\n}";
        with_model(src, |m| {
            let xs: Vec<_> = m.decls.iter().filter(|d| d.name == "x").collect();
            assert_eq!(xs.len(), 2);
            // The field: written by `this.x =`, read by `return x`.
            let field = xs.iter().find(|d| d.kind == DeclKind::Field).unwrap();
            assert_eq!((field.reads, field.writes), (1, 1));
            // The parameter: read by the right-hand `x`.
            let param = xs.iter().find(|d| d.kind == DeclKind::Param).unwrap();
            assert_eq!((param.reads, param.writes), (1, 0));
        });
    }

    #[test]
    fn method_names_and_member_selectors_are_no_references() {
        let src = "class A {\n  void f(String s) { String u = s.trim(); g(u); other.h(u); }\n  void g(String v) {}\n}";
        with_model(src, |m| {
            assert_eq!(decl(m, "s"), (DeclKind::Param, 1, 0));
            assert_eq!(decl(m, "u"), (DeclKind::Let, 2, 1));
            let names: Vec<&str> = m.refs.iter().map(|r| r.name.as_str()).collect();
            assert!(!names.contains(&"trim"), "{names:?}");
            assert!(!names.contains(&"h"), "{names:?}");
            assert!(names.contains(&"other"), "{names:?}");
            assert!(
                m.refs
                    .iter()
                    .find(|r| r.name == "other")
                    .unwrap()
                    .decl
                    .is_none()
            );
        });
    }

    #[test]
    fn loops_catch_resources_lambdas_and_patterns() {
        let src = "class A {\n  void f(java.util.List<String> xs, Object o) {\n    for (int i = 0; i < 3; i++) { use(i); }\n    for (String x : xs) { use(x); }\n    try (var in = open()) { use(in); } catch (Exception e) { use(e); }\n    xs.forEach(y -> use(y));\n    xs.forEach((a, b) -> use(a));\n    if (o instanceof String s && s.isEmpty()) { use(s); }\n    switch (o) { case Integer k -> use(k); default -> {} }\n  }\n}";
        with_model(src, |m| {
            assert_eq!(decl(m, "i").0, DeclKind::Let);
            assert_eq!(decl(m, "i").1, 3, "i < 3, i++, use(i)");
            assert_eq!(decl(m, "x"), (DeclKind::Let, 1, 1));
            assert_eq!(decl(m, "in"), (DeclKind::Let, 1, 1));
            assert_eq!(decl(m, "e"), (DeclKind::CatchParam, 1, 0));
            assert_eq!(decl(m, "y"), (DeclKind::Param, 1, 0));
            assert_eq!(decl(m, "a"), (DeclKind::Param, 1, 0));
            assert_eq!(decl(m, "b").0, DeclKind::Param);
            assert_eq!(decl(m, "s"), (DeclKind::Let, 2, 1));
            assert_eq!(decl(m, "k"), (DeclKind::Let, 1, 1));
            assert_eq!(ty(m, src, "s").as_deref(), Some("String"));
        });
    }

    #[test]
    fn records_enums_and_anonymous_classes() {
        let src = "record P(int x, int y) { int sum() { return x + y; } }\nenum E { ONE, TWO; int v() { return ONE.ordinal(); } }\nclass B { Runnable r = new Runnable() { int c; public void run() { c++; } }; }";
        with_model(src, |m| {
            assert_eq!(decl(m, "x"), (DeclKind::Field, 1, 1));
            assert_eq!(decl(m, "ONE"), (DeclKind::Field, 1, 0));
            assert_eq!(decl(m, "c"), (DeclKind::Field, 1, 1));
            assert_eq!(m.type_scopes.len(), 4, "P, E, B and the anonymous class");
        });
    }

    #[test]
    fn labels_annotations_imports_and_method_references_are_no_references() {
        let src = "package com.x;\nimport java.util.List;\n@Anno(value = \"v\")\nclass A {\n  void f(java.util.List<String> xs) {\n    outer: for (;;) { break outer; }\n    xs.forEach(System.out::println);\n  }\n}";
        with_model(src, |m| {
            let names: Vec<&str> = m.refs.iter().map(|r| r.name.as_str()).collect();
            assert!(!names.contains(&"outer"), "{names:?}");
            assert!(!names.contains(&"value"), "{names:?}");
            assert!(!names.contains(&"println"), "{names:?}");
            assert!(!names.contains(&"com"), "{names:?}");
            assert!(names.contains(&"System"), "{names:?}");
        });
    }
}
