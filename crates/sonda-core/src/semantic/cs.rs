//! Scopes and symbols for C# (tree-sitter-c-sharp).
//!
//! One iterative pass over the tree. Types open a scope holding their
//! fields, properties and methods; methods, accessors, local functions and
//! lambdas open one for their parameters; blocks, loops, `using`, `fixed`
//! and `catch` open one for their locals. Pattern and `out` variables go to
//! the scope they're written in. Every other name in an expression is a
//! reference, and `this.x` refers to the enclosing type's member. References
//! are resolved after the pass: C# forbids using a local before its
//! declaration and shadowing one in a nested scope, so whole-scope
//! visibility finds the same declaration the compiler does. Inherited
//! members are declared in other types, often other files: references to
//! them resolve to nothing.
//!
//! Each declaration keeps the type written where it's declared (none for
//! `var`), which rules use to approximate typed analyses.

use super::{DeclKind, Function, Model, Ref, ScopeId, ScopeKind};
use std::collections::HashSet;
use std::time::Instant;
use tree_sitter::Node;

/// Nodes between deadline checks.
const CHECK_EVERY: u32 = 4096;

const TYPES: &[&str] = &[
    "class_declaration",
    "struct_declaration",
    "record_declaration",
    "record_struct_declaration",
    "interface_declaration",
];

const FUNCTIONS: &[&str] = &[
    "method_declaration",
    "constructor_declaration",
    "destructor_declaration",
    "operator_declaration",
    "conversion_operator_declaration",
    "indexer_declaration",
    "accessor_declaration",
    "local_function_statement",
    "lambda_expression",
    "anonymous_method_expression",
];

/// Parents whose identifiers name types, namespaces, labels or members,
/// never a variable.
const NOT_EXPRESSIONS: &[&str] = &[
    "qualified_name",
    "generic_name",
    "type_argument_list",
    "type_parameter",
    "type_parameter_list",
    "type_parameter_constraints_clause",
    "type_parameter_constraint",
    "base_list",
    "attribute",
    "using_directive",
    "namespace_declaration",
    "file_scoped_namespace_declaration",
    "explicit_interface_specifier",
    "array_type",
    "nullable_type",
    "pointer_type",
    "ref_type",
    "tuple_element",
    "labeled_statement",
    "goto_statement",
    "member_binding_expression",
    "name_colon",
    "name_equals",
    "typeof_expression",
    "default_expression",
    "sizeof_expression",
    "type_pattern",
    "with_initializer",
];

struct Binder<'t, 's> {
    m: Model<'t>,
    src: &'s [u8],
    /// Ids of nodes that name a declaration, or a member rather than a
    /// variable.
    not_refs: HashSet<usize>,
}

pub(super) fn build<'t>(root: Node<'t>, src: &[u8], deadline: Instant) -> Option<Model<'t>> {
    let mut b = Binder {
        m: Model::new(),
        src,
        not_refs: HashSet::new(),
    };
    let mut walk = Walk {
        scopes: vec![(0, 0)],
        types: Vec::new(),
        ancestors: Vec::new(),
        depth: 0,
    };
    let mut cursor = root.walk();
    let mut visited = 0u32;
    loop {
        visited += 1;
        if visited.is_multiple_of(CHECK_EVERY) && Instant::now() >= deadline {
            return None;
        }
        let node = cursor.node();
        let field = cursor.field_name();
        let scope = walk.scopes.last().map_or(0, |s| s.1);
        let type_scope = walk.types.last().map(|t| t.1);
        if let Some(opened) = b.visit(node, &walk.ancestors, field, scope, type_scope) {
            walk.scopes.push((walk.depth, opened));
            if TYPES.contains(&node.kind()) {
                walk.types.push((walk.depth, opened));
            }
        }
        if cursor.goto_first_child() {
            walk.ancestors.push(node);
            walk.depth += 1;
            continue;
        }
        if !walk.leave(&mut cursor) {
            b.m.root = Some(root);
            b.m.resolve();
            return Some(b.m);
        }
    }
}

/// Where `build`'s walk is: the scopes and the type scopes open, each with
/// the depth of the node that opened it, and the nodes above the cursor.
struct Walk<'t> {
    scopes: Vec<(usize, ScopeId)>,
    /// The innermost type scope, for `this.x`.
    types: Vec<(usize, ScopeId)>,
    ancestors: Vec<Node<'t>>,
    depth: usize,
}

impl<'t> Walk<'t> {
    /// Leaves the node at the cursor for the next one that isn't below it,
    /// closing the scopes the nodes left opened; false at the end of the
    /// tree.
    fn leave(&mut self, cursor: &mut tree_sitter::TreeCursor<'t>) -> bool {
        loop {
            while self.scopes.len() > 1 && self.scopes.last().is_some_and(|s| s.0 >= self.depth) {
                self.scopes.pop();
            }
            while self.types.last().is_some_and(|t| t.0 >= self.depth) {
                self.types.pop();
            }
            if cursor.goto_next_sibling() {
                return true;
            }
            if !cursor.goto_parent() {
                return false;
            }
            self.ancestors.pop();
            self.depth -= 1;
        }
    }
}

fn has_modifier(declaration: Node, word: &str, src: &[u8]) -> bool {
    let mut cursor = declaration.walk();
    declaration
        .named_children(&mut cursor)
        .any(|c| c.kind() == "modifier" && c.utf8_text(src).is_ok_and(|t| t == word))
}

impl<'t> Binder<'t, '_> {
    fn text(&self, node: Node) -> String {
        node.utf8_text(self.src).unwrap_or_default().to_string()
    }

    /// Handles one node; returns the scope it opens for its children.
    fn visit(
        &mut self,
        node: Node<'t>,
        ancestors: &[Node<'t>],
        field: Option<&str>,
        scope: ScopeId,
        type_scope: Option<ScopeId>,
    ) -> Option<ScopeId> {
        let kind = node.kind();
        match kind {
            k if TYPES.contains(&k) => Some(self.type_declaration(node, scope)),
            "enum_declaration" | "delegate_declaration" => {
                if let Some(name) = node.child_by_field_name("name") {
                    self.declare(scope, name, DeclKind::Class, None, false);
                }
                None
            }
            "enum_member_declaration" => {
                if let Some(name) = node.child_by_field_name("name") {
                    self.not_refs.insert(name.id());
                }
                None
            }
            k if FUNCTIONS.contains(&k) => Some(self.function(node, scope)),
            "field_declaration" | "event_field_declaration" => {
                self.fields(node, scope);
                None
            }
            "property_declaration" | "event_declaration" => {
                self.property(node, scope);
                None
            }
            "block" | "switch_section" | "for_statement" | "using_statement"
            | "fixed_statement" => Some(self.block(node, scope)),
            "local_declaration_statement" => {
                if let Some(v) = node
                    .named_children(&mut node.walk())
                    .find(|c| c.kind() == "variable_declaration")
                {
                    self.variables(scope, v, DeclKind::Let, false);
                }
                None
            }
            "foreach_statement" => Some(self.foreach(node, scope)),
            "catch_clause" => Some(self.catch(node, scope)),
            "declaration_pattern" | "declaration_expression" => {
                self.pattern_declaration(node, scope);
                None
            }
            "parenthesized_variable_designation" | "tuple_pattern" => {
                self.designations(scope, node);
                None
            }
            "initializer_expression" => {
                self.object_initializer(node, ancestors.last().copied());
                None
            }
            "anonymous_object_creation_expression" => {
                self.anonymous_object(node);
                None
            }
            "identifier" => {
                self.reference(node, ancestors, field, scope, type_scope);
                None
            }
            _ => None,
        }
    }

    /// A class, struct, interface or record: its name, and the scope of
    /// its members.
    fn type_declaration(&mut self, node: Node<'t>, scope: ScopeId) -> ScopeId {
        if let Some(name) = node.child_by_field_name("name") {
            self.declare(scope, name, DeclKind::Class, None, false);
        }
        let members = self.m.push_scope(scope, ScopeKind::Type);
        self.m.type_scopes.push((node, members));
        members
    }

    /// The `variable_declaration`s directly under `node`.
    fn variable_declarations(node: Node<'t>) -> Vec<Node<'t>> {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .filter(|c| c.kind() == "variable_declaration")
            .collect()
    }

    fn fields(&mut self, node: Node<'t>, scope: ScopeId) {
        let is_static =
            has_modifier(node, "static", self.src) || has_modifier(node, "const", self.src);
        for v in Self::variable_declarations(node) {
            self.variables(scope, v, DeclKind::Field, is_static);
        }
    }

    fn property(&mut self, node: Node<'t>, scope: ScopeId) {
        let Some(name) = node.child_by_field_name("name") else {
            return;
        };
        let is_static = has_modifier(node, "static", self.src);
        self.declare(
            scope,
            name,
            DeclKind::Property,
            node.child_by_field_name("type"),
            is_static,
        );
        if let Some(d) = self.m.decls.last_mut() {
            d.declarator = Some(node);
        }
    }

    /// A block's scope; a `for`, `using` or `fixed` declares its variables
    /// in it.
    fn block(&mut self, node: Node<'t>, scope: ScopeId) -> ScopeId {
        let block = self.m.push_scope(scope, ScopeKind::Block);
        if !matches!(node.kind(), "block" | "switch_section") {
            for v in Self::variable_declarations(node) {
                self.variables(block, v, DeclKind::Let, false);
            }
        }
        block
    }

    /// Declares `name`, written once by `declarator` (a `foreach` or a
    /// pattern).
    fn declare_written(
        &mut self,
        scope: ScopeId,
        name: Node<'t>,
        ty: Option<Node<'t>>,
        declarator: Node<'t>,
    ) {
        self.declare(scope, name, DeclKind::Let, ty, false);
        if let Some(d) = self.m.decls.last_mut() {
            d.declarator = Some(declarator);
            d.writes += 1;
        }
    }

    fn foreach(&mut self, node: Node<'t>, scope: ScopeId) -> ScopeId {
        let block = self.m.push_scope(scope, ScopeKind::Block);
        let ty = node
            .child_by_field_name("type")
            .filter(|t| t.kind() != "implicit_type");
        match node.child_by_field_name("left") {
            Some(left) if left.kind() == "identifier" => {
                self.declare_written(block, left, ty, node)
            }
            Some(left) => self.designations(block, left),
            None => {}
        }
        block
    }

    fn catch(&mut self, node: Node<'t>, scope: ScopeId) -> ScopeId {
        let block = self.m.push_scope(scope, ScopeKind::Block);
        let mut cursor = node.walk();
        let declaration = node
            .named_children(&mut cursor)
            .find(|c| c.kind() == "catch_declaration");
        if let Some(d) = declaration
            && let Some(name) = d.child_by_field_name("name")
        {
            self.declare(
                block,
                name,
                DeclKind::CatchParam,
                d.child_by_field_name("type"),
                false,
            );
        }
        block
    }

    /// `x is T t` and `out var t`.
    fn pattern_declaration(&mut self, node: Node<'t>, scope: ScopeId) {
        let ty = node
            .child_by_field_name("type")
            .filter(|t| t.kind() != "implicit_type");
        match node.child_by_field_name("name") {
            Some(name) if name.kind() == "identifier" => {
                self.declare_written(scope, name, ty, node)
            }
            Some(name) => self.designations(scope, name),
            None => {}
        }
    }

    /// `new P { Name = n }`: Name is the new object's member.
    fn object_initializer(&mut self, node: Node<'t>, parent: Option<Node<'t>>) {
        if !parent.is_some_and(|p| {
            matches!(
                p.kind(),
                "object_creation_expression" | "implicit_object_creation_expression"
            )
        }) {
            return;
        }
        let mut cursor = node.walk();
        for a in node
            .named_children(&mut cursor)
            .filter(|c| c.kind() == "assignment_expression")
        {
            if let Some(left) = a.child_by_field_name("left") {
                self.not_refs.insert(left.id());
            }
        }
    }

    /// `new { N = 1, n }`: N names a property; n is a reference.
    fn anonymous_object(&mut self, node: Node<'t>) {
        let mut cursor = node.walk();
        let children: Vec<Node<'t>> = node.children(&mut cursor).collect();
        for pair in children.windows(2) {
            if pair[0].kind() == "identifier"
                && !pair[1].is_named()
                && pair[1].utf8_text(self.src) == Ok("=")
            {
                self.not_refs.insert(pair[0].id());
            }
        }
    }

    fn function(&mut self, node: Node<'t>, scope: ScopeId) -> ScopeId {
        if let Some(name) = node.child_by_field_name("name") {
            self.declare_function_name(node, name, scope);
        }
        let inner = self.m.push_scope(scope, ScopeKind::Function);
        let list = Self::parameter_list(node);
        let mut params = Vec::with_capacity(list.len());
        for (name, ty, declarator) in list {
            let first = self.m.decls.len();
            self.declare(inner, name, DeclKind::Param, ty, false);
            if let Some(d) = self.m.decls.last_mut() {
                d.declarator = Some(declarator);
            }
            params.push((first..self.m.decls.len()).collect());
        }
        self.m.functions.push(Function {
            node,
            scope: inner,
            params,
        });
        inner
    }

    /// A method's or a local function's name is declared; another
    /// function's (a constructor's, an accessor's) is no reference.
    fn declare_function_name(&mut self, node: Node<'t>, name: Node<'t>, scope: ScopeId) {
        let (kind, ty) = match node.kind() {
            "method_declaration" => (DeclKind::Method, node.child_by_field_name("returns")),
            "local_function_statement" => (DeclKind::Function, node.child_by_field_name("type")),
            _ => {
                self.not_refs.insert(name.id());
                return;
            }
        };
        let is_static = has_modifier(node, "static", self.src);
        self.declare(scope, name, kind, ty, is_static);
        if let Some(d) = self.m.decls.last_mut() {
            d.declarator = Some(node);
        }
    }

    /// (name, type, declaring node) per parameter. A `params T[] rest`
    /// parameter has its type and name on the list itself; a lambda's lone
    /// parameter (`x => ...`) is the list.
    fn parameter_list(node: Node<'t>) -> Vec<(Node<'t>, Option<Node<'t>>, Node<'t>)> {
        let mut list = Vec::new();
        let Some(p) = node.child_by_field_name("parameters") else {
            return list;
        };
        if !matches!(p.kind(), "parameter_list" | "bracketed_parameter_list") {
            list.push((p, None, p));
            return list;
        }
        let mut cursor = p.walk();
        if !cursor.goto_first_child() {
            return list;
        }
        let mut params_type = None;
        loop {
            let c = cursor.node();
            match cursor.field_name() {
                Some("type") => params_type = Some(c),
                Some("name") => list.push((c, params_type.take(), p)),
                _ if c.kind() == "parameter" => {
                    if let Some(name) = c.child_by_field_name("name") {
                        list.push((name, c.child_by_field_name("type"), c));
                    }
                }
                _ => {}
            }
            if !cursor.goto_next_sibling() {
                return list;
            }
        }
    }

    /// Declares each variable of a `variable_declaration`.
    fn variables(
        &mut self,
        scope: ScopeId,
        declaration: Node<'t>,
        kind: DeclKind,
        is_static: bool,
    ) {
        let ty = declaration
            .child_by_field_name("type")
            .filter(|t| t.kind() != "implicit_type");
        let mut cursor = declaration.walk();
        let declarators: Vec<Node<'t>> = declaration
            .named_children(&mut cursor)
            .filter(|c| c.kind() == "variable_declarator")
            .collect();
        for declarator in declarators {
            match declarator.child_by_field_name("name") {
                Some(name) => {
                    self.declare(scope, name, kind, ty, is_static);
                    if let Some(d) = self.m.decls.last_mut() {
                        d.declarator = Some(declarator);
                        // An initializer writes the variable.
                        d.writes += u32::from(declarator.named_child_count() > 1);
                    }
                }
                // `var (a, b) = t`
                None => {
                    if let Some(pattern) = declarator.named_child(0) {
                        self.designations(scope, pattern);
                    }
                }
            }
        }
    }

    /// Declares the names in a deconstruction: `(a, b)`, `var (a, b)`.
    fn designations(&mut self, scope: ScopeId, node: Node<'t>) {
        let mut stack = vec![node];
        while let Some(n) = stack.pop() {
            match n.kind() {
                "identifier" => {
                    if !self.not_refs.contains(&n.id()) {
                        self.declare(scope, n, DeclKind::Let, None, false);
                        if let Some(d) = self.m.decls.last_mut() {
                            d.writes += 1;
                        }
                    }
                }
                "tuple_pattern"
                | "parenthesized_variable_designation"
                | "declaration_expression" => {
                    let mut c = n.walk();
                    stack.extend(
                        n.named_children(&mut c)
                            .filter(|x| x.kind() != "implicit_type"),
                    );
                }
                _ => {}
            }
        }
    }

    fn declare(
        &mut self,
        scope: ScopeId,
        name: Node<'t>,
        kind: DeclKind,
        ty: Option<Node<'t>>,
        is_static: bool,
    ) {
        self.not_refs.insert(name.id());
        let text = self.text(name);
        self.m.declare(scope, text, kind, name);
        if let Some(d) = self.m.decls.last_mut() {
            d.ty = ty;
            d.is_static = is_static;
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
        if self.not_refs.contains(&node.id()) || matches!(field, Some("type" | "returns")) {
            return;
        }
        let Some(&parent) = ancestors.last() else {
            return;
        };
        let Some(scope) = self.reference_scope(parent, field, scope, type_scope) else {
            return;
        };
        let (read, write) = self.access(node, parent, ancestors, field);
        self.m.refs.push(Ref {
            name: self.text(node),
            node,
            scope,
            read,
            write,
            decl: None,
        });
    }

    /// The scope an identifier under `parent` refers into, or None when
    /// it's no reference: a name in a declaration or a type, `x.Name` other
    /// than after `this.` (Name is a member of x's type), or the type on
    /// the right of `is` or `as`.
    fn reference_scope(
        &self,
        parent: Node<'t>,
        field: Option<&str>,
        scope: ScopeId,
        type_scope: Option<ScopeId>,
    ) -> Option<ScopeId> {
        let pk = parent.kind();
        if NOT_EXPRESSIONS.contains(&pk) || (pk == "argument" && field == Some("name")) {
            return None;
        }
        if pk == "member_access_expression" && field == Some("name") {
            let t = type_scope?;
            return parent
                .utf8_text(self.src)
                .is_ok_and(|p| p.starts_with("this."))
                .then_some(t);
        }
        if matches!(field, Some("name")) {
            return None;
        }
        if matches!(pk, "is_expression" | "as_expression") && field == Some("right") {
            return None;
        }
        Some(scope)
    }

    /// Whether the reference `node` reads its variable and whether it
    /// writes it. `this.x = 1` and `this.x++` write x through the member
    /// access.
    fn access(
        &self,
        node: Node<'t>,
        parent: Node<'t>,
        ancestors: &[Node<'t>],
        field: Option<&str>,
    ) -> (bool, bool) {
        let (target, holder, holder_field) = if parent.kind() == "member_access_expression" {
            let grandparent = ancestors.len().checked_sub(2).map(|i| ancestors[i]);
            let left_of = grandparent.filter(|g| g.child_by_field_name("left") == Some(parent));
            (
                parent,
                grandparent.unwrap_or(parent),
                if left_of.is_some() {
                    Some("left")
                } else {
                    None
                },
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
            "postfix_unary_expression" | "prefix_unary_expression"
                if holder.named_child(0) == Some(target)
                    && holder
                        .utf8_text(self.src)
                        .is_ok_and(|t| t.contains("++") || t.contains("--")) =>
            {
                (true, true)
            }
            "argument" if holder.named_child(0) == Some(target) => {
                let t = holder.utf8_text(self.src).unwrap_or_default();
                if t.starts_with("out ") {
                    (false, true)
                } else if t.starts_with("ref ") {
                    (true, true)
                } else {
                    (true, false)
                }
            }
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
        parser.set_language(&Lang::CSharp.grammar()).unwrap();
        let tree = parser.parse(src, None).unwrap();
        let model = super::super::build(
            Lang::CSharp,
            tree.root_node(),
            src.as_bytes(),
            Instant::now() + Duration::from_secs(10),
        )
        .unwrap();
        check(&model);
    }

    /// name → (kind, reads, writes), for the first declaration of each name.
    fn decl(m: &Model, name: &str) -> (DeclKind, u32, u32) {
        let d = m
            .decls
            .iter()
            .find(|d| d.name == name)
            .unwrap_or_else(|| panic!("{name} not declared"));
        (d.kind, d.reads, d.writes)
    }

    fn ty(m: &Model, src: &str, name: &str) -> Option<String> {
        let d = m.decls.iter().find(|d| d.name == name)?;
        d.ty.map(|t| t.utf8_text(src.as_bytes()).unwrap().to_string())
    }

    #[test]
    fn members_locals_and_patterns() {
        let src = "
class A {
  int count; static string Name; P Prop { get; set; }
  void F(int p, out int o, params string[] rest) {
    var local = 1; o = 2;
    this.count = p; count++;
    foreach (var item in items) { G(item); }
    if (x is Foo f) { f.Bar(); }
    int.TryParse(s, out var n); n += 1;
    var obj = new P { Prop = local };
    Func<int, int> l = y => y + local;
    try { } catch (Exception e) { Log(e); }
    var (a, b) = t; a = b;
  }
}";
        with_model(src, |m| {
            assert_eq!(decl(m, "count"), (DeclKind::Field, 1, 2));
            assert_eq!(decl(m, "p"), (DeclKind::Param, 1, 0));
            assert_eq!(decl(m, "o"), (DeclKind::Param, 0, 1));
            assert_eq!(decl(m, "rest"), (DeclKind::Param, 0, 0));
            assert_eq!(ty(m, src, "rest").as_deref(), Some("string[]"));
            assert_eq!(decl(m, "local"), (DeclKind::Let, 2, 1));
            assert_eq!(decl(m, "Prop"), (DeclKind::Property, 0, 0));
            assert_eq!(decl(m, "item"), (DeclKind::Let, 1, 1));
            assert_eq!(decl(m, "f"), (DeclKind::Let, 1, 1));
            assert_eq!(decl(m, "n"), (DeclKind::Let, 1, 2));
            assert_eq!(decl(m, "y"), (DeclKind::Param, 1, 0));
            assert_eq!(decl(m, "e"), (DeclKind::CatchParam, 1, 0));
            assert_eq!(decl(m, "a"), (DeclKind::Let, 0, 2));
            assert_eq!(decl(m, "b"), (DeclKind::Let, 1, 1));
            assert_eq!(decl(m, "F"), (DeclKind::Method, 0, 0));
            assert_eq!(ty(m, src, "p").as_deref(), Some("int"));
            assert_eq!(ty(m, src, "f").as_deref(), Some("Foo"));
            assert_eq!(ty(m, src, "local"), None);
            assert!(m.decls.iter().find(|d| d.name == "Name").unwrap().is_static);
            // Names of types and members are no references.
            assert!(
                !m.refs
                    .iter()
                    .any(|r| ["Foo", "Bar", "Exception", "TryParse"].contains(&r.name.as_str()))
            );
        });
    }

    #[test]
    fn nested_scopes_resolve_to_the_nearest_declaration() {
        let src = "
class Outer {
  static int shared;
  class Inner { int Get() => shared; }
  void F() { int shared = 1; Use(shared); }
}";
        with_model(src, |m| {
            let field = m
                .decls
                .iter()
                .position(|d| d.name == "shared" && d.kind == DeclKind::Field)
                .unwrap();
            let local = m
                .decls
                .iter()
                .position(|d| d.name == "shared" && d.kind == DeclKind::Let)
                .unwrap();
            let targets: Vec<Option<usize>> = m
                .refs
                .iter()
                .filter(|r| r.name == "shared")
                .map(|r| r.decl)
                .collect();
            assert_eq!(targets, [Some(field), Some(local)]);
        });
    }
}
