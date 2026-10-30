//! Scopes and symbols for JavaScript and TypeScript (tree-sitter-javascript
//! and tree-sitter-typescript, which share these node kinds).
//!
//! One iterative pass over the tree: scopes are opened by functions,
//! blocks, loop headers, `catch` and `switch`; `var` goes to the nearest
//! function scope; parameters, patterns, imports, classes and TypeScript
//! types are declared; every other name is a reference. References are
//! resolved after the pass, so hoisting works. Types and values share one
//! namespace: imports used only as types count as used.

use super::{DeclKind, Function, Model, Ref, ScopeId, ScopeKind};
use std::collections::HashSet;
use std::time::Instant;
use tree_sitter::Node;

/// Nodes between deadline checks.
const CHECK_EVERY: u32 = 4096;

const FUNCTIONS: &[&str] = &[
    "function_declaration",
    "generator_function_declaration",
    "function_expression",
    "function",
    "generator_function",
    "arrow_function",
    "method_definition",
    "class_static_block",
];

/// Names that are declarations here; never references.
const NAMES: &[&str] = &[
    "identifier",
    "shorthand_property_identifier",
    "shorthand_property_identifier_pattern",
    "type_identifier",
];

const PATTERN_PARENTS: &[&str] = &[
    "array_pattern",
    "object_pattern",
    "rest_pattern",
    "pair_pattern",
    "assignment_pattern",
    "object_assignment_pattern",
];

struct Binder<'t, 's> {
    m: Model<'t>,
    src: &'s [u8],
    /// Ids of nodes that name a declaration (or are otherwise not
    /// references, like an import's original name).
    not_refs: HashSet<usize>,
    /// Ids of statement blocks that are a function's body, which share the
    /// function's scope.
    function_bodies: HashSet<usize>,
}

pub(super) fn build<'t>(root: Node<'t>, src: &[u8], deadline: Instant) -> Option<Model<'t>> {
    let mut b = Binder {
        m: Model::new(),
        src,
        not_refs: HashSet::new(),
        function_bodies: HashSet::new(),
    };
    // (depth of the node that opened it, scope)
    let mut scopes: Vec<(usize, ScopeId)> = vec![(0, 0)];
    let mut ancestors: Vec<Node<'t>> = Vec::new();
    let mut cursor = root.walk();
    let mut depth = 0;
    let mut visited = 0u32;
    loop {
        visited += 1;
        if visited.is_multiple_of(CHECK_EVERY) && Instant::now() >= deadline {
            return None;
        }
        let node = cursor.node();
        let scope = scopes.last().map_or(0, |s| s.1);
        if let Some(opened) = b.visit(node, ancestors.last().copied(), scope) {
            scopes.push((depth, opened));
        }
        if cursor.goto_first_child() {
            ancestors.push(node);
            depth += 1;
            continue;
        }
        loop {
            // Leaving the node at `depth`: close the scopes it opened.
            while scopes.len() > 1 && scopes.last().is_some_and(|s| s.0 >= depth) {
                scopes.pop();
            }
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                b.m.resolve();
                return Some(b.m);
            }
            ancestors.pop();
            depth -= 1;
        }
    }
}

impl<'t> Binder<'t, '_> {
    fn text(&self, node: Node) -> String {
        node.utf8_text(self.src).unwrap_or_default().to_string()
    }

    /// Handles one node; returns the scope it opens for its children.
    fn visit(
        &mut self,
        node: Node<'t>,
        parent: Option<Node<'t>>,
        scope: ScopeId,
    ) -> Option<ScopeId> {
        let kind = node.kind();
        if kind.starts_with("jsx_") {
            self.m.has_jsx = true;
        }
        match kind {
            k if FUNCTIONS.contains(&k) => Some(self.function(node, scope)),
            "class_declaration" | "abstract_class_declaration" => {
                if let Some(name) = node.child_by_field_name("name") {
                    self.declare(scope, name, DeclKind::Class);
                }
                None
            }
            "class" => {
                // A class expression's own name is visible only inside it.
                if let Some(name) = node.child_by_field_name("name") {
                    self.not_refs.insert(name.id());
                }
                None
            }
            "class_body" => {
                self.m.classes.push(node);
                None
            }
            "statement_block" if self.function_bodies.contains(&node.id()) => None,
            "statement_block" | "switch_body" | "for_statement" => {
                Some(self.m.push_scope(scope, ScopeKind::Block))
            }
            "for_in_statement" => {
                let block = self.m.push_scope(scope, ScopeKind::Block);
                let declares = [
                    ("var", DeclKind::Var),
                    ("let", DeclKind::Let),
                    ("const", DeclKind::Const),
                ]
                .into_iter()
                .find(|(token, _)| has_token(node, token));
                if let (Some((_, decl_kind)), Some(left)) =
                    (declares, node.child_by_field_name("left"))
                {
                    let target = if decl_kind == DeclKind::Var {
                        self.m.function_scope(scope)
                    } else {
                        block
                    };
                    let first = self.m.decls.len();
                    self.declare_pattern(target, left, decl_kind);
                    self.written_in(first, block);
                }
                Some(block)
            }
            "catch_clause" => {
                let block = self.m.push_scope(scope, ScopeKind::Block);
                if let Some(param) = node.child_by_field_name("parameter") {
                    self.declare_pattern(block, param, DeclKind::CatchParam);
                }
                Some(block)
            }
            // tree-sitter-javascript reads `let // comment` + newline + `a, b`
            // as the expression `let` followed by the expression `a, b`:
            // declare those names as the `let` they are.
            "expression_statement"
                if node
                    .named_child(0)
                    .is_some_and(|c| c.kind() == "identifier" && self.text(c) == "let")
                    && node
                        .named_children(&mut node.walk())
                        .skip(1)
                        .all(|c| c.kind() == "comment") =>
            {
                if let Some(c) = node.named_child(0) {
                    self.not_refs.insert(c.id());
                }
                let mut next = node.next_named_sibling();
                while let Some(n) = next.filter(|n| n.kind() == "comment") {
                    next = n.next_named_sibling();
                }
                let mut stack: Vec<Node> = next
                    .filter(|n| n.kind() == "expression_statement")
                    .and_then(|n| n.named_child(0))
                    .into_iter()
                    .collect();
                while let Some(n) = stack.pop() {
                    match n.kind() {
                        "sequence_expression" => {
                            let mut c = n.walk();
                            stack.extend(n.named_children(&mut c));
                        }
                        "assignment_expression" => {
                            if let Some(l) = n.child_by_field_name("left")
                                && l.kind() == "identifier"
                            {
                                self.declare(scope, l, DeclKind::Let);
                            }
                        }
                        "identifier" => self.declare(scope, n, DeclKind::Let),
                        _ => {}
                    }
                }
                None
            }
            "lexical_declaration" | "variable_declaration" => {
                let (decl_kind, target) = if kind == "variable_declaration" {
                    (DeclKind::Var, self.m.function_scope(scope))
                } else if has_token(node, "const") {
                    (DeclKind::Const, scope)
                } else {
                    (DeclKind::Let, scope)
                };
                let first = self.m.decls.len();
                let mut cursor = node.walk();
                for declarator in node.named_children(&mut cursor) {
                    if let Some(name) = declarator.child_by_field_name("name") {
                        self.declare_pattern(target, name, decl_kind);
                        if name.kind() == "identifier"
                            && let Some(d) = self.m.decls.last_mut()
                        {
                            d.declarator = Some(declarator);
                        }
                    }
                }
                self.written_in(first, scope);
                None
            }
            // Parameter names in a type (`(a: T) => U`) or an overload
            // signature bind nothing at run time and refer to nothing.
            "function_type"
            | "constructor_type"
            | "call_signature"
            | "construct_signature"
            | "method_signature"
            | "function_signature"
            | "abstract_method_signature" => {
                if let Some(params) = node.child_by_field_name("parameters") {
                    let mut cursor = params.walk();
                    let list: Vec<Node> = params.named_children(&mut cursor).collect();
                    for p in list {
                        self.pattern(scope, p, None);
                    }
                }
                if kind == "function_signature"
                    && let Some(name) = node.child_by_field_name("name")
                {
                    self.not_refs.insert(name.id());
                }
                None
            }
            "import_statement" => {
                self.import(node);
                None
            }
            "export_statement" => {
                // `export { a as b } from './m'` names nothing local.
                let reexport = node.child_by_field_name("source").is_some();
                let mut cursor = node.walk();
                for clause in node
                    .named_children(&mut cursor)
                    .filter(|c| c.kind() == "export_clause")
                {
                    let mut inner = clause.walk();
                    for spec in clause.named_children(&mut inner) {
                        if let Some(alias) = spec.child_by_field_name("alias") {
                            self.not_refs.insert(alias.id());
                        }
                        if reexport && let Some(name) = spec.child_by_field_name("name") {
                            self.not_refs.insert(name.id());
                        }
                    }
                }
                None
            }
            "interface_declaration"
            | "type_alias_declaration"
            | "enum_declaration"
            | "internal_module"
            | "module" => {
                if let Some(name) = node.child_by_field_name("name") {
                    self.declare(scope, name, DeclKind::Type);
                }
                None
            }
            k if NAMES.contains(&k) => {
                self.reference(node, parent, scope);
                None
            }
            _ => None,
        }
    }

    fn function(&mut self, node: Node<'t>, scope: ScopeId) -> ScopeId {
        let kind = node.kind();
        let name = node.child_by_field_name("name");
        if matches!(
            kind,
            "function_declaration" | "generator_function_declaration"
        ) && let Some(name) = name
        {
            self.declare(scope, name, DeclKind::Function);
        }
        let mut outer = scope;
        if matches!(
            kind,
            "function_expression" | "function" | "generator_function"
        ) && let Some(name) = name
        {
            // A function expression's own name lives in a scope of its own
            // around the function, so the body may shadow it.
            outer = self.m.push_scope(scope, ScopeKind::Function);
            self.declare(outer, name, DeclKind::Function);
        }
        let inner = self.m.push_scope(outer, ScopeKind::Function);
        let list: Vec<Node> = match node.child_by_field_name("parameters") {
            Some(params) => {
                let mut cursor = params.walk();
                params
                    .named_children(&mut cursor)
                    .filter(|p| p.kind() != "comment")
                    .collect()
            }
            None => node.child_by_field_name("parameter").into_iter().collect(),
        };
        let mut params = Vec::with_capacity(list.len());
        for p in list {
            let first = self.m.decls.len();
            self.declare_pattern(inner, p, DeclKind::Param);
            params.push((first..self.m.decls.len()).collect());
        }
        self.m.functions.push(Function {
            node,
            scope: inner,
            params,
        });
        if let Some(body) = node.child_by_field_name("body")
            && body.kind() == "statement_block"
        {
            self.function_bodies.insert(body.id());
        }
        inner
    }

    fn import(&mut self, node: Node<'t>) {
        let mut stack: Vec<Node> = Vec::new();
        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
        while let Some(n) = stack.pop() {
            match n.kind() {
                "import_clause"
                | "named_imports"
                | "namespace_import"
                | "import_require_clause" => {
                    let mut c = n.walk();
                    stack.extend(n.named_children(&mut c));
                }
                "identifier" => self.declare(0, n, DeclKind::Import),
                "import_specifier" => {
                    let alias = n.child_by_field_name("alias");
                    let name = n.child_by_field_name("name");
                    match (alias, name) {
                        (Some(alias), Some(name)) => {
                            // `import { a as b }`: `a` is the module's name, `b` is local.
                            self.not_refs.insert(name.id());
                            self.declare(0, alias, DeclKind::Import);
                        }
                        (None, Some(name)) => self.declare(0, name, DeclKind::Import),
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    }

    fn declare(&mut self, scope: ScopeId, name: Node<'t>, kind: DeclKind) {
        self.not_refs.insert(name.id());
        let text = self.text(name);
        self.m.declare(scope, text, kind, name);
    }

    /// Records that declarations from `first` on are written in `block`
    /// (where a `var` in a block differs from the scope it belongs to).
    fn written_in(&mut self, first: usize, block: ScopeId) {
        for d in &mut self.m.decls[first..] {
            d.block = block;
        }
    }

    fn declare_pattern(&mut self, scope: ScopeId, pattern: Node<'t>, kind: DeclKind) {
        self.pattern(scope, pattern, Some(kind));
    }

    /// Declares every name a binding pattern binds, or with no `kind` only
    /// keeps them from being references. Default values inside it are
    /// expressions, left to the walk as references.
    fn pattern(&mut self, scope: ScopeId, pattern: Node<'t>, kind: Option<DeclKind>) {
        let mut stack = vec![(pattern, false)];
        while let Some((n, rest_sibling)) = stack.pop() {
            match n.kind() {
                "identifier" | "shorthand_property_identifier_pattern" => match kind {
                    Some(kind) => {
                        self.declare(scope, n, kind);
                        if rest_sibling && let Some(d) = self.m.decls.last_mut() {
                            d.rest_sibling = true;
                        }
                    }
                    None => {
                        self.not_refs.insert(n.id());
                    }
                },
                "object_pattern" => {
                    let mut c = n.walk();
                    let has_rest = n.named_children(&mut c).any(|x| x.kind() == "rest_pattern");
                    let mut c = n.walk();
                    for child in n.named_children(&mut c) {
                        stack.push((child, has_rest && child.kind() != "rest_pattern"));
                    }
                }
                "pair_pattern" => {
                    if let Some(v) = n.child_by_field_name("value") {
                        stack.push((v, rest_sibling));
                    }
                }
                "assignment_pattern" | "object_assignment_pattern" => {
                    if let Some(l) = n.child_by_field_name("left") {
                        stack.push((l, rest_sibling));
                    }
                }
                "required_parameter" | "optional_parameter" => {
                    if let Some(p) = n.child_by_field_name("pattern") {
                        stack.push((p, false));
                    }
                }
                "array_pattern" | "rest_pattern" => {
                    let mut c = n.walk();
                    for child in n.named_children(&mut c) {
                        stack.push((child, false));
                    }
                }
                _ => {}
            }
        }
    }

    fn reference(&mut self, node: Node<'t>, parent: Option<Node<'t>>, scope: ScopeId) {
        if self.not_refs.contains(&node.id()) {
            return;
        }
        let text = self.text(node);
        if text == "arguments" {
            // Arrow functions see their enclosing function's `arguments`:
            // mark every function scope around the use.
            let mut s = Some(scope);
            while let Some(id) = s {
                if self.m.scopes[id].kind == ScopeKind::Function {
                    self.m.scopes[id].uses_arguments = true;
                }
                s = self.m.scopes[id].parent;
            }
        }
        let parent_kind = parent.map_or("", |p| p.kind());
        // `<div>` is an HTML element, not a variable.
        if matches!(
            parent_kind,
            "jsx_opening_element" | "jsx_closing_element" | "jsx_self_closing_element"
        ) && text.starts_with(|c: char| c.is_ascii_lowercase())
        {
            return;
        }
        let is_field =
            |field: &str| parent.and_then(|p| p.child_by_field_name(field)) == Some(node);
        let (read, write) = match parent_kind {
            "assignment_expression" if is_field("left") => (false, true),
            "augmented_assignment_expression" if is_field("left") => (true, true),
            "update_expression" => (true, true),
            "for_in_statement" if is_field("left") => (false, true),
            k if PATTERN_PARENTS.contains(&k) => match k {
                // Default values are read; the bound names are written.
                "assignment_pattern" | "object_assignment_pattern" if !is_field("left") => {
                    (true, false)
                }
                "pair_pattern" if !is_field("value") => (true, false),
                _ => (false, true),
            },
            _ if node.kind() == "shorthand_property_identifier_pattern" => (false, true),
            _ => (true, false),
        };
        self.m.refs.push(Ref {
            name: text,
            node,
            scope,
            read,
            write,
            decl: None,
        });
    }
}

fn has_token(node: Node, token: &str) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor).any(|c| c.kind() == token)
}

#[cfg(test)]
mod tests {
    use super::super::{DeclKind, Model};
    use crate::lang::Lang;
    use std::time::{Duration, Instant};

    fn with_model(lang: Lang, src: &str, check: impl FnOnce(&Model)) {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&lang.grammar()).unwrap();
        let tree = parser.parse(src, None).unwrap();
        let model = super::super::build(
            lang,
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

    #[test]
    fn scopes_hoisting_and_patterns() {
        let src = "
import def, { a as b, c } from 'm';
function f(p, { q, r: s = def, ...rest }, [t]) {
  if (p) { var v = 1; let w = 2; }
  x = v + s;
  for (const k of b) { k; }
  try {} catch (e) {}
  return g();
  function g() { return t; }
}
const h = () => { let y; y = 1; };
";
        with_model(Lang::JavaScript, src, |m| {
            assert_eq!(decl(m, "def"), (DeclKind::Import, 1, 0));
            assert_eq!(decl(m, "b"), (DeclKind::Import, 1, 0));
            assert!(
                m.decls.iter().all(|d| d.name != "a"),
                "the imported name isn't local"
            );
            assert_eq!(decl(m, "c"), (DeclKind::Import, 0, 0));
            assert_eq!(decl(m, "p"), (DeclKind::Param, 1, 0));
            assert_eq!(decl(m, "s"), (DeclKind::Param, 1, 0));
            assert!(m.decls.iter().find(|d| d.name == "q").unwrap().rest_sibling);
            assert_eq!(decl(m, "t"), (DeclKind::Param, 1, 0));
            // `var` is visible outside its block; `let` isn't, and `x` is an implicit global.
            assert_eq!(decl(m, "v"), (DeclKind::Var, 1, 0));
            assert_eq!(decl(m, "w"), (DeclKind::Let, 0, 0));
            assert!(
                m.refs
                    .iter()
                    .any(|r| r.name == "x" && r.write && r.decl.is_none())
            );
            assert_eq!(decl(m, "k"), (DeclKind::Const, 1, 0));
            assert_eq!(decl(m, "e"), (DeclKind::CatchParam, 0, 0));
            // Hoisted: called before its declaration.
            assert_eq!(decl(m, "g"), (DeclKind::Function, 1, 0));
            assert_eq!(decl(m, "y"), (DeclKind::Let, 0, 1));
            assert_eq!(decl(m, "h"), (DeclKind::Const, 0, 0));
        });
    }

    #[test]
    fn typescript_types_and_jsx_count_as_uses() {
        let src = "
import { Props, Unused } from './types';
import React from 'react';
import Button from './Button';
interface Local { a: number }
export function C(p: Props): Local { return <div><Button /></div>; }
";
        with_model(Lang::Tsx, src, |m| {
            assert!(m.has_jsx);
            assert_eq!(decl(m, "Props").1, 1);
            assert_eq!(decl(m, "Button").1, 1);
            assert_eq!(decl(m, "Unused").1, 0);
            assert_eq!(decl(m, "Local"), (DeclKind::Type, 1, 0));
            assert!(
                m.refs.iter().all(|r| r.name != "div"),
                "HTML tags aren't references"
            );
        });
    }

    #[test]
    fn let_followed_by_a_comment_still_declares() {
        let src = "function f(xs) {\n  let // first\n  a,\n  // second\n  b, c = xs.length;\n  while (c--) { a = xs[c]; b = a; }\n  return b;\n}";
        with_model(Lang::JavaScript, src, |m| {
            assert_eq!(decl(m, "a"), (DeclKind::Let, 1, 1));
            assert_eq!(decl(m, "b"), (DeclKind::Let, 1, 1));
            assert_eq!(decl(m, "c").0, DeclKind::Let);
            assert!(m.refs.iter().all(|r| r.decl.is_some() || r.name == "xs"));
        });
    }

    #[test]
    fn running_out_of_time_gives_no_model() {
        let src = "let a = 1;\n".repeat(10_000);
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&Lang::JavaScript.grammar()).unwrap();
        let tree = parser.parse(&src, None).unwrap();
        assert!(
            super::super::build(
                Lang::JavaScript,
                tree.root_node(),
                src.as_bytes(),
                Instant::now()
            )
            .is_none()
        );
    }
}
