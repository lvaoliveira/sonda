//! The walk the binders of typed languages (C#, Java) share: one iterative
//! pass over the tree that keeps the scopes and the type scopes open, each
//! with the depth of the node that opened it, and the nodes above the
//! cursor. A binder only says what each node declares and opens.

use super::{DeclId, DeclKind, Function, Model, Ref, ScopeId, ScopeKind};
use std::collections::HashSet;
use std::time::Instant;
use tree_sitter::Node;

/// What a binder keeps while it walks: the model it builds, the source,
/// and the ids of nodes that name a declaration or a member rather than a
/// variable.
pub(super) struct Binder<'t, 's> {
    pub(super) m: Model<'t>,
    pub(super) src: &'s [u8],
    pub(super) not_refs: HashSet<usize>,
}

/// A parameter: its name, the type written for it, and the node that
/// declares it.
pub(super) type Param<'t> = (Node<'t>, Option<Node<'t>>, Node<'t>);

impl<'t, 's> Binder<'t, 's> {
    pub(super) fn new(src: &'s [u8]) -> Self {
        Binder {
            m: Model::new(),
            src,
            not_refs: HashSet::new(),
        }
    }

    pub(super) fn text(&self, node: Node) -> String {
        node.utf8_text(self.src).unwrap_or_default().to_string()
    }

    /// Declares `name` in `scope`, with the type written where it's
    /// declared.
    pub(super) fn declare(
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

    /// Declares `name`, for a language whose declarations take effect where
    /// they're written (`Model::resolve_in_order`): `effect` gets `from`,
    /// the byte this one takes effect at. Returns its id.
    pub(super) fn declare_at(
        &mut self,
        effect: &mut Vec<usize>,
        scope: ScopeId,
        name: Node<'t>,
        kind: DeclKind,
        ty: Option<Node<'t>>,
        from: usize,
    ) -> DeclId {
        self.declare(scope, name, kind, ty, false);
        effect.push(from);
        self.m.decls.len() - 1
    }

    /// A function's scope, holding its parameters.
    pub(super) fn function(
        &mut self,
        node: Node<'t>,
        scope: ScopeId,
        list: Vec<Param<'t>>,
    ) -> ScopeId {
        let inner = self.m.push_scope(scope, ScopeKind::Function);
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

    /// Records a use of the name `node`, to resolve once the walk is done.
    pub(super) fn add_ref(&mut self, node: Node<'t>, scope: ScopeId, read: bool, write: bool) {
        self.m.refs.push(Ref {
            name: self.text(node),
            node,
            scope,
            read,
            write,
            decl: None,
        });
    }
}

/// Nodes between deadline checks.
const CHECK_EVERY: u32 = 4096;

/// A scope a node opens for its children, and whether it's a type's.
pub(super) type Opened = Option<(ScopeId, bool)>;

/// Where the walk is: the scopes and the type scopes open, each with the
/// depth of the node that opened it, and the nodes above the cursor.
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

/// Calls `visit` on each node in source order, with the nodes above it, its
/// field name, the scope it's in and the innermost type's; whatever scope
/// `visit` returns holds the node's children. False when `deadline` passes
/// first.
pub(super) fn run<'t>(
    root: Node<'t>,
    deadline: Instant,
    mut visit: impl FnMut(Node<'t>, &[Node<'t>], Option<&str>, ScopeId, Option<ScopeId>) -> Opened,
) -> bool {
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
            return false;
        }
        let node = cursor.node();
        let field = cursor.field_name();
        let scope = walk.scopes.last().map_or(0, |s| s.1);
        let type_scope = walk.types.last().map(|t| t.1);
        if let Some((opened, is_type)) = visit(node, &walk.ancestors, field, scope, type_scope) {
            walk.scopes.push((walk.depth, opened));
            if is_type {
                walk.types.push((walk.depth, opened));
            }
        }
        if cursor.goto_first_child() {
            walk.ancestors.push(node);
            walk.depth += 1;
            continue;
        }
        if !walk.leave(&mut cursor) {
            return true;
        }
    }
}
