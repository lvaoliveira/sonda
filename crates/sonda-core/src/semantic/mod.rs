//! Domain: the semantic layer (ADR-0008). Phase S1, scopes and symbols:
//! which declaration each name refers to, built per file from the syntax
//! tree. Rules use it through `Check::Semantic`.
//!
//! Built iteratively (no recursion over the tree), and bounded by the file's
//! deadline: a file that runs out of time keeps its syntactic findings and
//! loses only the semantic ones, with a warning.

mod cs;
mod js;

use crate::lang::Lang;
use std::collections::HashMap;
use std::time::Instant;
use tree_sitter::Node;

pub(crate) type ScopeId = usize;
pub(crate) type DeclId = usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScopeKind {
    /// The file: an ES module or a script.
    Module,
    /// A function's parameters and body.
    Function,
    /// A block, loop header, `catch` or `switch` body: where `let`, `const`
    /// and `class` live.
    Block,
    /// A C# class, struct, record or interface body: its fields, properties
    /// and methods.
    Type,
}

pub(crate) struct Scope {
    pub(crate) parent: Option<ScopeId>,
    pub(crate) kind: ScopeKind,
    /// A function scope whose body (or a nested arrow's) reads `arguments`.
    pub(crate) uses_arguments: bool,
    /// Declarations by name, in source order.
    names: HashMap<String, Vec<DeclId>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeclKind {
    Var,
    Let,
    Const,
    Function,
    Class,
    Param,
    CatchParam,
    Import,
    /// TypeScript interfaces, type aliases, enums and namespaces, which
    /// merge with other declarations of the same name.
    Type,
    /// C# type members.
    Field,
    Property,
    Method,
}

pub(crate) struct Decl<'t> {
    pub(crate) name: String,
    pub(crate) kind: DeclKind,
    /// The name where it is declared.
    pub(crate) node: Node<'t>,
    pub(crate) scope: ScopeId,
    /// The scope it is written in: `scope`, except for a `var` in a block,
    /// which belongs to the function around it.
    pub(crate) block: ScopeId,
    /// The `variable_declarator` whose name is this declaration's node, for
    /// a variable declared with a plain name (`let x = ...`).
    pub(crate) declarator: Option<Node<'t>>,
    pub(crate) reads: u32,
    pub(crate) writes: u32,
    /// Declared next to a `...rest` element (`const { a, ...rest } = o`):
    /// often there only to leave `a` out of `rest`.
    pub(crate) rest_sibling: bool,
    /// The type written where it's declared, for typed languages (C#): `int`
    /// in `int x`. None when it's `var` or not written.
    pub(crate) ty: Option<Node<'t>>,
    /// Declared `static` (C# members).
    pub(crate) is_static: bool,
}

pub(crate) struct Ref<'t> {
    pub(crate) name: String,
    pub(crate) node: Node<'t>,
    pub(crate) scope: ScopeId,
    pub(crate) read: bool,
    pub(crate) write: bool,
    /// None: a global, or a name declared nowhere in the file.
    pub(crate) decl: Option<DeclId>,
}

/// A function and what its parameters declare.
pub(crate) struct Function<'t> {
    pub(crate) node: Node<'t>,
    /// The scope of its parameters and body.
    pub(crate) scope: ScopeId,
    /// Per parameter, in order, the names it declares (several when
    /// destructured, none for `this: T`).
    pub(crate) params: Vec<Vec<DeclId>>,
}

pub(crate) struct Model<'t> {
    pub(crate) scopes: Vec<Scope>,
    pub(crate) decls: Vec<Decl<'t>>,
    pub(crate) refs: Vec<Ref<'t>>,
    pub(crate) functions: Vec<Function<'t>>,
    /// Every `class_body`, in source order.
    pub(crate) classes: Vec<Node<'t>>,
    /// The file contains JSX, which classic React runtimes compile to
    /// `React.createElement` without naming `React`.
    pub(crate) has_jsx: bool,
    /// The file's syntax tree, for rules that look at more than names.
    pub(crate) root: Option<Node<'t>>,
    /// Each reference's index in `refs`, by its node's id.
    ref_index: HashMap<usize, usize>,
}

impl<'t> Model<'t> {
    fn new() -> Self {
        Model {
            scopes: vec![Scope {
                parent: None,
                kind: ScopeKind::Module,
                uses_arguments: false,
                names: HashMap::new(),
            }],
            decls: Vec::new(),
            refs: Vec::new(),
            functions: Vec::new(),
            classes: Vec::new(),
            has_jsx: false,
            root: None,
            ref_index: HashMap::new(),
        }
    }

    fn push_scope(&mut self, parent: ScopeId, kind: ScopeKind) -> ScopeId {
        self.scopes.push(Scope {
            parent: Some(parent),
            kind,
            uses_arguments: false,
            names: HashMap::new(),
        });
        self.scopes.len() - 1
    }

    /// The nearest scope at or above `scope` that `var` declarations go to.
    fn function_scope(&self, mut scope: ScopeId) -> ScopeId {
        while self.scopes[scope].kind == ScopeKind::Block {
            scope = self.scopes[scope].parent.unwrap_or(0);
        }
        scope
    }

    fn declare(&mut self, scope: ScopeId, name: String, kind: DeclKind, node: Node<'t>) {
        let id = self.decls.len();
        self.scopes[scope]
            .names
            .entry(name.clone())
            .or_default()
            .push(id);
        self.decls.push(Decl {
            name,
            kind,
            node,
            scope,
            block: scope,
            declarator: None,
            reads: 0,
            writes: 0,
            rest_sibling: false,
            ty: None,
            is_static: false,
        });
    }

    /// Whether `scope` is `outer` or nested inside it.
    pub(crate) fn within(&self, mut scope: ScopeId, outer: ScopeId) -> bool {
        loop {
            if scope == outer {
                return true;
            }
            match self.scopes[scope].parent {
                Some(p) => scope = p,
                None => return false,
            }
        }
    }

    /// The first declaration of `name` visible from `scope`.
    pub(crate) fn lookup(&self, mut scope: ScopeId, name: &str) -> Option<DeclId> {
        loop {
            if let Some(&first) = self.scopes[scope].names.get(name).and_then(|d| d.first()) {
                return Some(first);
            }
            scope = self.scopes[scope].parent?;
        }
    }

    /// The declaration a name refers to, for a node recorded as a reference.
    pub(crate) fn decl_of(&self, name: Node) -> Option<&Decl<'t>> {
        let r = &self.refs[*self.ref_index.get(&name.id())?];
        r.decl.map(|d| &self.decls[d])
    }

    /// Every scope's declarations grouped by name, for redeclaration checks.
    pub(crate) fn names(&self) -> impl Iterator<Item = (ScopeId, &[DeclId])> {
        self.scopes
            .iter()
            .enumerate()
            .flat_map(|(id, s)| s.names.values().map(move |d| (id, d.as_slice())))
    }

    /// Links each reference to the nearest declaration of its name, and
    /// counts reads and writes. Declarations are visible in their whole scope
    /// (hoisting), which is what matters for finding unused or misused ones.
    fn resolve(&mut self) {
        self.ref_index = self
            .refs
            .iter()
            .enumerate()
            .map(|(i, r)| (r.node.id(), i))
            .collect();
        for i in 0..self.refs.len() {
            let decl = self.lookup(self.refs[i].scope, &self.refs[i].name);
            let r = &mut self.refs[i];
            r.decl = decl;
            if let Some(d) = r.decl {
                self.decls[d].reads += u32::from(r.read);
                self.decls[d].writes += u32::from(r.write);
            }
        }
    }
}

/// Builds the model for languages the semantic layer supports; None for
/// the others, and when `deadline` passes first.
pub(crate) fn build<'t>(
    lang: Lang,
    root: Node<'t>,
    src: &[u8],
    deadline: Instant,
) -> Option<Model<'t>> {
    match lang {
        Lang::JavaScript | Lang::TypeScript | Lang::Tsx => js::build(root, src, deadline),
        Lang::CSharp => cs::build(root, src, deadline),
        _ => None,
    }
}

/// Whether the semantic layer supports `lang` (so a `None` from `build` means
/// it ran out of time).
pub(crate) fn supports(lang: Lang) -> bool {
    matches!(
        lang,
        Lang::JavaScript | Lang::TypeScript | Lang::Tsx | Lang::CSharp
    )
}
