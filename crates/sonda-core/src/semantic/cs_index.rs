//! A project-wide index of C# type declarations (ADR-0020), for rules that
//! compare a declaration with ones in other files: an override with the
//! method it overrides, a class with its base classes and interfaces.
//!
//! Each worker summarizes the types its file declares (`extract`): names,
//! bases, members and parameter signatures, with positions. The summary
//! crosses the worker boundary as a fact, like the other project-level
//! facts, so no syntax tree leaves the sandbox. The scanner then indexes
//! every file's summary (`ProjectIndex`) and resolves a base type by simple
//! name and generic arity, narrowed by namespaces and using directives when
//! several types share it. Types from referenced assemblies aren't in the
//! project, so they resolve to nothing.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tree_sitter::Node;

/// A position in the file, 1-based, columns counting characters.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Default)]
pub(crate) struct Span {
    pub(crate) line: usize,
    pub(crate) column: usize,
    pub(crate) end_line: usize,
    pub(crate) end_column: usize,
}

/// A reference to a type by its simple name and number of type arguments.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub(crate) struct TypeRef {
    pub(crate) name: String,
    pub(crate) arity: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct ParamDecl {
    pub(crate) name: String,
    pub(crate) ty: String,
    pub(crate) default: Option<String>,
    pub(crate) is_params: bool,
    pub(crate) span: Span,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct MemberDecl {
    /// "method", "property", "field", "event", "constructor", "destructor".
    pub(crate) kind: String,
    pub(crate) name: String,
    pub(crate) modifiers: Vec<String>,
    /// Implements an interface member explicitly: `void IStore.Save()`.
    pub(crate) explicit: bool,
    pub(crate) returns: String,
    pub(crate) params: Vec<ParamDecl>,
    pub(crate) has_body: bool,
    /// Calls written in the body that dispose-pattern checks look for.
    pub(crate) calls: Vec<String>,
    pub(crate) span: Span,
}

impl MemberDecl {
    pub(crate) fn has(&self, modifier: &str) -> bool {
        self.modifiers.iter().any(|m| m == modifier)
    }

    /// Visible to derived types: not private (members are private by default).
    pub(crate) fn inherited(&self) -> bool {
        ["public", "protected", "internal"]
            .iter()
            .any(|m| self.has(m))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct TypeDecl {
    pub(crate) name: String,
    pub(crate) arity: usize,
    pub(crate) namespace: String,
    /// Enclosing types, outermost first.
    pub(crate) outer: Vec<String>,
    /// "class", "struct", "record", "interface", "enum", "delegate".
    pub(crate) kind: String,
    pub(crate) modifiers: Vec<String>,
    pub(crate) attributes: Vec<String>,
    pub(crate) bases: Vec<TypeRef>,
    pub(crate) members: Vec<MemberDecl>,
    pub(crate) span: Span,
}

impl TypeDecl {
    pub(crate) fn has(&self, modifier: &str) -> bool {
        self.modifiers.iter().any(|m| m == modifier)
    }

    /// Namespace, enclosing types and name: the same for every part of a
    /// partial type.
    pub(crate) fn full_name(&self) -> String {
        let mut parts: Vec<&str> = Vec::new();
        if !self.namespace.is_empty() {
            parts.push(&self.namespace);
        }
        parts.extend(self.outer.iter().map(String::as_str));
        parts.push(&self.name);
        format!("{}`{}", parts.join("."), self.arity)
    }
}

/// What one file declares, and the namespaces it imports.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub(crate) struct FileIndex {
    pub(crate) usings: Vec<String>,
    pub(crate) types: Vec<TypeDecl>,
}

/// The fact kind a file's index travels under.
pub(crate) const FACT: &str = "cs-index";

// ---------------------------------------------------- extraction

const TYPE_KINDS: &[(&str, &str)] = &[
    ("class_declaration", "class"),
    ("struct_declaration", "struct"),
    ("record_declaration", "record"),
    ("record_struct_declaration", "struct"),
    ("interface_declaration", "interface"),
    ("enum_declaration", "enum"),
    ("delegate_declaration", "delegate"),
];

struct Extractor<'s> {
    src: &'s [u8],
}

impl Extractor<'_> {
    fn text(&self, n: Node) -> String {
        n.utf8_text(self.src).unwrap_or_default().to_string()
    }

    /// Without whitespace, so `List< int >` and `List<int>` compare equal.
    fn type_text(&self, n: Node) -> String {
        self.text(n)
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect()
    }

    fn span(&self, n: Node) -> Span {
        // Columns count characters: convert each end's byte offset.
        let char_column = |byte: usize| -> usize {
            let start = self.src[..byte]
                .iter()
                .rposition(|b| *b == b'\n')
                .map_or(0, |i| i + 1);
            String::from_utf8_lossy(&self.src[start..byte])
                .chars()
                .count()
                + 1
        };
        Span {
            line: n.start_position().row + 1,
            column: char_column(n.start_byte()),
            end_line: n.end_position().row + 1,
            end_column: char_column(n.end_byte()),
        }
    }

    fn modifiers(&self, n: Node) -> Vec<String> {
        let mut cursor = n.walk();
        n.named_children(&mut cursor)
            .filter(|c| c.kind() == "modifier")
            .map(|c| self.text(c))
            .collect()
    }

    fn attributes(&self, n: Node) -> Vec<String> {
        let mut out = Vec::new();
        let mut cursor = n.walk();
        for list in n
            .named_children(&mut cursor)
            .filter(|c| c.kind() == "attribute_list")
        {
            let mut c = list.walk();
            for a in list
                .named_children(&mut c)
                .filter(|a| a.kind() == "attribute")
            {
                if let Some(name) = a.child_by_field_name("name") {
                    let full = self.text(name);
                    let last = full.rsplit('.').next().unwrap_or(&full).to_string();
                    out.push(
                        last.strip_suffix("Attribute")
                            .map(str::to_string)
                            .unwrap_or(last),
                    );
                }
            }
        }
        out
    }

    fn type_ref(&self, n: Node) -> TypeRef {
        match n.kind() {
            "generic_name" => TypeRef {
                name: n.named_child(0).map(|i| self.text(i)).unwrap_or_default(),
                arity: n.named_child(1).map_or(0, |a| a.named_child_count()),
            },
            "qualified_name" => n.child_by_field_name("name").map_or_else(
                || TypeRef {
                    name: self.text(n),
                    arity: 0,
                },
                |x| self.type_ref(x),
            ),
            _ => TypeRef {
                name: self.text(n),
                arity: 0,
            },
        }
    }

    fn params(&self, owner: Node) -> Vec<ParamDecl> {
        let mut out = Vec::new();
        let Some(list) = owner.child_by_field_name("parameters") else {
            return out;
        };
        let mut cursor = list.walk();
        if !cursor.goto_first_child() {
            return out;
        }
        // A `params T[] rest` parameter keeps its type and name on the list.
        let mut params_type = None;
        loop {
            let c = cursor.node();
            match cursor.field_name() {
                Some("type") => params_type = Some(c),
                Some("name") => out.push(ParamDecl {
                    name: self.text(c),
                    ty: params_type
                        .take()
                        .map(|t| self.type_text(t))
                        .unwrap_or_default(),
                    default: None,
                    is_params: true,
                    span: self.span(c),
                }),
                _ if c.kind() == "parameter" => {
                    if let Some(name) = c.child_by_field_name("name") {
                        let mut dc = c.walk();
                        let default = c
                            .named_children(&mut dc)
                            .find(|x| x.start_byte() >= name.end_byte())
                            .map(|d| self.type_text(d));
                        out.push(ParamDecl {
                            name: self.text(name),
                            ty: c
                                .child_by_field_name("type")
                                .map(|t| self.type_text(t))
                                .unwrap_or_default(),
                            default,
                            is_params: false,
                            span: self.span(name),
                        });
                    }
                }
                _ => {}
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        out
    }

    fn member(&self, n: Node) -> Vec<MemberDecl> {
        let kind = match n.kind() {
            "method_declaration" => "method",
            "property_declaration" => "property",
            "field_declaration" => "field",
            "event_field_declaration" | "event_declaration" => "event",
            "constructor_declaration" => "constructor",
            "destructor_declaration" => "destructor",
            _ => return Vec::new(),
        };
        let modifiers = self.modifiers(n);
        let mut cursor = n.walk();
        let explicit = n
            .named_children(&mut cursor)
            .any(|c| c.kind() == "explicit_interface_specifier");
        let body = n.child_by_field_name("body");
        // Calls the dispose pattern looks for, without whitespace: only in
        // Dispose methods and finalizers.
        let disposing = kind == "destructor"
            || n.child_by_field_name("name")
                .is_some_and(|x| self.text(x) == "Dispose");
        let calls = body
            .filter(|_| disposing)
            .map(|b| {
                let compact: String = self
                    .text(b)
                    .chars()
                    .filter(|c| !c.is_whitespace())
                    .collect();
                [
                    "Dispose(true)",
                    "Dispose(false)",
                    "GC.SuppressFinalize(this)",
                ]
                .iter()
                .filter(|c| compact.contains(*c))
                .map(|c| c.to_string())
                .collect()
            })
            .unwrap_or_default();
        let returns = n
            .child_by_field_name("returns")
            .or_else(|| n.child_by_field_name("type"))
            .map(|t| self.type_text(t))
            .unwrap_or_default();
        if matches!(kind, "field" | "event") && n.child_by_field_name("name").is_none() {
            // One member per declarator: `int a, b;`
            let mut c = n.walk();
            let Some(variables) = n
                .named_children(&mut c)
                .find(|v| v.kind() == "variable_declaration")
            else {
                return Vec::new();
            };
            let ty = variables
                .child_by_field_name("type")
                .map(|t| self.type_text(t))
                .unwrap_or_default();
            let mut vc = variables.walk();
            return variables
                .named_children(&mut vc)
                .filter(|d| d.kind() == "variable_declarator")
                .filter_map(|d| d.child_by_field_name("name"))
                .map(|name| MemberDecl {
                    kind: kind.to_string(),
                    name: self.text(name),
                    modifiers: modifiers.clone(),
                    explicit: false,
                    returns: ty.clone(),
                    params: Vec::new(),
                    has_body: false,
                    calls: Vec::new(),
                    span: self.span(name),
                })
                .collect();
        }
        let name = n.child_by_field_name("name");
        vec![MemberDecl {
            kind: kind.to_string(),
            name: name.map(|x| self.text(x)).unwrap_or_default(),
            modifiers,
            explicit,
            returns,
            params: self.params(n),
            has_body: body.is_some(),
            calls,
            span: self.span(name.unwrap_or(n)),
        }]
    }
}

/// Summarizes the types a C# file declares. One iterative walk: types are
/// found at any depth, with their namespace and enclosing types.
pub(crate) fn extract(root: Node, src: &[u8]) -> FileIndex {
    let x = Extractor { src };
    let mut index = FileIndex::default();
    // (depth, name) of enclosing namespaces and types.
    let mut namespaces: Vec<(usize, String)> = Vec::new();
    let mut file_namespace = String::new();
    let mut outer: Vec<(usize, String)> = Vec::new();
    let mut cursor = root.walk();
    let mut depth = 0;
    loop {
        let node = cursor.node();
        match node.kind() {
            "using_directive" => {
                // Plain `using N;`, not aliases or `using static`.
                let t = x.text(node);
                if node.child_by_field_name("name").is_none()
                    && !t.contains("static")
                    && let Some(n) = node.named_child(0)
                {
                    index.usings.push(x.text(n));
                }
            }
            "file_scoped_namespace_declaration" => {
                file_namespace = node
                    .child_by_field_name("name")
                    .map(|n| x.text(n))
                    .unwrap_or_default();
            }
            "namespace_declaration" => {
                if let Some(n) = node.child_by_field_name("name") {
                    namespaces.push((depth, x.text(n)));
                }
            }
            k => {
                if let Some((_, kind)) = TYPE_KINDS.iter().find(|(tk, _)| *tk == k)
                    && let Some(name) = node.child_by_field_name("name")
                {
                    let mut ns: Vec<&str> = Vec::new();
                    if !file_namespace.is_empty() {
                        ns.push(&file_namespace);
                    }
                    ns.extend(namespaces.iter().map(|(_, n)| n.as_str()));
                    let mut c = node.walk();
                    let type_params = node
                        .named_children(&mut c)
                        .find(|p| p.kind() == "type_parameter_list");
                    let mut bc = node.walk();
                    let bases = node
                        .named_children(&mut bc)
                        .find(|b| b.kind() == "base_list")
                        .map(|b| {
                            let mut c = b.walk();
                            b.named_children(&mut c).map(|t| x.type_ref(t)).collect()
                        })
                        .unwrap_or_default();
                    let members = node
                        .child_by_field_name("body")
                        .filter(|b| b.kind() == "declaration_list")
                        .map(|b| {
                            let mut c = b.walk();
                            b.named_children(&mut c).flat_map(|m| x.member(m)).collect()
                        })
                        .unwrap_or_default();
                    index.types.push(TypeDecl {
                        name: x.text(name),
                        arity: type_params.map_or(0, |p| p.named_child_count()),
                        namespace: ns.join("."),
                        outer: outer.iter().map(|(_, n)| n.clone()).collect(),
                        kind: kind.to_string(),
                        modifiers: x.modifiers(node),
                        attributes: x.attributes(node),
                        bases,
                        members,
                        span: x.span(name),
                    });
                    outer.push((depth, x.text(name)));
                }
            }
        }
        // Types are only declared at namespace and type level: skip member
        // bodies, initializers and parameter lists.
        let declares = !matches!(
            node.kind(),
            "block"
                | "arrow_expression_clause"
                | "accessor_list"
                | "parameter_list"
                | "variable_declaration"
                | "enum_member_declaration_list"
                | "attribute_list"
                | "base_list"
                | "type_parameter_constraints_clause"
        );
        if declares && cursor.goto_first_child() {
            depth += 1;
            continue;
        }
        loop {
            while namespaces.last().is_some_and(|(d, _)| *d >= depth) {
                namespaces.pop();
            }
            while outer.last().is_some_and(|(d, _)| *d >= depth) {
                outer.pop();
            }
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return index;
            }
            depth -= 1;
        }
    }
}

// ---------------------------------------------------- the project index

/// Every file's declarations, by type. Files are numbered by their position
/// in the list given to `new`.
pub(crate) struct ProjectIndex<'a> {
    files: Vec<&'a FileIndex>,
    /// Each type's parts (several for a partial type): (file, declaration).
    types: Vec<Vec<(usize, &'a TypeDecl)>>,
    by_full_name: HashMap<String, usize>,
    /// (simple name, arity) to the types that have it.
    by_name: HashMap<(String, usize), Vec<usize>>,
}

/// A type of the project: its parts across files.
pub(crate) type TypeId = usize;

impl<'a> ProjectIndex<'a> {
    pub(crate) fn new(files: Vec<&'a FileIndex>) -> Self {
        let mut index = ProjectIndex {
            files,
            types: Vec::new(),
            by_full_name: HashMap::new(),
            by_name: HashMap::new(),
        };
        for (file, f) in index.files.iter().enumerate() {
            for t in &f.types {
                let full = t.full_name();
                let id = match index.by_full_name.get(&full) {
                    Some(id) => *id,
                    None => {
                        let id = index.types.len();
                        index.types.push(Vec::new());
                        index.by_full_name.insert(full, id);
                        index
                            .by_name
                            .entry((t.name.clone(), t.arity))
                            .or_default()
                            .push(id);
                        id
                    }
                };
                index.types[id].push((file, t));
            }
        }
        index
    }

    pub(crate) fn len(&self) -> usize {
        self.types.len()
    }

    /// A type's parts: (file, declaration).
    pub(crate) fn parts(&self, id: TypeId) -> &[(usize, &'a TypeDecl)] {
        &self.types[id]
    }

    /// The first part, which stands for the type's name, kind and file.
    pub(crate) fn decl(&self, id: TypeId) -> (usize, &'a TypeDecl) {
        self.types[id][0]
    }

    /// Every member of every part.
    pub(crate) fn members(&self, id: TypeId) -> impl Iterator<Item = (usize, &'a MemberDecl)> + '_ {
        self.types[id]
            .iter()
            .flat_map(|(file, t)| t.members.iter().map(move |m| (*file, m)))
    }

    /// Every base type reference of every part, with the part it's from.
    pub(crate) fn bases(&self, id: TypeId) -> Vec<(usize, &'a TypeDecl, &'a TypeRef)> {
        self.types[id]
            .iter()
            .flat_map(|(file, t)| t.bases.iter().map(move |b| (*file, *t, b)))
            .collect()
    }

    /// The project type `r` names, as written in `from` (a part declared in
    /// `file`): unique by simple name and arity, or else narrowed to the
    /// namespaces visible there. None for types from other assemblies and
    /// names that stay ambiguous.
    pub(crate) fn resolve(&self, file: usize, from: &TypeDecl, r: &TypeRef) -> Option<TypeId> {
        let candidates = self.by_name.get(&(r.name.clone(), r.arity))?;
        if let [one] = candidates.as_slice() {
            return Some(*one);
        }
        let usings = &self.files[file].usings;
        let visible: Vec<TypeId> = candidates
            .iter()
            .copied()
            .filter(|id| {
                let ns = &self.decl(*id).1.namespace;
                ns == &from.namespace
                    || from.namespace.starts_with(&format!("{ns}."))
                    || usings.iter().any(|u| u == ns)
            })
            .collect();
        match visible.as_slice() {
            [one] => Some(*one),
            _ => None,
        }
    }

    /// The base class of a class, if it's declared in the project: the
    /// first base type, when it resolves to a class or record.
    pub(crate) fn base_class(&self, id: TypeId) -> Option<TypeId> {
        let (file, part, first) = self.types[id]
            .iter()
            .find_map(|(f, t)| t.bases.first().map(|b| (*f, *t, b)))?;
        self.resolve(file, part, first)
            .filter(|b| *b != id && matches!(self.decl(*b).1.kind.as_str(), "class" | "record"))
    }

    /// The interfaces a type lists that are declared in the project.
    pub(crate) fn interfaces(&self, id: TypeId) -> Vec<TypeId> {
        let mut out: Vec<TypeId> = self
            .bases(id)
            .into_iter()
            .filter_map(|(f, t, b)| self.resolve(f, t, b))
            .filter(|b| *b != id && self.decl(*b).1.kind == "interface")
            .collect();
        out.dedup();
        out
    }

    /// Base classes declared in the project, nearest first, without cycles.
    pub(crate) fn ancestors(&self, id: TypeId) -> Vec<TypeId> {
        let mut out = Vec::new();
        let mut current = id;
        while let Some(base) = self.base_class(current) {
            if base == id || out.contains(&base) || out.len() > 32 {
                break;
            }
            out.push(base);
            current = base;
        }
        out
    }
}
