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

use super::dotnet::{self, PlatformType};
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

/// A reference to a type by its simple name and number of type arguments,
/// and what qualifies it where it's written: `System.IO` in
/// `System.IO.Stream`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub(crate) struct TypeRef {
    pub(crate) name: String,
    pub(crate) arity: usize,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) qualifier: String,
}

impl TypeRef {
    /// The reference a type written as text names: `List<int>`,
    /// `System.IO.Stream`, `Stream?`. None for arrays, tuples and pointers.
    pub(crate) fn parse(text: &str) -> Option<TypeRef> {
        let text = text.trim().trim_end_matches('?');
        let text = text.strip_prefix("global::").unwrap_or(text);
        if text.is_empty() || text.ends_with(']') || text.ends_with('*') || text.starts_with('(') {
            return None;
        }
        let (path, arity) = match text.find('<') {
            Some(open) => {
                let args = &text[open + 1..text.rfind('>')?];
                let mut depth = 0;
                let commas = args
                    .chars()
                    .filter(|c| {
                        match c {
                            '<' | '(' => depth += 1,
                            '>' | ')' => depth -= 1,
                            _ => {}
                        }
                        *c == ',' && depth == 0
                    })
                    .count();
                (&text[..open], commas + 1)
            }
            None => (text, 0),
        };
        let (qualifier, name) = path.rsplit_once('.').unwrap_or(("", path));
        Some(TypeRef {
            name: name.to_string(),
            arity,
            qualifier: qualifier.to_string(),
        })
    }
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
    #[serde(default)]
    pub(crate) attributes: Vec<String>,
    /// A property's accessors: "get", "set", "init".
    #[serde(default)]
    pub(crate) accessors: Vec<String>,
    /// A method with type parameters of its own.
    #[serde(default)]
    pub(crate) generic: bool,
    /// A field the type assigns a `new` object to, in its initializer or
    /// any member.
    #[serde(default)]
    pub(crate) created: bool,
    /// The first and last line of the whole declaration, attributes
    /// included.
    #[serde(default)]
    pub(crate) lines: (usize, usize),
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
    /// The first and last line of the whole declaration.
    #[serde(default)]
    pub(crate) lines: (usize, usize),
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

/// A place in a file where a type or method declared elsewhere is used,
/// for rules that need that declaration to judge it.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct Site {
    /// "bitwise" (an enum's members combined with `|`, `&` or `^`),
    /// "params-array" (an array written for a `params` parameter), "new",
    /// "cast" (a variable cast to a type, or converted with `as`),
    /// "entity" (a durable entity interface), "extension" (the type an
    /// extension method extends), "action-param" (a controller action's
    /// parameter type).
    pub(crate) kind: String,
    /// The type, or for "params-array" the method, the site names.
    pub(crate) name: String,
    pub(crate) arity: usize,
    /// The namespace the site is written in.
    pub(crate) namespace: String,
    /// The full name of the type the site is written in.
    pub(crate) owner: String,
    /// For "params-array": the receiver's type, when not the owner; for
    /// "cast", the variable's declared type.
    pub(crate) receiver: Option<String>,
    /// For "params-array": the number of arguments.
    pub(crate) count: usize,
    pub(crate) span: Span,
}

/// What one file declares, the namespaces it imports, and where it uses
/// declarations from elsewhere.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub(crate) struct FileIndex {
    pub(crate) usings: Vec<String>,
    /// `global using N;`, which every file of the project imports.
    #[serde(default)]
    pub(crate) global_usings: Vec<String>,
    pub(crate) types: Vec<TypeDecl>,
    #[serde(default)]
    pub(crate) sites: Vec<Site>,
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
                    let last = last
                        .strip_suffix("Attribute")
                        .map(str::to_string)
                        .unwrap_or(last);
                    // [PartCreationPolicy(CreationPolicy.Shared)]
                    if last == "PartCreationPolicy" && self.text(a).contains("Shared") {
                        out.push("PartCreationPolicy.Shared".to_string());
                    }
                    out.push(last);
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
                ..TypeRef::default()
            },
            "qualified_name" => n.child_by_field_name("name").map_or_else(
                || TypeRef {
                    name: self.text(n),
                    ..TypeRef::default()
                },
                |x| {
                    let qualifier = n
                        .child_by_field_name("qualifier")
                        .map(|q| self.text(q))
                        .unwrap_or_default();
                    TypeRef {
                        qualifier: qualifier
                            .strip_prefix("global::")
                            .unwrap_or(&qualifier)
                            .to_string(),
                        ..self.type_ref(x)
                    }
                },
            ),
            // `class B(int x) : A(x)`
            "primary_constructor_base_type" => n
                .child_by_field_name("type")
                .or_else(|| n.named_child(0))
                .map_or_else(TypeRef::default, |t| self.type_ref(t)),
            _ => TypeRef {
                name: self.text(n),
                ..TypeRef::default()
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
        let attributes = self.attributes(n);
        // A property's get, set and init.
        let accessors: Vec<String> = n
            .child_by_field_name("accessors")
            .map(|list| {
                let mut c = list.walk();
                list.named_children(&mut c)
                    .filter_map(|acc| {
                        let mut ac = acc.walk();
                        let keyword = acc
                            .children(&mut ac)
                            .find(|k| matches!(k.kind(), "get" | "set" | "init"));
                        keyword
                            .map(|k| k.kind().to_string())
                            .or_else(|| acc.child_by_field_name("name").map(|k| self.text(k)))
                    })
                    .collect()
            })
            .unwrap_or_default();
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
                    .collect::<String>()
                    .replace("disposing:", "");
                let mut found: Vec<String> = [
                    "Dispose(true)",
                    "Dispose(false)",
                    "GC.SuppressFinalize(this)",
                    "base.Dispose(",
                ]
                .iter()
                .filter(|c| compact.contains(*c))
                .map(|c| c.to_string())
                .collect();
                // Nothing but the pattern's calls: `only:` and the calls.
                let only = compact
                    .trim_start_matches("=>")
                    .trim_start_matches('{')
                    .trim_end_matches('}')
                    .replace("this.", "");
                let only = only.trim_end_matches(';');
                if !only.is_empty() && !only.contains(['{', '}']) {
                    found.push(format!("only:{only}"));
                }
                found
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
                .filter_map(|d| Some((d, d.child_by_field_name("name")?)))
                .map(|(d, name)| MemberDecl {
                    kind: kind.to_string(),
                    name: self.text(name),
                    modifiers: modifiers.clone(),
                    explicit: false,
                    returns: ty.clone(),
                    params: Vec::new(),
                    has_body: false,
                    calls: Vec::new(),
                    span: self.span(name),
                    attributes: attributes.clone(),
                    accessors: Vec::new(),
                    generic: false,
                    created: d
                        .child_by_field_name("value")
                        .or_else(|| d.named_child(d.named_child_count() as u32 - 1))
                        .is_some_and(is_creation),
                    lines: lines(n),
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
            attributes,
            accessors,
            generic: n
                .named_children(&mut n.walk())
                .any(|c| c.kind() == "type_parameter_list"),
            created: false,
            lines: lines(n),
        }]
    }
}

/// Names the durable entity APIs take an entity interface through.
const ENTITY_CALLS: &[&str] = &[
    "SignalEntityAsync",
    "SignalEntity",
    "CreateEntityProxy",
    "ReadEntityStateAsync",
];

/// A site waiting for a variable's declared type, which takes the semantic
/// model: (the site, the operands or receiver whose type names it).
type Pending<'t> = (Site, Vec<Node<'t>>);

impl Extractor<'_> {
    /// The enum an operand of `|`, `&` or `^` names directly, `Color.Red`.
    fn enum_member(&self, n: Node) -> Option<String> {
        let n = unparenthesized(n);
        (n.kind() == "member_access_expression")
            .then(|| n.child_by_field_name("expression"))
            .flatten()
            .filter(|e| {
                matches!(
                    e.kind(),
                    "identifier" | "member_access_expression" | "qualified_name"
                )
            })
            .map(|e| self.simple(e))
    }

    fn simple(&self, n: Node) -> String {
        match n.kind() {
            "member_access_expression" | "qualified_name" => n
                .child_by_field_name("name")
                .map_or_else(|| self.text(n), |x| self.simple(x)),
            "generic_name" => n
                .named_child(0)
                .map_or_else(|| self.text(n), |x| self.text(x)),
            _ => self.text(n),
        }
    }

    fn site(
        &self,
        kind: &str,
        name: String,
        arity: usize,
        ns: &str,
        owner: &str,
        span: Span,
    ) -> Site {
        Site {
            kind: kind.to_string(),
            name,
            arity,
            namespace: ns.to_string(),
            owner: owner.to_string(),
            receiver: None,
            count: 0,
            span,
        }
    }
}

/// `new T(...)`, `new(...)`, or one of them in parentheses.
fn is_creation(n: Node) -> bool {
    matches!(
        unparenthesized(n).kind(),
        "object_creation_expression" | "implicit_object_creation_expression"
    )
}

/// Fields a type's members assign a `new` object to: `f = new T()` or
/// `this.f = new T()`. Nested types are their own.
fn created_fields(body: Node, x: &Extractor) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack: Vec<Node> = {
        let mut c = body.walk();
        body.named_children(&mut c).collect()
    };
    while let Some(n) = stack.pop() {
        if TYPE_KINDS.iter().any(|(k, _)| *k == n.kind()) {
            continue;
        }
        if n.kind() == "assignment_expression"
            && n.child_by_field_name("right").is_some_and(is_creation)
            && let Some(left) = n.child_by_field_name("left")
        {
            let name = match left.kind() {
                "identifier" => Some(left),
                "member_access_expression"
                    if left
                        .child_by_field_name("expression")
                        .is_some_and(|e| e.kind() == "this_expression" || x.text(e) == "this") =>
                {
                    left.child_by_field_name("name")
                }
                _ => None,
            };
            out.extend(name.map(|n| x.text(n)));
        }
        let mut c = n.walk();
        stack.extend(n.named_children(&mut c));
    }
    out
}

fn lines(n: Node) -> (usize, usize) {
    (n.start_position().row + 1, n.end_position().row + 1)
}

/// The distinct platform types `path` names under each of `prefixes`.
fn platform_lookup<'p>(
    platform: &'static dotnet::Platform,
    path: &str,
    prefixes: impl Iterator<Item = &'p str>,
) -> Vec<&'static PlatformType> {
    let mut found: Vec<&'static PlatformType> = Vec::new();
    for prefix in prefixes {
        let key = if prefix.is_empty() {
            path.to_string()
        } else {
            format!("{prefix}.{path}")
        };
        if let Some(t) = platform.get(&key)
            && !found.iter().any(|f| std::ptr::eq(*f, t))
        {
            found.push(t);
        }
    }
    found
}

fn unparenthesized(mut n: Node) -> Node {
    while n.kind() == "parenthesized_expression" {
        match n.named_child(0) {
            Some(inner) => n = inner,
            None => break,
        }
    }
    n
}

/// Summarizes what a C# file declares, and where it uses declarations a
/// project rule has to look up. One iterative walk; the semantic model is
/// built only when a site needs a variable's declared type.
pub(crate) fn extract<'t>(root: Node<'t>, src: &[u8], deadline: std::time::Instant) -> FileIndex {
    let mut indexer = Indexer {
        x: Extractor { src },
        index: FileIndex::default(),
        namespaces: Vec::new(),
        file_namespace: String::new(),
        outer: Vec::new(),
        pending: Vec::new(),
    };
    let mut cursor = root.walk();
    let mut depth = 0;
    loop {
        indexer.visit(cursor.node(), depth);
        if cursor.goto_first_child() {
            depth += 1;
            continue;
        }
        loop {
            indexer.leave(depth);
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                let Indexer {
                    mut index, pending, ..
                } = indexer;
                resolve_pending(&mut index, pending, root, src, deadline);
                return index;
            }
            depth -= 1;
        }
    }
}

/// `extract`'s walk: what it has found, and where it is.
struct Indexer<'s, 't> {
    x: Extractor<'s>,
    index: FileIndex,
    /// (depth, name) of the enclosing namespaces.
    namespaces: Vec<(usize, String)>,
    file_namespace: String,
    /// (depth, name, arity) of the enclosing types.
    outer: Vec<(usize, String, usize)>,
    pending: Vec<Pending<'t>>,
}

/// The number of type arguments of a `generic_name`; 0 for any other type.
fn generic_arity(t: Node) -> usize {
    if t.kind() == "generic_name" {
        t.named_child(1).map_or(0, |a| a.named_child_count())
    } else {
        0
    }
}

impl<'t> Indexer<'_, 't> {
    fn visit(&mut self, node: Node<'t>, depth: usize) {
        match node.kind() {
            "using_directive" => self.using(node),
            "file_scoped_namespace_declaration" => {
                self.file_namespace = node
                    .child_by_field_name("name")
                    .map(|n| self.x.text(n))
                    .unwrap_or_default();
            }
            "namespace_declaration" => {
                if let Some(n) = node.child_by_field_name("name") {
                    self.namespaces.push((depth, self.x.text(n)));
                }
            }
            "cast_expression" | "as_expression" => self.cast(node),
            "binary_expression" => self.bitwise(node),
            "invocation_expression" => self.params_array(node),
            "object_creation_expression" => self.creation(node),
            "generic_name" => self.entity(node),
            "parameter" => self.extension(node),
            "method_declaration" => self.action_params(node),
            k => {
                if let Some((_, kind)) = TYPE_KINDS.iter().find(|(tk, _)| *tk == k)
                    && let Some(name) = node.child_by_field_name("name")
                {
                    self.type_declaration(node, name, kind, depth);
                }
            }
        }
    }

    /// Leaving the node at `depth`: the namespaces and types it opened end.
    fn leave(&mut self, depth: usize) {
        while self.namespaces.last().is_some_and(|(d, _)| *d >= depth) {
            self.namespaces.pop();
        }
        while self.outer.last().is_some_and(|(d, _, _)| *d >= depth) {
            self.outer.pop();
        }
    }

    fn ns(&self) -> String {
        let mut parts: Vec<&str> = Vec::new();
        if !self.file_namespace.is_empty() {
            parts.push(&self.file_namespace);
        }
        parts.extend(self.namespaces.iter().map(|(_, n)| n.as_str()));
        parts.join(".")
    }

    /// The full name of the innermost enclosing type, as `full_name` has it.
    fn owner(&self) -> String {
        let Some((_, name, arity)) = self.outer.last() else {
            return String::new();
        };
        let namespace = self.ns();
        let mut parts: Vec<&str> = Vec::new();
        if !namespace.is_empty() {
            parts.push(&namespace);
        }
        parts.extend(
            self.outer[..self.outer.len() - 1]
                .iter()
                .map(|(_, n, _)| n.as_str()),
        );
        parts.push(name);
        format!("{}`{arity}", parts.join("."))
    }

    /// A site of `kind` at `span`, in the current namespace and type.
    fn site(&self, kind: &str, name: String, arity: usize, span: Span) -> Site {
        self.x
            .site(kind, name, arity, &self.ns(), &self.owner(), span)
    }

    /// Plain `using N;`, not aliases or `using static`.
    fn using(&mut self, node: Node) {
        let t = self.x.text(node);
        if node.child_by_field_name("name").is_none()
            && !t.contains("static")
            && let Some(n) = node.named_child(0)
        {
            if t.starts_with("global") {
                self.index.global_usings.push(self.x.text(n));
            } else {
                self.index.usings.push(self.x.text(n));
            }
        }
    }

    /// `(Concrete)value` and `value as Concrete`: the variable's declared
    /// type and the target decide.
    fn cast(&mut self, node: Node<'t>) {
        let (target, value) = if node.kind() == "cast_expression" {
            (
                node.child_by_field_name("type"),
                node.child_by_field_name("value"),
            )
        } else {
            (
                node.child_by_field_name("right"),
                node.child_by_field_name("left"),
            )
        };
        if let (Some(target), Some(value)) = (target, value)
            && matches!(
                target.kind(),
                "identifier" | "generic_name" | "qualified_name"
            )
            && unparenthesized(value).kind() == "identifier"
        {
            let name = self.x.type_text(target);
            let site = self.site("cast", name, 0, self.x.span(node));
            self.pending.push((site, vec![unparenthesized(value)]));
        }
    }

    /// `Color.Red | Color.Red`, or `flags | Color.Red`, where the variable's
    /// declared type decides.
    fn bitwise(&mut self, node: Node<'t>) {
        let op = node
            .child_by_field_name("operator")
            .map(|o| self.x.text(o))
            .unwrap_or_default();
        if !matches!(op.as_str(), "|" | "&" | "^") {
            return;
        }
        let (Some(l), Some(r)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) else {
            return;
        };
        match (self.x.enum_member(l), self.x.enum_member(r)) {
            (Some(a), Some(b)) if a == b => {
                let site = self.site("bitwise", a, 0, self.x.span(node));
                self.index.sites.push(site);
            }
            (Some(a), None) | (None, Some(a)) => {
                let variable = if self.x.enum_member(l).is_some() {
                    r
                } else {
                    l
                };
                if unparenthesized(variable).kind() == "identifier" {
                    let site = self.site("bitwise", a, 0, self.x.span(node));
                    self.pending.push((site, vec![unparenthesized(variable)]));
                }
            }
            _ => {}
        }
    }

    /// An array written out for a call's last argument.
    fn params_array(&mut self, node: Node<'t>) {
        let args: Vec<Node> = node
            .child_by_field_name("arguments")
            .map(|a| {
                let mut c = a.walk();
                a.named_children(&mut c)
                    .filter_map(|arg| {
                        arg.named_child(arg.named_child_count().saturating_sub(1) as u32)
                    })
                    .collect()
            })
            .unwrap_or_default();
        // `[.. xs]` spreads a sequence into the array, which `params` can't
        // do on its own.
        let spreads = |a: &Node| {
            let mut c = a.walk();
            a.named_children(&mut c).any(|e| {
                e.named_child(0)
                    .is_some_and(|x| x.kind() == "spread_element")
            })
        };
        let written = args.last().filter(|a| {
            a.kind() == "implicit_array_creation_expression"
                || (a.kind() == "collection_expression" && !spreads(a))
                || (a.kind() == "array_creation_expression" && a.named_child_count() >= 2)
        });
        let (Some(last), Some(function)) = (written, node.child_by_field_name("function")) else {
            return;
        };
        // `new object[] { x }`: an object array given for `params object[]`
        // isn't reported (measured on SonarQube 26.7); x may be an array.
        if last.child_by_field_name("type").is_some_and(|t| {
            matches!(
                self.x.text(t).as_str(),
                "object[]" | "Object[]" | "System.Object[]"
            )
        }) {
            return;
        }
        let mut site = self.site("params-array", String::new(), 0, self.x.span(*last));
        site.count = args.len();
        // `s.Split(new[] { '.', '-' })`, `TrimStart(new char[] { '/' })`:
        // string's params methods, told by the characters they're given.
        if function.kind() == "member_access_expression" && args.len() == 1 {
            let method = function
                .child_by_field_name("name")
                .map(|n| self.x.simple(n))
                .unwrap_or_default();
            let chars = last
                .named_children(&mut last.walk())
                .filter(|c| c.kind() == "initializer_expression")
                .flat_map(|i| i.named_children(&mut i.walk()).collect::<Vec<_>>())
                .collect::<Vec<_>>();
            if matches!(method.as_str(), "Split" | "Trim" | "TrimStart" | "TrimEnd")
                && !chars.is_empty()
                && chars.iter().all(|c| c.kind() == "character_literal")
            {
                site.name = method;
                site.receiver = Some("string".to_string());
                self.index.sites.push(site);
                return;
            }
        }
        match function.kind() {
            "identifier" | "generic_name" => {
                site.name = self.x.simple(function);
                self.index.sites.push(site);
            }
            "member_access_expression" => {
                site.name = function
                    .child_by_field_name("name")
                    .map(|n| self.x.simple(n))
                    .unwrap_or_default();
                match function.child_by_field_name("expression") {
                    // `this.M(...)`: the owner's.
                    Some(r) if self.x.text(r) == "this" => self.index.sites.push(site),
                    // `Type.M(...)` or `variable.M(...)`: the model tells.
                    Some(r) if r.kind() == "identifier" => self.pending.push((site, vec![r])),
                    _ => {}
                }
            }
            _ => {}
        }
    }

    fn creation(&mut self, node: Node) {
        if let Some(t) = node.child_by_field_name("type") {
            let site = self.site("new", self.x.simple(t), generic_arity(t), self.x.span(node));
            self.index.sites.push(site);
        }
    }

    /// `Set<T>()` and the other entity calls: `T` is an entity.
    fn entity(&mut self, node: Node) {
        if ENTITY_CALLS.contains(&self.x.simple(node).as_str())
            && let Some(arg) = node.named_child(1).and_then(|a| a.named_child(0))
        {
            let site = self.site("entity", self.x.simple(arg), 0, self.x.span(node));
            self.index.sites.push(site);
        }
    }

    /// An extension method's `this` parameter: its type is extended.
    fn extension(&mut self, node: Node) {
        let mut c = node.walk();
        let this = node
            .named_children(&mut c)
            .any(|m| m.kind() == "modifier" && self.x.text(m) == "this");
        if this && let Some(t) = node.child_by_field_name("type") {
            let site = self.site(
                "extension",
                self.x.simple(t),
                generic_arity(t),
                self.x.span(t),
            );
            self.index.sites.push(site);
        }
    }

    /// A public action of a class named like a controller: its parameters'
    /// types may be request models.
    fn action_params(&mut self, node: Node) {
        let controller = self
            .outer
            .last()
            .is_some_and(|(_, n, _)| n.ends_with("Controller"));
        let modifiers = self.x.modifiers(node);
        if !controller
            || !modifiers.iter().any(|m| m == "public")
            || modifiers.iter().any(|m| m == "static")
        {
            return;
        }
        let Some(list) = node.child_by_field_name("parameters") else {
            return;
        };
        let mut c = list.walk();
        for p in list
            .named_children(&mut c)
            .filter(|p| p.kind() == "parameter")
        {
            if self.x.attributes(p).iter().any(|a| a == "FromServices") {
                continue;
            }
            if let Some(t) = p.child_by_field_name("type") {
                let site = self.site("action-param", self.x.simple(t), 0, self.x.span(t));
                self.index.sites.push(site);
            }
        }
    }

    /// A class, struct, interface, record or enum: its declaration, and the
    /// type the walk is now in.
    fn type_declaration(&mut self, node: Node, name: Node, kind: &str, depth: usize) {
        let x = &self.x;
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
        let body = node
            .child_by_field_name("body")
            .filter(|b| b.kind() == "declaration_list");
        let mut members: Vec<MemberDecl> = body
            .map(|b| {
                let mut c = b.walk();
                b.named_children(&mut c).flat_map(|m| x.member(m)).collect()
            })
            .unwrap_or_default();
        if let Some(b) = body {
            for field in created_fields(b, x) {
                for m in members
                    .iter_mut()
                    .filter(|m| m.kind == "field" && m.name == field)
                {
                    m.created = true;
                }
            }
        }
        let arity = type_params.map_or(0, |p| p.named_child_count());
        let declaration = TypeDecl {
            name: x.text(name),
            arity,
            namespace: self.ns(),
            outer: self.outer.iter().map(|(_, n, _)| n.clone()).collect(),
            kind: kind.to_string(),
            modifiers: x.modifiers(node),
            attributes: x.attributes(node),
            bases,
            members,
            span: x.span(name),
            lines: lines(node),
        };
        self.index.types.push(declaration);
        self.outer.push((depth, x.text(name), arity));
    }
}

/// Settles the sites that need a variable's declared type: an operand of a
/// bitwise operation must have the enum's type, and a call's receiver names
/// its type, or is a type itself (`Type.M(...)`) when it declares nothing.
fn resolve_pending(
    index: &mut FileIndex,
    pending: Vec<Pending>,
    root: Node,
    src: &[u8],
    deadline: std::time::Instant,
) {
    if pending.is_empty() {
        return;
    }
    let Some(model) = super::build(crate::lang::Lang::CSharp, root, src, deadline) else {
        return;
    };
    let x = Extractor { src };
    // A name's declared type: written, or `var x = new T()`.
    let declared = |n: Node| -> Option<Option<String>> {
        let d = model.decl_of(n)?;
        let ty = d.ty.or_else(|| {
            d.declarator
                .filter(|v| v.kind() == "variable_declarator" && v.named_child_count() > 1)
                .and_then(|v| v.named_child(v.named_child_count() as u32 - 1))
                .filter(|v| v.kind() == "object_creation_expression")
                .and_then(|v| v.child_by_field_name("type"))
        });
        Some(ty.map(|t| x.simple(t)))
    };
    for (mut site, nodes) in pending {
        let Some(&n) = nodes.first() else {
            continue;
        };
        match site.kind.as_str() {
            "bitwise" => {
                if declared(n).flatten().is_some_and(|t| t == site.name) {
                    index.sites.push(site);
                }
            }
            // The variable's declared type as written, generics included.
            "cast" => {
                if let Some(t) = model.decl_of(n).and_then(|d| d.ty) {
                    site.receiver = Some(x.type_text(t));
                    index.sites.push(site);
                }
            }
            _ => match declared(n) {
                Some(Some(t)) => {
                    site.receiver = Some(t);
                    index.sites.push(site);
                }
                Some(None) => {}
                // Not a variable: a type with static methods.
                None => {
                    site.receiver = Some(x.text(n));
                    index.sites.push(site);
                }
            },
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
    /// The namespaces the project declares types in.
    namespaces: std::collections::HashSet<String>,
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
            namespaces: std::collections::HashSet::new(),
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
                index.namespaces.insert(t.namespace.clone());
            }
        }
        index
    }

    /// The files indexed, in the order given to `new`.
    pub(crate) fn files(&self) -> &[&'a FileIndex] {
        &self.files
    }

    /// The type with a full name, as `TypeDecl::full_name` writes it.
    pub(crate) fn type_named(&self, full_name: &str) -> Option<TypeId> {
        self.by_full_name.get(full_name).copied()
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
        self.resolve_in(file, &from.namespace, r)
    }

    /// `resolve_in`, from code inside the type `owner` (a full name): its
    /// nested types, and those of the types enclosing it, come first, as in
    /// C#'s lookup.
    pub(crate) fn resolve_at(
        &self,
        file: usize,
        namespace: &str,
        owner: &str,
        r: &TypeRef,
    ) -> Option<TypeId> {
        if r.qualifier.is_empty() {
            let mut path = owner.split('`').next().unwrap_or(owner);
            while path.len() > namespace.len() {
                if let Some(id) = self.type_named(&format!("{path}.{}`{}", r.name, r.arity)) {
                    return Some(id);
                }
                let Some((outer, _)) = path.rsplit_once('.') else {
                    break;
                };
                path = outer;
            }
        }
        self.resolve_in(file, namespace, r)
    }

    /// `resolve`, from code in `namespace` of `file`.
    pub(crate) fn resolve_in(&self, file: usize, namespace: &str, r: &TypeRef) -> Option<TypeId> {
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
                ns == namespace
                    || namespace.starts_with(&format!("{ns}."))
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

    /// The platform type `r` names, written in `namespace` of `file`
    /// (ADR-0022): through the namespace and those enclosing it, the file's
    /// usings and the project's global ones. None when the project declares
    /// a type of that name, which would shadow it, or when the name stays
    /// unresolved or ambiguous.
    pub(crate) fn platform_type(
        &self,
        file: usize,
        namespace: &str,
        r: &TypeRef,
    ) -> Option<&'static PlatformType> {
        if r.qualifier.is_empty() && self.by_name.contains_key(&(r.name.clone(), r.arity)) {
            return None;
        }
        let platform = dotnet::platform();
        let own = if r.arity > 0 {
            format!("{}`{}", r.name, r.arity)
        } else {
            r.name.clone()
        };
        let path = if r.qualifier.is_empty() {
            own
        } else {
            format!("{}.{own}", r.qualifier)
        };
        let enclosing =
            std::iter::successors(Some(namespace), |ns| ns.rsplit_once('.').map(|(p, _)| p))
                .filter(|ns| !ns.is_empty());
        let usings: Vec<&str> = self.files[file]
            .usings
            .iter()
            .chain(self.global_usings())
            .map(String::as_str)
            .collect();
        let prefixes = std::iter::once("")
            .chain(enclosing)
            .chain(usings.iter().copied());
        match platform_lookup(platform, &path, prefixes).as_slice() {
            [one] => return Some(*one),
            [] => {}
            _ => return None,
        }
        if !r.qualifier.is_empty() || !self.implicit_usings_apply(&usings) {
            return None;
        }
        match platform_lookup(platform, &path, IMPLICIT_USINGS.iter().copied()).as_slice() {
            [one] => Some(*one),
            _ => None,
        }
    }

    /// Whether the SDK's implicit usings count for a file with `usings`:
    /// when nothing the file imports could declare the name instead, or when
    /// the file imports none of their namespaces itself, which projects
    /// without them nearly always do.
    fn implicit_usings_apply(&self, usings: &[&str]) -> bool {
        let platform = dotnet::platform();
        let known = |ns: &str| platform.has_namespace(ns) || self.namespaces.contains(ns);
        usings.iter().all(|u| known(u)) || !usings.iter().any(|u| IMPLICIT_USINGS.contains(u))
    }

    fn global_usings(&self) -> impl Iterator<Item = &String> + '_ {
        self.files.iter().flat_map(|f| f.global_usings.iter())
    }

    /// Whether a project type implements a platform interface such as
    /// `System.IDisposable`, through its bases in the project and the
    /// platform. None when a base resolves to neither.
    pub(crate) fn implements(&self, id: TypeId, interface: &str) -> Option<bool> {
        let platform = dotnet::platform();
        let mut todo = vec![id];
        let mut seen = Vec::new();
        let mut unknown = false;
        while let Some(t) = todo.pop() {
            if seen.contains(&t) || seen.len() > 64 {
                continue;
            }
            seen.push(t);
            for (file, part, base) in self.types[t]
                .iter()
                .flat_map(|(f, p)| p.bases.iter().map(move |b| (*f, *p, b)))
            {
                if let Some(b) = self.resolve(file, part, base) {
                    todo.push(b);
                } else if let Some(p) = self.platform_type(file, &part.namespace, base) {
                    if platform.implements(&p.name, interface) {
                        return Some(true);
                    }
                } else {
                    unknown = true;
                }
            }
        }
        (!unknown).then_some(false)
    }

    /// Whether a type written in `namespace` of `file` implements a
    /// platform interface: a project type or a platform one. None when the
    /// name resolves to neither.
    pub(crate) fn type_implements(
        &self,
        file: usize,
        namespace: &str,
        r: &TypeRef,
        interface: &str,
    ) -> Option<bool> {
        match self.resolve_in(file, namespace, r) {
            Some(id) => self.implements(id, interface),
            None => self
                .platform_type(file, namespace, r)
                .map(|p| dotnet::platform().implements(&p.name, interface)),
        }
    }
}

/// The namespaces SDK-style projects import implicitly
/// (`<ImplicitUsings>`): Microsoft.NET.Sdk's.
const IMPLICIT_USINGS: &[&str] = &[
    "System",
    "System.Collections.Generic",
    "System.IO",
    "System.Linq",
    "System.Net.Http",
    "System.Threading",
    "System.Threading.Tasks",
];
