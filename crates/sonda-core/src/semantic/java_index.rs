//! A project-wide index of Java type declarations (ADR-0020, extended to
//! Java), for rules that compare a declaration with ones in other files: an
//! override with the method it overrides, a class with its superclasses, a
//! field with its type's declaration, a call with its callee's parameters.
//!
//! Each worker summarizes the types its file declares (`extract`): names,
//! supertypes, fields, methods and constructors, with positions, and the
//! calls that pass an array literal last. The summary crosses the worker
//! boundary as a fact, so no syntax tree leaves the sandbox. The scanner then
//! indexes every file's summary (`ProjectIndex`) and resolves a type name as
//! Java does, at the level summaries allow: nested types of the enclosing
//! types, the file's single-type imports, its package, then its on-demand
//! imports. The JDK and libraries aren't in the project, so their types
//! resolve to nothing.

use super::cs_index::Span;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;
use tree_sitter::Node;

/// The fact that carries a file's summary.
pub(crate) const FACT: &str = "java-index";

/// A type as written: its simple name, what qualifies it (`java.util` in
/// `java.util.List`), its type arguments and array dimensions. A wildcard
/// is `?` with its bound, if any, as its only argument; a primitive has no
/// qualifier and a lowercase name.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub(crate) struct TypeRef {
    pub(crate) name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) qualifier: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) args: Vec<TypeRef>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub(crate) dims: usize,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

impl TypeRef {
    pub(crate) fn is_primitive(&self) -> bool {
        self.qualifier.is_empty()
            && matches!(
                self.name.as_str(),
                "int" | "long" | "short" | "byte" | "char" | "boolean" | "float" | "double"
            )
    }

    pub(crate) fn is_wildcard(&self) -> bool {
        self.name == "?"
    }
}

/// A type parameter and its bounds.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub(crate) struct TypeParam {
    pub(crate) name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) bounds: Vec<TypeRef>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub(crate) struct FieldDecl {
    pub(crate) name: String,
    pub(crate) ty: TypeRef,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) modifiers: Vec<String>,
    pub(crate) span: Span,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub(crate) struct MethodDecl {
    pub(crate) name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) params: Vec<TypeRef>,
    /// Its last parameter is `T...`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) varargs: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) constructor: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) modifiers: Vec<String>,
    /// Annotations by simple name, `Override` included.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) annotations: Vec<String>,
    /// Its body only calls the same method of `super` with its own
    /// parameters, and returns what that returns.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) only_calls_super: bool,
    /// The name, where issues about the method are reported.
    pub(crate) span: Span,
    /// The first and last lines of the whole declaration, annotations
    /// included.
    pub(crate) lines: (usize, usize),
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub(crate) struct TypeDecl {
    pub(crate) name: String,
    /// The types it's nested in, outermost first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) outer: Vec<String>,
    /// `class`, `interface`, `enum`, `record` or `annotation`.
    pub(crate) kind: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) modifiers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) type_params: Vec<TypeParam>,
    /// A class's superclass, or the interfaces an interface extends.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) extends: Vec<TypeRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) implements: Vec<TypeRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) fields: Vec<FieldDecl>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) methods: Vec<MethodDecl>,
    /// The name.
    pub(crate) span: Span,
}

/// A call or `new` whose last argument is an array literal,
/// `f(new String[] {"a"})`, for the varargs rule.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub(crate) struct Site {
    /// The method's name, or the created type's simple name.
    pub(crate) callee: String,
    /// What the call is made on, as written (`Var` in `Var.m(...)`), or the
    /// created type's qualifier; empty for an unqualified call.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) qualifier: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) constructor: bool,
    pub(crate) args: usize,
    /// The types it's written in, outermost first, for unqualified calls.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) within: Vec<String>,
    /// The array literal.
    pub(crate) span: Span,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub(crate) struct FileIndex {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) package: String,
    /// Single-type imports, `java.util.List`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) imports: Vec<String>,
    /// On-demand imports, by package or type: `java.util` for `java.util.*`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) wildcards: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) types: Vec<TypeDecl>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) sites: Vec<Site>,
}

struct Extractor<'s> {
    src: &'s [u8],
}

impl<'s> Extractor<'s> {
    fn text(&self, n: Node) -> &'s str {
        std::str::from_utf8(&self.src[n.byte_range()]).unwrap_or_default()
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

    fn type_ref(&self, n: Node) -> TypeRef {
        match n.kind() {
            "generic_type" => {
                let mut t = n
                    .named_child(0)
                    .map(|b| self.type_ref(b))
                    .unwrap_or_default();
                if let Some(args) = named(n).into_iter().find(|c| c.kind() == "type_arguments") {
                    t.args = named(args).into_iter().map(|a| self.type_ref(a)).collect();
                }
                t
            }
            "scoped_type_identifier" => {
                let text = self.text(n);
                let (qualifier, name) = text.rsplit_once('.').unwrap_or(("", text));
                TypeRef {
                    name: name.trim().to_string(),
                    qualifier: qualifier.split_whitespace().collect(),
                    ..TypeRef::default()
                }
            }
            "array_type" => {
                let mut t = n
                    .child_by_field_name("element")
                    .map(|e| self.type_ref(e))
                    .unwrap_or_default();
                t.dims += n
                    .child_by_field_name("dimensions")
                    .map_or(1, |d| self.text(d).matches('[').count());
                t
            }
            "wildcard" => TypeRef {
                name: "?".into(),
                // `? extends T` keeps T; `? super T` is anything above T.
                args: named(n)
                    .into_iter()
                    .filter(|c| c.kind() != "annotation" && c.kind() != "marker_annotation")
                    .filter(|_| self.text(n).contains("extends"))
                    .map(|b| self.type_ref(b))
                    .collect(),
                ..TypeRef::default()
            },
            "annotated_type" => named(n)
                .into_iter()
                .rev()
                .find(|c| !matches!(c.kind(), "annotation" | "marker_annotation"))
                .map(|c| self.type_ref(c))
                .unwrap_or_default(),
            _ => TypeRef {
                name: self.text(n).to_string(),
                ..TypeRef::default()
            },
        }
    }

    fn modifiers(&self, decl: Node) -> (Vec<String>, Vec<String>) {
        let mut modifiers = Vec::new();
        let mut annotations = Vec::new();
        let Some(mods) = children(decl).into_iter().find(|c| c.kind() == "modifiers") else {
            return (modifiers, annotations);
        };
        for m in children(mods) {
            match m.kind() {
                "marker_annotation" | "annotation" => {
                    if let Some(name) = m.child_by_field_name("name") {
                        let t = self.text(name);
                        annotations.push(t.rsplit('.').next().unwrap_or(t).to_string());
                    }
                }
                _ if m.is_named() && m.kind().ends_with("comment") => {}
                _ => modifiers.push(self.text(m).to_string()),
            }
        }
        (modifiers, annotations)
    }

    fn type_params(&self, decl: Node) -> Vec<TypeParam> {
        let Some(tp) = decl.child_by_field_name("type_parameters") else {
            return Vec::new();
        };
        named(tp)
            .into_iter()
            .filter(|p| p.kind() == "type_parameter")
            .map(|p| {
                let parts = named(p);
                let name = parts
                    .iter()
                    .find(|c| c.kind() == "type_identifier" || c.kind() == "identifier")
                    .map(|c| self.text(*c).to_string())
                    .unwrap_or_default();
                let bounds = parts
                    .iter()
                    .filter(|c| c.kind() == "type_bound")
                    .flat_map(|b| named(*b))
                    .map(|t| self.type_ref(t))
                    .collect();
                TypeParam { name, bounds }
            })
            .collect()
    }

    fn type_list(&self, n: Option<Node>) -> Vec<TypeRef> {
        n.into_iter()
            .flat_map(named)
            .flat_map(|c| {
                if c.kind() == "type_list" {
                    named(c)
                } else {
                    vec![c]
                }
            })
            .map(|t| self.type_ref(t))
            .collect()
    }

    fn method(&self, m: Node) -> MethodDecl {
        let (modifiers, annotations) = self.modifiers(m);
        let name = m.child_by_field_name("name");
        let mut params = Vec::new();
        let mut names = Vec::new();
        let mut varargs = false;
        if let Some(ps) = m.child_by_field_name("parameters") {
            for p in named(ps) {
                match p.kind() {
                    "formal_parameter" => {
                        if let Some(t) = p.child_by_field_name("type") {
                            params.push(self.type_ref(t));
                        }
                        names.extend(p.child_by_field_name("name").map(|n| self.text(n)));
                    }
                    "spread_parameter" => {
                        varargs = true;
                        let ty = named(p).into_iter().find(|c| {
                            !matches!(
                                c.kind(),
                                "modifiers"
                                    | "variable_declarator"
                                    | "annotation"
                                    | "marker_annotation"
                            )
                        });
                        params.push(ty.map(|t| self.type_ref(t)).unwrap_or_default());
                        names.extend(
                            named(p)
                                .into_iter()
                                .find(|c| c.kind() == "variable_declarator")
                                .and_then(|d| d.child_by_field_name("name"))
                                .map(|n| self.text(n)),
                        );
                    }
                    _ => {}
                }
            }
        }
        let name_text = name.map(|n| self.text(n)).unwrap_or_default();
        MethodDecl {
            name: name_text.to_string(),
            params,
            varargs,
            constructor: m.kind() == "constructor_declaration",
            modifiers,
            annotations,
            only_calls_super: self.only_calls_super(m, name_text, &names),
            span: name.map(|n| self.span(n)).unwrap_or_default(),
            lines: (m.start_position().row + 1, m.end_position().row + 1),
        }
    }

    /// `return super.name(params);` or `super.name(params);`, alone.
    fn only_calls_super(&self, m: Node, name: &str, params: &[&str]) -> bool {
        let Some(body) = m.child_by_field_name("body") else {
            return false;
        };
        let statements: Vec<Node> = named(body)
            .into_iter()
            .filter(|s| !s.kind().ends_with("comment"))
            .collect();
        let [only] = statements.as_slice() else {
            return false;
        };
        let call = match only.kind() {
            "expression_statement" | "return_statement" => only.named_child(0),
            _ => None,
        };
        let Some(call) = call.filter(|c| c.kind() == "method_invocation") else {
            return false;
        };
        let args: Vec<&str> = call
            .child_by_field_name("arguments")
            .map(|a| {
                named(a)
                    .into_iter()
                    .filter(|x| !x.kind().ends_with("comment"))
                    .map(|x| self.text(x))
                    .collect()
            })
            .unwrap_or_default();
        call.child_by_field_name("object")
            .is_some_and(|o| o.kind() == "super")
            && call
                .child_by_field_name("name")
                .is_some_and(|n| self.text(n) == name)
            && args == params
    }

    fn fields(&self, f: Node) -> Vec<FieldDecl> {
        let (modifiers, _) = self.modifiers(f);
        let Some(ty) = f.child_by_field_name("type") else {
            return Vec::new();
        };
        let ty = self.type_ref(ty);
        named(f)
            .into_iter()
            .filter(|d| d.kind() == "variable_declarator")
            .filter_map(|d| d.child_by_field_name("name"))
            .map(|n| {
                let mut ty = ty.clone();
                // `int a[]`
                if let Some(dims) = n.parent().and_then(|d| d.child_by_field_name("dimensions")) {
                    ty.dims += self.text(dims).matches('[').count();
                }
                FieldDecl {
                    name: self.text(n).to_string(),
                    ty,
                    modifiers: modifiers.clone(),
                    span: self.span(n),
                }
            })
            .collect()
    }

    fn type_decl(&self, t: Node, outer: &[String]) -> TypeDecl {
        let (mut modifiers, _) = self.modifiers(t);
        let kind = match t.kind() {
            "class_declaration" => "class",
            "interface_declaration" => "interface",
            "enum_declaration" => "enum",
            "record_declaration" => "record",
            _ => "annotation",
        };
        // Members of an interface are public, and nested types static.
        if kind == "interface" || kind == "annotation" {
            modifiers.push("abstract".into());
        }
        let name = t.child_by_field_name("name");
        let (extends, implements) = match kind {
            "interface" => (
                self.type_list(
                    children(t)
                        .into_iter()
                        .find(|c| c.kind() == "extends_interfaces"),
                ),
                Vec::new(),
            ),
            _ => (
                t.child_by_field_name("superclass")
                    .and_then(|s| s.named_child(0))
                    .map(|s| vec![self.type_ref(s)])
                    .unwrap_or_default(),
                self.type_list(t.child_by_field_name("interfaces")),
            ),
        };
        let mut decl = TypeDecl {
            name: name.map(|n| self.text(n).to_string()).unwrap_or_default(),
            outer: outer.to_vec(),
            kind: kind.into(),
            modifiers,
            type_params: self.type_params(t),
            extends,
            implements,
            span: name.map(|n| self.span(n)).unwrap_or_default(),
            ..TypeDecl::default()
        };
        let in_interface = kind == "interface" || kind == "annotation";
        if let Some(body) = t.child_by_field_name("body") {
            let members = named(body).into_iter().flat_map(|m| {
                // An enum's members follow its constants.
                if m.kind() == "enum_body_declarations" {
                    named(m)
                } else {
                    vec![m]
                }
            });
            for m in members {
                match m.kind() {
                    "field_declaration" | "constant_declaration" => {
                        let mut fields = self.fields(m);
                        if in_interface {
                            for f in &mut fields {
                                f.modifiers
                                    .extend(["public", "static", "final"].map(String::from));
                            }
                        }
                        decl.fields.extend(fields);
                    }
                    "method_declaration"
                    | "constructor_declaration"
                    | "compact_constructor_declaration" => {
                        let mut method = self.method(m);
                        if in_interface && !method.modifiers.iter().any(|x| x == "private") {
                            method.modifiers.push("public".into());
                        }
                        decl.methods.push(method);
                    }
                    _ => {}
                }
            }
        }
        decl
    }

    fn site(&self, n: Node, within: &[String]) -> Option<Site> {
        let args = n.child_by_field_name("arguments")?;
        let args: Vec<Node> = named(args)
            .into_iter()
            .filter(|a| !a.kind().ends_with("comment"))
            .collect();
        let last = args.last()?;
        let literal = last.kind() == "array_creation_expression"
            && named(*last).iter().any(|c| c.kind() == "array_initializer");
        if !literal {
            return None;
        }
        let (callee, qualifier, constructor) = if n.kind() == "object_creation_expression" {
            // An anonymous class's `new` isn't a plain constructor call.
            if named(n).iter().any(|c| c.kind() == "class_body") {
                return None;
            }
            let t = self.type_ref(n.child_by_field_name("type")?);
            (t.name, t.qualifier, true)
        } else {
            (
                self.text(n.child_by_field_name("name")?).to_string(),
                n.child_by_field_name("object")
                    .map(|o| self.text(o).to_string())
                    .unwrap_or_default(),
                false,
            )
        };
        Some(Site {
            callee,
            qualifier,
            constructor,
            args: args.len(),
            within: within.to_vec(),
            span: self.span(*last),
        })
    }
}

fn named(n: Node) -> Vec<Node> {
    let mut c = n.walk();
    n.named_children(&mut c).collect()
}

fn children(n: Node) -> Vec<Node> {
    let mut c = n.walk();
    n.children(&mut c).collect()
}

const TYPE_DECLARATIONS: &[&str] = &[
    "class_declaration",
    "interface_declaration",
    "enum_declaration",
    "record_declaration",
    "annotation_type_declaration",
];

/// The summary of one file: its package, imports, the types it declares at
/// any depth, and the calls that pass an array literal last.
pub(crate) fn extract(root: Node, src: &[u8], deadline: Instant) -> FileIndex {
    let x = Extractor { src };
    let mut index = FileIndex::default();
    for child in named(root) {
        match child.kind() {
            "package_declaration" => {
                if let Some(name) = named(child)
                    .into_iter()
                    .find(|c| matches!(c.kind(), "scoped_identifier" | "identifier"))
                {
                    index.package = x.text(name).to_string();
                }
            }
            "import_declaration" => {
                let all = children(child);
                if all.iter().any(|c| c.kind() == "static") {
                    continue;
                }
                let Some(name) = all
                    .iter()
                    .find(|c| matches!(c.kind(), "scoped_identifier" | "identifier"))
                else {
                    continue;
                };
                let name = x.text(*name).to_string();
                if all.iter().any(|c| c.kind() == "asterisk") {
                    index.wildcards.push(name);
                } else {
                    index.imports.push(name);
                }
            }
            _ => {}
        }
    }
    // (node, the named types around it)
    let mut stack: Vec<(Node, Vec<String>)> = vec![(root, Vec::new())];
    let mut visited = 0usize;
    while let Some((n, outer)) = stack.pop() {
        visited += 1;
        if visited.is_multiple_of(4096) && Instant::now() > deadline {
            break;
        }
        let mut inner = outer.clone();
        if TYPE_DECLARATIONS.contains(&n.kind()) {
            let decl = x.type_decl(n, &outer);
            inner.push(decl.name.clone());
            index.types.push(decl);
        } else if matches!(n.kind(), "object_creation_expression" | "method_invocation")
            && let Some(site) = x.site(n, &outer)
        {
            index.sites.push(site);
        }
        let mut c = n.walk();
        let kids: Vec<Node> = n.named_children(&mut c).collect();
        stack.extend(kids.into_iter().rev().map(|k| (k, inner.clone())));
    }
    index
}

/// A type: (its file, its position in the file's types).
pub(crate) type TypeId = (usize, usize);

/// Every file's summary, with the types by full name.
pub(crate) struct ProjectIndex<'a> {
    files: Vec<&'a FileIndex>,
    by_name: HashMap<String, TypeId>,
}

impl<'a> ProjectIndex<'a> {
    pub(crate) fn new(files: Vec<&'a FileIndex>) -> Self {
        let mut by_name = HashMap::new();
        for (f, file) in files.iter().enumerate() {
            for (t, decl) in file.types.iter().enumerate() {
                by_name.entry(full_name(file, decl)).or_insert((f, t));
            }
        }
        Self { files, by_name }
    }

    pub(crate) fn files(&self) -> &[&'a FileIndex] {
        &self.files
    }

    pub(crate) fn decl(&self, id: TypeId) -> &'a TypeDecl {
        &self.files[id.0].types[id.1]
    }

    /// The type `name` refers to, written as `qualifier.name` in `file`
    /// inside the types `within` (outermost first).
    pub(crate) fn resolve(
        &self,
        file: usize,
        within: &[String],
        qualifier: &str,
        name: &str,
    ) -> Option<TypeId> {
        let f = self.files[file];
        let package = |p: &str, rest: &str| {
            if p.is_empty() {
                rest.to_string()
            } else {
                format!("{p}.{rest}")
            }
        };
        if !qualifier.is_empty() {
            // A full name, or a type nested in one this file sees.
            if let Some(id) = self.by_name.get(&format!("{qualifier}.{name}")) {
                return Some(*id);
            }
            let (head, rest) = qualifier.split_once('.').unwrap_or((qualifier, ""));
            let outer = self.resolve(file, within, "", head)?;
            let outer_name = full_name(self.files[outer.0], self.decl(outer));
            let nested = [outer_name.as_str(), rest, name]
                .iter()
                .filter(|s| !s.is_empty())
                .copied()
                .collect::<Vec<_>>()
                .join(".");
            return self.by_name.get(&nested).copied();
        }
        // Nested in the types around the use, innermost first, then the
        // file's top-level types.
        for k in (0..=within.len()).rev() {
            let mut path = within[..k].to_vec();
            path.push(name.to_string());
            if let Some(id) = self.by_name.get(&package(&f.package, &path.join("."))) {
                return Some(*id);
            }
        }
        // Nested in a supertype of the enclosing type.
        if let Some(enclosing) = (!within.is_empty())
            .then(|| self.by_name.get(&package(&f.package, &within.join("."))))
            .flatten()
        {
            for sup in self.supertypes(*enclosing) {
                let nested = format!("{}.{name}", full_name(self.files[sup.0], self.decl(sup)));
                if let Some(id) = self.by_name.get(&nested) {
                    return Some(*id);
                }
            }
        }
        if let Some(import) = f
            .imports
            .iter()
            .find(|i| i.rsplit('.').next() == Some(name))
        {
            return self.by_name.get(import).copied();
        }
        if let Some(id) = self.by_name.get(&package(&f.package, name)) {
            return Some(*id);
        }
        let mut found = f
            .wildcards
            .iter()
            .filter_map(|w| self.by_name.get(&format!("{w}.{name}")));
        match (found.next(), found.next()) {
            (Some(id), None) => Some(*id),
            _ => None,
        }
    }

    /// Resolves a type written in the declaration of `id`.
    pub(crate) fn resolve_in(&self, id: TypeId, ty: &TypeRef) -> Option<TypeId> {
        let decl = self.decl(id);
        let mut within = decl.outer.clone();
        within.push(decl.name.clone());
        self.resolve(id.0, &within, &ty.qualifier, &ty.name)
    }

    /// The direct supertypes of `id` the project declares.
    pub(crate) fn supertypes(&self, id: TypeId) -> Vec<TypeId> {
        let decl = self.decl(id);
        // A supertype is resolved from where the type is declared, not
        // from inside it.
        decl.extends
            .iter()
            .chain(&decl.implements)
            .filter_map(|t| self.resolve(id.0, &decl.outer, &t.qualifier, &t.name))
            .filter(|s| *s != id)
            .collect()
    }

    /// The superclass of a class, when the project declares it.
    pub(crate) fn superclass(&self, id: TypeId) -> Option<TypeId> {
        let decl = self.decl(id);
        if decl.kind != "class" {
            return None;
        }
        let t = decl.extends.first()?;
        self.resolve(id.0, &decl.outer, &t.qualifier, &t.name)
            .filter(|s| *s != id && self.decl(*s).kind == "class")
    }
}

/// `package.Outer.Name`.
pub(crate) fn full_name(file: &FileIndex, decl: &TypeDecl) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if !file.package.is_empty() {
        parts.push(&file.package);
    }
    parts.extend(decl.outer.iter().map(String::as_str));
    parts.push(&decl.name);
    parts.join(".")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index(src: &str) -> FileIndex {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(src, None).unwrap();
        extract(
            tree.root_node(),
            src.as_bytes(),
            Instant::now() + std::time::Duration::from_secs(10),
        )
    }

    #[test]
    fn summarizes_types_members_and_sites() {
        let x = index(
            "package p;\nimport java.util.List;\nimport q.*;\npublic class A<T extends java.io.Serializable> extends B implements C, D<T> {\nprivate transient List<? extends T> items;\nint a[];\n@Override\npublic String f(int x) { return super.f(x); }\nA(String... xs) {}\nvoid g() { new A(new String[] {\"a\"}); }\nstatic class N {}\ninterface I { int K = 1; void h(); }\n}",
        );
        assert_eq!(x.package, "p");
        assert_eq!(x.imports, ["java.util.List"]);
        assert_eq!(x.wildcards, ["q"]);
        let a = &x.types[0];
        assert_eq!((a.name.as_str(), a.kind.as_str()), ("A", "class"));
        assert_eq!(a.type_params[0].bounds[0].qualifier, "java.io");
        assert_eq!(a.extends[0].name, "B");
        assert_eq!(a.implements.len(), 2);
        let items = &a.fields[0];
        assert_eq!(items.ty.name, "List");
        assert_eq!(items.ty.args[0].name, "?");
        assert_eq!(items.ty.args[0].args[0].name, "T");
        assert!(items.modifiers.contains(&"transient".to_string()));
        assert_eq!(a.fields[1].ty.dims, 1);
        let f = &a.methods[0];
        assert!(f.only_calls_super);
        assert_eq!(f.annotations, ["Override"]);
        assert_eq!(f.span.line, 8);
        assert_eq!(f.lines, (7, 8));
        assert!(a.methods[1].constructor && a.methods[1].varargs);
        assert_eq!(x.types[1].outer, ["A"]);
        let i = &x.types[2];
        assert_eq!(i.kind, "interface");
        assert!(i.fields[0].modifiers.contains(&"static".to_string()));
        assert!(i.methods[0].modifiers.contains(&"public".to_string()));
        assert_eq!(x.sites.len(), 1);
        assert!(x.sites[0].constructor);
        assert_eq!(x.sites[0].within, ["A"]);
    }

    #[test]
    fn resolves_names_as_java_does() {
        let a = index(
            "package p;\nimport q.Other;\nimport r.*;\nclass A extends Base { Inner i; class Inner {} }",
        );
        let base = index("package p;\nclass Base { static class Deep {} }");
        let other = index("package q;\npublic class Other {}");
        let wild = index("package r;\npublic class Wild {}");
        let decoy = index("package s;\npublic class Other {}");
        let files = vec![&a, &base, &other, &wild, &decoy];
        let ix = ProjectIndex::new(files);
        let within = vec!["A".to_string()];
        assert_eq!(ix.resolve(0, &within, "", "Inner"), Some((0, 1)));
        assert_eq!(ix.resolve(0, &within, "", "Base"), Some((1, 0)));
        assert_eq!(ix.resolve(0, &within, "", "Deep"), Some((1, 1)));
        assert_eq!(ix.resolve(0, &within, "", "Other"), Some((2, 0)));
        assert_eq!(ix.resolve(0, &within, "", "Wild"), Some((3, 0)));
        assert_eq!(ix.resolve(0, &within, "s", "Other"), Some((4, 0)));
        assert_eq!(ix.resolve(0, &within, "Base", "Deep"), Some((1, 1)));
        assert_eq!(ix.resolve(0, &within, "", "List"), None);
        assert_eq!(ix.superclass((0, 0)), Some((1, 0)));
    }
}
