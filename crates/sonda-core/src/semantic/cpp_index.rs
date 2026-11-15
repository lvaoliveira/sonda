//! A project-wide index of C++ class declarations (ADR-0020, extended to
//! C++), for rules that compare a class with its bases in other files: a
//! member function hiding a base's function of the same name.
//!
//! Each worker summarizes the classes its file defines (`extract`): their
//! namespaces and enclosing classes, bases, member functions and fields,
//! with positions. The summary crosses the worker boundary as a fact, so no
//! syntax tree leaves the sandbox. The scanner indexes every file's summary
//! (`ProjectIndex`) and resolves a base by its simple name, as close to the
//! derived class's namespace as it can; a name it can't settle, or one
//! from outside the project (Qt's, the standard library's), resolves to
//! nothing.
//!
//! What the build compiles isn't known: every `#if` branch is read, and a
//! macro is taken as written.

use super::cs_index::Span;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;
use tree_sitter::Node;

/// The fact that carries a file's summary.
pub(crate) const FACT: &str = "cpp-index";

/// A member function declared or defined in a class.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub(crate) struct MethodDecl {
    pub(crate) name: String,
    /// Its parameters' types as written, whitespace removed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) params: Vec<String>,
    /// Declared `virtual`, or `override` or `final`, which only a virtual
    /// function can be.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) virtual_: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) static_: bool,
    /// Under `private:`, or before any access specifier in a `class`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) private_: bool,
    /// The name, where issues about it are reported.
    pub(crate) span: Span,
}

/// A data member.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub(crate) struct FieldDecl {
    pub(crate) name: String,
    /// Its type as written, whitespace removed.
    pub(crate) ty: String,
}

/// A class or struct with a body.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub(crate) struct ClassDecl {
    pub(crate) name: String,
    /// The namespaces and classes it's in, outermost first; an unnamed
    /// namespace is empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) scope: Vec<String>,
    /// Its bases as written, without template arguments: `ns::Base`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) bases: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) methods: Vec<MethodDecl>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) fields: Vec<FieldDecl>,
    /// Names a `using Base::name;` brings in from a base.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) using: Vec<String>,
    /// The name.
    pub(crate) span: Span,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub(crate) struct FileIndex {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) classes: Vec<ClassDecl>,
}

/// How many classes a file may summarize: a generated file declaring more
/// isn't worth the size of its summary.
const MAX_CLASSES: usize = 2_000;

struct Extractor<'s> {
    src: &'s [u8],
    deadline: Instant,
    classes: Vec<ClassDecl>,
}

/// The classes a C++ file defines.
pub(crate) fn extract(root: Node, src: &[u8], deadline: Instant) -> FileIndex {
    let mut x = Extractor {
        src,
        deadline,
        classes: Vec::new(),
    };
    x.walk(root, &mut Vec::new());
    FileIndex { classes: x.classes }
}

impl<'s> Extractor<'s> {
    fn text(&self, n: Node) -> &'s str {
        std::str::from_utf8(&self.src[n.byte_range()]).unwrap_or_default()
    }

    /// The text without whitespace: `constBox&` for `const Box &`, enough to
    /// tell two parameter lists apart.
    fn compact(&self, n: Node) -> String {
        self.text(n).split_whitespace().collect()
    }

    fn span(&self, n: Node) -> Span {
        Span {
            line: n.start_position().row + 1,
            column: n.start_position().column + 1,
            end_line: n.end_position().row + 1,
            end_column: n.end_position().column + 1,
        }
    }

    /// Walks declarations, keeping the namespaces and classes around them;
    /// a class defined in a function body counts in the function's
    /// namespace.
    fn walk(&mut self, n: Node, scope: &mut Vec<String>) {
        if Instant::now() > self.deadline || self.classes.len() >= MAX_CLASSES {
            return;
        }
        match n.kind() {
            "namespace_definition" => {
                let names: Vec<String> = n
                    .child_by_field_name("name")
                    .map(|name| {
                        self.text(name)
                            .split("::")
                            .map(|s| s.trim().to_string())
                            .collect()
                    })
                    .unwrap_or_else(|| vec![String::new()]);
                let depth = scope.len();
                scope.extend(names);
                if let Some(body) = n.child_by_field_name("body") {
                    for c in named(body) {
                        self.walk(c, scope);
                    }
                }
                scope.truncate(depth);
            }
            "class_specifier" | "struct_specifier" => self.class(n, scope),
            _ => {
                for c in named(n) {
                    self.walk(c, scope);
                }
            }
        }
    }

    fn class(&mut self, n: Node, scope: &mut Vec<String>) {
        let (Some(name), Some(body)) =
            (n.child_by_field_name("name"), n.child_by_field_name("body"))
        else {
            // A declaration, or an anonymous struct: nothing to compare.
            if let Some(body) = n.child_by_field_name("body") {
                for c in named(body) {
                    self.walk(c, scope);
                }
            }
            return;
        };
        let simple = match name.kind() {
            // A specialization, `template <> class A<int>`, is A.
            "template_type" => name.child_by_field_name("name").unwrap_or(name),
            "qualified_identifier" => name.child_by_field_name("name").unwrap_or(name),
            _ => name,
        };
        let mut class = ClassDecl {
            name: self.text(simple).to_string(),
            scope: scope.clone(),
            span: self.span(simple),
            ..ClassDecl::default()
        };
        if let Some(clause) = named(n)
            .into_iter()
            .find(|c| c.kind() == "base_class_clause")
        {
            for base in named(clause) {
                if matches!(
                    base.kind(),
                    "type_identifier" | "qualified_identifier" | "template_type"
                ) {
                    class
                        .bases
                        .push(without_template_arguments(&self.compact(base)));
                }
            }
        }
        let position = self.classes.len();
        self.classes.push(ClassDecl::default());
        scope.push(class.name.clone());
        let mut private = n.kind() == "class_specifier";
        for member in named(body) {
            if member.kind() == "access_specifier" {
                private = self.text(member).trim() == "private";
                continue;
            }
            let before = class.methods.len();
            self.member(member, &mut class, scope);
            for m in &mut class.methods[before..] {
                m.private_ = private;
            }
        }
        scope.pop();
        self.classes[position] = class;
    }

    fn member(&mut self, member: Node, class: &mut ClassDecl, scope: &mut Vec<String>) {
        match member.kind() {
            "template_declaration" => {
                for c in named(member) {
                    self.member(c, class, scope);
                }
            }
            "using_declaration" => {
                if let Some(q) = named(member)
                    .into_iter()
                    .find(|c| c.kind() == "qualified_identifier")
                {
                    let t = self.compact(q);
                    class
                        .using
                        .push(t.rsplit("::").next().unwrap_or(&t).to_string());
                }
            }
            "function_definition" | "field_declaration" | "declaration" => {
                self.declaration_member(member, class, scope);
            }
            _ => {}
        }
    }

    /// A member function or data member, and any class it defines: in a
    /// member function's body, or as a member's type (`struct In {} x;`).
    fn declaration_member(&mut self, member: Node, class: &mut ClassDecl, scope: &mut Vec<String>) {
        if member.kind() == "function_definition"
            && let Some(body) = member.child_by_field_name("body")
        {
            self.walk(body, scope);
        }
        if let Some(ty) = member.child_by_field_name("type")
            && matches!(ty.kind(), "class_specifier" | "struct_specifier")
        {
            self.class(ty, scope);
        }
        let declarators: Vec<Node> = {
            let mut c = member.walk();
            member
                .children_by_field_name("declarator", &mut c)
                .collect()
        };
        for d in declarators {
            self.declarator(member, d, class);
        }
    }

    /// What one of a member's declarators declares: a member function, or
    /// a data member.
    fn declarator(&self, member: Node, d: Node, class: &mut ClassDecl) {
        if let Some(f) = function_declarator(d) {
            class.methods.extend(self.method(member, f));
            return;
        }
        if member.kind() == "field_declaration"
            && let Some(name) = declared_name(d)
            && let Some(ty) = member.child_by_field_name("type")
        {
            class.fields.push(FieldDecl {
                name: self.text(name).to_string(),
                ty: self.compact(ty) + &pointer_suffix(self, d),
            });
        }
    }

    fn method(&self, member: Node, f: Node) -> Option<MethodDecl> {
        let name = f.child_by_field_name("declarator")?;
        // Only plain names: not `operator=`, a destructor or a qualified
        // name.
        if !matches!(name.kind(), "field_identifier" | "identifier") {
            return None;
        }
        let words = |n: Node| -> Vec<&str> {
            let mut c = n.walk();
            n.children(&mut c).map(|w| self.text(w)).collect()
        };
        let specifiers = words(f);
        let own = words(member);
        let params = f
            .child_by_field_name("parameters")
            .map(|list| {
                named(list)
                    .into_iter()
                    .filter(|p| {
                        matches!(
                            p.kind(),
                            "parameter_declaration" | "optional_parameter_declaration"
                        )
                    })
                    .map(|p| match p.child_by_field_name("declarator") {
                        // Everything before the declarator, `const` included,
                        // then what the declarator adds.
                        Some(d) => {
                            let before = &self.src[p.start_byte()..d.start_byte()];
                            let ty: String = unqualified(&String::from_utf8_lossy(before))
                                .split_whitespace()
                                .collect();
                            ty + &pointer_suffix(self, d)
                        }
                        None => unqualified(self.text(p)).split_whitespace().collect(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        Some(MethodDecl {
            name: self.text(name).to_string(),
            params,
            virtual_: own.contains(&"virtual")
                || specifiers
                    .iter()
                    .any(|w| matches!(*w, "override" | "final")),
            static_: own.contains(&"static"),
            private_: false,
            span: self.span(name),
        })
    }
}

fn named(n: Node) -> Vec<Node> {
    let mut c = n.walk();
    n.named_children(&mut c).collect()
}

/// The function declarator under a member's declarator, through `*` and `&`.
fn function_declarator(d: Node) -> Option<Node> {
    let mut d = d;
    for _ in 0..8 {
        match d.kind() {
            "function_declarator" => return Some(d),
            "pointer_declarator" | "reference_declarator" => {
                d = d
                    .child_by_field_name("declarator")
                    .or_else(|| named(d).last().copied())?;
            }
            _ => return None,
        }
    }
    None
}

/// The name a field's declarator declares, through `*`, `&` and `[]`.
fn declared_name(d: Node) -> Option<Node> {
    let mut d = d;
    for _ in 0..8 {
        match d.kind() {
            "field_identifier" | "identifier" => return Some(d),
            "pointer_declarator"
            | "reference_declarator"
            | "array_declarator"
            | "init_declarator"
            | "bitfield_clause" => {
                d = d
                    .child_by_field_name("declarator")
                    .or_else(|| named(d).first().copied())?;
            }
            _ => return None,
        }
    }
    None
}

/// The `*`, `&` and `[]` a declarator adds to its type.
fn pointer_suffix(x: &Extractor, d: Node) -> String {
    let mut suffix = String::new();
    let mut d = d;
    for _ in 0..8 {
        match d.kind() {
            "pointer_declarator" => suffix.push('*'),
            "reference_declarator" => suffix.push_str(if x.text(d).starts_with("&&") {
                "&&"
            } else {
                "&"
            }),
            "array_declarator" => suffix.push_str("[]"),
            "abstract_pointer_declarator" => suffix.push('*'),
            "abstract_reference_declarator" => suffix.push('&'),
            _ => break,
        }
        match d
            .child_by_field_name("declarator")
            .or_else(|| named(d).last().copied())
        {
            Some(next) if next.id() != d.id() => d = next,
            _ => break,
        }
    }
    suffix
}

/// `const Box&` for `const roo::Box&`: a parameter's type written with or
/// without its namespace is the same type.
fn unqualified(ty: &str) -> String {
    let mut out = String::new();
    let mut rest = ty;
    while let Some(i) = rest.find("::") {
        // Drop the identifier right before `::`, and spaces around it.
        let head = rest[..i].trim_end();
        let keep = head.trim_end_matches(|c: char| c.is_alphanumeric() || c == '_');
        out.push_str(keep);
        rest = rest[i + 2..].trim_start();
    }
    out.push_str(rest);
    out
}

/// `ns::Base` for `ns::Base<T>`.
fn without_template_arguments(name: &str) -> String {
    let mut out = String::new();
    let mut depth = 0;
    for c in name.chars() {
        match c {
            '<' => depth += 1,
            '>' => depth -= 1,
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

/// A class in the index: the file's position, then the class's.
pub(crate) type ClassId = (usize, usize);

/// Every file's classes, by simple name.
pub(crate) struct ProjectIndex<'a> {
    files: Vec<&'a FileIndex>,
    by_name: HashMap<&'a str, Vec<ClassId>>,
}

impl<'a> ProjectIndex<'a> {
    pub(crate) fn new(files: Vec<&'a FileIndex>) -> Self {
        let mut by_name: HashMap<&str, Vec<ClassId>> = HashMap::new();
        for (f, file) in files.iter().enumerate() {
            for (c, class) in file.classes.iter().enumerate() {
                by_name.entry(class.name.as_str()).or_default().push((f, c));
            }
        }
        Self { files, by_name }
    }

    pub(crate) fn files(&self) -> &[&'a FileIndex] {
        &self.files
    }

    pub(crate) fn class(&self, id: ClassId) -> &'a ClassDecl {
        &self.files[id.0].classes[id.1]
    }

    /// The class a base written as `name` (`ns::Base` or `Base`) in `from`
    /// is: the candidates whose scope ends with the name's qualifier, then
    /// the ones whose scope is shared with `from`, closest first; nothing
    /// when that leaves more than one.
    pub(crate) fn resolve(&self, from: ClassId, name: &str) -> Option<ClassId> {
        let (qualifier, simple) = name.rsplit_once("::").unwrap_or(("", name));
        let qualifier: Vec<&str> = qualifier.split("::").filter(|s| !s.is_empty()).collect();
        let candidates: Vec<ClassId> = self
            .by_name
            .get(simple)?
            .iter()
            .copied()
            .filter(|id| *id != from)
            .filter(|id| {
                let scope = &self.class(*id).scope;
                scope.len() >= qualifier.len()
                    && scope[scope.len() - qualifier.len()..]
                        .iter()
                        .zip(&qualifier)
                        .all(|(a, b)| a == b)
            })
            .collect();
        if candidates.len() <= 1 {
            return candidates.first().copied();
        }
        // The ones sharing the longest stretch of `from`'s scope.
        let own = &self.class(from).scope;
        let shared = |id: &ClassId| {
            self.class(*id)
                .scope
                .iter()
                .zip(own)
                .take_while(|(a, b)| a == b)
                .count()
        };
        let best = candidates.iter().map(shared).max()?;
        let closest: Vec<ClassId> = candidates
            .into_iter()
            .filter(|id| shared(id) == best)
            .collect();
        // The same class in two files (a header copied into a test): the
        // first.
        let first = closest[0];
        closest
            .iter()
            .all(|id| self.class(*id).scope == self.class(first).scope)
            .then_some(first)
    }

    /// The classes `id` derives from, nearest first, each once.
    pub(crate) fn ancestors(&self, id: ClassId) -> Vec<ClassId> {
        let mut out: Vec<ClassId> = Vec::new();
        let mut queue = vec![id];
        while let Some(c) = queue.pop() {
            for base in &self.class(c).bases {
                if let Some(b) = self.resolve(c, base)
                    && b != id
                    && !out.contains(&b)
                    && out.len() < 64
                {
                    out.push(b);
                    queue.insert(0, b);
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index(src: &str) -> FileIndex {
        let mut p = tree_sitter::Parser::new();
        p.set_language(&tree_sitter_cpp::LANGUAGE.into()).unwrap();
        let tree = p.parse(src, None).unwrap();
        let far = Instant::now() + std::time::Duration::from_secs(60);
        extract(tree.root_node(), src.as_bytes(), far)
    }

    #[test]
    fn summarizes_classes_bases_members() {
        let f = index(
            "namespace a::b {\ntemplate <typename T>\nclass D : public Base, private ns::Other<T> {\n public:\n  using Base::f;\n  virtual void f(int x) const = 0;\n  void g(const Box &b, int* p) override {}\n  static int h();\n  uint8_t q_, *r_;\n  struct In { int z; };\n};\n}\nvoid free() { struct Local {}; }",
        );
        assert_eq!(f.classes.len(), 3);
        assert_eq!(f.classes[2].name, "Local");
        let d = &f.classes[0];
        assert_eq!(
            (d.name.as_str(), d.scope.clone()),
            ("D", vec!["a".to_string(), "b".to_string()])
        );
        assert_eq!(d.bases, ["Base", "ns::Other"]);
        assert_eq!(d.using, ["f"]);
        let names: Vec<_> = d
            .methods
            .iter()
            .map(|m| (m.name.as_str(), m.virtual_, m.static_))
            .collect();
        assert_eq!(
            names,
            [("f", true, false), ("g", true, false), ("h", false, true)]
        );
        assert_eq!(d.methods[1].params, ["constBox&", "int*"]);
        let q = index("struct A { void f(const ns::Box& b, roo::Color* c); };");
        assert_eq!(q.classes[0].methods[0].params, ["constBox&", "Color*"]);
        let fields: Vec<_> = d
            .fields
            .iter()
            .map(|f| (f.name.as_str(), f.ty.as_str()))
            .collect();
        assert_eq!(fields, [("q_", "uint8_t"), ("r_", "uint8_t*")]);
        assert_eq!(f.classes[1].scope, ["a", "b", "D"]);
        assert_eq!(f.classes[1].name, "In");
    }

    #[test]
    fn resolves_bases_by_namespace() {
        let a = index(
            "namespace x { class Base { void f(); }; }\nnamespace y { class Base { void g(); }; }",
        );
        let b = index(
            "namespace x { class D : public Base {}; }\nclass E : public y::Base {};\nclass F : public Base {};",
        );
        let index = ProjectIndex::new(vec![&a, &b]);
        assert_eq!(index.resolve((1, 0), "Base"), Some((0, 0)));
        assert_eq!(index.resolve((1, 1), "y::Base"), Some((0, 1)));
        // Two equally close candidates: nothing.
        assert_eq!(index.resolve((1, 2), "Base"), None);
        assert_eq!(index.ancestors((1, 0)), [(0, 0)]);
    }
}
