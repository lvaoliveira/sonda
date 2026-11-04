//! Unnecessary using directives (ADR-0022, step 3): what each name a file
//! writes may come from, so that a directive nothing comes through can be
//! told apart from one an unresolved name may need.
//!
//! Packages add types and extension methods to the platform's namespaces
//! too (`System.Drawing.Bitmap`, `System.Linq.AsyncEnumerable`), so a
//! namespace isn't known to be unused from what it declares alone: a
//! directive is unnecessary only when every name that could come from a
//! namespace resolves, and none through it.

use super::{IMPLICIT_USINGS, Infer, Ty};
use crate::semantic::dotnet::Declared;
use std::collections::HashSet;
use tree_sitter::Node;

/// What a name the file writes may come from.
enum Source {
    /// A declaration, an enclosing namespace, the SDK's implicit usings:
    /// no using directive of the file.
    Elsewhere,
    /// The namespaces of these using directives.
    Through(Vec<String>),
    /// It doesn't resolve: any directive may be what brings it.
    Unknown,
}

/// The methods a query expression calls by name.
const QUERY_METHODS: &[&str] = &[
    "Select",
    "SelectMany",
    "Where",
    "Join",
    "GroupJoin",
    "OrderBy",
    "OrderByDescending",
    "ThenBy",
    "ThenByDescending",
    "GroupBy",
    "Cast",
];

/// Contextual keywords written as identifiers.
const KEYWORDS: &[&str] = &[
    "var",
    "dynamic",
    "nameof",
    "value",
    "_",
    "global",
    "unmanaged",
    "notnull",
    "managed",
    "nint",
    "nuint",
    "record",
    "async",
    "await",
    "args",
];

/// A using directive's kind.
enum Directive<'t> {
    Namespace(String),
    Alias(String),
    Static(Node<'t>),
}

/// A file's using directives, the names it mentions, and where the names
/// it resolves come from.
type UsingFacts<'m, 't> = (
    Vec<(Node<'t>, Directive<'t>)>,
    HashSet<&'m str>,
    Vec<Source>,
);

impl<'m, 't> Infer<'m, 't> {
    /// The file's using directives that import nothing it uses: a
    /// namespace no name comes through, while every other name resolves; a
    /// repeated one, or one for a namespace its code is already in; an alias
    /// never written; `using static` of a platform type none of whose
    /// members or nested types is named. Global usings are left alone, as
    /// documented, and so are directives inside `#if`.
    pub(crate) fn unnecessary_usings(&self) -> Vec<Node<'t>> {
        let Some(root) = self.m.root else {
            return Vec::new();
        };
        let (mut directives, names, sources) = self.using_facts(root);
        if directives.is_empty() {
            return Vec::new();
        }
        // The first of two repeated directives is the one that counts.
        directives.sort_by_key(|(n, _)| n.start_byte());
        let mut out = self.unnecessary_directives(directives, &names, &sources);
        out.sort_by_key(|n| n.start_byte());
        out
    }

    /// The file's using directives, the names it mentions, and where each
    /// name it resolves comes from.
    fn using_facts(&self, root: Node<'t>) -> UsingFacts<'m, 't> {
        let mut directives: Vec<(Node<'t>, Directive<'t>)> = Vec::new();
        let mut names: HashSet<&'m str> = HashSet::new();
        let mut sources: Vec<Source> = Vec::new();
        let mut stack = vec![root];
        while let Some(n) = stack.pop() {
            match n.kind() {
                "using_directive" => {
                    if let Some(d) = self.directive(n) {
                        directives.push((n, d));
                    }
                    continue;
                }
                "comment" => {
                    for cref in crefs(self.text(n)) {
                        names.insert(cref);
                        sources.push(self.type_source(cref, n.start_byte(), None));
                    }
                }
                "identifier" => {
                    names.insert(self.text(n));
                    if let Some(source) = self.source(n) {
                        sources.push(source);
                    }
                }
                "query_expression" => sources.push(self.extension_source(QUERY_METHODS)),
                _ => {}
            }
            stack.extend(n.children(&mut n.walk()));
        }
        (directives, names, sources)
    }

    /// The directives, in source order, that the file doesn't need: a
    /// repeated one, one for the namespace it's in, one nothing resolves
    /// through, an unused alias, an unused `using static`.
    fn unnecessary_directives(
        &self,
        directives: Vec<(Node<'t>, Directive<'t>)>,
        names: &HashSet<&'m str>,
        sources: &[Source],
    ) -> Vec<Node<'t>> {
        let unknown = sources.iter().any(|s| matches!(s, Source::Unknown));
        let through = |ns: &str| {
            sources
                .iter()
                .any(|s| matches!(s, Source::Through(v) if v.iter().any(|x| x == ns)))
        };
        let mut seen: Vec<(usize, String)> = Vec::new();
        let mut out = Vec::new();
        for (node, d) in directives {
            let scope = node.parent().map_or(0, |p| p.id());
            let unnecessary = match &d {
                Directive::Namespace(ns) => {
                    let repeated = seen.contains(&(scope, ns.clone()));
                    seen.push((scope, ns.clone()));
                    repeated || self.already_in(node, ns) || (!unknown && !through(ns))
                }
                Directive::Alias(alias) => !names.contains(alias.as_str()),
                Directive::Static(ty) => self.static_unused(*ty, names),
            };
            if unnecessary {
                out.push(node);
            }
        }
        out
    }

    /// A directive this checks: not global, not inside `#if`.
    fn directive(&self, n: Node<'t>) -> Option<Directive<'t>> {
        let tokens: Vec<&str> = n.children(&mut n.walk()).map(|c| c.kind()).collect();
        if tokens.contains(&"global") || n.parent()?.kind().starts_with("preproc") {
            return None;
        }
        if let Some(alias) = n.child_by_field_name("name") {
            return Some(Directive::Alias(self.text(alias).to_string()));
        }
        let target = n.named_child(n.named_child_count().checked_sub(1)? as u32)?;
        if tokens.contains(&"static") {
            return Some(Directive::Static(target));
        }
        let ns: String = self.text(target).split_whitespace().collect();
        Some(Directive::Namespace(ns))
    }

    /// Whether all the code a directive applies to is in its namespace or
    /// one inside it, so already sees what it declares.
    fn already_in(&self, directive: Node, ns: &str) -> bool {
        let Some(parent) = directive.parent() else {
            return false;
        };
        let covered = if parent.kind() == "compilation_unit" {
            self.unit_namespaces(parent)
        } else {
            self.enclosing_namespace(parent).map(|n| vec![n])
        };
        covered.is_some_and(|covered| {
            !covered.is_empty()
                && covered
                    .iter()
                    .all(|c| c == ns || c.starts_with(&format!("{ns}.")))
        })
    }

    /// The namespaces a file declares at its top level; None when it has
    /// code outside any namespace.
    fn unit_namespaces(&self, unit: Node) -> Option<Vec<String>> {
        let mut covered = Vec::new();
        for c in unit.named_children(&mut unit.walk()) {
            match c.kind() {
                "using_directive" | "comment" | "extern_alias_directive" | "attribute_list" => {}
                k if k.starts_with("preproc") => {}
                "namespace_declaration" | "file_scoped_namespace_declaration" => {
                    covered.push(self.namespace_name(c));
                }
                _ => return None,
            }
        }
        Some(covered)
    }

    /// The name of the namespace declaration around `n`, if any.
    fn enclosing_namespace(&self, mut n: Node) -> Option<String> {
        loop {
            if n.kind() == "namespace_declaration" {
                return Some(self.namespace_name(n));
            }
            n = n.parent()?;
        }
    }

    /// A namespace declaration's full name, with those it's nested in.
    fn namespace_name(&self, decl: Node) -> String {
        let mut parts = Vec::new();
        let mut n = Some(decl);
        while let Some(d) = n {
            if matches!(
                d.kind(),
                "namespace_declaration" | "file_scoped_namespace_declaration"
            ) && let Some(name) = d.child_by_field_name("name")
            {
                parts.push(self.text(name).split_whitespace().collect::<String>());
            }
            n = d.parent();
        }
        parts.reverse();
        parts.join(".")
    }

    /// Whether `using static` of a platform type names nothing it imports:
    /// the static members and nested types it declares itself.
    fn static_unused(&self, ty: Node, names: &HashSet<&str>) -> bool {
        let Some(key) = self.written(ty).and_then(|t| t.key().map(str::to_string)) else {
            return false;
        };
        let Some(declared) = self.platform.get(&key) else {
            return false;
        };
        let members = declared
            .members
            .iter()
            .filter(|m| m.has("static") || m.has("const"))
            .map(|m| m.name.as_str());
        let nested = self
            .platform
            .declared_in(&key)
            .into_iter()
            .flat_map(|d| d.types.iter().map(String::as_str));
        !members.chain(nested).any(|n| names.contains(n))
    }

    /// What an identifier may come from, when it could name something a
    /// using directive imports: a type, or an extension method called on a
    /// receiver.
    fn source(&self, id: Node) -> Option<Source> {
        // `List<int>`: the generic name stands where the identifier would.
        let at = match id.parent() {
            Some(g) if g.kind() == "generic_name" => g,
            _ => id,
        };
        let parent = at.parent()?;
        let field = field_of(parent, at);
        let name = self.text(id);
        let type_source = || Some(self.type_source(name, id.start_byte(), Some(id)));
        match (parent.kind(), field) {
            ("member_access_expression", Some("expression")) => type_source(),
            ("member_access_expression", Some("name")) => {
                let receiver = parent.child_by_field_name("expression")?;
                let outer = parent.parent()?;
                if outer.kind() == "invocation_expression"
                    && outer.child_by_field_name("function").map(|f| f.id()) == Some(parent.id())
                {
                    Some(self.call_source(outer, receiver, name))
                } else if outer.kind() == "argument" {
                    // A method group, maybe an extension method's.
                    Some(self.method_group_source(receiver, name))
                } else {
                    None
                }
            }
            ("member_binding_expression", Some("name")) => {
                let access = parent.parent()?;
                let call = access.parent()?;
                (call.kind() == "invocation_expression").then(|| {
                    let receiver = access.child_by_field_name("condition");
                    match receiver {
                        Some(r) => self.call_source(call, r, name),
                        None => Source::Unknown,
                    }
                })
            }
            ("qualified_name", Some("qualifier")) => type_source(),
            ("attribute", Some("name")) => type_source(),
            (_, Some("type" | "returns")) => type_source(),
            (
                "base_list"
                | "type_argument_list"
                | "constant_pattern"
                | "array_type"
                | "nullable_type"
                | "pointer_type"
                | "ref_type"
                | "tuple_element"
                | "primary_constructor_base_type"
                | "explicit_interface_specifier"
                | "type_parameter_constraint",
                _,
            ) => type_source(),
            ("as_expression" | "is_expression", Some("right")) => type_source(),
            ("argument", _) => {
                // `nameof(Type)`
                let call = parent.parent()?.parent()?;
                let function = call.child_by_field_name("function")?;
                (call.kind() == "invocation_expression" && self.text(function) == "nameof")
                    .then(type_source)
                    .flatten()
            }
            _ => None,
        }
    }

    /// What a name in a type's place may come from.
    fn type_source(&self, name: &str, byte: usize, id: Option<Node>) -> Source {
        if KEYWORDS.contains(&name) || self.type_params.contains(name) {
            return Source::Elsewhere;
        }
        let enclosing = self.enclosing_namespaces(byte);
        let prefix = format!("{name}`");
        if let Some(local) = self
            .locals
            .iter()
            .find(|(k, _)| k.starts_with(&prefix))
            .and_then(|(_, l)| *l)
        {
            // Seen from where it's declared, or through its namespace.
            return match self.namespace_at(local.node.start_byte()) {
                Some(ns) if !enclosing.contains(&ns) => Source::Through(vec![ns]),
                _ => Source::Elsewhere,
            };
        }
        if id.is_some_and(|id| self.m.decl_of(id).is_some()) {
            return Source::Elsewhere;
        }
        let declares = |ns: &str| {
            self.platform.declared_in(ns).is_some_and(|d: &Declared| {
                d.types.contains(name) || d.types.contains(&format!("{name}Attribute"))
            })
        };
        if enclosing.iter().any(|ns| declares(ns)) {
            return Source::Elsewhere;
        }
        let through: Vec<String> = self
            .usings
            .iter()
            .filter(|u| declares(u))
            .cloned()
            .collect();
        if !through.is_empty() {
            return Source::Through(through);
        }
        // A namespace's first segment: `System` in `System.IO.File`.
        let root = |ns: &str| ns.split('.').next() == Some(name);
        if self.platform.has_namespace(name)
            || self.usings.iter().any(|u| root(u))
            || self.namespaces.iter().any(|(_, _, ns)| root(ns))
        {
            return Source::Elsewhere;
        }
        if self.implicit && IMPLICIT_USINGS.iter().any(|ns| declares(ns)) {
            return Source::Elsewhere;
        }
        Source::Unknown
    }

    /// What `receiver.name(...)` may come from: an instance method, or an
    /// extension method of some namespace.
    fn call_source(&self, call: Node, receiver: Node, name: &str) -> Source {
        if call
            .child_by_field_name("function")
            .is_some_and(|f| f.kind() == "member_access_expression")
            && let Some(c) = self.call(call)
        {
            if !c.extension {
                return Source::Elsewhere;
            }
            let namespaces: Vec<String> = c
                .methods
                .iter()
                .filter_map(|f| match f {
                    super::Found::Platform { declaring, .. } => declaring
                        .name
                        .rsplit_once('.')
                        .map(|(ns, _)| ns.to_string()),
                    super::Found::Local(_) => None,
                })
                .collect();
            return Source::Through(namespaces);
        }
        // `receiver?.name(...)`, or a call that doesn't resolve.
        let arguments = call.child_by_field_name("arguments").map_or(0, |a| {
            a.named_children(&mut a.walk())
                .filter(|x| x.kind() == "argument")
                .count()
        });
        if let Some(ty) = self.type_of(receiver).map(unwrap_nullable)
            && !self.members(&ty, name, Some(arguments)).is_empty()
        {
            return Source::Elsewhere;
        }
        self.extension_source(&[name])
    }

    /// What `F(receiver.name)` may pass: an instance method or an extension
    /// method.
    fn method_group_source(&self, receiver: Node, name: &str) -> Source {
        if let Some(ty) = self.type_of(receiver).map(unwrap_nullable)
            && (0..6).any(|n| !self.members(&ty, name, Some(n)).is_empty())
        {
            return Source::Elsewhere;
        }
        self.extension_source(&[name])
    }

    /// The using directives whose namespace declares extension methods of
    /// these names, or Unknown.
    fn extension_source(&self, names: &[&str]) -> Source {
        let through: Vec<String> = self
            .usings
            .iter()
            .filter(|u| {
                self.platform
                    .declared_in(u)
                    .is_some_and(|d| names.iter().any(|n| d.extensions.contains(*n)))
            })
            .cloned()
            .collect();
        if through.is_empty() {
            Source::Unknown
        } else {
            Source::Through(through)
        }
    }

    /// The namespaces code at `byte` is in, with their parents.
    fn enclosing_namespaces(&self, byte: usize) -> Vec<String> {
        let mut out = Vec::new();
        for (s, e, ns) in &self.namespaces {
            if *s <= byte && byte < *e {
                let mut ns = ns.as_str();
                loop {
                    out.push(ns.to_string());
                    match ns.rsplit_once('.') {
                        Some((outer, _)) => ns = outer,
                        None => break,
                    }
                }
            }
        }
        out
    }

    /// The innermost namespace declared around `byte`.
    fn namespace_at(&self, byte: usize) -> Option<String> {
        self.namespaces
            .iter()
            .filter(|(s, e, _)| *s <= byte && byte < *e)
            .max_by_key(|(s, _, _)| *s)
            .map(|(_, _, ns)| ns.clone())
    }
}

fn unwrap_nullable(t: Ty) -> Ty {
    if t.is("System.Nullable`1") {
        t.args().first().cloned().unwrap_or(t)
    } else {
        t
    }
}

/// The field a child is in.
fn field_of<'a>(parent: Node<'a>, child: Node) -> Option<&'a str> {
    let mut c = parent.walk();
    if !c.goto_first_child() {
        return None;
    }
    loop {
        if c.node().id() == child.id() {
            return c.field_name();
        }
        if !c.goto_next_sibling() {
            return None;
        }
    }
}

/// The first name of each `cref` in a documentation comment.
fn crefs(comment: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = comment;
    while let Some(i) = rest.find("cref=\"") {
        rest = &rest[i + 6..];
        let end = rest
            .find(|c: char| !(c.is_alphanumeric() || c == '_'))
            .unwrap_or(rest.len());
        // `T:System.String`: the documentation ID's prefix.
        let word = &rest[..end];
        if !word.is_empty() && !rest[end..].starts_with(':') {
            out.push(word);
        }
        rest = &rest[end..];
    }
    out
}
