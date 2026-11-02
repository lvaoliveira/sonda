//! Expression types for C# rules (ADR-0022, step 2): what a name, a call or
//! a member access evaluates to, from the file's declarations and the
//! platform's (`semantic/dotnet.rs`).
//!
//! Types are resolved as C# resolves them, as far as one file tells: type
//! parameters, then types the file declares, then platform types through
//! the enclosing namespaces, the file's `using` directives and, when
//! nothing imported could declare the name instead, the SDK's implicit
//! usings. Members are found through base classes and interfaces, with
//! generic arguments substituted; extension methods through the namespaces
//! the file imports. When any step can't tell, the answer is None: rules
//! then report nothing, which costs recall only.
//!
//! What it doesn't see: types declared in other files of the project, which
//! could shadow a platform type of the same name in the same namespace.

use super::dotnet::{self, Platform, PlatformMember, PlatformType};
use super::{DeclKind, Model, ScopeId};
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

/// A type: a platform one by key, or one this file declares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Ty {
    Named {
        /// A platform key (`System.Collections.Generic.List`1`), or for a
        /// type of this file its name and arity (`Order`0`).
        key: String,
        args: Vec<Ty>,
        local: bool,
    },
    Array(Box<Ty>),
    /// `!n`: a type parameter of the platform type a member belongs to.
    Var(u32),
    /// `!!n`: a type parameter of the platform method itself.
    MVar(u32),
    /// A type parameter this file declares: `T`.
    Param(String),
    /// A type argument nothing tells.
    Unknown,
}

const STRING: &str = "System.String";

impl Ty {
    fn platform(key: &str, args: Vec<Ty>) -> Ty {
        Ty::Named {
            key: key.to_string(),
            args,
            local: false,
        }
    }

    /// The platform key of a platform type.
    pub(crate) fn key(&self) -> Option<&str> {
        match self {
            Ty::Named {
                key, local: false, ..
            } => Some(key),
            _ => None,
        }
    }

    pub(crate) fn is(&self, key: &str) -> bool {
        self.key() == Some(key)
    }

    pub(crate) fn args(&self) -> &[Ty] {
        match self {
            Ty::Named { args, .. } => args,
            _ => &[],
        }
    }

    /// Parses a platform type reference: `System.Collections.Generic.List`1<!0>`.
    pub(crate) fn parse(text: &str) -> Option<Ty> {
        let bytes = text.as_bytes();
        let mut i = 0;
        let ty = parse_at(bytes, &mut i, 0)?;
        (i == bytes.len()).then_some(ty)
    }

    /// With the platform type's parameters (`!n`) and the method's (`!!n`)
    /// replaced; those nothing binds become Unknown.
    fn substitute(&self, vars: &[Ty], mvars: &[Ty]) -> Ty {
        match self {
            Ty::Var(n) => vars.get(*n as usize).cloned().unwrap_or(Ty::Unknown),
            Ty::MVar(n) => mvars.get(*n as usize).cloned().unwrap_or(Ty::Unknown),
            Ty::Array(e) => Ty::Array(Box::new(e.substitute(vars, mvars))),
            Ty::Named { key, args, local } => Ty::Named {
                key: key.clone(),
                args: args.iter().map(|a| a.substitute(vars, mvars)).collect(),
                local: *local,
            },
            other => other.clone(),
        }
    }

    fn known(self) -> Option<Ty> {
        (self != Ty::Unknown).then_some(self)
    }
}

fn parse_at(b: &[u8], i: &mut usize, depth: u8) -> Option<Ty> {
    if depth > 16 {
        return None;
    }
    let mut ty = if b[*i..].starts_with(b"!!") || b[*i..].starts_with(b"!") {
        let method = b[*i..].starts_with(b"!!");
        *i += if method { 2 } else { 1 };
        let start = *i;
        while *i < b.len() && b[*i].is_ascii_digit() {
            *i += 1;
        }
        let n: u32 = std::str::from_utf8(&b[start..*i]).ok()?.parse().ok()?;
        if method { Ty::MVar(n) } else { Ty::Var(n) }
    } else {
        let start = *i;
        while *i < b.len() && !matches!(b[*i], b'<' | b',' | b'>' | b'[' | b']' | b'*') {
            *i += 1;
        }
        let key = std::str::from_utf8(&b[start..*i]).ok()?.to_string();
        let mut args = Vec::new();
        if b.get(*i) == Some(&b'<') {
            *i += 1;
            loop {
                args.push(parse_at(b, i, depth + 1)?);
                match b.get(*i) {
                    Some(b',') => *i += 1,
                    Some(b'>') => {
                        *i += 1;
                        break;
                    }
                    _ => return None,
                }
            }
        }
        if key.is_empty() {
            return None;
        }
        Ty::Named {
            key,
            args,
            local: false,
        }
    };
    loop {
        match b.get(*i) {
            Some(b'[') => {
                while *i < b.len() && b[*i] != b']' {
                    *i += 1;
                }
                *i += 1;
                ty = Ty::Array(Box::new(ty));
            }
            Some(b'*') => return None,
            _ => return Some(ty),
        }
    }
}

/// The framework type a C# keyword names.
fn keyword_type(word: &str) -> Option<&'static str> {
    Some(match word {
        "bool" => "System.Boolean",
        "byte" => "System.Byte",
        "sbyte" => "System.SByte",
        "char" => "System.Char",
        "short" => "System.Int16",
        "ushort" => "System.UInt16",
        "int" => "System.Int32",
        "uint" => "System.UInt32",
        "long" => "System.Int64",
        "ulong" => "System.UInt64",
        "nint" => "System.IntPtr",
        "nuint" => "System.UIntPtr",
        "float" => "System.Single",
        "double" => "System.Double",
        "decimal" => "System.Decimal",
        "string" => STRING,
        "object" => "System.Object",
        "void" => "System.Void",
        _ => return None,
    })
}

/// The SDK's implicit usings (`<ImplicitUsings>`), Microsoft.NET.Sdk's.
const IMPLICIT_USINGS: &[&str] = &[
    "System",
    "System.Collections.Generic",
    "System.IO",
    "System.Linq",
    "System.Net.Http",
    "System.Threading",
    "System.Threading.Tasks",
];

/// A type this file declares.
#[derive(Clone, Copy)]
struct LocalType<'t> {
    node: Node<'t>,
    /// The scope of its members; None for enums and delegates.
    members: Option<ScopeId>,
}

/// A member found on a type.
pub(crate) enum Found<'m, 't> {
    Platform {
        declaring: &'static PlatformType,
        member: &'static PlatformMember,
        /// The declaring type's type arguments.
        vars: Vec<Ty>,
    },
    Local(&'m super::Decl<'t>),
}

/// What a call resolves to.
pub(crate) struct Call<'m, 't> {
    /// The receiver's type; None for a call without one.
    pub(crate) receiver: Option<Ty>,
    /// The methods it may call, all with the same name and a fitting
    /// number of parameters.
    pub(crate) methods: Vec<Found<'m, 't>>,
    /// Whether they are extension methods, the receiver their first
    /// argument.
    pub(crate) extension: bool,
}

pub(crate) struct Infer<'m, 't> {
    m: &'m Model<'t>,
    src: &'m [u8],
    platform: &'static Platform,
    usings: Vec<String>,
    /// Whether the SDK's implicit usings may resolve a name.
    implicit: bool,
    /// Namespace bodies: (start byte, end byte, name).
    namespaces: Vec<(usize, usize, String)>,
    /// Types by name and arity (`Order`0`); None when declared twice.
    locals: HashMap<String, Option<LocalType<'t>>>,
    type_params: HashSet<String>,
}

impl<'m, 't> Infer<'m, 't> {
    pub(crate) fn new(m: &'m Model<'t>, src: &'m [u8]) -> Option<Infer<'m, 't>> {
        let root = m.root?;
        let platform = dotnet::platform();
        let text = |n: Node| n.utf8_text(src).unwrap_or_default().to_string();
        let mut usings = Vec::new();
        let mut namespaces = Vec::new();
        let mut locals: HashMap<String, Option<LocalType<'t>>> = HashMap::new();
        let mut type_params = HashSet::new();
        let scopes: HashMap<usize, ScopeId> =
            m.type_scopes.iter().map(|(n, s)| (n.id(), *s)).collect();
        let mut stack = vec![root];
        while let Some(n) = stack.pop() {
            match n.kind() {
                "using_directive" => {
                    let t = text(n);
                    if n.child_by_field_name("name").is_none()
                        && !t.contains("static")
                        && let Some(name) = n.named_child(0)
                    {
                        usings.push(text(name));
                    }
                    continue;
                }
                "file_scoped_namespace_declaration" | "namespace_declaration" => {
                    if let Some(name) = n.child_by_field_name("name") {
                        let end = if n.kind() == "namespace_declaration" {
                            n.end_byte()
                        } else {
                            root.end_byte()
                        };
                        namespaces.push((n.start_byte(), end, text(name)));
                    }
                }
                "type_parameter" => {
                    if let Some(name) = n.child_by_field_name("name").or_else(|| n.named_child(0)) {
                        type_params.insert(text(name));
                    }
                }
                "class_declaration"
                | "struct_declaration"
                | "record_declaration"
                | "record_struct_declaration"
                | "interface_declaration"
                | "enum_declaration"
                | "delegate_declaration" => {
                    if let Some(name) = n.child_by_field_name("name") {
                        let arity = n
                            .named_children(&mut n.walk())
                            .find(|c| c.kind() == "type_parameter_list")
                            .map_or(0, |l| l.named_child_count());
                        let key = format!("{}`{arity}", text(name));
                        let local = LocalType {
                            node: n,
                            members: scopes.get(&n.id()).copied(),
                        };
                        locals
                            .entry(key)
                            .and_modify(|e| *e = None)
                            .or_insert(Some(local));
                    }
                }
                // Expressions and statements declare no types.
                "block" | "arrow_expression_clause" => continue,
                _ => {}
            }
            let mut c = n.walk();
            stack.extend(n.named_children(&mut c));
        }
        // A file's own namespaces, and those sharing their first segment,
        // are taken for the project's.
        let roots: HashSet<&str> = namespaces
            .iter()
            .filter_map(|(_, _, ns)| ns.split('.').next())
            .collect();
        // Implicit usings apply when nothing imported could declare a name
        // instead, or when the file imports none of their namespaces
        // itself, which projects without them nearly always do.
        let implicit = usings.iter().all(|u| {
            platform.has_namespace(u) || u.split('.').next().is_some_and(|r| roots.contains(r))
        }) || !usings.iter().any(|u| IMPLICIT_USINGS.contains(&u.as_str()));
        Some(Infer {
            m,
            src,
            platform,
            usings,
            implicit,
            namespaces,
            locals,
            type_params,
        })
    }

    fn text(&self, n: Node) -> &'m str {
        n.utf8_text(self.src).unwrap_or_default()
    }

    // ------------------------------------------------ written types

    /// The type a type node names.
    pub(crate) fn written(&self, ty: Node) -> Option<Ty> {
        match ty.kind() {
            "predefined_type" => keyword_type(self.text(ty)).map(|k| Ty::platform(k, Vec::new())),
            "nullable_type" => {
                let inner = self.written(
                    ty.child_by_field_name("type")
                        .or_else(|| ty.named_child(0))?,
                )?;
                if self.is_value_type(&inner) {
                    Some(Ty::platform("System.Nullable`1", vec![inner]))
                } else {
                    Some(inner)
                }
            }
            "array_type" => {
                let element = self.written(ty.child_by_field_name("type")?)?;
                Some(Ty::Array(Box::new(element)))
            }
            "identifier" | "generic_name" | "qualified_name" | "alias_qualified_name" => {
                self.named(ty)
            }
            "tuple_type" => {
                let elements: Vec<Ty> = ty
                    .named_children(&mut ty.walk())
                    .filter(|e| e.kind() == "tuple_element")
                    .map(|e| {
                        e.child_by_field_name("type")
                            .and_then(|t| self.written(t))
                            .unwrap_or(Ty::Unknown)
                    })
                    .collect();
                let key = format!("System.ValueTuple`{}", elements.len());
                self.platform
                    .get(&key)
                    .map(|_| Ty::platform(&key, elements))
            }
            _ => None,
        }
    }

    fn named(&self, ty: Node) -> Option<Ty> {
        // (qualifier, name, type argument nodes)
        let (qualifier, name, arg_nodes): (String, &str, Vec<Node>) = match ty.kind() {
            "identifier" => (String::new(), self.text(ty), Vec::new()),
            "generic_name" => {
                let name = ty.named_child(0)?;
                let args = ty
                    .named_child(1)
                    .map(|l| l.named_children(&mut l.walk()).collect())
                    .unwrap_or_default();
                (String::new(), self.text(name), args)
            }
            "qualified_name" => {
                let q = self.text(ty.child_by_field_name("qualifier")?);
                let inner = ty.child_by_field_name("name")?;
                let (_, name, args) = match inner.kind() {
                    "generic_name" => {
                        let args = inner
                            .named_child(1)
                            .map(|l| l.named_children(&mut l.walk()).collect())
                            .unwrap_or_default();
                        (String::new(), self.text(inner.named_child(0)?), args)
                    }
                    _ => (String::new(), self.text(inner), Vec::new()),
                };
                (q.trim_start_matches("global::").to_string(), name, args)
            }
            _ => return None,
        };
        let args: Vec<Ty> = arg_nodes
            .iter()
            .map(|a| self.written(*a).unwrap_or(Ty::Unknown))
            .collect();
        let arity = args.len();
        if qualifier.is_empty() {
            if arity == 0 && self.type_params.contains(name) {
                return Some(Ty::Param(name.to_string()));
            }
            let local_key = format!("{name}`{arity}");
            if let Some(local) = self.locals.get(&local_key) {
                return local.map(|_| Ty::Named {
                    key: local_key,
                    args,
                    local: true,
                });
            }
        }
        let own = if arity > 0 {
            format!("{name}`{arity}")
        } else {
            name.to_string()
        };
        let path = if qualifier.is_empty() {
            own
        } else {
            format!("{qualifier}.{own}")
        };
        self.platform_key(&path, ty.start_byte(), !qualifier.is_empty())
            .map(|key| Ty::platform(&key, args))
    }

    /// The platform key `path` names at `byte`: through the enclosing
    /// namespaces and the usings, then the implicit ones.
    fn platform_key(&self, path: &str, byte: usize, qualified: bool) -> Option<String> {
        let mut prefixes: Vec<&str> = vec![""];
        let mut enclosing: Vec<&(usize, usize, String)> = self
            .namespaces
            .iter()
            .filter(|(s, e, _)| *s <= byte && byte < *e)
            .collect();
        enclosing.sort_by_key(|(s, _, _)| std::cmp::Reverse(*s));
        for (_, _, ns) in enclosing {
            let mut ns = ns.as_str();
            loop {
                prefixes.push(ns);
                match ns.rsplit_once('.') {
                    Some((outer, _)) => ns = outer,
                    None => break,
                }
            }
        }
        prefixes.extend(self.usings.iter().map(String::as_str));
        let find = |prefixes: &mut dyn Iterator<Item = &str>| -> Vec<String> {
            let mut found: Vec<String> = Vec::new();
            for p in prefixes {
                let key = if p.is_empty() {
                    path.to_string()
                } else {
                    format!("{p}.{path}")
                };
                if self.platform.get(&key).is_some() && !found.contains(&key) {
                    found.push(key);
                }
            }
            found
        };
        let found = find(&mut prefixes.into_iter());
        match found.len() {
            1 => return found.into_iter().next(),
            0 => {}
            _ => return None,
        }
        if qualified || !self.implicit {
            return None;
        }
        let found = find(&mut IMPLICIT_USINGS.iter().copied());
        (found.len() == 1)
            .then(|| found.into_iter().next())
            .flatten()
    }

    fn is_value_type(&self, ty: &Ty) -> bool {
        match ty {
            Ty::Named {
                key, local: false, ..
            } => self
                .platform
                .get(key)
                .is_some_and(|t| matches!(t.kind.as_str(), "struct" | "enum")),
            Ty::Named {
                key, local: true, ..
            } => self.locals.get(key).copied().flatten().is_some_and(|l| {
                matches!(
                    l.node.kind(),
                    "struct_declaration" | "record_struct_declaration" | "enum_declaration"
                )
            }),
            _ => false,
        }
    }

    /// Whether a type is a value type, as far as declarations tell: None
    /// when they don't.
    pub(crate) fn value_type(&self, ty: &Ty) -> Option<bool> {
        match ty {
            Ty::Array(_) => Some(false),
            Ty::Named {
                key, local: false, ..
            } => self
                .platform
                .get(key)
                .map(|t| matches!(t.kind.as_str(), "struct" | "enum")),
            Ty::Named { local: true, .. } => Some(self.is_value_type(ty)),
            _ => None,
        }
    }

    // ------------------------------------------------ supertypes and members

    /// A type, its base classes and the interfaces it implements, with
    /// their type arguments, nearest first and base classes before
    /// interfaces.
    pub(crate) fn supertypes(&self, ty: &Ty) -> Vec<Ty> {
        let mut out: Vec<Ty> = Vec::new();
        let mut todo = std::collections::VecDeque::from([ty.clone()]);
        while let Some(t) = todo.pop_front() {
            if out.contains(&t) || out.len() > 64 {
                continue;
            }
            match &t {
                Ty::Array(e) => {
                    for key in [
                        "System.Collections.Generic.IList`1",
                        "System.Collections.Generic.IReadOnlyList`1",
                    ] {
                        todo.push_back(Ty::platform(key, vec![(**e).clone()]));
                    }
                    todo.push_back(Ty::platform("System.Array", Vec::new()));
                }
                Ty::Named {
                    key,
                    args,
                    local: false,
                } => {
                    if let Some(p) = self.platform.get(key) {
                        let next = p
                            .base
                            .iter()
                            .chain(p.interfaces.iter())
                            .filter_map(|b| Ty::parse(b))
                            .map(|b| b.substitute(args, &[]));
                        todo.extend(next);
                        if p.kind == "interface" {
                            todo.push_back(Ty::platform("System.Object", Vec::new()));
                        }
                    }
                }
                Ty::Named {
                    key, local: true, ..
                } => {
                    if let Some(local) = self.locals.get(key).copied().flatten()
                        && let Some(bases) = local
                            .node
                            .named_children(&mut local.node.walk())
                            .find(|c| c.kind() == "base_list")
                    {
                        let mut c = bases.walk();
                        let written: Vec<Ty> = bases
                            .named_children(&mut c)
                            .filter_map(|b| {
                                let b = if b.kind() == "primary_constructor_base_type" {
                                    b.named_child(0)?
                                } else {
                                    b
                                };
                                self.written(b)
                            })
                            .collect();
                        todo.extend(written);
                    }
                }
                _ => {}
            }
            out.push(t);
        }
        out
    }

    /// The members named `name` a type has: methods taking `arguments`
    /// arguments for a call, properties and fields otherwise. Those of the
    /// nearest type declaring any, as C# hides inherited members with a
    /// derived one's and reaches an interface's through the class.
    pub(crate) fn members(
        &self,
        ty: &Ty,
        name: &str,
        arguments: Option<usize>,
    ) -> Vec<Found<'m, 't>> {
        let mut out = Vec::new();
        for t in self.supertypes(ty) {
            if !out.is_empty() {
                break;
            }
            match &t {
                Ty::Named {
                    key,
                    args,
                    local: false,
                } => {
                    let Some(p) = self.platform.get(key) else {
                        continue;
                    };
                    for m in p.members.iter().filter(|m| m.name == name) {
                        let fits = match arguments {
                            Some(n) => m.kind == "method" && accepts(m, n, 0),
                            None => matches!(m.kind.as_str(), "property" | "field" | "event"),
                        };
                        if fits {
                            out.push(Found::Platform {
                                declaring: p,
                                member: m,
                                vars: args.clone(),
                            });
                        }
                    }
                }
                Ty::Named {
                    key, local: true, ..
                } => {
                    let Some(scope) = self
                        .locals
                        .get(key)
                        .copied()
                        .flatten()
                        .and_then(|l| l.members)
                    else {
                        continue;
                    };
                    for &d in self.m.decls_named(scope, name) {
                        let d = &self.m.decls[d];
                        let fits = match arguments {
                            Some(n) => {
                                d.kind == DeclKind::Method
                                    && d.declarator.is_some_and(|m| self.local_accepts(m, n))
                            }
                            None => matches!(d.kind, DeclKind::Field | DeclKind::Property),
                        };
                        if fits {
                            out.push(Found::Local(d));
                        }
                    }
                }
                _ => {}
            }
        }
        out
    }

    fn local_accepts(&self, method: Node, n: usize) -> bool {
        let Some(list) = method.child_by_field_name("parameters") else {
            return n == 0;
        };
        let params: Vec<Node> = list
            .named_children(&mut list.walk())
            .filter(|p| p.kind() == "parameter")
            .collect();
        let text = self.text(list);
        let variadic = text.contains("params ");
        let required = params
            .iter()
            .filter(|p| !self.text(**p).contains('='))
            .count()
            - usize::from(variadic && !params.is_empty());
        n >= required && (variadic || n <= params.len())
    }

    /// The type a member evaluates to.
    fn member_type(&self, found: &Found) -> Option<Ty> {
        match found {
            Found::Platform { member, vars, .. } => {
                Ty::parse(&member.ty).map(|t| t.substitute(vars, &[]))
            }
            Found::Local(d) => {
                d.ty.filter(|t| t.kind() != "implicit_type")
                    .and_then(|t| self.written(t))
            }
        }
    }

    /// The type all of `found` agree on.
    fn agreed(&self, found: &[Found]) -> Option<Ty> {
        let mut types = found.iter().map(|f| self.member_type(f));
        let first = types.next()??;
        types
            .all(|t| t.as_ref() == Some(&first))
            .then_some(first)
            .and_then(Ty::known)
            .filter(|t| !contains_unbound(t))
    }

    /// Whether a namespace's extension methods are in scope at `byte`.
    fn imports(&self, namespace: &str, byte: usize) -> bool {
        self.usings.iter().any(|u| u == namespace)
            || self.namespaces.iter().any(|(s, e, ns)| {
                *s <= byte
                    && byte < *e
                    && (ns == namespace || ns.starts_with(&format!("{namespace}.")))
            })
            || (self.implicit && IMPLICIT_USINGS.contains(&namespace))
    }

    /// Extension methods named `name` that take `receiver` and `arguments`
    /// more, in scope at `byte`, with the receiver's type arguments bound.
    fn extensions(
        &self,
        receiver: &Ty,
        name: &str,
        arguments: usize,
        byte: usize,
    ) -> Vec<(Found<'m, 't>, Vec<Ty>)> {
        let supertypes = self.supertypes(receiver);
        let mut out = Vec::new();
        for (declaring, method) in self.platform.extensions(name) {
            let namespace = declaring.name.rsplit_once('.').map_or("", |(ns, _)| ns);
            if !accepts(method, arguments, 1) || !self.imports(namespace, byte) {
                continue;
            }
            let Some(first) = method.params.first().and_then(|p| Ty::parse(&p.ty)) else {
                continue;
            };
            // Bind the method's type parameters from the receiver.
            let mut bound: Vec<Ty> = vec![Ty::Unknown; method.generic as usize];
            let fits = match &first {
                Ty::MVar(n) => {
                    if let Some(b) = bound.get_mut(*n as usize) {
                        *b = receiver.clone();
                    }
                    true
                }
                Ty::Named { key, .. } => supertypes
                    .iter()
                    .find(|s| s.key() == Some(key.as_str()))
                    .is_some_and(|s| unify(&first, s, &mut bound)),
                Ty::Array(_) => unify(&first, receiver, &mut bound),
                _ => false,
            };
            if fits {
                out.push((
                    Found::Platform {
                        declaring,
                        member: method,
                        vars: Vec::new(),
                    },
                    bound,
                ));
            }
        }
        out
    }

    // ------------------------------------------------ expressions

    /// The type an expression evaluates to.
    pub(crate) fn type_of(&self, expr: Node) -> Option<Ty> {
        self.typed(expr, 0)
    }

    fn typed(&self, expr: Node, depth: u8) -> Option<Ty> {
        if depth > 12 {
            return None;
        }
        let d = depth + 1;
        let string = || Some(Ty::platform(STRING, Vec::new()));
        match expr.kind() {
            "parenthesized_expression" => self.typed(expr.named_child(0)?, d),
            "identifier" => self.name_type(expr, d),
            "this" | "this_expression" => self.enclosing_type(expr),
            "member_access_expression" => {
                let name = expr.child_by_field_name("name")?;
                let receiver = self.receiver(expr.child_by_field_name("expression")?, d)?;
                self.agreed(&self.members(&receiver, self.text(simple(name)?), None))
            }
            "invocation_expression" => {
                let Some(call) = self.call_at(expr, d) else {
                    return self.object_method(expr);
                };
                if call.extension {
                    // The method's own type arguments come from the receiver.
                    let mut types = call.methods.iter().map(|f| match f {
                        Found::Platform { member, .. } => {
                            let receiver = call.receiver.as_ref()?;
                            let bound = self.bind_extension(member, receiver)?;
                            Ty::parse(&member.ty).map(|t| t.substitute(&[], &bound))
                        }
                        Found::Local(_) => None,
                    });
                    let first = types.next()??;
                    types
                        .all(|t| t.as_ref() == Some(&first))
                        .then_some(first)
                        .and_then(Ty::known)
                        .filter(|t| !contains_unbound(t))
                } else {
                    self.agreed(&call.methods)
                }
            }
            "object_creation_expression" | "array_creation_expression" | "cast_expression" => {
                self.written(expr.child_by_field_name("type")?)
            }
            "as_expression" => self.written(expr.child_by_field_name("right")?),
            "await_expression" => {
                let awaited = self.typed(expr.named_child(0)?, d)?;
                match awaited.key()? {
                    "System.Threading.Tasks.Task`1" | "System.Threading.Tasks.ValueTask`1" => {
                        awaited.args().first().cloned().and_then(Ty::known)
                    }
                    _ => None,
                }
            }
            "element_access_expression" => {
                let receiver = self.typed(expr.child_by_field_name("expression")?, d)?;
                match receiver {
                    Ty::Array(e) => (*e).known(),
                    ref t if t.is(STRING) => Some(Ty::platform("System.Char", Vec::new())),
                    t => self.agreed(
                        &self
                            .members(&t, "Item", None)
                            .into_iter()
                            .filter(|f| matches!(f, Found::Platform { member, .. } if member.params.len() == 1))
                            .collect::<Vec<_>>(),
                    ),
                }
            }
            "string_literal"
            | "verbatim_string_literal"
            | "raw_string_literal"
            | "interpolated_string_expression" => string(),
            "boolean_literal" => Some(Ty::platform("System.Boolean", Vec::new())),
            "character_literal" => Some(Ty::platform("System.Char", Vec::new())),
            "integer_literal" | "real_literal" => {
                let t = self.text(expr).to_ascii_lowercase();
                let key = if expr.kind() == "integer_literal" {
                    if t.ends_with("ul") || t.ends_with("lu") {
                        "System.UInt64"
                    } else if t.ends_with('l') {
                        "System.Int64"
                    } else if t.ends_with('u') {
                        "System.UInt32"
                    } else {
                        "System.Int32"
                    }
                } else if t.ends_with('f') {
                    "System.Single"
                } else if t.ends_with('m') {
                    "System.Decimal"
                } else {
                    "System.Double"
                };
                Some(Ty::platform(key, Vec::new()))
            }
            "binary_expression" => {
                let op = self.text(expr.child_by_field_name("operator")?);
                let (l, r) = (
                    expr.child_by_field_name("left")?,
                    expr.child_by_field_name("right")?,
                );
                match op {
                    "==" | "!=" | "<" | ">" | "<=" | ">=" | "&&" | "||" => {
                        Some(Ty::platform("System.Boolean", Vec::new()))
                    }
                    "+" if [l, r]
                        .iter()
                        .any(|x| self.typed(*x, d).is_some_and(|t| t.is(STRING))) =>
                    {
                        string()
                    }
                    _ => None,
                }
            }
            "conditional_expression" => {
                let a = self.typed(expr.child_by_field_name("consequence")?, d)?;
                let b = self.typed(expr.child_by_field_name("alternative")?, d)?;
                (a == b).then_some(a)
            }
            _ => None,
        }
    }

    /// A receiver: an expression's type, or a type named for a static
    /// member (`File.OpenRead`).
    fn receiver(&self, expr: Node, depth: u8) -> Option<Ty> {
        if let Some(t) = self.typed(expr, depth) {
            return Some(t);
        }
        let is_variable = matches!(expr.kind(), "identifier") && self.m.decl_of(expr).is_some();
        if !is_variable
            && matches!(
                expr.kind(),
                "identifier" | "generic_name" | "qualified_name" | "predefined_type"
            )
        {
            return self.written(expr);
        }
        if expr.kind() == "member_access_expression" {
            // `System.IO.File`: a qualified type name.
            let path = self.text(expr).replace(char::is_whitespace, "");
            return self
                .platform_key(&path, expr.start_byte(), true)
                .map(|k| Ty::platform(&k, Vec::new()));
        }
        None
    }

    /// The type of a name: its declaration's, or for `var` what it was
    /// initialized with.
    fn name_type(&self, name: Node, depth: u8) -> Option<Ty> {
        let d = self.m.decl_of(name)?;
        match d.kind {
            DeclKind::Method | DeclKind::Class | DeclKind::Function => return None,
            _ => {}
        }
        if let Some(t) = d.ty.filter(|t| t.kind() != "implicit_type") {
            return self.written(t);
        }
        // `foreach (var x in xs)`
        if let Some(each) = d.node.parent().filter(|p| p.kind() == "foreach_statement") {
            let collection = self.typed(each.child_by_field_name("right")?, depth)?;
            return self.element_type(&collection);
        }
        let declarator = d.declarator.filter(|v| v.kind() == "variable_declarator")?;
        let value = declarator.named_child(declarator.named_child_count().checked_sub(1)? as u32)?;
        if value.id() == name.id()
            || value.kind() == "identifier" && value.start_byte() == d.node.start_byte()
        {
            return None;
        }
        self.typed(value, depth)
    }

    /// The element type a `foreach` over a collection of this type gets.
    pub(crate) fn element_type(&self, collection: &Ty) -> Option<Ty> {
        if let Ty::Array(e) = collection {
            return (**e).clone().known();
        }
        if collection.is(STRING) {
            return Some(Ty::platform("System.Char", Vec::new()));
        }
        self.supertypes(collection)
            .into_iter()
            .find(|s| s.is("System.Collections.Generic.IEnumerable`1"))
            .and_then(|s| s.args().first().cloned())
            .and_then(Ty::known)
    }

    /// The type a node is written in, its own type parameters as arguments.
    pub(crate) fn enclosing_type(&self, node: Node) -> Option<Ty> {
        let (decl, _) = self
            .m
            .type_scopes
            .iter()
            .filter(|(n, _)| n.start_byte() <= node.start_byte() && node.end_byte() <= n.end_byte())
            .max_by_key(|(n, _)| n.start_byte())?;
        let name = self.text(decl.child_by_field_name("name")?);
        let params: Vec<Ty> = decl
            .named_children(&mut decl.walk())
            .find(|c| c.kind() == "type_parameter_list")
            .map(|l| {
                l.named_children(&mut l.walk())
                    .map(|p| Ty::Param(self.text(p).to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let key = format!("{name}`{}", params.len());
        self.locals.get(&key).copied().flatten().map(|_| Ty::Named {
            key,
            args: params,
            local: true,
        })
    }

    // ------------------------------------------------ calls

    /// What an invocation calls, and on what.
    pub(crate) fn call(&self, invocation: Node) -> Option<Call<'m, 't>> {
        self.call_at(invocation, 0)
    }

    fn call_at(&self, invocation: Node, depth: u8) -> Option<Call<'m, 't>> {
        let function = invocation.child_by_field_name("function")?;
        let arguments = invocation.child_by_field_name("arguments").map_or(0, |a| {
            a.named_children(&mut a.walk())
                .filter(|x| x.kind() == "argument")
                .count()
        });
        match function.kind() {
            "member_access_expression" => {
                let name = self.text(simple(function.child_by_field_name("name")?)?);
                let receiver =
                    self.receiver(function.child_by_field_name("expression")?, depth + 1)?;
                let methods = self.members(&receiver, name, Some(arguments));
                if !methods.is_empty() {
                    return Some(Call {
                        receiver: Some(receiver),
                        methods,
                        extension: false,
                    });
                }
                let methods: Vec<Found> = self
                    .extensions(&receiver, name, arguments, invocation.start_byte())
                    .into_iter()
                    .map(|(f, _)| f)
                    .collect();
                (!methods.is_empty()).then_some(Call {
                    receiver: Some(receiver),
                    methods,
                    extension: true,
                })
            }
            "identifier" => {
                let owner = self.enclosing_type(invocation)?;
                let methods = self.members(&owner, self.text(function), Some(arguments));
                (!methods.is_empty()).then_some(Call {
                    receiver: None,
                    methods,
                    extension: false,
                })
            }
            _ => None,
        }
    }

    /// `x.ToString()`, `x.GetType()`, `x.GetHashCode()` and `x.Equals(y)`
    /// on any receiver: Object's methods, whatever x is.
    fn object_method(&self, invocation: Node) -> Option<Ty> {
        let function = invocation
            .child_by_field_name("function")
            .filter(|f| f.kind() == "member_access_expression")?;
        let name = self.text(function.child_by_field_name("name")?);
        let arguments = invocation.child_by_field_name("arguments").map_or(0, |a| {
            a.named_children(&mut a.walk())
                .filter(|x| x.kind() == "argument")
                .count()
        });
        let key = match (name, arguments) {
            ("ToString", 0) => STRING,
            ("GetType", 0) => "System.Type",
            ("GetHashCode", 0) => "System.Int32",
            ("Equals", 1) => "System.Boolean",
            _ => return None,
        };
        Some(Ty::platform(key, Vec::new()))
    }

    /// An extension method's own type arguments, from its receiver.
    fn bind_extension(&self, member: &PlatformMember, receiver: &Ty) -> Option<Vec<Ty>> {
        let first = Ty::parse(&member.params.first()?.ty)?;
        let mut bound = vec![Ty::Unknown; member.generic as usize];
        let fits = match &first {
            Ty::MVar(n) => {
                *bound.get_mut(*n as usize)? = receiver.clone();
                true
            }
            Ty::Named { key, .. } => self
                .supertypes(receiver)
                .iter()
                .find(|s| s.key() == Some(key.as_str()))
                .is_some_and(|s| unify(&first, s, &mut bound)),
            _ => unify(&first, receiver, &mut bound),
        };
        fits.then_some(bound)
    }
}

/// The identifier of a simple or generic name.
fn simple(name: Node) -> Option<Node> {
    match name.kind() {
        "generic_name" => name.named_child(0),
        _ => Some(name),
    }
}

/// Whether a platform method takes `n` arguments, after `skip` leading
/// parameters (an extension method's receiver).
fn accepts(m: &PlatformMember, n: usize, skip: usize) -> bool {
    let params = m.params.get(skip..).unwrap_or_default();
    let tagged = |p: &dotnet::PlatformParam, tag: &str| p.tags.iter().any(|t| t == tag);
    let variadic = params.last().is_some_and(|p| tagged(p, "params"));
    let required = params
        .iter()
        .filter(|p| !tagged(p, "optional") && !tagged(p, "params"))
        .count();
    n >= required && (variadic || n <= params.len())
}

/// Binds `pattern`'s method parameters (`!!n`) against `actual`, the same
/// shape with arguments in their place.
fn unify(pattern: &Ty, actual: &Ty, bound: &mut [Ty]) -> bool {
    match (pattern, actual) {
        (Ty::MVar(n), t) => {
            if let Some(b) = bound.get_mut(*n as usize)
                && *b == Ty::Unknown
            {
                *b = t.clone();
            }
            true
        }
        (Ty::Array(p), Ty::Array(a)) => unify(p, a, bound),
        (
            Ty::Named {
                key: pk, args: pa, ..
            },
            Ty::Named {
                key: ak, args: aa, ..
            },
        ) => pk == ak && pa.len() == aa.len() && pa.iter().zip(aa).all(|(p, a)| unify(p, a, bound)),
        (p, a) => p == a,
    }
}

/// Whether a type still names a platform type parameter or nothing at its
/// top: a member whose type the call doesn't settle.
fn contains_unbound(t: &Ty) -> bool {
    matches!(t, Ty::Var(_) | Ty::MVar(_) | Ty::Unknown)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lang::Lang;

    fn with_infer(src: &str, f: impl FnOnce(&Infer, Node)) {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&Lang::CSharp.grammar()).unwrap();
        let tree = parser.parse(src, None).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let m =
            super::super::build(Lang::CSharp, tree.root_node(), src.as_bytes(), deadline).unwrap();
        let infer = Infer::new(&m, src.as_bytes()).unwrap();
        f(&infer, tree.root_node());
    }

    /// The type of each `_ = expr;` discard in the source, rendered.
    fn discards(src: &str) -> Vec<Option<String>> {
        let mut out = Vec::new();
        with_infer(src, |infer, root| {
            let mut stack = vec![root];
            let mut found = Vec::new();
            while let Some(n) = stack.pop() {
                if n.kind() == "assignment_expression"
                    && n.child_by_field_name("left")
                        .is_some_and(|l| l.utf8_text(src.as_bytes()).unwrap() == "_")
                {
                    found.push(n);
                }
                let mut c = n.walk();
                stack.extend(n.named_children(&mut c));
            }
            found.sort_by_key(|n| n.start_byte());
            for n in found {
                out.push(
                    infer
                        .type_of(n.child_by_field_name("right").unwrap())
                        .map(|t| render(&t)),
                );
            }
        });
        out
    }

    fn render(t: &Ty) -> String {
        match t {
            Ty::Named { key, args, .. } if args.is_empty() => key.clone(),
            Ty::Named { key, args, .. } => {
                format!(
                    "{key}<{}>",
                    args.iter().map(render).collect::<Vec<_>>().join(",")
                )
            }
            Ty::Array(e) => format!("{}[]", render(e)),
            Ty::Param(p) => p.clone(),
            other => format!("{other:?}"),
        }
    }

    #[test]
    fn parses_platform_references() {
        assert_eq!(
            Ty::parse("System.Collections.Generic.Dictionary`2<!0,System.Int32[]>"),
            Some(Ty::platform(
                "System.Collections.Generic.Dictionary`2",
                vec![
                    Ty::Var(0),
                    Ty::Array(Box::new(Ty::platform("System.Int32", Vec::new())))
                ]
            ))
        );
        assert_eq!(Ty::parse("!!1"), Some(Ty::MVar(1)));
        assert_eq!(Ty::parse("System.Byte*"), None);
    }

    #[test]
    fn types_through_platform_members() {
        let src = "using System.IO;\nusing System.Linq;\nusing System.Collections.Generic;\nusing System.Threading.Tasks;\nnamespace N;\nclass Order { public string Name { get; set; } }\nclass A {\n  List<Order> orders;\n  async Task F(string path, Dictionary<string, List<int>> map) {\n    _ = File.OpenRead(path);\n    _ = orders.Where(o => o.Name != null).ToList();\n    _ = orders.FirstOrDefault();\n    _ = orders[0].Name.ToUpper();\n    _ = map[\"a\"];\n    _ = map.Values;\n    _ = path.Split(',');\n    var s = new StreamReader(path);\n    _ = await s.ReadToEndAsync();\n    foreach (var o in orders) { _ = o; }\n    _ = orders.Select(o => o.Name);\n    _ = Unknown.Thing();\n  }\n}\n";
        assert_eq!(
            discards(src),
            [
                Some("System.IO.FileStream".into()),
                Some("System.Collections.Generic.List`1<Order`0>".into()),
                Some("Order`0".into()),
                Some("System.String".into()),
                Some("System.Collections.Generic.List`1<System.Int32>".into()),
                Some("System.Collections.Generic.Dictionary.ValueCollection<System.String,System.Collections.Generic.List`1<System.Int32>>".into()),
                Some("System.String[]".into()),
                Some("System.String".into()),
                Some("Order`0".into()),
                // Select's element type comes from the lambda.
                Some("System.Collections.Generic.IEnumerable`1<Unknown>".into()),
                None,
            ]
        );
    }

    #[test]
    fn implicit_usings_only_when_nothing_else_could_declare_the_name() {
        // No usings at all: the SDK's implicit ones apply.
        assert_eq!(
            discards("namespace N;\nclass A { void F(List<int> xs) { _ = xs.Count; } }\n"),
            [Some("System.Int32".into())]
        );
        // A file importing System itself is from a project without them,
        // and a third-party namespace could declare List: unknown.
        assert_eq!(
            discards(
                "using System;\nusing Vendor.Collections;\nnamespace N;\nclass A { void F(List<int> xs) { _ = xs.Count; } }\n"
            ),
            [None]
        );
        // One importing none of their namespaces uses them.
        assert_eq!(
            discards(
                "using Vendor.Collections;\nnamespace N;\nclass A { void F(List<int> xs, object o) { _ = xs.Count; _ = o.ToString().Length; } }\n"
            ),
            [Some("System.Int32".into()), Some("System.Int32".into())]
        );
        // A type the file declares shadows the platform's.
        assert_eq!(
            discards(
                "namespace N;\nclass List<T> { public string Count; }\nclass A { void F(List<int> xs) { _ = xs.Count; } }\n"
            ),
            [Some("System.String".into())]
        );
    }

    #[test]
    fn local_types_and_their_platform_bases() {
        let src = "using System.Collections.Generic;\nclass Bag : List<string> { public int Extra() => 1; }\nclass A { void F(Bag b) { _ = b.Extra(); _ = b[0]; _ = this; } }\n";
        assert_eq!(
            discards(src),
            [
                Some("System.Int32".into()),
                Some("System.String".into()),
                Some("A`0".into())
            ]
        );
    }
}
