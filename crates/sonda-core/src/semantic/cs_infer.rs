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
//! the file imports. Conversions between types are classified as C# does
//! (identity, implicit, explicit, through a conversion operator), and
//! arithmetic follows its numeric promotion. When any step can't tell, the
//! answer is None: rules then report nothing, which costs recall only.
//!
//! What it doesn't see: types declared in other files of the project, which
//! could shadow a platform type of the same name in the same namespace.

mod resolve;
mod usings;

pub(crate) use resolve::{Arg, Bound, Constant, Param, arguments};

use super::dotnet::{self, Platform, PlatformMember, PlatformType};
use super::{DeclKind, Model, ScopeId};
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

/// A type: a platform one by key, or one this file declares.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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

/// The numeric types, by key, that a value of this numeric type converts to
/// implicitly; None for a type that isn't numeric.
fn widens_to(key: &str) -> Option<&'static [&'static str]> {
    const DECIMAL: &str = "System.Decimal";
    const DOUBLE: &str = "System.Double";
    const SINGLE: &str = "System.Single";
    const INT64: &str = "System.Int64";
    const UINT64: &str = "System.UInt64";
    const INT32: &str = "System.Int32";
    const UINT32: &str = "System.UInt32";
    const NINT: &str = "System.IntPtr";
    const NUINT: &str = "System.UIntPtr";
    Some(match key {
        "System.SByte" => &["System.Int16", INT32, INT64, SINGLE, DOUBLE, DECIMAL, NINT],
        "System.Byte" => &[
            "System.Int16",
            "System.UInt16",
            INT32,
            UINT32,
            INT64,
            UINT64,
            SINGLE,
            DOUBLE,
            DECIMAL,
            NINT,
            NUINT,
        ],
        "System.Int16" => &[INT32, INT64, SINGLE, DOUBLE, DECIMAL, NINT],
        "System.UInt16" | "System.Char" => &[
            "System.UInt16",
            INT32,
            UINT32,
            INT64,
            UINT64,
            SINGLE,
            DOUBLE,
            DECIMAL,
            NINT,
            NUINT,
        ],
        INT32 => &[INT64, SINGLE, DOUBLE, DECIMAL, NINT],
        UINT32 => &[INT64, UINT64, SINGLE, DOUBLE, DECIMAL, NUINT],
        INT64 | UINT64 => &[SINGLE, DOUBLE, DECIMAL],
        NINT => &[INT64, SINGLE, DOUBLE, DECIMAL],
        NUINT => &[UINT64, SINGLE, DOUBLE, DECIMAL],
        SINGLE => &[DOUBLE],
        DOUBLE | DECIMAL => &[],
        _ => return None,
    })
}

/// The type both operands of an arithmetic operator are promoted to, as
/// C#'s binary numeric promotion does; None when it's an error or not
/// numeric.
fn promoted(a: &str, b: &str) -> Option<&'static str> {
    const SIGNED: &[&str] = &[
        "System.SByte",
        "System.Int16",
        "System.Int32",
        "System.Int64",
    ];
    const INTEGRAL: &[&str] = &[
        "System.SByte",
        "System.Byte",
        "System.Int16",
        "System.UInt16",
        "System.Char",
        "System.Int32",
        "System.UInt32",
        "System.Int64",
        "System.UInt64",
    ];
    let floating = |k: &str| matches!(k, "System.Single" | "System.Double");
    let numeric = |k: &str| INTEGRAL.contains(&k) || floating(k) || k == "System.Decimal";
    if !numeric(a) || !numeric(b) {
        return None;
    }
    let either = |k: &str| a == k || b == k;
    Some(if either("System.Decimal") {
        if floating(a) || floating(b) {
            return None;
        }
        "System.Decimal"
    } else if either("System.Double") {
        "System.Double"
    } else if either("System.Single") {
        "System.Single"
    } else if either("System.UInt64") {
        if SIGNED.contains(&a) || SIGNED.contains(&b) {
            return None;
        }
        "System.UInt64"
    } else if either("System.Int64") {
        "System.Int64"
    } else if either("System.UInt32") {
        if ["System.SByte", "System.Int16", "System.Int32"]
            .iter()
            .any(|s| either(s))
        {
            "System.Int64"
        } else {
            "System.UInt32"
        }
    } else {
        "System.Int32"
    })
}

/// The type an operand of a unary operator or a shift is promoted to:
/// integral types narrower than int become int.
fn unary_promoted(key: &str) -> Option<&'static str> {
    Some(match key {
        "System.SByte" | "System.Byte" | "System.Int16" | "System.UInt16" | "System.Char"
        | "System.Int32" => "System.Int32",
        "System.UInt32" => "System.UInt32",
        "System.Int64" => "System.Int64",
        "System.UInt64" => "System.UInt64",
        "System.Single" => "System.Single",
        "System.Double" => "System.Double",
        "System.Decimal" => "System.Decimal",
        _ => return None,
    })
}

/// How a value of one type converts to another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Conversion {
    Identity,
    /// To a base class or an implemented interface, boxing, a numeric
    /// widening, or to a nullable: what C# does without a cast.
    Implicit,
    /// What only a cast does, built into the language: a downcast,
    /// unboxing, a numeric narrowing.
    Explicit,
    /// Through a conversion operator one of the types declares.
    UserDefined,
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

/// What a file declares and imports, read once per file and kept with
/// its semantic model.
pub(crate) struct Context<'t> {
    usings: Vec<String>,
    /// Whether the SDK's implicit usings may resolve a name.
    implicit: bool,
    /// Namespace bodies: (start byte, end byte, name).
    namespaces: Vec<(usize, usize, String)>,
    /// Types by name and arity (`Order`0`); None when declared twice.
    locals: HashMap<String, Option<LocalType<'t>>>,
    type_params: HashSet<String>,
}

pub(crate) struct Infer<'m, 't> {
    m: &'m Model<'t>,
    src: &'m [u8],
    platform: &'static Platform,
    cx: &'m Context<'t>,
}

impl<'t> std::ops::Deref for Infer<'_, 't> {
    type Target = Context<'t>;

    fn deref(&self) -> &Context<'t> {
        self.cx
    }
}

impl<'m, 't> Infer<'m, 't> {
    pub(crate) fn new(m: &'m Model<'t>, src: &'m [u8]) -> Option<Infer<'m, 't>> {
        let cx = m
            .cs_context
            .get_or_init(|| Context::read(m, src))
            .as_ref()?;
        Some(Infer {
            m,
            src,
            platform: dotnet::platform(),
            cx,
        })
    }
}

impl<'t> Context<'t> {
    fn read(m: &Model<'t>, src: &[u8]) -> Option<Context<'t>> {
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
        Some(Context {
            usings,
            implicit,
            namespaces,
            locals,
            type_params,
        })
    }
}

impl<'m, 't> Infer<'m, 't> {
    fn text(&self, n: Node) -> &'m str {
        n.utf8_text(self.src).unwrap_or_default()
    }

    /// Whether a namespace's types are in scope by their simple names at
    /// `byte`: imported with a `using` directive, or enclosing it.
    pub(crate) fn in_scope(&self, namespace: &str, byte: usize) -> bool {
        self.usings.iter().any(|u| u == namespace)
            || self.namespaces.iter().any(|(s, e, ns)| {
                *s <= byte
                    && byte < *e
                    && (ns == namespace || ns.starts_with(&format!("{namespace}.")))
            })
    }

    /// Whether the file declares a type, or a type parameter, named `name`.
    pub(crate) fn declares(&self, name: &str) -> bool {
        self.type_params.contains(name)
            || self
                .locals
                .keys()
                .any(|k| k.split('`').next() == Some(name))
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

    /// Whether a type is an interface, as far as declarations tell.
    pub(crate) fn interface(&self, ty: &Ty) -> Option<bool> {
        match ty {
            Ty::Array(_) => Some(false),
            Ty::Named {
                key, local: false, ..
            } => self.platform.get(key).map(|t| t.kind == "interface"),
            Ty::Named {
                key, local: true, ..
            } => self
                .locals
                .get(key)
                .copied()
                .flatten()
                .map(|l| l.node.kind() == "interface_declaration"),
            _ => None,
        }
    }

    /// Whether every base a type lists, and theirs, resolves: what its
    /// supertypes leave out otherwise is unknown, not absent.
    pub(crate) fn complete(&self, ty: &Ty) -> bool {
        self.supertypes(ty).iter().all(|t| match t {
            Ty::Named {
                key, local: true, ..
            } => {
                let Some(local) = self.locals.get(key).copied().flatten() else {
                    return false;
                };
                local
                    .node
                    .named_children(&mut local.node.walk())
                    .filter(|c| c.kind() == "base_list")
                    .all(|bases| {
                        bases.named_children(&mut bases.walk()).all(|b| {
                            let b = if b.kind() == "primary_constructor_base_type" {
                                b.named_child(0)
                            } else {
                                Some(b)
                            };
                            b.and_then(|b| self.written(b)).is_some()
                        })
                    })
            }
            Ty::Named { local: false, .. } | Ty::Array(_) => true,
            _ => false,
        })
    }

    /// Whether a type's base classes all resolve. Only the first type a
    /// base list names can be a class; the others are interfaces, whose
    /// members a class's own code can't name without a receiver.
    pub(crate) fn base_classes_known(&self, ty: &Ty) -> bool {
        self.supertypes(ty).iter().all(|t| match t {
            Ty::Named {
                key, local: true, ..
            } => {
                let Some(local) = self.locals.get(key).copied().flatten() else {
                    return false;
                };
                if local.node.kind() == "interface_declaration" {
                    return true;
                }
                let first = local
                    .node
                    .named_children(&mut local.node.walk())
                    .find(|c| c.kind() == "base_list")
                    .and_then(|b| b.named_child(0));
                first.is_none_or(|b| {
                    let b = if b.kind() == "primary_constructor_base_type" {
                        b.named_child(0)
                    } else {
                        Some(b)
                    };
                    b.and_then(|b| self.written(b)).is_some()
                })
            }
            Ty::Named { local: false, .. } | Ty::Array(_) => true,
            _ => false,
        })
    }

    /// How a value of type `from` converts to `to`; None when declarations
    /// don't tell, or when C# wouldn't allow it.
    pub(crate) fn conversion(&self, from: &Ty, to: &Ty) -> Option<Conversion> {
        if !settled(from) || !settled(to) {
            return None;
        }
        if from == to {
            return Some(Conversion::Identity);
        }
        if let (Some(f), Some(t)) = (from.key(), to.key())
            && let Some(wider) = widens_to(f)
            && widens_to(t).is_some()
        {
            return Some(if wider.contains(&t) {
                Conversion::Implicit
            } else {
                Conversion::Explicit
            });
        }
        const NULLABLE: &str = "System.Nullable`1";
        match (from.is(NULLABLE), to.is(NULLABLE)) {
            (false, true) => {
                return match self.conversion(from, to.args().first()?)? {
                    Conversion::Identity | Conversion::Implicit => Some(Conversion::Implicit),
                    other => Some(other),
                };
            }
            (true, true) => {
                return match self.conversion(from.args().first()?, to.args().first()?)? {
                    Conversion::Identity => Some(Conversion::Identity),
                    other => Some(other),
                };
            }
            (true, false) if from.args().first() == Some(to) => {
                return Some(Conversion::Explicit);
            }
            _ => {}
        }
        if to.is("System.Object") {
            return Some(Conversion::Implicit);
        }
        if !self.complete(from) || !self.complete(to) {
            return None;
        }
        let up = self.supertypes(from);
        if up.contains(to) {
            return Some(Conversion::Implicit);
        }
        // `IEnumerable<string>` to `IEnumerable<object>`: variance, which
        // the declarations here don't record, of interfaces and delegates.
        if up.iter().any(|s| s.key().is_some() && s.key() == to.key())
            && (self.interface(to) != Some(false) || self.delegate(to))
        {
            return None;
        }
        if let (Ty::Array(a), Ty::Array(b)) = (from, to) {
            return match self.conversion(a, b)? {
                Conversion::Implicit if self.value_type(a) == Some(false) => {
                    Some(Conversion::Implicit)
                }
                Conversion::Implicit | Conversion::Explicit
                    if self.value_type(a) == Some(false) && self.value_type(b) == Some(false) =>
                {
                    Some(Conversion::Explicit)
                }
                _ => None,
            };
        }
        let down = self.supertypes(to).contains(from);
        let enum_number =
            |a: &Ty, b: &Ty| self.kind(a) == Some("enum") && b.key().and_then(widens_to).is_some();
        let interface_class = |a: &Ty, b: &Ty| {
            self.interface(a) == Some(true)
                && (self.interface(b) == Some(true)
                    || (self.value_type(b) == Some(false) && !self.sealed(b)))
        };
        if down
            || enum_number(from, to)
            || enum_number(to, from)
            || interface_class(from, to)
            || interface_class(to, from)
        {
            return Some(Conversion::Explicit);
        }
        // C# allows no conversion operator between types related otherwise.
        self.user_conversion(from, to, false)
            .then_some(Conversion::UserDefined)
    }

    /// A platform type's kind, or a local one's: "class", "struct",
    /// "interface", "enum" or "delegate".
    fn kind(&self, ty: &Ty) -> Option<&str> {
        match ty {
            Ty::Named {
                key, local: false, ..
            } => self.platform.get(key).map(|t| t.kind.as_str()),
            Ty::Named {
                key, local: true, ..
            } => {
                let l = self.locals.get(key).copied().flatten()?;
                Some(match l.node.kind() {
                    "struct_declaration" | "record_struct_declaration" => "struct",
                    "interface_declaration" => "interface",
                    "enum_declaration" => "enum",
                    "delegate_declaration" => "delegate",
                    _ => "class",
                })
            }
            _ => None,
        }
    }

    /// Whether a type is a delegate type.
    pub(crate) fn delegate(&self, ty: &Ty) -> bool {
        self.kind(ty) == Some("delegate")
    }

    fn sealed(&self, ty: &Ty) -> bool {
        match ty {
            Ty::Named {
                key, local: false, ..
            } => self
                .platform
                .get(key)
                .is_some_and(|t| t.has("sealed") || t.has("static")),
            Ty::Named {
                key, local: true, ..
            } => self.locals.get(key).copied().flatten().is_some_and(|l| {
                l.node
                    .children(&mut l.node.walk())
                    .any(|c| c.kind() == "modifier" && matches!(self.text(c), "sealed" | "static"))
            }),
            _ => false,
        }
    }

    /// Whether `from` or `to`, or a base class of either, declares a
    /// conversion operator from one to the other; an implicit one only, if
    /// `implicit`.
    fn user_conversion(&self, from: &Ty, to: &Ty, implicit: bool) -> bool {
        let names: &[&str] = if implicit {
            &["op_Implicit"]
        } else {
            &["op_Implicit", "op_Explicit"]
        };
        // Through a standard implicit conversion on either side.
        let standard = |a: &Ty, b: &Ty| {
            a == b
                || self.supertypes(a).contains(b)
                || a.key()
                    .and_then(widens_to)
                    .is_some_and(|w| b.key().is_some_and(|k| w.contains(&k)))
        };
        // Types not fully known compare by their definitions.
        let converts = |a: &Ty, b: &Ty| {
            if settled(a) && settled(b) {
                standard(a, b)
            } else {
                a.key().is_some() && a.key() == b.key()
            }
        };
        let fits = |ret: Option<Ty>, param: Option<Ty>| {
            ret.is_some_and(|r| converts(&r, to)) && param.is_some_and(|p| converts(from, &p))
        };
        [from, to].iter().any(|t| {
            self.supertypes(t).iter().any(|s| match s {
                Ty::Named {
                    key,
                    args,
                    local: false,
                } => self.platform.get(key).is_some_and(|p| {
                    p.members.iter().any(|m| {
                        names.contains(&m.name.as_str())
                            && fits(
                                Ty::parse(&m.ty).map(|t| t.substitute(args, &[])),
                                m.params
                                    .first()
                                    .and_then(|p| Ty::parse(&p.ty))
                                    .map(|t| t.substitute(args, &[])),
                            )
                    })
                }),
                Ty::Named {
                    key, local: true, ..
                } => self.locals.get(key).copied().flatten().is_some_and(|l| {
                    let Some(body) = l.node.child_by_field_name("body") else {
                        return false;
                    };
                    body.named_children(&mut body.walk())
                        .filter(|c| c.kind() == "conversion_operator_declaration")
                        .filter(|c| {
                            !implicit || c.children(&mut c.walk()).any(|k| k.kind() == "implicit")
                        })
                        .any(|c| {
                            let param = c
                                .child_by_field_name("parameters")
                                .and_then(|p| p.named_child(0))
                                .and_then(|p| p.child_by_field_name("type"));
                            fits(
                                c.child_by_field_name("type").and_then(|t| self.written(t)),
                                param.and_then(|p| self.written(p)),
                            )
                        })
                }),
                _ => false,
            })
        })
    }

    /// Whether a class, or one of its base classes but Object, overrides
    /// `Equals(object)`: None when its bases don't all resolve.
    pub(crate) fn overrides_equals(&self, ty: &Ty) -> Option<bool> {
        if !self.complete(ty) {
            return None;
        }
        Some(self.supertypes(ty).iter().any(|s| {
            match s {
                Ty::Named {
                    key, local: false, ..
                } => {
                    key != "System.Object"
                        && self.platform.get(key).is_some_and(|p| {
                            p.kind != "interface"
                                && p.members.iter().any(|m| {
                                    m.kind == "method"
                                        && m.name == "Equals"
                                        && !m.has("static")
                                        && m.params.len() == 1
                                        && m.params[0].ty == "System.Object"
                                })
                        })
                }
                Ty::Named {
                    key, local: true, ..
                } => self
                    .locals
                    .get(key)
                    .copied()
                    .flatten()
                    .and_then(|l| l.members)
                    .is_some_and(|scope| {
                        self.m.decls_named(scope, "Equals").iter().any(|&d| {
                            let d = &self.m.decls[d];
                            d.kind == DeclKind::Method
                                && d.declarator.is_some_and(|m| {
                                    m.child_by_field_name("parameters")
                                        .is_some_and(|p| p.named_child_count() == 1)
                                        && self.text(m).contains("override")
                                })
                        })
                    }),
                _ => false,
            }
        }))
    }

    /// Whether a type, or a base class, declares `operator ==`, or is a
    /// record, whose compiler-made one compares values.
    pub(crate) fn has_equality_operator(&self, ty: &Ty) -> bool {
        self.supertypes(ty).iter().any(|s| match s {
            Ty::Named {
                key, local: false, ..
            } => self
                .platform
                .get(key)
                .is_some_and(|p| p.members.iter().any(|m| m.name == "op_Equality")),
            Ty::Named {
                key, local: true, ..
            } => self.locals.get(key).copied().flatten().is_some_and(|l| {
                matches!(
                    l.node.kind(),
                    "record_declaration" | "record_struct_declaration"
                ) || l.node.child_by_field_name("body").is_some_and(|b| {
                    b.named_children(&mut b.walk()).any(|c| {
                        c.kind() == "operator_declaration"
                            && c.child_by_field_name("operator")
                                .is_some_and(|o| self.text(o) == "==")
                    })
                })
            }),
            _ => false,
        })
    }

    /// Whether some class or struct implementing this interface overrides
    /// `Equals`: one of the platform's, or one this file declares.
    pub(crate) fn implemented_with_equals(&self, interface: &Ty) -> bool {
        if interface
            .key()
            .is_some_and(|k| self.platform.equality_interfaces().contains(k))
        {
            return true;
        }
        let Some(key) = (match interface {
            Ty::Named { key, .. } => Some(key),
            _ => None,
        }) else {
            return false;
        };
        self.locals.iter().any(|(name, local)| {
            let Some(l) = local else {
                return false;
            };
            if !matches!(l.node.kind(), "class_declaration" | "struct_declaration") {
                return false;
            }
            let ty = Ty::Named {
                key: name.clone(),
                args: Vec::new(),
                local: true,
            };
            self.supertypes(&ty)
                .iter()
                .any(|s| matches!(s, Ty::Named { key: k, .. } if k == key))
                && self.overrides_equals(&ty) == Some(true)
        })
    }

    /// Whether a name used in a member of type `ty` is an instance member it
    /// inherits from a base class: None when its base classes don't all
    /// resolve.
    pub(crate) fn inherited_instance_member(&self, ty: &Ty, name: &str) -> Option<bool> {
        if !self.base_classes_known(ty) {
            return None;
        }
        Some(self.supertypes(ty).iter().skip(1).any(|s| {
            match s {
                Ty::Named {
                    key, local: false, ..
                } => self.platform.get(key).is_some_and(|p| {
                    p.kind != "interface"
                        && p.members
                            .iter()
                            .any(|m| m.name == name && !m.has("static") && !m.has("const"))
                }),
                Ty::Named {
                    key, local: true, ..
                } => self
                    .locals
                    .get(key)
                    .copied()
                    .flatten()
                    .and_then(|l| l.members)
                    .is_some_and(|scope| {
                        self.m
                            .decls_named(scope, name)
                            .iter()
                            .any(|&d| !self.m.decls[d].is_static)
                    }),
                _ => false,
            }
        }))
    }

    /// Whether an interface `ty` implements, through its bases, declares a
    /// member named `name`: None when its bases don't all resolve.
    pub(crate) fn interface_declares(&self, ty: &Ty, name: &str) -> Option<bool> {
        if !self.complete(ty) {
            return None;
        }
        Some(self.supertypes(ty).iter().any(|s| {
            self.interface(s) == Some(true)
                && match s {
                    Ty::Named {
                        key, local: false, ..
                    } => self
                        .platform
                        .get(key)
                        .is_some_and(|p| p.members.iter().any(|m| m.name == name)),
                    Ty::Named {
                        key, local: true, ..
                    } => self
                        .locals
                        .get(key)
                        .copied()
                        .flatten()
                        .and_then(|l| l.members)
                        .is_some_and(|scope| !self.m.decls_named(scope, name).is_empty()),
                    _ => false,
                }
        }))
    }

    // ------------------------------------------------ supertypes and members

    /// A type, its base classes and the interfaces it implements, with
    /// their type arguments, nearest first and base classes before
    /// interfaces.
    pub(crate) fn supertypes(&self, ty: &Ty) -> Vec<Ty> {
        if let Some(s) = self.m.cs_supertypes.borrow().get(ty) {
            return s.clone();
        }
        let s = self.find_supertypes(ty);
        self.m
            .cs_supertypes
            .borrow_mut()
            .insert(ty.clone(), s.clone());
        s
    }

    fn find_supertypes(&self, ty: &Ty) -> Vec<Ty> {
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

    /// A member's parameter types and its type, with the declaring type's
    /// arguments substituted: what a call or access through another type
    /// must find the same to mean the same.
    pub(crate) fn signature(&self, found: &Found) -> Option<(Vec<Ty>, Ty)> {
        match found {
            Found::Platform { member, vars, .. } => {
                let params = member
                    .params
                    .iter()
                    .map(|p| Ty::parse(&p.ty).map(|t| t.substitute(vars, &[])))
                    .collect::<Option<Vec<_>>>()?;
                let ty = Ty::parse(&member.ty).map_or(Ty::Unknown, |t| t.substitute(vars, &[]));
                Some((params, ty))
            }
            Found::Local(d) => {
                let declarator = d.declarator?;
                let params = match declarator.child_by_field_name("parameters") {
                    Some(list) => list
                        .named_children(&mut list.walk())
                        .filter(|p| p.kind() == "parameter")
                        .map(|p| p.child_by_field_name("type").and_then(|t| self.written(t)))
                        .collect::<Option<Vec<_>>>()?,
                    None => Vec::new(),
                };
                let ty = declarator
                    .child_by_field_name("returns")
                    .or(d.ty)
                    .and_then(|t| self.written(t))?;
                Some((params, ty))
            }
        }
    }

    /// The extension methods a call `receiver.name(...)` with `arguments`
    /// arguments, at `byte`, may bind to.
    pub(crate) fn extension_methods(
        &self,
        receiver: &Ty,
        name: &str,
        arguments: usize,
        byte: usize,
    ) -> Vec<&'static PlatformMember> {
        self.extensions(receiver, name, arguments, byte)
            .into_iter()
            .filter_map(|(f, _)| match f {
                Found::Platform { member, .. } => Some(member),
                Found::Local(_) => None,
            })
            .collect()
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
        if let Some(t) = self.m.cs_types.borrow().get(&expr.id()) {
            return t.clone();
        }
        let t = self.typed(expr, 0);
        self.m.cs_types.borrow_mut().insert(expr.id(), t.clone());
        t
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
                // `nameof(x)`, unless a method of that name is declared.
                if let Some(f) = expr.child_by_field_name("function")
                    && f.kind() == "identifier"
                    && self.text(f) == "nameof"
                    && self.m.decl_of(f).is_none()
                {
                    return string();
                }
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
                    "+" | "-" | "*" | "/" | "%" | "&" | "|" | "^" => {
                        let (a, b) = (self.typed(l, d)?, self.typed(r, d)?);
                        let bool_key = "System.Boolean";
                        if matches!(op, "&" | "|" | "^") && a.is(bool_key) && b.is(bool_key) {
                            return Some(a);
                        }
                        let key = promoted(a.key()?, b.key()?)?;
                        let floating = ["System.Single", "System.Double", "System.Decimal"];
                        if matches!(op, "&" | "|" | "^") && floating.contains(&key) {
                            return None;
                        }
                        Some(Ty::platform(key, Vec::new()))
                    }
                    "<<" | ">>" | ">>>" => {
                        let a = self.typed(l, d)?;
                        let key = unary_promoted(a.key()?)?;
                        matches!(
                            key,
                            "System.Int32" | "System.UInt32" | "System.Int64" | "System.UInt64"
                        )
                        .then(|| Ty::platform(key, Vec::new()))
                    }
                    _ => None,
                }
            }
            "prefix_unary_expression" => {
                let operand = expr.named_child(0)?;
                let op = self.text(expr).trim_start();
                if op.starts_with('!') {
                    return Some(Ty::platform("System.Boolean", Vec::new()));
                }
                let t = self.typed(operand, d)?;
                let key = t.key()?;
                if op.starts_with("++") || op.starts_with("--") {
                    return widens_to(key).map(|_| t.clone());
                }
                if op.starts_with('-') {
                    // -uint is a long, -ulong an error.
                    return match key {
                        "System.UInt32" => Some(Ty::platform("System.Int64", Vec::new())),
                        "System.UInt64" => None,
                        _ => unary_promoted(key).map(|k| Ty::platform(k, Vec::new())),
                    };
                }
                if op.starts_with('+') {
                    return unary_promoted(key).map(|k| Ty::platform(k, Vec::new()));
                }
                if op.starts_with('~') {
                    return unary_promoted(key)
                        .filter(|k| {
                            !matches!(*k, "System.Single" | "System.Double" | "System.Decimal")
                        })
                        .map(|k| Ty::platform(k, Vec::new()));
                }
                None
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

/// Whether a type is fully known: no type parameter or unknown argument
/// anywhere in it.
fn settled(t: &Ty) -> bool {
    match t {
        Ty::Named { args, .. } => args.iter().all(settled),
        Ty::Array(e) => settled(e),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lang::Lang;

    pub(super) fn with_infer(src: &str, f: impl FnOnce(&Infer, Node)) {
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

    pub(super) fn render(t: &Ty) -> String {
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

    #[test]
    fn numeric_promotion() {
        let src = "class A { void F(int i, long l, uint u, ulong ul, byte b, float f, double d, decimal m) {\n\
            _ = i + 42;\n_ = l * i;\n_ = -u;\n_ = b << 2;\n_ = f + d;\n_ = m + d;\n_ = ul + i;\n_ = u + i;\n_ = b + b;\n} }\n";
        assert_eq!(
            discards(src),
            [
                Some("System.Int32".into()),
                Some("System.Int64".into()),
                Some("System.Int64".into()),
                Some("System.Int32".into()),
                Some("System.Double".into()),
                // decimal and double don't mix, nor ulong and int.
                None,
                None,
                Some("System.Int64".into()),
                Some("System.Int32".into()),
            ]
        );
    }

    #[test]
    fn conversions() {
        let src = "using System;\nusing System.Collections.Generic;\nclass Fruit { }\nclass Orange : Fruit { }\nstruct Money { public static explicit operator Money(int v) => default; }\n\
            class A { void F(int i, long l, object o, string s, IComparable c, List<string> ls, IEnumerable<string> es, IEnumerable<object> eo, Fruit f, Orange g, Money m, int? n, DayOfWeek day, IDisposable dis) { } }\n";
        with_infer(src, |infer, root| {
            let mut types = HashMap::new();
            let mut stack = vec![root];
            while let Some(n) = stack.pop() {
                if n.kind() == "parameter" {
                    let name = n.child_by_field_name("name").unwrap();
                    let ty = n.child_by_field_name("type").unwrap();
                    types.insert(
                        name.utf8_text(src.as_bytes()).unwrap().to_string(),
                        infer.written(ty).unwrap(),
                    );
                }
                stack.extend(n.named_children(&mut n.walk()));
            }
            let c = |a: &str, b: &str| infer.conversion(&types[a], &types[b]);
            use Conversion::*;
            assert_eq!(c("i", "i"), Some(Identity));
            assert_eq!(c("i", "l"), Some(Implicit));
            assert_eq!(c("l", "i"), Some(Explicit));
            assert_eq!(c("i", "n"), Some(Implicit));
            assert_eq!(c("n", "i"), Some(Explicit));
            assert_eq!(c("i", "o"), Some(Implicit));
            assert_eq!(c("o", "s"), Some(Explicit));
            assert_eq!(c("s", "c"), Some(Implicit));
            assert_eq!(c("c", "s"), Some(Explicit));
            assert_eq!(c("ls", "es"), Some(Implicit));
            assert_eq!(c("g", "f"), Some(Implicit));
            assert_eq!(c("f", "g"), Some(Explicit));
            assert_eq!(c("i", "m"), Some(UserDefined));
            assert_eq!(c("day", "i"), Some(Explicit));
            assert_eq!(c("dis", "f"), Some(Explicit));
            // Variance isn't recorded: unknown, not explicit.
            assert_eq!(c("es", "eo"), None);
        });
    }
}
