//! C# rules that compare a declaration with declarations in other files of
//! the project (ADR-0020): an override with the method it overrides, a
//! method with the interface member it implements, a class with its base
//! classes. They run once per scan, on the project index the files'
//! summaries build (`semantic::cs_index`), and are `Check::Structural` in
//! the catalog. Their rules are declared with the other class rules; this
//! module holds their checks.

use crate::semantic::cs_index::{
    FACT, FileIndex, MemberDecl, ParamDecl, ProjectIndex, Site, Span, TypeDecl, TypeId, TypeRef,
};
use crate::semantic::dotnet::{self, PlatformType};

const DISPOSABLE: &str = "System.IDisposable";

/// A finding: the rule, the index of the file it's in, and where.
pub(crate) type Finding = (&'static str, usize, Span);

/// The rules this module checks.
pub(crate) const RULES: &[&str] = &[
    "cs/deep-inheritance",
    "cs/parameter-name-mismatch",
    "cs/override-changes-default",
    "cs/override-without-params",
    "cs/override-adds-params",
    "cs/hiding-member-less-visible",
    "cs/base-method-hidden",
    "cs/interface-colliding-members",
    "cs/field-differs-from-base-by-case",
    "cs/dispose-pattern",
    "cs/bitwise-on-non-flags-enum",
    "cs/array-for-params",
    "cs/shared-part-created-with-new",
    "cs/extension-in-same-namespace",
    "cs/durable-entity-interface",
    "cs/underposting-value-type",
    "cs/disposable-fields-without-idisposable",
    "cs/interface-downcast",
];

/// The findings of the rules `active` lists, for files given as their
/// facts. Files without a C# index are skipped.
pub(crate) fn run<'f>(
    facts: impl Iterator<Item = &'f [(String, String)]>,
    active: &[&str],
) -> Vec<Finding> {
    if !RULES.iter().any(|r| active.contains(r)) {
        return Vec::new();
    }
    // (position in the scanner's list, the file's summary)
    let parsed: Vec<(usize, FileIndex)> = crate::semantic::summaries(facts, FACT);
    let index = ProjectIndex::new(parsed.iter().map(|(_, x)| x).collect());
    let mut found: Vec<Finding> = Vec::new();
    let on = |rule: &str| active.contains(&rule);
    for id in 0..index.len() {
        let (_, decl) = index.decl(id);
        match decl.kind.as_str() {
            "class" | "struct" | "record" => type_rules(&index, id, &decl.kind, &on, &mut found),
            "interface" if on("cs/interface-colliding-members") => {
                colliding_members(&index, id, &mut found)
            }
            _ => {}
        }
    }
    uses(&index, &on, &mut found);
    found
        .into_iter()
        .map(|(rule, file, span)| (rule, parsed[file].0, span))
        .collect()
}

/// Lines an assembly-level `[SuppressMessage]` silences, for each of
/// `targets` given as (scope, target): (its position in `targets`, the file
/// in the scanner's list, first line, last line). Targets are documentation
/// IDs, `~M:Ns.Type.Method(System.Int32)`; a type covers all its parts, a
/// member all overloads with its name and number of parameters, and
/// "module" without a target the whole project. "namespace" scope only
/// silences the namespace declaration itself, which rules don't report on.
pub(crate) fn targeted_regions<'f>(
    facts: impl Iterator<Item = &'f [(String, String)]>,
    targets: &[(&str, &str)],
) -> Vec<(usize, usize, usize, usize)> {
    if targets.is_empty() {
        return Vec::new();
    }
    let all: Vec<&[(String, String)]> = facts.collect();
    let parsed: Vec<(usize, FileIndex)> = all
        .iter()
        .enumerate()
        .filter_map(|(i, f)| {
            let (_, json) = f.iter().find(|(k, _)| k == FACT)?;
            serde_json::from_str(json).ok().map(|x| (i, x))
        })
        .collect();
    let index = ProjectIndex::new(parsed.iter().map(|(_, x)| x).collect());
    let files: Vec<usize> = parsed.iter().map(|(i, _)| *i).collect();
    let mut out = Vec::new();
    for (n, (scope, target)) in targets.iter().enumerate() {
        let target = target.trim().trim_start_matches('~');
        let (prefix, name) = target.split_once(':').unwrap_or(("", target));
        if target.is_empty() {
            if *scope == "module" {
                out.extend((0..all.len()).map(|file| (n, file, 1, usize::MAX)));
            }
            continue;
        }
        let regions = match (prefix, *scope) {
            ("T", _) | ("", "type") => type_regions(&index, name),
            ("N", "namespaceanddescendants") | ("", "namespaceanddescendants") => {
                namespace_regions(&index, name)
            }
            ("M" | "P" | "F" | "E", _) | ("", "member") => member_regions(&index, prefix, name),
            _ => Vec::new(),
        };
        out.extend(
            regions
                .into_iter()
                .map(|(file, start, end)| (n, files[file], start, end)),
        );
    }
    out
}

/// (file of the index, first line, last line) of a type's parts.
type Regions = Vec<(usize, usize, usize)>;

/// The parts of the type `name`.
fn type_regions(index: &ProjectIndex, name: &str) -> Regions {
    let Some(id) = index.type_named(&doc_type_name(name)) else {
        return Vec::new();
    };
    index
        .parts(id)
        .iter()
        .map(|(file, t)| (*file, t.lines.0, t.lines.1))
        .collect()
}

/// The top-level types of the namespace `name` and those inside it.
fn namespace_regions(index: &ProjectIndex, name: &str) -> Regions {
    let mut out = Vec::new();
    for id in 0..index.len() {
        for (file, t) in index.parts(id) {
            let ns = &t.namespace;
            let inside = ns == name || ns.strip_prefix(name).is_some_and(|r| r.starts_with('.'));
            if inside && t.outer.is_empty() {
                out.push((*file, t.lines.0, t.lines.1));
            }
        }
    }
    out
}

/// The members a documentation ID names: by name (and, for a method, by
/// its number of parameters), a constructor, a static constructor or a
/// finalizer.
fn member_regions(index: &ProjectIndex, prefix: &str, name: &str) -> Regions {
    // Parameters, then the return type of a conversion operator.
    let (path, params) = match name.split_once('(') {
        Some((path, rest)) => (path, Some(rest.split(')').next().unwrap_or(""))),
        None => (name, None),
    };
    let path = path.split('~').next().unwrap_or(path);
    let Some((owner, member)) = path.rsplit_once('.') else {
        return Vec::new();
    };
    // Explicit implementations: `Ns#IStore#Save`.
    let member = member.rsplit('#').next().unwrap_or(member);
    let member = member.split('`').next().unwrap_or(member);
    let arity = params.map(doc_param_count);
    let Some(id) = index.type_named(&doc_type_name(owner)) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (file, t) in index.parts(id) {
        for m in &t.members {
            let named = match path.rsplit('.').next() {
                Some("#ctor") => m.kind == "constructor" && !m.has("static"),
                Some("#cctor") => m.kind == "constructor" && m.has("static"),
                Some("Finalize") if m.kind == "destructor" => true,
                _ => m.name == member,
            };
            let fits = prefix != "M" || arity.unwrap_or(0) == m.params.len();
            if named && fits {
                out.push((*file, m.lines.0, m.lines.1));
            }
        }
    }
    out
}

/// A documentation ID's type name as `TypeDecl::full_name` writes it:
/// enclosing types without their arity, the type with it.
fn doc_type_name(name: &str) -> String {
    let segments: Vec<&str> = name.split('.').collect();
    let mut parts: Vec<String> = segments[..segments.len() - 1]
        .iter()
        .map(|s| s.split('`').next().unwrap_or(s).to_string())
        .collect();
    let last = segments[segments.len() - 1];
    parts.push(if last.contains('`') {
        last.to_string()
    } else {
        format!("{last}`0")
    });
    parts.join(".")
}

/// The number of parameters in a documentation ID's parameter list, whose
/// generic arguments are in braces: `System.Collections.Generic.List{System.Int32},System.String`.
fn doc_param_count(params: &str) -> usize {
    if params.trim().is_empty() {
        return 0;
    }
    let mut depth = 0i32;
    let mut count = 1;
    for c in params.chars() {
        match c {
            '{' | '[' => depth += 1,
            '}' | ']' => depth -= 1,
            ',' if depth == 0 => count += 1,
            _ => {}
        }
    }
    count
}

fn looks_like_interface(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next() == Some('I') && chars.next().is_some_and(char::is_uppercase)
}

fn methods<'a>(index: &ProjectIndex<'a>, id: TypeId) -> Vec<(usize, &'a MemberDecl)> {
    index
        .members(id)
        .filter(|(_, m)| m.kind == "method")
        .collect()
}

/// The method of a type that matches `method`: the one with its name and
/// parameter types, or else the only one with its name and arity. None when
/// several overloads fit and none has the same types (generics, say).
fn method_like<'a>(
    index: &ProjectIndex<'a>,
    id: TypeId,
    method: &MemberDecl,
) -> Option<&'a MemberDecl> {
    let candidates: Vec<&MemberDecl> = methods(index, id)
        .into_iter()
        .map(|(_, m)| m)
        .filter(|m| m.name == method.name && m.params.len() == method.params.len())
        .collect();
    let types = param_types(method);
    candidates
        .iter()
        .find(|m| param_types(m) == types)
        .copied()
        .or(match candidates.as_slice() {
            [one] => Some(*one),
            _ => None,
        })
}

/// Interfaces a type implements, declared in the project: those it lists,
/// their base interfaces, and those its project base classes list.
fn all_interfaces(index: &ProjectIndex, id: TypeId) -> Vec<TypeId> {
    let mut todo: Vec<TypeId> = index.interfaces(id);
    for a in index.ancestors(id) {
        todo.extend(index.interfaces(a));
    }
    let mut out: Vec<TypeId> = Vec::new();
    while let Some(i) = todo.pop() {
        if out.contains(&i) || out.len() > 64 {
            continue;
        }
        out.push(i);
        todo.extend(index.interfaces(i));
    }
    out
}

/// The declaration a method overrides or implements, when the project
/// declares it: the overridden method of a base class, the same-named
/// member of an interface, or the other half of a partial method.
fn counterpart<'a>(
    index: &ProjectIndex<'a>,
    id: TypeId,
    method: &MemberDecl,
) -> Option<&'a MemberDecl> {
    let arity = method.params.len();
    if method.has("override") {
        return index
            .ancestors(id)
            .into_iter()
            .find_map(|a| method_like(index, a, method));
    }
    if method.has("partial") {
        return methods(index, id).into_iter().map(|(_, m)| m).find(|m| {
            m.name == method.name
                && m.params.len() == arity
                && m.has_body != method.has_body
                && m.has("partial")
        });
    }
    if method.has("public") && !method.has("static") {
        return all_interfaces(index, id)
            .into_iter()
            .find_map(|i| method_like(index, i, method));
    }
    None
}

/// The project rules about a class, struct or record.
fn type_rules(
    index: &ProjectIndex,
    id: TypeId,
    kind: &str,
    on: &dyn Fn(&str) -> bool,
    found: &mut Vec<Finding>,
) {
    overrides_and_implementations(index, id, on, found);
    if kind != "struct" && on("cs/disposable-fields-without-idisposable") {
        disposable_fields(index, id, found);
    }
    if kind != "class" {
        return;
    }
    if on("cs/deep-inheritance") {
        deep_inheritance(index, id, found);
    }
    if on("cs/hiding-member-less-visible") || on("cs/base-method-hidden") {
        hidden_base_methods(index, id, on, found);
    }
    if on("cs/field-differs-from-base-by-case") {
        fields_differing_by_case(index, id, found);
    }
    if on("cs/dispose-pattern") {
        dispose_pattern(index, id, found);
    }
}

fn overrides_and_implementations(
    index: &ProjectIndex,
    id: TypeId,
    on: &dyn Fn(&str) -> bool,
    found: &mut Vec<Finding>,
) {
    for (file, method) in methods(index, id) {
        if method.explicit {
            continue;
        }
        if let Some(other) = counterpart(index, id, method)
            && other.params.len() == method.params.len()
        {
            compare_with_counterpart(method, other, file, on, found);
        }
    }
}

/// A method's parameters against those of the member it overrides or
/// implements, with as many.
fn compare_with_counterpart(
    method: &MemberDecl,
    other: &MemberDecl,
    file: usize,
    on: &dyn Fn(&str) -> bool,
    found: &mut Vec<Finding>,
) {
    let pairs: Vec<(&ParamDecl, &ParamDecl)> = method.params.iter().zip(&other.params).collect();
    if on("cs/parameter-name-mismatch")
        && let Some(mine) = parameter_name_mismatch(&pairs)
    {
        found.push(("cs/parameter-name-mismatch", file, mine.span));
    }
    if method.has("override") {
        for (mine, theirs) in &pairs {
            override_parameter_findings(mine, theirs, file, on, found);
        }
    }
    // A default the overridden or implemented member declares and this
    // one leaves out: callers get it or not depending on the type they
    // call through (measured on SonarQube 26.7, for an interface's
    // member too).
    if on("cs/override-changes-default") && !method.has("partial") {
        found.extend(
            pairs
                .iter()
                .filter(|(mine, theirs)| theirs.default.is_some() && mine.default.is_none())
                .map(|(mine, _)| ("cs/override-changes-default", file, mine.span)),
        );
    }
}

/// The first parameter named otherwise than its counterpart; `_` marks a
/// parameter unused on purpose.
fn parameter_name_mismatch<'p>(pairs: &[(&'p ParamDecl, &ParamDecl)]) -> Option<&'p ParamDecl> {
    pairs
        .iter()
        .find(|(a, b)| a.name != b.name && !a.name.chars().all(|c| c == '_'))
        .map(|(mine, _)| *mine)
}

/// An override's parameter against the one it overrides: a different
/// default (an interface's defaults apply only through the interface, so
/// overrides only, as documented), a `params` dropped or added.
fn override_parameter_findings(
    mine: &ParamDecl,
    theirs: &ParamDecl,
    file: usize,
    on: &dyn Fn(&str) -> bool,
    found: &mut Vec<Finding>,
) {
    if on("cs/override-changes-default")
        && let (Some(a), Some(b)) = (&mine.default, &theirs.default)
        && canonical_default(a) != canonical_default(b)
    {
        found.push(("cs/override-changes-default", file, mine.span));
    }
    if on("cs/override-without-params") && theirs.is_params && !mine.is_params {
        found.push(("cs/override-without-params", file, mine.span));
    }
    if on("cs/override-adds-params") && mine.is_params && !theirs.is_params {
        found.push(("cs/override-adds-params", file, mine.span));
    }
}

/// A default value, with the spellings of "the type's default" made one:
/// `default`, `default(T)`, `new()` (for a struct) and `null`.
fn canonical_default(value: &str) -> &str {
    if value == "default" || value == "new()" || value == "null" || value.starts_with("default(") {
        "default"
    } else {
        value
    }
}

/// A class's base class, as far as the project and the platform tell.
enum Base {
    /// None but Object: no base type, or only interfaces.
    Object,
    Project(TypeId),
    Platform(&'static PlatformType),
    /// A class neither declares, from another library.
    Unknown,
}

fn base_of(index: &ProjectIndex, id: TypeId) -> Base {
    let Some((file, part, first)) = index
        .parts(id)
        .iter()
        .find_map(|(f, t)| t.bases.first().map(|b| (*f, *t, b)))
    else {
        return Base::Object;
    };
    if let Some(b) = index.resolve(file, part, first) {
        return match index.decl(b).1.kind.as_str() {
            "class" | "record" => Base::Project(b),
            _ => Base::Object,
        };
    }
    match index.platform_type(file, &part.namespace, first) {
        Some(p) if p.kind == "class" => Base::Platform(p),
        Some(_) => Base::Object,
        None if looks_like_interface(&first.name) => Base::Object,
        None => Base::Unknown,
    }
}

/// Classes more than five levels from Object, the platform's base classes
/// and Object included. A base from another library counts as one level:
/// the least it can be.
/// More than five base classes declared in the project: .NET's own
/// (`Controller`, `ControllerBase`) and `object` don't count (measured on
/// SonarQube 26.7).
fn deep_inheritance(index: &ProjectIndex, id: TypeId, found: &mut Vec<Finding>) {
    if index.ancestors(id).len() > 5 {
        let (file, decl) = index.decl(id);
        found.push(("cs/deep-inheritance", file, decl.span));
    }
}

fn param_types(m: &MemberDecl) -> Vec<&str> {
    m.params.iter().map(|p| p.ty.as_str()).collect()
}

/// Whether the project class named `derived` inherits from `base`.
fn derives_from(
    index: &ProjectIndex,
    file: usize,
    from: &TypeDecl,
    derived: &str,
    base: &str,
) -> bool {
    let simple = |t: &str| {
        t.split('<')
            .next()
            .unwrap_or(t)
            .rsplit('.')
            .next()
            .unwrap_or(t)
            .to_string()
    };
    let reference = TypeRef {
        name: simple(derived),
        arity: 0,
        ..TypeRef::default()
    };
    index.resolve(file, from, &reference).is_some_and(|d| {
        index
            .ancestors(d)
            .into_iter()
            .any(|a| index.decl(a).1.name == simple(base))
    })
}

fn hidden_base_methods(
    index: &ProjectIndex,
    id: TypeId,
    on: &dyn Fn(&str) -> bool,
    found: &mut Vec<Finding>,
) {
    let ancestors = index.ancestors(id);
    if ancestors.is_empty() {
        return;
    }
    let (file, part) = index.decl(id);
    let base_methods: Vec<&MemberDecl> = ancestors
        .iter()
        .flat_map(|a| methods(index, *a))
        .map(|(_, m)| m)
        .filter(|m| m.inherited())
        .collect();
    for (mfile, method) in methods(index, id) {
        if method.has("override") || method.explicit {
            continue;
        }
        let mine = param_types(method);
        // A private method with a visible, non-virtual base method's signature.
        if on("cs/hiding-member-less-visible")
            && !method.inherited()
            && base_methods.iter().any(|b| {
                b.name == method.name
                    && param_types(b) == mine
                    && !["virtual", "abstract", "override"].iter().any(|w| b.has(w))
            })
        {
            found.push(("cs/hiding-member-less-visible", mfile, method.span));
        }
        // Same name and arity, every parameter the same or wider.
        if on("cs/base-method-hidden")
            && base_methods.iter().any(|b| {
                let theirs = param_types(b);
                b.name == method.name
                    && theirs.len() == mine.len()
                    && theirs != mine
                    && mine.iter().zip(&theirs).all(|(a, t)| {
                        a == t || *a == "object" || derives_from(index, file, part, t, a)
                    })
            })
        {
            found.push(("cs/base-method-hidden", mfile, method.span));
        }
    }
}

fn fields_differing_by_case(index: &ProjectIndex, id: TypeId, found: &mut Vec<Finding>) {
    let inherited: Vec<&MemberDecl> = index
        .ancestors(id)
        .into_iter()
        .flat_map(|a| index.members(a).map(|(_, m)| m).collect::<Vec<_>>())
        .filter(|m| m.kind == "field" && m.inherited())
        .collect();
    if inherited.is_empty() {
        return;
    }
    for (file, field) in index.members(id).filter(|(_, m)| m.kind == "field") {
        let clash = inherited.iter().any(|b| {
            b.name != field.name
                && b.name.eq_ignore_ascii_case(&field.name)
                && !(b.has("static") && field.has("static"))
        });
        if clash {
            found.push(("cs/field-differs-from-base-by-case", file, field.span));
        }
    }
}

fn colliding_members(index: &ProjectIndex, id: TypeId, found: &mut Vec<Finding>) {
    let bases = index.interfaces(id);
    if bases.len() < 2 {
        return;
    }
    let own: Vec<&str> = index.members(id).map(|(_, m)| m.name.as_str()).collect();
    let names: Vec<Vec<&str>> = bases
        .iter()
        .map(|b| index.members(*b).map(|(_, m)| m.name.as_str()).collect())
        .collect();
    let collides = names.iter().enumerate().any(|(i, a)| {
        a.iter()
            .any(|n| !own.contains(n) && names.iter().skip(i + 1).any(|b| b.contains(n)))
    });
    if collides {
        let (file, decl) = index.decl(id);
        found.push(("cs/interface-colliding-members", file, decl.span));
    }
}

/// The dispose pattern, for classes that implement IDisposable themselves
/// or through a base class. Sealed classes are left out.
fn dispose_pattern(index: &ProjectIndex, id: TypeId, found: &mut Vec<Finding>) {
    let (file, decl) = index.decl(id);
    if index
        .parts(id)
        .iter()
        .any(|(_, t)| t.has("sealed") || t.has("static"))
    {
        return;
    }
    let lists = index
        .bases(id)
        .iter()
        .any(|(_, _, b)| b.name == "IDisposable" && b.arity == 0);
    let Some(base_disposable) = base_disposable(index, id) else {
        return;
    };
    if !lists && !base_disposable {
        return;
    }
    let members: Vec<&MemberDecl> = index.members(id).map(|(_, m)| m).collect();
    if dispose_problem(&members, lists, base_disposable) {
        found.push(("cs/dispose-pattern", file, decl.span));
    }
}

/// Whether the base class is disposable; None when that's unknown.
fn base_disposable(index: &ProjectIndex, id: TypeId) -> Option<bool> {
    match base_of(index, id) {
        Base::Object => Some(false),
        Base::Project(b) => index.implements(b, DISPOSABLE),
        Base::Platform(p) => Some(dotnet::platform().implements(&p.name, DISPOSABLE)),
        Base::Unknown => None,
    }
}

/// Whether a disposable type's members break the dispose pattern.
fn dispose_problem(members: &[&MemberDecl], lists: bool, base_disposable: bool) -> bool {
    let dispose = |explicit: bool| {
        members.iter().find(|m| {
            m.kind == "method"
                && m.name == "Dispose"
                && m.params.is_empty()
                && m.explicit == explicit
        })
    };
    let dispose_bool = members.iter().find(|m| {
        m.kind == "method"
            && m.name == "Dispose"
            && m.params.len() == 1
            && matches!(
                m.params[0].ty.as_str(),
                "bool" | "Boolean" | "System.Boolean"
            )
    });
    let finalizer = members.iter().find(|m| m.kind == "destructor");
    let calls = |m: &MemberDecl, c: &str| m.calls.iter().any(|x| x == c);
    let only = |m: &MemberDecl, body: &str| calls(m, &format!("only:{body}"));
    let (public_dispose, explicit_dispose) = (dispose(false), dispose(true));
    (lists && base_disposable)
        || explicit_dispose.is_some()
        || finalizer.is_some_and(|f| f.has_body && !only(f, "Dispose(false)"))
        || if base_disposable {
            // Each level releases its base's resources too.
            [public_dispose, dispose_bool]
                .into_iter()
                .flatten()
                .any(|m| m.has_body && !calls(m, "base.Dispose("))
        } else {
            public_dispose.is_some_and(|d| d.has("virtual") || d.has("abstract"))
                || !dispose_bool
                    .is_some_and(|d| d.has("protected") && (d.has("virtual") || d.has("abstract")))
                || public_dispose.is_some_and(|d| {
                    d.has_body && !only(d, "Dispose(true);GC.SuppressFinalize(this)")
                })
        }
}

/// A class that creates an IDisposable and keeps it in a field must be
/// IDisposable itself, so its owner can release it. Tasks are the
/// documented exception.
fn disposable_fields(index: &ProjectIndex, id: TypeId, found: &mut Vec<Finding>) {
    if index.parts(id).iter().any(|(_, t)| t.has("static")) {
        return;
    }
    let owner = index.parts(id).iter().find(|(file, part)| {
        part.members.iter().any(|m| {
            m.kind == "field"
                && m.created
                && !m.has("static")
                && TypeRef::parse(&m.returns).is_some_and(|r| {
                    !matches!(r.name.as_str(), "Task" | "ValueTask")
                        && index.type_implements(*file, &part.namespace, &r, DISPOSABLE)
                            == Some(true)
                })
        })
    });
    if let Some((file, part)) = owner
        && index.implements(id, DISPOSABLE) == Some(false)
    {
        found.push(("cs/disposable-fields-without-idisposable", *file, part.span));
    }
}

/// Value types a request model's property may have, besides the project's
/// own enums and structs.
const VALUE_TYPES: &[&str] = &[
    "int",
    "long",
    "short",
    "byte",
    "uint",
    "ulong",
    "ushort",
    "sbyte",
    "bool",
    "decimal",
    "double",
    "float",
    "char",
    "DateTime",
    "DateTimeOffset",
    "TimeSpan",
    "Guid",
    "DateOnly",
    "TimeOnly",
];

/// A controller: an [ApiController], or a class whose bases, through the
/// project, reach Controller or ControllerBase.
fn is_controller(index: &ProjectIndex, id: TypeId) -> bool {
    let attributed = index
        .parts(id)
        .iter()
        .any(|(_, t)| t.attributes.iter().any(|a| a == "ApiController"));
    let mut chain = vec![id];
    chain.extend(index.ancestors(id));
    attributed
        || chain
            .iter()
            .flat_map(|t| index.bases(*t))
            .any(|(_, _, b)| matches!(b.name.as_str(), "Controller" | "ControllerBase"))
}

/// Rules judging a use in one file by a declaration in another: enum
/// operations, arrays for `params`, `new` of shared parts, extensions,
/// entity interfaces and action models.
fn uses(index: &ProjectIndex, on: &dyn Fn(&str) -> bool, found: &mut Vec<Finding>) {
    let mut entities: Vec<TypeId> = Vec::new();
    let mut models: Vec<TypeId> = Vec::new();
    for (file, f) in index.files().iter().enumerate() {
        for site in &f.sites {
            if let Some(rule) = site_finding(index, on, file, site) {
                found.push((rule, file, site.span));
            }
            collect_site_types(index, on, file, site, &mut entities, &mut models);
        }
    }
    entity_interfaces(index, &entities, found);
    underposted_models(index, &models, found);
}

/// A rule's check of one site.
type SiteCheck = fn(&ProjectIndex, usize, &Site) -> bool;

/// The rule a site breaks on its own, if any.
fn site_finding(
    index: &ProjectIndex,
    on: &dyn Fn(&str) -> bool,
    file: usize,
    site: &Site,
) -> Option<&'static str> {
    let (rule, check): (&'static str, SiteCheck) = match site.kind.as_str() {
        "bitwise" => ("cs/bitwise-on-non-flags-enum", non_flags_enum),
        "cast" => ("cs/interface-downcast", interface_downcast),
        "params-array" => ("cs/array-for-params", array_for_params),
        "new" => ("cs/shared-part-created-with-new", shared_part),
        "extension" => ("cs/extension-in-same-namespace", extends_a_neighbour),
        _ => return None,
    };
    (on(rule) && check(index, file, site)).then_some(rule)
}

/// The entity interfaces and the action models a site names, each once,
/// for the rules that judge them as a whole.
fn collect_site_types(
    index: &ProjectIndex,
    on: &dyn Fn(&str) -> bool,
    file: usize,
    site: &Site,
    entities: &mut Vec<TypeId>,
    models: &mut Vec<TypeId>,
) {
    let (found, into) = match site.kind.as_str() {
        "entity" if on("cs/durable-entity-interface") => (
            resolve_site(index, file, site).filter(|id| index.decl(*id).1.kind == "interface"),
            entities,
        ),
        "action-param" if on("cs/underposting-value-type") => {
            (action_model(index, file, site), models)
        }
        _ => return,
    };
    if let Some(id) = found
        && !into.contains(&id)
    {
        into.push(id);
    }
}

/// The site's type name, by its name and arity, resolved where it's used.
fn resolve_site(index: &ProjectIndex, file: usize, site: &Site) -> Option<TypeId> {
    index.resolve_in(file, &site.namespace, &site_type(site))
}

fn site_type(site: &Site) -> TypeRef {
    TypeRef {
        name: site.name.clone(),
        arity: site.arity,
        ..TypeRef::default()
    }
}

/// `|`, `&` or `^` on an enum, of the project or the platform, without
/// `[Flags]`.
fn non_flags_enum(index: &ProjectIndex, file: usize, site: &Site) -> bool {
    match resolve_site(index, file, site) {
        Some(id) => {
            index.decl(id).1.kind == "enum"
                && !index
                    .parts(id)
                    .iter()
                    .any(|(_, t)| t.attributes.iter().any(|a| a == "Flags"))
        }
        None => index
            .platform_type(file, &site.namespace, &site_type(site))
            .is_some_and(|p| p.kind == "enum" && !p.has("Flags")),
    }
}

/// A cast from an interface to a class, struct or record other than object.
fn interface_downcast(index: &ProjectIndex, file: usize, site: &Site) -> bool {
    let kind = |text: &str| -> Option<(String, String)> {
        let r = TypeRef::parse(text)?;
        match index.resolve_at(file, &site.namespace, &site.owner, &r) {
            Some(id) => {
                let (_, t) = index.decl(id);
                Some((t.kind.clone(), t.full_name()))
            }
            None => index
                .platform_type(file, &site.namespace, &r)
                .map(|p| (p.kind.clone(), p.name.clone())),
        }
    };
    let from = site.receiver.as_deref().and_then(kind);
    let to = kind(&site.name);
    matches!((from, to), (Some((from, _)), Some((to, target)))
        if from == "interface"
            && matches!(to.as_str(), "class" | "struct" | "record")
            && target != "System.Object")
}

/// An array written out for a call that binds to a `params` method: no
/// overload of its arity takes the array as a plain parameter.
fn array_for_params(index: &ProjectIndex, file: usize, site: &Site) -> bool {
    // .NET's own: string's character methods and Path.Combine (measured on
    // SonarQube 26.7).
    match (site.receiver.as_deref(), site.name.as_str()) {
        (Some("string" | "String"), "Split" | "Trim" | "TrimStart" | "TrimEnd") => return true,
        (Some("Path" | "System.IO.Path"), "Combine") => return true,
        _ => {}
    }
    let target = match &site.receiver {
        None => index.type_named(&site.owner),
        Some(t) => index.resolve_in(
            file,
            &site.namespace,
            &TypeRef {
                name: t.clone(),
                arity: 0,
                ..TypeRef::default()
            },
        ),
    };
    let Some(target) = target else {
        return false;
    };
    let mut types = vec![target];
    types.extend(index.ancestors(target));
    let candidates: Vec<&MemberDecl> = types
        .iter()
        .flat_map(|t| index.members(*t).map(|(_, m)| m).collect::<Vec<_>>())
        .filter(|m| m.kind == "method" && m.name == site.name && m.params.len() == site.count)
        .collect();
    candidates
        .iter()
        .any(|m| m.params.last().is_some_and(|p| p.is_params))
        && !candidates
            .iter()
            .any(|m| m.params.last().is_some_and(|p| !p.is_params))
}

/// `new` of a part exported as shared.
fn shared_part(index: &ProjectIndex, file: usize, site: &Site) -> bool {
    resolve_site(index, file, site).is_some_and(|id| {
        index.parts(id).iter().any(|(_, t)| {
            t.attributes
                .iter()
                .any(|a| a == "PartCreationPolicy.Shared")
        })
    })
}

/// An extension method for a type of the same namespace, not generated.
fn extends_a_neighbour(index: &ProjectIndex, file: usize, site: &Site) -> bool {
    resolve_site(index, file, site).is_some_and(|id| {
        let (_, d) = index.decl(id);
        matches!(d.kind.as_str(), "class" | "struct" | "record" | "interface")
            && d.namespace == site.namespace
            && !index
                .parts(id)
                .iter()
                .any(|(_, t)| t.attributes.iter().any(|a| a == "GeneratedCode"))
    })
}

/// The class or record a controller's action takes as its model.
fn action_model(index: &ProjectIndex, file: usize, site: &Site) -> Option<TypeId> {
    let controller = index
        .type_named(&site.owner)
        .is_some_and(|c| is_controller(index, c));
    if !controller {
        return None;
    }
    resolve_site(index, file, site)
        .filter(|id| matches!(index.decl(*id).1.kind.as_str(), "class" | "record"))
}

/// Durable entity interfaces: not generic, and only methods taking at most
/// one argument and returning void or Task.
fn entity_interfaces(index: &ProjectIndex, entities: &[TypeId], found: &mut Vec<Finding>) {
    for &id in entities {
        let (file, decl) = index.decl(id);
        if decl.arity > 0 {
            found.push(("cs/durable-entity-interface", file, decl.span));
            continue;
        }
        for (f, member) in index.members(id) {
            let returns = member.returns.split('<').next().unwrap_or_default();
            let ok = member.kind == "method"
                && !member.generic
                && member.params.len() <= 1
                && matches!(returns, "void" | "Task");
            if !ok {
                found.push(("cs/durable-entity-interface", f, member.span));
            }
        }
    }
}

/// The public settable value-type properties of action models that
/// nothing requires: a request that leaves them out gets their default.
fn underposted_models(index: &ProjectIndex, models: &[TypeId], found: &mut Vec<Finding>) {
    for &id in models {
        for (f, property) in index
            .members(id)
            .filter(|(_, m)| m.kind == "property" && m.has("public"))
        {
            let (_, part) = index.decl(id);
            let value = VALUE_TYPES.contains(&property.returns.as_str())
                || index
                    .resolve_in(
                        f,
                        &part.namespace,
                        &TypeRef {
                            name: property.returns.clone(),
                            arity: 0,
                            ..TypeRef::default()
                        },
                    )
                    .is_some_and(|t| matches!(index.decl(t).1.kind.as_str(), "enum" | "struct"));
            let required = property.has("required")
                || property
                    .attributes
                    .iter()
                    .any(|a| matches!(a.as_str(), "Required" | "JsonRequired" | "BindRequired"));
            let settable = property.accessors.iter().any(|a| a == "set" || a == "init");
            if value && !required && settable {
                found.push(("cs/underposting-value-type", f, property.span));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::tests::far_deadline;
    use crate::analysis::{analyze, cs_project_rules};
    use crate::config::Config;
    use crate::lang::Lang;
    use crate::rules::RuleSet;

    /// (path, line) of each finding of `rule` in a project of these files.
    fn project(rule: &str, files: &[(&str, &str)]) -> Vec<(String, usize)> {
        let mut cfg = Config::default();
        cfg.rules.enabled = vec![rule.to_string()];
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let mut analyzed: Vec<_> = files
            .iter()
            .map(|(path, src)| {
                analyze(path, Lang::CSharp, src, &rules, &cfg, far_deadline()).unwrap()
            })
            .collect();
        cs_project_rules(&mut analyzed, &rules);
        let mut hits: Vec<(String, usize)> = analyzed
            .iter()
            .flat_map(|f| {
                f.issues
                    .iter()
                    .filter(|i| i.rule == rule)
                    .map(|i| (f.path.clone(), i.line))
            })
            .collect();
        hits.sort();
        hits
    }

    #[test]
    fn assembly_level_suppressions_target_other_files() {
        let files = [
            (
                "GlobalSuppressions.cs",
                "using System.Diagnostics.CodeAnalysis;\n[assembly: SuppressMessage(\"Bug\", \"S1244\", Scope = \"member\", Target = \"~M:Shop.Cart.Total(System.Double)~System.Boolean\")]\n[assembly: SuppressMessage(\"Bug\", \"S1244:Float equality\", Scope = \"type\", Target = \"~T:Shop.Box`1.Inner\")]\n[assembly: SuppressMessage(\"Bug\", \"S1244\", Scope = \"namespaceanddescendants\", Target = \"~N:Shop.Legacy\")]\n",
            ),
            (
                "Cart.cs",
                "namespace Shop;\npublic class Cart {\n  bool Total(double x) { return x == 0.1; }\n  bool Total(double x, double y) { return x == y; }\n  bool Other(double x) { return x == 0.3; }\n}\npublic class Box<T> {\n  class Inner {\n    bool F(double x) => x == 0.4;\n  }\n}\n",
            ),
            (
                "Old.cs",
                "namespace Shop.Legacy.Parts {\n  class Gear {\n    bool F(double x) => x == 0.5;\n  }\n}\nnamespace Shop.LegacyNot {\n  class Gear {\n    bool F(double x) => x == 0.6;\n  }\n}\n",
            ),
        ];
        assert_eq!(
            project("cs/float-equality", &files),
            [
                ("Cart.cs".to_string(), 4),
                ("Cart.cs".to_string(), 5),
                ("Old.cs".to_string(), 8)
            ]
        );
        // Module scope without a target silences the key everywhere.
        let module = [
            (
                "GlobalSuppressions.cs",
                "[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage(\"Bug\", \"S1244\", Scope = \"module\")]\n",
            ),
            files[1],
        ];
        assert_eq!(project("cs/float-equality", &module), []);
    }

    #[test]
    fn implementations_and_overrides_in_other_files() {
        let files = [
            (
                "IAccount.cs",
                "namespace Bank;\npublic interface IAccount {\n  void Add(int money);\n}\n",
            ),
            (
                "Base.cs",
                "namespace Bank;\npublic class Base {\n  public virtual void Run(int distance = 42, params string[] tags) { }\n  public virtual void Go(CancellationToken t = default) { }\n}\n",
            ),
            (
                "Account.cs",
                "namespace Bank;\npublic class Account : Base, IAccount {\n  public void Add(int amount) { }\n  public override void Run(int distance = 5, string[] tags) { }\n  public override void Go(CancellationToken t = default(CancellationToken)) { }\n}\n",
            ),
        ];
        assert_eq!(
            project("cs/parameter-name-mismatch", &files),
            [("Account.cs".into(), 3)]
        );
        assert_eq!(
            project("cs/override-changes-default", &files),
            [("Account.cs".into(), 4)]
        );
        assert_eq!(
            project("cs/override-without-params", &files),
            [("Account.cs".into(), 4)]
        );
    }

    #[test]
    fn names_resolve_through_namespaces_and_usings() {
        // Two classes named Base: the using picks the one Derived extends.
        let files = [
            (
                "A/Base.cs",
                "namespace A;\npublic class Base { public virtual void Run(int count) { } }\n",
            ),
            (
                "B/Base.cs",
                "namespace B;\npublic class Base { public virtual void Run(int other) { } }\n",
            ),
            (
                "C/Derived.cs",
                "using B;\nnamespace C;\npublic class Derived : Base {\n  public override void Run(int count) { }\n}\n",
            ),
        ];
        assert_eq!(
            project("cs/parameter-name-mismatch", &files),
            [("C/Derived.cs".into(), 4)]
        );
        // Without a using, the name stays ambiguous and nothing is reported.
        let ambiguous = [
            files[0],
            files[1],
            (
                "C/Derived.cs",
                "namespace C;\npublic class Derived : Base {\n  public override void Run(int count) { }\n}\n",
            ),
        ];
        assert_eq!(project("cs/parameter-name-mismatch", &ambiguous), []);
    }

    #[test]
    fn hierarchies_across_files() {
        let mut files: Vec<(String, String)> = (1..=7)
            .map(|i| {
                let base = if i == 1 {
                    "External".to_string()
                } else {
                    format!("L{}", i - 1)
                };
                (
                    format!("L{i}.cs"),
                    format!("namespace N;\npublic class L{i} : {base} {{ }}\n"),
                )
            })
            .collect();
        files.push(("Fruit.cs".into(), "namespace N;\npublic class Fruit { protected string plantingSeason; public void Run(int n) { } }\n".into()));
        files.push((
            "Raspberry.cs".into(),
            "namespace N;\npublic class Raspberry : Fruit {\n  protected string plantingseason;\n  private void Run(int n) { }\n}\n".into(),
        ));
        let refs: Vec<(&str, &str)> = files
            .iter()
            .map(|(p, s)| (p.as_str(), s.as_str()))
            .collect();
        // L7 has six project ancestors; L6, five and an external one.
        assert_eq!(project("cs/deep-inheritance", &refs), [("L7.cs".into(), 2)]);
        assert_eq!(
            project("cs/field-differs-from-base-by-case", &refs),
            [("Raspberry.cs".into(), 3)]
        );
        assert_eq!(
            project("cs/hiding-member-less-visible", &refs),
            [("Raspberry.cs".into(), 4)]
        );
    }

    #[test]
    fn platform_types_from_the_reference_packs() {
        let files = [
            (
                "Streams.cs",
                "using System.IO;\nnamespace N;\npublic class S1 : MemoryStream { }\npublic class S2 : S1 { }\npublic class S3 : S2 { }\n",
            ),
            (
                "Errors.cs",
                "namespace N;\npublic class E1 : System.Exception { }\npublic class E2 : E1 { }\n",
            ),
            (
                "Plain.cs",
                "namespace N;\npublic class P1 { }\npublic class P2 : P1 { }\npublic class P3 : P2 { }\npublic class P4 : P3 { }\npublic class P5 : P4 { }\npublic class P6 : P5 { }\npublic class P7 : P6 { }\n",
            ),
        ];
        // Only the project's classes count: not MemoryStream's chain, nor
        // Object.
        assert_eq!(
            project("cs/deep-inheritance", &files),
            [("Plain.cs".into(), 8)]
        );
    }

    #[test]
    fn disposable_fields() {
        let files = [
            (
                "Log.cs",
                "using System;\nusing System.IO;\nusing System.Threading;\nusing System.Threading.Tasks;\nnamespace N;\n\
                 class Log { private FileStream file; void Open(string p) { this.file = new FileStream(p, FileMode.Open); } }\n\
                 class Ok : IDisposable { private Timer t = new Timer(_ => { }); public void Dispose() => t.Dispose(); }\n\
                 class Given { private readonly Stream s; public Given(Stream s) { this.s = s; } }\n\
                 class Work { private Task t = new Task(() => { }); }\n\
                 class Holder { private Resource r = new(); }\n\
                 class Derived : Base { private FileStream f = new FileStream(\"x\", FileMode.Open); }\n\
                 class Static { private static FileStream f = new FileStream(\"x\", FileMode.Open); }\n",
            ),
            (
                "Resource.cs",
                "namespace N;\npublic class Resource : System.IDisposable { public void Dispose() { } }\npublic class Base : Resource { }\n",
            ),
            (
                "Vendor.cs",
                "using System.IO;\nusing Vendor.Lib;\nnamespace N;\nclass Plugin : VendorBase { private FileStream f = new FileStream(\"x\", FileMode.Open); }\nclass Wrapper { private VendorHandle h = new VendorHandle(); }\n",
            ),
        ];
        assert_eq!(
            project("cs/disposable-fields-without-idisposable", &files),
            [("Log.cs".into(), 6), ("Log.cs".into(), 10)]
        );
    }

    #[test]
    fn interface_downcasts() {
        let files = [
            (
                "Shapes.cs",
                "namespace N;\npublic interface IShape { }\npublic interface IRound : IShape { }\npublic class Circle : IShape { }\npublic class Base { }\n",
            ),
            (
                "Nested.cs",
                "namespace N;\npublic class Tests {\n  public interface IPerson { }\n  public class Employee : IPerson { }\n  void F(IPerson p) { var e = (Employee)p; }\n}\npublic class Other { public class Employee { } public interface IPerson { } }\n",
            ),
            (
                "Use.cs",
                "using System.Collections.Generic;\nnamespace N;\nclass A {\nIShape shape;\nint F(IShape s, Base b, IEnumerable<int> xs) {\nvar c = (Circle)s;\nvar d = s as Circle;\nvar e = (IRound)s;\nvar f = (Circle)b;\nvar g = (Circle)shape;\nvar h = (List<int>)xs;\nvar i = (IList<int>)xs;\nvar j = (object)s;\nvar k = (Object)s;\nreturn 0;\n}\n}\n",
            ),
        ];
        assert_eq!(
            project("cs/interface-downcast", &files),
            [
                ("Nested.cs".into(), 5),
                ("Use.cs".into(), 6),
                ("Use.cs".into(), 7),
                ("Use.cs".into(), 10),
                ("Use.cs".into(), 11)
            ]
        );
    }

    #[test]
    fn dispose_pattern_as_documented() {
        let files = [
            (
                "Foo.cs",
                "using System;\nnamespace N;\n\
                 public class Foo1 : IDisposable { public void Dispose() { } }\n\
                 public sealed class Sealed : IDisposable { public void Dispose() { } }\n\
                 public class Foo2 : IDisposable { void IDisposable.Dispose() { Dispose(true); GC.SuppressFinalize(this); } protected virtual void Dispose(bool disposing) { } }\n\
                 public class Foo3 : IDisposable { public virtual void Dispose() { Dispose(true); GC.SuppressFinalize(this); } protected virtual void Dispose(bool disposing) { } }\n\
                 public class Foo4 : IDisposable { public void Dispose() { Dispose(true); GC.SuppressFinalize(this); } protected virtual void Dispose(bool disposing) { } ~Foo4() { Cleanup(); } void Cleanup() { } }\n\
                 public class Good : IDisposable { public void Dispose() { Dispose(true); GC.SuppressFinalize(this); } protected virtual void Dispose(bool disposing) { } ~Good() { Dispose(false); } }\n\
                 public class Extra : IDisposable { public void Dispose() { Log(); Dispose(true); GC.SuppressFinalize(this); } protected virtual void Dispose(bool disposing) { } void Log() { } }\n\
                 public class Named : IDisposable { public void Dispose() { this.Dispose(disposing: true); GC.SuppressFinalize(this); } protected virtual void Dispose(bool disposing) { } }\n",
            ),
            (
                "Derived.cs",
                "using System;\nusing System.IO;\nnamespace N;\n\
                 public class Calls : Good { protected override void Dispose(bool disposing) { base.Dispose(disposing); } }\n\
                 public class Forgets : Good { protected override void Dispose(bool disposing) { } }\n\
                 public class Relists : Good, IDisposable { }\n\
                 public class OwnStream : MemoryStream { protected override void Dispose(bool disposing) { base.Dispose(disposing); } }\n\
                 public class LeakyStream : MemoryStream { protected override void Dispose(bool disposing) { } }\n\
                 public class Vendor : Vendor.Lib.Thing, IDisposable { public void Dispose() { } }\n",
            ),
        ];
        assert_eq!(
            project("cs/dispose-pattern", &files),
            [
                ("Derived.cs".into(), 5),
                ("Derived.cs".into(), 6),
                ("Derived.cs".into(), 8),
                ("Foo.cs".into(), 3),
                ("Foo.cs".into(), 5),
                ("Foo.cs".into(), 6),
                ("Foo.cs".into(), 7),
                ("Foo.cs".into(), 9)
            ]
        );
    }

    #[test]
    fn partial_types_and_interfaces_across_files() {
        let files = [
            (
                "IA.cs",
                "namespace N;\npublic interface IA { int Id { get; } }\n",
            ),
            (
                "IB.cs",
                "namespace N;\npublic interface IB { int Id { get; } }\n",
            ),
            ("IC.cs", "namespace N;\npublic interface IC : IA, IB { }\n"),
            (
                "H1.cs",
                "namespace N;\npublic partial class Holder : IDisposable { }\n",
            ),
            (
                "H2.cs",
                "namespace N;\npublic partial class Holder {\n  public void Dispose() { Dispose(true); GC.SuppressFinalize(this); }\n  protected virtual void Dispose(bool d) { }\n}\n",
            ),
        ];
        assert_eq!(
            project("cs/interface-colliding-members", &files),
            [("IC.cs".into(), 2)]
        );
        // The pattern is complete across the two parts.
        assert_eq!(project("cs/dispose-pattern", &files), []);
    }

    /// Measured on SonarQube 26.7: an implementation leaving out its
    /// interface's default is reported; .NET's params methods given an array
    /// are, an object array isn't.
    #[test]
    fn defaults_and_params_measured() {
        let files = [
            (
                "Agent.cs",
                "namespace N;\npublic interface IAgent {\n  string Get(bool simplified = false);\n  string Other(string a, int b = 0);\n}\npublic class Agent : IAgent {\n  public string Get(bool simplified) => \"a\";\n  public string Other(string a, int b = 0) => a;\n}\n",
            ),
            (
                "Use.cs",
                "namespace N;\npublic class Use {\n  string F(string s, object[] row) {\n    var a = s.TrimStart(new char[] { '/', '\\\\' });\n    var b = s.Split(new[] { '.', '-' })[0];\n    var c = System.IO.Path.Combine(new[] { s, s });\n    Run(\"m\", new object[] { row[0] });\n    return a + b + c;\n  }\n  static void Run(string m, params object[] args) { }\n}\n",
            ),
        ];
        assert_eq!(
            project("cs/override-changes-default", &files),
            [("Agent.cs".into(), 7)]
        );
        assert_eq!(
            project("cs/array-for-params", &files),
            [("Use.cs".into(), 4), ("Use.cs".into(), 5)]
        );
    }

    #[test]
    fn uses_judged_by_declarations_elsewhere() {
        let files = [
            (
                "Color.cs",
                "namespace N;\npublic enum Color { Red, Blue }\n",
            ),
            (
                "Access.cs",
                "namespace N;\n[Flags]\npublic enum Access { Read = 1, Write = 2 }\n",
            ),
            (
                "Log.cs",
                "namespace N;\npublic static class Log {\n  public static void Write(params string[] parts) { }\n  public static void Take(string[] xs) { }\n}\n",
            ),
            (
                "Logger.cs",
                "namespace N;\npublic class Logger { public void Write(params string[] parts) { } }\n",
            ),
            (
                "Part.cs",
                "namespace N;\n[Export(typeof(IFoo))]\n[PartCreationPolicy(CreationPolicy.Shared)]\npublic class Part { }\n",
            ),
            (
                "Use.cs",
                "namespace N;\npublic class Use {\n  void F(Color c, Access a) {\n    var x = Color.Red | Color.Blue;\n    var y = Access.Read | Access.Write;\n    var z = c & Color.Red;\n    Log.Write(new[] { \"a\", \"b\" });\n    Log.Take(new[] { \"a\" });\n    Log.Write([.. names]);\n    var l = new Logger();\n    l.Write(new string[] { \"x\" });\n    var p = new Part();\n  }\n}\n",
            ),
        ];
        assert_eq!(
            project("cs/bitwise-on-non-flags-enum", &files),
            [("Use.cs".into(), 4), ("Use.cs".into(), 6)]
        );
        assert_eq!(
            project("cs/array-for-params", &files),
            [("Use.cs".into(), 7), ("Use.cs".into(), 11)]
        );
        assert_eq!(
            project("cs/shared-part-created-with-new", &files),
            [("Use.cs".into(), 12)]
        );
    }

    #[test]
    fn extensions_entities_and_models_across_files() {
        let files = [
            ("Order.cs", "namespace Shop;\npublic class Order { }\n"),
            (
                "Ext.cs",
                "namespace Shop;\npublic static class OrderExt {\n  public static int Total(this Order o) => 0;\n}\n",
            ),
            (
                "Helpers/Ext.cs",
                "namespace Shop.Helpers;\npublic static class More {\n  public static int Count(this Shop.Order o) => 0;\n}\n",
            ),
            (
                "ICounter.cs",
                "namespace Shop;\npublic interface ICounter {\n  void Add(int a, int b);\n  int Get();\n  void Reset();\n}\n",
            ),
            (
                "Fn.cs",
                "namespace Shop;\npublic class Fn {\n  Task G(IDurableEntityClient c, EntityId id) => c.SignalEntityAsync<ICounter>(id, x => x.Reset());\n}\n",
            ),
            (
                "Models/OrderModel.cs",
                "namespace Shop;\npublic class OrderModel {\n  public int Quantity { get; set; }\n  public int? Max { get; set; }\n  public required int Min { get; set; }\n  public string Name { get; set; }\n}\n",
            ),
            (
                "Controllers/OrdersController.cs",
                "namespace Shop;\n[ApiController]\npublic class OrdersController : ControllerBase {\n  public IActionResult Create(OrderModel order) => Ok();\n}\n",
            ),
        ];
        assert_eq!(
            project("cs/extension-in-same-namespace", &files),
            [("Ext.cs".into(), 3)]
        );
        assert_eq!(
            project("cs/durable-entity-interface", &files),
            [("ICounter.cs".into(), 3), ("ICounter.cs".into(), 4)]
        );
        assert_eq!(
            project("cs/underposting-value-type", &files),
            [("Models/OrderModel.cs".into(), 3)]
        );
    }

    #[test]
    fn pragmas_silence_project_findings() {
        let files = [
            (
                "IAccount.cs",
                "namespace Bank;\npublic interface IAccount {\n  void Add(int money);\n}\n",
            ),
            (
                "Account.cs",
                "namespace Bank;\npublic class Account : IAccount {\n#pragma warning disable S927 // the interface's name reads worse here\n  public void Add(int amount) { }\n#pragma warning restore S927\n}\n",
            ),
        ];
        assert_eq!(project("cs/parameter-name-mismatch", &files), []);
    }
}
