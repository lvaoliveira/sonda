//! C# rules that compare a declaration with declarations in other files of
//! the project (ADR-0019): an override with the method it overrides, a
//! method with the interface member it implements, a class with its base
//! classes. They run once per scan, on the project index the files'
//! summaries build (`semantic::cs_index`), and are `Check::Structural` in
//! the catalog. Their rules are declared with the other class rules; this
//! module holds their checks.

use crate::semantic::cs_index::{
    FACT, FileIndex, MemberDecl, ParamDecl, ProjectIndex, Span, TypeDecl, TypeId, TypeRef,
};

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
    // (position in the scanner's list, the file's index)
    let parsed: Vec<(usize, FileIndex)> = facts
        .enumerate()
        .filter_map(|(i, f)| {
            let (_, json) = f.iter().find(|(k, _)| k == FACT)?;
            serde_json::from_str(json).ok().map(|x| (i, x))
        })
        .collect();
    let index = ProjectIndex::new(parsed.iter().map(|(_, x)| x).collect());
    let mut found: Vec<Finding> = Vec::new();
    let on = |rule: &str| active.contains(&rule);
    for id in 0..index.len() {
        let (_, decl) = index.decl(id);
        match decl.kind.as_str() {
            "class" | "struct" | "record" => {
                overrides_and_implementations(&index, id, &on, &mut found);
                if decl.kind == "class" {
                    if on("cs/deep-inheritance") {
                        deep_inheritance(&index, id, &mut found);
                    }
                    if on("cs/hiding-member-less-visible") || on("cs/base-method-hidden") {
                        hidden_base_methods(&index, id, &on, &mut found);
                    }
                    if on("cs/field-differs-from-base-by-case") {
                        fields_differing_by_case(&index, id, &mut found);
                    }
                    if on("cs/dispose-pattern") {
                        dispose_pattern(&index, id, &mut found);
                    }
                }
            }
            "interface" if on("cs/interface-colliding-members") => {
                colliding_members(&index, id, &mut found)
            }
            _ => {}
        }
    }
    found
        .into_iter()
        .map(|(rule, file, span)| (rule, parsed[file].0, span))
        .collect()
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
        let Some(other) = counterpart(index, id, method) else {
            continue;
        };
        if other.params.len() != method.params.len() {
            continue;
        }
        let pairs: Vec<(&ParamDecl, &ParamDecl)> =
            method.params.iter().zip(&other.params).collect();
        // The first differing name; `_` marks a parameter unused on purpose.
        if on("cs/parameter-name-mismatch")
            && let Some((mine, _)) = pairs
                .iter()
                .find(|(a, b)| a.name != b.name && !a.name.chars().all(|c| c == '_'))
        {
            found.push(("cs/parameter-name-mismatch", file, mine.span));
        }
        for (mine, theirs) in &pairs {
            // Overrides, as documented: an interface's defaults apply only
            // through the interface.
            if on("cs/override-changes-default")
                && method.has("override")
                && let (Some(a), Some(b)) = (&mine.default, &theirs.default)
                && canonical_default(a) != canonical_default(b)
            {
                found.push(("cs/override-changes-default", file, mine.span));
            }
            if method.has("override") {
                if on("cs/override-without-params") && theirs.is_params && !mine.is_params {
                    found.push(("cs/override-without-params", file, mine.span));
                }
                if on("cs/override-adds-params") && mine.is_params && !theirs.is_params {
                    found.push(("cs/override-adds-params", file, mine.span));
                }
            }
        }
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

fn deep_inheritance(index: &ProjectIndex, id: TypeId, found: &mut Vec<Finding>) {
    let ancestors = index.ancestors(id);
    let mut depth = ancestors.len();
    // A base class from another assembly: one more level, at least.
    let last = *ancestors.last().unwrap_or(&id);
    let (file, part) = index.decl(last);
    if let Some(first) = index.parts(last).iter().find_map(|(_, t)| t.bases.first())
        && !looks_like_interface(&first.name)
        && index
            .resolve(file, part, first)
            .is_none_or(|b| b == last || ancestors.contains(&b) || b == id)
    {
        depth += 1;
    }
    if depth > 5 {
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

fn dispose_pattern(index: &ProjectIndex, id: TypeId, found: &mut Vec<Finding>) {
    let (file, decl) = index.decl(id);
    let lists = index
        .bases(id)
        .iter()
        .any(|(_, _, b)| b.name == "IDisposable");
    if !lists
        || index
            .parts(id)
            .iter()
            .any(|(_, t)| t.has("sealed") || t.has("static"))
    {
        return;
    }
    // A project base class is where the pattern lives.
    if index.base_class(id).is_some() {
        return;
    }
    let members: Vec<(usize, &MemberDecl)> = index.members(id).collect();
    let dispose = members
        .iter()
        .find(|(_, m)| m.kind == "method" && m.name == "Dispose" && m.params.is_empty());
    let dispose_bool = members.iter().find(|(_, m)| {
        m.kind == "method"
            && m.name == "Dispose"
            && m.params.first().is_some_and(|p| p.ty == "bool")
    });
    let finalizer = members.iter().find(|(_, m)| m.kind == "destructor");
    let calls = |m: &MemberDecl, c: &str| m.calls.iter().any(|x| x == c);
    let problem =
        if let Some((f, d)) = dispose.filter(|(_, d)| d.has("virtual") || d.has("abstract")) {
            Some((*f, d.span))
        } else if !dispose_bool
            .is_some_and(|(_, d)| d.has("protected") && (d.has("virtual") || d.has("abstract")))
        {
            Some((file, decl.span))
        } else if let Some((f, d)) = dispose.filter(|(_, d)| {
            d.has_body && (!calls(d, "Dispose(true)") || !calls(d, "GC.SuppressFinalize(this)"))
        }) {
            Some((*f, d.span))
        } else {
            finalizer
                .filter(|(_, f)| f.has_body && !calls(f, "Dispose(false)"))
                .map(|(f, d)| (*f, d.span))
        };
    if let Some((f, span)) = problem {
        found.push(("cs/dispose-pattern", f, span));
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
        let mut files: Vec<(String, String)> = (1..=6)
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
        // L6 has five project ancestors and an external one.
        assert_eq!(project("cs/deep-inheritance", &refs), [("L6.cs".into(), 2)]);
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
}
