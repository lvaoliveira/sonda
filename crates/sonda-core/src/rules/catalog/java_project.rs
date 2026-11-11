//! Java rules that need declarations from other files of the project
//! (ADR-0020): an override with the method it overrides, a class with its
//! superclasses, a field with its type, a call with its callee. They run
//! once per scan, on the index the files' summaries build
//! (`semantic::java_index`), and are `Check::Structural` in the catalog.
//!
//! What a type outside the project is (the JDK's, a library's) is known
//! only for the few names listed here; any other is given the benefit of
//! the doubt.

use crate::semantic::cs_index::Span;
use crate::semantic::java_index::{
    FACT, FileIndex, MethodDecl, ProjectIndex, TypeDecl, TypeId, TypeRef,
};

/// A finding: the rule, the index of the file it's in, and where.
pub(crate) type Finding = (&'static str, usize, Span);

pub(crate) const USELESS_OVERRIDE: &str = "java/useless-override";
pub(crate) const SERIALIZABLE_FIELD: &str = "java/serializable-field-type";
pub(crate) const SUBCLASS_EQUALS: &str = "java/subclass-adds-fields-not-equals";
pub(crate) const VARARGS_ARRAY: &str = "java/varargs-array";
pub(crate) const ABSTRACT_REDECLARED: &str = "java/abstract-method-redeclared";
pub(crate) const DROPS_SYNCHRONIZED: &str = "java/override-drops-synchronized";
pub(crate) const DEEP_INHERITANCE: &str = "java/inheritance-too-deep";

/// The rules this module checks.
pub(crate) const RULES: &[&str] = &[
    USELESS_OVERRIDE,
    SERIALIZABLE_FIELD,
    SUBCLASS_EQUALS,
    VARARGS_ARRAY,
    ABSTRACT_REDECLARED,
    DROPS_SYNCHRONIZED,
    DEEP_INHERITANCE,
];

/// How many classes a JDK class is from `Object`, itself and `Object`
/// included, for the depth of the classes extending it.
const JDK_DEPTH: &[(&str, usize)] = &[
    ("Object", 1),
    ("Throwable", 2),
    ("Exception", 3),
    ("Error", 3),
    ("RuntimeException", 4),
    ("IOException", 4),
    ("ReflectiveOperationException", 4),
    ("IllegalArgumentException", 5),
    ("IllegalStateException", 5),
    ("UnsupportedOperationException", 5),
    ("NullPointerException", 5),
    ("IndexOutOfBoundsException", 5),
    ("ClassCastException", 5),
    ("ArithmeticException", 5),
    ("UncheckedIOException", 5),
    ("NumberFormatException", 6),
    ("ArrayIndexOutOfBoundsException", 6),
    ("Number", 2),
    ("Thread", 2),
    ("Format", 2),
    ("MessageFormat", 3),
    ("DateFormat", 3),
    ("SimpleDateFormat", 4),
    ("TimeZone", 2),
    ("AbstractCollection", 2),
    ("AbstractList", 3),
    ("AbstractMap", 2),
    ("AbstractSet", 3),
    ("ArrayList", 4),
    ("HashMap", 3),
    ("HashSet", 4),
    ("LinkedHashMap", 4),
    ("TreeMap", 3),
];

/// Ancestors a class may have, `Object` included (SonarQube's default).
const MAX_DEPTH: usize = 5;

/// JDK classes whose subclasses are serializable.
const JDK_SERIALIZABLE: &[&str] = &[
    "Throwable",
    "Exception",
    "Error",
    "RuntimeException",
    "Number",
    "Format",
    "MessageFormat",
    "DateFormat",
    "SimpleDateFormat",
    "NumberFormat",
    "DecimalFormat",
    "Date",
    "Calendar",
    "GregorianCalendar",
    "ArrayList",
    "LinkedList",
    "HashMap",
    "LinkedHashMap",
    "TreeMap",
    "HashSet",
    "LinkedHashSet",
    "TreeSet",
    "Vector",
    "Hashtable",
    "Properties",
    "EventObject",
    "Random",
    "BitSet",
    "Enum",
    "AbstractQueuedSynchronizer",
];

/// JDK types that aren't serializable, as field types.
const JDK_NOT_SERIALIZABLE: &[&str] = &[
    "Object",
    "Type",
    "Thread",
    "ThreadGroup",
    "ThreadLocal",
    "Optional",
    "OptionalInt",
    "OptionalLong",
    "OptionalDouble",
    "Stream",
    "IntStream",
    "LongStream",
    "DoubleStream",
    "Iterator",
    "Iterable",
    "Comparator",
    "Runnable",
    "Callable",
    "InputStream",
    "OutputStream",
    "Reader",
    "Writer",
    "ClassLoader",
    "Method",
    "Field",
    "Constructor",
];

/// The JDK's collection interfaces: a field of one that isn't private may
/// hold anything.
const COLLECTION_INTERFACES: &[&str] = &[
    "Collection",
    "List",
    "Set",
    "Map",
    "Queue",
    "Deque",
    "SortedMap",
    "SortedSet",
    "NavigableMap",
    "NavigableSet",
    "ConcurrentMap",
];

/// The JDK's collections, whose type arguments are what they hold.
const COLLECTION_CLASSES: &[&str] = &[
    "ArrayList",
    "LinkedList",
    "HashMap",
    "LinkedHashMap",
    "TreeMap",
    "HashSet",
    "LinkedHashSet",
    "TreeSet",
    "Vector",
    "Hashtable",
    "ArrayDeque",
    "EnumMap",
    "EnumSet",
    "ConcurrentHashMap",
    "CopyOnWriteArrayList",
    "CopyOnWriteArraySet",
];

/// JDK classes that define `equals`.
const JDK_EQUALS: &[&str] = &[
    "ArrayList",
    "LinkedList",
    "HashMap",
    "TreeMap",
    "LinkedHashMap",
    "HashSet",
    "TreeSet",
    "Date",
    "Calendar",
    "GregorianCalendar",
    "AbstractList",
    "AbstractMap",
    "AbstractSet",
    "MessageFormat",
    "DateFormat",
    "SimpleDateFormat",
    "NumberFormat",
    "DecimalFormat",
];

/// The findings of the rules `active` lists, for files given as their
/// facts. Files without a Java index are skipped.
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
    let on = |rule: &str| active.contains(&rule);
    let mut found: Vec<Finding> = Vec::new();
    for (f, file) in index.files().iter().enumerate() {
        for t in 0..file.types.len() {
            let id = (f, t);
            if on(USELESS_OVERRIDE) {
                useless_overrides(&index, id, &mut found);
            }
            if index.decl(id).kind == "class" {
                if on(ABSTRACT_REDECLARED) {
                    redeclared_abstract_methods(&index, id, &mut found);
                }
                if on(DROPS_SYNCHRONIZED) {
                    overrides_dropping_synchronized(&index, id, &mut found);
                }
                // Its ancestors, `Object` included (measured on SonarQube 26.7).
                if on(DEEP_INHERITANCE) && depth(&index, id) - 1 > MAX_DEPTH {
                    found.push((DEEP_INHERITANCE, f, index.decl(id).span));
                }
                if on(SERIALIZABLE_FIELD) {
                    non_serializable_fields(&index, id, &mut found);
                }
                if on(SUBCLASS_EQUALS) && adds_fields_without_equals(&index, id) {
                    found.push((SUBCLASS_EQUALS, f, index.decl(id).span));
                }
            }
        }
        if on(VARARGS_ARRAY) {
            for site in &file.sites {
                if passes_array_to_varargs(&index, f, site) {
                    found.push((VARARGS_ARRAY, f, site.span));
                }
            }
        }
    }
    found
        .into_iter()
        .map(|(rule, file, span)| (rule, parsed[file].0, span))
        .collect()
}

fn has(list: &[String], word: &str) -> bool {
    list.iter().any(|m| m == word)
}

fn visibility(modifiers: &[String]) -> u8 {
    if has(modifiers, "public") {
        3
    } else if has(modifiers, "protected") {
        2
    } else if has(modifiers, "private") {
        0
    } else {
        1
    }
}

/// The JDK's name for a type outside the project, or nothing when it's
/// qualified with another package.
fn jdk_name(t: &TypeRef) -> Option<&str> {
    (t.qualifier.is_empty() || t.qualifier.starts_with("java.")).then_some(t.name.as_str())
}

// ---------------------------------------------------------------- S1185

/// Overrides that only call the method they override, as SonarQube 26.7
/// reports them (measured): not `equals`, `hashCode` or `toString`, not a
/// final one, not one with an annotation besides `@Override`, and not one
/// that widens the overridden method's visibility (`protected` to `public`).
fn useless_overrides(index: &ProjectIndex, id: TypeId, found: &mut Vec<Finding>) {
    let decl = index.decl(id);
    for m in decl
        .methods
        .iter()
        .filter(|m| m.only_calls_super && !m.constructor)
    {
        if matches!(m.name.as_str(), "equals" | "hashCode" | "toString")
            || has(&m.modifiers, "final")
            || m.annotations.iter().any(|a| a != "Override")
        {
            continue;
        }
        let overridden = match overridden_method(index, id, m) {
            Some(parent) => visibility(&parent.modifiers),
            // `Object`'s are protected.
            None if matches!(m.name.as_str(), "clone" | "finalize") => 2,
            None => visibility(&m.modifiers),
        };
        if overridden >= visibility(&m.modifiers) {
            found.push((USELESS_OVERRIDE, id.0, m.span));
        }
    }
}

/// The method `m` of `id` overrides, in a superclass the project declares.
fn overridden_method<'a>(
    index: &'a ProjectIndex,
    id: TypeId,
    m: &MethodDecl,
) -> Option<&'a MethodDecl> {
    let mut seen = vec![id];
    let mut current = index.superclass(id);
    while let Some(sup) = current.filter(|s| !seen.contains(s)) {
        seen.push(sup);
        let found = index
            .decl(sup)
            .methods
            .iter()
            .find(|p| !p.constructor && p.name == m.name && p.params.len() == m.params.len());
        if found.is_some() {
            return found;
        }
        current = index.superclass(sup);
    }
    None
}

// ---------------------------------------------------------------- S1948

/// Whether a type the project declares is serializable: an enum, or one that
/// implements `Serializable` itself or through a supertype.
fn is_serializable(index: &ProjectIndex, id: TypeId, seen: &mut Vec<TypeId>) -> bool {
    if seen.contains(&id) {
        return false;
    }
    seen.push(id);
    let decl = index.decl(id);
    if decl.kind == "enum" {
        return true;
    }
    decl.extends.iter().chain(&decl.implements).any(|t| {
        if matches!(t.name.as_str(), "Serializable" | "Externalizable") {
            return true;
        }
        match index.resolve(id.0, &decl.outer, &t.qualifier, &t.name) {
            Some(sup) => is_serializable(index, sup, seen),
            None => jdk_name(t).is_some_and(|n| {
                JDK_SERIALIZABLE.contains(&n) || n.ends_with("Exception") || n.ends_with("Error")
            }),
        }
    })
}

/// The type parameters in scope in a type: its own and its enclosing
/// types'.
fn type_params_in_scope<'a>(
    index: &'a ProjectIndex,
    id: TypeId,
) -> Vec<&'a crate::semantic::java_index::TypeParam> {
    let decl = index.decl(id);
    let file = index.files()[id.0];
    let mut params: Vec<_> = decl.type_params.iter().collect();
    for k in 0..decl.outer.len() {
        if let Some(outer) = file
            .types
            .iter()
            .find(|t| t.name == decl.outer[k] && t.outer == decl.outer[..k])
        {
            params.extend(&outer.type_params);
        }
    }
    params
}

/// Non-static, non-transient fields of a serializable class whose type
/// isn't serializable, as SonarQube 26.7 reports them (measured): a type
/// that doesn't implement `Serializable`, a type variable without such a
/// bound, a collection interface when the field isn't private, and a
/// collection holding a type that isn't serializable.
fn non_serializable_fields(index: &ProjectIndex, id: TypeId, found: &mut Vec<Finding>) {
    let decl = index.decl(id);
    if !is_serializable(index, id, &mut Vec::new()) {
        return;
    }
    let params = type_params_in_scope(index, id);
    let type_var = |t: &TypeRef| {
        (t.qualifier.is_empty() && t.args.is_empty())
            .then(|| params.iter().find(|p| p.name == t.name))
            .flatten()
    };
    // Whether a type, as written in this class, isn't serializable.
    let not_serializable = |t: &TypeRef| -> bool {
        if t.is_primitive() || t.dims > 0 {
            return false;
        }
        if let Some(p) = type_var(t) {
            return !p.bounds.iter().any(|b| {
                matches!(b.name.as_str(), "Serializable" | "Externalizable")
                    || index
                        .resolve_in(id, b)
                        .is_some_and(|s| is_serializable(index, s, &mut Vec::new()))
                    || jdk_name(b).is_some_and(|n| JDK_SERIALIZABLE.contains(&n))
            });
        }
        match index.resolve_in(id, t) {
            Some(ty) => !is_serializable(index, ty, &mut Vec::new()),
            None => jdk_name(t).is_some_and(|n| JDK_NOT_SERIALIZABLE.contains(&n)),
        }
    };
    // What a collection holds: a type variable there may be anything, and
    // isn't held against it.
    let holds_unserializable = |t: &TypeRef| {
        t.args.iter().any(|a| {
            let a = if a.is_wildcard() {
                match a.args.first() {
                    Some(bound) => bound,
                    None => return false,
                }
            } else {
                a
            };
            type_var(a).is_none()
                && !jdk_name(a).is_some_and(|n| {
                    COLLECTION_INTERFACES.contains(&n) || COLLECTION_CLASSES.contains(&n)
                })
                && not_serializable(a)
        })
    };
    for field in &decl.fields {
        if has(&field.modifiers, "static") || has(&field.modifiers, "transient") {
            continue;
        }
        let t = &field.ty;
        let collection = index.resolve_in(id, t).is_none()
            && jdk_name(t).is_some_and(|n| {
                COLLECTION_INTERFACES.contains(&n) || COLLECTION_CLASSES.contains(&n)
            });
        let flagged = if collection {
            let interface = jdk_name(t).is_some_and(|n| COLLECTION_INTERFACES.contains(&n));
            interface && !has(&field.modifiers, "private") || holds_unserializable(t)
        } else {
            not_serializable(t)
        };
        if flagged {
            found.push((SERIALIZABLE_FIELD, id.0, field.span));
        }
    }
}

// ---------------------------------------------------------------- S2160

/// A class that adds instance fields to a superclass defining `equals`, at
/// any distance, without defining its own.
fn adds_fields_without_equals(index: &ProjectIndex, id: TypeId) -> bool {
    let defines_equals = |d: &TypeDecl| {
        d.methods
            .iter()
            .any(|m| !m.constructor && m.name == "equals" && m.params.len() == 1)
    };
    let decl = index.decl(id);
    if defines_equals(decl) || !decl.fields.iter().any(|f| !has(&f.modifiers, "static")) {
        return false;
    }
    let mut seen = vec![id];
    let mut current = id;
    loop {
        let d = index.decl(current);
        let Some(parent) = d.extends.first() else {
            return false;
        };
        match index.resolve(current.0, &d.outer, &parent.qualifier, &parent.name) {
            Some(sup) if !seen.contains(&sup) => {
                if defines_equals(index.decl(sup)) {
                    return true;
                }
                seen.push(sup);
                current = sup;
            }
            Some(_) => return false,
            None => return jdk_name(parent).is_some_and(|n| JDK_EQUALS.contains(&n)),
        }
    }
}

// ---------------------------------------------------------------- S3878

/// An array literal passed as the varargs of a constructor or method the
/// project declares, or of `format`, `printf` and `asList`.
fn passes_array_to_varargs(
    index: &ProjectIndex,
    file: usize,
    site: &crate::semantic::java_index::Site,
) -> bool {
    if !site.constructor && matches!(site.callee.as_str(), "format" | "printf" | "asList") {
        return true;
    }
    // Every overload of that name and arity takes varargs.
    let takes_varargs = |methods: Vec<&MethodDecl>| {
        let same: Vec<&MethodDecl> = methods
            .into_iter()
            .filter(|m| m.params.len() == site.args)
            .collect();
        !same.is_empty() && same.iter().all(|m| m.varargs)
    };
    let with_supers = |start: TypeId| {
        let mut methods = Vec::new();
        let mut seen = Vec::new();
        let mut current = Some(start);
        while let Some(t) = current.filter(|t| !seen.contains(t)) {
            seen.push(t);
            methods.extend(
                index
                    .decl(t)
                    .methods
                    .iter()
                    .filter(|m| !m.constructor && m.name == site.callee),
            );
            current = index.superclass(t);
        }
        methods
    };
    if site.constructor {
        return index
            .resolve(file, &site.within, &site.qualifier, &site.callee)
            .is_some_and(|t| {
                takes_varargs(
                    index
                        .decl(t)
                        .methods
                        .iter()
                        .filter(|m| m.constructor)
                        .collect(),
                )
            });
    }
    if site.qualifier.is_empty() || site.qualifier == "this" {
        // The innermost enclosing type that has a method of that name.
        for k in (1..=site.within.len()).rev() {
            let (outer, name) = (&site.within[..k - 1], &site.within[k - 1]);
            let Some(t) = index.resolve(file, outer, "", name) else {
                continue;
            };
            let methods = with_supers(t);
            if !methods.is_empty() {
                return takes_varargs(methods);
            }
        }
        return false;
    }
    // `Type.method(...)`: a static call on a type the project declares.
    let (qualifier, name) = site
        .qualifier
        .rsplit_once('.')
        .unwrap_or(("", &site.qualifier));
    let starts_upper = name.chars().next().is_some_and(char::is_uppercase);
    starts_upper
        && index
            .resolve(file, &site.within, qualifier, name)
            .is_some_and(|t| takes_varargs(with_supers(t)))
}

// ---------------------------------------------------------------- S3038

/// Abstract methods of an abstract class that an interface it implements,
/// directly or through other interfaces, already declares.
fn redeclared_abstract_methods(index: &ProjectIndex, id: TypeId, found: &mut Vec<Finding>) {
    let decl = index.decl(id);
    if !has(&decl.modifiers, "abstract") {
        return;
    }
    // The interfaces it implements, and the ones they extend.
    let mut interfaces: Vec<TypeId> = Vec::new();
    let mut queue: Vec<TypeId> = decl
        .implements
        .iter()
        .filter_map(|t| index.resolve(id.0, &decl.outer, &t.qualifier, &t.name))
        .collect();
    while let Some(i) = queue.pop() {
        if interfaces.contains(&i) || index.decl(i).kind != "interface" {
            continue;
        }
        interfaces.push(i);
        queue.extend(index.supertypes(i));
    }
    for m in decl
        .methods
        .iter()
        .filter(|m| has(&m.modifiers, "abstract"))
    {
        let declared = interfaces.iter().any(|i| {
            index
                .decl(*i)
                .methods
                .iter()
                .any(|im| im.name == m.name && im.params.len() == m.params.len())
        });
        // Reported where the declaration starts, its annotations included.
        if declared {
            let line = m.lines.0;
            let at = Span {
                line,
                column: 1,
                end_line: line,
                end_column: 1,
            };
            found.push((ABSTRACT_REDECLARED, id.0, at));
        }
    }
}

// ---------------------------------------------------------------- S3551

/// Overrides that aren't `synchronized` of a method that is, in the nearest
/// superclass declaring it.
fn overrides_dropping_synchronized(index: &ProjectIndex, id: TypeId, found: &mut Vec<Finding>) {
    let decl = index.decl(id);
    for m in decl.methods.iter().filter(|m| {
        !m.constructor && !has(&m.modifiers, "synchronized") && !has(&m.modifiers, "static")
    }) {
        if overridden_method(index, id, m).is_some_and(|p| has(&p.modifiers, "synchronized")) {
            found.push((DROPS_SYNCHRONIZED, id.0, m.span));
        }
    }
}

// ---------------------------------------------------------------- S110

/// How many classes `id` is from `Object`, itself and `Object` included,
/// through the project's classes and, past them, a JDK class's known depth.
fn depth(index: &ProjectIndex, id: TypeId) -> usize {
    let mut seen = vec![id];
    let mut current = id;
    let mut count = 1;
    loop {
        let d = index.decl(current);
        let Some(parent) = d.extends.first() else {
            return count + 1;
        };
        match index.resolve(current.0, &d.outer, &parent.qualifier, &parent.name) {
            Some(sup) if !seen.contains(&sup) && index.decl(sup).kind == "class" => {
                seen.push(sup);
                current = sup;
                count += 1;
            }
            Some(_) => return count,
            None => {
                let known = jdk_name(parent)
                    .and_then(|n| JDK_DEPTH.iter().find(|(j, _)| *j == n).map(|(_, d)| *d));
                let unknown = if parent.name.ends_with("Exception") {
                    4
                } else {
                    2
                };
                return count + known.unwrap_or(unknown);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::analyze;
    use crate::analysis::tests::far_deadline;
    use crate::config::Config;
    use crate::lang::Lang;
    use crate::rules::RuleSet;

    /// `rule`'s findings over files given as (path, source), as (path, line).
    fn flagged(rule: &str, files: &[(&str, &str)]) -> Vec<(String, usize)> {
        let mut cfg = Config::default();
        cfg.rules.enabled = vec![rule.to_string()];
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let mut analyzed: Vec<_> = files
            .iter()
            .map(|(path, src)| {
                analyze(path, Lang::Java, src, &rules, &cfg, far_deadline()).unwrap()
            })
            .collect();
        crate::analysis::java_project_rules(&mut analyzed, &rules);
        let mut found: Vec<(String, usize)> = analyzed
            .iter()
            .flat_map(|f| {
                f.issues
                    .iter()
                    .filter(|i| i.rule == rule)
                    .map(|i| (f.path.clone(), i.line))
            })
            .collect();
        found.sort();
        found
    }

    fn at(path: &str, line: usize) -> (String, usize) {
        (path.to_string(), line)
    }

    const BASE: (&str, &str) = (
        "Base.java",
        "package p;\npublic class Base {\nprotected String hidden() { return \"\"; }\npublic String shown() { return \"\"; }\npublic synchronized boolean ready() { return true; }\n}",
    );

    /// Measured on SonarQube 26.7, the parent in another file.
    #[test]
    fn useless_overrides() {
        let child = (
            "C.java",
            "package p;\npublic class C extends Base {\n@Override\npublic String hidden() { return super.hidden(); }\n@Override\npublic String shown() { return super.shown(); }\n@Override public String toString() { return super.toString(); }\n@Override @Deprecated public final String x() { return super.x(); }\n}",
        );
        assert_eq!(
            flagged("java/useless-override", &[BASE, child]),
            [at("C.java", 6)]
        );
    }

    #[test]
    fn serializable_fields() {
        let files = [
            ("Plain.java", "package p;\npublic class Plain {}"),
            (
                "SerBase.java",
                "package p;\npublic class SerBase implements java.io.Serializable {}",
            ),
            ("Iface.java", "package p;\npublic interface Iface {}"),
            (
                "S.java",
                "package p;\nimport java.util.*;\npublic class S<T, U extends java.io.Serializable> extends SerBase {\nprivate Plain a;\nprivate SerBase b;\nprivate Iface c;\nprivate T d;\nprivate U e;\nprivate List<String> f;\npublic List<String> g;\nprivate List<Plain> h;\nprivate transient Plain i;\nprivate static Plain j;\nprivate Object k;\nprivate int l;\n}",
            ),
            (
                "E.java",
                "package p;\npublic class E extends Exception {\nprivate Plain a;\n}",
            ),
            (
                "N.java",
                "package p;\npublic class N {\nprivate Plain a;\n}",
            ),
        ];
        assert_eq!(
            flagged("java/serializable-field-type", &files),
            [
                at("E.java", 3),
                at("S.java", 4),
                at("S.java", 6),
                at("S.java", 7),
                at("S.java", 10),
                at("S.java", 11),
                at("S.java", 14)
            ]
        );
    }

    #[test]
    fn subclasses_adding_fields_to_equals() {
        let files = [
            (
                "Eq.java",
                "package p;\npublic class Eq {\npublic boolean equals(Object o) { return false; }\n}",
            ),
            ("Mid.java", "package p;\npublic class Mid extends Eq {}"),
            (
                "A.java",
                "package p;\npublic class A extends Mid {\nint b;\n}",
            ),
            (
                "B.java",
                "package p;\npublic class B extends Eq {\nstatic int b;\n}",
            ),
            (
                "F.java",
                "package p;\npublic class F extends java.text.MessageFormat {\nint b;\nF() { super(\"\"); }\n}",
            ),
        ];
        assert_eq!(
            flagged("java/subclass-adds-fields-not-equals", &files),
            [at("A.java", 2), at("F.java", 2)]
        );
    }

    #[test]
    fn arrays_passed_as_varargs() {
        let files = [
            (
                "Var.java",
                "package q;\npublic class Var {\npublic Var(String... xs) {}\npublic static void m(String... xs) {}\npublic static void n(String[] xs) {}\n}",
            ),
            (
                "A.java",
                "package p;\nimport q.Var;\nclass A {\nvoid g(String... xs) {}\nvoid f() {\nnew Var(new String[] {\"a\"});\nnew Var(new String[3]);\nVar.m(new String[] {\"a\"});\nVar.n(new String[] {\"a\"});\ng(new String[] {\"a\"});\n}\n}",
            ),
        ];
        assert_eq!(
            flagged("java/varargs-array", &files),
            [at("A.java", 6), at("A.java", 8), at("A.java", 10)]
        );
    }

    #[test]
    fn abstract_redeclarations_synchronized_and_depth() {
        let files = [
            BASE,
            (
                "I.java",
                "package p;\npublic interface I { boolean check(); }",
            ),
            (
                "J.java",
                "package p;\npublic interface J extends I { void reset(); }",
            ),
            (
                "AB.java",
                "package p;\npublic abstract class AB implements J {\n@Override\npublic abstract boolean check();\npublic abstract void other();\n}",
            ),
            (
                "SY.java",
                "package p;\npublic class SY extends Base {\n@Override\npublic boolean ready() { return false; }\n}",
            ),
            (
                "R1.java",
                "package p;\npublic class R1 extends RuntimeException {}",
            ),
            ("R2.java", "package p;\npublic class R2 extends R1 {}"),
            ("R3.java", "package p;\npublic class R3 extends R2 {}"),
        ];
        assert_eq!(
            flagged("java/abstract-method-redeclared", &files),
            [at("AB.java", 3)]
        );
        assert_eq!(
            flagged("java/override-drops-synchronized", &files),
            [at("SY.java", 4)]
        );
        assert_eq!(
            flagged("java/inheritance-too-deep", &files),
            [at("R3.java", 2)]
        );
    }

    #[test]
    fn suppressed_lines_stay_quiet() {
        let child = (
            "C.java",
            "package p;\npublic class C extends Base {\n@Override\npublic String shown() { return super.shown(); } // NOSONAR\n}",
        );
        assert!(flagged("java/useless-override", &[BASE, child]).is_empty());
    }
}
