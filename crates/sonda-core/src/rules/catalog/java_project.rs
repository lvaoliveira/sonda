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
pub(crate) const MISSING_OVERRIDE: &str = "java/missing-override";
pub(crate) const STATIC_VIA_SUBCLASS: &str = "java/static-via-subclass";
pub(crate) const CLASS_COUPLING: &str = "java/class-coupling";
pub(crate) const WILDCARD_RETURN: &str = "java/wildcard-return-type";
pub(crate) const GENERIC_EXCEPTION: &str = "java/generic-exception-thrown";
pub(crate) const FIELD_SHADOWS_PARENT: &str = "java/field-shadows-parent";

/// The rules this module checks.
pub(crate) const RULES: &[&str] = &[
    USELESS_OVERRIDE,
    SERIALIZABLE_FIELD,
    SUBCLASS_EQUALS,
    VARARGS_ARRAY,
    ABSTRACT_REDECLARED,
    DROPS_SYNCHRONIZED,
    DEEP_INHERITANCE,
    MISSING_OVERRIDE,
    STATIC_VIA_SUBCLASS,
    CLASS_COUPLING,
    WILDCARD_RETURN,
    GENERIC_EXCEPTION,
    FIELD_SHADOWS_PARENT,
];

/// How many of the project's types a class may depend on (SonarQube's
/// default for S6539).
const MAX_COUPLING: usize = 20;

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

/// The findings of the rules `on` runs on one type.
fn type_findings(
    index: &ProjectIndex,
    id: TypeId,
    on: &dyn Fn(&str) -> bool,
    found: &mut Vec<Finding>,
) {
    if on(USELESS_OVERRIDE) {
        useless_overrides(index, id, found);
    }
    if on(MISSING_OVERRIDE) {
        overrides_without_annotation(index, id, found);
    }
    if on(WILDCARD_RETURN) {
        wildcard_returns(index, id, found);
    }
    if on(GENERIC_EXCEPTION) {
        generic_exceptions_declared(index, id, found);
    }
    if index.decl(id).kind == "class" {
        class_findings(index, id, on, found);
    }
}

/// The findings of the rules `on` runs on a class.
fn class_findings(
    index: &ProjectIndex,
    id: TypeId,
    on: &dyn Fn(&str) -> bool,
    found: &mut Vec<Finding>,
) {
    let (f, span) = (id.0, index.decl(id).span);
    if on(CLASS_COUPLING) && project_types_used(index, id) > MAX_COUPLING {
        found.push((CLASS_COUPLING, f, span));
    }
    if on(ABSTRACT_REDECLARED) {
        redeclared_abstract_methods(index, id, found);
    }
    if on(DROPS_SYNCHRONIZED) {
        overrides_dropping_synchronized(index, id, found);
    }
    // Its ancestors, `Object` included (measured on SonarQube 26.7).
    if on(DEEP_INHERITANCE) && depth(index, id) - 1 > MAX_DEPTH {
        found.push((DEEP_INHERITANCE, f, span));
    }
    if on(SERIALIZABLE_FIELD) {
        non_serializable_fields(index, id, found);
    }
    if on(SUBCLASS_EQUALS) && adds_fields_without_equals(index, id) {
        found.push((SUBCLASS_EQUALS, f, span));
    }
    if on(FIELD_SHADOWS_PARENT) {
        fields_shadowing_ancestors(index, id, found);
    }
}

/// The findings of the rules `on` runs on a file's calls.
fn file_findings(
    index: &ProjectIndex,
    f: usize,
    file: &FileIndex,
    on: &dyn Fn(&str) -> bool,
    found: &mut Vec<Finding>,
) {
    if on(STATIC_VIA_SUBCLASS) {
        found.extend(
            file.static_calls
                .iter()
                .filter(|call| static_reached_through_subclass(index, f, call))
                .map(|call| (STATIC_VIA_SUBCLASS, f, call.span)),
        );
    }
    if on(VARARGS_ARRAY) {
        found.extend(
            file.sites
                .iter()
                .filter(|site| passes_array_to_varargs(index, f, site))
                .map(|site| (VARARGS_ARRAY, f, site.span)),
        );
    }
}

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
            type_findings(&index, (f, t), &on, &mut found);
        }
        file_findings(&index, f, file, &on, &mut found);
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
    let check = SerializableFields {
        index,
        id,
        params: type_params_in_scope(index, id),
    };
    for field in &decl.fields {
        if !has(&field.modifiers, "static")
            && !has(&field.modifiers, "transient")
            && check.flags(field)
        {
            found.push((SERIALIZABLE_FIELD, id.0, field.span));
        }
    }
}

/// A serializable class's fields, judged by the types written in it.
struct SerializableFields<'i, 'a> {
    index: &'i ProjectIndex<'a>,
    id: TypeId,
    params: Vec<&'i crate::semantic::java_index::TypeParam>,
}

impl<'i> SerializableFields<'i, '_> {
    /// The class's type variable a type names, if it's one.
    fn type_var(&self, t: &TypeRef) -> Option<&'i crate::semantic::java_index::TypeParam> {
        (t.qualifier.is_empty() && t.args.is_empty())
            .then(|| self.params.iter().find(|p| p.name == t.name).copied())
            .flatten()
    }

    /// Whether a field's type isn't serializable; a collection by what it
    /// holds, or, declared as an interface, by being visible.
    fn flags(&self, field: &crate::semantic::java_index::FieldDecl) -> bool {
        let t = &field.ty;
        let collection = self.index.resolve_in(self.id, t).is_none()
            && jdk_name(t).is_some_and(|n| {
                COLLECTION_INTERFACES.contains(&n) || COLLECTION_CLASSES.contains(&n)
            });
        if !collection {
            return self.not_serializable(t);
        }
        let interface = jdk_name(t).is_some_and(|n| COLLECTION_INTERFACES.contains(&n));
        interface && !has(&field.modifiers, "private") || self.holds_unserializable(t)
    }

    /// Whether a type, as written in this class, isn't serializable.
    fn not_serializable(&self, t: &TypeRef) -> bool {
        if t.is_primitive() || t.dims > 0 {
            return false;
        }
        if let Some(p) = self.type_var(t) {
            return !p.bounds.iter().any(|b| self.serializable_bound(b));
        }
        match self.index.resolve_in(self.id, t) {
            Some(ty) => !is_serializable(self.index, ty, &mut Vec::new()),
            None => jdk_name(t).is_some_and(|n| JDK_NOT_SERIALIZABLE.contains(&n)),
        }
    }

    fn serializable_bound(&self, b: &TypeRef) -> bool {
        matches!(b.name.as_str(), "Serializable" | "Externalizable")
            || self
                .index
                .resolve_in(self.id, b)
                .is_some_and(|s| is_serializable(self.index, s, &mut Vec::new()))
            || jdk_name(b).is_some_and(|n| JDK_SERIALIZABLE.contains(&n))
    }

    /// What a collection holds: a type variable there may be anything, and
    /// isn't held against it; a bare wildcard, `List<?>`, is (measured on
    /// SonarQube 26.7).
    fn holds_unserializable(&self, t: &TypeRef) -> bool {
        t.args.iter().any(|a| {
            let a = if a.is_wildcard() {
                match a.args.first() {
                    Some(bound) => bound,
                    None => return true,
                }
            } else {
                a
            };
            self.type_var(a).is_none()
                && !jdk_name(a).is_some_and(|n| {
                    COLLECTION_INTERFACES.contains(&n) || COLLECTION_CLASSES.contains(&n)
                })
                && self.not_serializable(a)
        })
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

// ---------------------------------------------------------------- S1161

/// Methods overriding a method with a body, in a superclass or an
/// interface (a default method) the project declares, without `@Override`
/// (measured on SonarQube 26.7). Implementing an abstract method isn't
/// reported, nor overriding `Object`'s alone.
fn overrides_without_annotation(index: &ProjectIndex, id: TypeId, found: &mut Vec<Finding>) {
    let decl = index.decl(id);
    if !matches!(
        decl.kind.as_str(),
        "class" | "enum" | "record" | "interface"
    ) {
        return;
    }
    // Every supertype the project declares, at any distance.
    let mut supers: Vec<TypeId> = Vec::new();
    let mut queue = index.supertypes(id);
    while let Some(t) = queue.pop() {
        if t == id || supers.contains(&t) {
            continue;
        }
        supers.push(t);
        queue.extend(index.supertypes(t));
    }
    for m in &decl.methods {
        if m.constructor
            || m.annotations.iter().any(|a| a == "Override")
            || has(&m.modifiers, "static")
            || has(&m.modifiers, "private")
        {
            continue;
        }
        // `toString()` overriding only `Object`'s finds no supertype here and
        // isn't reported; overriding a project class's, it is (measured).
        let overrides = supers.iter().any(|t| {
            let parent = index.decl(*t);
            parent.methods.iter().any(|p| {
                !p.constructor
                    && p.body
                    && p.name == m.name
                    && same_parameters(m, p, parent)
                    && !has(&p.modifiers, "static")
                    && !has(&p.modifiers, "private")
            })
        });
        if overrides {
            found.push((MISSING_OVERRIDE, id.0, m.span));
        }
    }
}

/// Whether `m` takes what `p`, declared in `parent`, takes: the same types by
/// name, or any reference type where `p` takes one of `parent`'s type
/// parameters. `fit(double)` doesn't override `fit(N)`: it overloads it.
fn same_parameters(m: &MethodDecl, p: &MethodDecl, parent: &TypeDecl) -> bool {
    m.params.len() == p.params.len()
        && m.params.iter().zip(&p.params).all(|(a, b)| {
            let type_var = b.qualifier.is_empty()
                && b.args.is_empty()
                && parent.type_params.iter().any(|t| t.name == b.name);
            if type_var {
                !a.is_primitive() || a.dims > 0
            } else {
                a.name == b.name && a.dims == b.dims
            }
        })
}

// ---------------------------------------------------------------- S3252

/// `Sub.method()` where `method` is a static method of a superclass of
/// `Sub`, and `Sub` doesn't declare one of that name.
fn static_reached_through_subclass(
    index: &ProjectIndex,
    file: usize,
    call: &crate::semantic::java_index::Site,
) -> bool {
    let (qualifier, name) = call
        .qualifier
        .rsplit_once('.')
        .unwrap_or(("", &call.qualifier));
    let Some(sub) = index.resolve(file, &call.within, qualifier, name) else {
        return false;
    };
    let declares = |t: TypeId| {
        index
            .decl(t)
            .methods
            .iter()
            .any(|m| !m.constructor && m.name == call.callee)
    };
    if declares(sub) {
        return false;
    }
    let mut seen = vec![sub];
    let mut current = index.superclass(sub);
    while let Some(t) = current.filter(|t| !seen.contains(t)) {
        seen.push(t);
        let methods: Vec<&MethodDecl> = index
            .decl(t)
            .methods
            .iter()
            .filter(|m| !m.constructor && m.name == call.callee)
            .collect();
        if !methods.is_empty() {
            return methods.iter().any(|m| has(&m.modifiers, "static"));
        }
        current = index.superclass(t);
    }
    false
}

// ---------------------------------------------------------------- S6539

/// How many of the project's own types a class refers to: the JDK's and
/// libraries' don't count (measured on SonarQube 26.7, with a library on the
/// classpath), nor the class itself, its nested types or type parameters.
fn project_types_used(index: &ProjectIndex, id: TypeId) -> usize {
    let decl = index.decl(id);
    let own = crate::semantic::java_index::full_name(index.files()[id.0], decl);
    let params: Vec<&str> = type_params_in_scope(index, id)
        .iter()
        .map(|p| p.name.as_str())
        .collect();
    let mut seen: Vec<TypeId> = Vec::new();
    for t in &decl.uses {
        if t.qualifier.is_empty() && params.contains(&t.name.as_str()) {
            continue;
        }
        let Some(target) = index.resolve_in(id, t) else {
            continue;
        };
        let name =
            crate::semantic::java_index::full_name(index.files()[target.0], index.decl(target));
        if name == own || name.starts_with(&format!("{own}.")) || seen.contains(&target) {
            continue;
        }
        seen.push(target);
    }
    seen.len()
}

// ---------------------------------------------------------------- S1452

/// A wildcard in what a method returns, once per `?`, as SonarQube 26.7
/// reports it (measured): not `Class<?>` or `Collector<T, ?, R>`, not a
/// private method, and not one implementing or overriding a supertype's,
/// whose type it must keep; the supertype's is reported instead.
fn wildcard_returns(index: &ProjectIndex, id: TypeId, found: &mut Vec<Finding>) {
    // Direct type arguments only: `List<Class<?>>` isn't reported.
    fn wildcards(t: &TypeRef) -> usize {
        t.args.iter().filter(|a| a.is_wildcard()).count()
    }
    let decl = index.decl(id);
    let mut supers: Vec<TypeId> = Vec::new();
    let mut queue = index.supertypes(id);
    while let Some(t) = queue.pop() {
        if t == id || supers.contains(&t) {
            continue;
        }
        supers.push(t);
        queue.extend(index.supertypes(t));
    }
    for m in &decl.methods {
        let Some(ret) = m.ret.as_ref() else { continue };
        if m.constructor
            || has(&m.modifiers, "private")
            || m.annotations.iter().any(|a| a == "Override")
            || matches!(ret.name.as_str(), "Class" | "Collector")
        {
            continue;
        }
        let inherited = supers.iter().any(|t| {
            index
                .decl(*t)
                .methods
                .iter()
                .any(|p| !p.constructor && p.name == m.name && p.params.len() == m.params.len())
        });
        if inherited {
            continue;
        }
        for _ in 0..wildcards(ret) {
            found.push((WILDCARD_RETURN, id.0, m.span));
        }
    }
}

// ---------------------------------------------------------------- S112

/// Generic exceptions a method declares (`throws Exception`, `Throwable`,
/// `RuntimeException`, `Error`), as SonarQube 26.7 reports them (measured):
/// not on a method implementing or overriding one whose signature it must
/// keep, and `Exception` not where a call passes one on, to a method of the
/// project declaring it (another file's included), or a `call()` or
/// `close()`.
fn generic_exceptions_declared(index: &ProjectIndex, id: TypeId, found: &mut Vec<Finding>) {
    const GENERIC: &[&str] = &["Exception", "Throwable", "RuntimeException", "Error"];
    let decl = index.decl(id);
    let supers = all_supertypes(index, id);
    for m in &decl.methods {
        if m.throws.iter().all(|(t, _)| !GENERIC.contains(&t.as_str()))
            || signature_not_its_own(index, decl, &supers, m)
        {
            continue;
        }
        let passes_one_on = m.calls.iter().any(|c| call_throws_generic(index, id, c));
        for (t, span) in &m.throws {
            if GENERIC.contains(&t.as_str()) && !(t == "Exception" && passes_one_on) {
                found.push((GENERIC_EXCEPTION, id.0, *span));
            }
        }
    }
}

/// Whether a method's `throws` comes from another declaration: an
/// override, a JDK hook it implements, or a method of a supertype with its
/// name and arity.
fn signature_not_its_own(
    index: &ProjectIndex,
    decl: &TypeDecl,
    supers: &[TypeId],
    m: &MethodDecl,
) -> bool {
    const JDK_HOOKS: &[(&str, &str)] = &[
        ("InvocationHandler", "invoke"),
        ("Callable", "call"),
        ("AutoCloseable", "close"),
        ("Closeable", "close"),
    ];
    m.annotations.iter().any(|a| a == "Override")
        || JDK_HOOKS.iter().any(|(iface, name)| {
            m.name == *name
                && decl
                    .implements
                    .iter()
                    .chain(&decl.extends)
                    .any(|t| t.name == *iface)
        })
        || supers.iter().any(|t| {
            index
                .decl(*t)
                .methods
                .iter()
                .any(|p| !p.constructor && p.name == m.name && p.params.len() == m.params.len())
        })
}

fn throws_generic(m: &MethodDecl) -> bool {
    m.throws
        .iter()
        .any(|(t, _)| matches!(t.as_str(), "Exception" | "Throwable"))
}

/// The methods of a type and its supertypes by name and arity.
fn methods_named<'i>(
    index: &'i ProjectIndex,
    t: TypeId,
    name: &str,
    args: usize,
) -> Vec<&'i MethodDecl> {
    let mut types = vec![t];
    types.extend(all_supertypes(index, t));
    types
        .into_iter()
        .flat_map(|t| index.decl(t).methods.iter())
        .filter(|m| !m.constructor && m.name == name && (m.params.len() == args || m.varargs))
        .collect()
}

/// Whether a call may throw `Exception` or `Throwable` on: `Callable.call()`
/// and `AutoCloseable.close()` declare it, a reader's or stream's
/// `close()` doesn't (measured on SonarQube 26.7), and a receiver of
/// unknown type may be either; else what the method called declares.
fn call_throws_generic(
    index: &ProjectIndex,
    id: TypeId,
    c: &crate::semantic::java_index::Call,
) -> bool {
    if matches!(c.name.as_str(), "call" | "close")
        && c.receiver.as_ref().is_none_or(|r| {
            matches!(r.name.as_str(), "Callable" | "AutoCloseable")
                || index.resolve_in(id, r).is_some_and(|t| {
                    methods_named(index, t, &c.name, c.args)
                        .into_iter()
                        .any(throws_generic)
                })
        })
    {
        return true;
    }
    let target = if c.own {
        Some(id)
    } else {
        c.receiver.as_ref().and_then(|r| index.resolve_in(id, r))
    };
    target.is_some_and(|t| {
        methods_named(index, t, &c.name, c.args)
            .into_iter()
            .any(throws_generic)
    })
}

/// Every supertype the project declares, at any distance.
/// A class's instance fields named like a field one of its project
/// ancestors declares, other than private ones, in any file (measured on
/// SonarQube 26.7).
fn fields_shadowing_ancestors(index: &ProjectIndex, id: TypeId, found: &mut Vec<Finding>) {
    let ancestors: Vec<TypeId> = all_supertypes(index, id)
        .into_iter()
        .filter(|&t| index.decl(t).kind == "class")
        .collect();
    if ancestors.is_empty() {
        return;
    }
    for field in &index.decl(id).fields {
        if has(&field.modifiers, "static") {
            continue;
        }
        let shadows = ancestors.iter().any(|&a| {
            index.decl(a).fields.iter().any(|p| {
                p.name == field.name
                    && !has(&p.modifiers, "private")
                    && !has(&p.modifiers, "static")
            })
        });
        if shadows {
            found.push((FIELD_SHADOWS_PARENT, id.0, field.span));
        }
    }
}

fn all_supertypes(index: &ProjectIndex, id: TypeId) -> Vec<TypeId> {
    let mut supers: Vec<TypeId> = Vec::new();
    let mut queue = index.supertypes(id);
    while let Some(t) = queue.pop() {
        if t == id || supers.contains(&t) {
            continue;
        }
        supers.push(t);
        queue.extend(index.supertypes(t));
    }
    supers
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

    /// Measured on SonarQube 26.7, the other declarations in other files.
    #[test]
    fn overrides_statics_coupling_and_suppression() {
        let files = [
            (
                "Base.java",
                "package p;\npublic class Base {\npublic void run() {}\nprotected void hook() {}\npublic static int id() { return 1; }\npublic void fit(Integer n) {}\n}",
            ),
            (
                "Abs.java",
                "package p;\npublic abstract class Abs { protected abstract void step(); }",
            ),
            (
                "I.java",
                "package p;\npublic interface I { void go(); default void later() {} }",
            ),
            ("Sub.java", "package p;\npublic class Sub extends Base {}"),
            (
                "C.java",
                "package p;\npublic class C extends Base implements I {\npublic void run() {}\nprotected void hook() {}\npublic void go() {}\npublic void later() {}\npublic String toString() { return \"\"; }\npublic void fit(int n) {}\nint f() { return Sub.id(); }\n}",
            ),
            (
                "D.java",
                "package p;\npublic class D extends Abs { protected void step() {} }",
            ),
            (
                "S.java",
                "package p;\npublic class S extends Base {\n@SuppressWarnings(\"java:S1161\")\npublic void run() {}\n@SuppressWarnings(\"all\")\nprotected void hook() {}\n}",
            ),
        ];
        assert_eq!(
            flagged("java/missing-override", &files),
            [at("C.java", 3), at("C.java", 4), at("C.java", 6)]
        );
        assert_eq!(
            flagged("java/static-via-subclass", &files),
            [at("C.java", 9)]
        );
        // 21 project types declared, used, or only created with `new`.
        let types: Vec<(String, String)> = (0..22)
            .map(|k| {
                (
                    format!("T{k}.java"),
                    format!("package p;\npublic class T{k} {{}}"),
                )
            })
            .collect();
        let locals: String = (0..21).map(|k| format!("T{k} v{k} = null;\n")).collect();
        let created: String = (0..21)
            .map(|k| format!("Object n{k} = new T{k}();\n"))
            .collect();
        let used = format!("package p;\nclass Used {{\nvoid f() {{\n{locals}}}\n}}");
        let made = format!("package p;\nclass Made {{\nvoid f() {{\n{created}}}\n}}");
        let mut all: Vec<(&str, &str)> = types
            .iter()
            .map(|(a, b)| (a.as_str(), b.as_str()))
            .collect();
        all.push(("Used.java", &used));
        all.push(("Made.java", &made));
        assert_eq!(flagged("java/class-coupling", &all), [at("Used.java", 2)]);
    }

    /// Measured on SonarQube 26.7: `throws Exception` passed on from another
    /// file's method, wildcards per argument, and `toString()` overriding a
    /// project class's.
    #[test]
    fn exceptions_wildcards_and_object_methods() {
        let files = [
            (
                "Svc.java",
                "package p;\npublic interface Svc {\nString find() throws Exception;\nString plain();\njava.util.Map<?, ?> detail();\n}",
            ),
            (
                "Ctl.java",
                "package p;\npublic class Ctl {\nprivate Svc svc;\npublic String c() throws Exception { return svc.find(); }\npublic String e() throws Exception { return svc.plain(); }\npublic String r() throws RuntimeException { return svc.find(); }\n}",
            ),
            (
                "Impl.java",
                "package p;\npublic class Impl implements Svc {\npublic String find() throws Exception { return \"\"; }\npublic String plain() { return \"\"; }\npublic java.util.Map<?, ?> detail() { return null; }\npublic java.util.List<Class<?>> nested() { return null; }\n}",
            ),
            (
                "P.java",
                "package p;\npublic class P { public String toString() { return \"p\"; } }",
            ),
            (
                "Q.java",
                "package p;\npublic class Q extends P { public String toString() { return \"q\"; } }",
            ),
            (
                "R.java",
                "package p;\npublic class R { public String toString() { return \"r\"; } }",
            ),
        ];
        assert_eq!(
            flagged("java/generic-exception-thrown", &files),
            [at("Ctl.java", 5), at("Ctl.java", 6), at("Svc.java", 3)]
        );
        assert_eq!(
            flagged("java/wildcard-return-type", &files),
            [at("Svc.java", 5), at("Svc.java", 5)]
        );
        assert_eq!(flagged("java/missing-override", &files), [at("Q.java", 2)]);
    }

    /// Measured on SonarQube 26.7: a field shadowing a parent's in another
    /// file, not a static one or a private one; and a `List<?>` field of a
    /// serializable class.
    #[test]
    fn shadowing_across_files() {
        let files = [
            (
                "Base.java",
                "public class Base {\n    public static String shared;\n    private String hidden;\n    protected int count;\n}\n",
            ),
            (
                "Kid.java",
                "public class Kid extends Base {\n    public static String shared;\n    private String hidden;\n    protected int count;\n}\n",
            ),
        ];
        assert_eq!(
            flagged("java/field-shadows-parent", &files),
            [("Kid.java".to_string(), 4)]
        );
        let ser = [(
            "S.java",
            "import java.io.Serializable;\nimport java.util.List;\npublic class S implements Serializable {\n    private List<?> wild;\n    private List<String> names;\n}\n",
        )];
        assert_eq!(
            flagged("java/serializable-field-type", &ser),
            [("S.java".to_string(), 4)]
        );
    }

    /// Measured on SonarQube 26.7: a reader's `close()` throws an
    /// IOException, which doesn't pass a generic `throws Exception` on.
    #[test]
    fn closing_a_reader_passes_no_exception_on() {
        let files = [(
            "A.java",
            "import java.io.BufferedReader;\npublic class A {\n    public static int f(BufferedReader br) throws Exception {\n        br.close();\n        return 1;\n    }\n\n    public static void g(AutoCloseable c) throws Exception {\n        c.close();\n    }\n}\n",
        )];
        assert_eq!(
            flagged("java/generic-exception-thrown", &files),
            [("A.java".to_string(), 3)]
        );
    }
}
