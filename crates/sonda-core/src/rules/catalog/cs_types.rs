//! What C# rules can know about types without a type checker, from the
//! semantic model (ADR-0008, `semantic/cs.rs`): the type written where a
//! name is declared, and the type of simple expressions over such names.
//! C# declares most types where it declares names, so this covers a lot,
//! but not inference across calls, inherited members or other files. Rules
//! built on it only approximate SonarQube's typed rules unless a match is
//! sound on its own, and say so with `related` references.

use super::cs::simple_name;
use super::cs_bugs::cs_integer;
use super::java_bugs::operator_text;
use super::java_security::text;
use super::*;
use crate::semantic::{Decl, DeclKind, Model};

/// Calls `f` with every node of the file and its ancestors, outermost
/// first: one cursor walk, so rules need no `parent()` calls, which cost a
/// node's depth each.
pub(super) fn walk_tree<'t>(m: &Model<'t>, mut f: impl FnMut(Node<'t>, &[Node<'t>])) {
    let Some(root) = m.root else {
        return;
    };
    let mut cursor = root.walk();
    let mut ancestors: Vec<Node<'t>> = Vec::new();
    loop {
        let node = cursor.node();
        f(node, &ancestors);
        if cursor.goto_first_child() {
            ancestors.push(node);
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return;
            }
            ancestors.pop();
        }
    }
}

/// The value a declarator is initialized with.
fn initializer(declarator: Node) -> Option<Node> {
    if declarator.kind() != "variable_declarator" || declarator.named_child_count() < 2 {
        return None;
    }
    declarator.named_child(declarator.named_child_count() as u32 - 1)
}

/// The declaration a name refers to, for a name used in an expression.
pub(super) fn decl<'m, 't>(m: &'m Model<'t>, name: Node) -> Option<&'m Decl<'t>> {
    match name.kind() {
        "identifier" => m.decl_of(name),
        // `this.x`: the model records x as a reference, other members not.
        "member_access_expression" => name.child_by_field_name("name").and_then(|n| m.decl_of(n)),
        "parenthesized_expression" => name.named_child(0).and_then(|e| decl(m, e)),
        _ => None,
    }
}

/// The declared type of a name used in an expression; for `var x = new T()`,
/// `T`.
pub(super) fn type_of_name<'t>(m: &Model<'t>, name: Node) -> Option<Node<'t>> {
    let d = decl(m, name)?;
    if d.ty.is_some() {
        return d.ty;
    }
    let value = d.declarator.and_then(initializer)?;
    matches!(
        value.kind(),
        "object_creation_expression" | "array_creation_expression" | "cast_expression"
    )
    .then(|| value.child_by_field_name("type"))
    .flatten()
}

/// What a name used in an expression was initialized with where it was
/// declared.
pub(super) fn initial_value<'t>(m: &Model<'t>, name: Node) -> Option<Node<'t>> {
    decl(m, name)
        .and_then(|d| d.declarator)
        .and_then(initializer)
}

/// A type's text without whitespace, `System.` or `global::`, with the
/// framework names of built-in types replaced by their keywords.
pub(super) fn normalized_type(ty: &[u8]) -> Vec<u8> {
    let t: Vec<u8> = ty
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    let t = t.strip_prefix(b"global::").unwrap_or(&t);
    let t = t.strip_prefix(b"System.").unwrap_or(t);
    let keyword: &[u8] = match t {
        b"Int32" => b"int",
        b"Int64" => b"long",
        b"Int16" => b"short",
        b"UInt32" => b"uint",
        b"UInt64" => b"ulong",
        b"UInt16" => b"ushort",
        b"Byte" => b"byte",
        b"SByte" => b"sbyte",
        b"Char" => b"char",
        b"Single" => b"float",
        b"Double" => b"double",
        b"Decimal" => b"decimal",
        b"Boolean" => b"bool",
        b"String" => b"string",
        b"Object" => b"object",
        other => other,
    };
    keyword.to_vec()
}

/// The type of a literal, by its kind and suffix.
fn literal_type(literal: Node, src: &[u8]) -> Option<&'static [u8]> {
    let t = text(literal, src).to_ascii_lowercase();
    Some(match literal.kind() {
        "integer_literal" => {
            // Hex digits never include u or l, so the suffix is unambiguous.
            let suffix: Vec<u8> = t
                .iter()
                .rev()
                .take_while(|b| matches!(b, b'u' | b'l'))
                .copied()
                .collect();
            match (suffix.contains(&b'u'), suffix.contains(&b'l')) {
                (true, true) => b"ulong",
                (false, true) => b"long",
                (true, false) => b"uint",
                _ => b"int",
            }
        }
        "real_literal" => match t.last() {
            Some(b'f') => b"float",
            Some(b'm') => b"decimal",
            _ => b"double",
        },
        "character_literal" => b"char",
        "string_literal"
        | "verbatim_string_literal"
        | "raw_string_literal"
        | "interpolated_string_expression" => b"string",
        "boolean_literal" => b"bool",
        _ => return None,
    })
}

const NUMERIC_RANK: &[&[u8]] = &[b"int", b"uint", b"long", b"ulong", b"float", b"double"];

/// The type of a simple expression: literals, names declared in the file,
/// `this.x`, casts, `new T()`, and arithmetic over those. None when that
/// takes more than declarations.
pub(super) fn expression_type(m: &Model, expr: Node, src: &[u8]) -> Option<Vec<u8>> {
    typed(m, expr, src, 8)
}

/// `expression_type`, giving up after `depth` nested operators.
fn typed(m: &Model, expr: Node, src: &[u8], depth: u8) -> Option<Vec<u8>> {
    let depth = depth.checked_sub(1)?;
    match expr.kind() {
        "parenthesized_expression" => expr.named_child(0).and_then(|e| typed(m, e, src, depth)),
        "prefix_unary_expression" => {
            let operand = expr.named_child(0)?;
            matches!(text(expr, src).first(), Some(b'-' | b'+' | b'~'))
                .then(|| typed(m, operand, src, depth))
                .flatten()
        }
        "cast_expression" | "object_creation_expression" => expr
            .child_by_field_name("type")
            .map(|t| normalized_type(text(t, src))),
        "identifier" | "member_access_expression" => {
            if let Some(t) = type_of_name(m, expr) {
                return Some(normalized_type(text(t, src)));
            }
            // `var n = 0`: the initializer's type.
            initial_value(m, expr)
                .and_then(|v| literal_type(v, src))
                .map(<[u8]>::to_vec)
        }
        "binary_expression" => {
            if !matches!(operator_text(expr, src), b"+" | b"-" | b"*" | b"/" | b"%") {
                return None;
            }
            let l = typed(m, expr.child_by_field_name("left")?, src, depth)?;
            let r = typed(m, expr.child_by_field_name("right")?, src, depth)?;
            numeric_promotion(&l, &r)
        }
        _ => literal_type(expr, src).map(<[u8]>::to_vec),
    }
}

/// The type of `a op b` for two numeric types, or None.
fn numeric_promotion(a: &[u8], b: &[u8]) -> Option<Vec<u8>> {
    let widen = |t: &[u8]| -> Option<usize> {
        match t {
            b"sbyte" | b"byte" | b"short" | b"ushort" | b"char" => Some(0),
            _ => NUMERIC_RANK.iter().position(|r| *r == t),
        }
    };
    let rank = widen(a)?.max(widen(b)?);
    Some(NUMERIC_RANK[rank].to_vec())
}

/// Bits of an integral type after C#'s promotion for shifts: 32 for int
/// and smaller, 64 for long.
pub(super) fn shift_width(ty: &[u8]) -> Option<u32> {
    match ty {
        b"sbyte" | b"byte" | b"short" | b"ushort" | b"char" | b"int" | b"uint" => Some(32),
        b"long" | b"ulong" => Some(64),
        _ => None,
    }
}

/// The range of an integral or float type, as f64 bounds.
pub(super) fn numeric_range(ty: &[u8]) -> Option<(f64, f64)> {
    Some(match ty {
        b"sbyte" => (-128.0, 127.0),
        b"byte" => (0.0, 255.0),
        b"short" => (-32768.0, 32767.0),
        b"ushort" | b"char" => (0.0, 65535.0),
        b"int" => (-2147483648.0, 2147483647.0),
        b"uint" => (0.0, 4294967295.0),
        b"long" => (-9223372036854775808.0, 9223372036854775807.0),
        b"ulong" => (0.0, 18446744073709551615.0),
        b"float" => (-3.4028235e38, 3.4028235e38),
        _ => return None,
    })
}

/// A numeric literal's value, with a leading minus sign.
pub(super) fn numeric_value(expr: Node, src: &[u8]) -> Option<f64> {
    match expr.kind() {
        "parenthesized_expression" => expr.named_child(0).and_then(|e| numeric_value(e, src)),
        "prefix_unary_expression" => {
            let v = numeric_value(expr.named_child(0)?, src)?;
            match text(expr, src).first() {
                Some(b'-') => Some(-v),
                Some(b'+') => Some(v),
                _ => None,
            }
        }
        "integer_literal" => cs_integer(expr, src).map(|v| v as f64),
        "real_literal" => {
            let t: String = String::from_utf8_lossy(text(expr, src)).replace('_', "");
            t.trim_end_matches(['f', 'F', 'd', 'D', 'm', 'M'])
                .parse()
                .ok()
        }
        _ => None,
    }
}

/// The declaration of the type named `name` in this file, such as its
/// `struct_declaration`. None when the file declares that name as
/// different kinds of type (in different namespaces or nested types), since
/// which one a use means takes more than names.
fn declared_kind<'t>(m: &Model<'t>, name: &[u8]) -> Option<Node<'t>> {
    let mut found: Option<Node<'t>> = None;
    for d in m
        .decls
        .iter()
        .filter(|d| d.kind == DeclKind::Class && d.name.as_bytes() == name)
    {
        let declaration = d.node.parent()?;
        match found {
            Some(f) if f.kind() != declaration.kind() => return None,
            Some(_) => {}
            None => found = Some(declaration),
        }
    }
    found
}

/// Whether `ty` is an array or a well-known collection or sequence type.
pub(super) fn is_collection(ty: Node, src: &[u8]) -> bool {
    element_type(ty, src).is_some()
        || matches!(
            simple_name(ty, src),
            b"Dictionary"
                | b"IDictionary"
                | b"IReadOnlyDictionary"
                | b"SortedDictionary"
                | b"ConcurrentDictionary"
                | b"ImmutableDictionary"
        )
}

const VALUE_TYPES: &[&[u8]] = &[
    b"int",
    b"long",
    b"short",
    b"byte",
    b"sbyte",
    b"uint",
    b"ulong",
    b"ushort",
    b"char",
    b"float",
    b"double",
    b"decimal",
    b"bool",
    b"DateTime",
    b"DateTimeOffset",
    b"TimeSpan",
    b"Guid",
    b"CancellationToken",
    b"DateOnly",
    b"TimeOnly",
    b"nint",
    b"nuint",
];

/// A built-in or well-known value type, a nullable one, a tuple, or a
/// struct or enum declared in this file.
pub(super) fn is_value_type(m: &Model, ty: &[u8]) -> bool {
    let t = normalized_type(ty);
    let t = t.strip_suffix(b"?").unwrap_or(&t);
    VALUE_TYPES.contains(&t)
        || t.starts_with(b"(")
        || t.starts_with(b"KeyValuePair<")
        || t.starts_with(b"ValueTuple")
        || declared_kind(m, t).is_some_and(|d| {
            matches!(
                d.kind(),
                "struct_declaration" | "enum_declaration" | "record_struct_declaration"
            )
        })
}

/// Delegate types: the framework's, names ending like one, and delegates
/// declared in this file.
pub(super) fn is_delegate_type(m: &Model, ty: &[u8]) -> bool {
    let t = normalized_type(ty);
    let base = t.split(|b| *b == b'<').next().unwrap_or(&t);
    matches!(
        base,
        b"Action" | b"Func" | b"EventHandler" | b"Predicate" | b"Comparison" | b"Converter"
    ) || [&b"Handler"[..], b"Callback", b"Delegate"]
        .iter()
        .any(|s| base.ends_with(s))
        || declared_kind(m, base).is_some_and(|d| d.kind() == "delegate_declaration")
}

/// Whether the class `derived`, declared in this file, inherits from `base`
/// through classes declared in this file.
pub(super) fn derives_from(m: &Model, derived: &[u8], base: &[u8], src: &[u8]) -> bool {
    let mut current = derived.to_vec();
    for _ in 0..8 {
        let Some(class) = declared_kind(m, &current).filter(|c| c.kind() == "class_declaration")
        else {
            return false;
        };
        let mut cursor = class.walk();
        let Some(first) = class
            .named_children(&mut cursor)
            .find(|c| c.kind() == "base_list")
            .and_then(|b| b.named_child(0))
        else {
            return false;
        };
        let parent = simple_name(first, src);
        if parent == base {
            return true;
        }
        current = parent.to_vec();
    }
    false
}

const COLLECTIONS: &[&[u8]] = &[
    b"List",
    b"IList",
    b"IEnumerable",
    b"ICollection",
    b"IReadOnlyList",
    b"IReadOnlyCollection",
    b"HashSet",
    b"ISet",
    b"IReadOnlySet",
    b"Collection",
    b"ReadOnlyCollection",
    b"ObservableCollection",
    b"Queue",
    b"Stack",
    b"LinkedList",
    b"SortedSet",
    b"ImmutableArray",
    b"ImmutableList",
    b"ImmutableHashSet",
    b"IQueryable",
    b"IAsyncEnumerable",
];

/// The element type of an array or a well-known generic collection type.
pub(super) fn element_type<'t>(ty: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    match ty.kind() {
        "array_type" => ty.child_by_field_name("type"),
        "generic_name" if COLLECTIONS.contains(&simple_name(ty, src)) => {
            let args = ty.named_child(1)?;
            (args.named_child_count() == 1)
                .then(|| args.named_child(0))
                .flatten()
        }
        "qualified_name" => ty
            .child_by_field_name("name")
            .and_then(|n| element_type(n, src)),
        _ => None,
    }
}

/// Whether `ty` is the generic type `name` (`List<T>` for "List").
pub(super) fn is_generic(ty: Node, name: &[u8], src: &[u8]) -> bool {
    let ty = if ty.kind() == "qualified_name" {
        ty.child_by_field_name("name").unwrap_or(ty)
    } else {
        ty
    };
    ty.kind() == "generic_name" && simple_name(ty, src) == name
}
