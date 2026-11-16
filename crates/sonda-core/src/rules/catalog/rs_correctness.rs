//! Rust rules, batch 4 (ADR-0007, ADR-0026): more of Clippy's correctness
//! lints that one file's syntax can decide. Their documentation is a sentence
//! and an example, so the details were settled by running Clippy on probe
//! files (ADR-0026, "Probing Clippy"). Where a lint needs a type, a rule
//! reports what the file's own declarations prove and is `related` to its key.

use super::java_security::text;
use super::prelude::*;
use super::rs::{arguments, block_items, method, receiver, same_pure_expression};

/// Rules that are off unless `rules.enabled` lists them (see
/// `catalog::OFF_BY_DEFAULT`): SonarQube's default profile has all of these.
pub(super) static OFF_BY_DEFAULT: &[&str] = &[];

const CALL: &str = "(call_expression) @match";
const METHOD_CALL: &str = "(call_expression function: (field_expression field: (field_identifier)) arguments: (arguments)) @match";
const BINARY: &str = "(binary_expression) @match";
const IMPL_OF_TRAIT: &str = "(impl_item trait: (_) type: (_)) @match";

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "rs/nonsensical-open-options",
        name: "File open options should be consistent",
        description: "An option set twice, `truncate` with `read` but not `write`, or `truncate` with \
                      `append` opens the file in a way that can't be what was meant.",
        message: "Make these open options consistent.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7447")],
        check: Check::Query {
            langs: RUST,
            query: METHOD_CALL,
            filter: Some(FindAll(nonsensical_open_options)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f() { let _ = OpenOptions::new().read(true).truncate(true).open(\"a\"); }",
            good: "fn f() { let _ = OpenOptions::new().write(true).truncate(true).open(\"a\"); }",
        }),
    },
    Rule {
        id: "rs/bad-bit-mask",
        name: "Incompatible bit masks should not be used in comparisons",
        description: "When the mask fixes the bits the comparison looks at, as in `x & 2 == 3`, the result \
                      is the same whatever `x` is.",
        message: "Correct this mask or the value it's compared with: the result never changes.",
        category: Bug,
        severity: Blocker,
        effort_minutes: 5,
        sonar: &[exact("S7438")],
        check: Check::Query {
            langs: RUST,
            query: BINARY,
            filter: Some(Keep(is_bad_bit_mask)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f(x: u32) -> bool { x & 1 == 2 }",
            good: "fn f(x: u32) -> bool { x & 2 == 2 }",
        }),
    },
    Rule {
        id: "rs/ineffective-bit-mask",
        name: "Unnecessary bit operations should not be performed",
        description: "In `x | 2 > 3` the mask can't change the outcome: it reads as `x > 3`.",
        message: "Remove this bit mask, which doesn't change the comparison.",
        category: CodeSmell,
        severity: Blocker,
        effort_minutes: 5,
        sonar: &[exact("S2437")],
        check: Check::Query {
            langs: RUST,
            query: BINARY,
            filter: Some(Keep(is_ineffective_bit_mask)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f(x: u32) -> bool { x | 2 > 3 }",
            good: "fn f(x: u32) -> bool { x > 3 }",
        }),
    },
    Rule {
        id: "rs/hash-borrow-str-and-bytes",
        name: "Conflicting `Borrow` and `Hash` implementations should be avoided",
        description: "A `str` and its bytes hash differently, so a type that implements `Hash`, \
                      `Borrow<str>` and `Borrow<[u8]>` breaks lookups through one of the borrows.",
        message: "Remove `Borrow<str>` or `Borrow<[u8]>`: their hashes can't both agree with this one.",
        category: Bug,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S7461")],
        check: Check::Query {
            langs: RUST,
            query: r#"(impl_item trait: [(type_identifier) @t (scoped_type_identifier name: (type_identifier) @t)] (#eq? @t "Hash")) @match
                      (attribute_item (attribute (identifier) @d arguments: (token_tree (identifier) @h)) (#eq? @d "derive") (#eq? @h "Hash")) @match"#,
            filter: Some(Keep(hashes_with_str_and_bytes_borrows)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "#[derive(Hash)]\nstruct K(String);\nimpl Borrow<str> for K { fn borrow(&self) -> &str { &self.0 } }\nimpl Borrow<[u8]> for K { fn borrow(&self) -> &[u8] { self.0.as_bytes() } }",
            good: "#[derive(Hash)]\nstruct K(String);\nimpl Borrow<str> for K { fn borrow(&self) -> &str { &self.0 } }",
        }),
    },
    Rule {
        id: "rs/recursive-format-impl",
        name: "Formatting trait implementations should not be recursive",
        description: "Formatting `self` with the trait being implemented, or calling `self.to_string()` in \
                      `Display`, calls the same `fmt` again until the stack overflows.",
        message: "Format the fields here instead of `self`, which recurses forever.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7440")],
        check: Check::Query {
            langs: RUST,
            query: IMPL_OF_TRAIT,
            filter: Some(FindAll(recursive_formatting)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "impl fmt::Display for S { fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, \"{}\", self) } }",
            good: "impl fmt::Display for S { fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, \"{}\", self.0) } }",
        }),
    },
    Rule {
        id: "rs/unit-returned-for-ord",
        name: "Closures of `type Fn(...) -> Ord` should not return the unit type",
        description: "`()` implements `Ord`, so a key closure that ends in `;` compiles, and sorts or \
                      compares nothing.",
        message: "Return the key from this closure: it returns `()`.",
        category: Bug,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[related("S7421")],
        check: Check::Query {
            langs: RUST,
            query: METHOD_CALL,
            filter: Some(Find(unit_key_closure)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f(v: &mut [(u8, u8)]) { v.sort_by_key(|x| { x.1; }); }",
            good: "fn f(v: &mut [(u8, u8)]) { v.sort_by_key(|x| x.1); }",
        }),
    },
    Rule {
        id: "rs/overflow-check-panics",
        name: "`checked_add` and `overflowing_add` should be used to prevent overflows",
        description: "`a + b < a` is C's overflow check, but in a debug build the addition panics before \
                      the comparison runs.",
        message: "Use `checked_add` or `overflowing_add` to detect the overflow.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[related("S7444")],
        check: Check::Query {
            langs: RUST,
            query: BINARY,
            filter: Some(Keep(is_panicking_overflow_check)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f(a: u32, b: u32) -> bool { a + b < a }",
            good: "fn f(a: u32, b: u32) -> bool { a.checked_add(b).is_none() }",
        }),
    },
    Rule {
        id: "rs/eager-transmute",
        name: "Calls to `std::mem::transmute` should not be evaluated eagerly",
        description: "`then_some` evaluates its argument first, so a transmute guarded by the condition \
                      runs even when the condition is false.",
        message: "Use `then(|| ...)` so the transmute runs only when the condition holds.",
        category: Bug,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[related("S7443")],
        check: Check::Query {
            langs: RUST,
            query: METHOD_CALL,
            filter: Some(Keep(transmutes_eagerly)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f(op: u8) -> Option<Op> { (op < 4).then_some(unsafe { std::mem::transmute(op) }) }",
            good: "fn f(op: u8) -> Option<Op> { (op < 4).then(|| unsafe { std::mem::transmute(op) }) }",
        }),
    },
    Rule {
        id: "rs/size-of-as-element-count",
        name: "`size_of::<T>` should not be used to count elements of type `T`",
        description: "These functions count elements of `T`; a count in bytes copies or covers `size_of::<T>()` \
                      times too much.",
        message: "Pass a count of elements here, not of bytes.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[related("S7431")],
        check: Check::Query {
            langs: RUST,
            query: CALL,
            filter: Some(Find(element_count_in_bytes)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "unsafe fn f(p: *const u16, q: *mut u16, n: usize) { std::ptr::copy(p, q, size_of::<u16>() * n); }",
            good: "unsafe fn f(p: *const u16, q: *mut u16, n: usize) { std::ptr::copy(p, q, n); }",
        }),
    },
];

// ---------------------------------------------------------------- helpers

/// The expression inside any parentheses.
fn unparen(mut n: Node) -> Node {
    while n.kind() == "parenthesized_expression" {
        match n.named_child(0) {
            Some(inner) => n = inner,
            None => break,
        }
    }
    n
}

fn operator<'a>(n: Node, src: &'a [u8]) -> &'a [u8] {
    n.child_by_field_name("operator")
        .map_or(&[][..], |o| text(o, src))
}

/// The operands of a binary expression, without their parentheses.
fn operands<'t>(n: Node<'t>) -> Option<(Node<'t>, Node<'t>)> {
    Some((
        unparen(n.child_by_field_name("left")?),
        unparen(n.child_by_field_name("right")?),
    ))
}

fn method_is(call: Node, src: &[u8], names: &[&str]) -> bool {
    method(call).is_some_and(|m| names.iter().any(|n| text(m, src) == n.as_bytes()))
}

/// The last segment of the path a function call names: `repeat` in
/// `std::iter::repeat::<u8>(1)`. None for a method call.
fn function_name<'a>(call: Node, src: &'a [u8]) -> Option<&'a [u8]> {
    let mut f = call.child_by_field_name("function")?;
    if f.kind() == "generic_function" {
        f = f.child_by_field_name("function")?;
    }
    match f.kind() {
        "identifier" => Some(text(f, src)),
        "scoped_identifier" => Some(text(f.child_by_field_name("name")?, src)),
        _ => None,
    }
}

/// A type's name without its path or generic arguments: `Display` for
/// `std::fmt::Display`, `Visitor` for `de::Visitor<'de>`.
fn type_name<'a>(ty: Node, src: &'a [u8]) -> &'a [u8] {
    let mut t = ty;
    if t.kind() == "generic_type" {
        t = t.child_by_field_name("type").unwrap_or(t);
    }
    if t.kind() == "scoped_type_identifier" {
        t = t.child_by_field_name("name").unwrap_or(t);
    }
    text(t, src)
}

/// Text without whitespace, to compare types however they're spaced.
fn squeezed(n: Node, src: &[u8]) -> Vec<u8> {
    text(n, src)
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect()
}

fn ancestors(n: Node) -> impl Iterator<Item = Node> {
    std::iter::successors(n.parent(), |p| p.parent())
}

/// The nodes under `root`, `root` included, not descending into the kinds
/// `skip` names.
fn descendants<'t>(root: Node<'t>, skip: &[&str]) -> Vec<Node<'t>> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        out.push(n);
        if n != root && skip.contains(&n.kind()) {
            continue;
        }
        let mut c = n.walk();
        stack.extend(n.named_children(&mut c));
    }
    out
}

/// The type and value a local is declared with: the last `let` before `at`
/// in the enclosing function, or else its parameter.
fn declaration<'t>(at: Node<'t>, src: &[u8]) -> Option<(Option<Node<'t>>, Option<Node<'t>>)> {
    let name = text(at, src);
    let function = ancestors(at).find(|n| n.kind() == "function_item")?;
    let body = function.child_by_field_name("body")?;
    let last_let = descendants(body, &["function_item", "closure_expression"])
        .into_iter()
        .filter(|n| {
            n.kind() == "let_declaration"
                && n.end_byte() <= at.start_byte()
                && n.child_by_field_name("pattern")
                    .is_some_and(|p| p.kind() == "identifier" && text(p, src) == name)
        })
        .max_by_key(|n| n.start_byte());
    if let Some(l) = last_let {
        return Some((
            l.child_by_field_name("type"),
            l.child_by_field_name("value"),
        ));
    }
    let params = function.child_by_field_name("parameters")?;
    let mut c = params.walk();
    params
        .named_children(&mut c)
        .find(|p| {
            p.kind() == "parameter"
                && p.child_by_field_name("pattern")
                    .is_some_and(|q| q.kind() == "identifier" && text(q, src) == name)
        })
        .map(|p| (p.child_by_field_name("type"), None))
}

/// A literal's type suffix: `u8` in `1u8`, `f64` in `2.0f64`.
fn literal_suffix(literal: Node, src: &[u8]) -> &'static str {
    let t = text(literal, src);
    let hex = t.starts_with(b"0x");
    const SUFFIXES: &[&str] = &[
        "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize",
        "f32", "f64",
    ];
    SUFFIXES
        .iter()
        .find(|s| t.ends_with(s.as_bytes()) && !(hex && s.starts_with('f')))
        .copied()
        .unwrap_or("")
}

// ---------------------------------------------------------------- constants

/// An integer or floating-point constant.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Num {
    Int(i128),
    Float(f64),
}

/// The value of a literal, a negated one, a character, or a constant the
/// file declares with a literal value.
fn constant(n: Node, src: &[u8]) -> Option<Num> {
    let n = unparen(n);
    match n.kind() {
        "identifier" => file_constant(n, src),
        _ => literal(n, src),
    }
}

fn literal(n: Node, src: &[u8]) -> Option<Num> {
    let n = unparen(n);
    match n.kind() {
        "integer_literal" if literal_suffix(n, src).starts_with('f') => {
            float(&text(n, src)[..text(n, src).len() - 3])
        }
        "integer_literal" => super::rs::integer_value(n, src)
            .and_then(|v| i128::try_from(v).ok())
            .map(Num::Int),
        "float_literal" => {
            let t = text(n, src);
            let t = t
                .strip_suffix(b"f32")
                .or_else(|| t.strip_suffix(b"f64"))
                .unwrap_or(t);
            float(t)
        }
        "char_literal" => {
            let t = std::str::from_utf8(text(n, src)).ok()?;
            let inner = t.strip_prefix('\'')?.strip_suffix('\'')?;
            let mut chars = inner.chars();
            match (chars.next(), chars.next()) {
                (Some(c), None) if c != '\\' => Some(Num::Int(c as i128)),
                _ => None,
            }
        }
        "unary_expression" if text(n, src).starts_with(b"-") => {
            match literal(n.named_child(0)?, src)? {
                Num::Int(v) => Some(Num::Int(-v)),
                Num::Float(v) => Some(Num::Float(-v)),
            }
        }
        _ => None,
    }
}

fn float(digits: &[u8]) -> Option<Num> {
    let s: String = std::str::from_utf8(digits)
        .ok()?
        .chars()
        .filter(|c| *c != '_')
        .collect();
    s.parse().ok().map(Num::Float)
}

/// `LIMIT`'s value, when the file has `const LIMIT: T = <literal>;` once (a
/// constant declared per `#[cfg]` has the value of the configuration built).
fn file_constant(name: Node, src: &[u8]) -> Option<Num> {
    let id = text(name, src);
    // Constants are named in upper case; anything else is a variable.
    if !id
        .iter()
        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
    {
        return None;
    }
    let root = ancestors(name).last()?;
    // Item-level constants, and those of the blocks around the use: not every
    // node, as most of a file is in function bodies.
    let named = |n: &Node| {
        n.kind() == "const_item"
            && n.child_by_field_name("name")
                .is_some_and(|n| text(n, src) == id)
    };
    let local = ancestors(name)
        .filter(|a| a.kind() == "block")
        .flat_map(|b| {
            let mut c = b.walk();
            b.named_children(&mut c).collect::<Vec<_>>()
        });
    let declared: Vec<Node> = descendants(root, &["function_item"])
        .into_iter()
        .chain(local)
        .filter(named)
        .collect();
    match declared.as_slice() {
        [c] => literal(c.child_by_field_name("value")?, src),
        _ => None,
    }
}

fn integer_constant(n: Node, src: &[u8]) -> Option<u128> {
    match constant(n, src)? {
        Num::Int(v) => u128::try_from(v).ok(),
        Num::Float(_) => None,
    }
}

// ---------------------------------------------------------------- bit masks

/// `x <mask op> m <comparison> c`, the constant on either side of each:
/// the comparison (turned so the masked value is on its left), the mask
/// operator, `m` and `c`.
fn masked_comparison<'a>(n: Node, src: &'a [u8]) -> Option<(&'a [u8], &'a [u8], u128, u128)> {
    let op = operator(n, src);
    if !matches!(op, b"==" | b"!=" | b"<" | b"<=" | b">" | b">=") {
        return None;
    }
    let (l, r) = operands(n)?;
    let (masked, c, op) = match (integer_constant(l, src), integer_constant(r, src)) {
        (None, Some(c)) => (l, c, op),
        (Some(c), None) => (r, c, flipped(op)),
        _ => return None,
    };
    if masked.kind() != "binary_expression" {
        return None;
    }
    let mask_op = operator(masked, src);
    if !matches!(mask_op, b"&" | b"|" | b"^") {
        return None;
    }
    let (ml, mr) = operands(masked)?;
    let m = match (integer_constant(ml, src), integer_constant(mr, src)) {
        (None, Some(m)) | (Some(m), None) => m,
        _ => return None,
    };
    Some((op, mask_op, m, c))
}

fn flipped(op: &[u8]) -> &'static [u8] {
    match op {
        b"<" => b">",
        b"<=" => b">=",
        b">" => b"<",
        b">=" => b"<=",
        b"==" => b"==",
        _ => b"!=",
    }
}

/// Clippy's table for `bad_bit_mask`: the comparison is constant.
fn is_bad_bit_mask(n: Node, src: &[u8]) -> bool {
    let Some((op, mask_op, m, c)) = masked_comparison(n, src) else {
        return false;
    };
    match (mask_op, op) {
        // Masking with zero leaves nothing to compare.
        (b"&", _) if m == 0 => true,
        (b"&", b"==" | b"!=") => c & m != c,
        (b"&", b"<" | b">=") => m < c,
        (b"&", b">" | b"<=") => m <= c,
        (b"|", b"==" | b"!=") => c | m != c,
        (b"|", b"<" | b">=") => m >= c,
        (b"|", b">" | b"<=") => m > c,
        _ => false,
    }
}

/// Clippy's table for `ineffective_bit_mask`: an `|` or `^` below a power of
/// two the comparison is against can't change the result.
fn is_ineffective_bit_mask(n: Node, src: &[u8]) -> bool {
    let Some((op, mask_op, m, c)) = masked_comparison(n, src) else {
        return false;
    };
    if !matches!(mask_op, b"|" | b"^") {
        return false;
    }
    match op {
        b">" | b"<=" => c
            .checked_add(1)
            .is_some_and(|limit| limit.is_power_of_two() && m < limit),
        b"<" | b">=" => c.is_power_of_two() && m < c,
        _ => false,
    }
}

// ---------------------------------------------------------------- files

const OPEN_OPTIONS: &[&str] = &[
    "read",
    "write",
    "append",
    "truncate",
    "create",
    "create_new",
];

/// In `OpenOptions::new()...open(path)`, each option set again, and the
/// whole chain when it truncates a file opened to read and not write, or
/// to append.
fn nonsensical_open_options<'t>(open: Node<'t>, src: &[u8]) -> Vec<Node<'t>> {
    if !method_is(open, src, &["open"]) {
        return Vec::new();
    }
    // The option calls, last first.
    let mut options: Vec<(Node, bool)> = Vec::new();
    let mut current = receiver(open);
    let start = loop {
        let Some(call) = current.filter(|c| c.kind() == "call_expression") else {
            return Vec::new();
        };
        let Some(name) = method(call) else {
            break call;
        };
        let args = arguments(call);
        let set = matches!(args.as_slice(), [a] if text(*a, src) == b"true");
        options.push((name, set));
        current = receiver(call);
    };
    let path = start
        .child_by_field_name("function")
        .map(|f| squeezed(f, src))
        .unwrap_or_default();
    if !(path.ends_with(b"OpenOptions::new") || path.ends_with(b"File::options"))
        || !arguments(start).is_empty()
    {
        return Vec::new();
    }
    options.reverse();
    let mut found = Vec::new();
    for (i, (name, _)) in options.iter().enumerate() {
        let n = text(*name, src);
        if OPEN_OPTIONS.iter().any(|o| o.as_bytes() == n)
            && options[..i]
                .iter()
                .any(|(earlier, _)| text(*earlier, src) == n)
        {
            found.push(*name);
        }
    }
    let set = |option: &str| {
        options
            .iter()
            .any(|(n, on)| *on && text(*n, src) == option.as_bytes())
    };
    if set("truncate") && set("read") && !set("write") {
        found.push(open);
    }
    if set("truncate") && set("append") {
        found.push(open);
    }
    found
}

// ---------------------------------------------------------------- traits

/// The trait an impl implements, by name: `Display` for `impl fmt::Display for A`.
fn trait_name<'a>(imp: Node, src: &'a [u8]) -> Option<&'a [u8]> {
    imp.child_by_field_name("trait").map(|t| type_name(t, src))
}

fn impl_type_name<'a>(imp: Node, src: &'a [u8]) -> Option<&'a [u8]> {
    imp.child_by_field_name("type").map(|t| type_name(t, src))
}

fn functions_in<'t>(imp: Node<'t>) -> Vec<Node<'t>> {
    let Some(body) = imp.child_by_field_name("body") else {
        return Vec::new();
    };
    let mut c = body.walk();
    body.named_children(&mut c)
        .filter(|n| n.kind() == "function_item")
        .collect()
}

fn function_named(f: Node, src: &[u8], name: &[u8]) -> bool {
    f.child_by_field_name("name")
        .is_some_and(|n| text(n, src) == name)
}

/// A `Hash` impl, or a `#[derive(Hash)]`, for a type the file also gives
/// `Borrow<str>` and `Borrow<[u8]>`.
fn hashes_with_str_and_bytes_borrows(node: Node, src: &[u8]) -> bool {
    let ty = match node.kind() {
        "impl_item" if trait_name(node, src) == Some(b"Hash") => impl_type_name(node, src),
        "attribute_item" if derives_hash(node, src) => derived_type(node, src),
        _ => None,
    };
    let Some(ty) = ty else {
        return false;
    };
    if !src.windows(7).any(|w| w == b"Borrow<") {
        return false;
    }
    let root = ancestors(node).last().unwrap_or(node);
    let borrows: Vec<Vec<u8>> = descendants(root, &["function_item"])
        .into_iter()
        .filter(|n| {
            n.kind() == "impl_item"
                && trait_name(*n, src) == Some(b"Borrow")
                && impl_type_name(*n, src) == Some(ty)
        })
        .filter_map(|n| {
            let args = n
                .child_by_field_name("trait")?
                .child_by_field_name("type_arguments")?;
            Some(squeezed(args, src))
        })
        .collect();
    borrows.iter().any(|b| b == b"<str>") && borrows.iter().any(|b| b == b"<[u8]>")
}

fn derives_hash(attribute: Node, src: &[u8]) -> bool {
    let Some(a) = attribute.named_child(0) else {
        return false;
    };
    let mut c = a.walk();
    let named: Vec<Node> = a.named_children(&mut c).collect();
    matches!(named.first(), Some(n) if text(*n, src) == b"derive")
        && named.iter().skip(1).any(|args| {
            let mut c = args.walk();
            args.named_children(&mut c).any(|t| text(t, src) == b"Hash")
        })
}

/// The struct, enum or union an attribute is on.
fn derived_type<'a>(attribute: Node, src: &'a [u8]) -> Option<&'a [u8]> {
    let mut n = attribute.next_named_sibling();
    while let Some(s) = n {
        match s.kind() {
            "attribute_item" | "line_comment" | "block_comment" => n = s.next_named_sibling(),
            "struct_item" | "enum_item" | "union_item" => {
                return Some(text(s.child_by_field_name("name")?, src));
            }
            _ => return None,
        }
    }
    None
}

// ---------------------------------------------------------------- formatting

/// Macros that format their arguments, and where the format string is.
const FORMAT_MACROS: &[(&str, usize)] = &[
    ("write", 1),
    ("writeln", 1),
    ("format", 0),
    ("format_args", 0),
    ("print", 0),
    ("println", 0),
    ("eprint", 0),
    ("eprintln", 0),
];

/// In `impl Display` or `impl Debug`, each formatting of `self` with the
/// same trait, and in `Display` each `self.to_string()`.
fn recursive_formatting<'t>(imp: Node<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let debug = match trait_name(imp, src) {
        Some(b"Display") => false,
        Some(b"Debug") => true,
        _ => return Vec::new(),
    };
    functions_in(imp)
        .into_iter()
        .filter(|f| function_named(*f, src, b"fmt"))
        .filter_map(|f| f.child_by_field_name("body"))
        .flat_map(|body| descendants(body, &["function_item", "impl_item"]))
        .filter(|n| match n.kind() {
            "macro_invocation" => formats_self(*n, src, debug),
            "call_expression" => {
                !debug
                    && method_is(*n, src, &["to_string"])
                    && arguments(*n).is_empty()
                    && receiver(*n).is_some_and(|r| text(r, src) == b"self")
            }
            _ => false,
        })
        .collect()
}

/// A macro's arguments: its token tree split at the top-level commas.
fn macro_arguments(tokens: Node) -> Vec<Vec<Node>> {
    let mut args = vec![Vec::new()];
    let mut c = tokens.walk();
    let children: Vec<Node> = tokens.children(&mut c).collect();
    for child in children
        .iter()
        .skip(1)
        .take(children.len().saturating_sub(2))
    {
        if child.kind() == "," {
            args.push(Vec::new());
        } else if let Some(last) = args.last_mut() {
            last.push(*child);
        }
    }
    args
}

/// Whether a format macro formats `self` with `Debug` (`debug`) or
/// `Display`, by its format string's placeholders.
fn formats_self(mac: Node, src: &[u8], debug: bool) -> bool {
    let Some(name) = mac.child_by_field_name("macro").map(|m| text(m, src)) else {
        return false;
    };
    let Some(&(_, at)) = FORMAT_MACROS.iter().find(|(n, _)| n.as_bytes() == name) else {
        return false;
    };
    let Some(tokens) = mac
        .named_children(&mut mac.walk())
        .find(|c| c.kind() == "token_tree")
    else {
        return false;
    };
    let args = macro_arguments(tokens);
    let Some([format]) = args.get(at).map(Vec::as_slice) else {
        return false;
    };
    if !matches!(format.kind(), "string_literal" | "raw_string_literal") {
        return false;
    }
    let rest = &args[at + 1..];
    let arg_text = |tokens: &[Node]| -> Vec<u8> {
        tokens
            .iter()
            .flat_map(|t| text(*t, src).iter().copied())
            .collect()
    };
    let named = |name: &[u8]| {
        rest.iter().find_map(|a| match a.as_slice() {
            [n, eq, value @ ..] if text(*n, src) == name && eq.kind() == "=" => {
                Some(arg_text(value))
            }
            _ => None,
        })
    };
    let positional: Vec<Vec<u8>> = rest
        .iter()
        .filter(|a| !matches!(a.as_slice(), [_, eq, ..] if eq.kind() == "="))
        .map(|a| arg_text(a))
        .collect();
    let mut next = 0;
    placeholders(text(*format, src))
        .into_iter()
        .any(|(arg, spec)| {
            let target = if arg.is_empty() {
                next += 1;
                positional.get(next - 1).cloned()
            } else if let Ok(i) = std::str::from_utf8(&arg).unwrap_or("x").parse::<usize>() {
                positional.get(i).cloned()
            } else {
                named(&arg).or(Some(arg.clone()))
            };
            let is_debug = spec.ends_with(b"?");
            let other_trait = !is_debug && spec.last().is_some_and(|c| b"xXobeEp".contains(c));
            let same_trait = if debug {
                is_debug
            } else {
                !is_debug && !other_trait
            };
            same_trait
                && target.is_some_and(|t| matches!(t.as_slice(), b"self" | b"&self" | b"*self"))
        })
}

/// A format string's placeholders: the argument each names (empty for the
/// next positional one) and its format spec.
fn placeholders(format: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < format.len() {
        match format[i] {
            b'{' if format.get(i + 1) == Some(&b'{') => i += 2,
            b'{' => {
                let Some(len) = format[i + 1..].iter().position(|b| *b == b'}') else {
                    break;
                };
                let inside = &format[i + 1..i + 1 + len];
                let (arg, spec) = match inside.iter().position(|b| *b == b':') {
                    Some(colon) => (&inside[..colon], &inside[colon + 1..]),
                    None => (inside, &[][..]),
                };
                out.push((arg.trim_ascii().to_vec(), spec.to_vec()));
                i += len + 2;
            }
            _ => i += 1,
        }
    }
    out
}

// ---------------------------------------------------------------- closures

const ORD_KEY_METHODS: &[&str] = &[
    "sort_by_key",
    "sort_unstable_by_key",
    "sort_by_cached_key",
    "max_by_key",
    "min_by_key",
    "binary_search_by_key",
    "is_sorted_by_key",
    "select_nth_unstable_by_key",
];

/// The key closure of a sort or comparison by key, when it returns `()`.
fn unit_key_closure<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !method_is(call, src, ORD_KEY_METHODS) {
        return None;
    }
    let closure = arguments(call)
        .into_iter()
        .last()
        .filter(|a| a.kind() == "closure_expression")?;
    returns_unit(closure.child_by_field_name("body")?, src).then_some(closure)
}

fn returns_unit(body: Node, src: &[u8]) -> bool {
    match body.kind() {
        "unit_expression" => true,
        "return_expression" => body.named_child_count() == 0,
        "block" => block_items(body)
            .into_iter()
            .rfind(|n| n.kind() != "attribute_item")
            .is_none_or(|last| match last.kind() {
                "expression_statement" => text(last, src).ends_with(b";"),
                "let_declaration" | "empty_statement" => true,
                "macro_invocation" => last.child_by_field_name("macro").is_some_and(|m| {
                    matches!(
                        text(m, src),
                        b"print" | b"println" | b"eprint" | b"eprintln"
                    )
                }),
                _ => returns_unit(last, src),
            }),
        _ => false,
    }
}

// ---------------------------------------------------------------- arithmetic

/// `a + b < a`, `a > a + b`, `a - b > a` and `a < a - b`, unless `a` is
/// declared signed or floating-point, which Clippy leaves alone.
fn is_panicking_overflow_check(n: Node, src: &[u8]) -> bool {
    let Some((l, r)) = operands(n) else {
        return false;
    };
    let shared = match operator(n, src) {
        b"<" => sum_with(l, r, src).or_else(|| difference_from(r, l, src)),
        b">" => sum_with(r, l, src).or_else(|| difference_from(l, r, src)),
        _ => None,
    };
    shared.is_some_and(|s| !is_signed_or_float(s, src))
}

/// The operand of the sum `sum` that `operand` repeats.
fn sum_with<'t>(sum: Node<'t>, operand: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if sum.kind() != "binary_expression" || operator(sum, src) != b"+" {
        return None;
    }
    let (a, b) = operands(sum)?;
    [a, b]
        .into_iter()
        .find(|x| same_pure_expression(*x, operand, src))
}

/// `diff`'s left operand, when it's `a - b` and `a` is `operand`.
fn difference_from<'t>(diff: Node<'t>, operand: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if diff.kind() != "binary_expression" || operator(diff, src) != b"-" {
        return None;
    }
    let (a, _) = operands(diff)?;
    same_pure_expression(a, operand, src).then_some(a)
}

fn is_signed_or_float(n: Node, src: &[u8]) -> bool {
    let signed = |t: &[u8]| t.starts_with(b"i") || t.starts_with(b"f");
    match n.kind() {
        "identifier" => declaration(n, src).is_some_and(|(ty, value)| {
            ty.is_some_and(|t| t.kind() == "primitive_type" && signed(text(t, src)))
                || value.is_some_and(|v| {
                    matches!(v.kind(), "integer_literal" | "float_literal")
                        && signed(literal_suffix(v, src).as_bytes())
                })
                || value.is_some_and(|v| v.kind() == "float_literal")
        }),
        "integer_literal" | "float_literal" => {
            n.kind() == "float_literal" || signed(literal_suffix(n, src).as_bytes())
        }
        _ => false,
    }
}

// ---------------------------------------------------------------- transmute

/// `(x < 4).then_some(transmute(x))`: a transmute of the value the
/// condition checks, run whether or not it holds.
fn transmutes_eagerly(call: Node, src: &[u8]) -> bool {
    if !method_is(call, src, &["then_some"]) {
        return false;
    }
    let args = arguments(call);
    let (Some(condition), [argument]) = (receiver(call), args.as_slice()) else {
        return false;
    };
    let Some(transmute) = descendants(*argument, &["closure_expression"])
        .into_iter()
        .find(|n| n.kind() == "call_expression" && function_name(*n, src) == Some(b"transmute"))
    else {
        return false;
    };
    let transmuted = arguments(transmute);
    let [value] = transmuted.as_slice() else {
        return false;
    };
    // A transmute to an integer or float has no invalid values.
    let to_number = transmute
        .child_by_field_name("function")
        .filter(|f| f.kind() == "generic_function")
        .and_then(|f| f.child_by_field_name("type_arguments"))
        .and_then(|a| a.named_child(1))
        .is_some_and(|t| t.kind() == "primitive_type" && text(t, src) != b"bool");
    !to_number && checks_value(condition, *value, src)
}

/// Whether a condition compares `value`, or tests it with `contains(&value)`.
fn checks_value(condition: Node, value: Node, src: &[u8]) -> bool {
    descendants(condition, &["closure_expression"]).into_iter().any(|n| match n.kind() {
        "binary_expression" if matches!(operator(n, src), b"<" | b"<=" | b">" | b">=" | b"==" | b"!=") => {
            operands(n).is_some_and(|(l, r)| same_pure_expression(l, value, src) || same_pure_expression(r, value, src))
        }
        "call_expression" if method_is(n, src, &["contains"]) => matches!(
            arguments(n).as_slice(),
            [a] if a.kind() == "reference_expression"
                && a.child_by_field_name("value").is_some_and(|v| same_pure_expression(v, value, src))
        ),
        _ => false,
    })
}

// ---------------------------------------------------------------- sizes

/// Functions and methods taking a count of elements, and which argument it
/// is (a method's receiver is a pointer too).
const COUNT_FUNCTIONS: &[(&str, usize)] = &[
    ("copy", 2),
    ("copy_nonoverlapping", 2),
    ("swap_nonoverlapping", 2),
    ("from_raw_parts", 1),
    ("from_raw_parts_mut", 1),
];
const COUNT_METHODS: &[(&str, usize)] = &[
    ("copy_to", 1),
    ("copy_from", 1),
    ("copy_to_nonoverlapping", 1),
    ("copy_from_nonoverlapping", 1),
    ("add", 0),
];

/// The count argument of a pointer copy or slice construction when it's
/// `size_of::<T>()` times something and the pointers point to `T`.
fn element_count_in_bytes<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let args = arguments(call);
    let (index, mut pointers) = match method(call) {
        Some(m) => {
            let &(_, i) = COUNT_METHODS
                .iter()
                .find(|(n, _)| n.as_bytes() == text(m, src))?;
            (i, vec![receiver(call)?])
        }
        None => {
            let name = function_name(call, src)?;
            let &(_, i) = COUNT_FUNCTIONS.iter().find(|(n, _)| n.as_bytes() == name)?;
            (i, Vec::new())
        }
    };
    let count = *args.get(index)?;
    pointers.extend(args.iter().take(index).copied());
    let element = bytes_of(count, src)?;
    if matches!(element.as_slice(), b"u8" | b"i8") {
        return None;
    }
    pointers
        .into_iter()
        .any(|p| pointee(p, src).as_deref() == Some(element.as_slice()))
        .then_some(count)
}

/// `T` when an expression is `size_of::<T>()`, a product with it, or such a
/// product divided by something.
fn bytes_of(n: Node, src: &[u8]) -> Option<Vec<u8>> {
    let n = unparen(n);
    match n.kind() {
        "type_cast_expression" => bytes_of(n.child_by_field_name("value")?, src),
        "call_expression"
            if function_name(n, src) == Some(b"size_of") && arguments(n).is_empty() =>
        {
            let f = n.child_by_field_name("function")?;
            let args = if f.kind() == "generic_function" {
                f.child_by_field_name("type_arguments")?
            } else {
                super::rs::type_arguments(f)?
            };
            Some(squeezed(args.named_child(0)?, src))
        }
        "binary_expression" => {
            let (l, r) = operands(n)?;
            match operator(n, src) {
                b"*" => bytes_of(l, src).or_else(|| bytes_of(r, src)),
                b"/" => bytes_of(l, src),
                _ => None,
            }
        }
        _ => None,
    }
}

/// What a pointer points to, when the file shows it: a local declared
/// `*const T`, `slice.as_ptr()` on a local declared as a slice, array or
/// `Vec` of `T`, or a cast to `*const T`.
fn pointee(p: Node, src: &[u8]) -> Option<Vec<u8>> {
    let p = unparen(p);
    match p.kind() {
        "type_cast_expression" => {
            let t = p.child_by_field_name("type")?;
            pointer_target(t, src)
        }
        "identifier" => {
            let t = declaration(p, src)?.0?;
            pointer_target(t, src)
        }
        "call_expression" if method_is(p, src, &["as_ptr", "as_mut_ptr"]) => {
            let owner = receiver(p).filter(|r| r.kind() == "identifier")?;
            element_type(declaration(owner, src)?.0?, src)
        }
        _ => None,
    }
}

fn pointer_target(ty: Node, src: &[u8]) -> Option<Vec<u8>> {
    if ty.kind() != "pointer_type" {
        return None;
    }
    Some(squeezed(ty.child_by_field_name("type")?, src))
}

/// `T` for `&[T]`, `&mut [T]`, `[T; N]`, `Vec<T>` and `&Vec<T>`.
fn element_type(ty: Node, src: &[u8]) -> Option<Vec<u8>> {
    match ty.kind() {
        "reference_type" => element_type(ty.child_by_field_name("type")?, src),
        "array_type" => Some(squeezed(ty.child_by_field_name("element")?, src)),
        "generic_type" if type_name(ty, src) == b"Vec" => Some(squeezed(
            ty.child_by_field_name("type_arguments")?.named_child(0)?,
            src,
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    //! Each case is one Clippy was run on (ADR-0026, "Batch 3"), with what it
    //! reported.
    use crate::analysis::analyze;
    use crate::config::Config;
    use crate::lang::Lang;
    use crate::rules::RuleSet;
    use std::time::{Duration, Instant};

    fn lines(rule: &str, src: &str) -> Vec<usize> {
        let cfg = Config::default();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        let a = analyze("t.rs", Lang::Rust, src, &rules, &cfg, deadline).unwrap();
        a.issues
            .iter()
            .filter(|i| i.rule == rule)
            .map(|i| i.line)
            .collect()
    }

    /// The lines `rule` reports when each of `cases` is a line of a function.
    fn reported(rule: &str, cases: &[&str]) -> Vec<usize> {
        let body: String = cases.iter().map(|c| format!("    {c}\n")).collect();
        lines(rule, &format!("fn f() {{\n{body}}}\n"))
            .into_iter()
            .map(|l| l - 1)
            .collect()
    }

    #[test]
    fn open_options_conflict_or_repeat() {
        let cases = [
            "OpenOptions::new().read(true).truncate(true).open(\"a\")?;",
            "OpenOptions::new().read(true).write(true).truncate(true).open(\"a\")?;",
            "OpenOptions::new().write(true).write(false).open(\"a\")?;",
            "OpenOptions::new().append(true).truncate(true).open(\"a\")?;",
            "OpenOptions::new().create(true).read(true).open(\"a\")?;",
            "OpenOptions::new().read(false).truncate(true).open(\"a\")?;",
            "OpenOptions::new().read(true).append(true).truncate(true).open(\"a\")?;",
            "OpenOptions::new().read(w).truncate(true).open(\"a\")?;",
            "std::fs::File::options().read(true).truncate(true).open(\"a\")?;",
            // Without `open` there is nothing to judge yet.
            "OpenOptions::new().read(true).truncate(true);",
        ];
        assert_eq!(
            reported("rs/nonsensical-open-options", &cases),
            [1, 3, 4, 7, 9]
        );
    }

    #[test]
    fn a_constant_declared_per_cfg_has_no_known_value() {
        let src = "#[cfg(linux)]\nconst P: u16 = 0x2000;\n#[cfg(not(linux))]\nconst P: u16 = 0;\nfn f(e: u16) -> bool { e & P != 0 }\n";
        assert!(lines("rs/bad-bit-mask", src).is_empty());
        let src = "const K: u32 = 4;\nfn f(x: u32) -> bool { x & K == 3 }\n";
        assert_eq!(lines("rs/bad-bit-mask", src), [2]);
    }

    #[test]
    fn bit_masks_by_clippys_tables() {
        let cases = [
            "if x & 2 == 3 {}",
            "if x & 2 < 3 {}",
            "if x & 1 > 1 {}",
            "if x | 1 == 0 {}",
            "if x | 1 < 1 {}",
            "if x | 1 > 0 {}",
            "if x & 2 == 2 {}",
            "if x | 2 > 3 {}",
            "if x ^ 1 < 4 {}",
            "if x | 1 >= 7 {}",
            "if x | 2 <= 3 {}",
            "if x | 4 > 3 {}",
            "if 3 == x & 2 {}",
            "if (x & 2) == 3 {}",
            "if x & 0 == 0 {}",
            "if x & 0x0f == 0x10 {}",
            "if x & y == 3 {}",
            "if x ^ 1 == 3 {}",
            "if x | 0 > 3 {}",
            "if x & 3 == 0 {}",
        ];
        assert_eq!(
            reported("rs/bad-bit-mask", &cases),
            [1, 2, 3, 4, 5, 6, 12, 13, 14, 15, 16]
        );
        assert_eq!(reported("rs/ineffective-bit-mask", &cases), [8, 9, 11, 19]);
    }

    #[test]
    fn hash_with_both_borrows() {
        let src = "pub struct H { data: String }\n\
            impl Hash for H { fn hash<S: Hasher>(&self, state: &mut S) { self.data.hash(state); } }\n\
            impl Borrow<str> for H { fn borrow(&self) -> &str { &self.data } }\n\
            impl Borrow<[u8]> for H { fn borrow(&self) -> &[u8] { self.data.as_bytes() } }\n\
            #[derive(Hash)]\n\
            pub struct H2 { data: String }\n\
            impl Borrow<str> for H2 { fn borrow(&self) -> &str { &self.data } }\n\
            impl Borrow<[u8]> for H2 { fn borrow(&self) -> &[u8] { self.data.as_bytes() } }\n\
            pub struct H3 { data: String }\n\
            impl Borrow<str> for H3 { fn borrow(&self) -> &str { &self.data } }\n\
            impl Borrow<[u8]> for H3 { fn borrow(&self) -> &[u8] { self.data.as_bytes() } }\n\
            #[derive(Hash, Debug)]\n\
            pub struct H4 { data: String }\n\
            impl Borrow<str> for H4 { fn borrow(&self) -> &str { &self.data } }\n";
        assert_eq!(lines("rs/hash-borrow-str-and-bytes", src), [2, 5]);
    }

    #[test]
    fn formatting_self_with_the_same_trait() {
        let imp = |t: &str, body: &str| {
            format!(
                "impl fmt::{t} for S {{ fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {{ {body} }} }}\n"
            )
        };
        let src = [
            imp("Display", "write!(f, \"{}\", self.to_string())"),
            imp("Display", "write!(f, \"{}\", self)"),
            imp("Debug", "write!(f, \"{:?}\", self)"),
            imp("Display", "write!(f, \"{:?}\", self)"),
            imp("Display", "write!(f, \"{}\", &self)"),
            imp("Display", "let s = self.to_string(); f.write_str(&s)"),
            imp("Display", "write!(f, \"{}\", *self)"),
            imp("Display", "write!(f, \"{self}\")"),
            imp("Display", "writeln!(f, \"{}\", self)"),
            imp("Display", "fmt::Display::fmt(self, f)"),
            imp("Display", "write!(f, \"{} and {:?}\", self.0, self)"),
            imp("Display", "write!(f, \"{:>5}\", self)"),
            imp("Display", "write!(f, \"{0}\", self)"),
            imp("LowerHex", "write!(f, \"{:x}\", self)"),
            imp("Display", "let s = format!(\"{}\", self); f.write_str(&s)"),
            imp("Display", "println!(\"{}\", self); Ok(())"),
            imp("Display", "write!(f, \"{}\", self.0.to_string())"),
            imp("Display", "write!(f, \"{}{}\", self.0, x = self)"),
        ]
        .concat();
        assert_eq!(
            lines("rs/recursive-format-impl", &src),
            [1, 2, 3, 5, 6, 7, 8, 9, 12, 13, 15, 16]
        );
    }

    #[test]
    fn key_closures_returning_unit() {
        let cases = [
            "v.sort_by_key(|x| { x.1; });",
            "v.sort_by_key(|x| x.1);",
            "let m = v.iter().max_by_key(|x| { x.1; });",
            "v.sort_by_key(|x| { let y = x.1; y });",
            "v.sort_by_key(|x| {});",
            "v.sort_by_key(|x| ());",
            "v.dedup_by_key(|x| { x.1; });",
            "v.select_nth_unstable_by_key(0, |x| { x.1; });",
            "v.sort_by_key(|x| { if x.0 > 1 { 1 } else { 0 }; });",
            "v.sort_by_key(|x| { return; });",
            "v.sort_by_key(|x| { println!(\"x\") });",
            "v.sort_by_key(|x| { match x.0 { 1 => 2, _ => 3 } });",
        ];
        assert_eq!(
            reported("rs/unit-returned-for-ord", &cases),
            [1, 3, 5, 6, 8, 9, 10, 11]
        );
    }

    #[test]
    fn c_style_overflow_checks() {
        let src = "fn f(a: u32, b: u32, c: i64) {\n\
                   if a + b < a {}\n\
                   if a > a + b {}\n\
                   if a + b < b {}\n\
                   if a - b > a {}\n\
                   if a < a - b {}\n\
                   if a + b <= a {}\n\
                   if a.wrapping_add(b) < a {}\n\
                   if a < (a + 1) {}\n\
                   if c + 1 < c {}\n\
                   let x = 1i32; let y = 2i32;\n\
                   if x + y < x {}\n\
                   }\n";
        assert_eq!(lines("rs/overflow-check-panics", src), [2, 3, 4, 5, 6]);
    }

    #[test]
    fn transmutes_then_some_runs_first() {
        let cases = [
            "let a = (op < 2).then_some(unsafe { std::mem::transmute::<u8, Op>(op) });",
            "let b = (op < 2).then(|| unsafe { std::mem::transmute::<u8, Op>(op) });",
            "let d = (op < 2 && op > 0).then_some(unsafe { std::mem::transmute::<u8, Op>(op) });",
            "let f = (true).then_some(unsafe { std::mem::transmute::<u8, Op>(op) });",
            "let g = (op < 2).then_some(unsafe { std::mem::transmute::<u8, Op>(1) });",
            "let h: Option<Op> = (op < 2).then_some(unsafe { std::mem::transmute(op) });",
            "let j = (op < 2).then_some(unsafe { std::mem::transmute::<u8, i8>(op) });",
            "let l = (0..2).contains(&op).then_some(unsafe { std::mem::transmute::<u8, Op>(op) });",
        ];
        assert_eq!(reported("rs/eager-transmute", &cases), [1, 3, 6, 8]);
    }

    #[test]
    fn byte_counts_where_elements_are_counted() {
        let src = "unsafe fn f(p: *const u16, q: *mut u16, n: usize, s: &[u16], t: &mut [u16], b: &[u8], c: &mut [u8]) {\n\
                   ptr::copy_nonoverlapping(p, q, size_of::<u16>() * n);\n\
                   ptr::copy_nonoverlapping(p, q, n);\n\
                   ptr::copy_nonoverlapping(s.as_ptr(), t.as_mut_ptr(), size_of::<u16>() * n);\n\
                   ptr::copy_nonoverlapping(b.as_ptr(), c.as_mut_ptr(), size_of::<u8>() * n);\n\
                   std::slice::from_raw_parts(p, n * std::mem::size_of::<u16>());\n\
                   p.copy_to(q, size_of::<u16>() * n);\n\
                   ptr::copy_nonoverlapping(p, q, size_of::<u16>() * n / 2);\n\
                   ptr::copy_nonoverlapping(p, q, n / size_of::<u16>());\n\
                   ptr::copy_nonoverlapping(p, q, size_of::<u32>() * n);\n\
                   ptr::copy_nonoverlapping(p, q, size_of::<u16>() + n);\n\
                   ptr::copy_nonoverlapping(p, q, (size_of::<u16>() * n) as usize);\n\
                   ptr::write_bytes(q, 0, size_of::<u16>() * n);\n\
                   ptr::copy_nonoverlapping(p as *const u8, q as *mut u8, size_of::<u16>() * n);\n\
                   }\n";
        assert_eq!(
            lines("rs/size-of-as-element-count", src),
            [2, 4, 6, 7, 8, 12]
        );
    }
}
