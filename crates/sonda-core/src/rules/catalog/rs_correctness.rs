//! Rust rules, batch 4 (ADR-0007, ADR-0026): Clippy's correctness lints that
//! one file's syntax can decide, 11 of them batch 3's rewritten. Their
//! documentation is a sentence
//! and an example, so the details were settled by running Clippy on probe
//! files (ADR-0026, "Probing Clippy"). Where a lint needs a type, a rule
//! reports what the file's own declarations prove and is `related` to its key.

use super::java_security::text;
use super::prelude::*;
use super::rs::{arguments, block_items, method, receiver, same_expression, same_pure_expression};
use std::cmp::Ordering;

/// Rules that are off unless `rules.enabled` lists them (see
/// `catalog::OFF_BY_DEFAULT`): SonarQube's default profile has all of these.
pub(super) static OFF_BY_DEFAULT: &[&str] = &[];

const CALL: &str = "(call_expression) @match";
const METHOD_CALL: &str = "(call_expression function: (field_expression field: (field_identifier)) arguments: (arguments)) @match";
const BINARY: &str = "(binary_expression) @match";
const AND: &str = r#"(binary_expression operator: "&&") @match"#;
const IMPL_OF_TRAIT: &str = "(impl_item trait: (_) type: (_)) @match";

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "rs/non-octal-permissions",
        name: "Unix file permissions should be set with octal values",
        description: "`mode(644)` is the decimal 644, octal 1204: not the permissions it looks like.",
        message: "Write these permissions in octal, such as `0o644`.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[related("S7448")],
        check: Check::Query {
            langs: RUST,
            query: CALL,
            filter: Some(Find(non_octal_permissions)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f(o: &mut OpenOptions) { o.mode(644); }",
            good: "fn f(o: &mut OpenOptions) { o.mode(0o644); }",
        }),
    },
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
        id: "rs/match-str-case-mismatch",
        name: "Case mismatches in pattern arms of match expressions should be avoided",
        description: "Matching on a lowercased string, an arm with an uppercase letter never matches \
                      (and the other way round).",
        message: "Change this arm's case to match the converted string.",
        category: Bug,
        severity: Blocker,
        effort_minutes: 5,
        sonar: &[exact("S7428")],
        check: Check::Query {
            langs: RUST,
            query: "(match_expression) @match",
            filter: Some(FindAll(case_mismatched_arms)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f(s: &str) { match s.to_lowercase().as_str() { \"Yes\" => {}, _ => {} } }",
            good: "fn f(s: &str) { match s.to_lowercase().as_str() { \"yes\" => {}, _ => {} } }",
        }),
    },
    Rule {
        id: "rs/infinite-iterator",
        name: "Infinite iterators should be finished off with a terminating operation",
        description: "Counting, collecting or folding an iterator that never ends, such as `(0..)` or \
                      `repeat(x)` without a `take`, never returns.",
        message: "Limit this iterator, with `take` for example, before consuming it.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7464")],
        check: Check::Query {
            langs: RUST,
            query: CALL,
            filter: Some(Keep(consumes_infinite_iterator)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f() -> Vec<u8> { std::iter::repeat(1).collect() }",
            good: "fn f() -> Vec<u8> { std::iter::repeat(1).take(5).collect() }",
        }),
    },
    Rule {
        id: "rs/redundant-comparison",
        name: "Redundant comparisons should be removed",
        description: "In `x <= 400 && x < 500` the second comparison never changes the result: one bound \
                      was probably meant to be the other way round.",
        message: "Remove the comparison that has no effect, or correct its bound.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7436")],
        check: Check::Query {
            langs: RUST,
            query: AND,
            filter: Some(Keep(is_redundant_comparison)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f(x: u32) -> bool { x <= 400 && x < 500 }",
            good: "fn f(x: u32) -> bool { x >= 400 && x < 500 }",
        }),
    },
    Rule {
        id: "rs/impossible-comparison",
        name: "Comparisons with overlapping ranges that are always false should not be made",
        description: "`x <= 400 && x > 500` is never true, so the code it guards never runs.",
        message: "Correct these bounds: together they can never be true.",
        category: Bug,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S7439")],
        check: Check::Query {
            langs: RUST,
            query: AND,
            filter: Some(Keep(is_impossible_comparison)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f(x: u32) -> bool { x <= 400 && x > 500 }",
            good: "fn f(x: u32) -> bool { x >= 400 && x < 500 }",
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
        id: "rs/while-float",
        name: "\"while\" loop counters should not have floating type",
        description: "Rounding errors add up on a floating-point counter, so the number of iterations \
                      isn't the one the bounds suggest.",
        message: "Use an integer counter for this loop.",
        category: Bug,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[related("S2193")],
        check: Check::Query {
            langs: RUST,
            query: "(while_expression condition: (_)) @match",
            filter: Some(Find(float_loop_condition)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f() { let mut x = 0.0; while x < 10.0 { x += 0.1; } }",
            good: "fn f() { let mut i = 0; while i < 100 { i += 1; } }",
        }),
    },
    Rule {
        id: "rs/mut-from-ref",
        name: "Functions should not return mutable references from immutable parameters",
        description: "A `&mut` derived through `unsafe` from a `&` can be made twice, two live mutable \
                      references to one value: undefined behavior.",
        message: "Take a mutable reference to return one, or return a shared reference.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7453")],
        check: Check::Query {
            langs: RUST,
            query: "(function_item return_type: (_)) @match",
            filter: Some(Find(mut_from_ref)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f(x: &u32) -> &mut u32 { unsafe { &mut *(x as *const u32 as *mut u32) } }",
            good: "fn f(x: &mut u32) -> &mut u32 { x }",
        }),
    },
    Rule {
        id: "rs/unsafe-pointer-deref",
        name: "Functions expecting raw pointer arguments should be marked as unsafe",
        description: "A public safe function that dereferences a raw pointer argument lets safe code pass \
                      any pointer and read or write through it.",
        message: "Mark this function `unsafe`, since it dereferences a raw pointer argument.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[related("S7446")],
        check: Check::Query {
            langs: RUST,
            query: "(function_item parameters: (parameters (parameter type: (pointer_type)))) @match",
            filter: Some(FindAll(dereferenced_pointer_arguments)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "pub fn f(p: *const u8) -> u8 { unsafe { *p } }",
            good: "pub unsafe fn f(p: *const u8) -> u8 { unsafe { *p } }",
        }),
    },
    Rule {
        id: "rs/to-string-shadows-display",
        name: "Inherent shadowing definitions of to_string should be avoided",
        description: "An inherent `to_string(&self)` hides the one `Display` provides, so the two can \
                      disagree depending on how the method is reached.",
        message: "Remove this method and rely on the `Display` implementation.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7458")],
        check: Check::Query {
            langs: RUST,
            query: "(impl_item !trait type: (_) body: (declaration_list)) @match",
            filter: Some(FindAll(to_string_shadowing_display)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "struct A;\nimpl A { fn to_string(&self) -> String { String::new() } }\nimpl fmt::Display for A { fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { Ok(()) } }",
            good: "struct A;\nimpl fmt::Display for A { fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { Ok(()) } }",
        }),
    },
    Rule {
        id: "rs/serde-visit-string-only",
        name: "Serde `visit_str` method should be implemented when `visit_string` is implemented",
        description: "Serde calls `visit_str` for borrowed strings, which a visitor implementing only \
                      `visit_string` then rejects.",
        message: "Implement `visit_str` as well.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7460")],
        check: Check::Query {
            langs: RUST,
            query: IMPL_OF_TRAIT,
            filter: Some(Find(visit_string_without_visit_str)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "impl<'de> Visitor<'de> for V { type Value = String; fn visit_string<E>(self, v: String) -> Result<String, E> { Ok(v) } }",
            good: "impl<'de> Visitor<'de> for V { type Value = String; fn visit_str<E>(self, v: &str) -> Result<String, E> { Ok(v.into()) } }",
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
        id: "rs/panicking-unwrap",
        name: "`unwrap()` should only be used when there is a value to unwrap",
        description: "An `unwrap` where the condition just showed the value is `None`, or an `Err`, always \
                      panics: the condition is probably inverted.",
        message: "This always panics: the condition shows there is no value to unwrap.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7442")],
        check: Check::Query {
            langs: RUST,
            query: "[(if_expression) (while_expression)] @match",
            filter: Some(FindAll(panicking_unwraps)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f(o: Option<u8>) -> u8 { if o.is_none() { o.unwrap() } else { 0 } }",
            good: "fn f(o: Option<u8>) -> u8 { if o.is_some() { o.unwrap() } else { 0 } }",
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

fn has_unsafe_modifier(function: Node, src: &[u8]) -> bool {
    let mut c = function.walk();
    function.named_children(&mut c).any(|m| {
        m.kind() == "function_modifiers" && text(m, src).windows(6).any(|w| w == b"unsafe")
    })
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

impl Num {
    fn compare(self, other: Num) -> Option<Ordering> {
        match (self, other) {
            (Num::Int(a), Num::Int(b)) => Some(a.cmp(&b)),
            (Num::Float(a), Num::Float(b)) => a.partial_cmp(&b),
            _ => None,
        }
    }
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

// ---------------------------------------------------------------- comparisons

/// One side of a range check: `subject < value` and its kin.
struct Bound<'t> {
    subject: Node<'t>,
    upper: bool,
    inclusive: bool,
    value: Num,
}

fn bound<'t>(comparison: Node<'t>, src: &[u8]) -> Option<Bound<'t>> {
    let c = unparen(comparison);
    if c.kind() != "binary_expression" {
        return None;
    }
    let (upper, inclusive) = match operator(c, src) {
        b"<" => (true, false),
        b"<=" => (true, true),
        b">" => (false, false),
        b">=" => (false, true),
        _ => return None,
    };
    let (l, r) = operands(c)?;
    match (constant(l, src), constant(r, src)) {
        (None, Some(value)) => Some(Bound {
            subject: l,
            upper,
            inclusive,
            value,
        }),
        (Some(value), None) => Some(Bound {
            subject: r,
            upper: !upper,
            inclusive,
            value,
        }),
        _ => None,
    }
}

/// The two bounds `a && b` puts on one side-effect-free expression.
fn bounds<'t>(and: Node<'t>, src: &[u8]) -> Option<(Bound<'t>, Bound<'t>)> {
    let a = bound(and.child_by_field_name("left")?, src)?;
    let b = bound(and.child_by_field_name("right")?, src)?;
    same_pure_expression(a.subject, b.subject, src).then_some((a, b))
}

fn is_redundant_comparison(and: Node, src: &[u8]) -> bool {
    let Some((a, b)) = bounds(and, src) else {
        return false;
    };
    // The same comparison twice is `identical-operands`' finding.
    a.upper == b.upper
        && a.value
            .compare(b.value)
            .is_some_and(|o| o != Ordering::Equal || a.inclusive != b.inclusive)
}

fn is_impossible_comparison(and: Node, src: &[u8]) -> bool {
    let Some((a, b)) = bounds(and, src) else {
        return false;
    };
    if a.upper == b.upper {
        return false;
    }
    let (low, high) = if a.upper { (b, a) } else { (a, b) };
    match low.value.compare(high.value) {
        Some(Ordering::Greater) => true,
        Some(Ordering::Equal) => !(low.inclusive && high.inclusive),
        _ => false,
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

/// The argument of `mode(644)`, `set_mode(644)` or `Permissions::from_mode(644)`
/// when it's an integer written in decimal or hexadecimal.
fn non_octal_permissions<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let named = if method(call).is_some() {
        method_is(call, src, &["mode", "set_mode"])
    } else {
        function_name(call, src) == Some(b"from_mode")
    };
    let args = arguments(call);
    let [arg] = args.as_slice() else {
        return None;
    };
    let t = text(*arg, src);
    (named && arg.kind() == "integer_literal" && !t.starts_with(b"0o") && !t.starts_with(b"0b"))
        .then_some(*arg)
}

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

// ---------------------------------------------------------------- strings

/// The case conversion a match is over: `to_lowercase` in
/// `match &*s.to_lowercase()`, `s.to_lowercase().as_str()` or
/// `&s.to_lowercase()[..]`.
fn case_conversion<'a>(value: Node, src: &'a [u8]) -> Option<&'a [u8]> {
    let mut n = value;
    loop {
        n = match n.kind() {
            "reference_expression" => n.child_by_field_name("value")?,
            "unary_expression" if text(n, src).starts_with(b"*") => n.named_child(0)?,
            "parenthesized_expression" => n.named_child(0)?,
            "index_expression" if n.named_child(1).is_some_and(|i| text(i, src) == b"..") => {
                n.named_child(0)?
            }
            "call_expression" => {
                let name = text(method(n)?, src);
                match name {
                    b"to_lowercase"
                    | b"to_ascii_lowercase"
                    | b"to_uppercase"
                    | b"to_ascii_uppercase" => {
                        return Some(name);
                    }
                    b"as_str" | b"as_ref" if arguments(n).is_empty() => receiver(n)?,
                    _ => return None,
                }
            }
            _ => return None,
        };
    }
}

/// The arms of a match over a case-converted string whose literal has the
/// other case, and so never matches.
fn case_mismatched_arms<'t>(m: Node<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let Some(conversion) = m
        .child_by_field_name("value")
        .and_then(|v| case_conversion(v, src))
    else {
        return Vec::new();
    };
    let Some(arms) = m.child_by_field_name("body") else {
        return Vec::new();
    };
    let mut c = arms.walk();
    arms.named_children(&mut c)
        .filter_map(|arm| arm.child_by_field_name("pattern")?.named_child(0))
        .filter(|lit| matches!(lit.kind(), "string_literal" | "raw_string_literal"))
        .filter(|lit| {
            let mut c = lit.walk();
            let content: String = lit
                .named_children(&mut c)
                .filter(|p| p.kind() == "string_content")
                .map(|p| String::from_utf8_lossy(text(p, src)).into_owned())
                .collect();
            let converted = match conversion {
                b"to_lowercase" => content.to_lowercase(),
                b"to_ascii_lowercase" => content.to_ascii_lowercase(),
                b"to_uppercase" => content.to_uppercase(),
                _ => content.to_ascii_uppercase(),
            };
            converted != content
        })
        .collect()
}

// ---------------------------------------------------------------- iterators

/// Methods that run an iterator to its end, with their argument counts.
const CONSUMERS: &[(&str, usize)] = &[
    ("count", 0),
    ("collect", 0),
    ("sum", 0),
    ("product", 0),
    ("last", 0),
    ("max", 0),
    ("min", 0),
    ("max_by", 1),
    ("min_by", 1),
    ("max_by_key", 1),
    ("min_by_key", 1),
    ("for_each", 1),
    ("partition", 1),
    ("fold", 2),
];

/// Adapters that are as infinite as what they're called on.
const INFINITE_KEEPING: &[&str] = &[
    "map",
    "filter",
    "skip",
    "enumerate",
    "by_ref",
    "fuse",
    "flat_map",
];

fn consumes_infinite_iterator(call: Node, src: &[u8]) -> bool {
    let Some(name) = method(call) else {
        return false;
    };
    let args = arguments(call).len();
    CONSUMERS
        .iter()
        .any(|(n, a)| n.as_bytes() == text(name, src) && *a == args)
        && receiver(call).is_some_and(|r| is_infinite(r, src))
}

/// Whether an iterator never ends: `(0..)`, `repeat(x)`, `.cycle()`, and
/// what the adapters above make of them.
fn is_infinite(n: Node, src: &[u8]) -> bool {
    let n = unparen(n);
    match n.kind() {
        "range_expression" => {
            let t = text(n, src).trim_ascii();
            n.named_child_count() == 1 && t.ends_with(b"..") && !t.starts_with(b"..")
        }
        "call_expression" => {
            let args = arguments(n);
            let Some(name) = method(n) else {
                return args.len() == 1 && is_std_repeat(n, src);
            };
            let on_infinite = || receiver(n).is_some_and(|r| is_infinite(r, src));
            match text(name, src) {
                b"cycle" => args.is_empty(),
                b"chain" => on_infinite() || args.first().is_some_and(|a| is_infinite(*a, src)),
                b"zip" => on_infinite() && args.first().is_some_and(|a| is_infinite(*a, src)),
                other => INFINITE_KEEPING.iter().any(|k| k.as_bytes() == other) && on_infinite(),
            }
        }
        _ => false,
    }
}

/// `std::iter::repeat`, written with its `iter::` path or imported from it
/// (other crates, such as rayon, have a `repeat` of their own).
fn is_std_repeat(call: Node, src: &[u8]) -> bool {
    let Some(f) = call.child_by_field_name("function") else {
        return false;
    };
    let path = squeezed(f, src);
    let path = path.strip_prefix(b"::").unwrap_or(&path);
    match f.kind() {
        "scoped_identifier" => matches!(
            path,
            b"iter::repeat" | b"std::iter::repeat" | b"core::iter::repeat"
        ),
        "identifier" if path == b"repeat" => {
            let root = ancestors(call).last().unwrap_or(call);
            descendants(root, &["function_item", "impl_item"])
                .into_iter()
                .any(|u| {
                    if u.kind() != "use_declaration" {
                        return false;
                    }
                    let t = squeezed(u, src);
                    let t = t.strip_prefix(b"pub").unwrap_or(&t);
                    let t = t
                        .strip_prefix(b"use::")
                        .or_else(|| t.strip_prefix(b"use"))
                        .unwrap_or(t);
                    (t.starts_with(b"std::iter::") || t.starts_with(b"core::iter::"))
                        && t.split(|b| !(b.is_ascii_alphanumeric() || *b == b'_'))
                            .any(|w| w == b"repeat")
                })
        }
        _ => false,
    }
}

// ---------------------------------------------------------------- floats

/// A `while` condition comparing a floating-point value.
fn float_loop_condition<'t>(w: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let condition = w.child_by_field_name("condition")?;
    let c = unparen(condition);
    let compares = c.kind() == "binary_expression"
        && matches!(
            operator(c, src),
            b"<" | b"<=" | b">" | b">=" | b"==" | b"!="
        );
    let (l, r) = operands(c)?;
    (compares && (is_float(l, src) || is_float(r, src))).then_some(condition)
}

fn is_float_type(ty: Node, src: &[u8]) -> bool {
    matches!(text(ty, src), b"f32" | b"f64")
}

/// Whether an expression is visibly floating-point: a float literal, a cast
/// to a float, or a local declared or initialized as one.
fn is_float(n: Node, src: &[u8]) -> bool {
    let n = unparen(n);
    match n.kind() {
        "identifier" => declaration(n, src).is_some_and(|(ty, value)| {
            ty.is_some_and(|t| is_float_type(t, src))
                || value.is_some_and(|v| is_float_literal(v, src))
        }),
        "type_cast_expression" => n
            .child_by_field_name("type")
            .is_some_and(|t| is_float_type(t, src)),
        _ => is_float_literal(n, src),
    }
}

fn is_float_literal(n: Node, src: &[u8]) -> bool {
    matches!(literal(n, src), Some(Num::Float(_)))
}

// ---------------------------------------------------------------- references

/// The references a type spells out, with their lifetime and whether they're
/// `&mut`; those in function types (`Fn(&mut T)`) aren't the type's own.
fn references<'t>(ty: Node<'t>, src: &[u8]) -> Vec<(Node<'t>, Option<Vec<u8>>, bool)> {
    descendants(ty, &["function_type"])
        .into_iter()
        .filter(|n| n.kind() == "reference_type")
        .map(|r| {
            let mut c = r.walk();
            let children: Vec<Node> = r.named_children(&mut c).collect();
            let lifetime = children
                .iter()
                .find(|c| c.kind() == "lifetime")
                .map(|l| text(*l, src).to_vec());
            let mutable = children.iter().any(|c| c.kind() == "mutable_specifier");
            (r, lifetime, mutable)
        })
        .collect()
}

/// A `&mut` in the return type of a function with `unsafe` code, whose
/// lifetime comes only from shared references among the inputs.
fn mut_from_ref<'t>(function: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let returned = references(function.child_by_field_name("return_type")?, src);
    if !returned.iter().any(|(_, _, m)| *m) {
        return None;
    }
    let body = function.child_by_field_name("body")?;
    let unsafe_code = has_unsafe_modifier(function, src)
        || descendants(body, &["function_item"])
            .iter()
            .any(|n| n.kind() == "unsafe_block");
    if !unsafe_code {
        return None;
    }
    let params = function.child_by_field_name("parameters")?;
    let mut c = params.walk();
    let mut self_ref = None;
    let mut inputs = Vec::new();
    for p in params.named_children(&mut c) {
        match p.kind() {
            "self_parameter" if text(p, src).starts_with(b"&") => {
                let mut c = p.walk();
                let children: Vec<Node> = p.named_children(&mut c).collect();
                let lifetime = children
                    .iter()
                    .find(|c| c.kind() == "lifetime")
                    .map(|l| text(*l, src).to_vec());
                let mutable = children.iter().any(|c| c.kind() == "mutable_specifier");
                self_ref = Some((lifetime.clone(), mutable));
                inputs.push((lifetime, mutable));
            }
            "parameter" => {
                if let Some(t) = p.child_by_field_name("type") {
                    inputs.extend(references(t, src).into_iter().map(|(_, l, m)| (l, m)));
                }
            }
            _ => {}
        }
    }
    returned
        .into_iter()
        .filter(|(_, _, m)| *m)
        .find_map(|(r, lifetime, _)| {
            let sources: Vec<bool> = match lifetime.as_deref() {
                Some(b"'static") => return None,
                Some(l) => inputs
                    .iter()
                    .filter(|(il, _)| il.as_deref() == Some(l))
                    .map(|(_, m)| *m)
                    .collect(),
                // Elided: `&self`'s lifetime, or else the only input reference's.
                None => match (&self_ref, inputs.as_slice()) {
                    (Some((_, m)), _) => vec![*m],
                    (None, [(_, m)]) => vec![*m],
                    _ => return None,
                },
            };
            (!sources.is_empty() && !sources.contains(&true)).then_some(r)
        })
}

/// Raw-pointer methods that are `unsafe` to call.
const UNSAFE_POINTER_METHODS: &[&str] = &[
    "read",
    "read_volatile",
    "read_unaligned",
    "write",
    "write_volatile",
    "write_unaligned",
    "write_bytes",
    "add",
    "sub",
    "offset",
    "byte_add",
    "byte_sub",
    "byte_offset",
    "offset_from",
    "as_ref",
    "as_mut",
    "as_uninit_ref",
    "as_uninit_mut",
    "copy_to",
    "copy_to_nonoverlapping",
    "copy_from",
    "copy_from_nonoverlapping",
    "replace",
    "swap",
    "drop_in_place",
    "get_unchecked",
    "get_unchecked_mut",
];

/// Whether a function is visible outside its crate as far as this file
/// shows: `pub`, in modules that are `pub`, or implementing a trait.
fn is_exported(function: Node, src: &[u8]) -> bool {
    let in_trait_impl = function
        .parent()
        .and_then(|d| d.parent())
        .is_some_and(|i| i.kind() == "impl_item" && i.child_by_field_name("trait").is_some());
    let public = |n: Node| {
        let mut c = n.walk();
        n.named_children(&mut c)
            .any(|v| v.kind() == "visibility_modifier" && text(v, src) == b"pub")
    };
    (in_trait_impl || public(function))
        && ancestors(function)
            .filter(|a| a.kind() == "mod_item")
            .all(public)
}

/// The uses of a public safe function's raw-pointer parameters that
/// dereference them: `*p`, an unsafe pointer method, or passing it to a
/// call inside `unsafe`.
fn dereferenced_pointer_arguments<'t>(function: Node<'t>, src: &[u8]) -> Vec<Node<'t>> {
    if has_unsafe_modifier(function, src) || !is_exported(function, src) {
        return Vec::new();
    }
    let (Some(params), Some(body)) = (
        function.child_by_field_name("parameters"),
        function.child_by_field_name("body"),
    ) else {
        return Vec::new();
    };
    let mut c = params.walk();
    let pointers: Vec<&[u8]> = params
        .named_children(&mut c)
        .filter(|p| {
            p.child_by_field_name("type")
                .is_some_and(|t| t.kind() == "pointer_type")
        })
        .filter_map(|p| p.child_by_field_name("pattern"))
        .filter(|p| p.kind() == "identifier")
        .map(|p| text(p, src))
        .collect();
    let nodes = descendants(body, &["function_item"]);
    // A `let` of the same name hides the parameter from there on.
    let shadowed = |id: Node| {
        nodes.iter().any(|n| {
            n.kind() == "let_declaration"
                && n.end_byte() <= id.start_byte()
                && n.child_by_field_name("pattern")
                    .is_some_and(|p| text(p, src) == text(id, src))
        })
    };
    nodes
        .iter()
        .copied()
        .filter(|n| n.kind() == "identifier" && pointers.contains(&text(*n, src)))
        .filter(|n| !shadowed(*n) && dereferences(*n, body, src))
        .collect()
}

fn dereferences(id: Node, body: Node, src: &[u8]) -> bool {
    let Some(parent) = id.parent() else {
        return false;
    };
    match parent.kind() {
        "unary_expression" => text(parent, src).starts_with(b"*"),
        "field_expression" => {
            parent.child_by_field_name("value") == Some(id)
                && parent
                    .parent()
                    .is_some_and(|c| c.kind() == "call_expression")
                && parent.child_by_field_name("field").is_some_and(|f| {
                    UNSAFE_POINTER_METHODS
                        .iter()
                        .any(|m| m.as_bytes() == text(f, src))
                })
        }
        "arguments" => {
            let in_unsafe = ancestors(parent)
                .take_while(|a| *a != body)
                .any(|a| a.kind() == "unsafe_block");
            in_unsafe
                && parent
                    .parent()
                    .is_some_and(|call| calls_unsafe_function(call, src))
        }
        _ => false,
    }
}

/// Whether a call inside `unsafe` is to an unsafe function: an unsafe
/// pointer method, or a function that the file declares `unsafe` or in an
/// `extern` block, or one it doesn't declare at all.
fn calls_unsafe_function(call: Node, src: &[u8]) -> bool {
    if let Some(m) = method(call) {
        return UNSAFE_POINTER_METHODS
            .iter()
            .any(|u| u.as_bytes() == text(m, src));
    }
    let Some(name) = function_name(call, src) else {
        return true;
    };
    let root = ancestors(call).last().unwrap_or(call);
    let declared: Vec<Node> = descendants(root, &["function_item"])
        .into_iter()
        .filter(|n| {
            matches!(n.kind(), "function_item" | "function_signature_item")
                && n.child_by_field_name("name")
                    .is_some_and(|f| text(f, src) == name)
        })
        .collect();
    declared.is_empty()
        || declared.iter().any(|f| {
            has_unsafe_modifier(*f, src) || ancestors(*f).any(|a| a.kind() == "foreign_mod_item")
        })
}

// ---------------------------------------------------------------- traits

/// The trait an impl implements, by name: `Display` for `impl fmt::Display for A`.
fn trait_name<'a>(imp: Node, src: &'a [u8]) -> Option<&'a [u8]> {
    imp.child_by_field_name("trait").map(|t| type_name(t, src))
}

fn impl_type_name<'a>(imp: Node, src: &'a [u8]) -> Option<&'a [u8]> {
    imp.child_by_field_name("type").map(|t| type_name(t, src))
}

/// The impls in the file for the trait and type, by name.
fn implements(root: Node, src: &[u8], trait_: &[u8], ty: &[u8]) -> bool {
    descendants(root, &["function_item"]).into_iter().any(|n| {
        n.kind() == "impl_item"
            && trait_name(n, src) == Some(trait_)
            && impl_type_name(n, src) == Some(ty)
    })
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

/// An inherent `to_string(&self) -> String` on a type that implements
/// `Display` in the file.
fn to_string_shadowing_display<'t>(imp: Node<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let Some(ty) = impl_type_name(imp, src) else {
        return Vec::new();
    };
    let candidates: Vec<Node> = functions_in(imp)
        .into_iter()
        .filter(|f| {
            function_named(*f, src, b"to_string")
                && f.child_by_field_name("parameters")
                    .is_some_and(|p| squeezed(p, src) == b"(&self)")
                && f.child_by_field_name("return_type")
                    .is_some_and(|r| text(r, src) == b"String")
        })
        .collect();
    if candidates.is_empty() {
        return Vec::new();
    }
    let root = ancestors(imp).last().unwrap_or(imp);
    if implements(root, src, b"Display", ty) {
        candidates
    } else {
        Vec::new()
    }
}

/// A serde `Visitor` that implements `visit_string` but not `visit_str`.
fn visit_string_without_visit_str<'t>(imp: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if trait_name(imp, src) != Some(b"Visitor") {
        return None;
    }
    let functions = functions_in(imp);
    if functions
        .iter()
        .any(|f| function_named(*f, src, b"visit_str"))
    {
        return None;
    }
    functions
        .into_iter()
        .find(|f| function_named(*f, src, b"visit_string"))
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

// ---------------------------------------------------------------- unwrap

#[derive(Clone, Copy, PartialEq)]
enum Variant {
    None,
    Some,
    Ok,
    Err,
}

/// What a condition being `holds` shows about an `Option` or `Result`:
/// each subject and the variant it is.
fn variant_checks<'t>(
    condition: Node<'t>,
    src: &[u8],
    holds: bool,
    out: &mut Vec<(Node<'t>, Variant)>,
) {
    let c = unparen(condition);
    match c.kind() {
        "unary_expression" if text(c, src).starts_with(b"!") => {
            if let Some(inner) = c.named_child(0) {
                variant_checks(inner, src, !holds, out);
            }
        }
        "binary_expression" => {
            let both = matches!((operator(c, src), holds), (b"&&", true) | (b"||", false));
            if let (true, Some((l, r))) = (both, operands(c)) {
                variant_checks(l, src, holds, out);
                variant_checks(r, src, holds, out);
            }
        }
        "call_expression" if arguments(c).is_empty() => {
            let (Some(name), Some(subject)) = (method(c), receiver(c)) else {
                return;
            };
            let variant = match (text(name, src), holds) {
                (b"is_some", true) | (b"is_none", false) => Variant::Some,
                (b"is_none", true) | (b"is_some", false) => Variant::None,
                (b"is_ok", true) | (b"is_err", false) => Variant::Ok,
                (b"is_err", true) | (b"is_ok", false) => Variant::Err,
                _ => return,
            };
            if same_pure_expression(subject, subject, src) {
                out.push((subject, variant));
            }
        }
        _ => {}
    }
}

/// The `unwrap`s and `expect`s in an `if` or `while` that its condition
/// shows will panic.
fn panicking_unwraps<'t>(n: Node<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let Some(condition) = n.child_by_field_name("condition") else {
        return Vec::new();
    };
    let then = n
        .child_by_field_name("consequence")
        .or_else(|| n.child_by_field_name("body"));
    let otherwise = n
        .child_by_field_name("alternative")
        .and_then(|e| e.named_child(0));
    let mut found = Vec::new();
    for (branch, holds) in [(then, true), (otherwise, false)] {
        if let Some(branch) = branch {
            let mut checks = Vec::new();
            variant_checks(condition, src, holds, &mut checks);
            found.extend(unwraps_that_panic(branch, &checks, src));
        }
    }
    found
}

/// The calls in `branch` that unwrap a subject `checks` shows has no value
/// to unwrap, before anything rebinds or assigns it.
fn unwraps_that_panic<'t>(
    branch: Node<'t>,
    checks: &[(Node<'t>, Variant)],
    src: &[u8],
) -> Vec<Node<'t>> {
    let nodes = descendants(branch, &["closure_expression", "function_item"]);
    let calls = nodes
        .iter()
        .copied()
        .filter(|c| c.kind() == "call_expression");
    calls
        .filter(|call| {
            checks.iter().any(|&(subject, variant)| {
                let panics = match variant {
                    Variant::None | Variant::Err => method_is(*call, src, &["unwrap", "expect"]),
                    Variant::Ok => method_is(*call, src, &["unwrap_err", "expect_err"]),
                    Variant::Some => false,
                };
                panics
                    && receiver(*call).is_some_and(|r| same_expression(r, subject, src))
                    && !changed_before(subject, &nodes, call.start_byte(), src)
            })
        })
        .collect()
}

/// Whether, among `nodes`, something before `at` rebinds or assigns `subject`.
fn changed_before(subject: Node, nodes: &[Node], at: usize, src: &[u8]) -> bool {
    nodes.iter().any(|n| {
        n.start_byte() < at
            && match n.kind() {
                "let_declaration" => n
                    .child_by_field_name("pattern")
                    .is_some_and(|p| text(p, src) == text(subject, src)),
                "assignment_expression" | "compound_assignment_expr" => n
                    .child_by_field_name("left")
                    .is_some_and(|l| same_expression(l, subject, src)),
                _ => false,
            }
    })
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
    fn permissions_must_be_octal() {
        let cases = [
            "o.mode(644);",
            "o.mode(0o644);",
            "o.mode(0x1a4);",
            "o.mode(0);",
            "o.mode(0b1);",
            "p.set_mode(755);",
            "let q = Permissions::from_mode(600);",
            "o.mode(M);",
            "o.mode(6_44);",
        ];
        assert_eq!(
            reported("rs/non-octal-permissions", &cases),
            [1, 3, 4, 6, 7, 9]
        );
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
    fn match_arms_in_the_wrong_case() {
        let cases = [
            "match &*text.to_ascii_lowercase() { \"foo\" => {}, \"Bar\" => {}, _ => {} }",
            "match text.to_uppercase().as_str() { \"A\" => {}, \"b\" => {}, _ => {} }",
            "match text.to_ascii_uppercase().as_ref() { \"ok\" => {}, _ => {} }",
            "match s.to_lowercase().as_str() { \"x\" | \"Y\" => {}, _ => {} }",
            "match text.to_lowercase().as_str() { \"1\" => {}, \"é\" => {}, \"É\" => {}, _ => {} }",
            "match text { \"Bar\" => {}, _ => {} }",
            "match &text.to_lowercase()[..] { \"Z\" => {}, _ => {} }",
            "match text.to_lowercase().as_str() { r\"Raw\" => {}, _ => {} }",
            "match text.to_uppercase().as_str() { \"\\u{1F600}\" => {}, _ => {} }",
        ];
        assert_eq!(
            reported("rs/match-str-case-mismatch", &cases),
            [1, 2, 3, 5, 7, 8]
        );
    }

    #[test]
    fn infinite_iterators_consumed_whole() {
        let cases = [
            "let a: Vec<u8> = std::iter::repeat(1u8).collect();",
            "let b = (0..).count();",
            "let c = (0..).map(|x| x * 2).sum::<u64>();",
            "let d = (0..).take(5).count();",
            "let e = [1, 2].iter().cycle().count();",
            "let h = (0..).find(|x| *x > 5);",
            "let i = (0..).zip(0..10).count();",
            "let m = (0..).skip(3).count();",
            "let n = std::iter::repeat_with(|| 1).count();",
            "let p = (0..).chain(0..3).count();",
            "let q = (1..).step_by(2).count();",
            "let r = (0..).fold(0, |a, x| a + x);",
            "let s = v.iter().chain((0..).map(|_| &0)).count();",
            "let t = (0..).peekable().count();",
        ];
        assert_eq!(
            reported("rs/infinite-iterator", &cases),
            [1, 2, 3, 5, 8, 10, 12, 13]
        );
        // Another crate's `repeat` (rayon's) is not std's.
        let src = "use rayon::iter::repeat;\nfn f() { repeat(()).count(); }\n";
        assert!(lines("rs/infinite-iterator", src).is_empty());
        let src = "use std::iter::{once, repeat};\nfn f() { repeat(()).count(); }\n";
        assert_eq!(lines("rs/infinite-iterator", src), [2]);
    }

    #[test]
    fn double_comparisons_against_constants() {
        let cases = [
            "if x <= 400 && x < 500 {}",
            "if x <= 400 && x > 500 {}",
            "if x > 10 && x > 5 {}",
            "if x == 5 && x < 10 {}",
            "if x > 5 || x > 10 {}",
            "if x < 5 && x >= 5 {}",
            "if x <= 5 && x >= 5 {}",
            "if 400 >= x && x < 500 {}",
            "if x < LIMIT && x < 20 {}",
            "if x < -1 && x > 3 {}",
            "if x as u8 > 3 && x as u8 > 4 {}",
            "if f < 1.0 && f < 2.0 {}",
            "if g() < 5 && g() < 10 {}",
            "if c >= 'z' && c <= 'a' {}",
            "if x > 5 && x < 6 {}",
            "if y && x < 5 && x < 10 {}",
            "if x < 5 && x < 5 {}",
            "if v.len() > 3 && v.len() > 5 {}",
        ];
        let src_cases: Vec<&str> = std::iter::once("const LIMIT: i32 = 10;")
            .chain(cases)
            .collect();
        let shifted = |v: Vec<usize>| v.into_iter().map(|l| l - 1).collect::<Vec<_>>();
        assert_eq!(
            shifted(reported("rs/redundant-comparison", &src_cases)),
            [1, 3, 8, 9, 11, 12]
        );
        assert_eq!(
            shifted(reported("rs/impossible-comparison", &src_cases)),
            [2, 6, 10, 14]
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
    fn while_conditions_on_floats() {
        let src = "fn f(mut x: f64, g: f64, n: i32) {\n\
                   while x < 42.0 { x += 1.0; }\n\
                   while (x as i32) < 4 { x += 1.0; }\n\
                   while x < 42f64 { x += 1.0; }\n\
                   let mut y = 0.0f32;\n\
                   while y < 3.0 { y += 0.1; }\n\
                   while x < g { x += 1.0; }\n\
                   let mut i = 0;\n\
                   while i < 10 { i += 1; }\n\
                   while x < 4.0 && n > 2 { x += 1.0; }\n\
                   while !(x > 4.0) { x += 1.0; }\n\
                   }\n";
        assert_eq!(lines("rs/while-float", src), [2, 4, 6, 7]);
    }

    #[test]
    fn mutable_references_from_shared_ones() {
        let src = "struct Foo { v: u32 }\n\
            fn r1(x: &Foo) -> &mut u32 { unsafe { &mut *(&x.v as *const u32 as *mut u32) } }\n\
            fn r2(x: &Foo) -> &mut u32 { todo!() }\n\
            fn r3<'a>(x: &'a Foo, y: &'a mut Foo) -> &'a mut u32 { unsafe { cast(x) } }\n\
            fn r4<'a, 'b>(x: &'a Foo, y: &'b mut Foo) -> &'a mut u32 { unsafe { cast(x) } }\n\
            impl Foo {\n\
            fn m1(&self) -> &mut u32 { unsafe { cast(self) } }\n\
            fn m2(&mut self) -> &mut u32 { &mut self.v }\n\
            fn m3(&self) -> Option<&mut u32> { unsafe { Some(cast(self)) } }\n\
            fn m4(&self, x: &mut u32) -> &mut u32 { unsafe { cast(self) } }\n\
            unsafe fn m5(&self) -> &mut u32 { cast(self) }\n\
            fn m6(&self) -> &'static mut u32 { unsafe { cast(self) } }\n\
            fn m7(&self) -> (&u32, &mut u32) { unsafe { (&self.v, cast(self)) } }\n\
            }\n";
        assert_eq!(lines("rs/mut-from-ref", src), [2, 5, 7, 9, 10, 11, 13]);
    }

    #[test]
    fn public_safe_functions_dereferencing_pointer_arguments() {
        let src = "pub fn p1(x: *const u8) -> u8 { unsafe { *x } }\n\
            pub unsafe fn p2(x: *const u8) -> u8 { *x }\n\
            fn p3(x: *const u8) -> u8 { unsafe { *x } }\n\
            pub fn p5(x: *const u8) -> u8 { unsafe { x.read() } }\n\
            pub fn p6(x: *const u8) -> u8 { unsafe { std::ptr::read(x) } }\n\
            pub fn p7(x: *const u8) -> bool { x.is_null() }\n\
            pub(crate) fn p9(x: *const u8) -> u8 { unsafe { *x } }\n\
            pub struct P;\n\
            impl P { pub fn p10(&self, x: *const u8) -> u8 { unsafe { *x } } }\n\
            pub fn p12(x: *const u8) -> u8 { let y = x; unsafe { *y } }\n\
            impl T1 for P { fn t(&self, x: *const u8) -> u8 { unsafe { *x } } }\n\
            pub fn p13(x: *const u8) -> usize { let x = x as usize; unsafe { from_usize(x) } }\n\
            fn safe_helper(p: *const u8) -> bool { p.is_null() }\n\
            pub fn p14(x: *const u8) -> bool { unsafe { safe_helper(x) } }\n\
            pub fn p15(a: *const u8, b: *const u8) -> bool { unsafe { a.cmp(&b).is_lt() } }\n\
            mod private { pub fn p16(x: *const u8) -> u8 { unsafe { *x } } }\n";
        assert_eq!(lines("rs/unsafe-pointer-deref", src), [1, 4, 5, 9, 11]);
    }

    #[test]
    fn to_string_beside_display() {
        let src = "pub struct A;\n\
            impl A { pub fn to_string(&self) -> String { String::new() } }\n\
            impl fmt::Display for A { fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { Ok(()) } }\n\
            pub struct B;\n\
            impl B { pub fn to_string(&self) -> String { String::new() } }\n\
            pub struct D;\n\
            impl D { pub fn to_string(&self, x: u8) -> String { String::new() } }\n\
            impl std::fmt::Display for D { fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { Ok(()) } }\n";
        assert_eq!(lines("rs/to-string-shadows-display", src), [2]);
    }

    #[test]
    fn serde_visitors_need_visit_str() {
        let src = "impl<'de> de::Visitor<'de> for V {\n    fn visit_string<E>(self, v: String) -> Result<(), E> { Ok(()) }\n}\n\
            impl<'de> Visitor<'de> for W {\n    fn visit_str<E>(self, v: &str) -> Result<(), E> { Ok(()) }\n    fn visit_string<E>(self, v: String) -> Result<(), E> { Ok(()) }\n}\n";
        assert_eq!(lines("rs/serde-visit-string-only", src), [2]);
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
    fn unwraps_the_condition_shows_will_panic() {
        let cases = [
            "if o.is_none() { o.unwrap(); }",
            "if o.is_some() { o.unwrap(); } else { o.unwrap(); }",
            "if r.is_err() { r.unwrap(); }",
            "if r.is_ok() { r.unwrap_err(); }",
            "if !o.is_some() { o.expect(\"x\"); }",
            "if o.is_none() { let o = Some(1); o.unwrap(); }",
            "if o.is_none() && ready { o.unwrap(); }",
            "if o.is_none() || ready { o.unwrap(); }",
            "if p.is_none() { p = Some(1); p.unwrap(); }",
            "if let None = o { o.unwrap(); }",
            "while o.is_none() { o.unwrap(); break; }",
            "if o.is_none() { let c = || o.unwrap(); }",
            "if s.o.is_none() { s.o.unwrap(); }",
        ];
        assert_eq!(
            reported("rs/panicking-unwrap", &cases),
            [1, 2, 3, 4, 5, 7, 11, 13]
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
