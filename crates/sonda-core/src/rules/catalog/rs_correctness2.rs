//! Rust rules, batch 5 (ADR-0007, ADR-0026): nine more of Clippy's
//! correctness lints, seven of them `rs_last.rs`'s rewritten, settled on
//! probe files as batch 4's were (ADR-0026, "Probing Clippy"). Where a lint
//! needs a type, a rule reports what the file's own declarations prove and
//! is `related` to its key.

use super::java_security::text;
use super::prelude::*;
use super::rs::{arguments, block_items, integer_value, method, receiver, same_pure_expression};
use super::rs_correctness::{
    ancestors, declaration, descendants, literal_suffix, macro_arguments, method_is, operands,
    operator, unparen,
};

/// Rules that are off unless `rules.enabled` lists them (see
/// `catalog::OFF_BY_DEFAULT`): SonarQube's default profile has all of these.
pub(super) static OFF_BY_DEFAULT: &[&str] = &[];

const BINARY: &str = "(binary_expression) @match";

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "rs/possible-missing-comma",
        name: "Array elements should be separated by commas",
        description: "An element `-2` at a line's end, then a line starting `-3`, is the one element \
                      `-2 - 3`: without a comma, the line break hides a subtraction.",
        message: "Add the comma this element is probably missing, or keep the operator on the line before.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3723")],
        check: Check::Query {
            langs: RUST,
            query: "(array_expression) @match\n\
                    (macro_invocation macro: (identifier) @m (token_tree) (#eq? @m \"vec\")) @match",
            filter: Some(FindAll(missing_commas)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "const A: [i32; 4] = [-1, -2, -3\n    -4, -5];",
            good: "const A: [i32; 5] = [-1, -2, -3,\n    -4, -5];",
        }),
    },
    Rule {
        id: "rs/useless-lint-attribute",
        name: "Lint attributes should not be used on crate imports",
        description: "`#[deny(dead_code)]` on a `use` or `extern crate` applies to that import alone, where \
                      the lint never fires; the attribute was most likely meant for the module, as \
                      `#![deny(dead_code)]`.",
        message: "Move this lint attribute to the module, as `#![...]`, or remove it.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7418")],
        check: Check::Query {
            langs: RUST,
            query: "(use_declaration) @match\n(extern_crate_declaration) @match",
            filter: Some(FindAll(useless_lint_attributes)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "#[deny(dead_code)]\nextern crate foo;",
            good: "#![deny(dead_code)]\nextern crate foo;",
        }),
    },
    Rule {
        id: "rs/unused-io-amount",
        name: "I/O buffers should be processed entirely",
        description: "`write` and `read` may process only part of the buffer and return how much they did; \
                      ignoring that count loses the rest.",
        message: "Use `write_all` or `read_exact`, or handle the count this returns.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[related("S7419")],
        check: Check::Query {
            langs: RUST,
            query: "(expression_statement) @match",
            filter: Some(Find(unused_io_amount)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f<W: std::io::Write>(w: &mut W) -> std::io::Result<()> { w.write(b\"foo\")?; Ok(()) }",
            good: "fn f<W: std::io::Write>(w: &mut W) -> std::io::Result<()> { w.write_all(b\"foo\")?; Ok(()) }",
        }),
    },
    Rule {
        id: "rs/enum-clike-unportable",
        name: "C-like enums should not have unportable variants",
        description: "An `isize` or `usize` discriminant that doesn't fit in 32 bits is truncated on a \
                      32-bit target, and works only on 64-bit ones.",
        message: "Give this enum a fixed-size `repr`, such as `#[repr(u64)]`, or a smaller value.",
        category: Bug,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S7426")],
        check: Check::Query {
            langs: RUST,
            query: "(enum_item) @match",
            filter: Some(FindAll(unportable_variants)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "#[repr(usize)]\nenum E { X = 0x1_0000_0000, Y = 0 }",
            good: "#[repr(u64)]\nenum E { X = 0x1_0000_0000, Y = 0 }",
        }),
    },
    Rule {
        id: "rs/inverted-saturating-sub",
        name: "`saturating_sub` should be used to avoid subtraction underflow",
        description: "`if a > b { b - a } else { 0 }` subtracts the greater value from the smaller, which \
                      underflows: the operands are the wrong way round.",
        message: "Swap these operands, or use `saturating_sub`.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[related("S7463")],
        check: Check::Query {
            langs: RUST,
            query: "(if_expression alternative: (else_clause)) @match",
            filter: Some(Find(inverted_saturating_sub)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f(a: u32, b: u32) -> u32 { if a > b { b - a } else { 0 } }",
            good: "fn f(a: u32, b: u32) -> u32 { a.saturating_sub(b) }",
        }),
    },
    Rule {
        id: "rs/absurd-extreme-comparison",
        name: "Unnecessary mathematical comparisons should not be made",
        description: "Comparing a value with its type's minimum or maximum, as in `len < 0` or \
                      `x > u8::MAX`, is always true, always false, or an equality written as an \
                      inequality.",
        message: "Remove this comparison, or write the equality it amounts to.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[related("S2198")],
        check: Check::Query {
            langs: RUST,
            query: BINARY,
            filter: Some(Keep(is_absurd_extreme_comparison)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f(v: &[u8]) -> bool { v.len() <= 0 }",
            good: "fn f(v: &[u8]) -> bool { v.is_empty() }",
        }),
    },
    Rule {
        id: "rs/while-immutable-condition",
        name: "Immutable variables should not be used in while loop conditions",
        description: "When the loop body changes none of the variables its condition reads, and the \
                      condition calls nothing, the loop runs never or forever.",
        message: "Change a variable of this condition in the loop, or rewrite the loop.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7415")],
        check: Check::Query {
            langs: RUST,
            query: "(while_expression condition: (_) body: (block)) @match",
            filter: Some(Find(immutable_while_condition)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f() { let i = 0; while i < 10 { println!(\"{i}\"); } }",
            good: "fn f() { let mut i = 0; while i < 10 { println!(\"{i}\"); i += 1; } }",
        }),
    },
    Rule {
        id: "rs/unit-cmp",
        name: "Unit values should not be compared",
        description: "`()` always equals itself, so comparing unit values, often blocks with a stray \
                      semicolon, is a constant.",
        message: "Compare the values these expressions were meant to produce.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[related("S7423")],
        check: Check::Query {
            langs: RUST,
            query: "(binary_expression) @match\n(call_expression function: (identifier)) @match",
            filter: Some(Keep(compares_units)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f() { assert_eq!({ foo(); }, { bar(); }); }",
            good: "fn f() { assert_eq!(foo(), bar()); }",
        }),
    },
    Rule {
        id: "rs/unit-hash",
        name: "Unit values should not be hashed",
        description: "Hashing `()` does nothing, so a value hashed this way doesn't tell the case apart.",
        message: "Hash a value that distinguishes this case, such as `0_u8`.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[related("S7422")],
        check: Check::Query {
            langs: RUST,
            query: "(call_expression function: (field_expression field: (field_identifier)) arguments: (arguments)) @match",
            filter: Some(Keep(hashes_unit)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f<H: Hasher>(e: &E, h: &mut H) { match e { E::Empty => ().hash(h), E::Value(x) => x.hash(h) } }",
            good: "fn f<H: Hasher>(e: &E, h: &mut H) { match e { E::Empty => 0_u8.hash(h), E::Value(x) => x.hash(h) } }",
        }),
    },
];

// ---------------------------------------------------------------- commas

/// Operators that are also prefix ones: `-`, `*` and `&&` (a double
/// reference), so a line break before one may hide a missing comma.
const UNARY_TOO: &[&[u8]] = &[b"-", b"*", b"&&"];

/// The last token of an element whose top-level operator, `-`, `*` or `&&`,
/// starts a line after its left operand: where the comma probably belongs.
fn missing_commas<'t>(n: Node<'t>, src: &[u8]) -> Vec<Node<'t>> {
    if n.kind() == "macro_invocation" {
        return vec_missing_commas(n, src);
    }
    if n.child_by_field_name("length").is_some() {
        return Vec::new();
    }
    let mut c = n.walk();
    n.named_children(&mut c)
        .filter(|e| e.kind() == "binary_expression")
        .filter_map(|e| {
            let left = e.child_by_field_name("left")?;
            let op = e.child_by_field_name("operator")?;
            (UNARY_TOO.contains(&text(op, src))
                && op.start_position().row > left.end_position().row)
                .then(|| last_token(left))
        })
        .collect()
}

fn last_token(mut n: Node) -> Node {
    while let Some(last) = n.child(n.child_count().saturating_sub(1)) {
        n = last;
    }
    n
}

/// `vec![...]` keeps its elements as tokens: each element's top-level
/// operator is its loosest binding one, the last of equals.
fn vec_missing_commas<'t>(mac: Node<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let mut c = mac.walk();
    let Some(tokens) = mac
        .named_children(&mut c)
        .find(|t| t.kind() == "token_tree")
    else {
        return Vec::new();
    };
    if src.get(tokens.start_byte()) != Some(&b'[') {
        return Vec::new();
    }
    let elements = macro_arguments(tokens);
    if elements.iter().flatten().any(|t| t.kind() == ";") {
        return Vec::new();
    }
    elements
        .iter()
        .filter_map(|element| {
            let (at, _) = element
                .iter()
                .enumerate()
                .skip(1)
                .filter(|(i, _)| ends_operand(element[i - 1]))
                .filter_map(|(i, t)| Some((i, precedence(text(*t, src))?)))
                .min_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(&a.0)))?;
            let (op, before) = (element[at], element[at - 1]);
            (UNARY_TOO.contains(&text(op, src))
                && op.start_position().row > before.end_position().row)
                .then_some(before)
        })
        .collect()
}

/// Whether a token can end an operand, so an operator after it is binary.
fn ends_operand(t: Node) -> bool {
    t.kind().ends_with("literal")
        || matches!(
            t.kind(),
            "identifier" | "token_tree" | "primitive_type" | "self" | "true" | "false" | "?"
        )
}

/// A binary operator's precedence, from tightest (10) to loosest.
fn precedence(op: &[u8]) -> Option<u8> {
    Some(match op {
        b"*" | b"/" | b"%" => 10,
        b"+" | b"-" => 9,
        b"<<" | b">>" => 8,
        b"&" => 7,
        b"^" => 6,
        b"|" => 5,
        b"==" | b"!=" | b"<" | b">" | b"<=" | b">=" => 4,
        b"&&" => 3,
        b"||" => 2,
        b".." | b"..=" => 1,
        _ => return None,
    })
}

// ---------------------------------------------------------------- attributes

const LINT_LEVELS: &[&[u8]] = &[b"allow", b"warn", b"deny", b"forbid", b"expect"];

/// Lints a `use` itself can raise, which an attribute on it may set.
const USE_LINTS: &[&[u8]] = &[
    b"ambiguous_glob_reexports",
    b"dead_code",
    b"deprecated",
    b"hidden_glob_reexports",
    b"unreachable_pub",
    b"unused",
    b"unused_braces",
    b"unused_import_braces",
    b"unused_imports",
    b"clippy::disallowed_types",
    b"clippy::enum_glob_use",
    b"clippy::macro_use_imports",
    b"clippy::module_name_repetitions",
    b"clippy::redundant_pub_crate",
    b"clippy::single_component_path_imports",
    b"clippy::unsafe_removed_from_name",
    b"clippy::wildcard_imports",
];

/// The lint attributes on an import, in order, up to the first that sets a
/// lint the import itself can raise: from there on Clippy takes them all to
/// be meant for it.
fn useless_lint_attributes<'t>(import: Node<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let mut attributes = Vec::new();
    let mut prev = import.prev_named_sibling();
    while let Some(p) = prev {
        match p.kind() {
            "attribute_item" => attributes.push(p),
            "line_comment" | "block_comment" => {}
            _ => break,
        }
        prev = p.prev_named_sibling();
    }
    attributes.reverse();
    let crate_import = import.kind() == "extern_crate_declaration";
    // `#[cfg_attr(feature = "x", macro_use)]` counts: it may be on.
    let macro_use = attributes.iter().any(|a| {
        attribute_parts(*a, src).is_some_and(|(name, arguments)| {
            name == b"macro_use"
                || (name == b"cfg_attr"
                    && arguments.is_some_and(|t| {
                        text(t, src)
                            .split(|b| !(b.is_ascii_alphanumeric() || *b == b'_'))
                            .any(|w| w == b"macro_use")
                    }))
        })
    });
    let mut useless = Vec::new();
    for a in attributes {
        let Some(lints) = lints_set(a, src) else {
            continue;
        };
        let meant_for_it = lints.iter().any(|l| {
            if crate_import {
                l == b"unused_extern_crates" || (macro_use && l == b"unused_imports")
            } else {
                USE_LINTS.contains(&l.as_slice())
            }
        });
        if meant_for_it {
            break;
        }
        useless.push(a);
    }
    useless
}

/// An attribute's name and arguments: `allow` and `(dead_code)`.
fn attribute_parts<'t, 'a>(item: Node<'t>, src: &'a [u8]) -> Option<(&'a [u8], Option<Node<'t>>)> {
    let mut c = item.walk();
    let attribute = item
        .named_children(&mut c)
        .find(|n| n.kind() == "attribute")?;
    let path = attribute.named_child(0)?;
    Some((text(path, src), attribute.child_by_field_name("arguments")))
}

/// The lints a lint-level attribute sets, Clippy's with their `clippy::`
/// prefix; None for any other attribute, and for one that sets only other
/// tools' lints (`rustdoc::...`).
fn lints_set(item: Node, src: &[u8]) -> Option<Vec<Vec<u8>>> {
    let (level, arguments) = attribute_parts(item, src)?;
    if !LINT_LEVELS.contains(&level) {
        return None;
    }
    let inner = text(arguments?, src);
    let inner = inner.get(1..inner.len().checked_sub(1)?)?;
    let lints: Vec<Vec<u8>> = inner
        .split(|b| *b == b',')
        .map(|l| {
            l.iter()
                .copied()
                .filter(|b| !b.is_ascii_whitespace())
                .collect::<Vec<u8>>()
        })
        .filter(|l| !l.is_empty() && !l.contains(&b'='))
        .filter(|l| !l.contains(&b':') || l.starts_with(b"clippy::"))
        .collect();
    (!lints.is_empty()).then_some(lints)
}

// ---------------------------------------------------------------- I/O

const IO_METHODS: &[&str] = &["write", "read", "write_vectored", "read_vectored"];

/// A statement that drops the count `write` or `read` returns: the call
/// alone, or through `?`, `unwrap`, `expect`, `unwrap_or(_else)`, `ok`,
/// `is_ok` or `is_err`. Only where the file names `Write` or `Read`, which
/// calling the trait's method needs, and doesn't give a type of its own a
/// method by that name.
fn unused_io_amount<'t>(statement: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut e = unparen(statement.named_child(0)?);
    if e.kind() == "try_expression" {
        e = e.named_child(0)?;
    } else if method_is(e, src, &["unwrap", "expect", "unwrap_or", "unwrap_or_else"]) {
        e = receiver(e)?;
        if method_is(e, src, &["ok"]) {
            e = receiver(e)?;
        }
    } else if method_is(e, src, &["ok", "is_ok", "is_err"]) {
        e = receiver(e)?;
    } else {
        // The bare call: rustc already warns of the unused `Result`, and
        // `MaybeUninit`, pointers and hashers have a `write` too.
        return None;
    }
    while e.kind() == "await_expression" {
        e = e.named_child(0)?;
    }
    if !method_is(e, src, IO_METHODS) || arguments(e).len() != 1 {
        return None;
    }
    let name = text(method(e)?, src);
    let reading = name.starts_with(b"read");
    (names_io_trait(src, reading)
        && may_be_io(receiver(e)?, src)
        && !has_inherent_method(e, name, src))
    .then_some(e)
}

/// Words that end the names of I/O types: `File`, `TcpStream`, `BufWriter`,
/// `GzEncoder`...
const IO_TYPE_ENDINGS: &[&str] = &[
    "File", "Stream", "Writer", "Reader", "Encoder", "Decoder", "Socket", "Pipe", "Stdin",
    "Stdout", "Stderr", "Lock", "Cursor", "Vec", "Box", "Sink", "Empty", "Repeat",
];

/// Whether a receiver may be an I/O type: unless the file declares it with a
/// type of its own name (`ctx: &mut WriteContext`), or creates it with one
/// (`Call::new(..)`), that isn't a type parameter, `dyn` or `impl`, or named
/// as I/O types are.
fn may_be_io(receiver: Node, src: &[u8]) -> bool {
    let receiver = unparen(receiver);
    if receiver.kind() != "identifier" {
        return true;
    }
    let Some((ty, value)) = local(receiver, src) else {
        return true;
    };
    let named = match (ty, value) {
        (Some(t), _) => declared_type_name(t, src),
        (None, Some(v)) => constructed_type_name(v, src),
        (None, None) => None,
    };
    let Some(named) = named else {
        return true;
    };
    let generic = ancestors(receiver)
        .filter(|a| matches!(a.kind(), "function_item" | "impl_item"))
        .filter_map(|a| a.child_by_field_name("type_parameters"))
        .any(|p| {
            descendants(p, &[])
                .iter()
                .any(|n| n.kind() == "type_identifier" && text(*n, src) == named)
        });
    generic
        || IO_TYPE_ENDINGS
            .iter()
            .any(|e| named.ends_with(e.as_bytes()))
}

/// The name of a declared type, through references: `WriteContext` for
/// `&mut WriteContext<'_>`. None for `dyn`, `impl` and anything unnamed.
fn declared_type_name<'a>(mut ty: Node, src: &'a [u8]) -> Option<&'a [u8]> {
    while ty.kind() == "reference_type" {
        ty = ty.child_by_field_name("type")?;
    }
    if ty.kind() == "generic_type" {
        ty = ty.child_by_field_name("type")?;
    }
    if ty.kind() == "scoped_type_identifier" {
        ty = ty.child_by_field_name("name")?;
    }
    (ty.kind() == "type_identifier").then(|| text(ty, src))
}

/// The type a value is made with: `Call` for `Call::new(..)` or
/// `File::open(..)?`.
fn constructed_type_name<'a>(value: Node, src: &'a [u8]) -> Option<&'a [u8]> {
    let mut v = unparen(value);
    while matches!(v.kind(), "try_expression" | "await_expression") {
        v = v.named_child(0)?;
    }
    if method_is(v, src, &["unwrap", "expect"]) {
        v = receiver(v)?;
    }
    let function = v.child_by_field_name("function")?;
    if function.kind() != "scoped_identifier" {
        return None;
    }
    let path = function.child_by_field_name("path")?;
    let name = match path.kind() {
        "identifier" => path,
        "scoped_identifier" => path.child_by_field_name("name")?,
        _ => return None,
    };
    let name = text(name, src);
    name.first()
        .is_some_and(u8::is_ascii_uppercase)
        .then_some(name)
}

/// Whether the file names `std::io`'s `Read` (`reading`) or `Write`, or the
/// async runtimes' `AsyncReadExt` or `AsyncWriteExt`: `io::Write`, a `use`
/// of `io::{.., Write}` or of `io::prelude`.
fn names_io_trait(src: &[u8], reading: bool) -> bool {
    let (name, extension): (&[u8], &[u8]) = if reading {
        (b"Read", b"AsyncReadExt")
    } else {
        (b"Write", b"AsyncWriteExt")
    };
    let is_word_at = |at: usize, word: &[u8]| {
        let before = at.checked_sub(1).and_then(|i| src.get(i));
        let after = src.get(at + word.len());
        let ident = |b: Option<&u8>| b.is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_');
        src[at..].starts_with(word) && !ident(before) && !ident(after)
    };
    let mut path = b"io::".to_vec();
    path.extend_from_slice(name);
    (0..src.len()).any(|at| match src[at] {
        b'i' => {
            is_word_at(at, &path)
                || is_word_at(at, b"io::prelude")
                || (src[at..].starts_with(b"io::{") && {
                    let list = &src[at + 5..];
                    let end = list.iter().position(|b| *b == b'}').unwrap_or(list.len());
                    let list = &list[..end];
                    (0..list.len()).any(|i| {
                        list[i..].starts_with(name)
                            && !list
                                .get(i + name.len())
                                .is_some_and(|b| b.is_ascii_alphanumeric())
                            && (i == 0 || !list[i - 1].is_ascii_alphanumeric())
                    })
                })
        }
        b'A' => is_word_at(at, extension),
        _ => false,
    })
}

/// Whether the file gives a type of its own a method by this name, outside
/// a trait implementation.
fn has_inherent_method(at: Node, name: &[u8], src: &[u8]) -> bool {
    let Some(root) = ancestors(at).last() else {
        return false;
    };
    descendants(root, &["function_item"]).into_iter().any(|n| {
        n.kind() == "impl_item"
            && n.child_by_field_name("trait").is_none()
            && n.child_by_field_name("body").is_some_and(|body| {
                let mut c = body.walk();
                body.named_children(&mut c).any(|f| {
                    f.kind() == "function_item"
                        && f.child_by_field_name("name")
                            .is_some_and(|n| text(n, src) == name)
                })
            })
    })
}

// ---------------------------------------------------------------- enums

/// The variants whose explicit discriminant doesn't fit 32 bits, when the
/// enum's discriminant is pointer-sized: `isize` (the default, `repr(C)`
/// too) must fit an `i32`, `usize` a `u32`.
fn unportable_variants<'t>(e: Node<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let Some((low, high)) = portable_range(e, src) else {
        return Vec::new();
    };
    let Some(body) = e.child_by_field_name("body") else {
        return Vec::new();
    };
    let mut c = body.walk();
    body.named_children(&mut c)
        .filter(|v| v.kind() == "enum_variant")
        .filter(|v| {
            v.child_by_field_name("value")
                .and_then(|value| evaluate(value, src, 0))
                .is_some_and(|x| x < low || x > high)
        })
        .collect()
}

/// The values a discriminant can portably take, None when the enum's
/// `repr` gives it a fixed size.
fn portable_range(e: Node, src: &[u8]) -> Option<(i128, i128)> {
    let mut range = (i128::from(i32::MIN), i128::from(i32::MAX));
    let mut prev = e.prev_named_sibling();
    while let Some(p) = prev {
        match p.kind() {
            "attribute_item" => {}
            "line_comment" | "block_comment" => {
                prev = p.prev_named_sibling();
                continue;
            }
            _ => break,
        }
        if let Some((b"repr", Some(arguments))) = attribute_parts(p, src) {
            let inner = text(arguments, src);
            for r in inner[1..inner.len().saturating_sub(1)].split(|b| *b == b',') {
                let r = r.trim_ascii();
                if r == b"usize" {
                    range = (0, i128::from(u32::MAX));
                } else if r != b"isize" && integer_bounds(r).is_some() {
                    return None;
                }
            }
        }
        prev = p.prev_named_sibling();
    }
    Some(range)
}

/// The least and greatest values of a primitive integer type, `isize` and
/// `usize` as on a 64-bit target.
fn integer_bounds(ty: &[u8]) -> Option<(i128, i128)> {
    Some(match ty {
        b"i8" => (i8::MIN.into(), i8::MAX.into()),
        b"i16" => (i16::MIN.into(), i16::MAX.into()),
        b"i32" => (i32::MIN.into(), i32::MAX.into()),
        b"i64" | b"isize" => (i64::MIN.into(), i64::MAX.into()),
        b"i128" => (i128::MIN, i128::MAX),
        b"u8" => (0, u8::MAX.into()),
        b"u16" => (0, u16::MAX.into()),
        b"u32" => (0, u32::MAX.into()),
        b"u64" | b"usize" => (0, u64::MAX.into()),
        b"u128" => (0, i128::MAX),
        _ => return None,
    })
}

/// The value of a constant integer expression: literals, the file's
/// constants, `T::MIN` and `T::MAX`, casts and arithmetic.
fn evaluate(n: Node, src: &[u8], depth: u8) -> Option<i128> {
    if depth > 8 {
        return None;
    }
    let n = unparen(n);
    match n.kind() {
        "integer_literal" => i128::try_from(integer_value(n, src)?).ok(),
        "unary_expression" if text(n, src).starts_with(b"-") => {
            evaluate(n.named_child(0)?, src, depth + 1)?.checked_neg()
        }
        "binary_expression" => {
            let (l, r) = operands(n)?;
            let (a, b) = (evaluate(l, src, depth + 1)?, evaluate(r, src, depth + 1)?);
            match operator(n, src) {
                b"+" => a.checked_add(b),
                b"-" => a.checked_sub(b),
                b"*" => a.checked_mul(b),
                b"<<" => a.checked_shl(u32::try_from(b).ok()?),
                b">>" => a.checked_shr(u32::try_from(b).ok()?),
                b"|" => Some(a | b),
                b"&" => Some(a & b),
                b"^" => Some(a ^ b),
                _ => None,
            }
        }
        "type_cast_expression" => {
            let v = evaluate(n.child_by_field_name("value")?, src, depth + 1)?;
            cast(v, text(n.child_by_field_name("type")?, src))
        }
        "scoped_identifier" => {
            let (ty, which) = (
                text(n.child_by_field_name("path")?, src),
                text(n.child_by_field_name("name")?, src),
            );
            let ty = ty.rsplit(|b| *b == b':').next()?;
            let (low, high) = integer_bounds(ty)?;
            match which {
                b"MIN" => Some(low),
                b"MAX" => Some(high),
                _ => None,
            }
        }
        "identifier" => evaluate(
            item_constant(n, src)?.child_by_field_name("value")?,
            src,
            depth + 1,
        ),
        _ => None,
    }
}

/// `v as ty`, wrapping as Rust does.
fn cast(v: i128, ty: &[u8]) -> Option<i128> {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    Some(match ty {
        b"i8" => (v as i8).into(),
        b"i16" => (v as i16).into(),
        b"i32" => (v as i32).into(),
        b"i64" | b"isize" => (v as i64).into(),
        b"u8" => (v as u8).into(),
        b"u16" => (v as u16).into(),
        b"u32" => (v as u32).into(),
        b"u64" | b"usize" => (v as u64).into(),
        b"i128" | b"u128" => v,
        _ => return None,
    })
}

/// The `const` (or `static`) item a name refers to, when the file declares
/// one by that name outside function bodies, and only one.
fn item_constant<'t>(name: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let id = text(name, src);
    if !id
        .iter()
        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
    {
        return None;
    }
    let root = ancestors(name).last()?;
    let found: Vec<Node> = descendants(root, &["function_item"])
        .into_iter()
        .filter(|n| {
            matches!(n.kind(), "const_item" | "static_item")
                && n.child_by_field_name("name")
                    .is_some_and(|n| text(n, src) == id)
        })
        .collect();
    match found.as_slice() {
        [c] => Some(*c),
        _ => None,
    }
}

// ---------------------------------------------------------------- types

/// An expression's primitive type, when the file shows it: a typed literal,
/// a cast, a declared or initialised local, a constant, `T::MAX`, a length.
fn primitive_type<'a>(n: Node, src: &'a [u8], depth: u8) -> Option<&'a [u8]> {
    if depth > 4 {
        return None;
    }
    let n = unparen(n);
    let primitive = |ty: Node| (ty.kind() == "primitive_type").then(|| text(ty, src));
    match n.kind() {
        "integer_literal" | "float_literal" => {
            let suffix = literal_suffix(n, src);
            (!suffix.is_empty()).then_some(suffix.as_bytes())
        }
        "boolean_literal" => Some(b"bool"),
        "type_cast_expression" => primitive(n.child_by_field_name("type")?),
        "identifier" => match local(n, src) {
            Some((Some(ty), _)) => primitive(ty),
            Some((None, value)) => primitive_type(value?, src, depth + 1),
            None => primitive(item_constant(n, src)?.child_by_field_name("type")?),
        },
        "scoped_identifier" => {
            let path = text(n.child_by_field_name("path")?, src);
            let ty = path.rsplit(|b| *b == b':').next()?;
            let extreme = matches!(text(n.child_by_field_name("name")?, src), b"MIN" | b"MAX");
            (extreme && integer_bounds(ty).is_some()).then_some(ty)
        }
        "call_expression" => (method_is(n, src, &["len", "count", "capacity"])
            && arguments(n).is_empty())
        .then_some(b"usize"),
        "binary_expression" => match operator(n, src) {
            b"+" | b"-" | b"*" | b"/" | b"%" => {
                let (l, r) = operands(n)?;
                primitive_type(l, src, depth + 1).or_else(|| primitive_type(r, src, depth + 1))
            }
            _ => None,
        },
        _ => None,
    }
}

fn is_unsigned(ty: &[u8]) -> bool {
    ty.starts_with(b"u") && integer_bounds(ty).is_some()
}

// ---------------------------------------------------------------- saturating sub

/// `if a > b { b - a } else { 0 }`: in the branch that subtracts, the
/// subtraction takes the greater operand from the smaller, of an unsigned
/// type. Reported at the condition.
fn inverted_saturating_sub<'t>(n: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let condition = unparen(n.child_by_field_name("condition")?);
    if condition.kind() != "binary_expression" {
        return None;
    }
    let left_greater_when_true = match operator(condition, src) {
        b">" | b">=" => true,
        b"<" | b"<=" => false,
        _ => return None,
    };
    let (l, r) = operands(condition)?;
    if descendants(condition, &[])
        .iter()
        .any(|d| matches!(d.kind(), "call_expression" | "macro_invocation"))
    {
        return None;
    }
    let otherwise = n.child_by_field_name("alternative")?.named_child(0)?;
    if otherwise.kind() != "block" {
        return None;
    }
    let then = sole_value(n.child_by_field_name("consequence")?)?;
    let otherwise = sole_value(otherwise)?;
    let zero = |v: Node| v.kind() == "integer_literal" && integer_value(v, src) == Some(0);
    let (difference, in_then) = if zero(otherwise) {
        (then, true)
    } else if zero(then) {
        (otherwise, false)
    } else {
        return None;
    };
    if difference.kind() != "binary_expression" || operator(difference, src) != b"-" {
        return None;
    }
    let (minuend, subtrahend) = operands(difference)?;
    let (greater, smaller) = if left_greater_when_true == in_then {
        (l, r)
    } else {
        (r, l)
    };
    let types = [l, r].map(|o| primitive_type(o, src, 0));
    let unsigned = types.iter().flatten().any(|t| is_unsigned(t))
        && types.iter().flatten().all(|t| is_unsigned(t));
    (unsigned
        && same_pure_expression(minuend, smaller, src)
        && same_pure_expression(subtrahend, greater, src))
    .then_some(condition)
}

/// A block's one expression, through nested blocks and parentheses.
fn sole_value(block: Node) -> Option<Node> {
    let items: Vec<Node> = block_items(block)
        .into_iter()
        .filter(|n| n.kind() != "attribute_item")
        .collect();
    let [only] = items.as_slice() else {
        return None;
    };
    let value = match only.kind() {
        "expression_statement" if only.child(only.child_count() - 1)?.kind() != ";" => {
            only.named_child(0)?
        }
        "expression_statement" | "let_declaration" | "empty_statement" => return None,
        _ => *only,
    };
    let value = unparen(value);
    if value.kind() == "block" {
        sole_value(value)
    } else {
        Some(value)
    }
}

// ---------------------------------------------------------------- extremes

#[derive(Clone, Copy)]
enum Extreme {
    Min,
    Max,
}

/// `x < 0` for an unsigned `x`, `x > i32::MAX` and their kin: a comparison
/// with the type's minimum or maximum that is always true, always false, or
/// an equality.
fn is_absurd_extreme_comparison(n: Node, src: &[u8]) -> bool {
    let op = operator(n, src);
    if !matches!(op, b"<" | b"<=" | b">" | b">=") {
        return false;
    }
    let Some((l, r)) = operands(n) else {
        return false;
    };
    if !may_be_extreme(l, src) && !may_be_extreme(r, src) {
        return false;
    }
    [(l, r, op), (r, l, mirrored(op))]
        .into_iter()
        .any(|(other, bound, op)| {
            // The type is the other side's, or the bound's own when that is
            // `T::MAX` or the other side a bare literal (`100 > i32::MAX`):
            // a type that compares with `bool` or `0` needn't be one.
            let ty = match primitive_type(other, src, 0) {
                Some(t) => t,
                None if unparen(other).kind() == "integer_literal"
                    || unparen(bound).kind() == "scoped_identifier" =>
                {
                    match primitive_type(bound, src, 0) {
                        Some(t) => t,
                        None => return false,
                    }
                }
                None => return false,
            };
            extreme(bound, ty, src).is_some_and(|e| absurd(op, e))
        })
}

/// What an extreme can look like, before any type is known: a cheap test,
/// as most comparisons aren't with one.
fn may_be_extreme(n: Node, src: &[u8]) -> bool {
    let n = unparen(n);
    match n.kind() {
        "boolean_literal" => true,
        "scoped_identifier" => n
            .child_by_field_name("name")
            .is_some_and(|m| matches!(text(m, src), b"MIN" | b"MAX")),
        "integer_literal" => integer_value(n, src).is_some_and(|v| {
            v == 0
                || [8, 16, 32, 64, 128]
                    .iter()
                    .any(|bits| v == (1u128 << (bits - 1)) - 1 || v == u128::MAX >> (128 - bits))
        }),
        "identifier" => text(n, src).first().is_some_and(u8::is_ascii_uppercase),
        _ => false,
    }
}

/// Whether `x op extreme` is decided by the extreme alone, or means `==`.
fn absurd(op: &[u8], e: Extreme) -> bool {
    match e {
        Extreme::Min => matches!(op, b"<" | b">=" | b"<="),
        Extreme::Max => matches!(op, b">" | b"<=" | b">="),
    }
}

fn mirrored(op: &[u8]) -> &'static [u8] {
    match op {
        b"<" => b">",
        b">" => b"<",
        b"<=" => b">=",
        _ => b"<=",
    }
}

/// Whether a side is its type's minimum or maximum: `false` and `true`,
/// `T::MIN` and `T::MAX`, and a literal or constant equal to an unsigned
/// type's 0 or any integer type's maximum.
fn extreme(side: Node, ty: &[u8], src: &[u8]) -> Option<Extreme> {
    let side = unparen(side);
    if ty == b"bool" {
        return match (side.kind(), text(side, src)) {
            ("boolean_literal", b"false") => Some(Extreme::Min),
            ("boolean_literal", b"true") => Some(Extreme::Max),
            _ => None,
        };
    }
    let (low, high) = integer_bounds(ty)?;
    let value = match side.kind() {
        "scoped_identifier" => {
            let path = text(side.child_by_field_name("path")?, src);
            if path.rsplit(|b| *b == b':').next()? != ty {
                return None;
            }
            return match text(side.child_by_field_name("name")?, src) {
                b"MIN" => Some(Extreme::Min),
                b"MAX" => Some(Extreme::Max),
                _ => None,
            };
        }
        "integer_literal" => i128::try_from(integer_value(side, src)?).ok()?,
        "identifier" => evaluate(side, src, 0)?,
        _ => return None,
    };
    if value == high {
        Some(Extreme::Max)
    } else if value == low && low == 0 {
        Some(Extreme::Min)
    } else {
        None
    }
}

// ---------------------------------------------------------------- while

/// Kinds that may change state when a condition is evaluated, or bind.
const NOT_PURE: &[&str] = &[
    "call_expression",
    "macro_invocation",
    "closure_expression",
    "await_expression",
    "unsafe_block",
    "let_condition",
    "let_chain",
    "block",
    "assignment_expression",
    "compound_assignment_expr",
];

/// Macros that only read the variables they're given.
const READING_MACROS: &[&[u8]] = &[
    b"println",
    b"print",
    b"eprintln",
    b"eprint",
    b"format",
    b"format_args",
    b"panic",
    b"assert",
    b"assert_eq",
    b"assert_ne",
    b"debug_assert",
    b"debug_assert_eq",
    b"debug_assert_ne",
    b"unreachable",
    b"todo",
    b"unimplemented",
    b"dbg",
    b"trace",
    b"debug",
    b"info",
    b"warn",
    b"error",
];

/// A `while` condition that calls nothing and reads locals the body never
/// changes: the loop runs never or forever.
fn immutable_while_condition<'t>(w: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let condition = w.child_by_field_name("condition")?;
    let body = w.child_by_field_name("body")?;
    let parts = descendants(condition, &[]);
    if parts.iter().any(|p| NOT_PURE.contains(&p.kind())) {
        return None;
    }
    // Variables, however bound (`let (a, b)`, `while let`, parameters):
    // constants and statics are named in upper case.
    let mut locals: Vec<(&[u8], bool)> = Vec::new();
    for p in parts {
        let variable = match p.kind() {
            "self" => true,
            "identifier" => {
                p.parent().is_none_or(|q| q.kind() != "scoped_identifier")
                    && text(p, src)
                        .first()
                        .is_some_and(|b| b.is_ascii_lowercase() || *b == b'_')
            }
            _ => false,
        };
        if !variable {
            continue;
        }
        let mutable_reference = p.kind() == "self"
            || local(p, src).is_some_and(|(ty, value)| {
                ty.is_some_and(|t| is_mut_reference(t, src))
                    || value.is_some_and(|v| is_mut_reference(v, src))
            });
        locals.push((text(p, src), mutable_reference));
    }
    if locals.is_empty() {
        return None;
    }
    let uses = descendants(body, &["function_item"]);
    let changed = locals.iter().any(|(name, mutable_reference)| {
        uses.iter().any(|u| {
            matches!(u.kind(), "identifier" | "self")
                && text(*u, src) == *name
                && !shadowed(*u, name, body, src)
                && may_change(*u, *mutable_reference, src)
        })
    });
    (!changed).then_some(condition)
}

/// `&mut T`, or `&mut value`.
fn is_mut_reference(n: Node, src: &[u8]) -> bool {
    matches!(n.kind(), "reference_type" | "reference_expression") && {
        let mut c = n.walk();
        let mutable = n.children(&mut c).any(|m| m.kind() == "mutable_specifier");
        mutable && text(n, src).starts_with(b"&")
    }
}

/// Whether a use of a variable may change it: assigned to (or a field or
/// element of it), borrowed `&mut`, a method's receiver, a `&mut` passed on,
/// or in a macro that isn't known only to read.
fn may_change(id: Node, mutable_reference: bool, src: &[u8]) -> bool {
    if id.parent().is_some_and(|p| p.kind() == "token_tree") {
        return changed_in_macro(id, src);
    }
    let mut place = id;
    while let Some(p) = place.parent() {
        let is_part = match p.kind() {
            "field_expression" => p.child_by_field_name("value") == Some(place),
            "index_expression" => p.named_child(0) == Some(place),
            "parenthesized_expression" => true,
            "unary_expression" => text(p, src).starts_with(b"*"),
            _ => false,
        };
        if !is_part {
            break;
        }
        if p.kind() == "field_expression"
            && p.parent().is_some_and(|c| {
                c.kind() == "call_expression" && c.child_by_field_name("function") == Some(p)
            })
        {
            return true;
        }
        place = p;
    }
    let Some(parent) = place.parent() else {
        return false;
    };
    match parent.kind() {
        "assignment_expression" | "compound_assignment_expr" => {
            parent.child_by_field_name("left") == Some(place)
        }
        "reference_expression" => is_mut_reference(parent, src),
        "arguments" => mutable_reference && place == id,
        _ => false,
    }
}

/// A variable among a macro's tokens: changed by any macro but those known
/// to read, and by those through a method, an assignment or `&mut`.
fn changed_in_macro(id: Node, src: &[u8]) -> bool {
    let reading = ancestors(id)
        .find(|a| a.kind() == "macro_invocation")
        .and_then(|m| m.child_by_field_name("macro"))
        .is_some_and(|m| READING_MACROS.contains(&text(m, src)));
    if !reading {
        return true;
    }
    let next = id.next_sibling().map(|n| text(n, src));
    let after_mut = id.prev_sibling().is_some_and(|p| text(p, src) == b"mut");
    after_mut
        || next.is_some_and(|n| {
            n == b"." || (n.ends_with(b"=") && !matches!(n, b"==" | b"!=" | b"<=" | b">="))
        })
}

/// Whether a use names another variable by the same name, bound in the loop
/// body before it: a `let`, a closure's parameter or a `for` pattern.
fn shadowed(id: Node, name: &[u8], body: Node, src: &[u8]) -> bool {
    for a in ancestors(id) {
        if rebinds(a, id, name, src) {
            return true;
        }
        if a == body {
            break;
        }
    }
    false
}

/// Whether a node around a use binds the name anew for it.
fn rebinds(around: Node, id: Node, name: &[u8], src: &[u8]) -> bool {
    let binds = |pattern: Node| {
        descendants(pattern, &[])
            .iter()
            .any(|n| n.kind() == "identifier" && text(*n, src) == name)
    };
    match around.kind() {
        "block" => {
            let mut c = around.walk();
            around.named_children(&mut c).any(|s| {
                s.kind() == "let_declaration"
                    && s.end_byte() <= id.start_byte()
                    && s.child_by_field_name("pattern").is_some_and(binds)
            })
        }
        "closure_expression" => around.child_by_field_name("parameters").is_some_and(binds),
        "for_expression" => {
            around
                .child_by_field_name("body")
                .is_some_and(|b| b.start_byte() <= id.start_byte())
                && around.child_by_field_name("pattern").is_some_and(binds)
        }
        _ => false,
    }
}

// ---------------------------------------------------------------- unit

/// A comparison of unit values: an operand is `()`, a block without a value,
/// a call to the file's function without a return type, or a local holding
/// one. `assert_eq!` and its kin don't count a literal `()`: asserting that
/// something returns unit.
fn compares_units(n: Node, src: &[u8]) -> bool {
    if n.kind() == "binary_expression" {
        return matches!(
            operator(n, src),
            b"==" | b"!=" | b"<" | b"<=" | b">" | b">="
        ) && operands(n)
            .is_some_and(|(l, r)| compared_unit(l, src) || compared_unit(r, src));
    }
    let Some(f) = n.child_by_field_name("function") else {
        return false;
    };
    if !matches!(
        text(f, src),
        b"assert_eq" | b"assert_ne" | b"debug_assert_eq" | b"debug_assert_ne"
    ) {
        return false;
    }
    let args = arguments(n);
    let [a, b, ..] = args.as_slice() else {
        return false;
    };
    let literal = |x: Node| unparen(x).kind() == "unit_expression";
    !literal(*a) && !literal(*b) && (compared_unit(*a, src) || compared_unit(*b, src))
}

/// `is_unit`, but not of a bare variable: comparisons name variables all
/// the time and unit ones almost never, so it isn't worth finding their
/// declarations (`u == ()` is found by the `()`).
fn compared_unit(n: Node, src: &[u8]) -> bool {
    unparen(n).kind() != "identifier" && is_unit(n, src, 0)
}

/// `().hash(state)`, of any unit value `is_unit` recognises.
fn hashes_unit(call: Node, src: &[u8]) -> bool {
    method_is(call, src, &["hash"])
        && arguments(call).len() == 1
        && receiver(call).is_some_and(|r| is_unit(r, src, 0))
}

/// Whether an expression's value is `()`, as far as the file shows.
fn is_unit(n: Node, src: &[u8], depth: u8) -> bool {
    if depth > 3 {
        return false;
    }
    let n = unparen(n);
    match n.kind() {
        "unit_expression" => true,
        "block" => {
            let items: Vec<Node> = block_items(n)
                .into_iter()
                .filter(|i| i.kind() != "attribute_item")
                .collect();
            match items.last() {
                None => true,
                Some(last) => match last.kind() {
                    "expression_statement" if text(*last, src).ends_with(b";") => true,
                    "let_declaration" | "empty_statement" => true,
                    "expression_statement" => last
                        .named_child(0)
                        .is_some_and(|e| is_unit(e, src, depth + 1)),
                    _ => is_unit(*last, src, depth + 1),
                },
            }
        }
        "call_expression" => n
            .child_by_field_name("function")
            .is_some_and(|f| f.kind() == "identifier" && unit_function(f, src)),
        "identifier" => local(n, src).is_some_and(|(ty, value)| match ty {
            Some(t) => t.kind() == "unit_type",
            None => value.is_some_and(|v| is_unit(v, src, depth + 1)),
        }),
        "if_expression" => {
            let then = n.child_by_field_name("consequence");
            let otherwise = n
                .child_by_field_name("alternative")
                .and_then(|a| a.named_child(0));
            then.zip(otherwise)
                .is_some_and(|(t, o)| is_unit(t, src, depth + 1) && is_unit(o, src, depth + 1))
        }
        _ => false,
    }
}

/// Whether the file's free functions by this name all return unit: none
/// declares a return type but `()`.
fn unit_function(name: Node, src: &[u8]) -> bool {
    let id = text(name, src);
    // `format!(..)` became `format (..)` in the macro pass.
    if src.get(name.end_byte()) == Some(&b' ') {
        return false;
    }
    let declared_unit = |f: &Node| {
        f.child_by_field_name("return_type")
            .is_none_or(|t| t.kind() == "unit_type")
    };
    let named = |f: &Node| {
        f.kind() == "function_item"
            && f.child_by_field_name("name")
                .is_some_and(|n| text(n, src) == id)
    };
    // A function declared in a block around the call hides the file's.
    for block in ancestors(name).filter(|a| a.kind() == "block") {
        let mut c = block.walk();
        if let Some(f) = block.named_children(&mut c).find(named) {
            return declared_unit(&f);
        }
    }
    let Some(root) = ancestors(name).last() else {
        return false;
    };
    let mut found = Vec::new();
    let mut scopes = vec![root];
    while let Some(scope) = scopes.pop() {
        let mut c = scope.walk();
        for item in scope.named_children(&mut c) {
            if item.kind() == "mod_item" {
                scopes.extend(item.child_by_field_name("body"));
            } else if named(&item) {
                found.push(item);
            }
        }
    }
    // A local by this name, such as a closure, hides the functions.
    !found.is_empty() && found.iter().all(declared_unit) && local(name, src).is_none()
}

// ---------------------------------------------------------------- locals

/// `declaration`, after a cheaper test that the enclosing function has a
/// `let` by this name before it, or a parameter: most names compared are
/// neither, and finding the `let` walks the whole function.
fn local<'t>(at: Node<'t>, src: &[u8]) -> Option<(Option<Node<'t>>, Option<Node<'t>>)> {
    let function = ancestors(at).find(|a| a.kind() == "function_item")?;
    let name = text(at, src);
    let before = &src[function.start_byte()..at.start_byte()];
    let ends_word = |rest: &[u8]| {
        rest.starts_with(name)
            && !rest
                .get(name.len())
                .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
    };
    let bound = before.windows(4).enumerate().any(|(i, w)| {
        w == b"let " && {
            let rest = before[i + 4..].trim_ascii_start();
            ends_word(rest.strip_prefix(b"mut ").unwrap_or(rest))
        }
    });
    let parameter = || {
        function.child_by_field_name("parameters").is_some_and(|p| {
            let p = text(p, src);
            (0..p.len()).any(|i| {
                ends_word(&p[i..])
                    && (i == 0 || !(p[i - 1].is_ascii_alphanumeric() || p[i - 1] == b'_'))
            })
        })
    };
    if bound || parameter() {
        declaration(at, src)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    //! Each case is one Clippy was run on (ADR-0026, "Batch 5"), with what it
    //! reported, but where noted.
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
        let mut found: Vec<usize> = a
            .issues
            .iter()
            .filter(|i| i.rule == rule)
            .map(|i| i.line)
            .collect();
        found.sort_unstable();
        found.dedup();
        found
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
    fn commas_missing_before_a_prefix_operator() {
        let src = "fn f(a: i32, b: i32) {
    let x = &[
        -1, -2, -3
        -4, -5,
    ];
    let z = &[a -
        b];
    let v = &[
        a
        *b,
        a
        &b,
        a
        +b,
    ];
    let p = &[
        a
        -b
        -1,
    ];
    let k = [
        a
        -b; 3
    ];
    let t = vec![
        1
        -2,
        a
        -b
        -1,
        c
        &&c,
    ];
}
";
        assert_eq!(
            lines("rs/possible-missing-comma", src),
            [3, 9, 18, 26, 29, 31]
        );
    }

    #[test]
    fn lint_attributes_on_imports() {
        let src = "#[deny(dead_code)]
use std::fmt::Debug;
#[allow(clippy::needless_borrow)]
use std::io::Read;
#[allow(clippy::needless_return, unused_imports)]
use std::fmt::Display;
#[allow(unused_variables)]
use std::fmt::Write;
#[allow(unused_imports)]
#[allow(clippy::needless_return)]
use std::cell::Cell;
#[allow(clippy::needless_return)]
#[warn(unused_imports)]
use std::cell::RefCell;
#[allow(rustdoc::broken_intra_doc_links)]
use std::num::NonZeroU64;
#[allow(dead_code)]
extern crate alloc;
#[allow(unused_imports)]
extern crate core as core2;
#[allow(unused_imports)]
#[macro_use]
extern crate std as std2;
#[allow(unused_extern_crates)]
extern crate alloc as alloc6;
#[allow(unused_imports)]
#[cfg_attr(feature = \"x\", macro_use)]
extern crate alloc as alloc7;
#[allow(dead_code)]
mod m {}
";
        // Clippy, with `x` off, reports line 26 too: the feature may be on.
        assert_eq!(lines("rs/useless-lint-attribute", src), [3, 7, 12, 17, 19]);
    }

    #[test]
    fn io_counts_dropped() {
        let src = "use std::io::{self, Read, Write};
fn f<W: Write, R: Read>(w: &mut W, r: &mut R, buf: &mut [u8]) -> io::Result<()> {
    w.write(b\"foo\")?;
    r.read(buf)?;
    w.write(b\"x\").unwrap();
    let _ = w.write(b\"x\");
    let n = w.write(b\"x\")?;
    w.write_all(b\"x\")?;
    w.write(b\"x\").ok();
    w.write(b\"x\").map_err(|e| e)?;
    w.write(b\"x\").unwrap_or_default();
    w.write(b\"x\");
    io::Write::write(w, b\"x\")?;
    let mut file = std::fs::File::open(\"x\")?;
    file.read(buf)?;
    Ok(())
}
fn g(ctx: &mut Context) -> io::Result<()> {
    ctx.write(b\"x\")?;
    Ok(())
}
";
        // Line 12 is Clippy's too; rustc already warns of the unused `Result`.
        assert_eq!(lines("rs/unused-io-amount", src), [3, 4, 5, 9, 15]);
        let no_trait = "fn f(w: &mut W) { w.write(b\"x\").unwrap(); }";
        assert!(lines("rs/unused-io-amount", no_trait).is_empty());
    }

    #[test]
    fn discriminants_beyond_32_bits() {
        let src = "#[repr(usize)]
enum A { X = 0x1_0000_0000, Y = 0 }
#[repr(isize)]
enum B { X = -0x8000_0001, Y = 0x7fff_ffff }
#[repr(u64)]
enum C { X = 0x1_0000_0000 }
#[repr(usize)]
enum E { X = 0xffff_ffff }
const BIG: usize = 1 << 40;
#[repr(usize)]
enum G { X = BIG }
enum L { X = 0x1_0000_0000 }
#[repr(C)]
enum N { X = 1 << 33 }
#[repr(isize)]
enum H { X = 0x7fff_ffff, Y }
#[repr(usize)]
enum K { X = u32::MAX as usize }
";
        assert_eq!(lines("rs/enum-clike-unportable", src), [2, 4, 11, 12, 14]);
    }

    #[test]
    fn subtractions_inverted_by_their_condition() {
        let cases = [
            "let a: u32 = 1;",
            "let b: u32 = 2;",
            "let r = if a > b { b - a } else { 0 };",
            "let r = if a > b { a - b } else { 0 };",
            "let r = if a < b { a - b } else { 0 };",
            "let r = if a > b { 0 } else { a - b };",
            "let r = if a <= b { 0 } else { b - a };",
            "let r = if a > b { b - a + 1 } else { 0 };",
            "let r = if a > b { b - a } else { 1 };",
            "let r = if a > b { b - a } else if a == b { 0 } else { 1 };",
            "let r = if a > b { b - a } else { u32::MIN };",
            "let r = if a > 5 { 5 - a } else { 0 };",
            "let r = if a + 1 > b { b - (a + 1) } else { 0 };",
            "let r = if a > b { { b - a } } else { 0 };",
            "let i: i32 = 1;",
            "let j: i32 = 2;",
            "let r = if i > j { j - i } else { 0 };",
            "let r = if a.gt(&b) { b - a } else { 0 };",
            "let r = if v.len() > a { a - v.len() } else { 0 };",
        ];
        assert_eq!(
            reported("rs/inverted-saturating-sub", &cases),
            [3, 5, 6, 7, 12, 13, 14]
        );
    }

    #[test]
    fn comparisons_with_a_types_extremes() {
        let cases = [
            "let x: u32 = 1;",
            "let y: i32 = 1;",
            "let z: u8 = 1;",
            "let b = true;",
            "if x < 0 {}",
            "if 0 <= x {}",
            "if x <= 0 {}",
            "if x > 0 {}",
            "if v.len() <= 0 {}",
            "if y < 0 {}",
            "if y >= i32::MAX {}",
            "if 100 > i32::MAX {}",
            "if z > 255 {}",
            "if z > 254 {}",
            "if b > true {}",
            "if b == true {}",
            "if y < -2147483648 {}",
            "if (x as u8) < 0 {}",
            "if n > usize::MAX {}",
            "if flag >= false {}",
            "let f = 1.0f64;",
            "if f < f64::MIN {}",
            "assert!(x >= 0);",
        ];
        assert_eq!(
            reported("rs/absurd-extreme-comparison", &cases),
            [5, 6, 7, 9, 11, 12, 13, 15, 18, 19, 23]
        );
    }

    #[test]
    fn loops_whose_condition_never_changes() {
        let src = "fn f(arg: i32, r: &mut i32) {
    let i = 0;
    while i > 10 { println!(\"x\"); }
    let mut j = 0;
    while j < 10 { j += 1; }
    let mut v = vec![1];
    while v.len() > 0 { v.pop(); }
    let mut m = 0;
    while m < 10 { inc(&mut m); }
    let mut q = 0;
    while q < 10 { let mut q = 5; q += 1; }
    let mut rr = 0;
    while rr < 10 { (|| rr += 1)(); }
    while *r > 0 { dec(r); }
    while *r > 0 {}
    while N > 0 {}
    let (mut a, b) = (0, 1);
    while a < b { a += 1; }
    let mut s = S { f: 0 };
    while s.f < 1 { s.f += 1; }
    let len = v.len();
    while len > 0 { v.pop(); }
    let mut k = 0;
    while k < 10 { write!(k, \"x\"); }
    let c = 0;
    while c < 10 { println!(\"{}\", c); }
}
impl S {
    fn g(&mut self, n: usize) { while self.len < n { self.push(1); } }
}
";
        assert_eq!(
            lines("rs/while-immutable-condition", src),
            [3, 11, 15, 22, 26]
        );
    }

    #[test]
    fn unit_values_compared() {
        let src = "fn foo() {}
fn bar() {}
fn baz() -> i32 { 1 }
fn f() {
    if { foo(); } == { bar(); } {}
    if foo() == bar() {}
    if () == () {}
    assert_eq!({ foo(); }, { bar(); });
    assert_ne!((), ());
    debug_assert_eq!(foo(), ());
    if baz() == baz() {}
    if { 1 } == { 2 } {}
    let u = ();
    if u == () {}
    assert!(foo() == ());
    debug_assert_ne!(foo(), bar());
    let foo = || 1;
    if foo() == 1 {}
    assert_eq!(format!(\"{}\", 1), format!(\"{}\", 2));
}
fn format() {}
";
        assert_eq!(lines("rs/unit-cmp", src), [5, 6, 7, 8, 14, 15, 16]);
    }

    #[test]
    fn unit_values_hashed() {
        let src = "fn foo() {}
fn baz() -> i32 { 1 }
fn h<H: Hasher>(state: &mut H, x: u8) {
    ().hash(state);
    foo().hash(state);
    x.hash(state);
    let u = ();
    u.hash(state);
    match x { 0 => ().hash(state), _ => x.hash(state) }
    (x, ()).hash(state);
    baz().hash(state);
}
";
        assert_eq!(lines("rs/unit-hash", src), [4, 5, 8, 9]);
    }
}
