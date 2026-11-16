//! Rust rules, batch 5 (ADR-0007, ADR-0026): more of Clippy's correctness
//! lints, settled on probe files as batch 4's were (ADR-0026, "Probing
//! Clippy"). Where a lint needs a type, a rule reports what the file's own
//! declarations prove and is `related` to its key.

use super::java_security::text;
use super::prelude::*;
use super::rs::{arguments, integer_value};
use super::rs_correctness::{
    ancestors, declaration, descendants, literal_suffix, method_is, operands, operator, unparen,
};

/// Rules that are off unless `rules.enabled` lists them (see
/// `catalog::OFF_BY_DEFAULT`): SonarQube's default profile has all of these.
pub(super) static OFF_BY_DEFAULT: &[&str] = &[];

const BINARY: &str = "(binary_expression) @match";

pub(super) static RULES: &[Rule] = &[
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
];

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

// ---------------------------------------------------------------- constants

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
}
