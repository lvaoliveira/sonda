//! Rust rules, batch 4 (ADR-0007, ADR-0026): the remaining lints whose pattern
//! a single file's syntax can show. As in the other batches each follows its
//! Clippy lint and reports only what the text proves where the lint needs a
//! type.

use super::java_security::text;
use super::prelude::*;
use super::rs::{arguments, integer_value, method, receiver, same_pure_expression};

/// Rules that are off unless `rules.enabled` lists them (see
/// `catalog::OFF_BY_DEFAULT`).
pub(super) static OFF_BY_DEFAULT: &[&str] = &[];

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "rs/unit-hash",
        name: "Unit values should not be hashed",
        description: "Hashing `()` feeds nothing to the hasher: the call has no effect.",
        message: "Hashing a unit value does nothing.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[related("S7422")],
        check: Check::Query {
            langs: RUST,
            query: "(call_expression function: (field_expression value: (unit_expression) field: (field_identifier) @name) arguments: (arguments)) @match",
            filter: Some(Keep(hashes_unit)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "use std::hash::{Hash, Hasher};\nfn f<H: Hasher>(h: &mut H) { ().hash(h); }",
            good: "use std::hash::{Hash, Hasher};\nfn f<H: Hasher>(h: &mut H) { 1u8.hash(h); }",
        }),
    },
    Rule {
        id: "rs/unit-cmp",
        name: "Unit values should not be compared",
        description: "Every unit value is equal to every other one, so a comparison with `()` is a constant.",
        message: "A unit value is compared here, which always gives the same answer.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[related("S7423")],
        check: Check::Query {
            langs: RUST,
            query: "[(binary_expression operator: [\"==\" \"!=\" \"<\" \"<=\" \">\" \">=\"]) (call_expression function: (identifier) arguments: (arguments))] @match",
            filter: Some(Find(compares_unit)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f(x: ()) -> bool { x == () }",
            good: "fn f(x: u8) -> bool { x == 0 }",
        }),
    },
    Rule {
        id: "rs/enum-clike-unportable",
        name: "C-like enums should not have unportable variants",
        description: "A discriminant that doesn't fit in 32 bits breaks on targets where `isize` is 32 bits wide, \
                      unless the enum names its integer type with `#[repr]`.",
        message: "This discriminant does not fit in 32 bits.",
        category: Bug,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[related("S7426")],
        check: Check::Query {
            langs: RUST,
            query: "(enum_item) @match",
            filter: Some(Find(unportable_discriminant)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "enum E { A = 0x1_0000_0000 }",
            good: "#[repr(u64)]\nenum E { A = 0x1_0000_0000 }",
        }),
    },
    Rule {
        id: "rs/inverted-saturating-sub",
        name: "`saturating_sub` should be used to avoid subtraction underflow",
        description: "Inside `if a > b`, `b.saturating_sub(a)` is always 0: the operands are the wrong way round.",
        message: "The operands are reversed, so this always gives 0.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[related("S7463")],
        check: Check::Query {
            langs: RUST,
            query: "(if_expression condition: (binary_expression operator: [\">\" \"<\"]) consequence: (block)) @match",
            filter: Some(Find(inverted_sub)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f(a: u32, b: u32) -> u32 { if a > b { b.saturating_sub(a) } else { 0 } }",
            good: "fn f(a: u32, b: u32) -> u32 { if a > b { a.saturating_sub(b) } else { 0 } }",
        }),
    },
    Rule {
        id: "rs/while-immutable-condition",
        name: "Immutable variables should not be used in while loop conditions",
        description: "A `while` whose condition reads only variables that can't change, and whose body never \
                      leaves the loop, either never runs or never stops.",
        message: "Nothing in this condition can change, so the loop never ends.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[related("S7415")],
        check: Check::Query {
            langs: RUST,
            query: "(while_expression condition: (_) body: (block)) @match",
            filter: Some(Find(immutable_while_condition)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn work() {}\nfn f(n: u32) { while n > 0 { work(); } }",
            good: "fn work() {}\nfn f(mut n: u32) { while n > 0 { work(); n -= 1; } }",
        }),
    },
    Rule {
        id: "rs/unused-io-amount",
        name: "I/O buffers should be processed entirely",
        description: "`read` and `write` may transfer fewer bytes than asked for: ignoring the count loses data. \
                      Use `read_exact`, `write_all` or look at the count.",
        message: "The number of bytes transferred is ignored here.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[related("S7419")],
        check: Check::Query {
            langs: RUST,
            query: "(expression_statement) @match",
            filter: Some(Keep(ignores_io_amount)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "use std::io::Write;\nfn f(w: &mut impl Write) -> std::io::Result<()> { w.write(b\"x\")?; Ok(()) }",
            good: "use std::io::Write;\nfn f(w: &mut impl Write) -> std::io::Result<()> { w.write_all(b\"x\")?; Ok(()) }",
        }),
    },
    Rule {
        id: "rs/possible-missing-comma",
        name: "Array elements should be separated by commas",
        description: "An array element that is an operation split over two lines, with the operator starting the \
                      second, is usually two elements with a comma forgotten.",
        message: "Is a comma missing before this operator?",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[related("S3723")],
        check: Check::Query {
            langs: RUST,
            query: "(array_expression) @match",
            filter: Some(Find(missing_comma)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f() -> [i32; 2] { [1,\n    2\n    -3] }",
            good: "fn f() -> [i32; 3] { [1,\n    2,\n    -3] }",
        }),
    },
];

fn is_comment(node: &Node) -> bool {
    matches!(node.kind(), "line_comment" | "block_comment")
}

fn hashes_unit(call: Node, src: &[u8]) -> bool {
    method(call).is_some_and(|m| text(m, src) == b"hash") && arguments(call).len() == 1
}

fn compares_unit<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let operands = if node.kind() == "binary_expression" {
        vec![
            node.child_by_field_name("left")?,
            node.child_by_field_name("right")?,
        ]
    } else {
        let function = text(node.child_by_field_name("function")?, src);
        if !matches!(
            function,
            b"assert_eq" | b"assert_ne" | b"debug_assert_eq" | b"debug_assert_ne"
        ) {
            return None;
        }
        arguments(node)
    };
    operands.into_iter().find(|o| o.kind() == "unit_expression")
}

/// An integer type `#[repr(..)]` names, which makes the discriminants' size explicit.
fn has_int_repr(item: Node, src: &[u8]) -> bool {
    let mut sibling = item.prev_named_sibling();
    while let Some(s) = sibling {
        if is_comment(&s) {
            sibling = s.prev_named_sibling();
            continue;
        }
        if s.kind() != "attribute_item" {
            return false;
        }
        let t = text(s, src);
        let names_repr = t.windows(5).any(|w| w == b"repr(");
        let names_int = [
            &b"u8"[..],
            b"i8",
            b"u16",
            b"i16",
            b"u32",
            b"i32",
            b"u64",
            b"i64",
        ]
        .iter()
        .chain([&b"u128"[..], b"i128", b"usize", b"isize"].iter())
        .any(|ty| t.windows(ty.len()).any(|w| w == *ty));
        if names_repr && names_int {
            return true;
        }
        sibling = s.prev_named_sibling();
    }
    false
}

/// Whether an explicit discriminant is outside what a 32-bit `isize` holds.
fn out_of_32_bits(value: Node, src: &[u8]) -> bool {
    match value.kind() {
        "integer_literal" => integer_value(value, src).is_some_and(|v| v > u128::from(u32::MAX)),
        "unary_expression" => {
            let is_minus = text(value, src).first() == Some(&b'-');
            let operand = value.named_child(0);
            is_minus
                && operand
                    .and_then(|o| integer_value(o, src))
                    .is_some_and(|v| v > 1 << 31)
        }
        _ => false,
    }
}

fn unportable_discriminant<'t>(item: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if has_int_repr(item, src) {
        return None;
    }
    let body = item.child_by_field_name("body")?;
    let mut c = body.walk();
    body.named_children(&mut c)
        .filter(|v| v.kind() == "enum_variant")
        .filter_map(|v| v.child_by_field_name("value"))
        .find(|value| out_of_32_bits(*value, src))
}

/// Calls in `node`, not looking into closures or nested functions.
fn calls_in<'t>(node: Node<'t>, out: &mut Vec<Node<'t>>) {
    if matches!(node.kind(), "closure_expression" | "function_item") {
        return;
    }
    if node.kind() == "call_expression" {
        out.push(node);
    }
    let mut c = node.walk();
    for child in node.named_children(&mut c) {
        calls_in(child, out);
    }
}

fn inverted_sub<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let condition = node.child_by_field_name("condition")?;
    let left = condition.child_by_field_name("left")?;
    let right = condition.child_by_field_name("right")?;
    // In `a > b` the smaller value is `b`; in `a < b` it is `a`.
    let (smaller, larger) = if text(condition.child_by_field_name("operator")?, src) == b">" {
        (right, left)
    } else {
        (left, right)
    };
    let mut calls = Vec::new();
    calls_in(node.child_by_field_name("consequence")?, &mut calls);
    calls.into_iter().find(|call| {
        let args = arguments(*call);
        method(*call).is_some_and(|m| text(m, src) == b"saturating_sub")
            && args.len() == 1
            && receiver(*call).is_some_and(|r| same_pure_expression(r, smaller, src))
            && same_pure_expression(args[0], larger, src)
    })
}

/// Names in a condition built only from variables, literals and operators;
/// `None` when it holds anything else (a call, a field, a dereference...).
fn plain_condition_names<'s>(node: Node, src: &'s [u8], names: &mut Vec<&'s [u8]>) -> Option<()> {
    match node.kind() {
        "identifier" => names.push(text(node, src)),
        "integer_literal" | "float_literal" | "boolean_literal" | "char_literal" => {}
        "parenthesized_expression" | "binary_expression" | "unary_expression" => {
            if node.kind() == "unary_expression" && text(node, src).first() == Some(&b'*') {
                return None;
            }
            let mut c = node.walk();
            for child in node.named_children(&mut c) {
                plain_condition_names(child, src, names)?;
            }
        }
        _ => return None,
    }
    Some(())
}

/// How a name is bound inside `function`: how many binding sites it has, and
/// whether the only one is a plain immutable `let` or parameter.
fn immutable_binding(function: Node, name: &[u8], src: &[u8]) -> bool {
    let mut sites = 0;
    let mut immutable = false;
    let mut stack = vec![function];
    while let Some(n) = stack.pop() {
        if n.kind() == "identifier" && text(n, src) == name {
            let parent = n.parent();
            let kind = parent.map_or("", |p| p.kind());
            let plain = matches!(kind, "let_declaration" | "parameter")
                && parent.and_then(|p| p.child_by_field_name("pattern")) == Some(n);
            if plain {
                sites += 1;
                let p = parent.unwrap();
                let mut c = p.walk();
                immutable = !p.children(&mut c).any(|k| k.kind() == "mutable_specifier");
            } else if kind.ends_with("pattern")
                || matches!(
                    kind,
                    "for_expression"
                        | "closure_parameters"
                        | "let_condition"
                        | "parameter"
                        | "let_declaration"
                        | "enum_variant"
                        | "static_item"
                        | "const_item"
                )
            {
                sites += 2;
            }
        }
        let mut c = n.walk();
        stack.extend(n.named_children(&mut c));
    }
    sites == 1 && immutable
}

fn leaves_loop(body: Node) -> bool {
    let mut stack = vec![body];
    while let Some(n) = stack.pop() {
        if matches!(
            n.kind(),
            "break_expression" | "return_expression" | "try_expression" | "macro_invocation"
        ) {
            return true;
        }
        let mut c = n.walk();
        stack.extend(n.named_children(&mut c));
    }
    false
}

fn immutable_while_condition<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let condition = node.child_by_field_name("condition")?;
    let mut names = Vec::new();
    plain_condition_names(condition, src, &mut names)?;
    if names.is_empty() || leaves_loop(node.child_by_field_name("body")?) {
        return None;
    }
    let mut scope = node.parent();
    while let Some(s) = scope {
        match s.kind() {
            "function_item" => break,
            "closure_expression" => return None,
            _ => scope = s.parent(),
        }
    }
    let function = scope?;
    names
        .iter()
        .all(|name| immutable_binding(function, name, src))
        .then_some(condition)
}

/// Whether the file names an I/O module or trait, which `read`/`write` need
/// to be the std ones: many crates have their own `write(&mut self, x)`.
fn mentions_io(src: &[u8]) -> bool {
    [
        &b"std::io"[..],
        b"tokio::io",
        b"futures::io",
        b"futures_util::io",
        b"async_std::io",
        b"AsyncReadExt",
        b"AsyncWriteExt",
    ]
    .iter()
    .any(|m| src.windows(m.len()).any(|w| w == *m))
}

fn ignores_io_amount(statement: Node, src: &[u8]) -> bool {
    if !mentions_io(src) {
        return false;
    }
    let Some(mut expr) = statement.named_child(0).filter(|e| !is_comment(e)) else {
        return false;
    };
    let mut stripped = false;
    loop {
        match expr.kind() {
            "try_expression" | "await_expression" | "parenthesized_expression" => {
                let Some(inner) = expr.named_child(0) else {
                    return false;
                };
                stripped = true;
                expr = inner;
            }
            "call_expression" => {
                let Some(name) = method(expr) else {
                    return false;
                };
                let name = text(name, src);
                if matches!(name, b"unwrap" | b"expect") {
                    let Some(inner) = receiver(expr) else {
                        return false;
                    };
                    stripped = true;
                    expr = inner;
                    continue;
                }
                return stripped
                    && receiver(expr).is_some_and(|r| text(r, src) != b"self")
                    && matches!(
                        name,
                        b"read" | b"write" | b"read_vectored" | b"write_vectored"
                    )
                    && arguments(expr).len() == 1;
            }
            _ => return false,
        }
    }
}

fn missing_comma<'t>(array: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut c = array.walk();
    let elements: Vec<_> = array
        .named_children(&mut c)
        .filter(|e| !is_comment(e))
        .collect();
    if elements.len() < 2 {
        return None;
    }
    elements.into_iter().find(|e| {
        if e.kind() != "binary_expression" {
            return false;
        }
        let (Some(left), Some(right), Some(op)) = (
            e.child_by_field_name("left"),
            e.child_by_field_name("right"),
            e.child_by_field_name("operator"),
        ) else {
            return false;
        };
        matches!(text(op, src), b"-" | b"*" | b"&")
            && op.start_position().row > left.end_position().row
            && op.start_position().row == right.start_position().row
    })
}

#[cfg(test)]
mod tests {
    use crate::analysis::analyze;
    use crate::config::Config;
    use crate::lang::Lang;
    use crate::rules::RuleSet;
    use std::time::{Duration, Instant};

    fn lines(rule: &str, src: &str) -> Vec<usize> {
        let mut cfg = Config::default();
        cfg.rules.enabled = super::OFF_BY_DEFAULT.iter().map(|&id| id.into()).collect();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        let a = analyze("t.rs", Lang::Rust, src, &rules, &cfg, deadline).unwrap();
        a.issues
            .iter()
            .filter(|i| i.rule == rule)
            .map(|i| i.line)
            .collect()
    }

    fn in_fn(rule: &str, body: &str) -> bool {
        !lines(rule, &format!("fn f() {{\n{body}\n}}\n")).is_empty()
    }

    #[test]
    fn hashing_a_unit_value_is_reported() {
        assert!(in_fn("rs/unit-hash", "().hash(&mut h);"));
        assert!(!in_fn("rs/unit-hash", "1u8.hash(&mut h);"));
        assert!(!in_fn("rs/unit-hash", "x.hash(&mut h);"));
    }

    #[test]
    fn comparing_a_unit_value_is_reported() {
        assert!(in_fn("rs/unit-cmp", "let _ = x == ();"));
        assert!(in_fn("rs/unit-cmp", "let _ = () != x;"));
        assert!(in_fn("rs/unit-cmp", "assert_eq!((), x);"));
        assert!(!in_fn("rs/unit-cmp", "let _ = x == y;"));
        assert!(!in_fn("rs/unit-cmp", "assert_eq!(x, y);"));
    }

    #[test]
    fn a_discriminant_wider_than_32_bits_needs_a_repr() {
        let rule = "rs/enum-clike-unportable";
        assert!(!lines(rule, "enum E { A = 0x1_0000_0000 }\n").is_empty());
        assert!(!lines(rule, "enum E { A = -0x8000_0001 }\n").is_empty());
        assert!(lines(rule, "enum E { A = 0xFFFF_FFFF }\n").is_empty());
        assert!(lines(rule, "enum E { A = -0x8000_0000 }\n").is_empty());
        assert!(lines(rule, "#[repr(u64)]\nenum E { A = 0x1_0000_0000 }\n").is_empty());
        assert!(
            lines(
                rule,
                "#[derive(Debug)]\n#[repr(i64)]\nenum E { A = 1 << 40 }\n"
            )
            .is_empty()
        );
    }

    #[test]
    fn subtracting_the_larger_from_the_smaller_saturates_to_zero() {
        let rule = "rs/inverted-saturating-sub";
        assert!(in_fn(rule, "if a > b { b.saturating_sub(a) } else { 0 };"));
        assert!(in_fn(rule, "if a < b { a.saturating_sub(b) } else { 0 };"));
        assert!(!in_fn(rule, "if a > b { a.saturating_sub(b) } else { 0 };"));
        assert!(!in_fn(rule, "if a < b { b.saturating_sub(a) } else { 0 };"));
        assert!(!in_fn(rule, "if a > b { c.saturating_sub(a) } else { 0 };"));
    }

    #[test]
    fn a_while_over_immutable_variables_is_reported() {
        let rule = "rs/while-immutable-condition";
        assert!(!lines(rule, "fn f(n: u32) { while n > 0 { g(); } }\n").is_empty());
        assert!(!lines(rule, "fn f() { let n = 3; while n > 0 { g(); } }\n").is_empty());
        // A variable that changes, or one declared `mut`, is fine.
        assert!(lines(rule, "fn f(mut n: u32) { while n > 0 { n -= 1; } }\n").is_empty());
        assert!(lines(rule, "fn f() { let mut n = 3; while n > 0 { g(); } }\n").is_empty());
        // A call can change what the condition reads, and a break ends the loop.
        assert!(lines(rule, "fn f(n: u32) { while n > g() { h(); } }\n").is_empty());
        assert!(lines(rule, "fn f(n: u32) { while n > 0 { if g() { break; } } }\n").is_empty());
        assert!(lines(rule, "fn f(n: u32) { while n > 0 { g()?; } }\n").is_empty());
        // Shadowed or unknown names are left alone.
        assert!(
            lines(
                rule,
                "fn f(n: u32) { let n = n; let mut n = n; while n > 0 { g(); } }\n"
            )
            .is_empty()
        );
        assert!(lines(rule, "fn f() { while N > 0 { g(); } }\n").is_empty());
        assert!(lines(rule, "fn f(r: &u32) { while *r > 0 { g(); } }\n").is_empty());
    }

    #[test]
    fn ignoring_the_amount_read_or_written_is_reported() {
        let rule = "rs/unused-io-amount";
        let io = |body: &str| {
            !lines(
                rule,
                &format!("use std::io::Write;\nfn f() {{\n{body}\n}}\n"),
            )
            .is_empty()
        };
        assert!(io("w.write(b\"x\")?;"));
        assert!(io("r.read(&mut buf).unwrap();"));
        assert!(io("r.read(&mut buf).await?;"));
        assert!(!io("let n = r.read(&mut buf)?;"));
        assert!(!io("w.write_all(b\"x\")?;"));
        assert!(!io("lock.read().unwrap();"));
        assert!(!io("w.flush()?;"));
        assert!(!io("self.write(b\"x\")?;"));
        // Without an I/O import the `write` is probably the crate's own.
        assert!(!in_fn(rule, "w.write(b\"x\")?;"));
    }

    #[test]
    fn an_operator_starting_the_line_inside_an_array_is_reported() {
        let rule = "rs/possible-missing-comma";
        assert!(!lines(rule, "fn f() { let a = [1,\n    2\n    -3, 4]; }\n").is_empty());
        assert!(lines(rule, "fn f() { let a = [1,\n    2,\n    -3]; }\n").is_empty());
        assert!(lines(rule, "fn f() { let a = [1, 2 - 3, 4]; }\n").is_empty());
        assert!(lines(rule, "fn f() { let a = [1 +\n    2, 3]; }\n").is_empty());
    }
}
