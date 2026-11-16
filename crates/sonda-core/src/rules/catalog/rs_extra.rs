//! Rust rules, batch 3 (ADR-0007, ADR-0026): contradictory conditions, calls
//! that always fail, and the misuses of pointers and iterators that one file's
//! syntax shows. As in the other batches each follows its Clippy lint, and
//! reports only what the text proves where the lint needs a type.

use super::java_security::text;
use super::prelude::*;
use super::rs::{
    arguments, block_items, integer_value, is_integer, method, path_tail, receiver,
    same_pure_expression,
};

/// Rules that are off unless `rules.enabled` lists them (see
/// `catalog::OFF_BY_DEFAULT`).
pub(super) static OFF_BY_DEFAULT: &[&str] = &[];

/// Every method call, shared with the other batches' rules.
const METHOD_CALL: &str = "(call_expression function: (field_expression field: (field_identifier)) arguments: (arguments)) @match";

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "rs/overly-complex-bool-expr",
        name: "Boolean expressions should not be gratuitous",
        description: "`a && !a` is always false and `a || !a` always true: the expression is a constant in disguise.",
        message: "This boolean expression is always the same value.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[related("S2589")],
        check: Check::Query {
            langs: RUST,
            query: "(binary_expression operator: [\"&&\" \"||\"]) @match",
            filter: Some(Find(contradictory_terms)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f(a: bool, b: bool) -> bool { a && b && !a }",
            good: "fn f(a: bool, b: bool) -> bool { a && b }",
        }),
    },
    Rule {
        id: "rs/let-underscore-lock",
        name: "Synchronization locks should not be dropped immediately after acquisition",
        description: "`let _ = m.lock();` drops the guard on the spot, so nothing is protected after that line.",
        message: "Bind the guard to a name, such as `_guard`, so it lives to the end of the scope.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[related("S7450")],
        check: Check::Query {
            langs: RUST,
            query: "(let_declaration value: (_)) @match",
            filter: Some(Keep(drops_lock_at_once)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f(m: &std::sync::Mutex<u8>) { let _ = m.lock().unwrap(); }",
            good: "fn f(m: &std::sync::Mutex<u8>) { let _guard = m.lock().unwrap(); }",
        }),
    },
    Rule {
        id: "rs/min-max-reversed",
        name: "Clamping values with `cmp::min` and `cmp::max` should use correct ranges",
        description: "`x.max(100).min(10)` is always 10: the lower bound is above the upper one.",
        message: "The bounds are reversed, so this always gives the same value.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6913")],
        check: Check::Query {
            langs: RUST,
            query: METHOD_CALL,
            filter: Some(Find(reversed_clamp)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f(x: i32) -> i32 { x.max(100).min(10) }",
            good: "fn f(x: i32) -> i32 { x.max(10).min(100) }",
        }),
    },
    Rule {
        id: "rs/out-of-bounds-index",
        name: "Accessing an array element should not trigger a panic",
        description: "Indexing an array past its length with a constant is a panic the compiler could have named.",
        message: "This index is past the end of the array.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[related("S6466")],
        check: Check::Query {
            langs: RUST,
            query: "(index_expression) @match",
            filter: Some(Keep(is_out_of_bounds)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f() -> u8 { let a = [1, 2, 3]; a[5] }",
            good: "fn f() -> u8 { let a = [1, 2, 3]; a[2] }",
        }),
    },
    Rule {
        id: "rs/unnecessary-cast",
        name: "Redundant casts should be avoided",
        description: "`1 as u32` is a `1_u32` the long way round, and `1u32 as u32` casts to the type it already has.",
        message: "Write the literal with its type instead of casting it.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[related("S4325")],
        check: Check::Query {
            langs: RUST,
            query: "(type_cast_expression value: [(integer_literal) (float_literal)] type: (primitive_type)) @match",
            filter: Some(Keep(is_unnecessary_literal_cast)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f() -> u32 { 1 as u32 }",
            good: "fn f() -> u32 { 1_u32 }",
        }),
    },
    Rule {
        id: "rs/null-pointer-argument",
        name: "Null pointers should not be passed to functions expecting non-null arguments",
        description: "`slice::from_raw_parts` and the `ptr` read/write/copy functions need a valid, non-null \
                      pointer even for zero length: a null one is undefined behavior.",
        message: "Do not pass a null pointer here.",
        category: Bug,
        severity: Major,
        effort_minutes: 15,
        sonar: &[related("S3807")],
        check: Check::Query {
            langs: RUST,
            query: "(call_expression function: (_) arguments: (arguments)) @match",
            filter: Some(Keep(passes_null_pointer)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f() -> &'static [u8] { unsafe { std::slice::from_raw_parts(std::ptr::null(), 0) } }",
            good: "fn f() -> &'static [u8] { &[] }",
        }),
    },
    Rule {
        id: "rs/transmute-null",
        name: "Null pointers should not be transmuted",
        description: "Transmuting a null pointer or the integer 0 into a reference or a function pointer builds a \
                      value the type forbids.",
        message: "Do not transmute a null pointer: the result is undefined behavior.",
        category: Bug,
        severity: Major,
        effort_minutes: 15,
        sonar: &[related("S7427"), related("S7429")],
        check: Check::Query {
            langs: RUST,
            query: "(call_expression function: [(identifier) (scoped_identifier) (generic_function)] arguments: (arguments)) @match",
            filter: Some(Keep(transmutes_null)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f() -> &'static u8 { unsafe { std::mem::transmute(0 as *const u8) } }",
            good: "fn f() -> Option<&'static u8> { None }",
        }),
    },
    Rule {
        id: "rs/read-line-untrimmed",
        name: "Lines read from the standard input should be trimmed",
        description: "`read_line` keeps the newline, so parsing the line without trimming it fails on every input.",
        message: "Trim the line before parsing it: it still ends with a newline.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[related("S7441")],
        check: Check::Query {
            langs: RUST,
            query: "(block) @match",
            filter: Some(Find(parses_untrimmed_line)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f() -> i32 { let mut s = String::new(); std::io::stdin().read_line(&mut s).unwrap(); s.parse().unwrap() }",
            good: "fn f() -> i32 { let mut s = String::new(); std::io::stdin().read_line(&mut s).unwrap(); s.trim().parse().unwrap() }",
        }),
    },
];

// ---- Conditions ----

/// The terms of a chain of one operator: `a && b && c`, without the parentheses.
fn chain_terms<'t>(top: Node<'t>, op: &[u8], src: &[u8]) -> Vec<Node<'t>> {
    let mut terms = Vec::new();
    let mut stack = vec![top];
    while let Some(n) = stack.pop() {
        let mut n = n;
        while n.kind() == "parenthesized_expression" && n.named_child_count() == 1 {
            let Some(inner) = n.named_child(0) else { break };
            n = inner;
        }
        let same_op = n.kind() == "binary_expression"
            && n.child_by_field_name("operator").map(|o| text(o, src)) == Some(op);
        if same_op {
            // Pushed right then left, so terms come out in source order.
            stack.extend(
                [
                    n.child_by_field_name("right"),
                    n.child_by_field_name("left"),
                ]
                .into_iter()
                .flatten(),
            );
        } else {
            terms.push(n);
        }
    }
    terms
}

/// Whether `node` is the outermost of a chain of its operator: only the top is
/// asked, so a long chain is reported once.
fn is_chain_top(node: Node, src: &[u8]) -> bool {
    let Some(op) = node.child_by_field_name("operator") else {
        return false;
    };
    let mut parent = node.parent();
    // Parentheses don't end a chain.
    while let Some(p) = parent.filter(|p| p.kind() == "parenthesized_expression") {
        parent = p.parent();
    }
    !parent.is_some_and(|p| {
        p.kind() == "binary_expression"
            && p.child_by_field_name("operator").map(|o| text(o, src)) == Some(text(op, src))
    })
}

/// `!x`'s `x`.
fn negated<'t>(term: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    (term.kind() == "unary_expression" && term.child(0).is_some_and(|op| text(op, src) == b"!"))
        .then(|| term.named_child(0))
        .flatten()
}

fn contradictory_terms<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !is_chain_top(node, src) {
        return None;
    }
    let op = text(node.child_by_field_name("operator")?, src);
    let terms = chain_terms(node, op, src);
    for (i, a) in terms.iter().enumerate() {
        let Some(inner) = negated(*a, src) else {
            continue;
        };
        if terms
            .iter()
            .enumerate()
            .any(|(j, b)| i != j && same_pure_expression(inner, *b, src))
        {
            return Some(node);
        }
    }
    None
}

fn drops_lock_at_once(declaration: Node, src: &[u8]) -> bool {
    let (Some(pattern), Some(value)) = (
        declaration.child_by_field_name("pattern"),
        declaration.child_by_field_name("value"),
    ) else {
        return false;
    };
    if text(pattern, src) != b"_" {
        return false;
    }
    // `m.lock()`, `m.lock().unwrap()`, `m.lock()?`: strip what unwraps the result.
    let mut call = value;
    loop {
        match call.kind() {
            "try_expression" | "parenthesized_expression" => match call.named_child(0) {
                Some(inner) => call = inner,
                None => return false,
            },
            "call_expression"
                if method(call).is_some_and(|m| matches!(text(m, src), b"unwrap" | b"expect")) =>
            {
                match receiver(call) {
                    Some(inner) => call = inner,
                    None => return false,
                }
            }
            _ => break,
        }
    }
    let Some(name) = method(call).filter(|_| call.kind() == "call_expression") else {
        return false;
    };
    let args = arguments(call);
    let called_on = receiver(call).map(|r| text(r, src)).unwrap_or_default();
    // The standard streams' `lock()` is a handle on a stream, not a mutex.
    let stream = [&b"stdin"[..], b"stdout", b"stderr"]
        .iter()
        .any(|s| called_on.windows(s.len()).any(|w| w == *s));
    args.is_empty()
        && !stream
        && matches!(text(name, src), b"lock" | b"read" | b"write" | b"try_lock")
}

// ---- Strings, numbers and indexing ----

/// A numeric literal's value: an integer or a float, underscores and suffix dropped.
fn number(literal: Node, src: &[u8]) -> Option<f64> {
    if !matches!(literal.kind(), "integer_literal" | "float_literal") {
        return None;
    }
    if literal.kind() == "integer_literal" {
        return integer_value(literal, src).map(|v| v as f64);
    }
    let raw: String = std::str::from_utf8(text(literal, src))
        .ok()?
        .chars()
        .filter(|c| *c != '_')
        .collect();
    let digits = raw
        .strip_suffix("f32")
        .or_else(|| raw.strip_suffix("f64"))
        .unwrap_or(&raw);
    digits.parse().ok()
}

fn reversed_clamp<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let outer = method(call)?;
    let inner_call = receiver(call)?;
    let inner = method(inner_call).filter(|_| inner_call.kind() == "call_expression")?;
    let (outer_args, inner_args) = (arguments(call), arguments(inner_call));
    let (a, b) = (
        number(*inner_args.first()?, src)?,
        number(*outer_args.first()?, src)?,
    );
    if outer_args.len() != 1 || inner_args.len() != 1 {
        return None;
    }
    // `.max(a).min(b)` clamps to [a, b]: reversed when a > b. `.min(b).max(a)`
    // is the same range written the other way round.
    let reversed = match (text(inner, src), text(outer, src)) {
        (b"max", b"min") => a > b,
        (b"min", b"max") => a < b,
        _ => false,
    };
    reversed.then_some(outer)
}

/// How many elements an array expression has.
fn array_length(array: Node, src: &[u8]) -> Option<u128> {
    if array.kind() != "array_expression" {
        return None;
    }
    if let Some(len) = array.child_by_field_name("length") {
        return integer_value(len, src);
    }
    let mut c = array.walk();
    Some(
        array
            .named_children(&mut c)
            .filter(|e| !matches!(e.kind(), "line_comment" | "block_comment"))
            .count() as u128,
    )
}

fn is_out_of_bounds(index: Node, src: &[u8]) -> bool {
    let mut c = index.walk();
    let parts: Vec<Node> = index.named_children(&mut c).collect();
    let [array, at] = parts.as_slice() else {
        return false;
    };
    let Some(at) = integer_value(*at, src) else {
        return false;
    };
    let length = if array.kind() == "identifier" {
        local_array_length(*array, src)
    } else {
        array_length(*array, src)
    };
    length.is_some_and(|n| at >= n)
}

/// The length of the array the nearest earlier `let name = [..]` in an
/// enclosing block gave `name`.
fn local_array_length(name: Node, src: &[u8]) -> Option<u128> {
    let wanted = text(name, src);
    let mut node = name;
    while let Some(parent) = node.parent() {
        if parent.kind() == "block" {
            let mut previous = node.prev_named_sibling();
            while let Some(s) = previous {
                if s.kind() == "let_declaration"
                    && s.child_by_field_name("pattern")
                        .is_some_and(|p| text(p, src) == wanted)
                {
                    return s
                        .child_by_field_name("value")
                        .and_then(|v| array_length(v, src));
                }
                previous = s.prev_named_sibling();
            }
        }
        node = parent;
    }
    None
}

fn is_unnecessary_literal_cast(cast: Node, src: &[u8]) -> bool {
    let (Some(value), Some(ty)) = (
        cast.child_by_field_name("value"),
        cast.child_by_field_name("type"),
    ) else {
        return false;
    };
    let target = std::str::from_utf8(text(ty, src)).unwrap_or("");
    let numeric = [
        "i8", "i16", "i32", "i64", "i128", "isize", "u8", "u16", "u32", "u64", "u128", "usize",
        "f32", "f64",
    ];
    if !numeric.contains(&target) {
        return false;
    }
    let literal = std::str::from_utf8(text(value, src)).unwrap_or("");
    // In hexadecimal `f` is a digit, so only `i` and `u` types can be a suffix.
    let hex = literal.starts_with("0x");
    let suffix = numeric
        .iter()
        .find(|s| literal.ends_with(**s) && !(hex && s.starts_with('f')));
    match (value.kind(), suffix) {
        // A suffixed literal cast to its own type.
        (_, Some(s)) => *s == target,
        // `1 as f64`: an integer literal where a float is wanted; `1.0 as f64`.
        (_, None) if target.starts_with('f') => true,
        // `1 as u32`: only when the value fits, since `256 as u8` truncates.
        ("integer_literal", None) => integer_value(value, src).is_some_and(|v| {
            let bits: u32 = match target {
                "i8" | "u8" => 8,
                "i16" | "u16" => 16,
                "i32" | "u32" => 32,
                "i64" | "u64" | "isize" | "usize" => 64,
                _ => 128,
            };
            let signed = target.starts_with('i');
            let max = if bits == 128 {
                u128::MAX
            } else {
                (1u128 << (bits - u32::from(signed))) - 1
            };
            v <= max
        }),
        _ => false,
    }
}

// ---- Items ----

// ---- Iterators and pointers ----

/// An expression that is a null pointer: `ptr::null()`, `null_mut()` or `0 as *const T`.
fn is_null_pointer(expression: Node, src: &[u8]) -> bool {
    match expression.kind() {
        "call_expression" => expression
            .child_by_field_name("function")
            .map(|f| text(f, src))
            .is_some_and(|f| {
                let path = f.split(|b| *b == b'<').next().unwrap_or_default();
                let last = path
                    .rsplit(|b| *b == b':')
                    .find(|s| !s.is_empty())
                    .unwrap_or_default();
                matches!(last, b"null" | b"null_mut") && arguments(expression).is_empty()
            }),
        "type_cast_expression" => {
            expression
                .child_by_field_name("type")
                .is_some_and(|t| t.kind() == "pointer_type")
                && expression
                    .child_by_field_name("value")
                    .is_some_and(|v| is_integer(v, src, 0))
        }
        _ => false,
    }
}

fn passes_null_pointer(call: Node, src: &[u8]) -> bool {
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    let Some((module, name)) = path_tail(function, src) else {
        return false;
    };
    let args = arguments(call);
    // How many leading arguments must not be null.
    let checked = match (module.as_str(), name.as_str()) {
        ("slice", "from_raw_parts" | "from_raw_parts_mut") => 1,
        (
            "ptr",
            "read" | "read_unaligned" | "read_volatile" | "write" | "write_unaligned"
            | "write_volatile" | "replace" | "write_bytes" | "drop_in_place",
        ) => 1,
        ("ptr", "copy" | "copy_nonoverlapping" | "swap" | "swap_nonoverlapping") => 2,
        _ => return false,
    };
    args.iter().take(checked).any(|a| is_null_pointer(*a, src))
}

fn transmutes_null(call: Node, src: &[u8]) -> bool {
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    let tail = text(function, src);
    let name_start = tail.windows(9).position(|w| w == b"transmute");
    let named_transmute = name_start.is_some()
        && !tail.get(name_start.unwrap_or(0) + 9..).is_some_and(|rest| {
            rest.first()
                .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
        });
    if !named_transmute {
        return false;
    }
    let args = arguments(call);
    args.first().is_some_and(|a| {
        is_null_pointer(*a, src) || (is_integer(*a, src, 0) && function_target(function, src))
    })
}

/// Whether a `transmute::<_, T>` names a function pointer as `T`.
fn function_target(function: Node, src: &[u8]) -> bool {
    let t = text(function, src);
    t.windows(3).any(|w| w == b"fn(") || t.windows(3).any(|w| w == b"fn ")
}

fn parses_untrimmed_line<'t>(block: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let items = block_items(block);
    for (i, item) in items.iter().enumerate() {
        // `stdin().read_line(&mut line)`, anywhere in the statement.
        let Some((buffer, receiver_text)) = read_line_target(*item, src) else {
            continue;
        };
        if !receiver_text.windows(5).any(|w| w == b"stdin") {
            continue;
        }
        for later in &items[i + 1..] {
            let mut stack = vec![*later];
            while let Some(n) = stack.pop() {
                if n.kind() == "call_expression"
                    && let Some(m) = method(n)
                    && text(m, src) == b"parse"
                    && receiver(n).is_some_and(|r| text(r, src) == buffer)
                {
                    return Some(m);
                }
                let mut c = n.walk();
                stack.extend(n.named_children(&mut c));
            }
        }
    }
    None
}

/// The buffer a statement's `read_line(&mut buffer)` fills, and what it reads from.
fn read_line_target<'s>(statement: Node, src: &'s [u8]) -> Option<(&'s [u8], &'s [u8])> {
    let mut stack = vec![statement];
    while let Some(n) = stack.pop() {
        if n.kind() == "call_expression"
            && let Some(m) = method(n)
            && text(m, src) == b"read_line"
        {
            let args = arguments(n);
            let target = args
                .first()
                .filter(|a| a.kind() == "reference_expression")?;
            let buffer = target.child_by_field_name("value")?;
            let from = receiver(n)?;
            return Some((text(buffer, src), text(from, src)));
        }
        let mut c = n.walk();
        stack.extend(n.named_children(&mut c));
    }
    None
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
    fn a_term_and_its_negation_in_one_chain_make_the_expression_constant() {
        assert!(in_fn("rs/overly-complex-bool-expr", "let _ = a && !a;"));
        assert!(in_fn(
            "rs/overly-complex-bool-expr",
            "let _ = a || b || !a;"
        ));
        assert!(in_fn(
            "rs/overly-complex-bool-expr",
            "let _ = x.y && z && !x.y;"
        ));
        assert!(!in_fn("rs/overly-complex-bool-expr", "let _ = a && !b;"));
        assert!(!in_fn(
            "rs/overly-complex-bool-expr",
            "let _ = a && (b || !a);"
        ));
        assert!(!in_fn(
            "rs/overly-complex-bool-expr",
            "let _ = f() && !f();"
        ));
        // One report for a long chain.
        let src = "fn f() {\n    let _ = a && b && c && !a;\n}\n";
        assert_eq!(lines("rs/overly-complex-bool-expr", src), [2]);
    }

    #[test]
    fn discarding_a_lock_guard_at_once_is_flagged_but_not_a_stream_lock() {
        assert!(in_fn(
            "rs/let-underscore-lock",
            "let _ = m.lock().unwrap();"
        ));
        assert!(in_fn("rs/let-underscore-lock", "let _ = m.lock();"));
        assert!(in_fn(
            "rs/let-underscore-lock",
            "let _ = rw.read().unwrap();"
        ));
        assert!(in_fn("rs/let-underscore-lock", "let _ = rw.write()?;"));
        assert!(!in_fn(
            "rs/let-underscore-lock",
            "let _guard = m.lock().unwrap();"
        ));
        assert!(!in_fn(
            "rs/let-underscore-lock",
            "let _ = std::io::stdout().lock();"
        ));
        assert!(!in_fn("rs/let-underscore-lock", "let _ = file.write(buf);"));
    }

    #[test]
    fn a_clamp_with_its_bounds_the_wrong_way_round_is_constant() {
        assert!(in_fn("rs/min-max-reversed", "let _ = x.max(100).min(10);"));
        assert!(in_fn("rs/min-max-reversed", "let _ = x.min(10).max(100);"));
        assert!(in_fn("rs/min-max-reversed", "let _ = x.max(1.5).min(0.5);"));
        assert!(!in_fn("rs/min-max-reversed", "let _ = x.max(10).min(100);"));
        assert!(!in_fn("rs/min-max-reversed", "let _ = x.max(a).min(b);"));
    }

    #[test]
    fn indexing_an_array_past_its_length_by_a_constant_is_flagged() {
        assert!(in_fn("rs/out-of-bounds-index", "let _ = [1, 2, 3][5];"));
        assert!(in_fn(
            "rs/out-of-bounds-index",
            "let a = [1, 2, 3];\nlet _ = a[3];"
        ));
        assert!(in_fn(
            "rs/out-of-bounds-index",
            "let a = [0; 4];\nlet _ = a[4];"
        ));
        assert!(!in_fn(
            "rs/out-of-bounds-index",
            "let a = [1, 2, 3];\nlet _ = a[2];"
        ));
        assert!(!in_fn(
            "rs/out-of-bounds-index",
            "let a = vec![1, 2, 3];\nlet _ = a[5];"
        ));
        assert!(!in_fn("rs/out-of-bounds-index", "let _ = a[5];"));
    }

    #[test]
    fn casting_a_literal_to_a_type_it_can_be_written_in_is_redundant() {
        for v in [
            "1 as u32",
            "0 as f64",
            "1.0 as f32",
            "1u32 as u32",
            "255 as u8",
            "1_000 as i64",
        ] {
            assert!(
                in_fn("rs/unnecessary-cast", &format!("let _ = {v};")),
                "{v}"
            );
        }
        for v in [
            "256 as u8",
            "1u8 as u32",
            "x as u32",
            "1.5 as i32",
            "-1 as i32",
            "1 as char",
        ] {
            assert!(
                !in_fn("rs/unnecessary-cast", &format!("let _ = {v};")),
                "{v}"
            );
        }
    }

    #[test]
    fn a_null_pointer_given_to_a_function_that_needs_a_valid_one_is_flagged() {
        assert!(in_fn(
            "rs/null-pointer-argument",
            "unsafe { slice::from_raw_parts(ptr::null(), 0) };"
        ));
        assert!(in_fn(
            "rs/null-pointer-argument",
            "unsafe { std::slice::from_raw_parts_mut(0 as *mut u8, 0) };"
        ));
        assert!(in_fn(
            "rs/null-pointer-argument",
            "unsafe { ptr::copy(ptr::null(), dst, 1) };"
        ));
        assert!(in_fn(
            "rs/null-pointer-argument",
            "unsafe { ptr::read(core::ptr::null_mut()) };"
        ));
        assert!(!in_fn(
            "rs/null-pointer-argument",
            "unsafe { slice::from_raw_parts(p, 0) };"
        ));
        assert!(in_fn(
            "rs/null-pointer-argument",
            "unsafe { ptr::copy(src, ptr::null_mut(), 1) }; unsafe { ptr::swap(a, ptr::null_mut()) };"
        ));
    }

    #[test]
    fn transmuting_a_null_pointer_is_flagged() {
        assert!(in_fn(
            "rs/transmute-null",
            "let _: &u8 = unsafe { mem::transmute(0 as *const u8) };"
        ));
        assert!(in_fn(
            "rs/transmute-null",
            "let _ = unsafe { std::mem::transmute::<_, &u8>(ptr::null::<u8>()) };"
        ));
        assert!(in_fn(
            "rs/transmute-null",
            "let _ = unsafe { transmute::<usize, fn()>(0) };"
        ));
        assert!(!in_fn(
            "rs/transmute-null",
            "let _ = unsafe { mem::transmute(p) };"
        ));
        assert!(!in_fn(
            "rs/transmute-null",
            "let _ = unsafe { mem::transmute_copy(&0) };"
        ));
    }

    #[test]
    fn parsing_a_line_read_from_stdin_without_trimming_is_flagged() {
        assert!(in_fn(
            "rs/read-line-untrimmed",
            "let mut s = String::new();\nio::stdin().read_line(&mut s).unwrap();\nlet n: i32 = s.parse().unwrap();"
        ));
        assert!(!in_fn(
            "rs/read-line-untrimmed",
            "let mut s = String::new();\nio::stdin().read_line(&mut s).unwrap();\nlet n: i32 = s.trim().parse().unwrap();"
        ));
        assert!(!in_fn(
            "rs/read-line-untrimmed",
            "let mut s = String::new();\nfile.read_line(&mut s).unwrap();\nlet n: i32 = s.parse().unwrap();"
        ));
        assert!(!in_fn(
            "rs/read-line-untrimmed",
            "let mut s = String::new();\nio::stdin().read_line(&mut s).unwrap();\nlet n = s.len();"
        ));
    }

    #[test]
    fn a_file_the_parser_cannot_read_is_reported_once_when_the_rule_is_on() {
        let mut cfg = Config::default();
        cfg.rules.enabled = vec!["rs/parse-failure".into()];
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        let found = |src: &str| {
            analyze("t.rs", Lang::Rust, src, &rules, &cfg, deadline)
                .unwrap()
                .issues
                .iter()
                .filter(|i| i.rule == "rs/parse-failure")
                .count()
        };
        assert_eq!(found("fn broken( { let = ; }\n"), 1);
        assert_eq!(found("fn fine() { let x = 1; }\n"), 0);
        // Off unless listed, as in SonarQube's default profile.
        let default_rules = RuleSet::new(&Config::default().rules).unwrap();
        let a = analyze(
            "t.rs",
            Lang::Rust,
            "fn broken( {\n",
            &default_rules,
            &Config::default(),
            deadline,
        )
        .unwrap();
        assert!(a.issues.iter().all(|i| i.rule != "rs/parse-failure"));
    }

    #[test]
    fn clippy_allow_silences_these_rules_too() {
        let src = "fn f() {\n    #[allow(clippy::overly_complex_bool_expr)]\n    let _ = a && !a;\n    let _ = b && !b;\n}\n";
        assert_eq!(lines("rs/overly-complex-bool-expr", src), [4]);
    }
}
