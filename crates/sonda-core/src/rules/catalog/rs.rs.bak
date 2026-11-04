//! Rust rules, batch 1 (ADR-0007, ADR-0026). SonarQube's Rust rules are
//! Clippy lints under its keys, so each rule here follows its lint's
//! documentation, and `rust_suppress.rs` lets `#[allow(clippy::lint)]`
//! silence it as it does there. Clippy sees types; these see syntax, so a
//! rule reports only what the file's own text proves, and is `related` to its
//! key where Clippy would find more.

use super::java_security::text;
use super::prelude::*;

/// Rules that are off unless `rules.enabled` lists them (see
/// `catalog::OFF_BY_DEFAULT`). SonarQube's default profile leaves out
/// `else_if_without_else` (a Clippy restriction lint) and `match_bool` (a
/// pedantic one), so these do too.
pub(super) static OFF_BY_DEFAULT: &[&str] = &["rs/else-if-without-else", "rs/match-on-bool"];

/// Every method call, which the rules about one method share: queries with
/// the same text are matched once.
const METHOD_CALL: &str = "(call_expression function: (field_expression field: (field_identifier)) arguments: (arguments)) @match";

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "rs/self-assignment",
        name: "Variables should not be self-assigned",
        description: "Assigning a place to itself does nothing: the statement is redundant, or the other side \
                      was meant to be a different value.",
        message: "Remove or correct this useless self-assignment.",
        category: Bug,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S1656")],
        check: Check::Query {
            langs: RUST,
            query: "(assignment_expression left: (_) right: (_)) @match",
            filter: Some(Keep(is_self_assignment)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f(a: i32) -> i32 { let mut x = a; x = x; x }",
            good: "fn f(a: i32) -> i32 { let mut x = a; x = 5; x }",
        }),
    },
    Rule {
        id: "rs/identical-operands",
        name: "Identical expressions should not be used on both sides of a binary operator",
        description: "`a == a` is always true, `a - a` always zero: one side is a mistake, or the \
                      expression is a roundabout constant.",
        message: "Identical expressions are used on both sides of this operator.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1764")],
        check: Check::Query {
            langs: RUST,
            query: "(binary_expression left: (_) right: (_)) @match",
            filter: Some(Keep(has_identical_operands)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f(a: i32, b: i32) -> bool { a + b == a + b }",
            good: "fn f(a: i32, b: i32) -> bool { a + b == b + a + 1 }",
        }),
    },
    Rule {
        id: "rs/same-condition-in-chain",
        name: "Related \"if/else if\" statements should not have the same condition",
        description: "A branch whose condition an earlier branch of the same chain already tested can never run.",
        message: "This condition was already tested earlier in the chain.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1862")],
        check: Check::Query {
            langs: RUST,
            query: "(if_expression condition: (_)) @match",
            filter: Some(Find(repeated_condition)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f(a: bool, b: bool) { if a { g(); } else if b { h(); } else if a { i(); } }",
            good: "fn f(a: bool, b: bool) { if a { g(); } else if b { h(); } else if !a { i(); } }",
        }),
    },
    Rule {
        id: "rs/skip-zero",
        name: "`skip(0)` should not be used on iterators",
        description: "Skipping no elements returns the same iterator: the call is dead code, or the count is wrong.",
        message: "Remove this `skip(0)`, which skips nothing.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S7456")],
        check: Check::Query {
            langs: RUST,
            query: METHOD_CALL,
            filter: Some(Find(skip_zero)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f(v: &[u8]) -> usize { v.iter().skip(0).count() }",
            good: "fn f(v: &[u8]) -> usize { v.iter().skip(1).count() }",
        }),
    },
    Rule {
        id: "rs/step-by-zero",
        name: "Calls to `step_by` that always panic should not be made",
        description: "`step_by(0)` panics, whatever the iterator holds.",
        message: "`step_by(0)` always panics.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S7457")],
        check: Check::Query {
            langs: RUST,
            query: METHOD_CALL,
            filter: Some(Find(step_by_zero)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f() { for _ in (0..10).step_by(0) {} }",
            good: "fn f() { for _ in (0..10).step_by(2) {} }",
        }),
    },
    Rule {
        id: "rs/splitn-limit",
        name: "`splitn` should not be used with a limit of 0 or 1",
        description: "A limit of 0 yields nothing and a limit of 1 the whole input, neither of which splits.",
        message: "A `splitn` limit of 0 or 1 never splits: use a limit of 2 or more, or drop the call.",
        category: Bug,
        severity: Major,
        effort_minutes: 3,
        sonar: &[related("S7430")],
        check: Check::Query {
            langs: RUST,
            query: METHOD_CALL,
            filter: Some(Find(splitn_limit)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f(s: &str) { for _ in s.splitn(1, ',') {} }",
            good: "fn f(s: &str) { for _ in s.splitn(2, ',') {} }",
        }),
    },
    Rule {
        id: "rs/modulo-one",
        name: "Remainder operations with `1` or `-1` should be avoided",
        description: "The remainder of a division by 1 or -1 is always 0.",
        message: "This remainder is always 0.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S7451")],
        check: Check::Query {
            langs: RUST,
            query: "(binary_expression operator: \"%\" right: (_)) @match",
            filter: Some(Keep(modulo_one)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f(a: i32) -> i32 { a % 1 }",
            good: "fn f(a: i32) -> i32 { a % 2 }",
        }),
    },
    Rule {
        id: "rs/resize-to-zero",
        name: "Avoid resizing a vector to zero using `vec.resize(0, value)`",
        description: "`resize(0, ..)` empties the vector the long way round, and evaluates a value it then drops.",
        message: "Use `clear()` instead of `resize(0, ..)`.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S7200")],
        check: Check::Query {
            langs: RUST,
            query: METHOD_CALL,
            filter: Some(Find(resize_to_zero)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f(v: &mut Vec<u8>) { v.resize(0, 1); }",
            good: "fn f(v: &mut Vec<u8>) { v.clear(); }",
        }),
    },
    Rule {
        id: "rs/option-env-unwrap",
        name: "`env!` should be preferred over `option_env!`",
        description: "`option_env!(..).unwrap()` defers to run time a failure that `env!` reports at compile time.",
        message: "Use `env!` here: a missing variable should fail the build.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S7445")],
        check: Check::Query {
            langs: RUST,
            query: METHOD_CALL,
            filter: Some(Find(option_env_unwrapped)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f() -> &'static str { option_env!(\"HOME\").unwrap() }",
            good: "fn f() -> &'static str { env!(\"HOME\") }",
        }),
    },
    Rule {
        id: "rs/uninit-assumed-init",
        name: "`MaybeUninit::uninit().assume_init()` should not be used",
        description: "It claims a value of any type is initialized without writing it, which is undefined \
                      behavior for nearly every type.",
        message: "Do not call `assume_init` on a fresh `MaybeUninit::uninit()`.",
        category: Bug,
        severity: Major,
        effort_minutes: 15,
        sonar: &[related("S7425")],
        check: Check::Query {
            langs: RUST,
            query: METHOD_CALL,
            filter: Some(Find(uninit_assumed_init)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f() -> u32 { unsafe { MaybeUninit::<u32>::uninit().assume_init() } }",
            good: "fn f() -> u32 { 0 }",
        }),
    },
    Rule {
        id: "rs/replace-with-uninit",
        name: "`mem::uninitialized` and `mem::zeroed()` should not be used to replace values",
        description: "`mem::replace(x, mem::uninitialized())` leaves `x` holding an invalid value if anything \
                      panics before it is overwritten.",
        message: "Do not replace a value with an uninitialized or zeroed one.",
        category: Bug,
        severity: Major,
        effort_minutes: 15,
        sonar: &[related("S7462")],
        check: Check::Query {
            langs: RUST,
            query: "(call_expression function: (_) arguments: (arguments)) @match",
            filter: Some(Keep(replaces_with_uninit)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f(x: &mut u32) -> u32 { unsafe { mem::replace(x, mem::zeroed()) } }",
            good: "fn f(x: &mut u32) -> u32 { mem::replace(x, 0) }",
        }),
    },
    Rule {
        id: "rs/null-pointer-from-zero",
        name: "\"std::ptr::null\" should be used to denote the null pointer",
        description: "`0 as *const T` says the same thing as `ptr::null()` less clearly.",
        message: "Use `std::ptr::null()` or `null_mut()`.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S4962")],
        check: Check::Query {
            langs: RUST,
            query: "(type_cast_expression value: (integer_literal) type: (pointer_type)) @match",
            filter: Some(Keep(zero_as_pointer)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f() -> *const u8 { 0 as *const u8 }",
            good: "fn f() -> *const u8 { std::ptr::null() }",
        }),
    },
    Rule {
        id: "rs/redundant-field-name",
        name: "Field init shorthand should be used",
        description: "`Point { x: x }` repeats the name that `Point { x }` already carries.",
        message: "Use the field init shorthand.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S3498")],
        check: Check::Query {
            langs: RUST,
            query: "(field_initializer field: (field_identifier) value: (identifier)) @match",
            filter: Some(Keep(is_redundant_field)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f(x: i32) -> P { P { x: x } }",
            good: "fn f(x: i32) -> P { P { x } }",
        }),
    },
    Rule {
        id: "rs/let-and-return",
        name: "Local variables should not be declared and then immediately returned",
        description: "`let x = e; x` names a value only to hand it back: returning `e` says the same thing.",
        message: "Return this expression directly.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[related("S1488")],
        check: Check::Query {
            langs: RUST,
            query: "(block) @match",
            filter: Some(Find(let_and_return)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f(a: i32) -> i32 { let x = a * 2; x }",
            good: "fn f(a: i32) -> i32 { a * 2 }",
        }),
    },
    Rule {
        id: "rs/match-on-bool",
        name: "Match expression conditions should not have boolean type",
        description: "A `match` with `true` and `false` arms is an `if` with extra syntax.",
        message: "Use an `if` here.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S920")],
        check: Check::Query {
            langs: RUST,
            query: "(match_expression body: (match_block)) @match",
            filter: Some(Keep(is_bool_match)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f(a: bool) -> u8 { match a { true => 1, false => 0 } }",
            good: "fn f(a: bool) -> u8 { if a { 1 } else { 0 } }",
        }),
    },
    Rule {
        id: "rs/else-if-without-else",
        name: "\"if ... else if\" constructs should end with \"else\" clauses",
        description: "An `else if` chain that ends without an `else` silently does nothing when no branch \
                      matches, which is easy to overlook.",
        message: "Add a final `else` to this chain.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S126")],
        check: Check::Query {
            langs: RUST,
            query: "(if_expression alternative: (else_clause (if_expression))) @match",
            filter: Some(Find(chain_without_else)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f(a: bool, b: bool) { if a { g(); } else if b { h(); } }",
            good: "fn f(a: bool, b: bool) { if a { g(); } else if b { h(); } else { i(); } }",
        }),
    },
];

// ---- Expressions ----

/// Whether two expressions are the same text, comments and whitespace aside.
/// Iterative: a deeply nested expression must not overflow the stack.
fn same_expression(a: Node, b: Node, src: &[u8]) -> bool {
    let mut stack = vec![(a, b)];
    while let Some((a, b)) = stack.pop() {
        if a.kind() != b.kind() || a.child_count() != b.child_count() {
            return false;
        }
        if a.child_count() == 0 {
            if text(a, src) != text(b, src) {
                return false;
            }
            continue;
        }
        let (mut ca, mut cb) = (a.walk(), b.walk());
        stack.extend(a.children(&mut ca).zip(b.children(&mut cb)));
    }
    true
}

/// Whether evaluating the expression twice differs from evaluating it once or
/// observes something: calls, macros, assignments and awaits.
fn has_side_effects(expression: Node) -> bool {
    let mut stack = vec![expression];
    while let Some(n) = stack.pop() {
        if matches!(
            n.kind(),
            "call_expression"
                | "macro_invocation"
                | "assignment_expression"
                | "compound_assignment_expr"
                | "await_expression"
                | "try_expression"
                | "closure_expression"
                | "block"
                | "unsafe_block"
        ) {
            return true;
        }
        let mut c = n.walk();
        stack.extend(n.named_children(&mut c));
    }
    false
}

/// The same expression on both sides, with nothing in it that changes between
/// the two evaluations.
fn same_pure_expression(a: Node, b: Node, src: &[u8]) -> bool {
    same_expression(a, b, src) && !has_side_effects(a)
}

fn is_self_assignment(node: Node, src: &[u8]) -> bool {
    match (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) {
        (Some(l), Some(r)) => same_pure_expression(l, r, src),
        _ => false,
    }
}

fn has_identical_operands(node: Node, src: &[u8]) -> bool {
    let Some(op) = node.child_by_field_name("operator") else {
        return false;
    };
    // Addition, multiplication and shifts of equal operands are not mistakes.
    if !matches!(
        text(op, src),
        b"=="
            | b"!="
            | b"<"
            | b"<="
            | b">"
            | b">="
            | b"&&"
            | b"||"
            | b"-"
            | b"/"
            | b"%"
            | b"^"
            | b"&"
            | b"|"
    ) {
        return false;
    }
    match (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) {
        (Some(l), Some(r)) => same_pure_expression(l, r, src),
        _ => false,
    }
}

/// The value of an integer literal: decimal, hexadecimal, octal or binary,
/// with its underscores and type suffix removed.
fn integer_value(literal: Node, src: &[u8]) -> Option<u128> {
    if literal.kind() != "integer_literal" {
        return None;
    }
    let raw: String = std::str::from_utf8(text(literal, src))
        .ok()?
        .chars()
        .filter(|c| *c != '_')
        .collect();
    let (radix, digits) = match raw.get(..2) {
        Some("0x") => (16, &raw[2..]),
        Some("0o") => (8, &raw[2..]),
        Some("0b") => (2, &raw[2..]),
        _ => (10, &raw[..]),
    };
    let end = digits
        .find(|c: char| !c.is_digit(radix))
        // A suffix such as `usize`: in hexadecimal, `u` and `i` are not digits.
        .unwrap_or(digits.len());
    u128::from_str_radix(&digits[..end], radix).ok()
}

fn is_integer(literal: Node, src: &[u8], value: u128) -> bool {
    integer_value(literal, src) == Some(value)
}

/// The arguments of a call, comments left out.
fn arguments(call: Node) -> Vec<Node> {
    let Some(args) = call.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut c = args.walk();
    args.named_children(&mut c)
        .filter(|a| !matches!(a.kind(), "line_comment" | "block_comment"))
        .collect()
}

/// The method a call names: `skip` in `it.skip(0)`.
fn method<'t>(call: Node<'t>) -> Option<Node<'t>> {
    call.child_by_field_name("function")
        .filter(|f| f.kind() == "field_expression")?
        .child_by_field_name("field")
}

/// The method's name node, when it is `name` and the call has `count`
/// arguments of which the first is the integer `zero`.
fn method_with_first_zero<'t>(
    call: Node<'t>,
    src: &[u8],
    names: &[&[u8]],
    count: usize,
) -> Option<Node<'t>> {
    let name = method(call)?;
    let args = arguments(call);
    (names.contains(&text(name, src)) && args.len() == count && is_integer(args[0], src, 0))
        .then_some(name)
}

fn skip_zero<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    method_with_first_zero(call, src, &[b"skip"], 1)
}

fn step_by_zero<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    method_with_first_zero(call, src, &[b"step_by"], 1)
}

fn resize_to_zero<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    // `Vec::resize` returns nothing: one whose result is unwrapped or tried is
    // another type's, such as `heapless::Vec`, which Clippy leaves alone.
    let result_used = call.parent().is_some_and(|p| {
        p.kind() == "try_expression"
            || (p.kind() == "field_expression"
                && p.parent().is_some_and(|g| g.kind() == "call_expression"))
    });
    if result_used {
        return None;
    }
    method_with_first_zero(call, src, &[b"resize"], 2)
}

fn splitn_limit<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let name = method(call)?;
    let args = arguments(call);
    (matches!(
        text(name, src),
        b"splitn" | b"rsplitn" | b"splitn_mut" | b"rsplitn_mut"
    ) && args.len() == 2
        && (is_integer(args[0], src, 0) || is_integer(args[0], src, 1)))
    .then_some(name)
}

fn modulo_one(node: Node, src: &[u8]) -> bool {
    let Some(right) = node.child_by_field_name("right") else {
        return false;
    };
    if is_integer(right, src, 1) {
        return true;
    }
    // `-1`
    right.kind() == "unary_expression"
        && right.named_child(0).is_some_and(|operand| {
            text(right, src).starts_with(b"-") && is_integer(operand, src, 1)
        })
}

/// A macro call named `name`, with any path in front of it.
fn is_macro(node: Node, src: &[u8], name: &[u8]) -> bool {
    node.kind() == "macro_invocation"
        && node.child_by_field_name("macro").is_some_and(|m| {
            let t = text(m, src);
            t == name || t.ends_with(&[b"::", name].concat())
        })
}

fn option_env_unwrapped<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let name = method(call)?;
    if !matches!(text(name, src), b"unwrap" | b"expect") {
        return None;
    }
    let receiver = call
        .child_by_field_name("function")?
        .child_by_field_name("value")?;
    is_macro(receiver, src, b"option_env").then_some(receiver)
}

/// A path's last two segments, `("MaybeUninit", "uninit")` for
/// `std::mem::MaybeUninit::<T>::uninit`, with generic arguments dropped.
fn path_tail(function: Node, src: &[u8]) -> Option<(String, String)> {
    let mut f = function;
    if f.kind() == "generic_function" {
        f = f.child_by_field_name("function")?;
    }
    if f.kind() != "scoped_identifier" {
        return None;
    }
    let name = text(f.child_by_field_name("name")?, src);
    let mut path = f.child_by_field_name("path")?;
    if path.kind() == "generic_type" {
        path = path.child_by_field_name("type")?;
    }
    let last = text(path, src).rsplit(|b| *b == b':').next()?;
    Some((
        String::from_utf8_lossy(last).into_owned(),
        String::from_utf8_lossy(name).into_owned(),
    ))
}

/// The generic arguments written on a path: `<u32>` in `MaybeUninit::<u32>::uninit`.
fn type_arguments<'t>(function: Node<'t>) -> Option<Node<'t>> {
    let f = if function.kind() == "generic_function" {
        return function.child_by_field_name("type_arguments");
    } else {
        function
    };
    f.child_by_field_name("path")?
        .child_by_field_name("type_arguments")
}

/// `MaybeUninit::uninit()` in any spelling.
fn is_maybe_uninit_new(call: Node, src: &[u8]) -> bool {
    call.kind() == "call_expression"
        && call
            .child_by_field_name("function")
            .and_then(|f| path_tail(f, src))
            .is_some_and(|(ty, name)| ty == "MaybeUninit" && name == "uninit")
}

/// The `let` a node is the initializer of, if it is one: its declared type.
fn declared_type<'t>(node: Node<'t>) -> Option<Node<'t>> {
    let mut n = node;
    for _ in 0..4 {
        let parent = n.parent()?;
        if parent.kind() == "let_declaration" {
            return parent.child_by_field_name("type");
        }
        n = parent;
    }
    None
}

fn uninit_assumed_init<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if text(method(call)?, src) != b"assume_init" || !arguments(call).is_empty() {
        return None;
    }
    let receiver = call
        .child_by_field_name("function")?
        .child_by_field_name("value")?;
    if !is_maybe_uninit_new(receiver, src) {
        return None;
    }
    // Clippy allows it for a type made of `MaybeUninit`s, such as the array
    // `arrayvec` fills with it, and tells them apart by type. Without types,
    // report only where the code writes the type, in the call or on the `let`
    // it initializes, and it holds no `MaybeUninit`.
    let holds_maybe_uninit = |t: &[u8]| t.windows(11).any(|w| w == b"MaybeUninit");
    let turbofish = receiver
        .child_by_field_name("function")
        .and_then(type_arguments)
        .map(|t| text(t, src));
    let annotated = declared_type(call).map(|t| text(t, src));
    let written = turbofish.or(annotated)?;
    if holds_maybe_uninit(written) {
        return None;
    }
    Some(receiver)
}

/// `mem::name`, `std::mem::name` or `core::mem::name`.
fn is_mem_function(function: Node, src: &[u8], name: &str) -> bool {
    path_tail(function, src).is_some_and(|(module, f)| module == "mem" && f == name)
}

fn replaces_with_uninit(call: Node, src: &[u8]) -> bool {
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    let args = arguments(call);
    if !is_mem_function(function, src, "replace") || args.len() != 2 {
        return false;
    }
    let value = args[1];
    if value.kind() != "call_expression" {
        return false;
    }
    let called = value.child_by_field_name("function");
    called.is_some_and(|f| {
        is_mem_function(f, src, "uninitialized") || is_mem_function(f, src, "zeroed")
    }) || (method(value).is_some_and(|m| text(m, src) == b"assume_init")
        && value
            .child_by_field_name("function")
            .and_then(|f| f.child_by_field_name("value"))
            .is_some_and(|r| is_maybe_uninit_new(r, src)))
}

fn zero_as_pointer(node: Node, src: &[u8]) -> bool {
    node.child_by_field_name("value")
        .is_some_and(|v| is_integer(v, src, 0))
}

fn is_redundant_field(node: Node, src: &[u8]) -> bool {
    match (
        node.child_by_field_name("field"),
        node.child_by_field_name("value"),
    ) {
        (Some(f), Some(v)) => text(f, src) == text(v, src),
        _ => false,
    }
}

// ---- Statements ----

/// The condition of each branch of an `if`/`else if` chain, from `head`.
fn chain_conditions(head: Node) -> Vec<Node> {
    let mut conditions = Vec::new();
    let mut branch = Some(head);
    while let Some(b) = branch {
        if let Some(c) = b.child_by_field_name("condition") {
            conditions.push(c);
        }
        branch = b
            .child_by_field_name("alternative")
            .and_then(|e| e.named_child(0))
            .filter(|n| n.kind() == "if_expression");
    }
    conditions
}

/// A chain's later condition that an earlier one already tested. Only the
/// chain's first `if` is asked, so a chain is reported once.
fn repeated_condition<'t>(head: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if head.parent().is_some_and(|p| p.kind() == "else_clause") {
        return None;
    }
    let conditions = chain_conditions(head);
    for (i, later) in conditions.iter().enumerate().skip(1) {
        if later.kind() == "let_condition" || has_side_effects(*later) {
            continue;
        }
        if conditions[..i]
            .iter()
            .any(|earlier| same_expression(*earlier, *later, src))
        {
            return Some(*later);
        }
    }
    None
}

fn chain_without_else<'t>(node: Node<'t>, _src: &[u8]) -> Option<Node<'t>> {
    // Only the chain's first `if`, and only when its last branch has no `else`.
    if node.parent().is_some_and(|p| p.kind() == "else_clause") {
        return None;
    }
    let mut last = node;
    while let Some(next) = last
        .child_by_field_name("alternative")
        .and_then(|e| e.named_child(0))
        .filter(|n| n.kind() == "if_expression")
    {
        last = next;
    }
    last.child_by_field_name("alternative")
        .is_none()
        .then_some(last)
}

/// The statements of a block, comments and attributes left out.
fn block_items(block: Node) -> Vec<Node> {
    let mut c = block.walk();
    block
        .named_children(&mut c)
        .filter(|n| !matches!(n.kind(), "line_comment" | "block_comment"))
        .collect()
}

fn let_and_return<'t>(block: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let items = block_items(block);
    let [.., declaration, tail] = items.as_slice() else {
        return None;
    };
    if tail.kind() != "identifier" || declaration.kind() != "let_declaration" {
        return None;
    }
    let pattern = declaration.child_by_field_name("pattern")?;
    let value = declaration.child_by_field_name("value")?;
    if pattern.kind() != "identifier"
        || text(pattern, src) != text(*tail, src)
        || declaration.child_by_field_name("type").is_some()
        || declaration.child_by_field_name("alternative").is_some()
    {
        return None;
    }
    // An attribute on the `let` is a sibling just before it.
    let attributed = declaration
        .prev_named_sibling()
        .is_some_and(|p| p.kind() == "attribute_item");
    // Returning a temporary that borrows from a guard changes when the guard
    // drops, which Clippy checks with types: skip what usually holds one.
    let guard = [
        &b".lock("[..],
        b".borrow(",
        b".borrow_mut(",
        b".read(",
        b".write(",
    ]
    .iter()
    .any(|m| text(value, src).windows(m.len()).any(|w| w == *m));
    (!attributed && !guard).then_some(*tail)
}

fn is_bool_match(node: Node, src: &[u8]) -> bool {
    let Some(body) = node.child_by_field_name("body") else {
        return false;
    };
    let mut c = body.walk();
    let arms: Vec<Node> = body
        .named_children(&mut c)
        .filter(|a| a.kind() == "match_arm")
        .collect();
    let [first, second] = arms.as_slice() else {
        return false;
    };
    let pattern = |arm: &Node| arm.child_by_field_name("pattern").map(|p| text(p, src));
    match (pattern(first), pattern(second)) {
        (Some(a), Some(b)) => {
            let boolean = |p: &[u8]| p == b"true" || p == b"false";
            (boolean(a) && boolean(b) && a != b)
                || (boolean(a) && b == b"_")
                || (a == b"_" && boolean(b))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::analyze;
    use crate::config::Config;
    use crate::lang::Lang;
    use crate::rules::RuleSet;
    use std::time::{Duration, Instant};

    /// The lines `rule` reports in `src`, with the off-by-default rules on.
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

    fn hit(rule: &str, body: &str) -> bool {
        !lines(rule, &format!("fn f() {{\n{body}\n}}\n")).is_empty()
    }

    #[test]
    fn self_assignment_needs_the_same_side_effect_free_place() {
        assert!(hit("rs/self-assignment", "x = x;"));
        assert!(hit("rs/self-assignment", "self.a.b = self.a.b;"));
        assert!(hit("rs/self-assignment", "v[i] = v[i];"));
        assert!(!hit("rs/self-assignment", "x = y;"));
        assert!(!hit("rs/self-assignment", "v[next()] = v[next()];"));
        assert!(!hit("rs/self-assignment", "x += x;"));
    }

    #[test]
    fn identical_operands_covers_the_operators_clippy_does() {
        for op in [
            "==", "!=", "<", "<=", ">", ">=", "&&", "||", "-", "/", "%", "^", "&", "|",
        ] {
            assert!(
                hit("rs/identical-operands", &format!("let _ = a.b {op} a.b;")),
                "{op}"
            );
        }
        for op in ["+", "*", "<<", ">>"] {
            assert!(
                !hit("rs/identical-operands", &format!("let _ = a {op} a;")),
                "{op}"
            );
        }
        assert!(!hit("rs/identical-operands", "let _ = next() == next();"));
        assert!(!hit("rs/identical-operands", "let _ = a == b;"));
        assert!(hit(
            "rs/identical-operands",
            "let _ = (a + b) * 2 == (a +  b)  *  2;"
        ));
    }

    #[test]
    fn a_repeated_condition_is_reported_once_per_chain() {
        let src = "fn f() {\n    if a {\n    } else if b {\n    } else if a {\n    } else if b {\n    }\n}\n";
        assert_eq!(lines("rs/same-condition-in-chain", src), [4]);
        assert!(!hit("rs/same-condition-in-chain", "if a {} else if b {}"));
        assert!(!hit(
            "rs/same-condition-in-chain",
            "if next() {} else if next() {}"
        ));
        assert!(!hit(
            "rs/same-condition-in-chain",
            "if let Some(x) = a {} else if let Some(x) = a {}"
        ));
        assert!(!hit("rs/same-condition-in-chain", "if a {} if a {}"));
    }

    #[test]
    fn counts_of_zero_and_one_are_read_through_suffixes_and_radixes() {
        assert!(hit("rs/skip-zero", "it.skip(0);"));
        assert!(hit("rs/skip-zero", "it.skip(0usize);"));
        assert!(hit("rs/skip-zero", "it.skip(0x0);"));
        assert!(!hit("rs/skip-zero", "it.skip(1);"));
        assert!(!hit("rs/skip-zero", "it.skip(n);"));
        assert!(hit("rs/step-by-zero", "(0..9).step_by(0);"));
        assert!(!hit("rs/step-by-zero", "(0..9).step_by(2);"));
        assert!(hit("rs/splitn-limit", "s.splitn(0, ',');"));
        assert!(hit("rs/splitn-limit", "s.rsplitn(1, ',');"));
        assert!(!hit("rs/splitn-limit", "s.splitn(2, ',');"));
        assert!(!hit("rs/splitn-limit", "s.split(',');"));
    }

    #[test]
    fn modulo_one_means_the_integers_one_and_minus_one() {
        assert!(hit("rs/modulo-one", "let _ = a % 1;"));
        assert!(hit("rs/modulo-one", "let _ = a % -1;"));
        assert!(hit("rs/modulo-one", "let _ = a % 1u32;"));
        assert!(!hit("rs/modulo-one", "let _ = a % 2;"));
        assert!(!hit("rs/modulo-one", "let _ = a % 1.0;"));
        assert!(!hit("rs/modulo-one", "let _ = 1 % a;"));
    }

    #[test]
    fn resize_to_zero_skips_other_types_whose_resize_returns_a_result() {
        assert!(hit("rs/resize-to-zero", "v.resize(0, 1);"));
        assert!(!hit("rs/resize-to-zero", "v.resize(1, 1);"));
        assert!(!hit("rs/resize-to-zero", "v.resize(0, 1).unwrap();"));
        assert!(!hit("rs/resize-to-zero", "v.resize(0, 1)?;"));
    }

    #[test]
    fn option_env_is_flagged_only_when_unwrapped() {
        assert!(hit(
            "rs/option-env-unwrap",
            "let _ = option_env!(\"A\").unwrap();"
        ));
        assert!(hit(
            "rs/option-env-unwrap",
            "let _ = option_env!(\"A\").expect(\"set\");"
        ));
        assert!(!hit(
            "rs/option-env-unwrap",
            "let _ = option_env!(\"A\").unwrap_or(\"b\");"
        ));
        assert!(!hit("rs/option-env-unwrap", "let _ = env!(\"A\");"));
    }

    #[test]
    fn uninit_is_reported_only_where_the_type_is_written_and_holds_no_maybe_uninit() {
        assert!(hit(
            "rs/uninit-assumed-init",
            "let x: u32 = unsafe { MaybeUninit::uninit().assume_init() };"
        ));
        assert!(hit(
            "rs/uninit-assumed-init",
            "let _ = unsafe { mem::MaybeUninit::<u32>::uninit().assume_init() };"
        ));
        // What `arrayvec` and `smallvec` do: an array of MaybeUninit is valid uninitialized.
        assert!(!hit(
            "rs/uninit-assumed-init",
            "let x: [MaybeUninit<u8>; 4] = unsafe { MaybeUninit::uninit().assume_init() };"
        ));
        assert!(!hit(
            "rs/uninit-assumed-init",
            "let _ = unsafe { MaybeUninit::<[MaybeUninit<u8>; 4]>::uninit().assume_init() };"
        ));
        // The type isn't written: Clippy would know it, this cannot.
        assert!(!hit(
            "rs/uninit-assumed-init",
            "let _ = unsafe { MaybeUninit::uninit().assume_init() };"
        ));
    }

    #[test]
    fn replacing_with_uninitialized_or_zeroed_needs_the_mem_path() {
        assert!(hit(
            "rs/replace-with-uninit",
            "mem::replace(x, mem::uninitialized());"
        ));
        assert!(hit(
            "rs/replace-with-uninit",
            "std::mem::replace(x, std::mem::zeroed());"
        ));
        assert!(hit(
            "rs/replace-with-uninit",
            "mem::replace(x, MaybeUninit::uninit().assume_init());"
        ));
        assert!(!hit(
            "rs/replace-with-uninit",
            "mem::replace(x, Default::default());"
        ));
        assert!(!hit(
            "rs/replace-with-uninit",
            "other::replace(x, mem::zeroed());"
        ));
    }

    #[test]
    fn only_a_literal_zero_cast_to_a_pointer_is_a_null_pointer() {
        assert!(hit("rs/null-pointer-from-zero", "let _ = 0 as *const u8;"));
        assert!(hit(
            "rs/null-pointer-from-zero",
            "let _ = 0usize as *mut u8;"
        ));
        assert!(!hit("rs/null-pointer-from-zero", "let _ = 4 as *const u8;"));
        assert!(!hit("rs/null-pointer-from-zero", "let _ = 0 as usize;"));
    }

    #[test]
    fn a_field_initializer_is_redundant_when_it_repeats_its_name() {
        assert!(hit("rs/redundant-field-name", "let _ = P { x: x, y };"));
        assert!(!hit("rs/redundant-field-name", "let _ = P { x: y, y: x };"));
        assert!(!hit("rs/redundant-field-name", "let _ = P { x: x + 1 };"));
        assert!(!hit("rs/redundant-field-name", "let _ = P { x };"));
    }

    #[test]
    fn let_and_return_needs_a_plain_binding_returned_straight_after() {
        assert!(hit("rs/let-and-return", "let x = a * 2;\nx"));
        assert!(hit("rs/let-and-return", "let mut x = a;\nx"));
        assert!(!hit("rs/let-and-return", "let x: u8 = a;\nx"));
        assert!(!hit("rs/let-and-return", "let x = a;\nlog(x);\nx"));
        assert!(!hit("rs/let-and-return", "let x = a;\nx;"));
        assert!(!hit(
            "rs/let-and-return",
            "let x = m.lock().unwrap().len();\nx"
        ));
        assert!(!hit("rs/let-and-return", "let y = a;\nx"));
        assert!(!hit("rs/let-and-return", "#[allow(unused)]\nlet x = a;\nx"));
    }

    #[test]
    fn match_on_bool_is_two_arms_of_true_and_false() {
        assert!(hit(
            "rs/match-on-bool",
            "match a { true => 1, false => 0 };"
        ));
        assert!(hit(
            "rs/match-on-bool",
            "match a { false => 0, true => 1 };"
        ));
        assert!(hit("rs/match-on-bool", "match a { true => 1, _ => 0 };"));
        assert!(!hit(
            "rs/match-on-bool",
            "match a { true => 1, false => 0, _ => 2 };"
        ));
        assert!(!hit(
            "rs/match-on-bool",
            "match a { true if b => 1, _ => 0 };"
        ));
        assert!(!hit("rs/match-on-bool", "match a { 1 => 1, _ => 0 };"));
    }

    #[test]
    fn a_chain_ends_with_else_and_is_reported_once_at_its_last_branch() {
        let src = "fn f() {\n    if a {\n    } else if b {\n    } else if c {\n    }\n}\n";
        assert_eq!(lines("rs/else-if-without-else", src), [4]);
        assert!(!hit(
            "rs/else-if-without-else",
            "if a {} else if b {} else {}"
        ));
        assert!(!hit("rs/else-if-without-else", "if a {}"));
        assert!(!hit("rs/else-if-without-else", "if a {} else {}"));
    }

    #[test]
    fn clippy_allow_attributes_silence_the_rule() {
        let src =
            "#[allow(clippy::self_assignment)]\nfn f() {\n    x = x;\n}\nfn g() {\n    x = x;\n}\n";
        assert_eq!(lines("rs/self-assignment", src), [6]);
        let src =
            "fn f() {\n    #[allow(clippy::eq_op)]\n    let _ = a == a;\n    let _ = b == b;\n}\n";
        assert_eq!(lines("rs/identical-operands", src), [4]);
        let src = "#![allow(clippy::all)]\nfn f() {\n    x = x;\n}\n";
        assert!(lines("rs/self-assignment", src).is_empty());
        // `clippy::all` leaves restriction lints on.
        let src = "#![allow(clippy::all)]\nfn f() {\n    if a {} else if b {}\n}\n";
        assert_eq!(lines("rs/else-if-without-else", src).len(), 1);
        // An unrelated allow silences nothing.
        let src = "#[allow(unused)]\nfn f() {\n    x = x;\n}\n";
        assert_eq!(lines("rs/self-assignment", src), [3]);
    }
}
