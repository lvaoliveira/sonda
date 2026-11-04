//! Rust rules, batch 2 (ADR-0007, ADR-0026): more of SonarQube's Clippy-based
//! set that one file's syntax can answer. Like `rs.rs`, each follows its
//! lint, and a rule that needs a type reports only what the text proves.

use super::java_security::text;
use super::prelude::*;
use super::rs::{
    arguments, block_items, has_side_effects, integer_value, is_integer, is_macro, method,
    same_pure_expression,
};

/// Rules that are off unless `rules.enabled` lists them (see
/// `catalog::OFF_BY_DEFAULT`). SonarQube's default profile leaves out
/// `unreadable_literal` (pedantic) and `print_stdout` (restriction).
pub(super) static OFF_BY_DEFAULT: &[&str] = &["rs/unreadable-literal", "rs/print-stdout"];

const IMPL_OF_TRAIT: &str = "(impl_item trait: (_) type: (_)) @match";

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "rs/wildcard-import",
        name: "Wildcard imports should not be used",
        description: "`use path::*` hides where a name comes from and lets a new item upstream shadow or \
                      clash with one already in use.",
        message: "Import the items you use instead of a wildcard.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[related("S2208")],
        check: Check::Query {
            langs: RUST,
            query: "(use_declaration) @match",
            filter: Some(Keep(has_wildcard_import)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "use std::collections::*;\nfn f() {}",
            good: "use std::collections::HashMap;\nfn f() {}",
        }),
    },
    Rule {
        id: "rs/unnecessary-semicolon",
        name: "Empty statements should be removed",
        description: "A `;` after a block-like `match` or `if` that evaluates to nothing is noise.",
        message: "Remove this unnecessary semicolon.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[related("S1116")],
        check: Check::Query {
            langs: RUST,
            query: "(empty_statement) @match",
            filter: Some(Keep(is_unnecessary_semicolon)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f(a: bool) { if a { g(); }; }",
            good: "fn f(a: bool) { if a { g(); } }",
        }),
    },
    Rule {
        id: "rs/invisible-characters",
        name: "Invisible Unicode characters should not be used",
        description: "A zero-width space, soft hyphen or word joiner in a literal looks like nothing and \
                      compares unequal to the text it seems to be.",
        message: "Replace this invisible character with an escape such as `\\u{200B}`.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2479")],
        check: Check::Query {
            langs: RUST,
            query: "[(string_literal) (raw_string_literal) (char_literal)] @match",
            filter: Some(Keep(has_invisible_character)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f() -> &'static str { \"a\u{200B}b\" }",
            good: "fn f() -> &'static str { \"a\\u{200B}b\" }",
        }),
    },
    Rule {
        id: "rs/approximate-constant",
        name: "Mathematical constants should not be hardcoded",
        description: "`3.14` is a poor `PI`: the standard library has the constants to the precision of the type.",
        message: "Use the constant from `std::f64::consts` instead of this approximation.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6164")],
        check: Check::Query {
            langs: RUST,
            query: "(float_literal) @match",
            filter: Some(Keep(approximates_constant)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn area(r: f64) -> f64 { 3.14159 * r * r }",
            good: "fn area(r: f64) -> f64 { std::f64::consts::PI * r * r }",
        }),
    },
    Rule {
        id: "rs/never-loop",
        name: "Loops with at most one iteration should be refactored",
        description: "A loop whose body always leaves on its first pass is an `if` in disguise, or a bug in \
                      what was meant to repeat.",
        message: "This loop never runs more than once.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[related("S1751")],
        check: Check::Query {
            langs: RUST,
            query: "[(loop_expression) (while_expression) (for_expression)] @match",
            filter: Some(Keep(never_loops)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f(v: &[u8]) -> u8 { for x in v { return *x; } 0 }",
            good: "fn f(v: &[u8]) -> u8 { v.first().copied().unwrap_or(0) }",
        }),
    },
    Rule {
        id: "rs/no-effect",
        name: "Non-empty statements should change control flow or have at least one side-effect",
        description: "A statement that only reads values, such as `x;` or `a + b;`, does nothing.",
        message: "This statement has no effect.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[related("S905")],
        check: Check::Query {
            langs: RUST,
            query: "(expression_statement) @match",
            filter: Some(Keep(has_no_effect_statement)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f(a: i32, b: i32) { a + b; }",
            good: "fn f(a: i32, b: i32) -> i32 { a + b }",
        }),
    },
    Rule {
        id: "rs/vec-init-then-push",
        name: "Inline vector literals should be preferred to chains of insertions",
        description: "A `Vec::new()` followed by `push`es of known items is a `vec![..]` written the long way.",
        message: "Use `vec![..]` instead of pushing the items one by one.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S7089")],
        check: Check::Query {
            langs: RUST,
            query: "(let_declaration) @match",
            filter: Some(Keep(vec_then_push)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f() -> Vec<u8> { let mut v = Vec::new(); v.push(1); v.push(2); v }",
            good: "fn f() -> Vec<u8> { vec![1, 2] }",
        }),
    },
    Rule {
        id: "rs/misnamed-getter",
        name: "Getters should access the expected fields",
        description: "A getter named after one field that returns another is a copy-paste slip the compiler \
                      cannot see when the types match.",
        message: "This getter is named after a field it doesn't return.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[related("S4275")],
        check: Check::Query {
            langs: RUST,
            query: "(function_item) @match",
            filter: Some(Find(misnamed_getter)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "struct P { x: u8, y: u8 }\nimpl P { fn x(&self) -> &u8 { &self.y } }",
            good: "struct P { x: u8, y: u8 }\nimpl P { fn x(&self) -> &u8 { &self.x } }",
        }),
    },
    Rule {
        id: "rs/almost-swapped",
        name: "Variables should be swapped using `std::mem::swap`",
        description: "`a = b; b = a;` leaves both holding `b`: the swap it looks like loses a value.",
        message: "Use `std::mem::swap(&mut a, &mut b)`: this leaves both with the same value.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7437")],
        check: Check::Query {
            langs: RUST,
            query: "(block) @match",
            filter: Some(Find(almost_swapped)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f(mut a: u8, mut b: u8) { a = b; b = a; }",
            good: "fn f(mut a: u8, mut b: u8) { std::mem::swap(&mut a, &mut b); }",
        }),
    },
    Rule {
        id: "rs/iter-next-loop",
        name: "The return value of `next` should not be looped over",
        description: "`for x in it.next()` loops over the one `Option` the call returns, not over the iterator.",
        message: "Loop over the iterator itself, or use `if let Some(x) = it.next()`.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[related("S7455")],
        check: Check::Query {
            langs: RUST,
            query: "(for_expression value: (call_expression function: (field_expression field: (field_identifier)) \
                     arguments: (arguments))) @match",
            filter: Some(Find(loops_over_next)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f(mut it: std::vec::IntoIter<u8>) { for x in it.next() { g(x); } }",
            good: "fn f(it: std::vec::IntoIter<u8>) { for x in it { g(x); } }",
        }),
    },
    Rule {
        id: "rs/inline-without-body",
        name: "The `#[inline]` attribute should not be used on trait methods without implementation",
        description: "A method declared without a body has nothing to inline: the attribute does nothing there.",
        message: "Remove `#[inline]`: this method has no body.",
        category: Bug,
        severity: Major,
        effort_minutes: 1,
        sonar: &[exact("S7449")],
        check: Check::Query {
            langs: RUST,
            query: "(function_signature_item) @match",
            filter: Some(Keep(is_inline_trait_signature)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "trait T { #[inline] fn m(&self); }",
            good: "trait T { fn m(&self); }",
        }),
    },
    Rule {
        id: "rs/mistyped-literal-suffix",
        name: "Numeric literal suffixes should not be mistyped",
        description: "`2_32` is the number 232, not the `i32` `2`: the underscore and width belong the other way round.",
        message: "Did you mean this literal's type suffix, such as `_i32`?",
        category: Bug,
        severity: Major,
        effort_minutes: 1,
        sonar: &[related("S7454")],
        check: Check::Query {
            langs: RUST,
            query: "[(integer_literal) (float_literal)] @match",
            filter: Some(Keep(is_mistyped_suffix)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f() -> i32 { 2_32 }",
            good: "fn f() -> i32 { 2_i32 }",
        }),
    },
    Rule {
        id: "rs/reversed-empty-range",
        name: "Reversed ranges and slices should not be empty",
        description: "`5..3` is empty: a loop over it never runs, and slicing with it panics.",
        message: "This range starts after it ends, so it is empty.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[related("S7432")],
        check: Check::Query {
            langs: RUST,
            query: "(range_expression) @match",
            filter: Some(Keep(is_reversed_range)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f() { for _ in 5..3 {} }",
            good: "fn f() { for _ in (3..5).rev() {} }",
        }),
    },
    Rule {
        id: "rs/erasing-op",
        name: "Erasing mathematical operations should not be performed",
        description: "`x * 0`, `x & 0` and `0 / x` are always 0, whatever `x` is.",
        message: "This operation always evaluates to 0.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[related("S2185")],
        check: Check::Query {
            langs: RUST,
            query: "(binary_expression left: (_) right: (_)) @match",
            filter: Some(Keep(is_erasing)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f(x: i32) -> i32 { x * 0 }",
            good: "fn f(x: i32) -> i32 { x * 2 }",
        }),
    },
    Rule {
        id: "rs/unreadable-literal",
        name: "Underscores should be used to make large numbers readable",
        description: "`1000000` takes a second look that `1_000_000` doesn't.",
        message: "Group the digits of this literal with underscores.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[related("S2148")],
        check: Check::Query {
            langs: RUST,
            query: "(integer_literal) @match",
            filter: Some(Keep(is_unreadable_literal)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f() -> u32 { 1000000 }",
            good: "fn f() -> u32 { 1_000_000 }",
        }),
    },
    Rule {
        id: "rs/print-stdout",
        name: "Standard outputs should not be used directly to log anything",
        description: "`print!` and `println!` write to a stream a library's caller doesn't choose: use a logger.",
        message: "Use a logger instead of printing to standard output.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S106")],
        check: Check::Query {
            langs: RUST,
            query: "(macro_invocation) @match",
            filter: Some(Keep(prints_to_stdout)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f() { println!(\"hi\"); }",
            good: "fn f() { log::info!(\"hi\"); }",
        }),
    },
    Rule {
        id: "rs/derive-ord-with-manual-partial-ord",
        name: "Manual PartialOrd implementation should be avoided when Ord is derived",
        description: "A derived `Ord` and a hand-written `PartialOrd` can disagree, and sorting and comparing \
                      then give different orders.",
        message: "Derive both, or implement both: `Ord` and `PartialOrd` must agree.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[related("S7417")],
        check: Check::Query {
            langs: RUST,
            query: IMPL_OF_TRAIT,
            filter: Some(Keep(ord_pair_split)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "#[derive(PartialEq, Eq, Ord)]\nstruct S(u8);\nimpl PartialOrd for S { fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> { None } }",
            good: "#[derive(PartialEq, Eq, Ord, PartialOrd)]\nstruct S(u8);",
        }),
    },
    Rule {
        id: "rs/derived-hash-with-manual-eq",
        name: "Avoid manual PartialEq implementation with a derived Hash",
        description: "Equal values must hash equally: a derived `Hash` beside a hand-written `PartialEq` (or the \
                      reverse) breaks that, and hash maps lose entries.",
        message: "Derive both, or implement both: `Hash` and `PartialEq` must agree.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[related("S7424")],
        check: Check::Query {
            langs: RUST,
            query: IMPL_OF_TRAIT,
            filter: Some(Keep(hash_eq_pair_split)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "#[derive(Hash)]\nstruct S(u8);\nimpl PartialEq for S { fn eq(&self, o: &Self) -> bool { true } }\nimpl Eq for S {}",
            good: "#[derive(Hash, PartialEq, Eq)]\nstruct S(u8);",
        }),
    },
    Rule {
        id: "rs/uninit-vec",
        name: "`set_len` should not be called on uninitialized vectors",
        description: "A vector's elements are uninitialized until written: `set_len` right after `with_capacity` \
                      exposes memory no one has written.",
        message: "Write the elements before `set_len`, or use `resize` or `MaybeUninit`.",
        category: Bug,
        severity: Major,
        effort_minutes: 15,
        sonar: &[related("S7459")],
        check: Check::Query {
            langs: RUST,
            query: "(call_expression function: (field_expression field: (field_identifier)) arguments: (arguments)) @match",
            filter: Some(Find(set_len_on_fresh_vec)),
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "fn f(n: usize) -> Vec<u8> { let mut v = Vec::with_capacity(n); unsafe { v.set_len(n); } v }",
            good: "fn f(n: usize) -> Vec<u8> { vec![0; n] }",
        }),
    },
];

// ---- Items ----

/// Whether `node` is inside a test module or function: a module named `test`
/// or `tests`, or anything written under `#[cfg(test)]` or `#[test]`.
fn in_test_code(node: Node, src: &[u8]) -> bool {
    let mut n = Some(node);
    while let Some(cur) = n {
        if matches!(cur.kind(), "mod_item" | "function_item") {
            if cur.kind() == "mod_item"
                && cur
                    .child_by_field_name("name")
                    .is_some_and(|m| matches!(text(m, src), b"test" | b"tests"))
            {
                return true;
            }
            let mut attr = cur.prev_named_sibling();
            while let Some(a) = attr.filter(|a| a.kind() == "attribute_item") {
                let t = text(a, src);
                if t.windows(9).any(|w| w == b"cfg(test)") || t == b"#[test]" {
                    return true;
                }
                attr = a.prev_named_sibling();
            }
        }
        n = cur.parent();
    }
    false
}

fn has_wildcard_import(declaration: Node, src: &[u8]) -> bool {
    // A re-export (`pub use a::*`) is the module's interface, not a convenience.
    if declaration
        .child(0)
        .is_some_and(|c| c.kind() == "visibility_modifier")
    {
        return false;
    }
    let mut stack = vec![declaration];
    while let Some(n) = stack.pop() {
        if n.kind() == "use_wildcard" {
            let path = text(n, src);
            // A prelude exists to be globbed; `super::*` is how a test module
            // reaches the code it tests.
            let prelude = text(declaration, src).windows(7).any(|w| w == b"prelude");
            let test_glob = path == b"super::*" && in_test_code(declaration, src);
            if !prelude && !test_glob {
                return true;
            }
        }
        let mut c = n.walk();
        stack.extend(n.named_children(&mut c));
    }
    false
}

fn is_inline_trait_signature(signature: Node, src: &[u8]) -> bool {
    if !signature
        .parent()
        .and_then(|p| p.parent())
        .is_some_and(|t| t.kind() == "trait_item")
    {
        return false;
    }
    let mut previous = signature.prev_named_sibling();
    while let Some(p) = previous {
        match p.kind() {
            "attribute_item" if text(p, src).starts_with(b"#[inline") => return true,
            "attribute_item" | "line_comment" | "block_comment" => {
                previous = p.prev_named_sibling()
            }
            _ => return false,
        }
    }
    false
}

/// The traits a type item derives, from the attributes written before it.
fn derives(item: Node, src: &[u8]) -> Vec<String> {
    let mut found = Vec::new();
    let mut attr = item.prev_named_sibling();
    while let Some(a) = attr.filter(|a| matches!(a.kind(), "attribute_item" | "line_comment")) {
        if a.kind() == "attribute_item" {
            let t = String::from_utf8_lossy(text(a, src)).into_owned();
            if let Some(args) = t.split_once("derive(").map(|(_, rest)| rest) {
                let list = args.split(')').next().unwrap_or_default();
                found.extend(
                    list.split(',')
                        .map(|name| name.rsplit("::").next().unwrap_or("").trim().to_string()),
                );
            }
        }
        attr = a.prev_named_sibling();
    }
    found
}

/// The name a type is declared or implemented under: `Foo` for `Foo<T>`.
fn type_name<'s>(ty: Node, src: &'s [u8]) -> &'s [u8] {
    let ty = if ty.kind() == "generic_type" {
        ty.child_by_field_name("type").unwrap_or(ty)
    } else {
        ty
    };
    text(ty, src)
}

/// The struct or enum `name` declared beside `implementation`.
fn declaration_beside<'t>(implementation: Node<'t>, name: &[u8], src: &[u8]) -> Option<Node<'t>> {
    let parent = implementation.parent()?;
    let mut c = parent.walk();
    parent.named_children(&mut c).find(|n| {
        matches!(n.kind(), "struct_item" | "enum_item")
            && n.child_by_field_name("name")
                .is_some_and(|d| text(d, src) == name)
    })
}

/// For `impl Trait for Type`: the trait's last segment and what `Type`
/// derives, when `Type` is declared in the same file.
fn implemented_and_derived(implementation: Node, src: &[u8]) -> Option<(String, Vec<String>)> {
    let trait_node = implementation.child_by_field_name("trait")?;
    let ty = implementation.child_by_field_name("type")?;
    let name = String::from_utf8_lossy(text(trait_node, src))
        .rsplit("::")
        .next()?
        .split('<')
        .next()?
        .trim()
        .to_string();
    let declaration = declaration_beside(implementation, type_name(ty, src), src)?;
    Some((name, derives(declaration, src)))
}

fn ord_pair_split(implementation: Node, src: &[u8]) -> bool {
    implemented_and_derived(implementation, src).is_some_and(|(implemented, derived)| {
        let has = |t: &str| derived.iter().any(|d| d == t);
        (implemented == "PartialOrd" && has("Ord") && !has("PartialOrd"))
            || (implemented == "Ord" && has("PartialOrd") && !has("Ord"))
    })
}

fn hash_eq_pair_split(implementation: Node, src: &[u8]) -> bool {
    implemented_and_derived(implementation, src).is_some_and(|(implemented, derived)| {
        let has = |t: &str| derived.iter().any(|d| d == t);
        (implemented == "PartialEq" && has("Hash") && !has("PartialEq"))
            || (implemented == "Hash" && has("PartialEq") && !has("Hash"))
    })
}

/// The field names of a struct declared in the file as `name`.
fn field_names<'s>(root: Node, name: &[u8], src: &'s [u8]) -> Option<Vec<&'s [u8]>> {
    let mut c = root.walk();
    let strukt = root.named_children(&mut c).find(|n| {
        n.kind() == "struct_item"
            && n.child_by_field_name("name")
                .is_some_and(|d| text(d, src) == name)
    })?;
    let body = strukt.child_by_field_name("body")?;
    let mut cc = body.walk();
    Some(
        body.named_children(&mut cc)
            .filter(|f| f.kind() == "field_declaration")
            .filter_map(|f| f.child_by_field_name("name"))
            .map(|n| text(n, src))
            .collect(),
    )
}

fn misnamed_getter<'t>(function: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let implementation = function.parent()?.parent()?;
    if implementation.kind() != "impl_item" || implementation.child_by_field_name("trait").is_some()
    {
        return None;
    }
    let name_node = function.child_by_field_name("name")?;
    let name = text(name_node, src);
    let params = function.child_by_field_name("parameters")?;
    let mut c = params.walk();
    let params: Vec<Node> = params.named_children(&mut c).collect();
    let [receiver] = params.as_slice() else {
        return None;
    };
    let mutable = match text(*receiver, src) {
        b"&self" => false,
        b"&mut self" => true,
        _ => return None,
    };
    // `x_mut` gets `x`'s field.
    let wanted = if mutable {
        name.strip_suffix(b"_mut")?
    } else {
        name
    };
    // The body is the one expression `self.f`, `&self.f` or `&mut self.f`.
    let body = function.child_by_field_name("body")?;
    let items = block_items(body);
    let [value] = items.as_slice() else {
        return None;
    };
    let mut field = *value;
    if field.kind() == "reference_expression" {
        field = field.child_by_field_name("value")?;
    }
    if field.kind() != "field_expression"
        || field.child_by_field_name("value").map(|v| text(v, src)) != Some(b"self")
    {
        return None;
    }
    let returned = text(field.child_by_field_name("field")?, src);
    let ty = type_name(implementation.child_by_field_name("type")?, src);
    let mut root = implementation;
    while let Some(p) = root.parent() {
        root = p;
    }
    let fields = field_names(root, ty, src)?;
    (returned != wanted && fields.contains(&wanted)).then_some(name_node)
}

// ---- Literals and expressions ----

fn has_invisible_character(literal: Node, src: &[u8]) -> bool {
    let s = std::str::from_utf8(text(literal, src)).unwrap_or("");
    // Zero-width space, soft hyphen and word joiner, written as themselves.
    s.chars()
        .any(|c| matches!(c, '\u{200B}' | '\u{AD}' | '\u{2060}'))
}

fn approximates_constant(literal: Node, src: &[u8]) -> bool {
    use std::f64::consts::*;
    // Clippy's table: each constant and the fewest characters of it to count.
    const KNOWN: &[(f64, usize)] = &[
        (E, 4),
        (FRAC_1_PI, 4),
        (FRAC_1_SQRT_2, 5),
        (FRAC_2_PI, 5),
        (FRAC_2_SQRT_PI, 5),
        (FRAC_PI_2, 5),
        (FRAC_PI_3, 5),
        (FRAC_PI_4, 5),
        (FRAC_PI_6, 5),
        (FRAC_PI_8, 5),
        (LN_2, 5),
        (LN_10, 5),
        (LOG10_E, 5),
        (LOG2_E, 5),
        (LOG2_10, 5),
        (LOG10_2, 5),
        (PI, 3),
        (SQRT_2, 5),
        (TAU, 3),
    ];
    let raw: String = String::from_utf8_lossy(text(literal, src))
        .chars()
        .filter(|c| *c != '_')
        .collect();
    let value = raw
        .strip_suffix("f64")
        .or_else(|| raw.strip_suffix("f32"))
        .unwrap_or(&raw);
    // Only plain decimals: `1e3` and a bare `3` are not approximations.
    if !value.contains('.') || value.contains(['e', 'E']) {
        return false;
    }
    KNOWN.iter().any(|&(constant, min_len)| {
        value.len() > min_len
            && (constant.to_string().starts_with(value)
                || format!("{constant:.*}", value.len() - 2) == value)
    })
}

/// Whether a block ends in an expression that gives it a value, rather than
/// in a statement.
fn block_has_value(block: Node) -> bool {
    block_items(block).last().is_some_and(|last| {
        !matches!(
            last.kind(),
            "expression_statement" | "let_declaration" | "empty_statement" | "attribute_item"
        ) && !last.kind().ends_with("_item")
    })
}

fn is_unit_block_like(expression: Node) -> bool {
    match expression.kind() {
        "if_expression" => {
            let mut blocks = Vec::new();
            let mut branch = Some(expression);
            while let Some(b) = branch {
                match b.child_by_field_name("consequence") {
                    Some(c) => blocks.push(c),
                    None => return false,
                }
                match b
                    .child_by_field_name("alternative")
                    .and_then(|a| a.named_child(0))
                {
                    Some(n) if n.kind() == "if_expression" => branch = Some(n),
                    Some(n) => {
                        blocks.push(n);
                        branch = None;
                    }
                    None => branch = None,
                }
            }
            blocks
                .iter()
                .all(|b| b.kind() == "block" && !block_has_value(*b))
        }
        "match_expression" => {
            let Some(body) = expression.child_by_field_name("body") else {
                return false;
            };
            let mut c = body.walk();
            let arms: Vec<Node> = body
                .named_children(&mut c)
                .filter(|a| a.kind() == "match_arm")
                .collect();
            !arms.is_empty()
                && arms.iter().all(|arm| {
                    arm.child_by_field_name("value")
                        .is_some_and(|v| v.kind() == "block" && !block_has_value(v))
                })
        }
        _ => false,
    }
}

fn is_unnecessary_semicolon(semicolon: Node, _src: &[u8]) -> bool {
    semicolon
        .prev_named_sibling()
        .filter(|p| p.kind() == "expression_statement")
        .and_then(|p| p.named_child(0))
        .is_some_and(is_unit_block_like)
}

/// The kinds of expression whose evaluation does nothing but compute a value.
fn is_effect_free(expression: Node) -> bool {
    let mut stack = vec![expression];
    while let Some(n) = stack.pop() {
        match n.kind() {
            "identifier" | "field_identifier" | "scoped_identifier" | "boolean_literal"
            | "integer_literal" | "float_literal" | "string_literal" | "char_literal" | "self" => {}
            "binary_expression"
            | "unary_expression"
            | "reference_expression"
            | "type_cast_expression"
            | "field_expression"
            | "parenthesized_expression"
            | "tuple_expression"
            | "array_expression" => {
                let mut c = n.walk();
                stack.extend(n.named_children(&mut c));
            }
            _ => return false,
        }
    }
    true
}

fn has_no_effect_statement(statement: Node, _src: &[u8]) -> bool {
    statement.named_child_count() == 1
        && statement.named_child(0).is_some_and(|e| {
            // `()` and a lone `_` are idioms, not forgotten work.
            e.kind() != "tuple_expression" || e.named_child_count() > 0
        })
        && statement.named_child(0).is_some_and(is_effect_free)
}

// ---- Loops and statements ----

/// Whether any node under `root` has one of `kinds`, without entering a
/// closure, whose `break` and `continue` are its own.
fn contains_kind(root: Node, kinds: &[&str]) -> bool {
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        if kinds.contains(&n.kind()) {
            return true;
        }
        if n.kind() == "closure_expression" {
            continue;
        }
        let mut c = n.walk();
        stack.extend(n.named_children(&mut c));
    }
    false
}

fn never_loops(node: Node, _src: &[u8]) -> bool {
    let Some(body) = node.child_by_field_name("body") else {
        return false;
    };
    // Where the body leaves unconditionally: directly in its statements.
    let leaves = block_items(body).iter().any(|item| {
        let e = if item.kind() == "expression_statement" {
            item.named_child(0)
        } else {
            Some(*item)
        };
        e.is_some_and(|e| match e.kind() {
            "return_expression" => true,
            // A label sends it to some other loop.
            "break_expression" => {
                e.named_child_count() == 0 || e.named_child(0).is_some_and(|c| c.kind() != "label")
            }
            _ => false,
        })
    });
    leaves && !contains_kind(body, &["continue_expression"])
}

fn vec_then_push(declaration: Node, src: &[u8]) -> bool {
    let (Some(pattern), Some(value)) = (
        declaration.child_by_field_name("pattern"),
        declaration.child_by_field_name("value"),
    ) else {
        return false;
    };
    if pattern.kind() != "identifier" {
        return false;
    }
    let creates_vec = match value.kind() {
        "call_expression" => value
            .child_by_field_name("function")
            .filter(|f| f.kind() == "scoped_identifier")
            .is_some_and(|f| {
                f.child_by_field_name("path").map(|p| text(p, src)) == Some(b"Vec")
                    && matches!(
                        f.child_by_field_name("name").map(|n| text(n, src)),
                        Some(b"new" | b"with_capacity")
                    )
            }),
        "macro_invocation" => {
            is_macro(value, src, b"vec")
                && value
                    .named_child(1)
                    .is_some_and(|t| t.named_child_count() == 0)
        }
        _ => false,
    };
    if !creates_vec {
        return false;
    }
    let name = text(pattern, src);
    // The next statement pushes onto it a value that doesn't use it.
    declaration
        .next_named_sibling()
        .filter(|s| s.kind() == "expression_statement")
        .and_then(|s| s.named_child(0))
        .is_some_and(|call| {
            call.kind() == "call_expression"
                && method(call).is_some_and(|m| text(m, src) == b"push")
                && call
                    .child_by_field_name("function")
                    .and_then(|f| f.child_by_field_name("value"))
                    .is_some_and(|r| text(r, src) == name)
                && arguments(call).iter().all(|a| !mentions(*a, name, src))
        })
}

/// Whether the identifier `name` appears under `root`.
fn mentions(root: Node, name: &[u8], src: &[u8]) -> bool {
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        if n.kind() == "identifier" && text(n, src) == name {
            return true;
        }
        let mut c = n.walk();
        stack.extend(n.named_children(&mut c));
    }
    false
}

fn almost_swapped<'t>(block: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let assignment = |s: Node<'t>| -> Option<(Node<'t>, Node<'t>)> {
        let e = (s.kind() == "expression_statement").then(|| s.named_child(0))??;
        (e.kind() == "assignment_expression").then_some(())?;
        Some((
            e.child_by_field_name("left")?,
            e.child_by_field_name("right")?,
        ))
    };
    let items = block_items(block);
    items.windows(2).find_map(|pair| {
        let (a1, b1) = assignment(pair[0])?;
        let (a2, b2) = assignment(pair[1])?;
        // `a = b; b = a;`: the second undoes the first, with the same two places.
        (same_pure_expression(a1, b2, src)
            && same_pure_expression(b1, a2, src)
            && !same_pure_expression(a1, b1, src))
        .then_some(pair[0])
    })
}

fn loops_over_next<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let call = node.child_by_field_name("value")?;
    (method(call).is_some_and(|m| text(m, src) == b"next") && arguments(call).is_empty())
        .then_some(call)
}

fn is_mistyped_suffix(literal: Node, src: &[u8]) -> bool {
    let t = std::str::from_utf8(text(literal, src)).unwrap_or("");
    if t.starts_with("0x") || t.starts_with("0o") || t.starts_with("0b") {
        return false;
    }
    let Some((head, tail)) = t.rsplit_once('_') else {
        return false;
    };
    let widths: &[&str] = if literal.kind() == "float_literal" {
        &["32", "64"]
    } else {
        &["8", "16", "32", "64"]
    };
    !head.is_empty()
        && head
            .chars()
            .all(|c| c.is_ascii_digit() || c == '_' || c == '.')
        && widths.contains(&tail)
}

fn is_reversed_range(range: Node, src: &[u8]) -> bool {
    // Only where it is iterated or sliced: `for _ in 5..3`, `v[5..3]`.
    let used = range.parent().is_some_and(|p| {
        p.kind() == "index_expression"
            || (p.kind() == "for_expression"
                && p.child_by_field_name("value").map(|v| v.id()) == Some(range.id()))
    });
    let mut c = range.walk();
    let bounds: Vec<Node> = range.named_children(&mut c).collect();
    let [from, to] = bounds.as_slice() else {
        return false;
    };
    let inclusive = text(range, src).windows(3).any(|w| w == b"..=");
    match (integer_value(*from, src), integer_value(*to, src)) {
        (Some(a), Some(b)) => used && (if inclusive { a > b } else { a > b }),
        _ => false,
    }
}

fn is_erasing(node: Node, src: &[u8]) -> bool {
    let (Some(l), Some(r), Some(op)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
        node.child_by_field_name("operator"),
    ) else {
        return false;
    };
    let zero_l = is_integer(l, src, 0);
    let zero_r = is_integer(r, src, 0);
    match text(op, src) {
        // Either side erases the other.
        b"*" | b"&" => {
            (zero_l && !zero_r && !has_side_effects(r))
                || (zero_r && !zero_l && !has_side_effects(l))
        }
        // Only a zero numerator does.
        b"/" => zero_l && !zero_r && !has_side_effects(r),
        _ => false,
    }
}

fn is_unreadable_literal(literal: Node, src: &[u8]) -> bool {
    let t = std::str::from_utf8(text(literal, src)).unwrap_or("");
    if t.contains('_') {
        return false;
    }
    let digits = t
        .trim_end_matches(|c: char| c.is_ascii_alphabetic() && !t.starts_with("0x"))
        .trim_start_matches("0x");
    let hex = t.starts_with("0x");
    let count = digits
        .chars()
        .filter(|c| c.is_ascii_hexdigit() || c.is_ascii_digit())
        .count();
    if t.starts_with("0o") || t.starts_with("0b") {
        return false;
    }
    if hex { count >= 5 } else { count >= 5 }
}

fn prints_to_stdout(node: Node, src: &[u8]) -> bool {
    is_macro(node, src, b"print") || is_macro(node, src, b"println")
}

fn set_len_on_fresh_vec<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let name_node = method(call)?;
    if text(name_node, src) != b"set_len" {
        return None;
    }
    let receiver = call
        .child_by_field_name("function")?
        .child_by_field_name("value")?;
    if receiver.kind() != "identifier" {
        return None;
    }
    let vec_name = text(receiver, src);
    // The statement the call is in, or the `unsafe` statement that wraps it alone.
    let mut statement = call
        .parent()
        .filter(|p| p.kind() == "expression_statement")?;
    if let Some(unsafe_block) = statement
        .parent()
        .and_then(|b| b.parent())
        .filter(|u| u.kind() == "unsafe_block")
    {
        if block_items(statement.parent()?).len() == 1 {
            statement = unsafe_block
                .parent()
                .filter(|p| p.kind() == "expression_statement")?;
        }
    }
    let previous = statement.prev_named_sibling()?;
    let made_here = previous.kind() == "let_declaration"
        && previous
            .child_by_field_name("pattern")
            .is_some_and(|p| text(p, src) == vec_name)
        && previous.child_by_field_name("value").is_some_and(|v| {
            v.kind() == "call_expression"
                && v.child_by_field_name("function")
                    .is_some_and(|f| text(f, src).ends_with(b"with_capacity"))
        });
    let reserved = previous.kind() == "expression_statement"
        && previous.named_child(0).is_some_and(|c| {
            c.kind() == "call_expression"
                && method(c).is_some_and(|m| matches!(text(m, src), b"reserve" | b"reserve_exact"))
                && c.child_by_field_name("function")
                    .and_then(|f| f.child_by_field_name("value"))
                    .is_some_and(|r| text(r, src) == vec_name)
        });
    // A `Vec<MaybeUninit<T>>` has nothing to initialize.
    let uninit = text(previous, src).windows(11).any(|w| w == b"MaybeUninit");
    ((made_here || reserved) && !uninit).then_some(name_node)
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

    fn hit(rule: &str, src: &str) -> bool {
        !lines(rule, src).is_empty()
    }

    fn in_fn(rule: &str, body: &str) -> bool {
        hit(rule, &format!("fn f() {{\n{body}\n}}\n"))
    }

    #[test]
    fn wildcards_are_allowed_for_preludes_reexports_and_test_modules() {
        assert!(hit("rs/wildcard-import", "use std::collections::*;"));
        assert!(hit("rs/wildcard-import", "use foo::{a, b::*};"));
        assert!(hit("rs/wildcard-import", "mod m { use super::*; }"));
        assert!(!hit("rs/wildcard-import", "use rayon::prelude::*;"));
        assert!(!hit("rs/wildcard-import", "pub use inner::*;"));
        assert!(!hit(
            "rs/wildcard-import",
            "#[cfg(test)]\nmod x { use super::*; }"
        ));
        assert!(!hit("rs/wildcard-import", "mod tests { use super::*; }"));
        assert!(!hit("rs/wildcard-import", "use std::collections::HashMap;"));
    }

    #[test]
    fn a_semicolon_after_a_unit_block_like_statement_is_unnecessary() {
        assert!(in_fn("rs/unnecessary-semicolon", "if a { g(); };"));
        assert!(in_fn(
            "rs/unnecessary-semicolon",
            "match a { _ => { g(); } };"
        ));
        assert!(!in_fn("rs/unnecessary-semicolon", "if a { g(); }"));
        // A value-producing branch needs its semicolon.
        assert!(!in_fn("rs/unnecessary-semicolon", "if a { 1 } else { 2 };"));
        assert!(!in_fn("rs/unnecessary-semicolon", "let x = 1;"));
    }

    #[test]
    fn invisible_characters_are_flagged_as_themselves_not_as_escapes() {
        assert!(in_fn("rs/invisible-characters", "let s = \"a\u{200B}b\";"));
        assert!(in_fn("rs/invisible-characters", "let s = \"a\u{AD}b\";"));
        assert!(!in_fn(
            "rs/invisible-characters",
            "let s = \"a\\u{200B}b\";"
        ));
        assert!(!in_fn("rs/invisible-characters", "let s = \"ab\";"));
    }

    #[test]
    fn approximations_need_enough_digits_of_a_known_constant() {
        for v in [
            "3.14",
            "3.14159",
            "2.718",
            "6.2831",
            "0.6931",
            "1.4142",
            "3.14_159f64",
        ] {
            assert!(
                in_fn("rs/approximate-constant", &format!("let x = {v};")),
                "{v}"
            );
        }
        for v in ["3.1", "3.0", "2.5", "3.15", "1e3", "100.0"] {
            assert!(
                !in_fn("rs/approximate-constant", &format!("let x = {v};")),
                "{v}"
            );
        }
    }

    #[test]
    fn a_loop_that_always_leaves_on_its_first_pass_never_loops() {
        assert!(in_fn("rs/never-loop", "for x in v { return x; }"));
        assert!(in_fn("rs/never-loop", "loop { g(); break; }"));
        assert!(in_fn("rs/never-loop", "while a { g(); return; }"));
        assert!(!in_fn("rs/never-loop", "for x in v { if x { return x; } }"));
        assert!(!in_fn(
            "rs/never-loop",
            "loop { if a { continue; } break; }"
        ));
        assert!(!in_fn("rs/never-loop", "loop { g(); }"));
    }

    #[test]
    fn a_statement_that_only_reads_values_has_no_effect() {
        assert!(in_fn("rs/no-effect", "a;"));
        assert!(in_fn("rs/no-effect", "a + b;"));
        assert!(in_fn("rs/no-effect", "s.len;"));
        assert!(in_fn("rs/no-effect", "(a, b);"));
        assert!(!in_fn("rs/no-effect", "g();"));
        assert!(!in_fn("rs/no-effect", "a = b;"));
        assert!(!in_fn("rs/no-effect", "a += b;"));
        assert!(!in_fn("rs/no-effect", "();"));
        assert!(!in_fn("rs/no-effect", "v.push(1);"));
    }

    #[test]
    fn pushes_right_after_an_empty_vec_are_a_literal() {
        assert!(in_fn(
            "rs/vec-init-then-push",
            "let mut v = Vec::new();\nv.push(1);"
        ));
        assert!(in_fn(
            "rs/vec-init-then-push",
            "let mut v = Vec::with_capacity(4);\nv.push(1);"
        ));
        assert!(in_fn(
            "rs/vec-init-then-push",
            "let mut v = vec![];\nv.push(1);"
        ));
        assert!(!in_fn(
            "rs/vec-init-then-push",
            "let mut v = Vec::new();\nv.push(v.len());"
        ));
        assert!(!in_fn(
            "rs/vec-init-then-push",
            "let mut v = Vec::new();\ng();\nv.push(1);"
        ));
        assert!(!in_fn(
            "rs/vec-init-then-push",
            "let mut v = vec![1];\nv.push(1);"
        ));
    }

    #[test]
    fn a_getter_is_misnamed_when_it_returns_another_field_and_its_own_exists() {
        let s = "struct P { x: u8, y: u8 }\nimpl P {\n";
        assert!(hit(
            "rs/misnamed-getter",
            &format!("{s} fn x(&self) -> u8 {{ self.y }}\n}}")
        ));
        assert!(hit(
            "rs/misnamed-getter",
            &format!("{s} fn x_mut(&mut self) -> &mut u8 {{ &mut self.y }}\n}}")
        ));
        assert!(!hit(
            "rs/misnamed-getter",
            &format!("{s} fn x(&self) -> u8 {{ self.x }}\n}}")
        ));
        // No field called `z`: it's an ordinary method that reads `y`.
        assert!(!hit(
            "rs/misnamed-getter",
            &format!("{s} fn z(&self) -> u8 {{ self.y }}\n}}")
        ));
        assert!(!hit(
            "rs/misnamed-getter",
            &format!("{s} fn x(&self, n: u8) -> u8 {{ self.y }}\n}}")
        ));
    }

    #[test]
    fn two_assignments_that_undo_each_other_are_an_almost_swap() {
        assert!(in_fn("rs/almost-swapped", "a = b;\nb = a;"));
        assert!(in_fn(
            "rs/almost-swapped",
            "self.a = self.b;\nself.b = self.a;"
        ));
        assert!(!in_fn("rs/almost-swapped", "a = b;\nb = c;"));
        assert!(!in_fn("rs/almost-swapped", "a = b;\ng();\nb = a;"));
        assert!(!in_fn("rs/almost-swapped", "a = a;\na = a;"));
    }

    #[test]
    fn only_a_for_over_the_result_of_next_is_flagged() {
        assert!(in_fn("rs/iter-next-loop", "for x in it.next() {}"));
        assert!(!in_fn("rs/iter-next-loop", "for x in it {}"));
        assert!(!in_fn("rs/iter-next-loop", "for x in it.iter() {}"));
    }

    #[test]
    fn inline_on_a_bodiless_trait_method_does_nothing() {
        assert!(hit(
            "rs/inline-without-body",
            "trait T { #[inline] fn m(&self); }"
        ));
        assert!(hit(
            "rs/inline-without-body",
            "trait T { #[inline(always)] fn m(&self); }"
        ));
        assert!(!hit("rs/inline-without-body", "trait T { fn m(&self); }"));
        assert!(!hit(
            "rs/inline-without-body",
            "trait T { #[inline] fn m(&self) {} }"
        ));
    }

    #[test]
    fn a_width_after_an_underscore_looks_like_a_suffix() {
        for v in ["2_32", "1_8", "10_64", "1.0_32", "2.5_64"] {
            assert!(
                in_fn("rs/mistyped-literal-suffix", &format!("let x = {v};")),
                "{v}"
            );
        }
        for v in ["2_i32", "1_000", "0x1_32", "1.0_f32", "3", "1_000_000"] {
            assert!(
                !in_fn("rs/mistyped-literal-suffix", &format!("let x = {v};")),
                "{v}"
            );
        }
    }

    #[test]
    fn a_reversed_range_is_flagged_where_it_is_iterated_or_sliced() {
        assert!(in_fn("rs/reversed-empty-range", "for _ in 5..3 {}"));
        assert!(in_fn("rs/reversed-empty-range", "for _ in 5..=3 {}"));
        assert!(in_fn("rs/reversed-empty-range", "let s = &v[5..3];"));
        assert!(!in_fn("rs/reversed-empty-range", "for _ in 3..5 {}"));
        assert!(!in_fn("rs/reversed-empty-range", "for _ in 3..=3 {}"));
        assert!(!in_fn("rs/reversed-empty-range", "let r = 5..3;"));
    }

    #[test]
    fn multiplying_or_masking_by_zero_erases_the_operand() {
        assert!(in_fn("rs/erasing-op", "let _ = x * 0;"));
        assert!(in_fn("rs/erasing-op", "let _ = 0 * x;"));
        assert!(in_fn("rs/erasing-op", "let _ = x & 0;"));
        assert!(in_fn("rs/erasing-op", "let _ = 0 / x;"));
        assert!(!in_fn("rs/erasing-op", "let _ = x / 0;"));
        assert!(!in_fn("rs/erasing-op", "let _ = x + 0;"));
        assert!(!in_fn("rs/erasing-op", "let _ = g() * 0;"));
    }

    #[test]
    fn long_ungrouped_numbers_are_unreadable() {
        assert!(in_fn("rs/unreadable-literal", "let _ = 1000000;"));
        assert!(in_fn("rs/unreadable-literal", "let _ = 100000u64;"));
        assert!(!in_fn("rs/unreadable-literal", "let _ = 1_000_000;"));
        assert!(!in_fn("rs/unreadable-literal", "let _ = 1000;"));
    }

    #[test]
    fn printing_to_stdout_is_flagged_and_logging_and_stderr_are_not() {
        assert!(in_fn("rs/print-stdout", "println!(\"x\");"));
        assert!(in_fn("rs/print-stdout", "print!(\"x\");"));
        assert!(!in_fn("rs/print-stdout", "eprintln!(\"x\");"));
        assert!(!in_fn("rs/print-stdout", "format!(\"x\");"));
    }

    #[test]
    fn a_trait_pair_split_between_derive_and_a_hand_written_impl_is_flagged() {
        let ord = "#[derive(PartialEq, Eq, Ord)]\nstruct S(u8);\nimpl PartialOrd for S { fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> { None } }";
        assert!(hit("rs/derive-ord-with-manual-partial-ord", ord));
        let ord2 = "#[derive(PartialEq, Eq, PartialOrd)]\nstruct S(u8);\nimpl Ord for S { fn cmp(&self, o: &Self) -> std::cmp::Ordering { todo!() } }";
        assert!(hit("rs/derive-ord-with-manual-partial-ord", ord2));
        let both = "#[derive(PartialEq, Eq, Ord, PartialOrd)]\nstruct S(u8);";
        assert!(!hit("rs/derive-ord-with-manual-partial-ord", both));
        let hash = "#[derive(Hash)]\nstruct S(u8);\nimpl PartialEq for S { fn eq(&self, o: &Self) -> bool { true } }";
        assert!(hit("rs/derived-hash-with-manual-eq", hash));
        let hash2 = "#[derive(PartialEq)]\nstruct S<T>(T);\nimpl<T> std::hash::Hash for S<T> { fn hash<H: std::hash::Hasher>(&self, h: &mut H) {} }";
        assert!(hit("rs/derived-hash-with-manual-eq", hash2));
        let manual_both = "struct S(u8);\nimpl PartialEq for S { fn eq(&self, o: &Self) -> bool { true } }\nimpl std::hash::Hash for S { fn hash<H: std::hash::Hasher>(&self, h: &mut H) {} }";
        assert!(!hit("rs/derived-hash-with-manual-eq", manual_both));
    }

    #[test]
    fn set_len_straight_after_with_capacity_or_reserve_exposes_uninitialized_memory() {
        assert!(in_fn(
            "rs/uninit-vec",
            "let mut v = Vec::with_capacity(n);\nunsafe { v.set_len(n); }"
        ));
        assert!(in_fn(
            "rs/uninit-vec",
            "v.reserve(n);\nunsafe { v.set_len(n); }"
        ));
        assert!(!in_fn(
            "rs/uninit-vec",
            "let mut v = Vec::with_capacity(n);\nfill(&mut v);\nunsafe { v.set_len(n); }"
        ));
        assert!(!in_fn(
            "rs/uninit-vec",
            "let mut v: Vec<MaybeUninit<u8>> = Vec::with_capacity(n);\nunsafe { v.set_len(n); }"
        ));
    }

    #[test]
    fn clippy_allow_silences_these_rules_too() {
        let src = "#[allow(clippy::wildcard_imports)]\nuse a::*;\nuse b::*;\n";
        assert_eq!(lines("rs/wildcard-import", src), [3]);
    }
}
