//! C# rules that implement their SonarQube key's documented behavior on the
//! semantic model (ADR-0008, ADR-0015): types from declarations, references
//! to declarations. They began as syntactic approximations in earlier
//! batches and keep their ids. A name whose type the file doesn't declare
//! gives no finding, which costs recall, not scope.

use super::cs::{cs_statements, same_code, simple_name, unparenthesized};
use super::cs_bugs::cs_call_arguments;
use super::cs_more::is_boolean_expression;
use super::cs_opt2::may_implement_contract;
use super::cs_types::{expression_type, is_delegate_type, is_generic, type_of_name, walk_tree};
use super::java_bugs::{find_in_scope, operator_text};
use super::java_security::text;
use super::java_smells::count_word;
use super::*;
use crate::semantic::{DeclKind, Model};

/// Rules that are off unless `rules.enabled` lists them: none, every rule
/// here is in SonarQube's default profile.
pub(super) static OFF_BY_DEFAULT: &[&str] = &[];

pub(super) static RULES: &[Rule] = &[
    // ---- Bugs ----
    Rule {
        id: "cs/float-equality",
        name: "Floating-point values should not be tested for equality",
        description: "Most decimal fractions have no exact binary representation, so `x == 0.1` can be false \
                      for a value that prints as 0.1. `x < 4 || x > 4` is the same test written indirectly.",
        message: "Compare with a tolerance, such as Math.Abs(x - y) < epsilon.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1244")],
        check: Check::Semantic {
            langs: CSHARP,
            find: float_equality,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { bool F(double x) { return x == 0.1; } }",
            good: "class A { bool F(double x) { return Math.Abs(x - 0.1) < 1e-9; } }",
        }),
    },
    Rule {
        id: "cs/integer-division-to-floating",
        name: "Integer division should not be assigned to floating-point variables",
        description: "`double d = 1 / 3;` divides integers first, which gives 0, and only then converts it.",
        message: "Make one operand floating point (1.0 / 3), or cast it before dividing.",
        category: Bug,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S2184")],
        check: Check::Semantic {
            langs: CSHARP,
            find: integer_division_into_float,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { double Ratio(int a, int b) { double r = a / b; return r; } }",
            good: "class A { double Ratio(int a, int b) { double r = (double)a / b; return r; } }",
        }),
    },
    Rule {
        id: "cs/begin-invoke-without-end",
        name: "BeginInvoke should be paired with EndInvoke",
        description: "Without EndInvoke a delegate's asynchronous call leaks its resources, and any exception it \
                      throws is lost.",
        message: "Call EndInvoke (in the callback, or later) for this BeginInvoke.",
        category: Bug,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S4583")],
        check: Check::Semantic {
            langs: CSHARP,
            find: unpaired_begin_invoke,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(Func<int> work) { work.BeginInvoke(null, null); } }",
            good: "class A { void F(Func<int> work) { var r = work.BeginInvoke(null, null); work.EndInvoke(r); } }",
        }),
    },
    // ---- Code smells ----
    Rule {
        id: "cs/non-short-circuit-logic",
        name: "Boolean conditions should use && and ||",
        description: "`&` and `|` evaluate both sides even when the result is already known, so a guard such as \
                      `x != null & x.Ok` still throws.",
        message: "Use '&&' or '||' instead.",
        category: CodeSmell,
        severity: Blocker,
        effort_minutes: 2,
        sonar: &[exact("S2178")],
        check: Check::Semantic {
            langs: CSHARP,
            find: non_short_circuit_logic,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { bool F(B b) { return b != null & b.Ok; } }",
            good: "class A { bool F(B b) { return b != null && b.Ok; } }",
        }),
    },
    Rule {
        id: "cs/redundant-boolean-literal",
        name: "Boolean literals should not be redundant",
        description: "`b ? true : false` is `b`, `x && true` is `x`, and `x == true` is `x`. Comparisons with \
                      a literal are only reported when the other side is a plain bool: on a nullable bool \
                      they aren't redundant.",
        message: "Remove the boolean literal and simplify the expression.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S1125")],
        check: Check::Semantic {
            langs: CSHARP,
            find: redundant_boolean_literals,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { bool F(bool b) { return b == true; } }",
            good: "class A { bool F(bool b, bool? c) { return b || c == true; } }",
        }),
    },
    Rule {
        id: "cs/any-instead-of-contains",
        name: "Contains should be used instead of Any for simple equality",
        description: "On a List, HashSet or SortedSet, `xs.Contains(y)` is faster than `xs.Any(x => x == y)`, \
                      which walks every element.",
        message: "Use Contains(...) instead of Any with an equality lambda.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6617")],
        check: Check::Semantic {
            langs: CSHARP,
            find: any_instead_of_contains,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { bool F(List<int> xs, int y) { return xs.Any(x => x == y); } }",
            good: "class A { bool F(List<int> xs, int y) { return xs.Contains(y); } }",
        }),
    },
    Rule {
        id: "cs/event-never-used",
        name: "Events should be invoked",
        description: "An event that nothing in its class invokes never fires: subscribing to it and testing it \
                      for null don't raise it.",
        message: "Raise this event, or remove it.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3264")],
        check: Check::Semantic {
            langs: CSHARP,
            find: events_never_invoked,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { public event EventHandler Changed; public void Watch(EventHandler h) { Changed += h; } }",
            good: "class A { public event EventHandler Changed; public void Set() { Changed?.Invoke(this, EventArgs.Empty); } }",
        }),
    },
    Rule {
        id: "cs/method-returns-constant",
        name: "Methods should not return constants",
        description: "A method whose only statement returns a literal is a constant in disguise, and callers \
                      may expect it to do more.",
        message: "Replace this method with a constant.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S3400")],
        check: Check::Semantic {
            langs: CSHARP,
            find: methods_returning_constants,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int Limit() { return 10; } int F() => Limit(); }",
            good: "class A { const int Limit = 10; int F() => Limit; }",
        }),
    },
    Rule {
        id: "cs/loop-could-be-where",
        name: "Loops should be simplified with LINQ expressions",
        description: "A foreach whose whole body is an `if` filters, and one that only uses one member of each \
                      element selects: `xs.Where(...)` and `xs.Select(x => x.P)` say so directly.",
        message: "Iterate the collection filtered with Where(...) or projected with Select(...).",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S3267")],
        check: Check::Semantic {
            langs: CSHARP,
            find: loops_simplifiable,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(int[] xs) { foreach (var x in xs) { if (x > 0) { G(x); } } } }",
            good: "class A { void F(int[] xs) { foreach (var x in xs.Where(x => x > 0)) { G(x); } } }",
        }),
    },
    Rule {
        id: "cs/where-then-predicate-method",
        name: "LINQ expressions should be simplified",
        description: "`Where(p).First()` is `First(p)`; `Select(x => x as T)` followed by a null check, and \
                      `Where(x => x is T)` followed by a cast, are `OfType<T>()`; Count() on a collection is its \
                      Count or Length; and ToList() or ToArray() in the middle of a query copies for nothing.",
        message: "Simplify this LINQ expression.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2971")],
        check: Check::Semantic {
            langs: CSHARP,
            find: linq_simplifiable,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int F(List<int> xs) { return xs.Where(x => x > 0).First(); } }",
            good: "class A { int F(List<int> xs) { return xs.First(x => x > 0); } }",
        }),
    },
    Rule {
        id: "cs/lock-on-weak-identity",
        name: "Locks should not be taken on objects with weak identity",
        description: "Strings, types, reflection objects, threads and a few exceptions can be shared across \
                      application domains, so a lock on one may block threads elsewhere.",
        message: "Lock on a private readonly object instead.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S3998")],
        check: Check::Semantic {
            langs: CSHARP,
            find: locks_on_weak_identity,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { readonly string key = \"k\"; void F() { lock (key) { } } }",
            good: "class A { readonly object key = new object(); void F() { lock (key) { } } }",
        }),
    },
];

// ---------------------------------------------------- helpers

/// The nodes of `kinds` that `keep` accepts, from one walk of the file.
fn matching<'t>(
    m: &Model<'t>,
    kinds: &[&str],
    keep: impl Fn(Node<'t>, &[Node<'t>]) -> bool,
) -> Vec<Node<'t>> {
    let mut found = Vec::new();
    walk_tree(m, |node, ancestors| {
        if kinds.contains(&node.kind()) && keep(node, ancestors) {
            found.push(node);
        }
    });
    found
}

fn method_name<'s>(call: Node, src: &'s [u8]) -> &'s [u8] {
    call.child_by_field_name("function")
        .filter(|f| f.kind() == "member_access_expression")
        .and_then(|f| f.child_by_field_name("name"))
        .map_or(&b""[..], |n| simple_name(n, src))
}

fn receiver(call: Node) -> Option<Node> {
    call.child_by_field_name("function")
        .filter(|f| f.kind() == "member_access_expression")
        .and_then(|f| f.child_by_field_name("expression"))
}

fn type_is(m: &Model, expr: Node, src: &[u8], types: &[&[u8]]) -> bool {
    expression_type(m, expr, src).is_some_and(|t| types.contains(&t.as_slice()))
}

// ---------------------------------------------------- filters

fn float_equality<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let is_float = |n: Node| type_is(m, n, src, &[b"float", b"double", b"float?", b"double?"]);
    // `a < b` as (strict, a, b), flipping `>`.
    let comparison = |n: Node<'t>| -> Option<(bool, Node<'t>, Node<'t>)> {
        let n = unparenthesized(n);
        let (l, r) = (
            n.child_by_field_name("left")?,
            n.child_by_field_name("right")?,
        );
        match operator_text(n, src) {
            b"<" => Some((true, l, r)),
            b">" => Some((true, r, l)),
            b"<=" => Some((false, l, r)),
            b">=" => Some((false, r, l)),
            _ => None,
        }
    };
    matching(m, &["binary_expression"], |node, _| {
        let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) else {
            return false;
        };
        match operator_text(node, src) {
            // `value == null` on a double? is a null check.
            b"==" | b"!=" => {
                (is_float(left) || is_float(right))
                    && ![left, right]
                        .iter()
                        .any(|s| unparenthesized(*s).kind() == "null_literal")
            }
            // `x < 4 || x > 4` and `x <= 4 && x >= 4`: != and == in disguise.
            op @ (b"||" | b"&&") => {
                let (Some((s1, a1, b1)), Some((s2, a2, b2))) =
                    (comparison(left), comparison(right))
                else {
                    return false;
                };
                let strict = op == b"||";
                s1 == strict
                    && s2 == strict
                    && same_code(a1, b2, src)
                    && same_code(b1, a2, src)
                    && (is_float(a1) || is_float(b1))
            }
            _ => false,
        }
    })
}

const INTEGRAL: &[&[u8]] = &[
    b"int", b"long", b"short", b"byte", b"sbyte", b"uint", b"ulong", b"ushort", b"char",
];
const FLOATING: &[&[u8]] = &[b"double", b"float", b"decimal"];

fn integer_division(m: &Model, e: Node, src: &[u8]) -> bool {
    let e = unparenthesized(e);
    e.kind() == "binary_expression"
        && operator_text(e, src) == b"/"
        && e.child_by_field_name("left")
            .is_some_and(|l| type_is(m, l, src, INTEGRAL))
        && e.child_by_field_name("right")
            .is_some_and(|r| type_is(m, r, src, INTEGRAL))
}

fn integer_division_into_float<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let floating = |t: Option<Node>| t.is_some_and(|t| FLOATING.contains(&simple_name(t, src)));
    let mut found = Vec::new();
    walk_tree(m, |node, _| match node.kind() {
        // double d = a / b;
        "variable_declarator" => {
            let declared = node.parent().and_then(|v| v.child_by_field_name("type"));
            if let Some(value) = (node.named_child_count() > 1)
                .then(|| node.named_child(node.named_child_count() as u32 - 1))
                .flatten()
                && floating(declared)
                && integer_division(m, value, src)
            {
                found.push(value);
            }
        }
        // d = a / b;
        "assignment_expression" => {
            if let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) && floating(type_of_name(m, left))
                && integer_division(m, right, src)
            {
                found.push(right);
            }
        }
        // Method(a / b) to a floating-point parameter of a method declared here.
        "invocation_expression" => {
            let Some(target) = node
                .child_by_field_name("function")
                .filter(|f| f.kind() == "identifier")
                .and_then(|f| m.decl_of(f))
                .filter(|d| {
                    d.kind == DeclKind::Method && m.decls_named(d.scope, &d.name).len() == 1
                })
            else {
                return;
            };
            let Some(params) = target
                .declarator
                .and_then(|d| d.child_by_field_name("parameters"))
            else {
                return;
            };
            let mut c = params.walk();
            let types: Vec<Option<Node>> = params
                .named_children(&mut c)
                .filter(|p| p.kind() == "parameter")
                .map(|p| p.child_by_field_name("type"))
                .collect();
            for (arg, ty) in cs_call_arguments(node).into_iter().zip(types) {
                if floating(ty) && integer_division(m, arg, src) {
                    found.push(arg);
                }
            }
        }
        _ => {}
    });
    found
}

fn unpaired_begin_invoke<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    matching(m, &["invocation_expression"], |call, ancestors| {
        if method_name(call, src) != b"BeginInvoke" {
            return false;
        }
        // A delegate's BeginInvoke; Control.BeginInvoke and the dispatcher's
        // need no EndInvoke.
        let Some(target) = receiver(call)
            .filter(|r| type_of_name(m, *r).is_some_and(|t| is_delegate_type(m, text(t, src))))
        else {
            return false;
        };
        let name = simple_name(target, src);
        // EndInvoke on the same delegate in the method, its callback included.
        let method = ancestors.iter().rev().find(|a| {
            matches!(
                a.kind(),
                "method_declaration"
                    | "local_function_statement"
                    | "constructor_declaration"
                    | "accessor_declaration"
            )
        });
        let paired = method.is_some_and(|f| {
            let body = text(*f, src);
            let call_text: Vec<u8> = [name, b".EndInvoke"].concat();
            body.windows(call_text.len()).any(|w| w == call_text)
        });
        // A method-group callback may end it elsewhere in the class.
        let callback_elsewhere = cs_call_arguments(call)
            .iter()
            .rev()
            .nth(1)
            .is_some_and(|c| {
                !matches!(
                    c.kind(),
                    "null_literal" | "lambda_expression" | "anonymous_method_expression"
                )
            })
            && ancestors
                .iter()
                .find(|a| a.kind() == "class_declaration")
                .is_some_and(|c| count_word(text(*c, src), b"EndInvoke") > 0);
        !paired && !callback_elsewhere
    })
}

fn non_short_circuit_logic<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let boolean = |n: Node| is_boolean_expression(n, src) || type_is(m, n, src, &[b"bool"]);
    matching(m, &["binary_expression"], |node, _| {
        matches!(operator_text(node, src), b"&" | b"|")
            && (node.child_by_field_name("left").is_some_and(boolean)
                || node.child_by_field_name("right").is_some_and(boolean))
    })
}

fn redundant_boolean_literals<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let literal =
        |n: Option<Node>| n.is_some_and(|n| unparenthesized(n).kind() == "boolean_literal");
    // A plain bool: a literal, a comparison or logic, or a name declared bool.
    let plain_bool = |n: Node| {
        let n = unparenthesized(n);
        n.kind() == "boolean_literal"
            || is_boolean_expression(n, src)
            || type_is(m, n, src, &[b"bool"])
    };
    matching(
        m,
        &[
            "binary_expression",
            "conditional_expression",
            "prefix_unary_expression",
        ],
        |node, ancestors| {
            match node.kind() {
                "conditional_expression" => {
                    let (Some(yes), Some(no)) = (
                        node.child_by_field_name("consequence"),
                        node.child_by_field_name("alternative"),
                    ) else {
                        return false;
                    };
                    // `c ? true : false`, or `c ? true : x` with x a plain bool.
                    (literal(Some(yes)) && plain_bool(no)) || (literal(Some(no)) && plain_bool(yes))
                }
                "binary_expression" => {
                    let (Some(left), Some(right)) = (
                        node.child_by_field_name("left"),
                        node.child_by_field_name("right"),
                    ) else {
                        return false;
                    };
                    // tree-sitter-c-sharp reads `x is true || y` as `x is (true || y)`.
                    if ancestors
                        .last()
                        .is_some_and(|p| p.kind() == "constant_pattern")
                    {
                        return false;
                    }
                    match operator_text(node, src) {
                        b"&&" | b"||" => literal(Some(left)) || literal(Some(right)),
                        b"==" | b"!=" => {
                            (literal(Some(left)) && plain_bool(right))
                                || (literal(Some(right)) && plain_bool(left))
                        }
                        _ => false,
                    }
                }
                _ => text(node, src).starts_with(b"!") && literal(node.named_child(0)),
            }
        },
    )
}

/// `x => x == y` with x not used on the other side.
fn equality_lambda(lambda: Node, src: &[u8]) -> bool {
    let Some(parameter) = lambda.child_by_field_name("parameters").map(|p| {
        let p = text(p, src).trim_ascii();
        p.strip_prefix(b"(")
            .and_then(|p| p.strip_suffix(b")"))
            .unwrap_or(p)
    }) else {
        return false;
    };
    let Some(body) = lambda
        .child_by_field_name("body")
        .filter(|b| b.kind() == "binary_expression" && operator_text(*b, src) == b"==")
    else {
        return false;
    };
    let (Some(l), Some(r)) = (
        body.child_by_field_name("left"),
        body.child_by_field_name("right"),
    ) else {
        return false;
    };
    let (l, r) = (text(l, src), text(r, src));
    // `x => x == y`, but not `x => x.Id == y`, which Contains can't express.
    (l == parameter) != (r == parameter)
        && count_word(if l == parameter { r } else { l }, parameter) == 0
}

fn any_instead_of_contains<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    matching(m, &["invocation_expression"], |call, _| {
        method_name(call, src) == b"Any"
            && matches!(cs_call_arguments(call).as_slice(), [l] if l.kind() == "lambda_expression" && equality_lambda(*l, src))
            && receiver(call)
                .and_then(|r| type_of_name(m, r))
                .is_some_and(|t| {
                    [&b"List"[..], b"HashSet", b"SortedSet"]
                        .iter()
                        .any(|n| is_generic(t, n, src))
                })
    })
}

fn events_never_invoked<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let mut uses = vec![Vec::new(); m.decls.len()];
    for r in &m.refs {
        if let Some(d) = r.decl {
            uses[d].push(r.node);
        }
    }
    m.decls
        .iter()
        .enumerate()
        .filter(|(i, d)| {
            let Some(event) = d
                .declarator
                .filter(|_| d.kind == DeclKind::Field)
                .and_then(|x| x.parent())
                .and_then(|v| v.parent())
                .filter(|e| e.kind() == "event_field_declaration")
            else {
                return false;
            };
            if ["override", "abstract", "virtual"]
                .iter()
                .any(|w| super::cs::cs_has_modifier(event, w, src))
            {
                return false;
            }
            let class = event.parent().and_then(|l| l.parent());
            if class.is_none_or(|c| super::cs::cs_has_modifier(c, "partial", src) || c.has_error())
            {
                return false;
            }
            // Subscribing, unsubscribing and testing for null don't raise it;
            // a call does, and so may any other use (copied to a local, passed on).
            !uses[*i].iter().any(|u| {
                let Some(parent) = u.parent() else {
                    return true;
                };
                let held = if parent.kind() == "member_access_expression" {
                    parent
                } else {
                    *u
                };
                let Some(holder) = held.parent() else {
                    return true;
                };
                match holder.kind() {
                    "assignment_expression" if holder.child_by_field_name("left") == Some(held) => {
                        !matches!(operator_text(holder, src), b"+=" | b"-=")
                    }
                    "binary_expression" => !matches!(operator_text(holder, src), b"==" | b"!="),
                    "is_pattern_expression" => false,
                    _ => true,
                }
            })
        })
        .map(|(_, d)| d.node)
        .collect()
}

fn methods_returning_constants<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    m.functions
        .iter()
        .map(|f| f.node)
        .filter(|method| method.kind() == "method_declaration")
        .filter_map(|method| {
            // Overrides and implementations return what their contract asks.
            let special = [
                "override", "virtual", "abstract", "extern", "partial", "async", "new",
            ]
            .iter()
            .any(|w| super::cs::cs_has_modifier(method, w, src));
            let mut cursor = method.walk();
            let marked = method
                .named_children(&mut cursor)
                .any(|c| matches!(c.kind(), "explicit_interface_specifier" | "attribute_list"));
            if special || marked || may_implement_contract(method, src) {
                return None;
            }
            // Class members only: interface methods are API.
            if method.parent()?.parent()?.kind() != "class_declaration" {
                return None;
            }
            let body = method.child_by_field_name("body")?;
            let value = match body.kind() {
                "arrow_expression_clause" => body.named_child(0)?,
                _ => match cs_statements(body).as_slice() {
                    [s] if s.kind() == "return_statement" => s.named_child(0)?,
                    _ => return None,
                },
            };
            matches!(
                unparenthesized(value).kind(),
                "integer_literal"
                    | "real_literal"
                    | "string_literal"
                    | "boolean_literal"
                    | "character_literal"
            )
            .then_some(value)
        })
        .collect()
}

fn loops_simplifiable<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let mut found = Vec::new();
    walk_tree(m, |foreach, _| {
        if foreach.kind() != "foreach_statement" {
            return;
        }
        let (Some(body), Some(variable)) = (
            foreach.child_by_field_name("body"),
            foreach.child_by_field_name("left"),
        ) else {
            return;
        };
        // `await foreach` iterates an async stream, which LINQ to Objects
        // doesn't filter.
        if body.kind() != "block"
            || variable.kind() != "identifier"
            || text(foreach, src).starts_with(b"await")
        {
            return;
        }
        let exits = |n: Node| {
            find_in_scope(n, super::cs::CS_SCOPE_STOPS, |x| {
                matches!(
                    x.kind(),
                    "break_statement"
                        | "return_statement"
                        | "yield_statement"
                        | "continue_statement"
                        | "await_expression"
                        | "goto_statement"
                )
            })
            .is_some()
        };
        let statements = cs_statements(body);
        let name = text(variable, src);
        // Filtering: the whole body is an `if` without else, testing the
        // element, and declaring nothing the body needs (`out var`, `is T t`).
        let filters = |condition: Node| {
            count_word(text(condition, src), name) > 0
                && find_in_scope(condition, super::cs::CS_SCOPE_STOPS, |n| {
                    matches!(
                        n.kind(),
                        "declaration_expression" | "declaration_pattern" | "recursive_pattern"
                    )
                })
                .is_none()
        };
        if let [statement] = statements.as_slice()
            && statement.kind() == "if_statement"
            && statement.child_by_field_name("alternative").is_none()
            && statement
                .child_by_field_name("condition")
                .is_some_and(filters)
            && !exits(*statement)
        {
            found.push(*statement);
            return;
        }
        // Selecting: the element is only used through one member.
        let mut member: Option<&[u8]> = None;
        let mut only_member = true;
        let mut used = false;
        let mut stack = vec![body];
        while let Some(n) = stack.pop() {
            if n.kind() == "identifier" && text(n, src) == name {
                used = true;
                let access = n
                    .parent()
                    .filter(|p| {
                        p.kind() == "member_access_expression"
                            && p.child_by_field_name("expression") == Some(n)
                    })
                    .and_then(|p| p.child_by_field_name("name"))
                    .map(|x| text(x, src));
                match (access, member) {
                    (Some(a), None) => member = Some(a),
                    (Some(a), Some(b)) if a == b => {}
                    _ => only_member = false,
                }
                continue;
            }
            let mut c = n.walk();
            stack.extend(n.named_children(&mut c));
        }
        // A call `x.M()` uses x, not just a value of it.
        let called = member.is_some_and(|mb| {
            let pattern: Vec<u8> = [name, b".", mb, b"("].concat();
            text(body, src).windows(pattern.len()).any(|w| w == pattern)
        });
        if used && only_member && member.is_some() && !called && !exits(body) {
            found.push(variable);
        }
    });
    found
}

const LINQ_CHAIN: &[&[u8]] = &[
    b"Where",
    b"Select",
    b"SelectMany",
    b"OrderBy",
    b"OrderByDescending",
    b"ThenBy",
    b"ThenByDescending",
    b"GroupBy",
    b"Distinct",
    b"Skip",
    b"Take",
    b"Any",
    b"All",
    b"Count",
    b"First",
    b"FirstOrDefault",
    b"Last",
    b"LastOrDefault",
    b"Single",
    b"SingleOrDefault",
    b"Sum",
    b"Min",
    b"Max",
    b"Average",
    b"Contains",
];

const PREDICATE_TAKERS: &[&[u8]] = &[
    b"Any",
    b"Count",
    b"LongCount",
    b"First",
    b"FirstOrDefault",
    b"Last",
    b"LastOrDefault",
    b"Single",
    b"SingleOrDefault",
];

fn lambda_body(call: Node) -> Option<Node> {
    cs_call_arguments(call)
        .first()
        .filter(|a| a.kind() == "lambda_expression")
        .and_then(|l| l.child_by_field_name("body"))
        .map(unparenthesized)
}

fn linq_simplifiable<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    matching(m, &["invocation_expression"], |call, _| {
        let name = method_name(call, src);
        let args = cs_call_arguments(call).len();
        let inner = receiver(call).filter(|r| r.kind() == "invocation_expression");
        let inner_name = inner.map_or(&b""[..], |i| method_name(i, src));
        // Where(p).First() is First(p).
        if PREDICATE_TAKERS.contains(&name)
            && args == 0
            && inner_name == b"Where"
            && inner.is_some_and(|i| cs_call_arguments(i).len() == 1)
        {
            return true;
        }
        // Select(x => x as T) then a null check: OfType<T>().
        if inner_name == b"Select"
            && inner
                .and_then(lambda_body)
                .is_some_and(|b| b.kind() == "as_expression")
            && lambda_body(call).is_some_and(|b| {
                let t = text(b, src);
                t.windows(7).any(|w| w == b"!= null") || t.windows(11).any(|w| w == b"is not null")
            })
        {
            return true;
        }
        // Where(x => x is T) then a cast: OfType<T>().
        if name == b"Select"
            && inner_name == b"Where"
            && inner
                .and_then(lambda_body)
                .is_some_and(|b| matches!(b.kind(), "is_expression" | "is_pattern_expression"))
            && lambda_body(call)
                .is_some_and(|b| matches!(b.kind(), "cast_expression" | "as_expression"))
        {
            return true;
        }
        // Count() on a collection with a Count or Length property.
        if name == b"Count"
            && args == 0
            && receiver(call)
                .and_then(|r| type_of_name(m, r))
                .is_some_and(|t| {
                    t.kind() == "array_type"
                        || [
                            &b"List"[..],
                            b"IList",
                            b"ICollection",
                            b"IReadOnlyCollection",
                            b"IReadOnlyList",
                            b"HashSet",
                            b"Dictionary",
                            b"IDictionary",
                            b"Queue",
                            b"Stack",
                            b"Collection",
                        ]
                        .iter()
                        .any(|n| is_generic(t, n, src))
                })
        {
            return true;
        }
        // ToList() or ToArray() in the middle of a query.
        LINQ_CHAIN.contains(&name)
            && matches!(inner_name, b"ToList" | b"ToArray")
            && inner.is_some_and(|i| cs_call_arguments(i).is_empty())
            && inner.and_then(receiver).is_some_and(|r| {
                r.kind() == "invocation_expression" && LINQ_CHAIN.contains(&method_name(r, src))
            })
    })
}

/// Types SonarQube names as having weak identity, and reflection types
/// deriving from MemberInfo.
const WEAK_IDENTITY: &[&[u8]] = &[
    b"string",
    b"String",
    b"Thread",
    b"MemberInfo",
    b"Type",
    b"MethodInfo",
    b"MethodBase",
    b"PropertyInfo",
    b"FieldInfo",
    b"ConstructorInfo",
    b"EventInfo",
    b"TypeInfo",
    b"ParameterInfo",
    b"MarshalByRefObject",
    b"ExecutionEngineException",
    b"OutOfMemoryException",
    b"StackOverflowException",
];

fn locks_on_weak_identity<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let mut found = Vec::new();
    walk_tree(m, |statement, _| {
        if statement.kind() != "lock_statement" {
            return;
        }
        let Some(target) = statement.named_child(0).map(unparenthesized) else {
            return;
        };
        let weak = match target.kind() {
            "string_literal"
            | "verbatim_string_literal"
            | "interpolated_string_expression"
            | "typeof_expression" => true,
            "invocation_expression" => matches!(
                method_name(target, src),
                b"GetType" | b"GetMethod" | b"GetProperty" | b"GetField"
            ),
            "member_access_expression" if text(target, src) == b"Thread.CurrentThread" => true,
            _ => type_of_name(m, target)
                .is_some_and(|t| WEAK_IDENTITY.contains(&simple_name(t, src))),
        };
        if weak {
            found.push(target);
        }
    });
    found
}

#[cfg(test)]
mod tests {
    use super::super::cs::tests::flagged;

    fn class(body: &str) -> String {
        format!("namespace N;\nclass A {{\n{body}\n}}\n")
    }

    #[test]
    fn floats_and_divisions() {
        let src = class(
            "void Take(double d) { }\nvoid F(double x, float f, int i, int j, decimal m, long l, double? nd) {\nvar a = x == 0.1;\nvar b = f != 2;\nvar c = x == 0;\nvar d = i == 1;\nvar e = m == 1.1m;\nvar g = x < 4 || x > 4;\nvar h = x <= 4 && x >= 4;\nvar k = x < 4 || x > 5;\nvar n = nd == null;\ndouble r = i / j;\ndecimal s = 3 / 2;\ndouble t = 1.0 / i;\ndouble u = (double)i / j;\nx = l / i;\nTake(i / j);\nint v = i / j;\n}",
        );
        assert_eq!(flagged("cs/float-equality", &src), [5, 6, 7, 10, 11]);
        assert_eq!(
            flagged("cs/integer-division-to-floating", &src),
            [14, 15, 18, 19]
        );
    }

    #[test]
    fn booleans() {
        let src = class(
            "bool F(bool b, bool? n, int x, bool c) {\nvar a = b ? true : false;\nvar d = b && true;\nvar e = !false;\nvar f = b == true;\nvar g = n == true;\nvar h = c ? true : b;\nvar k = c ? true : n;\nvar u = u2 is true || !d;\nvar p = b & c;\nvar q = (x > 1) | b;\nvar r = x & 3;\nvar s = flags & Mask;\nreturn a;\n}",
        );
        assert_eq!(
            flagged("cs/redundant-boolean-literal", &src),
            [4, 5, 6, 7, 9]
        );
        assert_eq!(flagged("cs/non-short-circuit-logic", &src), [12, 13]);
    }

    #[test]
    fn collections_and_linq() {
        let src = class(
            "void F(List<int> xs, HashSet<int> hs, IEnumerable<int> seq, int y, int[] arr, IQueryable<V> q) {\nvar a = xs.Any(x => x == y);\nvar b = hs.Any(x => y == x);\nvar c = seq.Any(x => x == y);\nvar d = xs.Any(x => x.Id == y);\nvar e = xs.Where(x => x > 0).First();\nvar f = seq.Select(x => x as Car).Where(x => x != null);\nvar g = seq.Where(x => x is Car).Select(x => (Car)x);\nvar h = xs.Count();\nvar k = arr.Count();\nvar l = seq.Count();\nvar n = xs.Count(x => x > 1);\nvar o = seq.Where(x => x > 0).ToList().Select(x => x * 2);\nvar p = seq.ToList();\nvar r = xs.Where(x => x > 0).Any(x => x > 1);\n}",
        );
        assert_eq!(flagged("cs/any-instead-of-contains", &src), [4, 5]);
        assert_eq!(
            flagged("cs/where-then-predicate-method", &src),
            [8, 9, 10, 11, 12, 15]
        );
    }

    #[test]
    fn events_constants_loops() {
        let src = "namespace N;\nclass A {\npublic event EventHandler Raised;\npublic event EventHandler Watched;\npublic event EventHandler Copied;\npublic event EventHandler Never;\nvoid R() { Raised?.Invoke(this, EventArgs.Empty); var h = Copied; h?.Invoke(this, null); }\nvoid W(EventHandler x) { Watched += x; if (Watched != null) { } Never -= x; }\nint Limit() { return 10; }\npublic string Name() => \"a\";\nint Twice(int x) => x * 2;\nint Param(int x) => 3;\npublic override string ToString() => \"A\";\nvoid L(int[] xs, List<P> ps) {\nforeach (var x in xs) { if (x > 0) { G(x); } }\nforeach (var x in xs) { if (x > 0) { return; } }\nforeach (var p in ps) { Show(p.Name); Log(p.Name); }\nforeach (var p in ps) { Show(p.Name); Log(p.Id); }\nforeach (var p in ps) { p.Save(); }\nforeach (var x in xs) { if (d.TryGetValue(x, out var v)) { G(v); } }\nforeach (var x in xs) { if (ready) { G(x); } }\n}\n}\nclass B : IThing { public int Size() => 4; }";
        assert_eq!(flagged("cs/event-never-used", src), [4, 6]);
        assert_eq!(flagged("cs/method-returns-constant", src), [9, 10, 12]);
        assert_eq!(flagged("cs/loop-could-be-where", src), [15, 17]);
    }

    #[test]
    fn invokes_and_locks() {
        let src = "namespace N;\nclass A {\nreadonly string key = \"k\";\nreadonly object sync = new object();\nvoid F(Func<int> w) { w.BeginInvoke(null, null); }\nvoid G(Func<int> w, Control c, Type t) {\nvar r = w.BeginInvoke(null, null); w.EndInvoke(r);\nc.BeginInvoke(new Action(H));\nlock (key) { }\nlock (sync) { }\nlock (\"x\") { }\nlock (t) { }\nlock (typeof(A)) { }\n}\n}";
        assert_eq!(flagged("cs/begin-invoke-without-end", src), [5]);
        assert_eq!(flagged("cs/lock-on-weak-identity", src), [9, 11, 12, 13]);
    }
}
