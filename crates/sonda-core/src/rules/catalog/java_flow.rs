//! Java rules, part 7 (ADR-0007, batch 16): flow checks approximated inside
//! one method (infinite loops, unclosed resources, Optional and null use,
//! locks, streams) and class-hierarchy checks against the classes declared
//! in the same file. These are sound within their scope and stay silent
//! when the answer depends on code they can't see.

use super::java_bugs::{has_annotation, has_modifier, statements};
use super::java_extra::{class_members, declared_type, name_text, type_text};
use super::java_final::{base_type, root_of};
use super::java_last::literal_kind;
use super::java_security::{call_arguments, find_node, method_name, text};
use super::java_smells::{children_of_kind, count_word};
use super::*;

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "java/infinite-loop",
        name: "Loops should not be infinite",
        description: "A loop with no way out hangs the thread.",
        message: "Add an exit, or make the loop condition real.",
        category: Bug,
        severity: Blocker,
        effort_minutes: 10,
        sonar: &[exact("S2189")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(while_statement) @match
(do_statement) @match
(for_statement) @match"#,
            filter: Some(Keep(loop_has_no_exit)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { while (true) { g(); } } }",
            good: "class A { void f() { while (true) { if (g()) { break; } } } }",
        }),
    },
    Rule {
        id: "java/zero-denominator",
        name: "Zero should not be a possible denominator",
        description: "Integer division by zero throws ArithmeticException.",
        message: "Divide by something that can't be zero.",
        category: Bug,
        severity: Critical,
        effort_minutes: 2,
        sonar: &[exact("S3518")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(binary_expression operator: ["/" "%"]) @match
(assignment_expression operator: ["/=" "%="]) @match"#,
            filter: Some(Keep(divides_by_literal_zero)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { int f(int x) { return x / 0; } }",
            good: "class A { int f(int x) { return x / 2; } }",
        }),
    },
    Rule {
        id: "java/invariant-return",
        name: "Methods returns should not be invariant",
        description: "If every return gives the same constant, the value carries no information.",
        message: "Return something that varies, or return nothing.",
        category: CodeSmell,
        severity: Blocker,
        effort_minutes: 5,
        sonar: &[exact("S3516")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Keep(returns_are_all_the_same_constant)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { int f(boolean b) { if (b) { return 0; } return 0; } }",
            good: "class A { int f(boolean b) { if (b) { return 0; } return 1; } }",
        }),
    },
    Rule {
        id: "java/redundant-assignment",
        name: "Assignments should not be redundant",
        description: "The variable already holds that value.",
        message: "Remove the assignment.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S4165")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(block) @match"#,
            filter: Some(Find(assignment_repeats_the_value)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(int x) { x = x; } }",
            good: "class A { void f(int x) { x = x + 1; } }",
        }),
    },
    Rule {
        id: "java/map-get-then-put",
        name: "Map.get and value test should be replaced with single method call",
        description: "computeIfAbsent does both in one step and one lookup.",
        message: "Use computeIfAbsent.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3824")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(block) @match"#,
            filter: Some(Find(map_get_null_check_then_put)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(Map<String, String> m, String k) { String v = m.get(k); if (v == null) { v = \"x\"; m.put(k, v); } } }",
            good: "class A { void f(Map<String, String> m, String k) { String v = m.computeIfAbsent(k, x -> \"x\"); } }",
        }),
    },
    Rule {
        id: "java/optional-get-unchecked",
        name: "Optional value should only be accessed after calling isPresent()",
        description: "get() on an empty Optional throws NoSuchElementException.",
        message: "Check isPresent(), or use orElse.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3655")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "get") arguments: (argument_list)) @match"#,
            filter: Some(Keep(optional_is_read_without_a_check)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { String f(Optional<String> o) { return o.get(); } }",
            good: "class A { String f(Optional<String> o) { return o.orElse(\"\"); } }",
        }),
    },
    Rule {
        id: "java/null-dereference",
        name: "Null pointers should not be dereferenced",
        description: "The variable is null on this path.",
        message: "Assign it before use.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2259")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(block) @match"#,
            filter: Some(Find(null_variable_is_dereferenced)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { String s = null; s.length(); } }",
            good: "class A { void f() { String s = \"a\"; s.length(); } }",
        }),
    },
    Rule {
        id: "java/resource-not-closed",
        name: "Resources should be closed",
        description: "An unclosed stream leaks a file handle.",
        message: "Use try-with-resources.",
        category: Bug,
        severity: Blocker,
        effort_minutes: 10,
        sonar: &[exact("S2095")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(local_variable_declaration) @match"#,
            filter: Some(Find(resource_is_never_closed)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() throws Exception { InputStream in = new FileInputStream(\"x\"); in.read(); } }",
            good: "class A { void f() throws Exception { try (InputStream in = new FileInputStream(\"x\")) { in.read(); } } }",
        }),
    },
    Rule {
        id: "java/constant-condition",
        name: "Conditionally executed code should be reachable",
        description: "A condition that is always true or false makes one branch dead.",
        message: "Remove the condition.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2583")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(if_statement condition: (parenthesized_expression [(true) (false)] @match))
(while_statement condition: (parenthesized_expression (false) @match))
(ternary_expression condition: [(true) (false)] @match)"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { if (false) { g(); } } }",
            good: "class A { void f(boolean b) { if (b) { g(); } } }",
        }),
    },
    Rule {
        id: "java/gratuitous-boolean",
        name: "Boolean expressions should not be gratuitous",
        description: "A literal operand makes the other side pointless.",
        message: "Remove the literal.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2589")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(binary_expression operator: ["&&" "||"]) @match"#,
            filter: Some(Keep(has_a_boolean_literal_operand)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { boolean f(boolean b) { return b && true; } }",
            good: "class A { boolean f(boolean b) { return b; } }",
        }),
    },
    Rule {
        id: "java/lock-not-released",
        name: "Locks should be released on all paths",
        description: "An exception between lock() and unlock() leaves the lock held.",
        message: "Call unlock() in a finally block.",
        category: Bug,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S2222")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(expression_statement (method_invocation name: (identifier) @n (#eq? @n "lock") arguments: (argument_list)) @match)"#,
            filter: Some(Keep(unlock_is_not_in_a_finally)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { Lock l; void f() { l.lock(); g(); l.unlock(); } }",
            good: "class A { Lock l; void f() { l.lock(); try { g(); } finally { l.unlock(); } } }",
        }),
    },
    Rule {
        id: "java/stream-intermediate-unused",
        name: "Intermediate Stream methods should not be left unused",
        description: "filter() and map() build a pipeline that never runs without a terminal operation.",
        message: "Add a terminal operation.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3958")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(expression_statement (method_invocation name: (identifier) @n (#any-of? @n "filter" "map" "sorted" "distinct" "peek" "limit" "skip" "flatMap" "boxed" "mapToInt" "mapToObj" "takeWhile" "dropWhile")) @match)"#,
            filter: Some(Keep(chain_starts_from_a_stream)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(List<String> l) { l.stream().filter(x -> true); } }",
            good: "class A { void f(List<String> l) { l.stream().filter(x -> true).count(); } }",
        }),
    },
    Rule {
        id: "java/stream-reused",
        name: "Consumed Stream pipelines should not be reused",
        description: "A stream can be consumed once.",
        message: "Create a new stream.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3959")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Find(stream_is_consumed_twice)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(List<String> l) { Stream<String> s = l.stream(); s.count(); s.forEach(x -> {}); } }",
            good: "class A { void f(List<String> l) { l.stream().count(); l.stream().forEach(x -> {}); } }",
        }),
    },
    Rule {
        id: "java/min-max-constant",
        name: "Min and max used in combination should not always return the same value",
        description: "With the bounds reversed the result is always the same constant.",
        message: "Swap the bounds.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S3065")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) @o name: (identifier) @n (#eq? @o "Math") (#any-of? @n "min" "max")) @match"#,
            filter: Some(Keep(clamp_bounds_are_reversed)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { int v = Math.min(Math.max(x, 10), 5); } }",
            good: "class A { void f() { int v = Math.min(Math.max(x, 5), 10); } }",
        }),
    },
    Rule {
        id: "java/inheritance-too-deep",
        name: "Inheritance tree of classes should not be too deep",
        description: "A deep chain hides where behaviour lives.",
        message: "Prefer composition.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 30,
        sonar: &[exact("S110")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Keep(inheritance_chain_is_deep)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A1 {}\nclass A2 extends A1 {}\nclass A3 extends A2 {}\nclass A4 extends A3 {}\nclass A5 extends A4 {}\nclass A6 extends A5 {}\nclass A7 extends A6 {}",
            good: "class A1 {}\nclass A2 extends A1 {}",
        }),
    },
    Rule {
        id: "java/static-via-subclass",
        name: "static base class members should not be accessed via derived types",
        description: "Writing the subclass hides where the member lives.",
        message: "Call it on the declaring class.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S3252")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) name: (identifier)) @match"#,
            filter: Some(Keep(static_member_called_through_subclass)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class B { static void s() {} }\nclass D extends B {}\nclass A { void f() { D.s(); } }",
            good: "class B { static void s() {} }\nclass D extends B {}\nclass A { void f() { B.s(); } }",
        }),
    },
    Rule {
        id: "java/abstract-method-redeclared",
        name: "Abstract methods should not be redundant",
        description: "The interface already declares it.",
        message: "Remove the declaration.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S3038")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Find(redeclares_an_interface_method)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "interface I { void f(); }\nabstract class A implements I { public abstract void f(); }",
            good: "interface I { void f(); }\nabstract class A implements I { }",
        }),
    },
    Rule {
        id: "java/compareto-overloaded",
        name: "compareTo should not be overloaded",
        description: "Comparable<T> calls compareTo(T); an overload with another type is never called.",
        message: "Take the Comparable's type argument.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S4351")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration name: (identifier) @n (#eq? @n "compareTo")) @match"#,
            filter: Some(Keep(compare_to_takes_another_type)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A implements Comparable<A> { public int compareTo(Object o) { return 0; } }",
            good: "class A implements Comparable<A> { public int compareTo(A o) { return 0; } }",
        }),
    },
    Rule {
        id: "java/hash-key-without-hashcode",
        name: "Classes that don't define hashCode() should not be used in hashes",
        description: "The default hashCode is the identity, so equal keys miss.",
        message: "Define equals and hashCode.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S2141")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(generic_type (type_identifier) @c (#any-of? @c "Set" "HashSet" "LinkedHashSet" "Map" "HashMap" "LinkedHashMap") (type_arguments . (type_identifier) @k)) @match"#,
            filter: Some(Keep(key_class_lacks_hash_code)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class P {}\nclass A { Set<P> s; }",
            good: "class P { public int hashCode() { return 1; } }\nclass A { Set<P> s; }",
        }),
    },
    Rule {
        id: "java/deprecated-call",
        name: "@Deprecated code should not be used",
        description: "Deprecated code is on its way out.",
        message: "Use the replacement.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S1874")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier)) @match"#,
            filter: Some(Keep(calls_a_deprecated_method_in_the_file)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { @Deprecated void old() {} void f() { old(); } }",
            good: "class A { void neu() {} void f() { neu(); } }",
        }),
    },
    Rule {
        id: "java/removal-call",
        name: "@Deprecated code marked for removal should never be used",
        description: "It will not compile in a coming release.",
        message: "Use the replacement now.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5738")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier)) @match"#,
            filter: Some(Keep(calls_a_method_marked_for_removal)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { @Deprecated(forRemoval = true) void old() {} void f() { old(); } }",
            good: "class A { void neu() {} void f() { neu(); } }",
        }),
    },
    Rule {
        id: "java/tree-key-not-comparable",
        name: "Types used as keys in Maps should implement Comparable",
        description: "A TreeMap throws ClassCastException on a key it can't order.",
        message: "Implement Comparable, or pass a Comparator.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6411")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(object_creation_expression type: (generic_type (type_identifier) @c (#any-of? @c "TreeMap" "TreeSet") (type_arguments . (type_identifier) @k)) arguments: (argument_list) @a) @match"#,
            filter: Some(Keep(key_class_is_not_comparable)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class P {}\nclass A { Object m = new TreeMap<P, String>(); }",
            good: "class P implements Comparable<P> { public int compareTo(P o) { return 0; } }\nclass A { Object m = new TreeMap<P, String>(); }",
        }),
    },
];

// ---------------------------------------------------- filters

const NESTED: &[&str] = &[
    "lambda_expression",
    "class_declaration",
    "interface_declaration",
    "enum_declaration",
    "record_declaration",
    "class_body",
];

fn nodes_in<'t>(root: Node<'t>, stops: &[&str], pred: impl Fn(Node<'t>) -> bool) -> Vec<Node<'t>> {
    let mut out = Vec::new();
    let mut cursor = root.walk();
    if !cursor.goto_first_child() {
        return out;
    }
    loop {
        let n = cursor.node();
        if pred(n) {
            out.push(n);
        }
        if !stops.contains(&n.kind()) && cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return out;
            }
        }
    }
}

fn enclosing_method(node: Node) -> Option<Node> {
    let mut p = node.parent();
    while let Some(n) = p {
        if matches!(
            n.kind(),
            "method_declaration" | "constructor_declaration" | "lambda_expression"
        ) {
            return Some(n);
        }
        p = n.parent();
    }
    None
}

fn find_declared_type<'t>(root: Node<'t>, name: &[u8], src: &[u8]) -> Option<Node<'t>> {
    find_node(root, |n| {
        matches!(
            n.kind(),
            "class_declaration"
                | "interface_declaration"
                | "record_declaration"
                | "enum_declaration"
        ) && name_text(n, src) == name
    })
}

fn has_method<'t>(class: Node<'t>, name: &[u8], src: &[u8]) -> Vec<Node<'t>> {
    class_members(class)
        .into_iter()
        .filter(|m| m.kind() == "method_declaration" && name_text(*m, src) == name)
        .collect()
}

fn superclass_name<'s>(class: Node, src: &'s [u8]) -> Option<&'s [u8]> {
    let sup = class.child_by_field_name("superclass")?;
    sup.named_child(0).map(|t| base_type(text(t, src)))
}

// ---- flow

fn can_exit(body: Node, src: &[u8]) -> bool {
    let mut stack = vec![(body, false)];
    while let Some((n, inner)) = stack.pop() {
        match n.kind() {
            "return_statement" | "throw_statement" => return true,
            "break_statement" => {
                if inner || n.named_child_count() > 0 {
                    // a labelled break may leave this loop; an inner one is for the inner loop
                    if n.named_child_count() > 0 {
                        return true;
                    }
                } else {
                    return true;
                }
            }
            "method_invocation"
                if method_name(n, src) == b"exit"
                    && n.child_by_field_name("object")
                        .is_some_and(|o| text(o, src) == b"System") =>
            {
                return true;
            }
            "lambda_expression" | "class_declaration" | "class_body" => continue,
            _ => {}
        }
        let nested = inner
            || matches!(
                n.kind(),
                "while_statement"
                    | "do_statement"
                    | "for_statement"
                    | "enhanced_for_statement"
                    | "switch_expression"
                    | "switch_statement"
            );
        let mut cursor = n.walk();
        for c in n.named_children(&mut cursor) {
            stack.push((c, nested));
        }
    }
    false
}

fn loop_has_no_exit(loop_: Node, src: &[u8]) -> bool {
    let truthy = |cond: Option<Node>| {
        cond.is_some_and(|c| {
            let inner = if c.kind() == "parenthesized_expression" {
                c.named_child(0)
            } else {
                Some(c)
            };
            inner.is_some_and(|i| i.kind() == "true")
        })
    };
    let infinite = match loop_.kind() {
        "for_statement" => {
            loop_.child_by_field_name("condition").is_none()
                || truthy(loop_.child_by_field_name("condition"))
        }
        _ => truthy(loop_.child_by_field_name("condition")),
    };
    infinite
        && loop_
            .child_by_field_name("body")
            .is_some_and(|b| !can_exit(b, src))
}

fn divides_by_literal_zero(node: Node, src: &[u8]) -> bool {
    node.child_by_field_name("right")
        .is_some_and(|r| r.kind() == "decimal_integer_literal" && text(r, src) == b"0")
        && node
            .child_by_field_name("left")
            .is_none_or(|l| l.kind() != "decimal_floating_point_literal")
}

fn returns_are_all_the_same_constant(method: Node, src: &[u8]) -> bool {
    let Some(body) = method.child_by_field_name("body") else {
        return false;
    };
    let returns = nodes_in(body, NESTED, |n| n.kind() == "return_statement");
    if returns.len() < 2 {
        return false;
    }
    let values: Vec<Option<Node>> = returns.iter().map(|r| r.named_child(0)).collect();
    let Some(Some(first)) = values.first() else {
        return false;
    };
    (literal_kind(*first).is_some() || matches!(first.kind(), "null_literal"))
        && values
            .iter()
            .all(|v| v.is_some_and(|v| text(v, src) == text(*first, src)))
}

fn assignment_repeats_the_value<'t>(block: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let assign = |s: Node<'t>| {
        (s.kind() == "expression_statement")
            .then(|| s.named_child(0))
            .flatten()
            .filter(|a| {
                a.kind() == "assignment_expression"
                    && a.child_by_field_name("operator")
                        .is_some_and(|o| text(o, src) == b"=")
            })
    };
    let items = statements(block);
    if let Some(s) = items.iter().copied().find(|s| {
        assign(*s).is_some_and(|a| {
            let (l, r) = (
                a.child_by_field_name("left"),
                a.child_by_field_name("right"),
            );
            l.zip(r)
                .is_some_and(|(l, r)| l.kind() == "identifier" && text(l, src) == text(r, src))
        })
    }) {
        return Some(s);
    }
    items.windows(2).find_map(|w| {
        let (a, b) = (assign(w[0])?, assign(w[1])?);
        let (l1, r1) = (
            a.child_by_field_name("left")?,
            a.child_by_field_name("right")?,
        );
        let (l2, r2) = (
            b.child_by_field_name("left")?,
            b.child_by_field_name("right")?,
        );
        (l1.kind() == "identifier"
            && text(l1, src) == text(l2, src)
            && text(r1, src) == text(r2, src)
            && matches!(
                r1.kind(),
                "identifier" | "string_literal" | "decimal_integer_literal" | "true" | "false"
            ))
        .then_some(w[1])
    })
}

fn map_get_null_check_then_put<'t>(block: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let items = statements(block);
    items.windows(2).find_map(|w| {
        let decl = (w[0].kind() == "local_variable_declaration").then_some(w[0])?;
        let declarator = children_of_kind(decl, "variable_declarator")
            .into_iter()
            .next()?;
        let var = text(declarator.child_by_field_name("name")?, src);
        let get = declarator
            .child_by_field_name("value")
            .filter(|v| v.kind() == "method_invocation" && method_name(*v, src) == b"get")?;
        let map = get
            .child_by_field_name("object")
            .filter(|o| o.kind() == "identifier")?;
        let key = call_arguments(get).first().copied()?;
        let ifs = (w[1].kind() == "if_statement").then_some(w[1])?;
        let cond = ifs.child_by_field_name("condition")?;
        let cond = if cond.kind() == "parenthesized_expression" {
            cond.named_child(0)?
        } else {
            cond
        };
        let null_test = cond.kind() == "binary_expression"
            && cond
                .child_by_field_name("operator")
                .is_some_and(|o| text(o, src) == b"==")
            && cond
                .child_by_field_name("left")
                .is_some_and(|l| text(l, src) == var)
            && cond
                .child_by_field_name("right")
                .is_some_and(|r| r.kind() == "null_literal");
        let puts = find_node(ifs.child_by_field_name("consequence")?, |n| {
            n.kind() == "method_invocation"
                && method_name(n, src) == b"put"
                && n.child_by_field_name("object")
                    .is_some_and(|o| text(o, src) == text(map, src))
                && call_arguments(n)
                    .first()
                    .is_some_and(|a| text(*a, src) == text(key, src))
        });
        (null_test && puts.is_some()).then_some(ifs)
    })
}

fn optional_is_read_without_a_check(call: Node, src: &[u8]) -> bool {
    let Some(object) = call
        .child_by_field_name("object")
        .filter(|o| o.kind() == "identifier")
    else {
        return false;
    };
    let name = text(object, src);
    if !base_type(type_text(declared_type(call, name, src), src)).starts_with(b"Optional") {
        return false;
    }
    let Some(method) = enclosing_method(call) else {
        return false;
    };
    let whole = text(method, src);
    ![
        &b".isPresent"[..],
        b".isEmpty",
        b".ifPresent",
        b".ifPresentOrElse",
        b".orElse",
    ]
    .iter()
    .any(|suffix| {
        let mut needle = name.to_vec();
        needle.extend_from_slice(suffix);
        whole.windows(needle.len()).any(|w| w == needle.as_slice())
    })
}

fn null_variable_is_dereferenced<'t>(block: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let items = statements(block);
    for (i, decl) in items.iter().enumerate() {
        if decl.kind() != "local_variable_declaration" {
            continue;
        }
        let Some(declarator) = children_of_kind(*decl, "variable_declarator")
            .into_iter()
            .next()
        else {
            continue;
        };
        if !declarator
            .child_by_field_name("value")
            .is_some_and(|v| v.kind() == "null_literal")
        {
            continue;
        }
        let Some(name) = declarator.child_by_field_name("name").map(|n| text(n, src)) else {
            continue;
        };
        for later in &items[i + 1..] {
            let Some(first) =
                find_node(*later, |n| n.kind() == "identifier" && text(n, src) == name)
            else {
                continue;
            };
            let parent = first.parent()?;
            // the first mention in a loop or branch may follow an assignment further down
            let nested = !matches!(
                later.kind(),
                "expression_statement" | "local_variable_declaration" | "return_statement"
            );
            let assigned_somewhere = items[i + 1..].iter().any(|s| {
                find_node(*s, |n| {
                    n.kind() == "assignment_expression"
                        && n.child_by_field_name("left")
                            .is_some_and(|l| l.kind() == "identifier" && text(l, src) == name)
                })
                .is_some()
            });
            if nested && assigned_somewhere {
                return None;
            }
            let dereferenced = match parent.kind() {
                "method_invocation" | "field_access" => {
                    parent.child_by_field_name("object") == Some(first)
                }
                "array_access" => parent.child_by_field_name("array") == Some(first),
                _ => false,
            };
            if dereferenced {
                return Some(parent);
            }
            break;
        }
    }
    None
}

fn resource_is_never_closed<'t>(decl: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    const TRACKED: &[&[u8]] = &[
        b"FileInputStream",
        b"FileOutputStream",
        b"FileReader",
        b"FileWriter",
        b"BufferedReader",
        b"BufferedWriter",
        b"InputStreamReader",
        b"OutputStreamWriter",
        b"PrintWriter",
        b"Scanner",
        b"ZipFile",
        b"Socket",
        b"ServerSocket",
        b"RandomAccessFile",
        b"DataInputStream",
        b"DataOutputStream",
        b"ObjectInputStream",
        b"ObjectOutputStream",
        b"BufferedInputStream",
        b"BufferedOutputStream",
    ];
    let declarator = children_of_kind(decl, "variable_declarator")
        .into_iter()
        .next()?;
    let value = declarator
        .child_by_field_name("value")
        .filter(|v| v.kind() == "object_creation_expression")?;
    let created = base_type(text(value.child_by_field_name("type")?, src));
    if !TRACKED.contains(&created)
        || count_word(text(value, src), b"System") > 0
        || count_word(text(value, src), b"ByteArrayOutputStream")
            + count_word(text(value, src), b"ByteArrayInputStream")
            > 0
    {
        return None;
    }
    let name_node = declarator.child_by_field_name("name")?;
    let name = text(name_node, src);
    let method = enclosing_method(decl)?;
    let mut close = name.to_vec();
    close.extend_from_slice(b".close(");
    let whole = text(method, src);
    if whole.windows(close.len()).any(|w| w == close.as_slice()) {
        return None;
    }
    let uses = nodes_in(method, &[], |n| {
        n.kind() == "identifier" && text(n, src) == name && n != name_node
    });
    let escapes = uses.iter().any(|u| {
        u.parent().is_some_and(|p| match p.kind() {
            "argument_list" | "return_statement" | "resource" => true,
            "assignment_expression" => p.child_by_field_name("right") == Some(*u),
            "variable_declarator" => p.child_by_field_name("value") == Some(*u),
            _ => false,
        })
    });
    (!escapes).then_some(name_node)
}

fn has_a_boolean_literal_operand(binary: Node, _: &[u8]) -> bool {
    let lit = |n: Option<Node>| n.is_some_and(|n| matches!(n.kind(), "true" | "false"));
    lit(binary.child_by_field_name("left")) || lit(binary.child_by_field_name("right"))
}

fn unlock_is_not_in_a_finally(call: Node, src: &[u8]) -> bool {
    let Some(object) = call
        .child_by_field_name("object")
        .filter(|o| o.kind() == "identifier")
    else {
        return false;
    };
    let name = text(object, src);
    let lock_type = type_text(declared_type(call, name, src), src);
    if count_word(lock_type, b"Lock") + count_word(lock_type, b"ReentrantLock") == 0
        && !lock_type.ends_with(b"Lock")
    {
        return false;
    }
    let Some(method) = enclosing_method(call) else {
        return false;
    };
    find_node(method, |f| {
        f.kind() == "finally_clause"
            && find_node(f, |n| {
                n.kind() == "method_invocation"
                    && method_name(n, src) == b"unlock"
                    && n.child_by_field_name("object")
                        .is_some_and(|o| text(o, src) == name)
            })
            .is_some()
    })
    .is_none()
}

fn chain_starts_from_a_stream(call: Node, src: &[u8]) -> bool {
    let mut cur = call.child_by_field_name("object");
    while let Some(c) = cur.filter(|c| c.kind() == "method_invocation") {
        if matches!(
            method_name(c, src),
            b"stream"
                | b"parallelStream"
                | b"chars"
                | b"lines"
                | b"range"
                | b"rangeClosed"
                | b"iterate"
                | b"generate"
        ) {
            return true;
        }
        cur = c.child_by_field_name("object");
    }
    false
}

fn stream_is_consumed_twice<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    const TERMINAL: &[&[u8]] = &[
        b"forEach",
        b"forEachOrdered",
        b"collect",
        b"count",
        b"reduce",
        b"anyMatch",
        b"allMatch",
        b"noneMatch",
        b"findFirst",
        b"findAny",
        b"toList",
        b"min",
        b"max",
        b"toArray",
        b"sum",
        b"average",
    ];
    let body = method.child_by_field_name("body")?;
    let decl = find_node(body, |n| {
        n.kind() == "local_variable_declaration"
            && matches!(
                base_type(type_text(n.child_by_field_name("type"), src)),
                b"Stream" | b"IntStream" | b"LongStream" | b"DoubleStream"
            )
    })?;
    let name = text(
        children_of_kind(decl, "variable_declarator")
            .into_iter()
            .next()?
            .child_by_field_name("name")?,
        src,
    );
    let terminals = nodes_in(body, &[], |n| {
        n.kind() == "method_invocation"
            && TERMINAL.contains(&method_name(n, src))
            && n.child_by_field_name("object")
                .is_some_and(|o| o.kind() == "identifier" && text(o, src) == name)
    });
    terminals.get(1).copied()
}

fn clamp_bounds_are_reversed(call: Node, src: &[u8]) -> bool {
    let value = |n: &Node| -> Option<i64> {
        (n.kind() == "decimal_integer_literal")
            .then(|| {
                String::from_utf8_lossy(text(*n, src))
                    .replace('_', "")
                    .parse()
                    .ok()
            })
            .flatten()
    };
    let (outer, inner): (&[u8], &[u8]) = if method_name(call, src) == b"min" {
        (b"min", b"max")
    } else {
        (b"max", b"min")
    };
    let args = call_arguments(call);
    let [a, b] = args.as_slice() else {
        return false;
    };
    let (nested, literal) = if a.kind() == "method_invocation" {
        (a, b)
    } else {
        (b, a)
    };
    if nested.kind() != "method_invocation"
        || method_name(*nested, src) != inner
        || !nested
            .child_by_field_name("object")
            .is_some_and(|o| text(o, src) == b"Math")
    {
        return false;
    }
    let inner_literal = call_arguments(*nested).iter().find_map(value);
    match (inner_literal, value(literal)) {
        (Some(x), Some(y)) => {
            if outer == b"min" {
                x > y
            } else {
                x < y
            }
        }
        _ => false,
    }
}

// ---- hierarchy

fn inheritance_chain_is_deep(class: Node, src: &[u8]) -> bool {
    let root = root_of(class);
    let mut depth = 0;
    let mut cur = class;
    while let Some(parent_name) = superclass_name(cur, src) {
        let Some(parent) = find_declared_type(root, parent_name, src) else {
            break;
        };
        depth += 1;
        cur = parent;
        if depth > 5 {
            return true;
        }
    }
    depth > 5
}

fn static_member_called_through_subclass(call: Node, src: &[u8]) -> bool {
    let Some(object) = call.child_by_field_name("object").filter(|o| {
        o.kind() == "identifier" && text(*o, src).first().is_some_and(u8::is_ascii_uppercase)
    }) else {
        return false;
    };
    let root = root_of(call);
    let name = method_name(call, src);
    let Some(derived) = find_declared_type(root, text(object, src), src)
        .filter(|d| d.kind() == "class_declaration")
    else {
        return false;
    };
    let Some(base) = superclass_name(derived, src).and_then(|b| find_declared_type(root, b, src))
    else {
        return false;
    };
    has_method(derived, name, src).is_empty()
        && has_method(base, name, src)
            .iter()
            .any(|m| has_modifier(*m, "static"))
}

fn redeclares_an_interface_method<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !has_modifier(class, "abstract") {
        return None;
    }
    let interfaces = class.child_by_field_name("interfaces")?;
    let root = root_of(class);
    let arity = |m: &Node| {
        m.child_by_field_name("parameters")
            .map_or(0, |p| p.named_child_count())
    };
    class_members(class).into_iter().find(|m| {
        m.kind() == "method_declaration"
            && has_modifier(*m, "abstract")
            && root_interfaces(root, interfaces, src).iter().any(|i| {
                has_method(*i, name_text(*m, src), src)
                    .iter()
                    .any(|im| arity(im) == arity(m))
            })
    })
}

fn root_interfaces<'t>(root: Node<'t>, list: Node, src: &[u8]) -> Vec<Node<'t>> {
    let mut out = Vec::new();
    let mut stack = vec![list];
    while let Some(n) = stack.pop() {
        if n.kind() == "type_identifier"
            && let Some(i) = find_declared_type(root, text(n, src), src)
                .filter(|d| d.kind() == "interface_declaration")
        {
            out.push(i);
        }
        let mut c = n.walk();
        stack.extend(n.named_children(&mut c));
    }
    out
}

fn compare_to_takes_another_type(method: Node, src: &[u8]) -> bool {
    let Some(class) = super::java_smells::enclosing_class(method) else {
        return false;
    };
    let Some(interfaces) = class.child_by_field_name("interfaces") else {
        return false;
    };
    let t = text(interfaces, src);
    let Some(start) = t.windows(11).position(|w| w == b"Comparable<") else {
        return false;
    };
    let rest = &t[start + 11..];
    let mut depth = 1;
    let mut end = None;
    for (i, &b) in rest.iter().enumerate() {
        match b {
            b'<' => depth += 1,
            b'>' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let Some(end) = end else {
        return false;
    };
    let want = &rest[..end];
    method
        .child_by_field_name("parameters")
        .and_then(|p| p.named_child(0))
        .and_then(|p| p.child_by_field_name("type"))
        .is_some_and(|ty| text(ty, src) != want)
}

fn first_type_argument<'s>(node: Node, src: &'s [u8]) -> Option<&'s [u8]> {
    let args = find_node(node, |n| n.kind() == "type_arguments")?;
    args.named_child(0).map(|t| text(t, src))
}

fn key_class_lacks_hash_code(generic: Node, src: &[u8]) -> bool {
    let Some(key) = first_type_argument(generic, src) else {
        return false;
    };
    find_declared_type(root_of(generic), key, src).is_some_and(|c| {
        c.kind() == "class_declaration"
            && c.child_by_field_name("superclass").is_none()
            && has_method(c, b"hashCode", src).is_empty()
    })
}

fn key_class_is_not_comparable(creation: Node, src: &[u8]) -> bool {
    let Some(key) = first_type_argument(creation, src) else {
        return false;
    };
    find_declared_type(root_of(creation), key, src).is_some_and(|c| {
        c.kind() == "class_declaration"
            && c.child_by_field_name("superclass").is_none()
            && c.child_by_field_name("interfaces")
                .is_none_or(|i| count_word(text(i, src), b"Comparable") == 0)
    })
}

fn deprecated_target<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if call.child_by_field_name("object").is_some() {
        return None;
    }
    let class = super::java_smells::enclosing_class(call)?;
    let caller = enclosing_method(call);
    let arity = call_arguments(call).len();
    // an overload with the same arity may be the one called: only flag when all are deprecated
    let candidates: Vec<Node> = has_method(class, method_name(call, src), src)
        .into_iter()
        .filter(|m| {
            m.child_by_field_name("parameters")
                .map_or(0, |p| p.named_child_count())
                == arity
        })
        .collect();
    let first = candidates.first().copied()?;
    (candidates
        .iter()
        .all(|m| has_annotation(*m, b"Deprecated", src))
        && Some(first) != caller)
        .then_some(first)
        .filter(|_| caller.is_none_or(|c| !has_annotation(c, b"Deprecated", src)))
}

fn calls_a_deprecated_method_in_the_file(call: Node, src: &[u8]) -> bool {
    deprecated_target(call, src).is_some()
}

fn calls_a_method_marked_for_removal(call: Node, src: &[u8]) -> bool {
    deprecated_target(call, src).is_some_and(|m| {
        let t = text(m.child(0).unwrap_or(m), src);
        count_word(t, b"forRemoval") > 0 && count_word(t, b"true") > 0
    })
}

#[cfg(test)]
mod tests {
    use crate::analysis::analyze;
    use crate::analysis::tests::far_deadline;
    use crate::config::Config;
    use crate::lang::Lang;
    use crate::rules::RuleSet;

    fn flagged(rule: &str, src: &str) -> Vec<usize> {
        let mut cfg = Config::default();
        cfg.rules.enabled = vec![rule.to_string()];
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let file = analyze("t", Lang::Java, src, &rules, &cfg, far_deadline()).unwrap();
        file.issues
            .iter()
            .filter(|i| i.rule == rule)
            .map(|i| i.line)
            .collect()
    }

    #[test]
    fn loops_and_resources() {
        let src = "class A {\n void f() {\n  while (true) { g(); }\n  while (true) { if (g()) { break; } }\n  for (;;) { for (int i = 0; i < 3; i++) { break; } }\n  while (true) { try { g(); } catch (E e) { return; } }\n  InputStream a = new FileInputStream(\"x\");\n  a.read();\n  InputStream b = new FileInputStream(\"y\");\n  b.close();\n  InputStream c = new FileInputStream(\"z\");\n  use(c);\n  Scanner s = new Scanner(System.in);\n }\n}";
        assert_eq!(flagged("java/infinite-loop", src), [3, 5]);
        assert_eq!(flagged("java/resource-not-closed", src), [7]);
    }

    #[test]
    fn null_optional_and_locks() {
        let src = "class A {\n Lock l;\n void f(Optional<String> o, Optional<String> p) {\n  o.get();\n  if (p.isPresent()) { p.get(); }\n  String s = null;\n  s.length();\n  String t = null;\n  if (x) { t = \"a\"; }\n  t.length();\n  l.lock();\n  g();\n  l.unlock();\n }\n void h() {\n  l.lock();\n  try { g(); } finally { l.unlock(); }\n }\n}";
        assert_eq!(flagged("java/optional-get-unchecked", src), [4]);
        assert_eq!(flagged("java/null-dereference", src), [7]);
        assert_eq!(flagged("java/lock-not-released", src), [11]);
    }

    #[test]
    fn streams_and_math() {
        let src = "class A {\n void f(List<String> l) {\n  l.stream().filter(x -> true);\n  l.stream().filter(x -> true).count();\n  Stream<String> s = l.stream();\n  s.count();\n  s.forEach(x -> {});\n  int v = Math.min(Math.max(x, 10), 5);\n  int w = Math.min(Math.max(x, 1), 5);\n  int z = x / 0;\n }\n int g(boolean b) { if (b) { return 0; } return 0; }\n}";
        assert_eq!(flagged("java/stream-intermediate-unused", src), [3]);
        assert_eq!(flagged("java/stream-reused", src), [7]);
        assert_eq!(flagged("java/min-max-constant", src), [8]);
        assert_eq!(flagged("java/zero-denominator", src), [10]);
        assert_eq!(flagged("java/invariant-return", src), [12]);
    }

    #[test]
    fn hierarchy() {
        let src = "interface I { void f(); }\nclass B { static void s() {} }\nclass D extends B {}\nabstract class C implements I { public abstract void f(); }\nclass P implements Comparable<P> { public int compareTo(Object o) { return 0; } }\nclass K {}\nclass U { Set<K> s; Object m = new TreeMap<K, String>(); void t() { D.s(); B.s(); } }";
        assert_eq!(flagged("java/static-via-subclass", src), [7]);
        assert_eq!(flagged("java/abstract-method-redeclared", src), [4]);
        assert_eq!(flagged("java/compareto-overloaded", src), [5]);
        assert_eq!(flagged("java/hash-key-without-hashcode", src), [7]);
        assert_eq!(flagged("java/tree-key-not-comparable", src), [7]);
    }
}
