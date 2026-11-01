//! The last Java rules that need only one file's syntax (ADR-0007, batch
//! 14): brace layout, loop and collection checks, and a few declared-type
//! checks.

use super::java_bugs::{has_modifier, statements};
use super::java_extra::{class_members, declared_type, name_text, type_text};
use super::java_final::{base_type, key_type_is_an_enum_in_the_file, named_children_of, root_of};
use super::java_last::count_nodes;
use super::java_security::{call_arguments, find_node, method_name, text};
use super::java_smells::{children_of_kind, count_word};
use super::*;

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "java/brace-on-its-own-line",
        name: "An open curly brace should be located at the end of a line",
        description: "The brace belongs with the statement it opens.",
        message: "Move the brace up to the previous line.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S1105")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(block "{" @match)
(class_body "{" @match)
(interface_body "{" @match)
(enum_body "{" @match)
(switch_block "{" @match)"#,
            filter: Some(Keep(opening_brace_starts_a_line)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A\n{\n}",
            good: "class A {\n}",
        }),
    },
    Rule {
        id: "java/brace-at-line-end",
        name: "An open curly brace should be located at the beginning of a line",
        description: "Allman style puts every brace on its own line.",
        message: "Move the brace to its own line.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S1106")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(block "{" @match)
(class_body "{" @match)
(interface_body "{" @match)
(enum_body "{" @match)
(switch_block "{" @match)"#,
            filter: Some(Keep(opening_brace_ends_a_line)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A {\n}",
            good: "class A\n{\n}",
        }),
    },
    Rule {
        id: "java/else-on-another-line",
        name: "Close curly brace and the next else, catch and finally keywords should be located on the same line",
        description: "Cuddled else keeps the chain together.",
        message: "Put the keyword after the brace.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S1107")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(if_statement "else" @match)
(try_statement (catch_clause) @match)
(try_statement (finally_clause) @match)"#,
            filter: Some(Keep(keyword_is_on_another_line)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { if (a) {\n g();\n}\nelse {\n h();\n} } }",
            good: "class A { void f() { if (a) {\n g();\n} else {\n h();\n} } }",
        }),
    },
    Rule {
        id: "java/else-on-the-same-line",
        name: "Close curly brace and the next else, catch and finally keywords should be on two different lines",
        description: "Allman style puts the keyword on its own line.",
        message: "Put the keyword on a new line.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S1108")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(if_statement "else" @match)
(try_statement (catch_clause) @match)
(try_statement (finally_clause) @match)"#,
            filter: Some(Keep(keyword_follows_the_brace)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { if (a) {\n g();\n} else {\n h();\n} } }",
            good: "class A { void f() { if (a) {\n g();\n}\nelse {\n h();\n} } }",
        }),
    },
    Rule {
        id: "java/closing-brace-not-first",
        name: "A close curly brace should be located at the beginning of a line",
        description: "A brace after code is easy to miss.",
        message: "Put the brace on its own line.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S1109")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(block "}" @match)
(class_body "}" @match)
(interface_body "}" @match)
(enum_body "}" @match)
(switch_block "}" @match)"#,
            filter: Some(Keep(closing_brace_follows_code)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() {\n g(); }\n}",
            good: "class A { void f() {\n g();\n}\n}",
        }),
    },
    Rule {
        id: "java/loop-bound-changes",
        name: "for loop stop conditions should be invariant",
        description: "Changing the bound inside the body makes the loop's length hard to predict.",
        message: "Compute the bound once, before the loop.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S127")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(for_statement) @match"#,
            filter: Some(Find(body_modifies_the_loop_bound)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(int n) { for (int i = 0; i < n; i++) { n--; } } }",
            good: "class A { void f(int n) { for (int i = 0; i < n; i++) { g(); } } }",
        }),
    },
    Rule {
        id: "java/enum-set",
        name: "Sets with elements that are enum values should be replaced with EnumSet",
        description: "EnumSet is faster and smaller.",
        message: "Use EnumSet.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S1641")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(object_creation_expression type: (generic_type (type_identifier) @c (#any-of? @c "HashSet" "TreeSet") (type_arguments . (type_identifier) @k))) @match"#,
            filter: Some(Keep(key_type_is_an_enum_in_the_file)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "enum Color { RED }\nclass A { Object s = new HashSet<Color>(); }",
            good: "enum Color { RED }\nclass A { Object s = EnumSet.noneOf(Color.class); }",
        }),
    },
    Rule {
        id: "java/identity-with-equals",
        name: "== and != should not be used when equals is overridden",
        description: "Two equal objects can be different instances.",
        message: "Use equals().",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1698")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(binary_expression operator: ["==" "!="]) @match"#,
            filter: Some(Keep(compares_instances_of_an_equals_class)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class P { public boolean equals(Object o) { return true; } }\nclass A { boolean f(P a, P b) { return a == b; } }",
            good: "class P { public boolean equals(Object o) { return true; } }\nclass A { boolean f(P a, P b) { return a.equals(b); } }",
        }),
    },
    Rule {
        id: "java/functional-interface-redefined",
        name: "Standard functional interfaces should not be redefined",
        description: "java.util.function already has this shape.",
        message: "Use the standard interface.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S1711")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(interface_declaration) @match"#,
            filter: Some(Keep(repeats_a_standard_functional_interface)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "interface Maker { String get(); }",
            good: "interface Maker { String get(); String other(); }",
        }),
    },
    Rule {
        id: "java/wait-on-condition",
        name: "Object.wait should not be called on objects that implement Condition",
        description: "Condition has await() and signal() for this.",
        message: "Call await().",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1844")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "wait")) @match"#,
            filter: Some(Keep(waits_on_a_condition)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(Condition c) { c.wait(); } }",
            good: "class A { void f(Condition c) { c.await(); } }",
        }),
    },
    Rule {
        id: "java/static-member-via-instance",
        name: "static members should be accessed statically",
        description: "Calling a static method on an instance suggests it is not.",
        message: "Call it on the class.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2209")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) name: (identifier)) @match"#,
            filter: Some(Keep(calls_a_static_method_on_an_instance)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class U { static void f() {} }\nclass A { void g(U u) { u.f(); } }",
            good: "class U { static void f() {} }\nclass A { void g() { U.f(); } }",
        }),
    },
    Rule {
        id: "java/lambda-explicit-types",
        name: "Types should be used in lambdas",
        description: "Repeating the parameter types adds noise.",
        message: "Remove the types.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S2211")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(lambda_expression parameters: (formal_parameters) @match)"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Runnable r = null; java.util.function.Function<String, Integer> f = (String s) -> s.length(); } }",
            good: "class A { void f() { java.util.function.Function<String, Integer> f = s -> s.length(); } }",
        }),
    },
    Rule {
        id: "java/inner-class-static",
        name: "Inner classes which do not reference their owning classes should be static",
        description: "A non-static inner class carries a hidden reference to its outer instance.",
        message: "Make it static.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2694")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_body (class_declaration) @match)"#,
            filter: Some(Keep(inner_class_ignores_the_outer)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { int n; class B { int m; } }",
            good: "class A { int n; static class B { int m; } }",
        }),
    },
    Rule {
        id: "java/get-class-loader",
        name: "JEE applications should not getClassLoader",
        description: "Application servers manage class loaders themselves.",
        message: "Use the context class loader.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3032")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "getClassLoader")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { ClassLoader c = A.class.getClassLoader(); } }",
            good: "class A { void f() { ClassLoader c = Thread.currentThread().getContextClassLoader(); } }",
        }),
    },
    Rule {
        id: "java/string-index-bounds",
        name: "Indexes passed to String operations should be within the string's bounds",
        description: "A negative or inverted index throws StringIndexOutOfBoundsException.",
        message: "Fix the index.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S3039")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "substring" "charAt" "subSequence")) @match"#,
            filter: Some(Keep(index_is_out_of_bounds)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { String t = s.substring(-1); } }",
            good: "class A { void f() { String t = s.substring(1); } }",
        }),
    },
    Rule {
        id: "java/loops-over-same-collection",
        name: "Multiple loops over the same set should be combined",
        description: "Two passes over one collection can be one.",
        message: "Merge the loops.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S3047")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(block) @match"#,
            filter: Some(Find(consecutive_loops_over_one_collection)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(List<String> l) { for (String s : l) { a(s); } for (String s : l) { b(s); } } }",
            good: "class A { void f(List<String> l) { for (String s : l) { a(s); b(s); } } }",
        }),
    },
    Rule {
        id: "java/collection-never-read",
        name: "Collection contents should be used",
        description: "A collection that is filled and never read is dead code.",
        message: "Use it, or remove it.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S4030")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Find(collection_is_only_written)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { List<String> l = new ArrayList<>(); l.add(\"x\"); } }",
            good: "class A { List<String> f() { List<String> l = new ArrayList<>(); l.add(\"x\"); return l; } }",
        }),
    },
    Rule {
        id: "java/member-order",
        name: "The members of an interface or class declaration should appear in a pre-defined order",
        description: "Fields, then constructors, then methods.",
        message: "Move the member.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S1213")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Find(member_is_out_of_order)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() {} int n; }",
            good: "class A { int n; void f() {} }",
        }),
    },
    Rule {
        id: "java/missing-license-header",
        name: "Track lack of copyright and license headers",
        description: "A header states who owns the file and under which terms it is shared.",
        message: "Add the header.",
        category: CodeSmell,
        severity: Blocker,
        effort_minutes: 5,
        sonar: &[exact("S1451")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(program) @match"#,
            filter: Some(Find(lacks_a_license_header)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A {}",
            good: "class A { void f() { /* Copyright 2026 Example Ltd. */\nclass A {} } }",
        }),
    },
];

// ---------------------------------------------------- filters

fn first_on_its_line(node: Node, src: &[u8]) -> bool {
    let start = node.start_byte();
    let line_start = src[..start]
        .iter()
        .rposition(|&b| b == b'\n')
        .map_or(0, |i| i + 1);
    src[line_start..start].iter().all(u8::is_ascii_whitespace)
}

fn spans_several_lines(node: Node) -> bool {
    node.start_position().row != node.end_position().row
}

fn opening_brace_starts_a_line(brace: Node, src: &[u8]) -> bool {
    first_on_its_line(brace, src)
}

fn opening_brace_ends_a_line(brace: Node, src: &[u8]) -> bool {
    !first_on_its_line(brace, src) && brace.parent().is_some_and(spans_several_lines)
}

fn closing_brace_follows_code(brace: Node, src: &[u8]) -> bool {
    !first_on_its_line(brace, src) && brace.parent().is_some_and(spans_several_lines)
}

fn preceding_brace_row(keyword: Node) -> Option<usize> {
    let prev = keyword.prev_sibling()?;
    matches!(prev.kind(), "block" | "catch_clause").then(|| prev.end_position().row)
}

fn keyword_is_on_another_line(keyword: Node, _: &[u8]) -> bool {
    preceding_brace_row(keyword).is_some_and(|row| row != keyword.start_position().row)
}

fn keyword_follows_the_brace(keyword: Node, _: &[u8]) -> bool {
    preceding_brace_row(keyword).is_some_and(|row| row == keyword.start_position().row)
}

fn body_modifies_the_loop_bound<'t>(for_statement: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let condition = for_statement.child_by_field_name("condition")?;
    let mut cursor = for_statement.walk();
    let updates: Vec<Node> = for_statement
        .children_by_field_name("update", &mut cursor)
        .collect();
    if updates.is_empty() {
        return None;
    }
    let idents = |n: Node| -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut stack = vec![n];
        while let Some(x) = stack.pop() {
            if x.kind() == "identifier" {
                out.push(text(x, src).to_vec());
            }
            let mut c = x.walk();
            stack.extend(x.named_children(&mut c));
        }
        out
    };
    let updated: Vec<Vec<u8>> = updates.iter().flat_map(|u| idents(*u)).collect();
    // method calls in the condition (list.size()) are not plain variables
    // only operands of a comparison are bounds; a bare flag is a different idiom
    let mut compared: Vec<Vec<u8>> = Vec::new();
    let mut stack = vec![condition];
    while let Some(x) = stack.pop() {
        if x.kind() == "binary_expression"
            && x.child_by_field_name("operator").is_some_and(|o| {
                matches!(text(o, src), b"<" | b"<=" | b">" | b">=" | b"!=" | b"==")
            })
        {
            for side in ["left", "right"] {
                if let Some(s) = x
                    .child_by_field_name(side)
                    .filter(|s| s.kind() == "identifier")
                {
                    compared.push(text(s, src).to_vec());
                }
            }
        }
        let mut c = x.walk();
        stack.extend(x.named_children(&mut c));
    }
    let bound: Vec<Vec<u8>> = compared
        .into_iter()
        .filter(|i| !updated.contains(i))
        .collect();
    let body = for_statement.child_by_field_name("body")?;
    find_node(body, |n| {
        let target = match n.kind() {
            "assignment_expression" => n.child_by_field_name("left"),
            "update_expression" => n.named_child(0),
            _ => None,
        };
        target.is_some_and(|t| {
            t.kind() == "identifier" && bound.iter().any(|b| b.as_slice() == text(t, src))
        })
    })
}

fn compares_instances_of_an_equals_class(binary: Node, src: &[u8]) -> bool {
    let operand = |n: Option<Node>| -> Option<Vec<u8>> {
        let n = n.filter(|n| n.kind() == "identifier")?;
        let t = declared_type(binary, text(n, src), src)?;
        Some(base_type(text(t, src)).to_vec())
    };
    let (Some(a), Some(b)) = (
        operand(binary.child_by_field_name("left")),
        operand(binary.child_by_field_name("right")),
    ) else {
        return false;
    };
    a == b
        && find_node(root_of(binary), |n| {
            matches!(n.kind(), "class_declaration" | "record_declaration")
                && name_text(n, src) == a.as_slice()
                && class_members(n)
                    .iter()
                    .any(|m| m.kind() == "method_declaration" && name_text(*m, src) == b"equals")
        })
        .is_some()
}

fn repeats_a_standard_functional_interface(iface: Node, src: &[u8]) -> bool {
    if !children_of_kind(iface, "extends_interfaces").is_empty() {
        return false;
    }
    let members = class_members(iface);
    let [only] = members.as_slice() else {
        return false;
    };
    if only.kind() != "method_declaration" || only.child_by_field_name("body").is_some() {
        return false;
    }
    let params = only
        .child_by_field_name("parameters")
        .map_or(0, |p| p.named_child_count());
    let returns = only
        .child_by_field_name("type")
        .map_or(&b""[..], |t| text(t, src));
    match name_text(*only, src) {
        b"get" => params == 0 && returns != b"void",
        b"accept" => (1..=2).contains(&params) && returns == b"void",
        b"test" => (1..=2).contains(&params) && returns == b"boolean",
        b"apply" => (1..=2).contains(&params) && returns != b"void" && returns != b"boolean",
        _ => false,
    }
}

fn waits_on_a_condition(call: Node, src: &[u8]) -> bool {
    call.child_by_field_name("object").is_some_and(|o| {
        o.kind() == "identifier"
            && base_type(type_text(declared_type(call, text(o, src), src), src))
                .ends_with(b"Condition")
    })
}

fn calls_a_static_method_on_an_instance(call: Node, src: &[u8]) -> bool {
    let Some(object) = call.child_by_field_name("object") else {
        return false;
    };
    let t = base_type(type_text(declared_type(call, text(object, src), src), src));
    if t.is_empty() {
        return false;
    }
    let name = method_name(call, src);
    find_node(root_of(call), |n| {
        n.kind() == "class_declaration" && name_text(n, src) == t && {
            let methods: Vec<Node> = class_members(n)
                .into_iter()
                .filter(|m| m.kind() == "method_declaration" && name_text(*m, src) == name)
                .collect();
            !methods.is_empty() && methods.iter().all(|m| has_modifier(*m, "static"))
        }
    })
    .is_some()
}

fn inner_class_ignores_the_outer(inner: Node, src: &[u8]) -> bool {
    if has_modifier(inner, "static") {
        return false;
    }
    let Some(outer) = inner
        .parent()
        .and_then(|b| b.parent())
        .filter(|c| c.kind() == "class_declaration")
    else {
        return false;
    };
    let whole = text(inner, src);
    if count_word(whole, name_text(outer, src)) > 0 {
        return false;
    }
    let instance_names: Vec<&[u8]> = class_members(outer)
        .iter()
        .filter(|m| !has_modifier(**m, "static"))
        .flat_map(|m| match m.kind() {
            "field_declaration" => super::java_smells::declarator_names(*m, src),
            "method_declaration" => vec![name_text(*m, src)],
            _ => Vec::new(),
        })
        .collect();
    !instance_names.iter().any(|n| count_word(whole, n) > 0)
        && inner.child_by_field_name("superclass").is_none()
}

fn index_is_out_of_bounds(call: Node, src: &[u8]) -> bool {
    // CharSequenceUtils.subSequence(x, -1) is a utility under test, not String
    if call.child_by_field_name("object").is_some_and(|o| {
        o.kind() == "identifier" && text(o, src).first().is_some_and(u8::is_ascii_uppercase)
    }) {
        return false;
    }
    let args = call_arguments(call);
    let negative = |a: &Node| a.kind() == "unary_expression" && text(*a, src).starts_with(b"-");
    if args.iter().any(negative) {
        return true;
    }
    if method_name(call, src) == b"substring" || method_name(call, src) == b"subSequence" {
        let value = |a: &Node| -> Option<u64> {
            (a.kind() == "decimal_integer_literal")
                .then(|| {
                    String::from_utf8_lossy(text(*a, src))
                        .replace('_', "")
                        .parse()
                        .ok()
                })
                .flatten()
        };
        if let [a, b] = args.as_slice() {
            return value(a).zip(value(b)).is_some_and(|(x, y)| x > y);
        }
    }
    false
}

fn consecutive_loops_over_one_collection<'t>(block: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let items = statements(block);
    items.windows(2).find_map(|w| {
        let iterated = |s: Node| {
            (s.kind() == "enhanced_for_statement")
                .then(|| s.child_by_field_name("value"))
                .flatten()
                .filter(|v| v.kind() == "identifier")
                .map(|v| text(v, src))
        };
        let (a, b) = (iterated(w[0])?, iterated(w[1])?);
        (a == b).then_some(w[1])
    })
}

fn collection_is_only_written<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    const COLLECTIONS: &[&[u8]] = &[
        b"List",
        b"ArrayList",
        b"LinkedList",
        b"Set",
        b"HashSet",
        b"TreeSet",
        b"LinkedHashSet",
        b"Map",
        b"HashMap",
        b"TreeMap",
        b"LinkedHashMap",
        b"Collection",
        b"Deque",
        b"ArrayDeque",
        b"Queue",
    ];
    let body = method.child_by_field_name("body")?;
    let declaration = find_node(body, |n| {
        n.kind() == "local_variable_declaration"
            && COLLECTIONS.contains(&base_type(type_text(n.child_by_field_name("type"), src)))
    })?;
    let declarator = children_of_kind(declaration, "variable_declarator")
        .into_iter()
        .next()?;
    let name_node = declarator.child_by_field_name("name")?;
    let name = text(name_node, src);
    let uses = count_nodes(body, &[], |n| {
        n.kind() == "identifier" && text(n, src) == name && n != name_node
    });
    let writes = count_nodes(body, &[], |n| {
        n.kind() == "method_invocation"
            && matches!(
                method_name(n, src),
                b"add"
                    | b"put"
                    | b"addAll"
                    | b"putAll"
                    | b"clear"
                    | b"remove"
                    | b"offer"
                    | b"push"
                    | b"addFirst"
                    | b"addLast"
                    | b"putIfAbsent"
            )
            && n.child_by_field_name("object")
                .is_some_and(|o| o.kind() == "identifier" && text(o, src) == name)
            && n.parent()
                .is_some_and(|p| p.kind() == "expression_statement")
    });
    (uses > 0 && uses == writes).then_some(name_node)
}

fn member_is_out_of_order<'t>(class: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    let mut highest = 0;
    for m in class_members(class) {
        let rank = match m.kind() {
            "field_declaration" => 1,
            "constructor_declaration" => 2,
            "method_declaration" => 3,
            _ => continue,
        };
        if rank < highest {
            return Some(m);
        }
        highest = highest.max(rank);
    }
    None
}

fn lacks_a_license_header<'t>(program: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let head: Vec<u8> = src
        .split(|&b| b == b'\n')
        .take(8)
        .flat_map(|l| l.iter().copied().chain(*b"\n"))
        .collect();
    let has = ["copyright", "license", "licence"]
        .iter()
        .any(|w| super::java_security::contains_ignoring_case(&head, w.as_bytes()));
    (!has)
        .then(|| named_children_of(program).into_iter().next())
        .flatten()
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
    fn braces_and_keywords() {
        let src = "class A {\n void f()\n {\n  if (a) {\n   g();\n  }\n  else {\n   h();\n  }\n  try {\n   g();\n  } catch (E e) {\n   h(); }\n }\n}";
        assert_eq!(flagged("java/brace-on-its-own-line", src), [3]);
        assert_eq!(flagged("java/else-on-another-line", src), [7]);
        assert_eq!(flagged("java/else-on-the-same-line", src), [12]);
        assert_eq!(flagged("java/closing-brace-not-first", src), [13]);
    }

    #[test]
    fn loops_and_collections() {
        let src = "class A {\n void f(int n, List<String> l) {\n  for (int i = 0; i < n; i++) { n--; }\n  for (int i = 0; i < n; i++) { g(i); }\n  for (String s : l) { a(s); }\n  for (String s : l) { b(s); }\n  List<String> tmp = new ArrayList<>();\n  tmp.add(\"x\");\n  String t = s.substring(3, 1);\n  String u = s.substring(1, 3);\n }\n}";
        assert_eq!(flagged("java/loop-bound-changes", src), [3]);
        assert_eq!(flagged("java/loops-over-same-collection", src), [6]);
        assert_eq!(flagged("java/collection-never-read", src), [7]);
        assert_eq!(flagged("java/string-index-bounds", src), [9]);
    }

    #[test]
    fn declared_types_and_members() {
        let src = "class P { public boolean equals(Object o) { return true; } static void s() {} void i() {} }\nclass A {\n int n;\n class In { int m; }\n class Uses { int k() { return n; } }\n void f(P a, P b, Condition c) {\n  boolean x = a == b;\n  a.s();\n  a.i();\n  c.wait();\n }\n A() {}\n int z;\n}";
        assert_eq!(flagged("java/identity-with-equals", src), [7]);
        assert_eq!(flagged("java/static-member-via-instance", src), [8]);
        assert_eq!(flagged("java/wait-on-condition", src), [10]);
        assert_eq!(flagged("java/inner-class-static", src), [4]);
        assert_eq!(flagged("java/member-order", src), [12]);
    }
}
