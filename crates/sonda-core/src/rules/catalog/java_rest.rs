//! The last cheap Java rules (ADR-0007, batch 15): wrappers in ternaries,
//! persistence and session checks, and a few loop and constructor-reference
//! mistakes.

use super::java_bugs::{has_annotation, has_modifier};
use super::java_extra::{class_members, declared_type, name_text, type_text};
use super::java_final::{base_type, root_of};
use super::java_security::{call_arguments, find_node, method_name, text};
use super::java_smells::{children_of_kind, count_word};
use super::*;

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "java/ternary-boxed-mix",
        name: "Dissimilar primitive wrappers should not be used with the ternary operator without explicit casting",
        description: "Integer and Double branches unbox and promote, so a null throws and an int silently becomes a double.",
        message: "Cast one branch.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2154")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(ternary_expression) @match"#,
            filter: Some(Keep(ternary_mixes_boxed_numbers)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { Number f(boolean b, Integer i, Double d) { return b ? i : d; } }",
            good: "class A { Number f(boolean b, Integer i, Integer j) { return b ? i : j; } }",
        }),
    },
    Rule {
        id: "java/persistence-annotation-mix",
        name: "Do not mix field and getter persistence annotations",
        description: "JPA uses the placement of @Id to pick field or property access, and ignores the other.",
        message: "Annotate only fields or only getters.",
        category: Bug,
        severity: Blocker,
        effort_minutes: 5,
        sonar: &[exact("S2206")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Find(mixes_field_and_getter_annotations)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "@Entity class A { @Id Long id; @Column String getName() { return null; } }",
            good: "@Entity class A { @Id Long id; @Column String name; }",
        }),
    },
    Rule {
        id: "java/session-attribute-not-serializable",
        name: "Non-serializable objects should not be stored in HttpSession instances",
        description: "Session replication and passivation need serializable values.",
        message: "Make the class Serializable.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2441")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "setAttribute" "putValue")) @match"#,
            filter: Some(Keep(stores_a_non_serializable_object)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class P {}\nclass A { void f(HttpSession s) { s.setAttribute(\"p\", new P()); } }",
            good: "class P implements Serializable {}\nclass A { void f(HttpSession s) { s.setAttribute(\"p\", new P()); } }",
        }),
    },
    Rule {
        id: "java/session-attributes-not-completed",
        name: "@Controller classes that use @SessionAttributes must call setComplete on their SessionStatus",
        description: "Without it the attributes live until the session ends.",
        message: "Call setComplete().",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3753")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Keep(session_attributes_never_completed)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "@Controller @SessionAttributes(\"x\") class A { void f() {} }",
            good: "@Controller @SessionAttributes(\"x\") class A { void f(SessionStatus s) { s.setComplete(); } }",
        }),
    },
    Rule {
        id: "java/unindented-conditional",
        name: "A conditionally executed single line should be denoted by indentation",
        description: "A statement at the same indent as its if looks unconditional.",
        message: "Indent it or add braces.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S3973")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(if_statement consequence: (_) @match)
(while_statement body: (_) @match)
(for_statement body: (_) @match)"#,
            filter: Some(Keep(single_line_is_not_indented)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() {\n if (a)\n g();\n } }",
            good: "class A { void f() {\n if (a)\n  g();\n } }",
        }),
    },
    Rule {
        id: "java/collection-constructor-as-function",
        name: "Collection constructors should not be used as java.util.function.Function",
        description: "ArrayList::new used as a Function takes the argument as the initial capacity.",
        message: "Use a lambda.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5329")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "map" "flatMap" "mapToObj" "apply") arguments: (argument_list (method_reference (identifier) @c "::" "new" (#any-of? @c "ArrayList" "HashSet" "HashMap" "LinkedList" "ArrayDeque" "StringBuilder" "Vector")))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { stream.map(ArrayList::new); } }",
            good: "class A { void f() { stream.map(x -> new ArrayList<>(x)); } }",
        }),
    },
    Rule {
        id: "java/list-remove-in-loop",
        name: "List.remove() should not be used in ascending for loops",
        description: "Removing shifts the elements, so the next one is skipped.",
        message: "Iterate downwards or use an iterator.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5413")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(for_statement) @match"#,
            filter: Some(Find(ascending_loop_removes_by_index)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(List<String> l) { for (int i = 0; i < l.size(); i++) { l.remove(i); } } }",
            good: "class A { void f(List<String> l) { for (int i = l.size() - 1; i >= 0; i--) { l.remove(i); } } }",
        }),
    },
    Rule {
        id: "java/index-of-range",
        name: "String.indexOf should be used with correct ranges",
        description: "A negative from-index is treated as 0, which hides a bug.",
        message: "Fix the index.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6915")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "indexOf" "lastIndexOf") arguments: (argument_list (_) (unary_expression) @match))"#,
            filter: Some(Keep(receiver_is_an_instance)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { int i = s.indexOf(\"x\", -1); } }",
            good: "class A { void f() { int i = s.indexOf(\"x\", 0); } }",
        }),
    },
    Rule {
        id: "java/subclass-adds-fields-not-equals",
        name: "Subclasses that add fields to classes that override equals should also override equals",
        description: "Two instances can compare equal while differing in the new fields.",
        message: "Override equals in the subclass.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S2160")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(program) @match"#,
            filter: Some(Find(subclass_adds_fields_without_equals)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class P { public boolean equals(Object o) { return true; } }\nclass C extends P { int extra; }",
            good: "class P { public boolean equals(Object o) { return true; } }\nclass C extends P { int extra; public boolean equals(Object o) { return true; } }",
        }),
    },
];

// ---------------------------------------------------- filters

fn receiver_is_an_instance(negative: Node, src: &[u8]) -> bool {
    // a static utility such as StringUtils.indexOf(s, c, -1) defines its own semantics
    let call = negative.parent().and_then(|a| a.parent());
    call.is_some_and(|c| {
        c.child_by_field_name("object").is_none_or(|o| {
            !(o.kind() == "identifier" && text(o, src).first().is_some_and(u8::is_ascii_uppercase))
        })
    })
}

fn ternary_mixes_boxed_numbers(ternary: Node, src: &[u8]) -> bool {
    const BOXED: &[&[u8]] = &[b"Integer", b"Long", b"Double", b"Float", b"Short", b"Byte"];
    let boxed = |n: Option<Node>| -> Option<Vec<u8>> {
        let n = n.filter(|n| n.kind() == "identifier")?;
        let t = type_text(declared_type(ternary, text(n, src), src), src);
        BOXED.contains(&t).then(|| t.to_vec())
    };
    match (
        boxed(ternary.child_by_field_name("consequence")),
        boxed(ternary.child_by_field_name("alternative")),
    ) {
        (Some(a), Some(b)) => a != b,
        _ => false,
    }
}

fn mixes_field_and_getter_annotations<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    const JPA: &[&[u8]] = &[
        b"Id",
        b"Column",
        b"Basic",
        b"ManyToOne",
        b"OneToMany",
        b"OneToOne",
        b"ManyToMany",
        b"JoinColumn",
        b"Embedded",
        b"Temporal",
        b"Enumerated",
        b"Lob",
        b"Version",
    ];
    let annotated = |m: Node| JPA.iter().any(|a| has_annotation(m, a, src));
    let members = class_members(class);
    let on_field = members
        .iter()
        .any(|m| m.kind() == "field_declaration" && annotated(*m));
    members
        .into_iter()
        .find(|m| m.kind() == "method_declaration" && annotated(*m) && on_field)
}

fn stores_a_non_serializable_object(call: Node, src: &[u8]) -> bool {
    let args = call_arguments(call);
    let Some(created) = args
        .get(1)
        .filter(|a| a.kind() == "object_creation_expression")
    else {
        return false;
    };
    let Some(t) = created.child_by_field_name("type") else {
        return false;
    };
    let name = base_type(text(t, src));
    find_node(root_of(call), |n| {
        n.kind() == "class_declaration"
            && name_text(n, src) == name
            && n.child_by_field_name("interfaces")
                .is_none_or(|i| count_word(text(i, src), b"Serializable") == 0)
            && n.child_by_field_name("superclass").is_none()
    })
    .is_some()
}

fn session_attributes_never_completed(class: Node, src: &[u8]) -> bool {
    (has_annotation(class, b"Controller", src) || has_annotation(class, b"RestController", src))
        && has_annotation(class, b"SessionAttributes", src)
        && count_word(text(class, src), b"setComplete") == 0
}

fn single_line_is_not_indented(body: Node, _: &[u8]) -> bool {
    if matches!(
        body.kind(),
        "block" | "if_statement" | "line_comment" | "block_comment"
    ) {
        return false;
    }
    let Some(owner) = body.parent() else {
        return false;
    };
    body.start_position().row > owner.start_position().row
        && body.start_position().column <= owner.start_position().column
}

fn ascending_loop_removes_by_index<'t>(for_statement: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut cursor = for_statement.walk();
    let update = for_statement
        .children_by_field_name("update", &mut cursor)
        .next()?;
    let counter = update.named_child(0).filter(|c| c.kind() == "identifier")?;
    if !text(update, src).ends_with(b"++") && !text(update, src).starts_with(b"++") {
        return None;
    }
    let name = text(counter, src);
    find_node(for_statement.child_by_field_name("body")?, |n| {
        n.kind() == "method_invocation"
            && method_name(n, src) == b"remove"
            && call_arguments(n)
                .first()
                .is_some_and(|a| a.kind() == "identifier" && text(*a, src) == name)
            && n.child_by_field_name("object").is_some_and(|o| {
                base_type(type_text(declared_type(n, text(o, src), src), src)).ends_with(b"List")
            })
    })
}

fn subclass_adds_fields_without_equals<'t>(program: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let classes = children_of_kind(program, "class_declaration");
    let defines_equals = |c: Node| {
        class_members(c)
            .iter()
            .any(|m| m.kind() == "method_declaration" && name_text(*m, src) == b"equals")
    };
    classes.iter().copied().find(|child| {
        let Some(sup) = child.child_by_field_name("superclass") else {
            return false;
        };
        let parent = classes
            .iter()
            .find(|c| **c != *child && count_word(text(sup, src), name_text(**c, src)) > 0);
        parent.is_some_and(|p| defines_equals(*p))
            && !defines_equals(*child)
            && class_members(*child)
                .iter()
                .any(|m| m.kind() == "field_declaration" && !has_modifier(*m, "static"))
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
    fn loops_and_ternaries() {
        let src = "class A {\n void f(List<String> l, boolean b, Integer i, Double d) {\n  for (int j = 0; j < l.size(); j++) { l.remove(j); }\n  for (int j = l.size() - 1; j >= 0; j--) { l.remove(j); }\n  Number n = b ? i : d;\n  Number m = b ? i : i;\n  if (b)\n  g();\n  if (b)\n   g();\n }\n}";
        assert_eq!(flagged("java/list-remove-in-loop", src), [3]);
        assert_eq!(flagged("java/ternary-boxed-mix", src), [5]);
        assert_eq!(flagged("java/unindented-conditional", src), [8]);
    }

    #[test]
    fn classes_and_sessions() {
        let src = "class P { public boolean equals(Object o) { return true; } }\nclass C extends P { int extra; }\nclass Q {}\nclass A { void f(HttpSession s) { s.setAttribute(\"q\", new Q()); s.setAttribute(\"p\", new P()); } }";
        assert_eq!(flagged("java/subclass-adds-fields-not-equals", src), [2]);
        assert_eq!(
            flagged("java/session-attribute-not-serializable", src),
            [4, 4]
        );
    }
}
