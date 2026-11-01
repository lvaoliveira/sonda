//! The last Java rules (ADR-0007, batch 20): constructor prologues,
//! record-pattern components, ClassFile and AssertJ misuse, and mocks of
//! whole classes. Constructors with statements before super() parse with
//! an ERROR node holding the call, which these rules read.

use super::java_bugs::statements;
use super::java_extra::{class_members, name_text};
use super::java_final::root_of;
use super::java_flow::{find_declared_type, has_method, nodes_in, superclass_name};
use super::java_security::{call_arguments, find_node, method_name, text};
use super::java_smells::{children_of_kind, count_word, enclosing_class};
use super::*;

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "java/unnamed-needs-var",
        name: "Unnamed variable declarations should use the var identifier",
        description: "`int _` and `var _` declare the same thing; var says less.",
        message: "Write var _.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S7466")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(local_variable_declaration type: (_) @t declarator: (variable_declarator name: (underscore_pattern))) @match"#,
            filter: Some(Keep(unnamed_has_explicit_type)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { int _ = g(); } }",
            good: "class A { void f() { var _ = g(); } }",
        }),
    },
    Rule {
        id: "java/record-pattern-unused-component",
        name: "Types of unused record components should be removed from pattern matching",
        description: "A component the body never reads needs no name or type.",
        message: "Write _ for it.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7475")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(if_statement condition: (parenthesized_expression (instanceof_expression pattern: (record_pattern)))) @match"#,
            filter: Some(Keep(record_pattern_has_unused_component)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "record P(int x, int y) {}\nclass A { void f(Object o) { if (o instanceof P(int x, int y)) { g(x); } } }",
            good: "record P(int x, int y) {}\nclass A { void f(Object o) { if (o instanceof P(int x, int _)) { g(x); } } }",
        }),
    },
    Rule {
        id: "java/constructor-prologue-long",
        name: "Excessive logic before super() should not bloat constructor",
        description: "Java 22 allows statements before super(), but a few lines is the limit.",
        message: "Move the logic into a helper.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S8444")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(constructor_body (ERROR) @match)"#,
            filter: Some(Keep(prologue_before_super_is_long)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A extends B { A(int x) { int a = 1; int b = 2; int c = 3; int d = 4; super(a); } }",
            good: "class A extends B { A(int x) { super(x); } }",
        }),
    },
    Rule {
        id: "java/validation-after-super",
        name: "Validation logic should be placed in constructor prologue when possible",
        description: "Checking an argument after super() lets the parent run on bad input.",
        message: "Validate before calling super().",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S8433")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(constructor_declaration) @match"#,
            filter: Some(Find(validates_after_super)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A extends B { A(String s) { super(s); Objects.requireNonNull(s); } }",
            good: "class A extends B { A(String s) { super(Objects.requireNonNull(s)); } }",
        }),
    },
    Rule {
        id: "java/fields-set-after-super",
        name: "Subclass fields should be initialized before calls to super() or this()",
        description: "The parent constructor can call an override that reads a field that is still null.",
        message: "Initialize the field in the prologue.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S8447")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(constructor_declaration) @match"#,
            filter: Some(Find(field_set_after_parent_calls_override)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class P { P() { init(); } void init() {} }\nclass C extends P { String name; C(String n) { super(); this.name = n; } void init() { name.length(); } }",
            good: "class P { P() { init(); } void init() {} }\nclass C extends P { String name; C(String n) { super(); } void init() { } }",
        }),
    },
    Rule {
        id: "java/class-transform-name",
        name: "Class name should be omitted when unchanged by class transform",
        description: "The overload without a name keeps the class name.",
        message: "Drop the name argument.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7477")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "transformClass")) @match"#,
            filter: Some(Keep(passes_the_models_own_name)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { cf.transformClass(model, model.thisClass().asSymbol(), t); } }",
            good: "class A { void f() { cf.transformClass(model, t); } }",
        }),
    },
    Rule {
        id: "java/class-build-for-transform",
        name: "transformClass method should be used instead of build when transforming a class",
        description: "build plus a manual transform is what transformClass does.",
        message: "Use transformClass.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7478")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "build") arguments: (argument_list (lambda_expression) @l)) @match"#,
            filter: Some(Keep(build_lambda_transforms_a_model)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { cf.build(desc, cb -> cb.transform(model, t)); } }",
            good: "class A { void f() { cf.transformClass(model, t); } }",
        }),
    },
    Rule {
        id: "java/assertj-global-config",
        name: "AssertJ configuration should be applied",
        description: "Global settings changed inside a test leak into every test that runs after it.",
        message: "Configure AssertJ once, in a configuration class.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5831")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#match? @n "^(setAllow|setExtract|setLenient|setMaxElements|setMaxLength|setPrint|setRemove|useRepresentation)")) @match"#,
            filter: Some(Keep(is_inside_a_test)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { @Test void t() { Assertions.setMaxLengthForSingleLineDescription(500); } }",
            good: "class A { @BeforeAll static void setup() { Assertions.setMaxLengthForSingleLineDescription(500); } }",
        }),
    },
    Rule {
        id: "java/mock-of-everything",
        name: "Mocking all non-private methods of a class should be avoided",
        description: "A class whose every method is stubbed is an interface in disguise.",
        message: "Extract an interface and mock that.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 15,
        sonar: &[exact("S5969")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Find(stubs_every_method_of_a_class)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class Svc { int a() { return 1; } int b() { return 2; } }\nclass T { @Test void t() { Svc m = mock(Svc.class); when(m.a()).thenReturn(1); when(m.b()).thenReturn(2); } }",
            good: "class Svc { int a() { return 1; } int b() { return 2; } }\nclass T { @Test void t() { Svc m = mock(Svc.class); when(m.a()).thenReturn(1); } }",
        }),
    },
];

// ---------------------------------------------------- filters

fn unnamed_has_explicit_type(declaration: Node, src: &[u8]) -> bool {
    declaration
        .child_by_field_name("type")
        .is_some_and(|t| text(t, src) != b"var")
}

fn record_pattern_has_unused_component(if_statement: Node, src: &[u8]) -> bool {
    let Some(pattern) = find_node(if_statement, |n| n.kind() == "record_pattern") else {
        return false;
    };
    let Some(body) = if_statement.child_by_field_name("consequence") else {
        return false;
    };
    nodes_in(pattern, &[], |n| n.kind() == "record_pattern_component")
        .iter()
        .any(|c| {
            c.named_children(&mut c.walk())
                .filter(|x| x.kind() == "identifier")
                .last()
                .is_some_and(|name| {
                    text(name, src) != b"_" && count_word(text(body, src), text(name, src)) == 0
                })
        })
}

fn prologue_before_super_is_long(error: Node, src: &[u8]) -> bool {
    let t = text(error, src);
    if !(t.starts_with(b"super") || t.starts_with(b"this")) {
        return false;
    }
    let Some(body) = error.parent().filter(|b| b.kind() == "constructor_body") else {
        return false;
    };
    let before = body
        .named_children(&mut body.walk())
        .take_while(|c| *c != error)
        .filter(|c| !matches!(c.kind(), "line_comment" | "block_comment"))
        .count();
    before > 3
}

fn validation_statement(statement: Node, src: &[u8]) -> bool {
    match statement.kind() {
        "expression_statement" => statement.named_child(0).is_some_and(|c| {
            c.kind() == "method_invocation"
                && matches!(
                    method_name(c, src),
                    b"requireNonNull"
                        | b"checkNotNull"
                        | b"checkArgument"
                        | b"notNull"
                        | b"isTrue"
                        | b"hasText"
                )
        }),
        "if_statement" => statement
            .child_by_field_name("consequence")
            .is_some_and(|c| find_node(c, |n| n.kind() == "throw_statement").is_some()),
        _ => false,
    }
}

fn validates_after_super<'t>(ctor: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let body = ctor.child_by_field_name("body")?;
    let items: Vec<Node> = body
        .named_children(&mut body.walk())
        .filter(|c| !matches!(c.kind(), "line_comment" | "block_comment"))
        .collect();
    let first = items.first()?;
    if first.kind() != "explicit_constructor_invocation" || !text(*first, src).starts_with(b"super")
    {
        return None;
    }
    items
        .get(1)
        .copied()
        .filter(|s| validation_statement(*s, src))
}

fn field_set_after_parent_calls_override<'t>(ctor: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let class = enclosing_class(ctor)?;
    let parent =
        superclass_name(class, src).and_then(|n| find_declared_type(root_of(ctor), n, src))?;
    let body = ctor.child_by_field_name("body")?;
    let has_super_call = body.named_children(&mut body.walk()).any(|c| {
        c.kind() == "explicit_constructor_invocation" && text(c, src).starts_with(b"super")
    });
    if !has_super_call {
        return None;
    }
    let parent_ctor_calls: Vec<&[u8]> = class_members(parent)
        .iter()
        .filter(|m| m.kind() == "constructor_declaration")
        .flat_map(|m| {
            nodes_in(*m, &[], |n| {
                n.kind() == "method_invocation" && n.child_by_field_name("object").is_none()
            })
            .into_iter()
            .map(|c| method_name(c, src))
            .collect::<Vec<_>>()
        })
        .collect();
    let overridden = parent_ctor_calls
        .iter()
        .any(|m| !has_method(class, m, src).is_empty());
    if !overridden {
        return None;
    }
    statements(body).into_iter().find(|s| {
        s.kind() == "expression_statement"
            && s.named_child(0).is_some_and(|a| {
                a.kind() == "assignment_expression"
                    && a.child_by_field_name("left")
                        .is_some_and(|l| l.kind() == "field_access")
            })
    })
}

fn passes_the_models_own_name(call: Node, src: &[u8]) -> bool {
    call_arguments(call)
        .get(1)
        .is_some_and(|a| count_word(text(*a, src), b"thisClass") > 0)
}

fn build_lambda_transforms_a_model(call: Node, src: &[u8]) -> bool {
    call_arguments(call).iter().any(|a| {
        a.kind() == "lambda_expression"
            && find_node(*a, |n| {
                n.kind() == "method_invocation" && method_name(n, src) == b"transform"
            })
            .is_some()
    })
}

fn is_inside_a_test(node: Node, src: &[u8]) -> bool {
    let mut p = node.parent();
    while let Some(n) = p {
        if n.kind() == "method_declaration" {
            return super::java_bugs::has_annotation(n, b"Test", src);
        }
        p = n.parent();
    }
    false
}

fn stubs_every_method_of_a_class<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let body = method.child_by_field_name("body")?;
    let root = root_of(method);
    for decl in nodes_in(body, &[], |n| n.kind() == "local_variable_declaration") {
        let d = children_of_kind(decl, "variable_declarator")
            .into_iter()
            .next()?;
        let value = d
            .child_by_field_name("value")
            .filter(|v| v.kind() == "method_invocation" && method_name(*v, src) == b"mock");
        let Some(value) = value else { continue };
        let arg = call_arguments(value)
            .into_iter()
            .next()
            .filter(|a| a.kind() == "class_literal");
        let Some(arg) = arg else { continue };
        let t = text(arg, src);
        let class = find_declared_type(root, t.strip_suffix(b".class").unwrap_or(t), src)
            .filter(|c| c.kind() == "class_declaration");
        let Some(class) = class else { continue };
        let name = text(d.child_by_field_name("name")?, src);
        let methods: Vec<&[u8]> = class_members(class)
            .iter()
            .filter(|m| {
                m.kind() == "method_declaration" && !super::java_bugs::has_modifier(**m, "private")
            })
            .map(|m| name_text(*m, src))
            .collect();
        if methods.len() < 2 {
            continue;
        }
        let stubbed = |m: &[u8]| {
            nodes_in(body, &[], |n| {
                n.kind() == "method_invocation"
                    && method_name(n, src) == m
                    && n.child_by_field_name("object")
                        .is_some_and(|o| text(o, src) == name)
            })
            .into_iter()
            .next()
            .is_some()
        };
        if methods.iter().all(|m| stubbed(m)) {
            return Some(decl);
        }
    }
    None
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
    fn constructors() {
        let src = "class P { P() { init(); } void init() {} }\nclass C extends P {\n String name;\n C(String n) { super(); this.name = n; }\n C(int a) { int a1 = 1; int b = 2; int c = 3; int d = 4; super(a1); }\n C(Object o) { super(); Objects.requireNonNull(o); }\n void init() {}\n}";
        assert_eq!(flagged("java/fields-set-after-super", src), [4]);
        assert_eq!(flagged("java/constructor-prologue-long", src), [5]);
        assert_eq!(flagged("java/validation-after-super", src), [6]);
    }

    #[test]
    fn patterns_and_mocks() {
        let src = "record P(int x, int y) {}\nclass Svc { int a() { return 1; } int b() { return 2; } }\nclass A {\n void f(Object o) {\n  if (o instanceof P(int x, int y)) { g(x); }\n  int _ = h();\n  var _ = h();\n }\n @Test void t() {\n  Svc m = mock(Svc.class);\n  when(m.a()).thenReturn(1);\n  when(m.b()).thenReturn(2);\n  Assertions.setMaxLengthForSingleLineDescription(5);\n }\n}";
        assert_eq!(flagged("java/record-pattern-unused-component", src), [5]);
        assert_eq!(flagged("java/unnamed-needs-var", src), [6]);
        assert_eq!(flagged("java/mock-of-everything", src), [10]);
        assert_eq!(flagged("java/assertj-global-config", src), [13]);
    }
}
