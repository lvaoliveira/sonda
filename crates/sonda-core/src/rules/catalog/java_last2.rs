//! The last Java rules answerable from one file (ADR-0007, batch 19):
//! enumeration and mass-assignment risks, nullness and Spring wiring,
//! test hygiene, catch order, and newer-Java idioms.

use super::java_bugs::{has_annotation, modifiers_of, statements};
use super::java_extra::class_members;
use super::java_final::{base_type, root_of};
use super::java_flow::{enclosing_method, find_declared_type, has_method, superclass_name};
use super::java_security::{call_arguments, find_node, method_name, string_value, text};
use super::java_smells::{children_of_kind, count_word, declarator_names, enclosing_class};
use super::*;

/// This module's rules that are off unless `rules.enabled` lists them
/// (see `catalog::OFF_BY_DEFAULT`).
pub(super) static OFF_BY_DEFAULT: &[&str] = &[
    "java/irregular-number-pattern",
    "java/serial-version-blind",
    "java/bean-validation-misplaced",
    "java/model-and-view-assertions",
    "java/high-frame-rate",
    "java/markdown-comment-html",
    "java/gatherer-default-combiner",
    "java/print-then-readln",
    "java/reverse-copy",
];

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "java/inner-class-super-call",
        name: "Inner class calls to super class methods should be unambiguous",
        description: "A call can mean the inner class's parent or the outer class's method.",
        message: "Qualify the call with super. or Outer.this.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2388")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation) @match"#,
            filter: Some(Keep(call_is_ambiguous_between_parent_and_outer)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class P { void go() {} }\nclass O { void go() {} class N extends P { void f() { go(); } } }",
            good: "class P { void go() {} }\nclass O { void go() {} class N extends P { void f() { super.go(); } } }",
        }),
    },
    Rule {
        id: "java/irregular-number-pattern",
        name: "Number patterns should be regular",
        description: "Groups of different sizes in a DecimalFormat pattern are almost always a typo.",
        message: "Make the groups the same size.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S3937")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(object_creation_expression type: (type_identifier) @t (#eq? @t "DecimalFormat") arguments: (argument_list (string_literal) @p)) @match"#,
            filter: Some(Keep(pattern_groups_are_irregular)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { DecimalFormat f = new DecimalFormat(\"#,##,###\"); } }",
            good: "class A { void f() { DecimalFormat f = new DecimalFormat(\"#,###,###\"); } }",
        }),
    },
    Rule {
        id: "java/bean-populated-from-request",
        name: "JavaBean properties should not be populated from untrusted input",
        description: "Copying request parameters onto a bean lets a caller set any property.",
        message: "Copy named properties only.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 15,
        sonar: &[exact("S4512")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "populate" "setProperty" "copyProperties")) @match"#,
            filter: Some(Keep(copies_request_parameters)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { BeanUtils.populate(bean, request.getParameterMap()); } }",
            good: "class A { void f() { bean.setName(request.getParameter(\"name\")); } }",
        }),
    },
    Rule {
        id: "java/serial-version-blind",
        name: "serialVersionUID should not be declared blindly",
        description: "1L and 0L are copied from templates and never change when the class does.",
        message: "Generate it with serialver, or remove it.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S4926")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(field_declaration) @match"#,
            filter: Some(Keep(serial_version_is_a_template_value)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A implements Serializable { private static final long serialVersionUID = 1L; }",
            good: "class A implements Serializable { private static final long serialVersionUID = 4817263517L; }",
        }),
    },
    Rule {
        id: "java/catch-hidden-by-parent",
        name: "Derived exceptions should not hide their parents' catch blocks",
        description: "A catch for a subclass after its parent can never run.",
        message: "Put the specific catch first.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S4970")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(try_statement) @match"#,
            filter: Some(Find(catch_follows_its_parent)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { try { g(); } catch (Exception e) { } catch (IOException e) { } } }",
            good: "class A { void f() { try { g(); } catch (IOException e) { } catch (Exception e) { } } }",
        }),
    },
    Rule {
        id: "java/bean-validation-misplaced",
        name: "Bean Validation (JSR 380) should be properly configured",
        description: "A constraint on a type it can't validate is silently ignored.",
        message: "Use a constraint that fits the type.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5128")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(field_declaration) @match"#,
            filter: Some(Keep(constraint_does_not_fit_the_type)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { @NotBlank int age; }",
            good: "class A { @NotNull Integer age; }",
        }),
    },
    Rule {
        id: "java/user-enumeration",
        name: "Authentication mechanisms should not permit user enumeration",
        description: "Telling a caller whether the user exists helps guessing logins.",
        message: "Keep hideUserNotFoundExceptions on.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5804")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "setHideUserNotFoundExceptions") arguments: (argument_list (false))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { provider.setHideUserNotFoundExceptions(false); } }",
            good: "class A { void f() { provider.setHideUserNotFoundExceptions(true); } }",
        }),
    },
    Rule {
        id: "java/permit-all",
        name: "Authorizations should be based on strong decisions",
        description: "permitAll on every request is not an authorization decision.",
        message: "Require authentication by default.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S5808")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "permitAll")) @match"#,
            filter: Some(Keep(permits_every_request)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { http.authorizeRequests().anyRequest().permitAll(); } }",
            good: "class A { void f() { http.authorizeRequests().anyRequest().authenticated(); } }",
        }),
    },
    Rule {
        id: "java/named-group-by-index",
        name: "Names of regular expressions named groups should be used",
        description: "A named group read by number defeats the name.",
        message: "Use matcher.group(\"name\").",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S5860")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "group") arguments: (argument_list (decimal_integer_literal))) @match"#,
            filter: Some(Keep(method_has_a_named_group_pattern)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { String f(String s) { Matcher m = Pattern.compile(\"(?<year>\\\\d+)\").matcher(s); return m.group(1); } }",
            good: "class A { String f(String s) { Matcher m = Pattern.compile(\"(?<year>\\\\d+)\").matcher(s); return m.group(\"year\"); } }",
        }),
    },
    Rule {
        id: "java/model-and-view-assertions",
        name: "Spring's ModelAndViewAssert assertions should be used instead of other assertions",
        description: "They give a better failure message.",
        message: "Use ModelAndViewAssert.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S5970")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#match? @n "^assert")) @match"#,
            filter: Some(Keep(asserts_on_a_model_and_view)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void t() { assertEquals(\"home\", mav.getViewName()); } }",
            good: "class A { void t() { ModelAndViewAssert.assertViewName(mav, \"home\"); } }",
        }),
    },
    Rule {
        id: "java/similar-tests",
        name: "Similar tests should be grouped in a single Parameterized test",
        description: "Tests that differ only in their literals are one test run with several inputs.",
        message: "Parameterize the test.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 15,
        sonar: &[exact("S5976")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Find(test_repeats_another_with_other_literals)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { @Test void a() { check(1); verify(2); } @Test void b() { check(3); verify(4); } }",
            good: "class A { @Test void a() { check(1); verify(2); } @Test void b() { other(); verify(4); } }",
        }),
    },
    Rule {
        id: "java/record-reflection",
        name: "Reflection should not be used to increase accessibility of records' fields",
        description: "Record fields are final, and setAccessible cannot make them writable.",
        message: "Use the accessor.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6216")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "setAccessible")) @match"#,
            filter: Some(Keep(opens_a_record_field)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "record R(int x) {}\nclass A { void f() throws Exception { R.class.getDeclaredField(\"x\").setAccessible(true); } }",
            good: "record R(int x) {}\nclass A { int f(R r) { return r.x(); } }",
        }),
    },
    Rule {
        id: "java/nullable-injection",
        name: "Nullable injected fields and parameters should provide a default value",
        description: "An optional dependency that is absent leaves the field null.",
        message: "Give it a default.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6816")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(field_declaration) @match"#,
            filter: Some(Keep(optional_injection_without_default)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { @Autowired(required = false) private Helper h; }",
            good: "class A { @Autowired(required = false) private Helper h = new Helper(); }",
        }),
    },
    Rule {
        id: "java/scoped-bean-in-singleton",
        name: "Non-singleton Spring beans should not be injected into singleton beans",
        description: "The singleton holds the first instance forever.",
        message: "Inject a provider or a scoped proxy.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S6832")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Find(singleton_holds_a_scoped_bean)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "@Scope(\"prototype\") @Component class P {}\n@Service class S { @Autowired P p; }",
            good: "@Scope(\"prototype\") @Component class P {}\n@Service class S { @Autowired ObjectProvider<P> p; }",
        }),
    },
    Rule {
        id: "java/reverse-copy",
        name: "Reverse view should be used instead of reverse copy in read-only cases",
        description: "Java 21's reversed() needs no copy.",
        message: "Use list.reversed().",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6877")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(block) @match"#,
            filter: Some(Find(copies_then_reverses)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(List<String> l) { List<String> r = new ArrayList<>(l); Collections.reverse(r); } }",
            good: "class A { void f(List<String> l) { var r = l.reversed(); } }",
        }),
    },
    Rule {
        id: "java/blocking-in-platform-pool",
        name: "Virtual threads should be used for tasks that include heavy blocking operations",
        description: "A fixed pool of platform threads is exhausted by sleeping tasks.",
        message: "Use newVirtualThreadPerTaskExecutor.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S6881")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "submit" "execute")) @match"#,
            filter: Some(Keep(pool_task_blocks)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { ExecutorService e = Executors.newFixedThreadPool(4); e.submit(() -> { Thread.sleep(1000); }); } }",
            good: "class A { void f() { ExecutorService e = Executors.newVirtualThreadPerTaskExecutor(); e.submit(() -> { Thread.sleep(1000); }); } }",
        }),
    },
    Rule {
        id: "java/high-frame-rate",
        name: "High frame rates should not be used",
        description: "A high frame rate drains the battery for little gain.",
        message: "Use 60 or less.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6898")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "setFrameRate")) @match"#,
            filter: Some(Keep(frame_rate_is_high)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { surface.setFrameRate(120f, 0); } }",
            good: "class A { void f() { surface.setFrameRate(60f, 0); } }",
        }),
    },
    Rule {
        id: "java/dirties-context-marker",
        name: "Use appropriate @DirtiesContext modes",
        description: "A bare @DirtiesContext rebuilds the context after every class.",
        message: "Say when: classMode or methodMode.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7177")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(marker_annotation name: (identifier) @n (#eq? @n "DirtiesContext")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "@DirtiesContext class A {}",
            good: "@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS) class A {}",
        }),
    },
    Rule {
        id: "java/gatherer-default-combiner",
        name: "Gatherer.ofSequential() should be used to build sequential gathers",
        description: "A default combiner means the gatherer is sequential.",
        message: "Use ofSequential.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7481")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) @o name: (identifier) @n (#eq? @o "Gatherer") (#eq? @n "of") arguments: (argument_list (method_invocation name: (identifier) @d (#eq? @d "defaultCombiner")))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Object g = Gatherer.of(init, integrator, Gatherer.defaultCombiner(), finisher); } }",
            good: "class A { void f() { Object g = Gatherer.ofSequential(init, integrator, finisher); } }",
        }),
    },
    Rule {
        id: "java/markdown-comment-html",
        name: "Markdown, HTML and Javadoc tags should be consistent",
        description: "A /// comment is Markdown: HTML and Javadoc tags inside it are not rendered.",
        message: "Use Markdown syntax.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7474")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(line_comment) @match"#,
            filter: Some(Keep(markdown_comment_uses_html)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A {\n /// Returns <b>the</b> value.\n int f() { return 1; }\n}",
            good: "class A {\n /// Returns **the** value.\n int f() { return 1; }\n}",
        }),
    },
    Rule {
        id: "java/print-then-readln",
        name: "Prefer IO.readln(String prompt) rather than IO.print followed by IO.readln()",
        description: "The prompt can be passed to readln.",
        message: "Pass the prompt to IO.readln.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S8469")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(block) @match"#,
            filter: Some(Find(prints_a_prompt_then_reads)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { IO.print(\"name: \"); String s = IO.readln(); } }",
            good: "class A { void f() { String s = IO.readln(\"name: \"); } }",
        }),
    },
];

// ---------------------------------------------------- filters

fn chain_names<'s>(call: Node, src: &'s [u8]) -> Vec<&'s [u8]> {
    let mut names = Vec::new();
    let mut cur = Some(call);
    while let Some(c) = cur.filter(|c| c.kind() == "method_invocation") {
        names.push(method_name(c, src));
        cur = c.child_by_field_name("object");
    }
    names
}

fn parent_of<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    superclass_name(class, src)
        .and_then(|n| find_declared_type(root_of(class), n, src))
        .filter(|p| p.kind() == "class_declaration")
}

fn call_is_ambiguous_between_parent_and_outer(call: Node, src: &[u8]) -> bool {
    if call.child_by_field_name("object").is_some() {
        return false;
    }
    let name = method_name(call, src);
    let Some(inner) = enclosing_class(call) else {
        return false;
    };
    let Some(outer) = enclosing_class(inner) else {
        return false;
    };
    let Some(parent) = parent_of(inner, src) else {
        return false;
    };
    // a nested class that extends its own outer class inherits, it isn't ambiguous
    parent != outer
        && has_method(inner, name, src).is_empty()
        && !has_method(parent, name, src).is_empty()
        && !has_method(outer, name, src).is_empty()
}

fn pattern_groups_are_irregular(creation: Node, src: &[u8]) -> bool {
    let Some(value) =
        find_node(creation, |n| n.kind() == "string_literal").and_then(|p| string_value(p, src))
    else {
        return false;
    };
    let integer = value.split(|&b| b == b'.').next().unwrap_or(value);
    let groups: Vec<&[u8]> = integer.split(|&b| b == b',').skip(1).collect();
    groups.len() >= 2 && groups.windows(2).any(|w| w[0].len() != w[1].len())
}

fn copies_request_parameters(call: Node, src: &[u8]) -> bool {
    count_word(text(call, src), b"getParameterMap") > 0
        || (matches!(method_name(call, src), b"populate" | b"copyProperties")
            && count_word(text(call, src), b"getParameter") > 0)
}

fn serial_version_is_a_template_value(field: Node, src: &[u8]) -> bool {
    declarator_names(field, src).contains(&&b"serialVersionUID"[..])
        && children_of_kind(field, "variable_declarator")
            .iter()
            .any(|d| {
                d.child_by_field_name("value")
                    .is_some_and(|v| matches!(text(v, src), b"0L" | b"1L" | b"0l" | b"1l"))
            })
}

fn is_a_subtype(child: &[u8], parent: &[u8], root: Node, src: &[u8]) -> bool {
    const BUILTIN: &[(&[u8], &[u8])] = &[
        (b"Throwable", b"Exception"),
        (b"Throwable", b"Error"),
        (b"Exception", b"IOException"),
        (b"Exception", b"RuntimeException"),
        (b"Exception", b"SQLException"),
        (b"Exception", b"InterruptedException"),
        (b"IOException", b"FileNotFoundException"),
        (b"IOException", b"UncheckedIOException"),
        (b"RuntimeException", b"IllegalArgumentException"),
        (b"RuntimeException", b"IllegalStateException"),
        (b"RuntimeException", b"NullPointerException"),
        (b"RuntimeException", b"UnsupportedOperationException"),
        (b"RuntimeException", b"IndexOutOfBoundsException"),
        (b"IllegalArgumentException", b"NumberFormatException"),
    ];
    let mut cur = child.to_vec();
    for _ in 0..8 {
        if BUILTIN
            .iter()
            .any(|(p, c)| *p == parent && *c == cur.as_slice())
        {
            return true;
        }
        let direct = BUILTIN
            .iter()
            .find(|(_, c)| *c == cur.as_slice())
            .map(|(p, _)| p.to_vec());
        let local = find_declared_type(root, &cur, src)
            .and_then(|d| superclass_name(d, src))
            .map(<[u8]>::to_vec);
        let Some(next) = local.or(direct) else {
            return false;
        };
        if next == parent {
            return true;
        }
        cur = next;
    }
    false
}

fn catch_follows_its_parent<'t>(try_statement: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let root = root_of(try_statement);
    let catches = children_of_kind(try_statement, "catch_clause");
    let type_of = |c: &Node| -> Option<Vec<u8>> {
        let p = c
            .named_children(&mut c.walk())
            .find(|p| p.kind() == "catch_formal_parameter")?;
        let t = p
            .named_children(&mut p.walk())
            .find(|t| t.kind() == "catch_type")?;
        Some(text(t, src).to_vec())
    };
    catches.iter().enumerate().find_map(|(i, later)| {
        let t = type_of(later)?;
        catches[..i]
            .iter()
            .any(|earlier| type_of(earlier).is_some_and(|e| is_a_subtype(&t, &e, root, src)))
            .then_some(*later)
    })
}

fn constraint_does_not_fit_the_type(field: Node, src: &[u8]) -> bool {
    let Some(ty) = field.child_by_field_name("type") else {
        return false;
    };
    let t = text(ty, src);
    let primitive = matches!(
        ty.kind(),
        "integral_type" | "floating_point_type" | "boolean_type"
    );
    let numeric = primitive
        || matches!(
            t,
            b"Integer" | b"Long" | b"Double" | b"BigDecimal" | b"Short"
        );
    let textual = matches!(t, b"String" | b"CharSequence");
    let any = |names: &[&[u8]]| names.iter().any(|a| has_annotation(field, a, src));
    (any(&[b"NotBlank", b"Email", b"Pattern"]) && numeric)
        || (any(&[
            b"Min",
            b"Max",
            b"Positive",
            b"Negative",
            b"DecimalMin",
            b"DecimalMax",
        ]) && textual)
        || (any(&[b"NotEmpty", b"NotBlank"]) && primitive)
}

fn permits_every_request(call: Node, src: &[u8]) -> bool {
    let names = chain_names(call, src);
    names.contains(&&b"anyRequest"[..])
        || count_word(text(call, src), b"/**") > 0
        || text(call, src).windows(4).any(|w| w == b"\"/**")
}

fn method_has_a_named_group_pattern(call: Node, src: &[u8]) -> bool {
    enclosing_method(call).is_some_and(|m| {
        text(m, src).windows(3).any(|w| w == b"(?<")
            && !text(m, src).windows(4).any(|w| w == b"(?<=")
    })
}

fn asserts_on_a_model_and_view(call: Node, src: &[u8]) -> bool {
    let t = text(call, src);
    t.windows(11).any(|w| w == b"getViewName") || t.windows(10).any(|w| w == b"getModelMa")
}

fn normalize(node: Node, src: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut stack = vec![node];
    while let Some(n) = stack.pop() {
        if n.child_count() == 0 {
            if matches!(
                n.kind(),
                "string_literal"
                    | "decimal_integer_literal"
                    | "decimal_floating_point_literal"
                    | "character_literal"
                    | "true"
                    | "false"
            ) {
                out.extend_from_slice(b"#");
            } else {
                out.extend_from_slice(text(n, src));
            }
            out.push(b' ');
        } else {
            let mut c = n.walk();
            let kids: Vec<Node> = n.children(&mut c).collect();
            stack.extend(kids.into_iter().rev());
        }
    }
    out
}

fn test_repeats_another_with_other_literals<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let tests: Vec<Node> = class_members(class)
        .into_iter()
        .filter(|m| m.kind() == "method_declaration" && has_annotation(*m, b"Test", src))
        .filter(|m| {
            m.child_by_field_name("body")
                .is_some_and(|b| statements(b).len() >= 2)
        })
        .collect();
    let shapes: Vec<(Vec<u8>, Vec<u8>)> = tests
        .iter()
        .map(|t| {
            let body = t
                .child_by_field_name("body")
                .map_or(Vec::new(), |b| normalize(b, src));
            (
                body,
                text(t.child_by_field_name("body").unwrap_or(*t), src).to_vec(),
            )
        })
        .collect();
    (1..tests.len()).find_map(|i| {
        (0..i)
            .any(|j| shapes[i].0 == shapes[j].0 && shapes[i].1 != shapes[j].1)
            .then_some(tests[i])
    })
}

fn opens_a_record_field(call: Node, src: &[u8]) -> bool {
    let Some(inner) = call
        .child_by_field_name("object")
        .filter(|o| o.kind() == "method_invocation")
    else {
        return false;
    };
    if method_name(inner, src) != b"getDeclaredField" {
        return false;
    }
    let Some(literal) = inner
        .child_by_field_name("object")
        .filter(|o| o.kind() == "class_literal")
    else {
        return false;
    };
    let t = text(literal, src);
    let name = t.strip_suffix(b".class").unwrap_or(t);
    find_declared_type(root_of(call), name, src).is_some_and(|d| d.kind() == "record_declaration")
}

fn optional_injection_without_default(field: Node, src: &[u8]) -> bool {
    let Some(a) = modifiers_of(field).map(|m| text(m, src)) else {
        return false;
    };
    let optional = a.windows(8).any(|w| w == b"required") && a.windows(5).any(|w| w == b"false");
    optional
        && children_of_kind(field, "variable_declarator")
            .iter()
            .all(|d| d.child_by_field_name("value").is_none())
}

fn singleton_holds_a_scoped_bean<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    const COMPONENTS: &[&[u8]] = &[
        b"Component",
        b"Service",
        b"Repository",
        b"Controller",
        b"RestController",
    ];
    if !COMPONENTS.iter().any(|a| has_annotation(class, a, src))
        || has_annotation(class, b"Scope", src)
    {
        return None;
    }
    let root = root_of(class);
    class_members(class).into_iter().find(|m| {
        m.kind() == "field_declaration"
            && (has_annotation(*m, b"Autowired", src) || has_annotation(*m, b"Inject", src))
            && m.child_by_field_name("type").is_some_and(|t| {
                find_declared_type(root, base_type(text(t, src)), src).is_some_and(|bean| {
                    modifiers_of(bean).is_some_and(|mods| {
                        let t = text(mods, src);
                        count_word(t, b"Scope") > 0 && !t.windows(9).any(|w| w == b"singleton")
                    })
                })
            })
    })
}

fn copies_then_reverses<'t>(block: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let items = statements(block);
    items.windows(2).find_map(|w| {
        let decl = (w[0].kind() == "local_variable_declaration").then_some(w[0])?;
        let d = children_of_kind(decl, "variable_declarator")
            .into_iter()
            .next()?;
        let name = text(d.child_by_field_name("name")?, src);
        let copy = d.child_by_field_name("value").filter(|v| {
            v.kind() == "object_creation_expression"
                && v.child_by_field_name("type")
                    .is_some_and(|t| base_type(text(t, src)) == b"ArrayList")
                && call_arguments(*v).len() == 1
        })?;
        let _ = copy;
        let reverse = w[1].named_child(0).filter(|c| {
            c.kind() == "method_invocation"
                && method_name(*c, src) == b"reverse"
                && call_arguments(*c)
                    .first()
                    .is_some_and(|a| text(*a, src) == name)
        })?;
        Some(reverse)
    })
}

fn pool_task_blocks(call: Node, src: &[u8]) -> bool {
    let Some(object) = call
        .child_by_field_name("object")
        .filter(|o| o.kind() == "identifier")
    else {
        return false;
    };
    let name = text(object, src);
    let platform_pool = find_node(root_of(call), |n| {
        n.kind() == "variable_declarator"
            && n.child_by_field_name("name")
                .is_some_and(|x| text(x, src) == name)
            && n.child_by_field_name("value").is_some_and(|v| {
                let t = text(v, src);
                count_word(t, b"newFixedThreadPool") + count_word(t, b"newCachedThreadPool") > 0
            })
    })
    .is_some();
    platform_pool
        && call_arguments(call).iter().any(|a| {
            a.kind() == "lambda_expression"
                && find_node(*a, |n| {
                    n.kind() == "method_invocation"
                        && method_name(n, src) == b"sleep"
                        && n.child_by_field_name("object")
                            .is_some_and(|o| text(o, src) == b"Thread")
                })
                .is_some()
        })
}

fn frame_rate_is_high(call: Node, src: &[u8]) -> bool {
    call_arguments(call).first().is_some_and(|a| {
        let digits: String = String::from_utf8_lossy(text(*a, src))
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        digits.parse::<f64>().is_ok_and(|v| v > 60.0)
    })
}

fn markdown_comment_uses_html(comment: Node, src: &[u8]) -> bool {
    let t = text(comment, src);
    t.starts_with(b"///")
        && (t.windows(2).any(|w| w == b"{@")
            || [&b"<p>"[..], b"<b>", b"<i>", b"<code>", b"<pre>", b"<ul>"]
                .iter()
                .any(|tag| t.windows(tag.len()).any(|w| w == *tag)))
}

fn prints_a_prompt_then_reads<'t>(block: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let is_io = |n: Node, names: &[&[u8]]| {
        n.kind() == "method_invocation"
            && n.child_by_field_name("object")
                .is_some_and(|o| text(o, src) == b"IO")
            && names.contains(&method_name(n, src))
    };
    let items = statements(block);
    items.windows(2).find_map(|w| {
        let first = w[0]
            .named_child(0)
            .filter(|c| is_io(*c, &[b"print", b"println"]))?;
        let second = if w[1].kind() == "local_variable_declaration" {
            children_of_kind(w[1], "variable_declarator")
                .into_iter()
                .next()?
                .child_by_field_name("value")
        } else {
            w[1].named_child(0)
        }?;
        (is_io(second, &[b"readln"]) && call_arguments(second).is_empty()).then_some(first)
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
    fn catch_order_and_tests() {
        let src = "class A {\n void f() {\n  try { g(); } catch (Exception e) { } catch (IOException e) { }\n  try { g(); } catch (IOException e) { } catch (Exception e) { }\n }\n @Test void a() { check(1); verify(2); }\n @Test void b() { check(3); verify(4); }\n @Test void c() throws Exception { Thread.sleep(5); }\n}";
        assert_eq!(flagged("java/catch-hidden-by-parent", src), [3]);
        assert_eq!(flagged("java/similar-tests", src), [7]);
    }

    #[test]
    fn spring_and_validation() {
        let src = "@Scope(\"prototype\") @Component class P {}\n@Service class S {\n @Autowired P p;\n @Autowired(required = false) Q q;\n @NotBlank int age;\n @NotNull Integer n;\n @Min(1) String s;\n}";
        assert_eq!(flagged("java/scoped-bean-in-singleton", src), [3]);
        assert_eq!(flagged("java/nullable-injection", src), [4]);
        assert_eq!(flagged("java/bean-validation-misplaced", src), [5, 7]);
    }

    #[test]
    fn small_checks() {
        let src = "class A {\n int f(Surface s, String t) {\n  s.setFrameRate(120f, 0);\n  s.setFrameRate(60f, 0);\n  DecimalFormat a = new DecimalFormat(\"#,##,###\");\n  DecimalFormat b = new DecimalFormat(\"#,###,###\");\n  IO.print(\"x\");\n  String r = IO.readln();\n  return 0;\n }\n}";
        assert_eq!(flagged("java/high-frame-rate", src), [3]);
        assert_eq!(flagged("java/irregular-number-pattern", src), [5]);
        assert_eq!(flagged("java/print-then-readln", src), [7]);
    }
}
