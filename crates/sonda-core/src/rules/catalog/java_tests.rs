//! Java rules, part 3 (ADR-0007, batch 10): JUnit and test-library idioms,
//! volatile and wait misuse, Spring proxy calls and a few smells. Queries stay
//! cheap on deep trees: see `js_modern.rs`.

use super::java_bugs::{has_annotation, has_modifier, modifiers_of, operator_text, statements};
use super::java_more::implements;
use super::java_security::{call_arguments, find_node, method_name, string_value, text};
use super::java_smells::{
    LOOPS, children_of_kind, count_word, declarator_names, enclosing_class, members,
};
use super::*;

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "java/assertion-in-run",
        name: "JUnit assertions should not be used in run methods",
        description: "An assertion that fails in another thread is lost; the test still passes.",
        message: "Report the failure back to the test thread.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 15,
        sonar: &[exact("S2186")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration name: (identifier) @n (#eq? @n "run")) @match"#,
            filter: Some(Keep(run_method_asserts)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class W implements Runnable { public void run() { assertEquals(1, x); } }",
            good: "class W implements Runnable { public void run() { result = x; } }",
        }),
    },
    Rule {
        id: "java/testcase-without-tests",
        name: "TestCases should contain tests",
        description: "A JUnit 3 TestCase with no test methods runs nothing.",
        message: "Add a test method.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2187")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration superclass: (superclass (type_identifier) @s (#eq? @s "TestCase"))) @match"#,
            filter: Some(Keep(testcase_has_no_test_methods)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class T extends TestCase { void helper() {} }",
            good: "class T extends TestCase { public void testIt() {} }",
        }),
    },
    Rule {
        id: "java/testcase-lifecycle-super",
        name: "JUnit test cases should call super methods",
        description: "Skipping super.setUp() or super.tearDown() skips the parent fixture.",
        message: "Call the super method.",
        category: CodeSmell,
        severity: Blocker,
        effort_minutes: 2,
        sonar: &[exact("S2188")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration name: (identifier) @n (#any-of? @n "setUp" "tearDown")) @match"#,
            filter: Some(Keep(lifecycle_skips_super)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class T extends TestCase { protected void setUp() { init(); } }",
            good: "class T extends TestCase { protected void setUp() { super.setUp(); init(); } }",
        }),
    },
    Rule {
        id: "java/wait-outside-loop",
        name: "Object.wait(...) should be called inside a loop",
        description: "A woken thread must re-check its condition, because wake-ups can be spurious.",
        message: "Wrap the wait in a while loop.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2274")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "wait")) @match"#,
            filter: Some(Keep(wait_is_not_in_a_loop)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() throws Exception { synchronized (lock) { lock.wait(); } } }",
            good: "class A { void f() throws Exception { synchronized (lock) { while (!ready) { lock.wait(); } } } }",
        }),
    },
    Rule {
        id: "java/volatile-compound-operation",
        name: "volatile variables should not be used with compound operators",
        description: "count++ on a volatile field is a read and a write, so updates are lost.",
        message: "Use an AtomicInteger or synchronize.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S3078")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(update_expression) @match
(assignment_expression) @match"#,
            filter: Some(Keep(updates_a_volatile_field)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { volatile int count; void f() { count++; } }",
            good: "class A { AtomicInteger count; void f() { count.incrementAndGet(); } }",
        }),
    },
    Rule {
        id: "java/week-year-mismatch",
        name: "DateTimeFormatters should not use mismatched year and week numbers",
        description: "A calendar year combined with a week number gives the wrong date at the year boundary.",
        message: "Use the week-based year (YYYY) with the week.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5917")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "ofPattern") arguments: (argument_list . (string_literal) @p)) @match"#,
            filter: Some(Keep(mixes_calendar_year_with_week)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { DateTimeFormatter f = DateTimeFormatter.ofPattern(\"yyyy-ww\"); } }",
            good: "class A { void f() { DateTimeFormatter f = DateTimeFormatter.ofPattern(\"yyyy-MM\"); } }",
        }),
    },
    Rule {
        id: "java/model-attribute-name",
        name: "Model attributes should follow the Java identifier naming convention",
        description: "A name that is not an identifier cannot be referenced from the view.",
        message: "Use a valid identifier.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6806")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(annotation name: (identifier) @n (#eq? @n "ModelAttribute")) @match"#,
            filter: Some(Keep(model_attribute_is_not_an_identifier)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class C { @ModelAttribute(\"my-name\") Object a() { return null; } }",
            good: "class C { @ModelAttribute(\"myName\") Object a() { return null; } }",
        }),
    },
    Rule {
        id: "java/hardcoded-path",
        name: "URIs should not be hardcoded",
        description: "A literal path or file URI breaks on another machine.",
        message: "Make this path configurable.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S1075")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(string_literal) @match"#,
            filter: Some(Keep(is_a_machine_specific_path)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { String p = \"/home/app/data\"; } }",
            good: "class A { void f() { String p = config.dataDir(); } }",
        }),
    },
    Rule {
        id: "java/redundant-cast",
        name: "Redundant casts should not be used",
        description: "Casting a value to the type it already has does nothing.",
        message: "Remove this cast.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S1905")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(cast_expression) @match"#,
            filter: Some(Keep(casts_to_its_own_type)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { String s = (String) \"x\"; } }",
            good: "class A { void f() { String s = \"x\"; } }",
        }),
    },
    Rule {
        id: "java/serializable-field-type",
        name: "Fields in a Serializable class should either be transient or serializable",
        description: "A List or Map field is only serializable if the instance behind it is.",
        message: "Make it transient, or use a serializable type.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S1948")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration (super_interfaces) @i) @match"#,
            filter: Some(Find(non_serializable_field)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A implements Serializable { private List<String> items; }",
            good: "class A implements Serializable { private transient List<String> items; }",
        }),
    },
    Rule {
        id: "java/read-resolve-visibility",
        name: "readResolve methods should be inheritable",
        description: "A private readResolve is ignored when a subclass is deserialized.",
        message: "Make it protected.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2062")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration name: (identifier) @n (#eq? @n "readResolve")) @match"#,
            filter: Some(Keep(private_in_extensible_class)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A implements Serializable { private Object readResolve() { return this; } }",
            good: "class A implements Serializable { protected Object readResolve() { return this; } }",
        }),
    },
    Rule {
        id: "java/pointless-math",
        name: "Do not perform unnecessary mathematical operations",
        description: "Rounding an integer, or taking the floor of one, changes nothing.",
        message: "Remove this call.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2185")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) @o name: (identifier) @n arguments: (argument_list . (decimal_integer_literal)) (#eq? @o "Math") (#any-of? @n "floor" "ceil" "rint" "round")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { double d = Math.floor(5); } }",
            good: "class A { void f() { double d = Math.floor(x); } }",
        }),
    },
    Rule {
        id: "java/test-without-assertion",
        name: "Tests should include assertions",
        description: "A test that asserts nothing passes whatever the code does.",
        message: "Add an assertion.",
        category: CodeSmell,
        severity: Blocker,
        effort_minutes: 10,
        sonar: &[exact("S2699")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Keep(test_has_no_assertion)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class T { @Test void a() { service.run(); } }",
            good: "class T { @Test void a() { assertEquals(1, service.run()); } }",
        }),
    },
    Rule {
        id: "java/commons-date-truncate",
        name: "DateUtils.truncate from Apache Commons Lang should not be used",
        description: "It misbehaves around DST changes.",
        message: "Use java.time.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S2718")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) @o name: (identifier) @n (#eq? @o "DateUtils") (#eq? @n "truncate")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Date d = DateUtils.truncate(now, Calendar.DATE); } }",
            good: "class A { void f() { LocalDate d = LocalDate.now(); } }",
        }),
    },
    Rule {
        id: "java/nullable-primitive",
        name: "@CheckForNull or @Nullable should not be used on primitive types",
        description: "A primitive can never be null.",
        message: "Remove the annotation or use a wrapper type.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S4682")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(formal_parameter) @match
(method_declaration) @match"#,
            filter: Some(Keep(nullable_primitive)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { @Nullable int f() { return 0; } }",
            good: "class A { @Nullable Integer f() { return null; } }",
        }),
    },
    Rule {
        id: "java/assertj-simplifiable",
        name: "AssertJ assertions should be simplified to the corresponding dedicated assertion",
        description: "hasSize(n) and isEmpty() report the actual contents when they fail; isEqualTo(0) does not.",
        message: "Use the dedicated assertion.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5838")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "isTrue" "isFalse" "isEqualTo")) @match"#,
            filter: Some(Keep(assertj_can_be_simplified)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { assertThat(list.size()).isEqualTo(3); } }",
            good: "class A { void f() { assertThat(list).hasSize(3); } }",
        }),
    },
    Rule {
        id: "java/assertj-chain",
        name: "Consecutive AssertJ assertThat statements should be chained",
        description: "Two statements on the same subject can be one chain.",
        message: "Chain these assertions.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5853")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(block) @match"#,
            filter: Some(Find(assertj_repeats_subject)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { assertThat(x).isNotNull(); assertThat(x).isEqualTo(1); } }",
            good: "class A { void f() { assertThat(x).isNotNull().isEqualTo(1); } }",
        }),
    },
    Rule {
        id: "java/assertthatthrownby-alone",
        name: "AssertJ assertThatThrownBy should not be used alone",
        description: "Without a follow-up it only checks that something was thrown.",
        message: "Check the exception type or message.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5958")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(expression_statement (method_invocation name: (identifier) @n (#eq? @n "assertThatThrownBy"))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { assertThatThrownBy(() -> f()); } }",
            good: "class A { void f() { assertThatThrownBy(() -> f()).isInstanceOf(IOException.class); } }",
        }),
    },
    Rule {
        id: "java/mockito-times-one",
        name: "Call to Mockito verify should be simplified",
        description: "times(1) is the default.",
        message: "Remove times(1).",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S6068")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "verify") arguments: (argument_list (_) (method_invocation name: (identifier) @t (#eq? @t "times") arguments: (argument_list (decimal_integer_literal) @one (#eq? @one "1"))))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { verify(mock, times(1)).run(); } }",
            good: "class A { void f() { verify(mock).run(); } }",
        }),
    },
    Rule {
        id: "java/mockito-qualified",
        name: "Mockito core methods should be statically imported",
        description: "Mockito.when(...) reads worse than when(...).",
        message: "Import the method statically.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S8924")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) @o name: (identifier) @n (#eq? @o "Mockito") (#any-of? @n "when" "verify" "mock" "spy" "doReturn" "doThrow")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Mockito.when(x.get()).thenReturn(1); } }",
            good: "class A { void f() { when(x.get()).thenReturn(1); } }",
        }),
    },
    Rule {
        id: "java/proxied-call-through-this",
        name: "Methods with Spring proxy should not be called via this",
        description: "A call from inside the class bypasses the proxy, so @Transactional and friends do nothing.",
        message: "Call it through another bean.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S6809")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation) @match"#,
            filter: Some(Keep(calls_own_proxied_method)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { @Transactional void a() {} void b() { a(); } }",
            good: "class A { @Transactional void a() {} void b() { other.a(); } }",
        }),
    },
    Rule {
        id: "java/select-star",
        name: "SQL queries should retrieve only necessary fields",
        description: "SELECT * breaks when columns are added and fetches more than is used.",
        message: "Name the columns.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6905")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(string_literal) @match"#,
            filter: Some(Keep(selects_all_columns)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { String q = \"SELECT * FROM users\"; } }",
            good: "class A { void f() { String q = \"SELECT id, name FROM users\"; } }",
        }),
    },
    Rule {
        id: "java/multiple-main-methods",
        name: "Only one main method should be defined in a class",
        description: "Two entry points make it unclear which one starts the program.",
        message: "Keep one main method.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S8446")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_body) @match"#,
            filter: Some(Find(second_main_method)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { public static void main(String[] a) {} public static void main(String a) {} }",
            good: "class A { public static void main(String[] a) {} }",
        }),
    },
    Rule {
        id: "java/month-numeric-literal",
        name: "Month and DayOfWeek enums should be used instead of numeric literals",
        description: "LocalDate.of(2024, 3, 1) hides which month 3 is.",
        message: "Use Month.MARCH.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S8694")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) @o name: (identifier) @n (#any-of? @o "LocalDate" "LocalDateTime" "YearMonth") (#eq? @n "of")) @match"#,
            filter: Some(Keep(month_is_a_number)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { LocalDate d = LocalDate.of(2024, 3, 1); } }",
            good: "class A { void f() { LocalDate d = LocalDate.of(2024, Month.MARCH, 1); } }",
        }),
    },
    Rule {
        id: "java/try-fail-catch",
        name: "Dedicated exception assertions should be used instead of try-catch with fail",
        description: "assertThrows states the intent and fails with a clear message.",
        message: "Use assertThrows.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S8714")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(try_statement) @match"#,
            filter: Some(Keep(try_ends_with_fail)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { try { f(); fail(); } catch (IOException e) { } } }",
            good: "class A { void f() { assertThrows(IOException.class, () -> f()); } }",
        }),
    },
    Rule {
        id: "java/ignored-status-return",
        name: "Return values should not be ignored when they contain the operation status code",
        description: "mkdir() and createNewFile() report failure only through their result.",
        message: "Check the returned value.",
        category: Bug,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S899")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(expression_statement (method_invocation name: (identifier) @n (#any-of? @n "mkdir" "mkdirs" "createNewFile" "renameTo" "tryLock"))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { dir.mkdirs(); } }",
            good: "class A { void f() { if (!dir.mkdirs()) { fail(); } } }",
        }),
    },
];

// ---------------------------------------------------- filters

fn extends_class(class: Node, name: &[u8], src: &[u8]) -> bool {
    class
        .child_by_field_name("superclass")
        .is_some_and(|s| count_word(text(s, src), name) > 0)
}

fn run_method_asserts(method: Node, src: &[u8]) -> bool {
    // Runnable.run() takes no arguments; a run(data, id) helper is something else.
    if method
        .child_by_field_name("parameters")
        .is_some_and(|p| p.named_child_count() > 0)
    {
        return false;
    }
    method.child_by_field_name("body").is_some_and(|b| {
        find_node(b, |n| {
            n.kind() == "method_invocation" && method_name(n, src).starts_with(b"assert")
        })
        .is_some()
    })
}

fn testcase_has_no_test_methods(class: Node, src: &[u8]) -> bool {
    let Some(body) = class.child_by_field_name("body") else {
        return false;
    };
    !members(body).iter().any(|m| {
        m.kind() == "method_declaration"
            && (m
                .child_by_field_name("name")
                .is_some_and(|n| text(n, src).starts_with(b"test"))
                || has_annotation(*m, b"Test", src))
    })
}

fn lifecycle_skips_super(method: Node, src: &[u8]) -> bool {
    let Some(class) = enclosing_class(method) else {
        return false;
    };
    if !extends_class(class, b"TestCase", src) {
        return false;
    }
    let name = method
        .child_by_field_name("name")
        .map_or(&b""[..], |n| text(n, src));
    method.child_by_field_name("body").is_some_and(|b| {
        find_node(b, |n| {
            n.kind() == "method_invocation"
                && method_name(n, src) == name
                && n.child_by_field_name("object")
                    .is_some_and(|o| o.kind() == "super")
        })
        .is_none()
    })
}

fn wait_is_not_in_a_loop(call: Node, src: &[u8]) -> bool {
    // `ObjectUtils.wait(lock, duration)` is a static helper, not Object.wait.
    if call.child_by_field_name("object").is_some_and(|o| {
        o.kind() == "identifier" && text(o, src).first().is_some_and(u8::is_ascii_uppercase)
    }) {
        return false;
    }
    let mut p = call.parent();
    let mut hops = 0;
    while let Some(n) = p {
        if LOOPS.contains(&n.kind()) {
            return false;
        }
        if matches!(
            n.kind(),
            "method_declaration" | "lambda_expression" | "constructor_declaration"
        ) {
            return true;
        }
        hops += 1;
        if hops > 128 {
            return false;
        }
        p = n.parent();
    }
    true
}

fn updates_a_volatile_field(node: Node, src: &[u8]) -> bool {
    let target = if node.kind() == "update_expression" {
        node.named_child(0)
    } else {
        // Only compound assignments read the old value.
        if operator_text(node, src) == b"=" {
            return false;
        }
        node.child_by_field_name("left")
    };
    let Some(target) = target else {
        return false;
    };
    let name = match target.kind() {
        "identifier" => text(target, src),
        "field_access" => target
            .child_by_field_name("field")
            .map_or(&b""[..], |f| text(f, src)),
        _ => return false,
    };
    let Some(class) = enclosing_class(node) else {
        return false;
    };
    let Some(body) = class.child_by_field_name("body") else {
        return false;
    };
    members(body).iter().any(|m| {
        m.kind() == "field_declaration"
            && has_modifier(*m, "volatile")
            && declarator_names(*m, src).contains(&name)
    })
}

fn mixes_calendar_year_with_week(call: Node, src: &[u8]) -> bool {
    call_arguments(call)
        .first()
        .and_then(|a| string_value(*a, src))
        .is_some_and(|p| p.windows(4).any(|w| w == b"yyyy") && p.windows(2).any(|w| w == b"ww"))
}

fn model_attribute_is_not_an_identifier(annotation: Node, src: &[u8]) -> bool {
    let Some(literal) = find_node(annotation, |n| n.kind() == "string_literal") else {
        return false;
    };
    string_value(literal, src).is_some_and(|v| {
        !v.is_empty() && !(v[0].is_ascii_alphabetic() || v[0] == b'_' || v[0] == b'$')
            || v.iter()
                .any(|b| !(b.is_ascii_alphanumeric() || *b == b'_' || *b == b'$'))
    })
}

fn is_a_machine_specific_path(string: Node, src: &[u8]) -> bool {
    // Annotation values such as @GetMapping("/x") are URLs of the service.
    if string.parent().is_some_and(|p| {
        matches!(
            p.kind(),
            "element_value_pair" | "annotation_argument_list" | "annotation"
        )
    }) {
        return false;
    }
    let Some(v) = string_value(string, src) else {
        return false;
    };
    v.starts_with(b"file:/")
        || v.starts_with(b"jar:file:")
        || (v.len() > 3 && v[0].is_ascii_alphabetic() && &v[1..3] == b":\\" && v[3] != b'"')
        || [
            &b"/usr/"[..],
            b"/etc/",
            b"/var/",
            b"/home/",
            b"/opt/",
            b"/tmp/",
            b"/Users/",
        ]
        .iter()
        .any(|p| v.starts_with(p))
}

fn casts_to_its_own_type(cast: Node, src: &[u8]) -> bool {
    let (Some(ty), Some(value)) = (
        cast.child_by_field_name("type"),
        cast.child_by_field_name("value"),
    ) else {
        return false;
    };
    match value.kind() {
        "string_literal" => text(ty, src) == b"String",
        "object_creation_expression" => value
            .child_by_field_name("type")
            .is_some_and(|t| text(t, src) == text(ty, src)),
        _ => false,
    }
}

fn non_serializable_field<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !implements(class, src, b"Serializable") {
        return None;
    }
    let body = class.child_by_field_name("body")?;
    members(body).into_iter().find(|m| {
        if m.kind() != "field_declaration"
            || has_modifier(*m, "static")
            || has_modifier(*m, "transient")
        {
            return false;
        }
        m.child_by_field_name("type").is_some_and(|t| {
            let head = text(t, src)
                .split(|&b| b == b'<')
                .next()
                .unwrap_or(&b""[..]);
            matches!(
                head,
                b"List"
                    | b"Map"
                    | b"Set"
                    | b"Collection"
                    | b"Queue"
                    | b"Deque"
                    | b"Optional"
                    | b"Iterator"
                    | b"Stream"
                    | b"Thread"
            )
        })
    })
}

fn private_in_extensible_class(method: Node, src: &[u8]) -> bool {
    has_modifier(method, "private")
        && enclosing_class(method)
            .is_some_and(|c| c.kind() == "class_declaration" && !has_modifier(c, "final"))
        && enclosing_class(method).is_some_and(|c| implements(c, src, b"Serializable"))
}

fn test_has_no_assertion(method: Node, src: &[u8]) -> bool {
    if !has_annotation(method, b"Test", src) {
        return false;
    }
    // `@Test(expected = ...)` and `@Test(timeout = ...)` carry their own check.
    if let Some(mods) = modifiers_of(method)
        && text(mods, src).windows(8).any(|w| w == b"expected")
    {
        return false;
    }
    let Some(body) = method.child_by_field_name("body") else {
        return false;
    };
    if body.named_child_count() == 0 {
        return false;
    }
    let t = text(body, src);
    ![
        &b"assert"[..],
        b"Assert",
        b"verify",
        b"fail",
        b"expect",
        b"should",
        b"then(",
        b"check",
        b"throw",
        b"mock",
        b"Mock",
        b"given",
        b"test",
        b"Test",
        b"validate",
        b"ensure",
    ]
    .iter()
    .any(|w| t.windows(w.len()).any(|x| x == *w))
}

fn nullable_primitive(node: Node, src: &[u8]) -> bool {
    let primitive = node.child_by_field_name("type").is_some_and(|t| {
        matches!(
            t.kind(),
            "integral_type" | "floating_point_type" | "boolean_type"
        )
    });
    primitive
        && (has_annotation(node, b"Nullable", src) || has_annotation(node, b"CheckForNull", src))
}

fn assertj_can_be_simplified(call: Node, src: &[u8]) -> bool {
    let Some(subject) = call
        .child_by_field_name("object")
        .filter(|o| o.kind() == "method_invocation" && method_name(*o, src) == b"assertThat")
    else {
        return false;
    };
    let Some(arg) = call_arguments(subject).into_iter().next() else {
        return false;
    };
    let name = method_name(call, src);
    match arg.kind() {
        "method_invocation" => match method_name(arg, src) {
            b"size" | b"length" => name == b"isEqualTo",
            b"isEmpty" => matches!(name, b"isTrue" | b"isFalse"),
            b"equals" | b"contains" | b"startsWith" | b"endsWith" => {
                matches!(name, b"isTrue" | b"isFalse")
            }
            _ => false,
        },
        "binary_expression" => {
            matches!(name, b"isTrue" | b"isFalse")
                && matches!(operator_text(arg, src), b"==" | b"!=")
        }
        _ => false,
    }
}

fn assertj_repeats_subject<'t>(block: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let subject = |s: Node<'t>| -> Option<&[u8]> {
        let mut call = (s.kind() == "expression_statement").then(|| s.named_child(0))??;
        // Walk down the chain to its assertThat(...) root.
        loop {
            if method_name(call, src) == b"assertThat" {
                return call_arguments(call).first().map(|a| text(*a, src));
            }
            call = call
                .child_by_field_name("object")
                .filter(|o| o.kind() == "method_invocation")?;
        }
    };
    let items = statements(block);
    items.windows(2).find_map(|pair| {
        let (a, b) = (subject(pair[0])?, subject(pair[1])?);
        (a == b && !a.is_empty()).then_some(pair[1])
    })
}

fn calls_own_proxied_method(call: Node, src: &[u8]) -> bool {
    if call
        .child_by_field_name("object")
        .is_some_and(|o| o.kind() != "this")
    {
        return false;
    }
    let Some(class) = enclosing_class(call) else {
        return false;
    };
    let Some(body) = class.child_by_field_name("body") else {
        return false;
    };
    let name = method_name(call, src);
    // Calling it from the proxied method itself is a recursion, not a bypass.
    let caller = {
        let mut p = call.parent();
        let mut hops = 0;
        let mut found = None;
        while let Some(n) = p {
            if n.kind() == "method_declaration" {
                found = n.child_by_field_name("name").map(|x| text(x, src));
                break;
            }
            hops += 1;
            if hops > 64 {
                break;
            }
            p = n.parent();
        }
        found
    };
    caller != Some(name)
        && members(body).iter().any(|m| {
            m.kind() == "method_declaration"
                && m.child_by_field_name("name")
                    .is_some_and(|n| text(n, src) == name)
                && [
                    "Transactional",
                    "Async",
                    "Cacheable",
                    "CachePut",
                    "CacheEvict",
                ]
                .iter()
                .any(|a| has_annotation(*m, a.as_bytes(), src))
        })
}

fn selects_all_columns(string: Node, src: &[u8]) -> bool {
    string_value(string, src).is_some_and(|v| {
        let lower = v.to_ascii_lowercase();
        let t = lower.trim_ascii_start();
        t.starts_with(b"select *") || t.starts_with(b"select\t*")
    })
}

fn second_main_method<'t>(body: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    members(body)
        .into_iter()
        .filter(|m| {
            m.kind() == "method_declaration"
                && has_modifier(*m, "static")
                && m.child_by_field_name("name")
                    .is_some_and(|n| text(n, src) == b"main")
        })
        .nth(1)
}

fn month_is_a_number(call: Node, src: &[u8]) -> bool {
    call_arguments(call).get(1).is_some_and(|m| {
        m.kind() == "decimal_integer_literal"
            && String::from_utf8_lossy(text(*m, src))
                .parse::<u32>()
                .is_ok_and(|n| (1..=12).contains(&n))
    })
}

fn try_ends_with_fail(try_: Node, src: &[u8]) -> bool {
    if children_of_kind(try_, "catch_clause").is_empty() {
        return false;
    }
    let Some(body) = try_.child_by_field_name("body") else {
        return false;
    };
    statements(body).last().is_some_and(|s| {
        s.kind() == "expression_statement"
            && s.named_child(0)
                .is_some_and(|c| c.kind() == "method_invocation" && method_name(c, src) == b"fail")
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
        let cfg = Config::default();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let file = analyze("t", Lang::Java, src, &rules, &cfg, far_deadline()).unwrap();
        file.issues
            .iter()
            .filter(|i| i.rule == rule)
            .map(|i| i.line)
            .collect()
    }

    #[test]
    fn junit3_and_threads() {
        let src = "class W implements Runnable {\npublic void run() { assertEquals(1, x); }\n}\nclass T extends TestCase {\nvoid helper() {}\n}\nclass U extends TestCase {\npublic void testIt() {}\nprotected void setUp() { init(); }\nprotected void tearDown() { super.tearDown(); }\n}\nclass V {\nvoid a() throws Exception { synchronized (l) { l.wait(); } }\nvoid b() throws Exception { synchronized (l) { while (!ok) { l.wait(); } } }\n}";
        assert_eq!(flagged("java/assertion-in-run", src), [2]);
        assert_eq!(flagged("java/testcase-without-tests", src), [4]);
        assert_eq!(flagged("java/testcase-lifecycle-super", src), [9]);
        assert_eq!(flagged("java/wait-outside-loop", src), [13]);
    }

    #[test]
    fn false_positives_found_in_real_code() {
        let src = "class A {\nvoid run(TestData d, String id) { assertEquals(1, d.x); }\nvoid f() throws Exception { ObjectUtils.wait(lock, d); lock.wait(); }\nString g = \"a:\\\"b\";\n}";
        assert!(flagged("java/assertion-in-run", src).is_empty());
        assert_eq!(flagged("java/wait-outside-loop", src), [3]);
        assert!(flagged("java/hardcoded-path", src).is_empty());
    }

    #[test]
    fn volatile_fields() {
        let src = "class A {\nvolatile int count;\nint plain;\nvoid f() { count++; plain++; count = 5; count += 2; this.count--; }\n}";
        assert_eq!(flagged("java/volatile-compound-operation", src), [4, 4, 4]);
    }

    #[test]
    fn strings() {
        let src = "class A {\nDateTimeFormatter a = DateTimeFormatter.ofPattern(\"yyyy-ww\");\nDateTimeFormatter b = DateTimeFormatter.ofPattern(\"yyyy-MM\");\n@ModelAttribute(\"my-name\") Object c() { return null; }\n@ModelAttribute(\"myName\") Object d() { return null; }\nString e = \"/home/app/data\";\nString f = \"C:\\\\data\";\nString g = \"/api/users\";\n@GetMapping(\"/home/x\") String h() { return \"\"; }\nString i = \"SELECT * FROM t\";\nString j = \"select id from t\";\nString k = (String) \"x\";\nObject l = (Object) \"x\";\nLocalDate m = LocalDate.of(2024, 3, 1);\nLocalDate n = LocalDate.of(2024, Month.MARCH, 1);\n}";
        assert_eq!(flagged("java/week-year-mismatch", src), [2]);
        assert_eq!(flagged("java/model-attribute-name", src), [4]);
        assert_eq!(flagged("java/hardcoded-path", src), [6, 7]);
        assert_eq!(flagged("java/select-star", src), [10]);
        assert_eq!(flagged("java/redundant-cast", src), [12]);
        assert_eq!(flagged("java/month-numeric-literal", src), [14]);
    }

    #[test]
    fn serialization_and_types() {
        let src = "class A implements Serializable {\nprivate List<String> items;\nprivate transient List<String> cache;\nprivate static List<String> shared;\nprivate String name;\nprivate Object readResolve() { return this; }\n}\nfinal class B implements Serializable { private Object readResolve() { return this; } }\nclass C { @Nullable int a() { return 0; } @Nullable Integer b() { return null; } void c(@CheckForNull boolean x) {} }";
        assert_eq!(flagged("java/serializable-field-type", src), [2]);
        assert_eq!(flagged("java/read-resolve-visibility", src), [6]);
        assert_eq!(flagged("java/nullable-primitive", src), [9, 9]);
    }

    #[test]
    fn test_helpers() {
        let src = "class T {\n@Test void a() { service.run(); }\n@Test void b() { assertEquals(1, 2); }\n@Test void c() { }\n@Test(expected = X.class) void d() { service.run(); }\nvoid e() {\nassertThat(list.size()).isEqualTo(3);\nassertThat(list).hasSize(3);\nassertThat(a == b).isTrue();\nassertThat(x).isNotNull();\nassertThat(x).isEqualTo(1);\nassertThat(y).isNotNull();\nassertThatThrownBy(() -> f());\nassertThatThrownBy(() -> f()).isInstanceOf(X.class);\nverify(mock, times(1)).run();\nverify(mock).run();\nMockito.when(x).thenReturn(1);\ntry { f(); fail(); } catch (IOException e) { }\ntry { f(); } catch (IOException e) { }\ndir.mkdirs();\nboolean ok = dir.mkdirs();\n}\n}";
        assert_eq!(flagged("java/test-without-assertion", src), [2]);
        assert_eq!(flagged("java/assertj-simplifiable", src), [7, 9]);
        assert_eq!(flagged("java/assertj-chain", src), [11]);
        assert_eq!(flagged("java/assertthatthrownby-alone", src), [13]);
        assert_eq!(flagged("java/mockito-times-one", src), [15]);
        assert_eq!(flagged("java/mockito-qualified", src), [17]);
        assert_eq!(flagged("java/try-fail-catch", src), [18]);
        assert_eq!(flagged("java/ignored-status-return", src), [20]);
    }

    #[test]
    fn spring_and_mains() {
        let src = "class A {\n@Transactional void a() {}\nvoid b() { a(); }\nvoid c() { this.a(); }\nvoid d() { other.a(); }\n@Transactional void e() { e(); }\npublic static void main(String[] x) {}\npublic static void main(String x) {}\nvoid main() {}\n}";
        assert_eq!(flagged("java/proxied-call-through-this", src), [3, 4]);
        assert_eq!(flagged("java/multiple-main-methods", src), [8]);
    }

    #[test]
    fn math_and_dates() {
        let src = "class A { void f() {\ndouble a = Math.floor(5);\ndouble b = Math.floor(x);\ndouble c = Math.round(2);\nDate d = DateUtils.truncate(now, 1);\n} }";
        assert_eq!(flagged("java/pointless-math", src), [2, 4]);
        assert_eq!(flagged("java/commons-date-truncate", src), [5]);
    }
}
