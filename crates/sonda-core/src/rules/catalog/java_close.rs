//! Java rules, part 8 (ADR-0007, batch 18): in-file approximations of the
//! hierarchy, nullness and newer-Java rules that need more than one file to
//! be exact. They look at the classes declared in the same file and stay
//! silent when the answer depends on code they cannot see.

use super::java_bugs::{has_annotation, has_modifier, statements};
use super::java_extra::{class_members, declared_type, name_text, type_text};
use super::java_final::{base_type, root_of};
use super::java_flow::{find_declared_type, has_method, nodes_in, superclass_name};
use super::java_security::{call_arguments, find_node, method_name, text};
use super::java_smells::{children_of_kind, count_word, enclosing_class};
use super::*;

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "java/indentation-inconsistent",
        name: "Source code should be indented consistently",
        description: "Statements of one block should start in the same column.",
        message: "Align the statements.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S1120")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(block) @match"#,
            filter: Some(Find(statement_is_misaligned)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() {\n  a();\n    b();\n } }",
            good: "class A { void f() {\n  a();\n  b();\n } }",
        }),
    },
    Rule {
        id: "java/equals-asymmetric",
        name: "equals methods should be symmetric and work for subclasses",
        description: "instanceof makes a.equals(b) differ from b.equals(a) once a subclass adds state.",
        message: "Compare getClass(), or make the class final.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S2162")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration name: (identifier) @n (#eq? @n "equals")) @match"#,
            filter: Some(Keep(equals_uses_instanceof_with_subclasses)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class P { public boolean equals(Object o) { return o instanceof P; } }\nclass C extends P {}",
            good: "class P { public boolean equals(Object o) { return o != null && o.getClass() == getClass(); } }\nclass C extends P {}",
        }),
    },
    Rule {
        id: "java/override-typo",
        name: "Child class methods named for parent class methods should be overrides",
        description: "Same name and arity with different types is usually a mistyped override.",
        message: "Match the parent's signature, or rename the method.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2177")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Find(method_looks_like_a_mistyped_override)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class P { void run(String s) {} }\nclass C extends P { void run(Object s) {} }",
            good: "class P { void run(String s) {} }\nclass C extends P { @Override void run(String s) {} }",
        }),
    },
    Rule {
        id: "java/catch-exception-needlessly",
        name: "Exception should not be caught when not required by called methods",
        description: "Nothing in the try block can throw a checked exception.",
        message: "Catch the specific unchecked exception, or nothing.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S2221")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(catch_clause) @match"#,
            filter: Some(Keep(catches_exception_around_plain_code)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(int a) { try { a++; } catch (Exception e) { g(); } } }",
            good: "class A { void f() { try { read(); } catch (IOException e) { g(); } } }",
        }),
    },
    Rule {
        id: "java/list-search-in-loop",
        name: "Collection methods with O(n) performance should be used carefully",
        description: "contains and indexOf on a list inside a loop make it quadratic.",
        message: "Use a Set or a Map.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 10,
        sonar: &[exact("S2250")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "contains" "indexOf")) @match"#,
            filter: Some(Keep(searches_a_list_in_a_loop)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(List<String> l, List<String> m) { for (String s : m) { if (l.contains(s)) { g(); } } } }",
            good: "class A { void f(Set<String> l, List<String> m) { for (String s : m) { if (l.contains(s)) { g(); } } } }",
        }),
    },
    Rule {
        id: "java/override-contract",
        name: "Method overrides should not change contracts",
        description: "An override that tightens a parameter or loosens the result breaks callers of the parent.",
        message: "Keep the parent's nullability.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S2638")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Find(override_changes_nullability)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class P { @NonNull String f() { return \"a\"; } }\nclass C extends P { @Nullable String f() { return null; } }",
            good: "class P { @NonNull String f() { return \"a\"; } }\nclass C extends P { @NonNull String f() { return \"b\"; } }",
        }),
    },
    Rule {
        id: "java/concrete-parameter",
        name: "Method parameters should be declared with base types",
        description: "A concrete collection parameter ties callers to one implementation.",
        message: "Declare the interface.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S3242")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(formal_parameter type: (generic_type (type_identifier) @t (#any-of? @t "ArrayList" "LinkedList" "HashMap" "TreeMap" "LinkedHashMap" "HashSet" "TreeSet" "LinkedHashSet"))) @match"#,
            filter: Some(Keep(parameter_of_a_public_method)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { public void f(ArrayList<String> l) {} }",
            good: "class A { public void f(List<String> l) {} }",
        }),
    },
    Rule {
        id: "java/annotation-default-passed",
        name: "Default annotation parameter values should not be passed as arguments",
        description: "The value is already what you get by default.",
        message: "Remove the argument.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S3254")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(annotation) @match"#,
            filter: Some(Keep(passes_the_default_value)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "@interface Cfg { int size() default 5; }\n@Cfg(size = 5) class A {}",
            good: "@interface Cfg { int size() default 5; }\n@Cfg(size = 6) class A {}",
        }),
    },
    Rule {
        id: "java/private-method-for-inner-class",
        name: "private methods called only by inner classes should be moved to those classes",
        description: "The outer class carries a method nothing in it uses.",
        message: "Move it into the inner class.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S3398")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Find(private_method_used_only_by_inner_classes)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { private void helper() {} class B { void f() { helper(); } } }",
            good: "class A { class B { private void helper() {} void f() { helper(); } } }",
        }),
    },
    Rule {
        id: "java/serializable-optional-field",
        name: "Value-based objects should not be serialized",
        description: "Optional is not Serializable, so the field breaks serialization.",
        message: "Store the value, or null.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3437")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Find(serializable_class_holds_optional)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A implements Serializable { private Optional<String> o; }",
            good: "class A implements Serializable { private String o; }",
        }),
    },
    Rule {
        id: "java/override-drops-synchronized",
        name: "Overrides should match their parent class methods in synchronization",
        description: "An unsynchronized override breaks the lock callers rely on.",
        message: "Add synchronized.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3551")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Find(override_drops_synchronized)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class P { synchronized void f() {} }\nclass C extends P { @Override void f() {} }",
            good: "class P { synchronized void f() {} }\nclass C extends P { @Override synchronized void f() {} }",
        }),
    },
    Rule {
        id: "java/test-swallows-everything",
        name: "Unit tests should throw exceptions",
        description: "A test that catches Exception hides the failure it exists to find.",
        message: "Declare throws and let it propagate.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3658")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Keep(test_is_one_catch_all)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { @Test void t() { try { g(); } catch (Exception e) { log(e); } } }",
            good: "class A { @Test void t() throws Exception { g(); } }",
        }),
    },
    Rule {
        id: "java/component-field-not-injected",
        name: "Members of Spring components should be injected",
        description: "A non-injected mutable field in a singleton bean is shared state.",
        message: "Inject it, or make it local.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3749")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Find(component_has_uninjected_field)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "@Service class A { private Helper helper = null; }",
            good: "@Service class A { @Autowired private Helper helper; }",
        }),
    },
    Rule {
        id: "java/null-for-nonnull-parameter",
        name: "Nullness of parameters should be guaranteed",
        description: "Passing null to a @NonNull parameter breaks its contract.",
        message: "Pass a value.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S4449")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation) @match"#,
            filter: Some(Keep(passes_null_to_a_nonnull_parameter)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void m(@NonNull String s) {} void f() { m(null); } }",
            good: "class A { void m(@NonNull String s) {} void f() { m(\"a\"); } }",
        }),
    },
    Rule {
        id: "java/varargs-called-with-null",
        name: "Vararg method arguments should not be confusing",
        description: "A lone null can be read as the array or as one element.",
        message: "Pass an empty array or a cast null.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5669")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation) @match"#,
            filter: Some(Keep(passes_a_bare_null_to_varargs)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void m(String... a) {} void f() { m(null); } }",
            good: "class A { void m(String... a) {} void f() { m(); } }",
        }),
    },
    Rule {
        id: "java/text-block-in-expression",
        name: "Text blocks should not be used in complex expressions",
        description: "A text block hides inside a longer expression.",
        message: "Assign it to a variable first.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6203")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(binary_expression operator: "+") @match"#,
            filter: Some(Keep(has_a_text_block_operand)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { String s = \"\"\"\n a\n \"\"\" + x; }",
            good: "class A { String t = \"\"\"\n a\n \"\"\"; String s = t + x; }",
        }),
    },
    Rule {
        id: "java/record-accessor-override",
        name: "Custom getter method should not be used to override record's getter behavior",
        description: "Callers expect the accessor to return the component.",
        message: "Compute it in a different method.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S6211")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(record_declaration) @match"#,
            filter: Some(Find(record_accessor_does_more)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "record R(int x) { public int x() { return x + 1; } }",
            good: "record R(int x) { public int next() { return x + 1; } }",
        }),
    },
    Rule {
        id: "java/record-pattern",
        name: "Use record pattern instead of explicit field access",
        description: "A record pattern extracts the components directly.",
        message: "Deconstruct the record.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S6878")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(if_statement) @match"#,
            filter: Some(Keep(reads_record_components_after_instanceof)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "record P(int x, int y) {}\nclass A { void f(Object o) { if (o instanceof P p) { g(p.x(), p.y()); } } }",
            good: "record P(int x, int y) {}\nclass A { void f(Object o) { if (o instanceof P(int x, int y)) { g(x, y); } } }",
        }),
    },
    Rule {
        id: "java/single-if-in-pattern-case",
        name: "Use when instead of a single if inside a pattern match body",
        description: "A guard belongs on the case.",
        message: "Use `case T t when cond ->`.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6916")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(switch_rule (block) @match)"#,
            filter: Some(Keep(block_is_one_if)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(Object o) { switch (o) { case String s -> { if (s.isEmpty()) { g(); } } default -> h(); } } }",
            good: "class A { void f(Object o) { switch (o) { case String s when s.isEmpty() -> g(); default -> h(); } } }",
        }),
    },
    Rule {
        id: "java/extra-comment-slashes",
        name: "Comments should start with the appropriate number of slashes",
        description: "Four slashes is a typo for two, and three is a Markdown doc comment.",
        message: "Use // or ///.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S7476")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(line_comment) @match"#,
            filter: Some(Keep(has_extra_slashes)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A {\n //// note\n int x;\n}",
            good: "class A {\n // note\n int x;\n}",
        }),
    },
    Rule {
        id: "java/gatherer-initializer",
        name: "Don't provide an initializer for a stateless stream gatherer",
        description: "A gatherer with no state needs no initializer.",
        message: "Use the overload without one.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7482")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) @o name: (identifier) @n (#eq? @o "Gatherer") (#any-of? @n "of" "ofSequential") arguments: (argument_list . (lambda_expression) @l)) @match"#,
            filter: Some(Keep(initializer_returns_null)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Object g = Gatherer.ofSequential(() -> null, integrator); } }",
            good: "class A { void f() { Object g = Gatherer.ofSequential(integrator); } }",
        }),
    },
    Rule {
        id: "java/gatherer-default-finisher",
        name: "When a defaultFinisher is passed to a Gatherer factory, use the overload that does not take a finisher",
        description: "The default finisher is what the shorter overload uses.",
        message: "Drop the argument.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7629")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) @o name: (identifier) @n (#eq? @o "Gatherer") (#any-of? @n "of" "ofSequential") arguments: (argument_list (method_invocation name: (identifier) @d (#eq? @d "defaultFinisher")))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Object g = Gatherer.ofSequential(init, integrator, Gatherer.defaultFinisher()); } }",
            good: "class A { void f() { Object g = Gatherer.ofSequential(init, integrator); } }",
        }),
    },
    Rule {
        id: "java/class-builder-method-body",
        name: "ClassBuilder.withMethodBody should be preferred to ClassBuilder.withMethod",
        description: "withMethod plus withCode is what withMethodBody does.",
        message: "Use withMethodBody.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7479")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "withMethod") arguments: (argument_list (lambda_expression) @l)) @match"#,
            filter: Some(Keep(lambda_only_adds_code)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { cb.withMethod(\"m\", desc, 1, mb -> mb.withCode(code)); } }",
            good: "class A { void f() { cb.withMethodBody(\"m\", desc, 1, code); } }",
        }),
    },
    Rule {
        id: "java/import-order",
        name: "Module imports should come first and imports should be grouped by kind",
        description: "Static and regular imports interleaved are hard to scan.",
        message: "Group the imports.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S8445")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(program) @match"#,
            filter: Some(Find(imports_are_interleaved)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "import static a.B.c;\nimport java.util.List;\nclass A {}",
            good: "import java.util.List;\nimport static a.B.c;\nclass A {}",
        }),
    },
    Rule {
        id: "java/virtual-executor-synchronized",
        name: "Virtual threads should not run tasks that include synchronized code",
        description: "Synchronized blocks pin the carrier thread.",
        message: "Use a ReentrantLock.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S6906")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "submit" "execute")) @match"#,
            filter: Some(Keep(virtual_task_synchronizes)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { ExecutorService e = Executors.newVirtualThreadPerTaskExecutor(); e.submit(() -> { synchronized (this) { g(); } }); } }",
            good: "class A { void f() { ExecutorService e = Executors.newVirtualThreadPerTaskExecutor(); e.submit(() -> { lock.lock(); }); } }",
        }),
    },
    Rule {
        id: "java/gyroscope-sensor",
        name: "Motion Sensor should not use gyroscope",
        description: "The gyroscope costs far more battery than the accelerometer.",
        message: "Use the rotation vector or accelerometer.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S6923")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(field_access field: (identifier) @f (#eq? @f "TYPE_GYROSCOPE")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Sensor s = sm.getDefaultSensor(Sensor.TYPE_GYROSCOPE); } }",
            good: "class A { void f() { Sensor s = sm.getDefaultSensor(Sensor.TYPE_ACCELEROMETER); } }",
        }),
    },
    Rule {
        id: "java/switch-to-expression",
        name: "Use Java 14 switch expression",
        description: "Every branch assigns the same variable.",
        message: "Use a switch expression.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S5194")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(switch_expression) @match"#,
            filter: Some(Keep(every_case_assigns_one_variable)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { int f(int x) { int r; switch (x) { case 1: r = 1; break; case 2: r = 2; break; default: r = 0; break; } return r; } }",
            good: "class A { int f(int x) { return switch (x) { case 1 -> 1; case 2 -> 2; default -> 0; }; } }",
        }),
    },
    Rule {
        id: "java/one-line-text-block",
        name: "Simple string literal should be used for single line strings",
        description: "A text block of one line is a string.",
        message: "Use a string literal.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S5663")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(string_literal) @match"#,
            filter: Some(Keep(text_block_has_one_line)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { String s = \"\"\"\n a\"\"\"; }",
            good: "class A { String s = \"a\"; }",
        }),
    },
    Rule {
        id: "java/saml-comments",
        name: "OpenSAML2 should be configured to prevent authentication bypass",
        description: "A comment inside a NameID can change which user the parser reads.",
        message: "Call setIgnoreComments(true).",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S5679")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(object_creation_expression type: (type_identifier) @t (#eq? @t "BasicParserPool")) @match"#,
            filter: Some(Keep(parser_pool_keeps_comments)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { BasicParserPool p = new BasicParserPool(); } }",
            good: "class A { void f() { BasicParserPool p = new BasicParserPool(); p.setIgnoreComments(true); } }",
        }),
    },
    Rule {
        id: "java/brain-method",
        name: "Methods should not perform too many tasks",
        description: "A long, branching, deeply nested method does several jobs at once.",
        message: "Split the method.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 30,
        sonar: &[exact("S6541")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Keep(is_a_brain_method)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(int a) {\n if (a == 1) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 2) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 3) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 4) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 5) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 6) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 7) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 8) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 9) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 10) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 11) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 12) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 13) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 14) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 15) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 16) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 17) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 18) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 19) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 20) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 21) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 22) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 23) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 24) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 25) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 26) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 27) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 28) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 29) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 30) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 31) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 32) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 33) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 34) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 35) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 36) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 37) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 38) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 39) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 40) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 41) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 42) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 43) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 44) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 45) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 46) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 47) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 48) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 49) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 50) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 51) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 52) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 53) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 54) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 55) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 56) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 57) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 58) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 59) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 60) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 61) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 62) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 63) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 64) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 65) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 66) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 67) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 68) { if (a > 1) { if (a > 2) { g(); } } }\n if (a == 69) { if (a > 1) { if (a > 2) { g(); } } }\n} }",
            good: "class A { void f(int a) { g(); } }",
        }),
    },
];

// ---------------------------------------------------- filters

fn in_loop(node: Node) -> bool {
    let mut p = node.parent();
    while let Some(n) = p {
        if matches!(
            n.kind(),
            "for_statement" | "enhanced_for_statement" | "while_statement" | "do_statement"
        ) {
            return true;
        }
        if matches!(
            n.kind(),
            "method_declaration" | "lambda_expression" | "class_body"
        ) {
            return false;
        }
        p = n.parent();
    }
    false
}

fn arity(method: Node) -> usize {
    method
        .child_by_field_name("parameters")
        .map_or(0, |p| p.named_child_count())
}

fn parameter_types<'s>(method: Node, src: &'s [u8]) -> Vec<&'s [u8]> {
    method
        .child_by_field_name("parameters")
        .map(|p| {
            p.named_children(&mut p.walk())
                .filter_map(|x| x.child_by_field_name("type").map(|t| text(t, src)))
                .collect()
        })
        .unwrap_or_default()
}

fn parent_class<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    superclass_name(class, src)
        .and_then(|n| find_declared_type(root_of(class), n, src))
        .filter(|p| p.kind() == "class_declaration")
}

fn null_annotation(declaration: Node, src: &[u8]) -> Option<bool> {
    if [&b"NonNull"[..], b"Nonnull", b"NotNull"]
        .iter()
        .any(|a| has_annotation(declaration, a, src))
    {
        Some(false)
    } else if [&b"Nullable"[..], b"CheckForNull"]
        .iter()
        .any(|a| has_annotation(declaration, a, src))
    {
        Some(true)
    } else {
        None
    }
}

fn statement_is_misaligned<'t>(block: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    let items = statements(block);
    items.windows(2).find_map(|w| {
        (w[1].start_position().row > w[0].end_position().row
            && w[1].start_position().column != w[0].start_position().column)
            .then_some(w[1])
    })
}

fn equals_uses_instanceof_with_subclasses(method: Node, src: &[u8]) -> bool {
    let Some(class) = enclosing_class(method).filter(|c| c.kind() == "class_declaration") else {
        return false;
    };
    if has_modifier(class, "final") {
        return false;
    }
    let name = name_text(class, src);
    let uses_instanceof = method.child_by_field_name("body").is_some_and(|b| {
        find_node(b, |n| {
            n.kind() == "instanceof_expression"
                && n.named_children(&mut n.walk())
                    .any(|c| text(c, src) == name)
        })
        .is_some()
    });
    uses_instanceof
        && find_node(root_of(method), |n| {
            n.kind() == "class_declaration" && superclass_name(n, src) == Some(name)
        })
        .is_some()
}

fn method_looks_like_a_mistyped_override<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let parent = parent_class(class, src)?;
    class_members(class).into_iter().find(|m| {
        m.kind() == "method_declaration"
            && !has_annotation(*m, b"Override", src)
            && !has_modifier(*m, "static")
            && {
                let same_name = has_method(parent, name_text(*m, src), src);
                let mine = parameter_types(*m, src);
                !same_name.is_empty()
                    && same_name
                        .iter()
                        .all(|p| arity(*p) == arity(*m) && parameter_types(*p, src) != mine)
            }
    })
}

fn catches_exception_around_plain_code(catch: Node, src: &[u8]) -> bool {
    let broad = catch
        .named_children(&mut catch.walk())
        .find(|c| c.kind() == "catch_formal_parameter")
        .is_some_and(|p| {
            p.named_children(&mut p.walk())
                .any(|t| matches!(text(t, src), b"Exception" | b"Throwable"))
        });
    let Some(body) = catch.parent().and_then(|t| t.child_by_field_name("body")) else {
        return false;
    };
    broad
        && find_node(body, |n| {
            matches!(
                n.kind(),
                "method_invocation" | "object_creation_expression" | "throw_statement"
            )
        })
        .is_none()
}

fn searches_a_list_in_a_loop(call: Node, src: &[u8]) -> bool {
    in_loop(call)
        && call.child_by_field_name("object").is_some_and(|o| {
            o.kind() == "identifier"
                && matches!(
                    base_type(type_text(declared_type(call, text(o, src), src), src)),
                    b"List" | b"ArrayList" | b"LinkedList"
                )
        })
}

fn override_changes_nullability<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let parent = parent_class(class, src)?;
    class_members(class).into_iter().find(|m| {
        m.kind() == "method_declaration"
            && has_method(parent, name_text(*m, src), src).iter().any(|p| {
                if arity(*p) != arity(*m) {
                    return false;
                }
                let result = null_annotation(*p, src) == Some(false)
                    && null_annotation(*m, src) == Some(true);
                let params = |x: Node| -> Vec<Option<bool>> {
                    x.child_by_field_name("parameters")
                        .map(|ps| {
                            ps.named_children(&mut ps.walk())
                                .map(|f| null_annotation(f, src))
                                .collect()
                        })
                        .unwrap_or_default()
                };
                let tighter = params(*p)
                    .iter()
                    .zip(params(*m))
                    .any(|(pp, mm)| *pp != Some(false) && mm == Some(false));
                result || tighter
            })
    })
}

fn parameter_of_a_public_method(param: Node, _: &[u8]) -> bool {
    param
        .parent()
        .and_then(|ps| ps.parent())
        .is_some_and(|m| m.kind() == "method_declaration" && has_modifier(m, "public"))
}

fn passes_the_default_value(annotation: Node, src: &[u8]) -> bool {
    let name = name_text(annotation, src);
    let Some(decl) = find_node(root_of(annotation), |n| {
        n.kind() == "annotation_type_declaration" && name_text(n, src) == name
    }) else {
        return false;
    };
    let Some(args) = annotation.child_by_field_name("arguments") else {
        return false;
    };
    args.named_children(&mut args.walk()).any(|pair| {
        pair.kind() == "element_value_pair" && {
            let (Some(k), Some(v)) = (
                pair.child_by_field_name("key"),
                pair.child_by_field_name("value"),
            ) else {
                return false;
            };
            find_node(decl, |e| {
                e.kind() == "annotation_type_element_declaration"
                    && name_text(e, src) == text(k, src)
                    && e.child_by_field_name("value")
                        .is_some_and(|d| text(d, src) == text(v, src))
            })
            .is_some()
        }
    })
}

fn private_method_used_only_by_inner_classes<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let members = class_members(class);
    let nested: Vec<Node> = members
        .iter()
        .copied()
        .filter(|m| m.kind() == "class_declaration")
        .collect();
    members.iter().copied().find(|m| {
        if m.kind() != "method_declaration" || !has_modifier(*m, "private") {
            return false;
        }
        let name = name_text(*m, src);
        let outside: usize = members
            .iter()
            .filter(|o| o.kind() != "class_declaration" && **o != *m)
            .map(|o| count_word(text(*o, src), name))
            .sum();
        let inside: usize = nested.iter().map(|n| count_word(text(*n, src), name)).sum();
        outside == 0 && inside > 0
    })
}

fn serializable_class_holds_optional<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !class
        .child_by_field_name("interfaces")
        .is_some_and(|i| count_word(text(i, src), b"Serializable") > 0)
    {
        return None;
    }
    class_members(class).into_iter().find(|m| {
        m.kind() == "field_declaration"
            && !has_modifier(*m, "static")
            && !has_modifier(*m, "transient")
            && base_type(type_text(m.child_by_field_name("type"), src)).starts_with(b"Optional")
    })
}

fn override_drops_synchronized<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let parent = parent_class(class, src)?;
    class_members(class).into_iter().find(|m| {
        m.kind() == "method_declaration"
            && !has_modifier(*m, "synchronized")
            && !has_modifier(*m, "static")
            && has_method(parent, name_text(*m, src), src)
                .iter()
                .any(|p| arity(*p) == arity(*m) && has_modifier(*p, "synchronized"))
    })
}

fn test_is_one_catch_all(method: Node, src: &[u8]) -> bool {
    if !has_annotation(method, b"Test", src) {
        return false;
    }
    let Some(body) = method.child_by_field_name("body") else {
        return false;
    };
    let items = statements(body);
    let [only] = items.as_slice() else {
        return false;
    };
    only.kind() == "try_statement"
        && children_of_kind(*only, "catch_clause").iter().any(|c| {
            c.named_children(&mut c.walk())
                .filter(|p| p.kind() == "catch_formal_parameter")
                .any(|p| {
                    p.named_children(&mut p.walk())
                        .any(|t| matches!(text(t, src), b"Exception" | b"Throwable"))
                })
        })
}

fn component_has_uninjected_field<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    const COMPONENTS: &[&[u8]] = &[
        b"Component",
        b"Service",
        b"Repository",
        b"Controller",
        b"RestController",
    ];
    if !COMPONENTS.iter().any(|a| has_annotation(class, a, src)) {
        return None;
    }
    class_members(class).into_iter().find(|m| {
        m.kind() == "field_declaration"
            && !has_modifier(*m, "static")
            && !has_modifier(*m, "final")
            && super::java_bugs::modifiers_of(*m)
                .is_none_or(|mods| !text(mods, src).contains(&b'@'))
            && m.child_by_field_name("type").is_some_and(|t| {
                !matches!(
                    t.kind(),
                    "integral_type" | "floating_point_type" | "boolean_type"
                ) && !matches!(
                    text(t, src),
                    b"String"
                        | b"Integer"
                        | b"Long"
                        | b"Boolean"
                        | b"Double"
                        | b"Logger"
                        | b"Object"
                )
            })
    })
}

fn same_class_target<'t>(call: Node<'t>, src: &[u8]) -> Vec<Node<'t>> {
    if call.child_by_field_name("object").is_some() {
        return Vec::new();
    }
    enclosing_class(call)
        .map(|c| has_method(c, method_name(call, src), src))
        .unwrap_or_default()
}

fn passes_null_to_a_nonnull_parameter(call: Node, src: &[u8]) -> bool {
    let args = call_arguments(call);
    same_class_target(call, src).iter().any(|m| {
        arity(*m) == args.len()
            && m.child_by_field_name("parameters").is_some_and(|ps| {
                ps.named_children(&mut ps.walk()).zip(&args).any(|(p, a)| {
                    a.kind() == "null_literal" && null_annotation(p, src) == Some(false)
                })
            })
    })
}

fn passes_a_bare_null_to_varargs(call: Node, src: &[u8]) -> bool {
    let args = call_arguments(call);
    matches!(args.as_slice(), [a] if a.kind() == "null_literal")
        && same_class_target(call, src).iter().any(|m| {
            m.child_by_field_name("parameters").is_some_and(|ps| {
                ps.named_children(&mut ps.walk())
                    .any(|p| p.kind() == "spread_parameter")
            })
        })
}

fn has_a_text_block_operand(binary: Node, src: &[u8]) -> bool {
    ["left", "right"].iter().any(|side| {
        binary
            .child_by_field_name(side)
            .is_some_and(|n| n.kind() == "string_literal" && text(n, src).starts_with(b"\"\"\""))
    })
}

fn record_accessor_does_more<'t>(record: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let components: Vec<&[u8]> = record
        .child_by_field_name("parameters")?
        .named_children(&mut record.walk())
        .filter_map(|p| p.child_by_field_name("name").map(|n| text(n, src)))
        .collect();
    class_members(record).into_iter().find(|m| {
        let name = name_text(*m, src);
        m.kind() == "method_declaration"
            && arity(*m) == 0
            && components.contains(&name)
            && m.child_by_field_name("body").is_some_and(|b| {
                let items = statements(b);
                let plain = |expected: &[u8]| items.len() == 1 && text(items[0], src) == expected;
                !(plain(&[b"return ", name, b";"].concat())
                    || plain(&[b"return this.", name, b";"].concat()))
            })
    })
}

fn reads_record_components_after_instanceof(if_statement: Node, src: &[u8]) -> bool {
    let Some(cond) = if_statement.child_by_field_name("condition") else {
        return false;
    };
    let Some(test) = find_node(cond, |n| n.kind() == "instanceof_expression") else {
        return false;
    };
    let parts: Vec<Node> = test.named_children(&mut test.walk()).collect();
    let [_, ty, binding] = parts.as_slice() else {
        return false;
    };
    if binding.kind() != "identifier" {
        return false;
    }
    let Some(record) = find_declared_type(root_of(if_statement), text(*ty, src), src)
        .filter(|r| r.kind() == "record_declaration")
    else {
        return false;
    };
    let components: Vec<&[u8]> = record
        .child_by_field_name("parameters")
        .map(|p| {
            p.named_children(&mut p.walk())
                .filter_map(|x| x.child_by_field_name("name").map(|n| text(n, src)))
                .collect()
        })
        .unwrap_or_default();
    let name = text(*binding, src);
    let Some(body) = if_statement.child_by_field_name("consequence") else {
        return false;
    };
    let uses = nodes_in(body, &[], |n| {
        n.kind() == "identifier" && text(n, src) == name
    });
    !uses.is_empty()
        && uses.iter().all(|u| {
            u.parent().is_some_and(|p| {
                p.kind() == "method_invocation"
                    && p.child_by_field_name("object") == Some(*u)
                    && components.contains(&method_name(p, src))
                    && call_arguments(p).is_empty()
            })
        })
}

fn block_is_one_if(block: Node, src: &[u8]) -> bool {
    let items = statements(block);
    let [only] = items.as_slice() else {
        return false;
    };
    let pattern_label = block
        .parent()
        .and_then(|rule| rule.named_child(0))
        .is_some_and(|label| {
            let words: Vec<&[u8]> = text(label, src)
                .split(|b| b.is_ascii_whitespace())
                .filter(|w| !w.is_empty())
                .collect();
            words.len() == 3
                && words[0] == b"case"
                && words[1].first().is_some_and(u8::is_ascii_uppercase)
        });
    pattern_label
        && only.kind() == "if_statement"
        && only.child_by_field_name("alternative").is_none()
}

fn has_extra_slashes(comment: Node, src: &[u8]) -> bool {
    text(comment, src).starts_with(b"////")
}

fn initializer_returns_null(call: Node, src: &[u8]) -> bool {
    call_arguments(call).first().is_some_and(|l| {
        l.kind() == "lambda_expression"
            && l.child_by_field_name("body")
                .is_some_and(|b| b.kind() == "null_literal")
            && text(*l, src).starts_with(b"()")
    })
}

fn lambda_only_adds_code(call: Node, src: &[u8]) -> bool {
    call_arguments(call).iter().any(|a| {
        a.kind() == "lambda_expression"
            && a.child_by_field_name("body").is_some_and(|b| {
                let inner = if b.kind() == "block" {
                    let s = statements(b);
                    if s.len() != 1 {
                        return false;
                    }
                    s[0].named_child(0)
                } else {
                    Some(b)
                };
                inner.is_some_and(|i| {
                    i.kind() == "method_invocation" && method_name(i, src) == b"withCode"
                })
            })
    })
}

fn imports_are_interleaved<'t>(program: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut seen_static = false;
    for import in children_of_kind(program, "import_declaration") {
        let is_static = count_word(text(import, src), b"static") > 0;
        if is_static {
            seen_static = true;
        } else if seen_static {
            return Some(import);
        }
    }
    None
}

fn virtual_task_synchronizes(call: Node, src: &[u8]) -> bool {
    let Some(object) = call
        .child_by_field_name("object")
        .filter(|o| o.kind() == "identifier")
    else {
        return false;
    };
    let name = text(object, src);
    let virtual_executor = find_node(root_of(call), |n| {
        n.kind() == "variable_declarator"
            && n.child_by_field_name("name")
                .is_some_and(|x| text(x, src) == name)
            && n.child_by_field_name("value")
                .is_some_and(|v| count_word(text(v, src), b"newVirtualThreadPerTaskExecutor") > 0)
    })
    .is_some();
    virtual_executor
        && call_arguments(call).iter().any(|a| {
            a.kind() == "lambda_expression"
                && find_node(*a, |n| n.kind() == "synchronized_statement").is_some()
        })
}

fn every_case_assigns_one_variable(switch: Node, src: &[u8]) -> bool {
    if !switch
        .parent()
        .is_some_and(|p| matches!(p.kind(), "expression_statement" | "block"))
    {
        return false;
    }
    let groups = nodes_in(switch, &["switch_expression"], |n| {
        n.kind() == "switch_block_statement_group"
    });
    if groups.len() < 2 {
        return false;
    }
    let mut target: Option<Vec<u8>> = None;
    groups.iter().all(|g| {
        let items: Vec<Node> = statements(*g)
            .into_iter()
            .filter(|s| s.kind() != "switch_label")
            .collect();
        let assign = items
            .first()
            .and_then(|s| s.named_child(0))
            .filter(|a| a.kind() == "assignment_expression");
        let ok_shape = items.len() == 2 && items[1].kind() == "break_statement" || items.len() == 1;
        let Some(left) = assign
            .and_then(|a| a.child_by_field_name("left"))
            .filter(|l| l.kind() == "identifier")
        else {
            return false;
        };
        let t = text(left, src).to_vec();
        let same = target.as_ref().is_none_or(|x| *x == t);
        target = Some(t);
        ok_shape && same
    })
}

fn text_block_has_one_line(literal: Node, src: &[u8]) -> bool {
    let t = text(literal, src);
    t.starts_with(b"\"\"\"") && t.iter().filter(|&&b| b == b'\n').count() == 1
}

fn parser_pool_keeps_comments(creation: Node, src: &[u8]) -> bool {
    let scope = enclosing_class(creation).unwrap_or(root_of(creation));
    count_word(text(scope, src), b"setIgnoreComments") == 0
}

fn is_a_brain_method(method: Node, src: &[u8]) -> bool {
    let lines = method.end_position().row - method.start_position().row + 1;
    if lines <= 64 {
        return false;
    }
    let Some(body) = method.child_by_field_name("body") else {
        return false;
    };
    let branches = nodes_in(body, &["lambda_expression", "class_body"], |n| {
        match n.kind() {
            "if_statement"
            | "for_statement"
            | "enhanced_for_statement"
            | "while_statement"
            | "do_statement"
            | "catch_clause"
            | "ternary_expression" => true,
            "switch_label" => text(n, src).starts_with(b"case"),
            _ => false,
        }
    })
    .len();
    branches > 14
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
    fn hierarchy_rules() {
        let src = "class P {\n synchronized void a() {}\n void run(String s) {}\n @NonNull String n() { return \"\"; }\n public boolean equals(Object o) { return o instanceof P; }\n}\nclass C extends P {\n void a() {}\n void run(Object s) {}\n @Nullable String n() { return null; }\n}";
        assert_eq!(flagged("java/override-drops-synchronized", src), [8]);
        assert_eq!(flagged("java/override-typo", src), [9]);
        assert_eq!(flagged("java/override-contract", src), [10]);
        assert_eq!(flagged("java/equals-asymmetric", src), [5]);
    }

    #[test]
    fn nullness_and_varargs() {
        let src = "class A {\n void m(@NonNull String s) {}\n void v(String... a) {}\n void f() {\n  m(null);\n  m(\"a\");\n  v(null);\n  v();\n }\n}";
        assert_eq!(flagged("java/null-for-nonnull-parameter", src), [5]);
        assert_eq!(flagged("java/varargs-called-with-null", src), [7]);
    }

    #[test]
    fn records_and_switches() {
        let src = "record P(int x, int y) { public int x() { return x + 1; } public int y() { return y; } }\nclass A {\n void f(Object o, int k) {\n  if (o instanceof P p) { g(p.x(), p.y()); }\n  int r;\n  switch (k) { case 1: r = 1; break; default: r = 0; break; }\n  String s = \"\"\"\n   a\"\"\";\n }\n}";
        assert_eq!(flagged("java/record-accessor-override", src), [1]);
        assert_eq!(flagged("java/record-pattern", src), [4]);
        assert_eq!(flagged("java/switch-to-expression", src), [6]);
        assert_eq!(flagged("java/one-line-text-block", src), [7]);
    }

    #[test]
    fn imports_and_inner_classes() {
        let src = "import static a.B.c;\nimport java.util.List;\nclass A {\n private void helper() {}\n class B { void f() { helper(); } }\n}";
        assert_eq!(flagged("java/import-order", src), [2]);
        assert_eq!(flagged("java/private-method-for-inner-class", src), [4]);
    }
}
