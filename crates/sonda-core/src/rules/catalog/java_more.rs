//! Java rules, part 2 (ADR-0007, batch 9): serialization, concurrency,
//! Spring and JUnit checks, and a few more smells. Queries stay cheap on deep
//! trees: see `js_modern.rs`.

use super::java_bugs::{
    find_in_scope, has_annotation, has_modifier, modifiers_of, operator_text, owning_declaration,
    parameter_types, statements,
};
use super::java_security::{
    call_arguments, contains_ignoring_case, find_node, method_name, string_value, text,
};
use super::java_smells::{
    LOOPS, children_of_kind, count_word, declarator_names, enclosing_class, members,
};
use super::*;

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "java/jump-in-finally",
        name: "Jump statements should not occur in finally blocks",
        description: "A return, break or continue in finally discards any exception that is propagating.",
        message: "Move this jump out of the finally block.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S1143")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(finally_clause) @match"#,
            filter: Some(Find(jump_in_finally)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { int f() { try { return g(); } finally { return 1; } } }",
            good: "class A { int f() { try { return g(); } finally { close(); } } }",
        }),
    },
    Rule {
        id: "java/externalizable-constructor",
        name: "Externalizable classes should have no-arguments constructors",
        description: "Deserialization creates the object with its public no-argument constructor.",
        message: "Add a public no-argument constructor.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2060")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration (super_interfaces) @i) @match"#,
            filter: Some(Keep(externalizable_lacks_default_constructor)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A implements Externalizable { A(int x) {} }",
            good: "class A implements Externalizable { public A() {} }",
        }),
    },
    Rule {
        id: "java/serializable-inner-class",
        name: "Serializable inner classes of non-serializable outer classes should be static",
        description: "Serializing an inner class drags in the outer instance it cannot serialize.",
        message: "Make this class static.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2066")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration (super_interfaces) @i) @match"#,
            filter: Some(Keep(inner_serializable_of_plain_outer)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class O { class I implements Serializable { } }",
            good: "class O { static class I implements Serializable { } }",
        }),
    },
    Rule {
        id: "java/equals-without-type-check",
        name: "equals(Object obj) should test the argument's type",
        description: "Casting without a check throws ClassCastException for other types.",
        message: "Test the argument's type before casting.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2097")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration name: (identifier) @n (#eq? @n "equals")) @match"#,
            filter: Some(Keep(equals_casts_without_checking)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { public boolean equals(Object o) { A a = (A) o; return true; } }",
            good: "class A { public boolean equals(Object o) { if (!(o instanceof A)) return false; A a = (A) o; return true; } }",
        }),
    },
    Rule {
        id: "java/predictable-string-operation",
        name: "String operations with predictable outcomes should be avoided",
        description: "Comparing two literals, or a literal with itself, always gives the same answer.",
        message: "Remove this operation.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2121")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (string_literal) name: (identifier) @n (#any-of? @n "equals" "equalsIgnoreCase" "contains" "startsWith" "endsWith" "indexOf" "compareTo") arguments: (argument_list . (string_literal))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { boolean b = \"a\".equals(\"a\"); } }",
            good: "class A { void f() { boolean b = x.equals(\"a\"); } }",
        }),
    },
    Rule {
        id: "java/return-value-ignored",
        name: "Return values from functions without side effects should not be ignored",
        description: "Calling toLowerCase() and dropping the result does nothing.",
        message: "Use the returned value.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2201")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(expression_statement (method_invocation name: (identifier) @n (#any-of? @n "toLowerCase" "toUpperCase" "trim" "strip" "substring" "repeat" "toCharArray" "equals" "equalsIgnoreCase" "isEmpty" "startsWith" "endsWith"))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { s.toLowerCase(); } }",
            good: "class A { void f() { s = s.toLowerCase(); } }",
        }),
    },
    Rule {
        id: "java/servlet-mutable-field",
        name: "Servlets should not have mutable instance fields",
        description: "One servlet instance serves every request, so its fields are shared state.",
        message: "Make this field final, or keep the state per request.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S2226")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration superclass: (superclass (type_identifier) @s (#any-of? @s "HttpServlet" "GenericServlet"))) @match"#,
            filter: Some(Find(mutable_instance_field)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class S extends HttpServlet { int hits; }",
            good: "class S extends HttpServlet { final int limit = 3; }",
        }),
    },
    Rule {
        id: "java/proxy-annotation-visibility",
        name: "Methods with Spring proxying annotations should be public",
        description: "Spring's proxies cannot intercept non-public methods.",
        message: "Make this method public.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2230")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Keep(proxied_method_is_not_public)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { @Transactional void f() {} }",
            good: "class A { @Transactional public void f() {} }",
        }),
    },
    Rule {
        id: "java/wait-on-thread",
        name: "wait, notify and notifyAll should not be called on Thread instances",
        description: "Thread uses its own monitor internally, so these calls interfere with join().",
        message: "Don't use a Thread as a lock.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2236")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "wait" "notify" "notifyAll")) @match"#,
            filter: Some(Keep(receiver_looks_like_a_thread)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(Thread thread) throws Exception { thread.wait(); } }",
            good: "class A { void f(Object lock) throws Exception { lock.wait(); } }",
        }),
    },
    Rule {
        id: "java/loop-never-runs",
        name: "Loop conditions should be true at least once",
        description: "A condition that is false on entry means the body never runs.",
        message: "Fix the loop bounds.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2252")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(for_statement) @match"#,
            filter: Some(Keep(condition_is_false_on_entry)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { for (int i = 10; i < 5; i++) {} } }",
            good: "class A { void f() { for (int i = 0; i < 5; i++) {} } }",
        }),
    },
    Rule {
        id: "java/wait-outside-synchronized",
        name: "wait, notify and notifyAll should only be called from synchronized code",
        description: "Without the monitor they throw IllegalMonitorStateException.",
        message: "Call this inside a synchronized block or method.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2273")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "wait" "notify" "notifyAll")) @match"#,
            filter: Some(Keep(is_not_in_synchronized_code)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() throws Exception { lock.wait(); } }",
            good: "class A { void f() throws Exception { synchronized (lock) { lock.wait(); } } }",
        }),
    },
    Rule {
        id: "java/misleading-operator",
        name: "Non-existent operators like =+ should not be used",
        description: "`x =+ 1` assigns +1, which is almost never what was meant.",
        message: "Use += or add a space.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2757")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(assignment_expression right: (unary_expression)) @match"#,
            filter: Some(Keep(sign_glued_to_equals)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { int x = 0; x =+ 1; } }",
            good: "class A { void f() { int x = 0; x += 1; } }",
        }),
    },
    Rule {
        id: "java/to-array-cast",
        name: "Collection.toArray() should be passed an array of the proper type",
        description: "Casting the Object[] result to a typed array throws ClassCastException.",
        message: "Pass a typed array to toArray().",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S3020")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(cast_expression type: (array_type) value: (method_invocation name: (identifier) @n (#eq? @n "toArray"))) @match"#,
            filter: Some(Keep(to_array_has_no_arguments)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { String[] a = (String[]) list.toArray(); } }",
            good: "class A { void f() { String[] a = list.toArray(new String[0]); } }",
        }),
    },
    Rule {
        id: "java/identical-branches",
        name: "All branches in a conditional structure should not have exactly the same implementation",
        description: "If every branch does the same thing, the condition decides nothing.",
        message: "Remove the condition, or fix the branch that should differ.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3923")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(if_statement) @match"#,
            filter: Some(Keep(all_branches_identical)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { if (a) { f(); } else { f(); } } }",
            good: "class A { void f() { if (a) { f(); } else { g(); } } }",
        }),
    },
    Rule {
        id: "java/default-package-application",
        name: "@SpringBootApplication and @ComponentScan should not be used in the default package",
        description: "Spring would scan every class on the classpath.",
        message: "Move the class into a package.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S4602")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(marker_annotation name: (identifier) @n (#any-of? @n "SpringBootApplication" "ComponentScan")) @match
(annotation name: (identifier) @n2 (#any-of? @n2 "SpringBootApplication" "ComponentScan")) @match"#,
            filter: Some(Keep(in_the_default_package)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "@SpringBootApplication class App {}",
            good: "package com.acme;\n@SpringBootApplication class App {}",
        }),
    },
    Rule {
        id: "java/thread-local-never-removed",
        name: "ThreadLocal variables should be cleaned up when no longer used",
        description: "In a thread pool a value left behind leaks into the next task.",
        message: "Call remove() when done.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S5164")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(field_declaration) @match"#,
            filter: Some(Keep(thread_local_is_never_removed)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { static ThreadLocal<String> t = new ThreadLocal<>(); }",
            good: "class A { static ThreadLocal<String> t = new ThreadLocal<>(); void done() { t.remove(); } }",
        }),
    },
    Rule {
        id: "java/nested-test-class-without-nested",
        name: "JUnit5 inner test classes should be annotated with @Nested",
        description: "JUnit 5 only runs non-static inner test classes that are marked @Nested.",
        message: "Add @Nested.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5790")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Keep(inner_test_class_lacks_nested)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "import org.junit.jupiter.api.Test;\nclass T { class Inner { @Test void a() {} } }",
            good: "import org.junit.jupiter.api.Test;\nclass T { @Nested class Inner { @Test void a() {} } }",
        }),
    },
    Rule {
        id: "java/test-silently-ignored",
        name: "JUnit5 test methods should not be silently ignored",
        description: "JUnit 5 skips private and static test methods without a warning.",
        message: "Make this test method non-private and non-static.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5810")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Keep(jupiter_test_is_private_or_static)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "import org.junit.jupiter.api.Test;\nclass T { @Test private void a() {} }",
            good: "import org.junit.jupiter.api.Test;\nclass T { @Test void a() {} }",
        }),
    },
    Rule {
        id: "java/competing-test-annotations",
        name: "Test methods should not be annotated with competing annotations",
        description: "A method with both @Test and @ParameterizedTest runs twice, or not as intended.",
        message: "Keep one test annotation.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5967")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Keep(has_several_test_annotations)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class T { @Test @ParameterizedTest void a() {} }",
            good: "class T { @ParameterizedTest void a() {} }",
        }),
    },
    Rule {
        id: "java/compute-if-absent-null",
        name: "Map computeIfAbsent() and computeIfPresent() should not be used to add null values",
        description: "A mapping function that returns null adds nothing.",
        message: "Use get() or containsKey() instead.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6104")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "computeIfAbsent" "computeIfPresent") arguments: (argument_list (_) (lambda_expression body: (null_literal)))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { m.computeIfAbsent(k, x -> null); } }",
            good: "class A { void f() { m.computeIfAbsent(k, x -> new ArrayList<>()); } }",
        }),
    },
    Rule {
        id: "java/async-in-configuration",
        name: "@Async should not be used on methods declared within a @Configuration class",
        description: "Configuration classes are proxied in a way that prevents @Async from working.",
        message: "Move the method to another bean.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S6817")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Keep(async_method_in_configuration)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "@Configuration class C { @Async void f() {} }",
            good: "@Component class C { @Async void f() {} }",
        }),
    },
    Rule {
        id: "java/path-variable-not-bound",
        name: "Path template variables should be properly bound to method parameters",
        description: "A {variable} with no matching @PathVariable parameter is never read.",
        message: "Bind the variable with @PathVariable.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6856")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Keep(path_variable_has_no_parameter)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class C { @GetMapping(\"/users/{id}\") String f() { return \"\"; } }",
            good: "class C { @GetMapping(\"/users/{id}\") String f(@PathVariable String id) { return id; } }",
        }),
    },
    Rule {
        id: "java/duplicate-bean-name",
        name: "Beans in a @Configuration class should have different names",
        description: "Two @Bean methods with one name register one bean and silently override the other.",
        message: "Rename one of the beans.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6862")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Find(second_bean_with_same_name)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "@Configuration class C { @Bean A a() { return null; } @Bean B a(int x) { return null; } }",
            good: "@Configuration class C { @Bean A a() { return null; } @Bean B b() { return null; } }",
        }),
    },
    Rule {
        id: "java/pbe-literal-salt",
        name: "Password hashing functions should use an unpredictable salt",
        description: "A fixed salt lets attackers precompute hashes for every user.",
        message: "Generate a random salt for every password.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S2053")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(object_creation_expression type: (type_identifier) @t (#eq? @t "PBEKeySpec") arguments: (argument_list (_) [(method_invocation object: (string_literal)) (array_creation_expression)])) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { new PBEKeySpec(pw, \"salt\".getBytes(), 10000, 256); } }",
            good: "class A { void f() { new PBEKeySpec(pw, randomSalt, 10000, 256); } }",
        }),
    },
    Rule {
        id: "java/custom-crypto",
        name: "Custom cryptographic algorithms should not be used",
        description: "Home-made ciphers and digests are almost always weaker than the standard ones.",
        message: "Use a standard algorithm.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 30,
        sonar: &[exact("S2257")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration superclass: (superclass (type_identifier) @s (#any-of? @s "MessageDigest" "CipherSpi" "MessageDigestSpi"))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class MyDigest extends MessageDigest { MyDigest() { super(\"x\"); } }",
            good: "class MyDigest { }",
        }),
    },
    Rule {
        id: "java/ldap-object-deserialization",
        name: "Deserialization of Java objects from LDAP should be disabled",
        description: "Returning objects from a search lets a malicious directory run code in the client.",
        message: "Don't return objects from LDAP searches.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S4434")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "setReturningObjFlag") arguments: (argument_list (true))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { controls.setReturningObjFlag(true); } }",
            good: "class A { void f() { controls.setReturningObjFlag(false); } }",
        }),
    },
    Rule {
        id: "java/activemq-untrusted-classes",
        name: "ActiveMQConnectionFactory should not be vulnerable to malicious code deserialization",
        description: "By default it will instantiate any class named in a message.",
        message: "Call setTrustedPackages.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S5301")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(object_creation_expression type: (type_identifier) @t (#eq? @t "ActiveMQConnectionFactory")) @match"#,
            filter: Some(Keep(file_never_restricts_trusted_packages)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { new ActiveMQConnectionFactory(url); } }",
            good: "class A { void f() { ActiveMQConnectionFactory f = new ActiveMQConnectionFactory(url); f.setTrustedPackages(List.of(\"com.acme\")); } }",
        }),
    },
    Rule {
        id: "java/hardcoded-ip",
        name: "IP addresses should not be hard-coded",
        description: "A literal address breaks when the network changes and can't be overridden per environment.",
        message: "Move this address to configuration.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S1313")],
        check: Check::Query {
            langs: JAVA,
            query: r#"((string_literal) @match (#match? @match "^\"[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+\"$"))"#,
            filter: Some(Keep(is_routable_ipv4)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { String host = \"203.0.113.7\"; } }",
            good: "class A { void f() { String host = System.getenv(\"HOST\");\nString local = \"127.0.0.1\"; } }",
        }),
    },
    Rule {
        id: "java/missing-override",
        name: "@Override should be used on overriding and implementing methods",
        description: "Without it, a typo in the signature silently creates a new method.",
        message: "Add @Override.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S1161")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Keep(object_method_lacks_override)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { public String toString() { return \"\"; } }",
            good: "class A { @Override public String toString() { return \"\"; } }",
        }),
    },
    Rule {
        id: "java/unused-method-parameter",
        name: "Unused method parameters should be removed",
        description: "A parameter nothing reads misleads callers.",
        message: "Remove this unused parameter.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1172")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Keep(private_method_has_unused_parameter)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { private void f(int unused) { g(); } void h() { f(1); } }",
            good: "class A { private void f(int used) { g(used); } void h() { f(1); } }",
        }),
    },
    Rule {
        id: "java/ignored-test-without-reason",
        name: "JUnit4 @Ignore and JUnit5 @Disabled annotations should be used to disable tests with a reason",
        description: "Without a reason, nobody knows when the test can come back.",
        message: "Say why the test is disabled.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S1607")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(marker_annotation name: (identifier) @n (#any-of? @n "Ignore" "Disabled")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class T { @Disabled void a() {} }",
            good: "class T { @Disabled(\"flaky on CI\") void a() {} }",
        }),
    },
    Rule {
        id: "java/for-update-unrelated",
        name: "for loop increment clauses should modify the loops' counters",
        description: "An update clause that touches other variables than the ones the condition tests usually never ends the loop.",
        message: "Update the variable the loop tests.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S1994")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(for_statement) @match"#,
            filter: Some(Keep(update_ignores_tested_variables)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { for (int i = 0; i < 10; j++) {} } }",
            good: "class A { void f() { for (int i = 0; i < 10; i++) {} } }",
        }),
    },
    Rule {
        id: "java/transient-in-plain-class",
        name: "Fields in non-serializable classes should not be transient",
        description: "transient means nothing in a class that is never serialized.",
        message: "Remove transient.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S2065")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Find(transient_field_of_plain_class)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { transient int x; }",
            good: "class A implements Serializable { transient int x; }",
        }),
    },
    Rule {
        id: "java/close-in-finally",
        name: "Try-with-resources should be used",
        description: "A resource closed in finally leaks if close() itself throws, and the code is longer.",
        message: "Use try-with-resources.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S2093")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(try_statement) @match"#,
            filter: Some(Keep(closes_in_finally)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { try { use(in); } finally { in.close(); } } }",
            good: "class A { void f() { try (InputStream in = open()) { use(in); } } }",
        }),
    },
    Rule {
        id: "java/log-and-rethrow",
        name: "Exceptions should be either logged or rethrown but not both",
        description: "The same failure then appears twice in the logs.",
        message: "Log it or rethrow it, not both.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2139")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(catch_clause) @match"#,
            filter: Some(Keep(logs_then_throws)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { try { g(); } catch (IOException e) { log.error(\"x\", e); throw e; } } }",
            good: "class A { void f() { try { g(); } catch (IOException e) { throw new UncheckedIOException(e); } } }",
        }),
    },
    Rule {
        id: "java/synchronized-read-object",
        name: "readObject should not be synchronized",
        description: "Deserialization already has exclusive access to the object.",
        message: "Remove synchronized.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2675")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration name: (identifier) @n (#eq? @n "readObject")) @match"#,
            filter: Some(Keep(is_synchronized)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { private synchronized void readObject(ObjectInputStream in) {} }",
            good: "class A { private void readObject(ObjectInputStream in) {} }",
        }),
    },
    Rule {
        id: "java/multiline-without-braces",
        name: "Multiline blocks should be enclosed in curly braces",
        description: "A second statement indented like the first looks guarded by the condition, but isn't.",
        message: "Add curly braces around the body.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2681")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(if_statement consequence: (expression_statement)) @match
(for_statement body: (expression_statement)) @match
(while_statement body: (expression_statement)) @match"#,
            filter: Some(Keep(next_line_looks_guarded)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A {\n  void f() {\n    if (ok)\n      a();\n      b();\n  }\n}",
            good: "class A {\n  void f() {\n    if (ok) {\n      a();\n      b();\n    }\n  }\n}",
        }),
    },
    Rule {
        id: "java/sleep-in-test",
        name: "Thread.sleep should not be used in tests",
        description: "Sleeping makes tests slow and flaky.",
        message: "Wait on a condition instead.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S2925")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) @o name: (identifier) @n (#eq? @o "Thread") (#eq? @n "sleep")) @match"#,
            filter: Some(Keep(inside_a_test_method)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class T { @Test void a() throws Exception { Thread.sleep(100); } }",
            good: "class T { void a() throws Exception { Thread.sleep(100); } }",
        }),
    },
    Rule {
        id: "java/incomplete-assertion",
        name: "Assertions should be complete",
        description: "assertThat(x) on its own asserts nothing.",
        message: "Add the assertion.",
        category: CodeSmell,
        severity: Blocker,
        effort_minutes: 2,
        sonar: &[exact("S2970")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(expression_statement (method_invocation name: (identifier) @n (#eq? @n "assertThat"))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { assertThat(actual); } }",
            good: "class A { void f() { assertThat(actual).isEqualTo(1); } }",
        }),
    },
    Rule {
        id: "java/array-copy-loop",
        name: "Arrays and lists should not be copied using loops",
        description: "System.arraycopy and Arrays.copyOf are faster and clearer.",
        message: "Use System.arraycopy.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S3012")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(for_statement) @match"#,
            filter: Some(Keep(loop_only_copies_elements)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { for (int i = 0; i < a.length; i++) { b[i] = a[i]; } } }",
            good: "class A { void f() { System.arraycopy(a, 0, b, 0, a.length); } }",
        }),
    },
    Rule {
        id: "java/assertion-argument-order",
        name: "Assertion arguments should be passed in the correct order",
        description: "The expected value goes first, or the failure message is backwards.",
        message: "Swap the arguments.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S3415")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "assertEquals" "assertNotEquals")) @match"#,
            filter: Some(Keep(actual_precedes_literal)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { assertEquals(result, 4); } }",
            good: "class A { void f() { assertEquals(4, result); } }",
        }),
    },
    Rule {
        id: "java/test-class-name",
        name: "Test classes should comply with a naming convention",
        description: "Build tools only run classes whose names match their pattern.",
        message: "Name this class *Test.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S3577")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Keep(test_class_name_is_unconventional)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class Checks { @Test void a() {} }",
            good: "class ChecksTest { @Test void a() {} }",
        }),
    },
    Rule {
        id: "java/assert-on-parameters",
        name: "Asserts should not be used to check the parameters of a public method",
        description: "Assertions are disabled by default, so the check silently disappears.",
        message: "Throw IllegalArgumentException.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S4274")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(assert_statement) @match"#,
            filter: Some(Keep(asserts_a_public_parameter)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { public void f(int x) { assert x > 0; } }",
            good: "class A { public void f(int x) { if (x <= 0) throw new IllegalArgumentException(); } }",
        }),
    },
    Rule {
        id: "java/composed-request-mapping",
        name: "Composed @RequestMapping variants should be preferred",
        description: "@GetMapping says it in one word.",
        message: "Use @GetMapping, @PostMapping or similar.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S4488")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(annotation name: (identifier) @n (#eq? @n "RequestMapping")) @match"#,
            filter: Some(Keep(request_mapping_sets_one_method)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class C { @RequestMapping(value = \"/x\", method = RequestMethod.GET) String f() { return \"\"; } }",
            good: "class C { @GetMapping(\"/x\") String f() { return \"\"; } }",
        }),
    },
    Rule {
        id: "java/jdbc-driver-for-name",
        name: "Class.forName() should not load JDBC 4.0+ drivers",
        description: "Drivers register themselves, so the call is dead weight.",
        message: "Remove this call.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S4925")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) @o name: (identifier) @n arguments: (argument_list . (string_literal) @c) (#eq? @o "Class") (#eq? @n "forName")) @match"#,
            filter: Some(Keep(names_a_jdbc_driver)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Class.forName(\"com.mysql.cj.jdbc.Driver\"); } }",
            good: "class A { void f() { Class.forName(\"com.acme.Plugin\"); } }",
        }),
    },
    Rule {
        id: "java/expected-in-test-annotation",
        name: "Exception testing via the @Test annotation should be avoided",
        description: "@Test(expected = X.class) passes if any line of the test throws X.",
        message: "Use assertThrows.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5777")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(annotation name: (identifier) @n (#eq? @n "Test")) @match"#,
            filter: Some(Keep(test_expects_an_exception)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class T { @Test(expected = IOException.class) void a() {} }",
            good: "class T { @Test void a() {} }",
        }),
    },
    Rule {
        id: "java/expected-exception-rule",
        name: "Exception testing via the JUnit ExpectedException rule should not be mixed",
        description: "The rule is deprecated in favour of assertThrows.",
        message: "Use assertThrows.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5776")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(field_declaration type: (type_identifier) @t (#eq? @t "ExpectedException")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class T { @Rule ExpectedException thrown = ExpectedException.none(); }",
            good: "class T { }",
        }),
    },
    Rule {
        id: "java/jupiter-public-test",
        name: "JUnit5 test classes and methods should have default package visibility",
        description: "public adds nothing in JUnit 5.",
        message: "Remove public.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S5786")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Keep(jupiter_test_is_public)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "import org.junit.jupiter.api.Test;\nclass T { @Test public void a() {} }",
            good: "import org.junit.jupiter.api.Test;\nclass T { @Test void a() {} }",
        }),
    },
    Rule {
        id: "java/too-many-assertions",
        name: "Test methods should not contain too many assertions",
        description: "A test with dozens of assertions fails at the first and hides the rest.",
        message: "Split this test.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 20,
        sonar: &[exact("S5961")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Keep(test_has_too_many_assertions)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class T { @Test void a() { assertEquals(0, x); assertEquals(1, x); assertEquals(2, x); assertEquals(3, x); assertEquals(4, x); assertEquals(5, x); assertEquals(6, x); assertEquals(7, x); assertEquals(8, x); assertEquals(9, x); assertEquals(10, x); assertEquals(11, x); assertEquals(12, x); assertEquals(13, x); assertEquals(14, x); assertEquals(15, x); assertEquals(16, x); assertEquals(17, x); assertEquals(18, x); assertEquals(19, x); assertEquals(20, x); assertEquals(21, x); assertEquals(22, x); assertEquals(23, x); assertEquals(24, x); assertEquals(25, x); } }",
            good: "class T { @Test void a() { assertEquals(1, x); } }",
        }),
    },
    Rule {
        id: "java/region-not-set",
        name: "Region should be set explicitly when creating a new AWS client",
        description: "The default region comes from the environment and differs between machines.",
        message: "Set the region.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6241")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "build")) @match"#,
            filter: Some(Keep(aws_client_without_region)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { S3Client c = S3Client.builder().build(); } }",
            good: "class A { void f() { S3Client c = S3Client.builder().region(r).build(); } }",
        }),
    },
    Rule {
        id: "java/credentials-provider-not-set",
        name: "Credentials Provider should be set explicitly when creating a new AWS client",
        description: "The default provider chain tries many sources and picks different ones in different places.",
        message: "Set the credentials provider.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6242")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "build")) @match"#,
            filter: Some(Keep(aws_client_without_credentials)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { S3Client c = S3Client.builder().region(r).build(); } }",
            good: "class A { void f() { S3Client c = S3Client.builder().region(r).credentialsProvider(p).build(); } }",
        }),
    },
    Rule {
        id: "java/aws-region-hardcoded",
        name: "AWS region should not be set with a hardcoded String",
        description: "A literal region makes the code awkward to deploy elsewhere.",
        message: "Read the region from configuration.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6262")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) @o name: (identifier) @n (#eq? @o "Region") (#eq? @n "of")) @match"#,
            filter: Some(Keep(first_argument_is_a_literal)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Region r = Region.of(\"eu-west-1\"); } }",
            good: "class A { void f() { Region r = Region.of(config.region()); } }",
        }),
    },
    Rule {
        id: "java/value-annotation-literal",
        name: "@Value annotation should inject property or SpEL expression",
        description: "@Value(\"text\") injects the literal text, which is rarely intended.",
        message: "Use a ${property} or #{expression}.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6804")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(annotation name: (identifier) @n (#eq? @n "Value")) @match"#,
            filter: Some(Keep(value_has_no_placeholder)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { @Value(\"plain\") String s; }",
            good: "class A { @Value(\"${app.name}\") String s; }",
        }),
    },
    Rule {
        id: "java/optional-primitive-request-param",
        name: "Optional REST parameters should have an object type",
        description: "A primitive cannot hold the null that a missing parameter produces.",
        message: "Use a wrapper type.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6814")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(formal_parameter) @match"#,
            filter: Some(Keep(optional_param_is_primitive)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class C { String f(@RequestParam(required = false) int page) { return \"\"; } }",
            good: "class C { String f(@RequestParam(required = false) Integer page) { return \"\"; } }",
        }),
    },
    Rule {
        id: "java/controller-should-be-rest",
        name: "@Controller should be replaced with @RestController",
        description: "When every method has @ResponseBody, @RestController says it once.",
        message: "Use @RestController.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6833")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(marker_annotation name: (identifier) @n (#eq? @n "Controller")) @match"#,
            filter: Some(Keep(every_method_is_a_response_body)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "@Controller class C { @ResponseBody String f() { return \"\"; } }",
            good: "@RestController class C { String f() { return \"\"; } }",
        }),
    },
    Rule {
        id: "java/cacheable-and-cacheput",
        name: "@Cacheable and @CachePut should not be combined",
        description: "One reads from the cache, the other always writes; together they contradict.",
        message: "Use only one of them.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7179")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Keep(combines_cacheable_and_cacheput)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class C { @Cacheable(\"a\") @CachePut(\"a\") String f() { return \"\"; } }",
            good: "class C { @Cacheable(\"a\") String f() { return \"\"; } }",
        }),
    },
    Rule {
        id: "java/pageable-parameter",
        name: "Methods returning Page or Slice must take Pageable as an input parameter",
        description: "Spring Data needs the Pageable to know which page to fetch.",
        message: "Add a Pageable parameter.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S7186")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Keep(page_method_lacks_pageable)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "interface R { Page<A> find(String name); }",
            good: "interface R { Page<A> find(String name, Pageable p); }",
        }),
    },
    Rule {
        id: "java/transaction-callback-signature",
        name: "@BeforeTransaction and @AfterTransaction methods must be void and take no arguments",
        description: "Spring invokes them without arguments and ignores their result.",
        message: "Make this method void with no parameters.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S7190")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Keep(transaction_callback_signature_is_wrong)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class T { @BeforeTransaction int f() { return 1; } }",
            good: "class T { @BeforeTransaction void f() {} }",
        }),
    },
    Rule {
        id: "java/junit4-assert-in-jupiter",
        name: "JUnit Jupiter tests should not use JUnit 4 assertions",
        description: "Jupiter and JUnit 4 put the message in different positions.",
        message: "Use org.junit.jupiter.api.Assertions.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S8715")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(import_declaration) @match"#,
            filter: Some(Keep(junit4_assert_in_jupiter_file)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "import org.junit.jupiter.api.Test;\nimport org.junit.Assert;\nclass T { }",
            good: "import org.junit.jupiter.api.Test;\nimport org.junit.jupiter.api.Assertions;\nclass T { }",
        }),
    },
    Rule {
        id: "java/duplicate-lifecycle-method",
        name: "Test classes should not contain multiple lifecycle methods of the same type",
        description: "JUnit does not define the order of two @BeforeEach methods.",
        message: "Merge these methods.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S8745")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Find(second_lifecycle_method_of_a_kind)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class T { @BeforeEach void a() {} @BeforeEach void b() {} }",
            good: "class T { @BeforeEach void a() {} @AfterEach void b() {} }",
        }),
    },
    Rule {
        id: "java/commented-out-code",
        name: "Sections of code should not be commented out",
        description: "Commented-out code rots, and version control already remembers it.",
        message: "Remove this commented-out code.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S125")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(line_comment) @match"#,
            filter: Some(Keep(looks_like_code)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A {\n// int x = compute(1);\n}",
            good: "class A {\n// Compute the total price.\n}",
        }),
    },
    Rule {
        id: "java/package-name",
        name: "Package names should comply with a naming convention",
        description: "Packages are lower case.",
        message: "Rename this package.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S120")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(package_declaration) @match"#,
            filter: Some(Keep(package_has_uppercase)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "package com.Acme;\nclass A { }",
            good: "package com.acme;\nclass A { }",
        }),
    },
    Rule {
        id: "java/switch-case-falls-through",
        name: "Switch cases should end with an unconditional break statement",
        description: "A case that runs into the next one is usually a forgotten break.",
        message: "Add a break, or a comment saying it is intended.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S128")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(switch_expression) @match"#,
            filter: Some(Find(case_falls_through)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(int x) { switch (x) { case 1: a(); case 2: b(); break; default: c(); } } }",
            good: "class A { void f(int x) { switch (x) { case 1: a(); break; case 2: b(); break; default: c(); } } }",
        }),
    },
    Rule {
        id: "java/local-shadows-field",
        name: "Local variables should not shadow class fields",
        description: "The field is then unreachable by its plain name.",
        message: "Rename the local variable.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1117")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(local_variable_declaration) @match"#,
            filter: Some(Keep(local_shadows_a_field)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { int count; void f() { int count = 1; } }",
            good: "class A { int count; void f() { int total = 1; } }",
        }),
    },
    Rule {
        id: "java/empty-statement",
        name: "Empty statements should be removed",
        description: "A stray semicolon is either noise or a bug.",
        message: "Remove this empty statement.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S1116")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(block (";") @match)"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { g();; } }",
            good: "class A { void f() { g(); } }",
        }),
    },
];

// ---------------------------------------------------- filters

fn all_annotations<'a>(declaration: Node, src: &'a [u8]) -> Vec<&'a [u8]> {
    let Some(mods) = modifiers_of(declaration) else {
        return Vec::new();
    };
    let mut cursor = mods.walk();
    mods.children(&mut cursor)
        .filter(|a| matches!(a.kind(), "marker_annotation" | "annotation"))
        .filter_map(|a| a.child_by_field_name("name").map(|n| text(n, src)))
        .collect()
}

fn implements(class: Node, src: &[u8], interface: &[u8]) -> bool {
    let mut cursor = class.walk();
    class
        .children(&mut cursor)
        .any(|i| i.kind() == "super_interfaces" && count_word(text(i, src), interface) > 0)
}

fn is_jupiter(src: &[u8]) -> bool {
    src.windows(17).any(|w| w == b"org.junit.jupiter")
}

fn is_test_method(method: Node, src: &[u8]) -> bool {
    all_annotations(method, src).iter().any(|a| {
        matches!(
            *a,
            b"Test" | b"ParameterizedTest" | b"RepeatedTest" | b"TestFactory"
        )
    })
}

fn jump_in_finally<'t>(finally: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    let mut found: Vec<Node> = Vec::new();
    let mut stack: Vec<(Node, bool)> = Vec::new();
    let mut cursor = finally.walk();
    for child in finally.named_children(&mut cursor) {
        stack.push((child, false));
    }
    while let Some((node, in_loop)) = stack.pop() {
        match node.kind() {
            "lambda_expression" | "class_body" => continue,
            "return_statement" => found.push(node),
            "break_statement" | "continue_statement" if !in_loop => found.push(node),
            _ => {}
        }
        let nested = in_loop || LOOPS.contains(&node.kind()) || node.kind() == "switch_expression";
        let mut c = node.walk();
        for child in node.named_children(&mut c) {
            stack.push((child, nested));
        }
    }
    found.into_iter().min_by_key(|n| n.start_byte())
}

fn externalizable_lacks_default_constructor(class: Node, src: &[u8]) -> bool {
    if !implements(class, src, b"Externalizable") {
        return false;
    }
    let Some(body) = class.child_by_field_name("body") else {
        return false;
    };
    let constructors: Vec<Node> = members(body)
        .into_iter()
        .filter(|m| m.kind() == "constructor_declaration")
        .collect();
    !constructors.is_empty()
        && !constructors
            .iter()
            .any(|c| has_modifier(*c, "public") && parameter_types(*c, src).is_empty())
}

fn inner_serializable_of_plain_outer(class: Node, src: &[u8]) -> bool {
    if !implements(class, src, b"Serializable") || has_modifier(class, "static") {
        return false;
    }
    let Some(outer) = class
        .parent()
        .filter(|b| b.kind() == "class_body")
        .and_then(|b| b.parent())
        .filter(|o| o.kind() == "class_declaration")
    else {
        return false;
    };
    !implements(outer, src, b"Serializable")
}

fn equals_casts_without_checking(method: Node, src: &[u8]) -> bool {
    if !matches!(parameter_types(method, src).as_slice(), [t] if *t == b"Object") {
        return false;
    }
    let Some(body) = method.child_by_field_name("body") else {
        return false;
    };
    let t = text(body, src);
    let checks = [
        &b"instanceof"[..],
        b"getClass",
        b"isInstance",
        b"getName",
        b"Objects.equals",
    ]
    .iter()
    .any(|w| t.windows(w.len()).any(|x| x == *w));
    !checks && find_node(body, |n| n.kind() == "cast_expression").is_some()
}

fn mutable_instance_field<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let body = class.child_by_field_name("body")?;
    members(body).into_iter().find(|m| {
        m.kind() == "field_declaration"
            && !has_modifier(*m, "static")
            && !has_modifier(*m, "final")
            && all_annotations(*m, src).is_empty()
    })
}

fn proxied_method_is_not_public(method: Node, src: &[u8]) -> bool {
    method.parent().is_some_and(|b| b.kind() == "class_body")
        && !has_modifier(method, "public")
        && all_annotations(method, src).iter().any(|a| {
            matches!(
                *a,
                b"Transactional"
                    | b"Async"
                    | b"Cacheable"
                    | b"CachePut"
                    | b"CacheEvict"
                    | b"PreAuthorize"
                    | b"PostAuthorize"
                    | b"Secured"
            )
        })
}

fn receiver_looks_like_a_thread(call: Node, src: &[u8]) -> bool {
    call.child_by_field_name("object")
        .is_some_and(|o| contains_ignoring_case(text(o, src), b"thread"))
}

fn condition_is_false_on_entry(for_loop: Node, src: &[u8]) -> bool {
    let (Some(init), Some(condition)) = (
        for_loop.child_by_field_name("init"),
        for_loop.child_by_field_name("condition"),
    ) else {
        return false;
    };
    let Some(declarator) = find_node(init, |n| n.kind() == "variable_declarator") else {
        return false;
    };
    let (Some(name), Some(start)) = (
        declarator.child_by_field_name("name"),
        declarator.child_by_field_name("value"),
    ) else {
        return false;
    };
    if condition.kind() != "binary_expression" {
        return false;
    }
    let (Some(l), Some(r)) = (
        condition.child_by_field_name("left"),
        condition.child_by_field_name("right"),
    ) else {
        return false;
    };
    let number = |n: Node| -> Option<i64> {
        (n.kind() == "decimal_integer_literal")
            .then(|| String::from_utf8_lossy(text(n, src)).parse().ok())
            .flatten()
    };
    let (Some(a), Some(b)) = (number(start), number(r)) else {
        return false;
    };
    if text(l, src) != text(name, src) {
        return false;
    }
    match operator_text(condition, src) {
        b"<" => a >= b,
        b"<=" => a > b,
        b">" => a <= b,
        b">=" => a < b,
        _ => false,
    }
}

fn is_not_in_synchronized_code(call: Node, _: &[u8]) -> bool {
    let mut p = call.parent();
    let mut hops = 0;
    while let Some(n) = p {
        match n.kind() {
            "synchronized_statement" => return false,
            "method_declaration" | "constructor_declaration" => {
                return !has_modifier(n, "synchronized");
            }
            "lambda_expression" => return false,
            _ => {}
        }
        hops += 1;
        if hops > 128 {
            return false;
        }
        p = n.parent();
    }
    false
}

fn sign_glued_to_equals(assignment: Node, src: &[u8]) -> bool {
    let (Some(left), Some(right)) = (
        assignment.child_by_field_name("left"),
        assignment.child_by_field_name("right"),
    ) else {
        return false;
    };
    if operator_text(assignment, src) != b"=" {
        return false;
    }
    let between = &src[left.end_byte()..right.start_byte()];
    between.len() >= 2
        && between.ends_with(b"=")
        && between[between.len() - 2].is_ascii_whitespace()
}

fn to_array_has_no_arguments(cast: Node, _: &[u8]) -> bool {
    cast.child_by_field_name("value")
        .is_some_and(|c| call_arguments(c).is_empty())
}

fn all_branches_identical(statement: Node, src: &[u8]) -> bool {
    let mut bodies: Vec<&[u8]> = Vec::new();
    let mut current = Some(statement);
    let mut has_else = false;
    while let Some(branch) = current {
        let Some(body) = branch.child_by_field_name("consequence") else {
            return false;
        };
        bodies.push(text(body, src));
        match branch.child_by_field_name("alternative") {
            Some(a) if a.kind() == "if_statement" => current = Some(a),
            Some(a) => {
                bodies.push(text(a, src));
                has_else = true;
                current = None;
            }
            None => current = None,
        }
    }
    // Only the head of a chain reports.
    let is_head = !statement.parent().is_some_and(|p| {
        p.kind() == "if_statement" && p.child_by_field_name("alternative") == Some(statement)
    });
    is_head && has_else && bodies.len() >= 2 && bodies.windows(2).all(|w| w[0] == w[1])
}

fn in_the_default_package(annotation: Node, _: &[u8]) -> bool {
    let mut root = annotation;
    let mut hops = 0;
    while let Some(p) = root.parent() {
        root = p;
        hops += 1;
        if hops > 64 {
            return false;
        }
    }
    let mut cursor = root.walk();
    !root
        .named_children(&mut cursor)
        .any(|c| c.kind() == "package_declaration")
}

fn thread_local_is_never_removed(field: Node, src: &[u8]) -> bool {
    field
        .child_by_field_name("type")
        .is_some_and(|t| text(t, src).starts_with(b"ThreadLocal"))
        && !src.windows(8).any(|w| w == b".remove(")
}

fn inner_test_class_lacks_nested(class: Node, src: &[u8]) -> bool {
    if !is_jupiter(src)
        || has_modifier(class, "static")
        || all_annotations(class, src).contains(&&b"Nested"[..])
    {
        return false;
    }
    let nested_in_class = class
        .parent()
        .and_then(|b| b.parent())
        .is_some_and(|o| o.kind() == "class_declaration");
    let Some(body) = class.child_by_field_name("body") else {
        return false;
    };
    nested_in_class
        && members(body)
            .iter()
            .any(|m| m.kind() == "method_declaration" && is_test_method(*m, src))
}

fn jupiter_test_is_private_or_static(method: Node, src: &[u8]) -> bool {
    is_jupiter(src)
        && is_test_method(method, src)
        && (has_modifier(method, "private") || has_modifier(method, "static"))
}

fn has_several_test_annotations(method: Node, src: &[u8]) -> bool {
    all_annotations(method, src)
        .iter()
        .filter(|a| {
            matches!(
                **a,
                b"Test" | b"ParameterizedTest" | b"RepeatedTest" | b"TestFactory" | b"TestTemplate"
            )
        })
        .count()
        > 1
}

fn async_method_in_configuration(method: Node, src: &[u8]) -> bool {
    has_annotation(method, b"Async", src)
        && enclosing_class(method).is_some_and(|c| has_annotation(c, b"Configuration", src))
}

fn path_variable_has_no_parameter(method: Node, src: &[u8]) -> bool {
    let mapped = all_annotations(method, src).iter().any(|a| {
        matches!(
            *a,
            b"GetMapping"
                | b"PostMapping"
                | b"PutMapping"
                | b"DeleteMapping"
                | b"PatchMapping"
                | b"RequestMapping"
        )
    });
    if !mapped {
        return false;
    }
    let Some(mods) = modifiers_of(method) else {
        return false;
    };
    let path = text(mods, src);
    let has_variable =
        path.windows(2).any(|w| w[0] == b'{' && w[1] != b'}') && path.contains(&b'/');
    if !has_variable {
        return false;
    }
    let Some(params) = method.child_by_field_name("parameters") else {
        return false;
    };
    // A shared @ModelAttribute method may bind the variable for every handler.
    if enclosing_class(method).is_some_and(|c| count_word(text(c, src), b"ModelAttribute") > 0) {
        return false;
    }
    let t = text(params, src);
    !t.windows(12).any(|w| w == b"PathVariable") && !t.windows(3).any(|w| w == b"Map")
}

fn second_bean_with_same_name<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !has_annotation(class, b"Configuration", src) {
        return None;
    }
    let body = class.child_by_field_name("body")?;
    let mut seen: Vec<&[u8]> = Vec::new();
    for m in members(body) {
        if m.kind() != "method_declaration" || !has_annotation(m, b"Bean", src) {
            continue;
        }
        let name = m
            .child_by_field_name("name")
            .map_or(&b""[..], |n| text(n, src));
        if seen.contains(&name) {
            return Some(m);
        }
        seen.push(name);
    }
    None
}

fn file_never_restricts_trusted_packages(creation: Node, src: &[u8]) -> bool {
    let _ = creation;
    !src.windows(18).any(|w| w == b"setTrustedPackages")
        && !src.windows(21).any(|w| w == b"setTrustAllPackages(f")
}

fn is_routable_ipv4(string: Node, src: &[u8]) -> bool {
    let Some(body) = string_value(string, src) else {
        return false;
    };
    let octets: Vec<u16> = String::from_utf8_lossy(body)
        .split('.')
        .filter_map(|o| o.parse().ok())
        .collect();
    octets.len() == 4
        && octets.iter().all(|&o| o <= 255)
        && octets[0] != 127
        && octets != [0, 0, 0, 0]
        && octets != [255, 255, 255, 255]
}

fn object_method_lacks_override(method: Node, src: &[u8]) -> bool {
    if has_annotation(method, b"Override", src)
        || has_modifier(method, "static")
        || !method.parent().is_some_and(|b| {
            b.kind() == "class_body" && b.parent().is_some_and(|c| c.kind() == "class_declaration")
        })
    {
        return false;
    }
    let name = method
        .child_by_field_name("name")
        .map_or(&b""[..], |n| text(n, src));
    let params = parameter_types(method, src);
    match name {
        b"toString" | b"hashCode" => params.is_empty() && has_modifier(method, "public"),
        b"equals" => matches!(params.as_slice(), [t] if *t == b"Object"),
        _ => false,
    }
}

fn private_method_has_unused_parameter(method: Node, src: &[u8]) -> bool {
    if method
        .child_by_field_name("name")
        .is_some_and(|n| text(n, src) == b"main")
    {
        return false;
    }
    if !(has_modifier(method, "private") || has_modifier(method, "static"))
        || has_annotation(method, b"Override", src)
    {
        return false;
    }
    let (Some(params), Some(body)) = (
        method.child_by_field_name("parameters"),
        method.child_by_field_name("body"),
    ) else {
        return false;
    };
    let mut cursor = params.walk();
    params.named_children(&mut cursor).any(|p| {
        p.child_by_field_name("name")
            .is_some_and(|n| count_word(text(body, src), text(n, src)) == 0)
    })
}

fn update_ignores_tested_variables(for_loop: Node, src: &[u8]) -> bool {
    let (Some(condition), Some(update)) = (
        for_loop.child_by_field_name("condition"),
        for_loop.child_by_field_name("update"),
    ) else {
        return false;
    };
    let written: Vec<&[u8]> = {
        let mut names = Vec::new();
        let mut nodes = vec![update];
        let mut cursor = update.walk();
        nodes.extend(update.named_children(&mut cursor));
        for n in nodes {
            let target = match n.kind() {
                "update_expression" => n.named_child(0),
                "assignment_expression" => n.child_by_field_name("left"),
                _ => None,
            };
            if let Some(t) = target.filter(|t| t.kind() == "identifier") {
                names.push(text(t, src));
            }
        }
        names
    };
    if written.is_empty() {
        return false;
    }
    let tested: Vec<&[u8]> = {
        let mut v: Vec<&[u8]> = Vec::new();
        let mut cursor = condition.walk();
        let mut stack = vec![condition];
        while let Some(n) = stack.pop() {
            if n.kind() == "identifier" {
                v.push(text(n, src));
            }
            stack.extend(n.named_children(&mut cursor));
        }
        v
    };
    !written.iter().any(|w| tested.contains(w))
}

fn transient_field_of_plain_class<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if class.child_by_field_name("superclass").is_some()
        || implements(class, src, b"Serializable")
        || implements(class, src, b"Externalizable")
        || class.child_by_field_name("interfaces").is_some()
    {
        return None;
    }
    let body = class.child_by_field_name("body")?;
    members(body)
        .into_iter()
        .find(|m| m.kind() == "field_declaration" && has_modifier(*m, "transient"))
}

fn closes_in_finally(try_: Node, src: &[u8]) -> bool {
    children_of_kind(try_, "finally_clause").iter().any(|f| {
        find_node(*f, |n| {
            n.kind() == "method_invocation"
                && method_name(n, src) == b"close"
                && call_arguments(n).is_empty()
        })
        .is_some()
    }) && try_.child_by_field_name("resources").is_none()
}

fn logs_then_throws(catch: Node, src: &[u8]) -> bool {
    let Some(body) = catch.child_by_field_name("body") else {
        return false;
    };
    let logs = find_node(body, |n| {
        n.kind() == "method_invocation"
            && matches!(
                method_name(n, src),
                b"error" | b"warn" | b"info" | b"debug" | b"log" | b"severe" | b"warning"
            )
            && n.child_by_field_name("object")
                .is_some_and(|o| contains_ignoring_case(text(o, src), b"log"))
    })
    .is_some();
    logs && find_in_scope(body, &["lambda_expression", "class_body"], |n| {
        n.kind() == "throw_statement"
    })
    .is_some()
}

fn is_synchronized(method: Node, _: &[u8]) -> bool {
    has_modifier(method, "synchronized")
}

fn next_line_looks_guarded(parent: Node, _: &[u8]) -> bool {
    let Some(body) = parent
        .child_by_field_name("consequence")
        .or_else(|| parent.child_by_field_name("body"))
    else {
        return false;
    };
    if parent.kind() == "if_statement" && parent.child_by_field_name("alternative").is_some() {
        return false;
    }
    let Some(next) = parent.next_named_sibling() else {
        return false;
    };
    body.start_position().row > parent.start_position().row
        && next.start_position().row > body.end_position().row
        && next.start_position().column == body.start_position().column
        && body.start_position().column > parent.start_position().column
}

fn inside_a_test_method(call: Node, src: &[u8]) -> bool {
    let mut p = call.parent();
    let mut hops = 0;
    while let Some(n) = p {
        if n.kind() == "method_declaration" {
            return is_test_method(n, src);
        }
        hops += 1;
        if hops > 128 {
            return false;
        }
        p = n.parent();
    }
    false
}

fn loop_only_copies_elements(for_loop: Node, src: &[u8]) -> bool {
    let Some(body) = for_loop.child_by_field_name("body") else {
        return false;
    };
    let items = if body.kind() == "block" {
        statements(body)
    } else {
        vec![body]
    };
    let [only] = items.as_slice() else {
        return false;
    };
    let Some(assignment) = only
        .named_child(0)
        .filter(|a| only.kind() == "expression_statement" && a.kind() == "assignment_expression")
    else {
        return false;
    };
    let (Some(l), Some(r)) = (
        assignment.child_by_field_name("left"),
        assignment.child_by_field_name("right"),
    ) else {
        return false;
    };
    operator_text(assignment, src) == b"="
        && l.kind() == "array_access"
        && r.kind() == "array_access"
        && l.child_by_field_name("index")
            .zip(r.child_by_field_name("index"))
            .is_some_and(|(a, b)| a.kind() == "identifier" && text(a, src) == text(b, src))
}

fn actual_precedes_literal(call: Node, src: &[u8]) -> bool {
    let mut args = call_arguments(call);
    // JUnit 4 puts the optional message first, JUnit 5 last.
    if args.len() == 3 {
        if is_jupiter(src) {
            args.pop();
        } else if args[0].kind() == "string_literal" {
            args.remove(0);
        }
    }
    let [first, second, ..] = args.as_slice() else {
        return false;
    };
    let literal = |n: &Node| {
        matches!(
            n.kind(),
            "decimal_integer_literal"
                | "string_literal"
                | "character_literal"
                | "true"
                | "false"
                | "null_literal"
        )
    };
    !literal(first)
        && literal(second)
        && first.kind() != "field_access"
        && text(*first, src) != b"null"
}

fn test_class_name_is_unconventional(class: Node, src: &[u8]) -> bool {
    let Some(name) = class.child_by_field_name("name").map(|n| text(n, src)) else {
        return false;
    };
    let Some(body) = class.child_by_field_name("body") else {
        return false;
    };
    // Nested classes are named for what they group, not for the build tool.
    if class.parent().is_some_and(|p| p.kind() == "class_body") {
        return false;
    }
    let has_test = members(body)
        .iter()
        .any(|m| m.kind() == "method_declaration" && is_test_method(*m, src));
    let conventional = name.starts_with(b"Test")
        || name.starts_with(b"IT")
        || [&b"Test"[..], b"Tests", b"TestCase", b"IT", b"ITCase"]
            .iter()
            .any(|s| name.ends_with(s));
    has_test && !conventional
}

fn asserts_a_public_parameter(assertion: Node, src: &[u8]) -> bool {
    let mut p = assertion.parent();
    let mut hops = 0;
    while let Some(n) = p {
        if n.kind() == "method_declaration" {
            if !has_modifier(n, "public") {
                return false;
            }
            let Some(params) = n.child_by_field_name("parameters") else {
                return false;
            };
            let mut cursor = params.walk();
            let names: Vec<&[u8]> = params
                .named_children(&mut cursor)
                .filter_map(|x| x.child_by_field_name("name").map(|n| text(n, src)))
                .collect();
            return names
                .iter()
                .any(|name| count_word(text(assertion, src), name) > 0);
        }
        hops += 1;
        if hops > 64 {
            return false;
        }
        p = n.parent();
    }
    false
}

fn request_mapping_sets_one_method(annotation: Node, src: &[u8]) -> bool {
    let t = text(annotation, src);
    let methods = t.windows(14).filter(|w| *w == b"RequestMethod.").count();
    methods == 1
        && !t.windows(8).any(|w| w == b"consumes")
        && !t.windows(8).any(|w| w == b"produces")
}

fn names_a_jdbc_driver(call: Node, src: &[u8]) -> bool {
    call_arguments(call)
        .first()
        .and_then(|a| string_value(*a, src))
        .is_some_and(|v| {
            let lower = v.to_ascii_lowercase();
            lower.ends_with(b"driver")
                && [
                    &b"jdbc"[..],
                    b"mysql",
                    b"postgres",
                    b"oracle",
                    b"sqlserver",
                    b"h2",
                    b"mariadb",
                    b"sqlite",
                ]
                .iter()
                .any(|w| lower.windows(w.len()).any(|x| x == *w))
        })
}

fn test_expects_an_exception(annotation: Node, src: &[u8]) -> bool {
    count_word(text(annotation, src), b"expected") > 0
}

fn jupiter_test_is_public(method: Node, src: &[u8]) -> bool {
    is_jupiter(src) && is_test_method(method, src) && has_modifier(method, "public")
}

fn test_has_too_many_assertions(method: Node, src: &[u8]) -> bool {
    if !is_test_method(method, src) {
        return false;
    }
    let Some(body) = method.child_by_field_name("body") else {
        return false;
    };
    let mut count = 0;
    let mut cursor = body.walk();
    let mut stack = vec![body];
    while let Some(n) = stack.pop() {
        if n.kind() == "method_invocation" && method_name(n, src).starts_with(b"assert") {
            count += 1;
        }
        stack.extend(n.named_children(&mut cursor));
    }
    count > 25
}

fn client_builder_chain<'a>(call: Node, src: &'a [u8]) -> Option<&'a [u8]> {
    let chain = text(call, src);
    (chain.windows(8).any(|w| w == b".builder") && chain.windows(6).any(|w| w == b"Client"))
        .then_some(chain)
}

fn aws_client_without_region(call: Node, src: &[u8]) -> bool {
    client_builder_chain(call, src).is_some_and(|c| !c.windows(7).any(|w| w == b"region("))
}

fn aws_client_without_credentials(call: Node, src: &[u8]) -> bool {
    client_builder_chain(call, src)
        .is_some_and(|c| !c.windows(20).any(|w| w == b"credentialsProvider("))
}

fn first_argument_is_a_literal(call: Node, _: &[u8]) -> bool {
    call_arguments(call)
        .first()
        .is_some_and(|a| a.kind() == "string_literal")
}

fn value_has_no_placeholder(annotation: Node, src: &[u8]) -> bool {
    let t = text(annotation, src);
    t.contains(&b'"') && !t.windows(2).any(|w| w == b"${" || w == b"#{")
}

fn optional_param_is_primitive(param: Node, src: &[u8]) -> bool {
    let Some(mods) = modifiers_of(param) else {
        return false;
    };
    let t = text(mods, src);
    let optional = count_word(t, b"RequestParam") > 0
        && t.windows(14)
            .any(|w| w == b"required=false" || w == b"required = fal")
        && !t.windows(12).any(|w| w == b"defaultValue");
    optional
        && param.child_by_field_name("type").is_some_and(|ty| {
            matches!(
                ty.kind(),
                "integral_type" | "floating_point_type" | "boolean_type"
            )
        })
}

fn every_method_is_a_response_body(annotation: Node, src: &[u8]) -> bool {
    let Some(class) = owning_declaration(annotation).filter(|d| d.kind() == "class_declaration")
    else {
        return false;
    };
    let Some(body) = class.child_by_field_name("body") else {
        return false;
    };
    let methods: Vec<Node> = members(body)
        .into_iter()
        .filter(|m| m.kind() == "method_declaration")
        .collect();
    !methods.is_empty()
        && methods
            .iter()
            .all(|m| has_annotation(*m, b"ResponseBody", src))
}

fn combines_cacheable_and_cacheput(method: Node, src: &[u8]) -> bool {
    has_annotation(method, b"Cacheable", src) && has_annotation(method, b"CachePut", src)
}

fn page_method_lacks_pageable(method: Node, src: &[u8]) -> bool {
    let Some(ty) = method.child_by_field_name("type") else {
        return false;
    };
    let head = text(ty, src)
        .split(|&b| b == b'<')
        .next()
        .unwrap_or(&b""[..]);
    matches!(head, b"Page" | b"Slice")
        && !parameter_types(method, src)
            .iter()
            .any(|t| matches!(*t, b"Pageable" | b"Sort"))
}

fn transaction_callback_signature_is_wrong(method: Node, src: &[u8]) -> bool {
    (has_annotation(method, b"BeforeTransaction", src)
        || has_annotation(method, b"AfterTransaction", src))
        && (!parameter_types(method, src).is_empty()
            || method
                .child_by_field_name("type")
                .is_some_and(|t| text(t, src) != b"void"))
}

fn junit4_assert_in_jupiter_file(import: Node, src: &[u8]) -> bool {
    is_jupiter(src) && {
        let t = text(import, src);
        t.windows(16).any(|w| w == b"org.junit.Assert")
    }
}

fn second_lifecycle_method_of_a_kind<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let body = class.child_by_field_name("body")?;
    let mut seen: Vec<&[u8]> = Vec::new();
    for m in members(body) {
        if m.kind() != "method_declaration" {
            continue;
        }
        for a in all_annotations(m, src) {
            if matches!(a, b"BeforeEach" | b"AfterEach" | b"BeforeAll" | b"AfterAll") {
                if seen.contains(&a) {
                    return Some(m);
                }
                seen.push(a);
            }
        }
    }
    None
}

fn looks_like_code(comment: Node, src: &[u8]) -> bool {
    let t = text(comment, src);
    let body = t.strip_prefix(b"//").unwrap_or(t).trim_ascii();
    let starts_like_code = body
        .first()
        .is_some_and(|b| b.is_ascii_lowercase() || *b == b'@' || *b == b'}')
        && !body.starts_with(b"http");
    let ends_like_code = body.ends_with(b";") || body.ends_with(b"{");
    starts_like_code && ends_like_code && (body.contains(&b'(') || body.contains(&b'='))
}

fn package_has_uppercase(package: Node, src: &[u8]) -> bool {
    let t = text(package, src);
    let name = t.strip_prefix(b"package").unwrap_or(t).trim_ascii();
    let name = name.strip_suffix(b";").unwrap_or(name);
    name.iter().any(u8::is_ascii_uppercase)
}

fn case_falls_through<'t>(switch: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let block = switch.child_by_field_name("body")?;
    let mut cursor = block.walk();
    let groups: Vec<Node> = block
        .named_children(&mut cursor)
        .filter(|g| g.kind() == "switch_block_statement_group")
        .collect();
    groups
        .iter()
        .take(groups.len().saturating_sub(1))
        .find_map(|g| {
            let items = statements(*g);
            let last = items.iter().rev().find(|n| n.kind() != "switch_label")?;
            let jumps = matches!(
                last.kind(),
                "break_statement" | "return_statement" | "throw_statement" | "continue_statement"
            ) || last.kind() == "block" && {
                let inner = statements(*last);
                inner.last().is_some_and(|l| {
                    matches!(
                        l.kind(),
                        "break_statement"
                            | "return_statement"
                            | "throw_statement"
                            | "continue_statement"
                    )
                })
            };
            let has_body = items.iter().any(|n| n.kind() != "switch_label");
            // A comment on the case saying it falls through is deliberate.
            let after = g
                .next_named_sibling()
                .map_or(&b""[..], |n| &src[g.end_byte()..n.start_byte()]);
            // A leading comment of the next case belongs to that case's node.
            let next_start = g
                .next_named_sibling()
                .map_or(&b""[..], |n| &text(n, src)[..text(n, src).len().min(60)]);
            let said_so = contains_ignoring_case(text(*g, src), b"fall")
                || contains_ignoring_case(after, b"fall")
                || contains_ignoring_case(next_start, b"fall");
            (has_body && !jumps && !said_so).then_some(*g)
        })
}

fn local_shadows_a_field(declaration: Node, src: &[u8]) -> bool {
    let Some(class) = enclosing_class(declaration) else {
        return false;
    };
    let Some(body) = class.child_by_field_name("body") else {
        return false;
    };
    let fields: Vec<&[u8]> = members(body)
        .into_iter()
        .filter(|m| m.kind() == "field_declaration")
        .flat_map(|f| declarator_names(f, src))
        .collect();
    // Skip a static method: it cannot see instance fields anyway.
    let mut owner = declaration.parent();
    let mut hops = 0;
    while let Some(n) = owner {
        if n.kind() == "method_declaration" {
            if has_modifier(n, "static") {
                return false;
            }
            break;
        }
        hops += 1;
        if hops > 64 {
            return false;
        }
        owner = n.parent();
    }
    declarator_names(declaration, src)
        .iter()
        .any(|n| fields.contains(n))
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
    fn finally_and_branches() {
        let src = "class A {\nint f() { try { return g(); } finally { return 1; } }\nint h() { try { return g(); } finally { for (;;) { break; } } }\nvoid i() { if (a) { f(); } else if (b) { f(); } else { f(); } }\nvoid j() { if (a) { f(); } else if (b) { g(); } else { f(); } }\nvoid k() { if (a) { f(); } else { f(); } }\n}";
        assert_eq!(flagged("java/jump-in-finally", src), [2]);
        assert_eq!(flagged("java/identical-branches", src), [4, 6]);
    }

    #[test]
    fn serialization() {
        let src = "class A implements Externalizable { A(int x) {} }\nclass B implements Externalizable { public B() {} B(int x) {} }\nclass C implements Externalizable { }\nclass O { class I implements Serializable { } static class J implements Serializable { } }\nclass P implements Serializable { class I implements Serializable { } }\nclass Q { transient int x; }\nclass R implements Serializable { transient int x; }\nclass S extends T { transient int x; }";
        assert_eq!(flagged("java/externalizable-constructor", src), [1]);
        assert_eq!(flagged("java/serializable-inner-class", src), [4]);
        assert_eq!(flagged("java/transient-in-plain-class", src), [6]);
    }

    #[test]
    fn equals_and_strings() {
        let src = "class A {\npublic boolean equals(Object o) { A a = (A) o; return true; }\npublic boolean equals(Object o) { if (!(o instanceof A)) return false; A a = (A) o; return true; }\nvoid f() { \"a\".equals(\"a\"); x.equals(\"a\"); s.toLowerCase(); s = s.trim(); }\n}";
        assert_eq!(flagged("java/equals-without-type-check", src), [2]);
        assert_eq!(flagged("java/predictable-string-operation", src), [4]);
        assert_eq!(flagged("java/return-value-ignored", src), [4, 4, 4]);
    }

    #[test]
    fn synchronization() {
        let src = "class A {\nvoid a() throws Exception { lock.wait(); }\nvoid b() throws Exception { synchronized (lock) { lock.wait(); } }\nsynchronized void c() throws Exception { wait(); }\nvoid d(Thread thread) throws Exception { thread.notify(); }\nvoid e(Object lock) throws Exception { lock.notify(); }\nprivate synchronized void readObject(ObjectInputStream i) {}\nprivate void writeObject(ObjectOutputStream o) {}\n}";
        assert_eq!(flagged("java/wait-outside-synchronized", src), [2, 5, 6]);
        assert_eq!(flagged("java/wait-on-thread", src), [5]);
        assert_eq!(flagged("java/synchronized-read-object", src), [7]);
    }

    #[test]
    fn loops_and_operators() {
        let src = "class A { void f() {\nfor (int i = 10; i < 5; i++) {}\nfor (int i = 0; i < 5; i++) {}\nfor (int i = 0; i < 9; j++) {}\nfor (int i = 0; i < 9; i++) { b[i] = a[i]; }\nfor (int i = 0; i < 9; i++) { b[i] = a[i] + 1; }\nint x = 0; x =+ 1; x = +1; x += 1;\nif (ok)\n  a();\n  b();\n} }";
        assert_eq!(flagged("java/loop-never-runs", src), [2]);
        assert_eq!(flagged("java/for-update-unrelated", src), [4]);
        assert_eq!(flagged("java/array-copy-loop", src), [5]);
        assert_eq!(flagged("java/misleading-operator", src), [7]);
        assert_eq!(flagged("java/multiline-without-braces", src), [8]);
    }

    #[test]
    fn casts_and_collections() {
        let src = "class A { void f() {\nString[] a = (String[]) list.toArray();\nString[] b = list.toArray(new String[0]);\nm.computeIfAbsent(k, x -> null);\nm.computeIfAbsent(k, x -> new ArrayList<>());\nString h = \"203.0.113.7\";\nString i = \"127.0.0.1\";\n} }";
        assert_eq!(flagged("java/to-array-cast", src), [2]);
        assert_eq!(flagged("java/compute-if-absent-null", src), [4]);
        assert_eq!(flagged("java/hardcoded-ip", src), [6]);
    }

    #[test]
    fn spring() {
        let src = "@Configuration class C {\n@Async void a() {}\n@Bean A x() { return null; }\n@Bean B x(int y) { return null; }\n@Transactional void t() {}\n@Transactional public void u() {}\n@GetMapping(\"/users/{id}\") String g() { return \"\"; }\n@GetMapping(\"/users/{id}\") String h(@PathVariable String id) { return id; }\n@GetMapping(\"/users\") String i() { return \"\"; }\n@Cacheable(\"a\") @CachePut(\"a\") String j() { return \"\"; }\n@Value(\"plain\") String k;\n@Value(\"${a.b}\") String l;\n@RequestMapping(value = \"/x\", method = RequestMethod.GET) String m() { return \"\"; }\n}\ninterface R {\nPage<A> find(String n);\nPage<A> find(String n, Pageable p);\n}\n@Controller class D { @ResponseBody String a() { return \"\"; } @ResponseBody String b() { return \"\"; } }\n@Controller class E { @ResponseBody String a() { return \"\"; } String b() { return \"\"; } }";
        assert_eq!(flagged("java/async-in-configuration", src), [2]);
        assert_eq!(flagged("java/duplicate-bean-name", src), [4]);
        assert_eq!(flagged("java/proxy-annotation-visibility", src), [2, 5, 10]);
        assert_eq!(flagged("java/path-variable-not-bound", src), [7]);
        assert_eq!(flagged("java/cacheable-and-cacheput", src), [10]);
        assert_eq!(flagged("java/value-annotation-literal", src), [11]);
        assert_eq!(flagged("java/composed-request-mapping", src), [13]);
        assert_eq!(flagged("java/pageable-parameter", src), [16]);
        assert_eq!(flagged("java/controller-should-be-rest", src), [19]);
    }

    #[test]
    fn junit_rules() {
        let src = "import org.junit.jupiter.api.Test;\nimport org.junit.Assert;\nclass Checks {\n@Test private void a() {}\n@Test void b() {}\n@Test public void c() {}\n@Test @ParameterizedTest void d() {}\n@Test void e() throws Exception { Thread.sleep(5); }\nvoid f() throws Exception { Thread.sleep(5); }\n@Test void g() { assertEquals(result, 4); assertEquals(4, result); assertEquals(a, b); }\n@Disabled void h() {}\n@Disabled(\"why\") void i() {}\n@BeforeEach void s1() {}\n@BeforeEach void s2() {}\n@Test(expected = IOException.class) void j() {}\nclass Inner { @Test void k() {} }\n@Nested class Good { @Test void l() {} }\n}";
        assert_eq!(flagged("java/test-silently-ignored", src), [4]);
        assert_eq!(flagged("java/jupiter-public-test", src), [6]);
        assert_eq!(flagged("java/competing-test-annotations", src), [7]);
        assert_eq!(flagged("java/sleep-in-test", src), [8]);
        assert_eq!(flagged("java/assertion-argument-order", src), [10]);
        assert_eq!(flagged("java/ignored-test-without-reason", src), [11]);
        assert_eq!(flagged("java/duplicate-lifecycle-method", src), [14]);
        assert_eq!(flagged("java/expected-in-test-annotation", src), [15]);
        assert_eq!(flagged("java/nested-test-class-without-nested", src), [16]);
        assert_eq!(flagged("java/junit4-assert-in-jupiter", src), [2]);
        assert_eq!(flagged("java/test-class-name", src), [3]);
    }

    #[test]
    fn false_positives_found_in_real_code() {
        let src = "import org.junit.jupiter.api.Test;\n@Controller class C {\n@ModelAttribute Owner o(@PathVariable int ownerId) { return null; }\n@GetMapping(\"/owners/{ownerId}/edit\") String e() { return \"\"; }\n}\nclass A {\nvoid f() { buf.replaceAll('a', 'b'); s.toLowerCase(); assertEquals(\"abc\", join(a), \"message\"); assertEquals(join(a), \"abc\", \"message\"); }\npublic static void main(String[] args) { }\nvoid g(int x) { switch (x) { case 1: a();\n// $FALL-THROUGH$\ncase 2: b(); break; default: c(); } }\n}";
        assert!(flagged("java/path-variable-not-bound", src).is_empty());
        assert_eq!(flagged("java/return-value-ignored", src), [7]);
        assert_eq!(flagged("java/assertion-argument-order", src), [7]);
        assert!(flagged("java/unused-method-parameter", src).is_empty());
        assert!(flagged("java/switch-case-falls-through", src).is_empty());
    }

    #[test]
    fn code_and_comments() {
        let src = "package com.Acme;\nclass A {\n// int x = compute(1);\n// Compute the total price.\n// see http://example.com/a;\n// }\nvoid f() { g();; }\nvoid h(int unused, int used) { i(used); }\nprivate void j(int unused, int used) { i(used); }\nvoid k(int x) { switch (x) { case 1: a(); case 2: b(); break; default: c(); } }\n}";
        assert_eq!(flagged("java/package-name", src), [1]);
        assert_eq!(flagged("java/commented-out-code", src), [3]);
        assert_eq!(flagged("java/unused-method-parameter", src), [9]);
        assert_eq!(flagged("java/switch-case-falls-through", src), [10]);
    }

    #[test]
    fn small_checks() {
        let src = "class A {\nint count;\nstatic ThreadLocal<String> t = new ThreadLocal<>();\nvoid a() { int count = 1; }\nstatic void b() { int count = 1; }\nvoid c(InputStream in) { try { use(in); } finally { in.close(); } }\nvoid d() { try { g(); } catch (IOException e) { log.error(\"x\", e); throw e; } }\nvoid e() { try { g(); } catch (IOException e) { throw new UncheckedIOException(e); } }\nvoid f() { Class.forName(\"com.mysql.cj.jdbc.Driver\"); Class.forName(\"com.acme.Plugin\"); }\nvoid g() { Region r = Region.of(\"eu-west-1\"); S3Client c = S3Client.builder().build(); }\npublic String toString() { return \"\"; }\n@Override public int hashCode() { return 1; }\n}";
        assert_eq!(flagged("java/local-shadows-field", src), [4]);
        assert_eq!(flagged("java/thread-local-never-removed", src), [3]);
        assert_eq!(flagged("java/close-in-finally", src), [6]);
        assert_eq!(flagged("java/log-and-rethrow", src), [7]);
        assert_eq!(flagged("java/jdbc-driver-for-name", src), [9]);
        assert_eq!(flagged("java/aws-region-hardcoded", src), [10]);
        assert_eq!(flagged("java/region-not-set", src), [10]);
        assert_eq!(flagged("java/missing-override", src), [11]);
    }
}
