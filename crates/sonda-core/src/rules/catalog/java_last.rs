//! Java rules, part 5 (ADR-0007, batch 12): size and complexity, naming,
//! serialization, and JUnit, AssertJ and Mockito idioms. Queries stay cheap
//! on deep trees: see `js_modern.rs`.

use super::java_bugs::{has_annotation, has_modifier, statements};
use super::java_extra::{class_members, declared_field, declared_type, name_text, type_text};
use super::java_security::{call_arguments, find_node, method_name, text};
use super::java_smells::{children_of_kind, count_word, declarator_names, enclosing_class};
use super::*;

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "java/too-many-returns",
        name: "Methods should not have too many return statements",
        description: "Many exits make the flow hard to follow.",
        message: "Reduce the number of returns.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 20,
        sonar: &[exact("S1142")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Keep(has_many_returns)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { int f(int x) { if (x == 1) { return 1; } if (x == 2) { return 2; } if (x == 3) { return 3; } return 4; } }",
            good: "class A { int f(int x) { return x; } }",
        }),
    },
    Rule {
        id: "java/nesting-depth",
        name: "Control flow statements should not be nested too deeply",
        description: "Deep nesting hides the main path.",
        message: "Extract a method or use early returns.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S134")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(if_statement) @match
(for_statement) @match
(enhanced_for_statement) @match
(while_statement) @match
(do_statement) @match
(switch_expression) @match
(try_statement) @match"#,
            filter: Some(Keep(is_nested_too_deeply)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { if (a) { if (b) { if (c) { if (d) { g(); } } } } } }",
            good: "class A { void f() { if (a && b) { g(); } } }",
        }),
    },
    Rule {
        id: "java/method-complexity",
        name: "Methods should not be too complex",
        description: "Every branch is another path to test.",
        message: "Split this method.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 20,
        sonar: &[exact("S1541")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Keep(is_too_complex)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(int a) { if (a == 1) {} if (a == 2) {} if (a == 3) {} if (a == 4) {} if (a == 5) {} if (a == 6) {} if (a == 7) {} if (a == 8) {} if (a == 9) {} if (a == 10) {} } }",
            good: "class A { void f(int a) { if (a == 1) {} } }",
        }),
    },
    Rule {
        id: "java/expression-complexity",
        name: "Expressions should not be too complex",
        description: "Four boolean operators in one expression are hard to read.",
        message: "Name the parts.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S1067")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(binary_expression operator: ["&&" "||"]) @match"#,
            filter: Some(Keep(is_too_complex_expression)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { boolean f(boolean a, boolean b, boolean c, boolean d, boolean e) { return a && b || c && d || e; } }",
            good: "class A { boolean f(boolean a, boolean b) { return a && b; } }",
        }),
    },
    Rule {
        id: "java/switch-case-too-long",
        name: "switch case clauses should not have too many lines of code",
        description: "A long case belongs in its own method.",
        message: "Extract a method.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S1151")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(switch_block_statement_group) @match"#,
            filter: Some(Keep(case_is_long)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(int x) { switch (x) { case 1: a();\n b();\n c();\n d();\n e();\n f();\n g();\n break; } } }",
            good: "class A { void f(int x) { switch (x) { case 1: a(); break; } } }",
        }),
    },
    Rule {
        id: "java/anonymous-class-too-long",
        name: "Anonymous classes should not have too many lines",
        description: "A long anonymous class should have a name.",
        message: "Make it a named class.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 15,
        sonar: &[exact("S1188")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(object_creation_expression (class_body) @match)"#,
            filter: Some(Keep(spans_over_twenty_lines)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { Object o = new Object() {\n int a;\n int b;\n int c;\n int d;\n int e;\n int f;\n int g;\n int h;\n int i;\n int j;\n int k;\n int l;\n int m;\n int n;\n int o;\n int p;\n int q;\n int r;\n int s;\n int t;\n int u;\n }; }",
            good: "class A { Object o = new Object() { int a; }; }",
        }),
    },
    Rule {
        id: "java/lambda-too-long",
        name: "Lambdas should not have too many lines",
        description: "A long lambda hides what it does.",
        message: "Extract a method.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S5612")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(lambda_expression body: (block) @match)"#,
            filter: Some(Keep(spans_over_ten_lines)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { Runnable r = () -> {\n a();\n b();\n c();\n d();\n e();\n f();\n g();\n h();\n i();\n j();\n k();\n }; }",
            good: "class A { Runnable r = () -> { a(); }; }",
        }),
    },
    Rule {
        id: "java/inner-class-too-long",
        name: "Inner classes should not have too many lines of code",
        description: "A long inner class is a class of its own.",
        message: "Move it out.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 15,
        sonar: &[exact("S2972")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_body (class_declaration) @match)"#,
            filter: Some(Keep(spans_over_twenty_five_lines)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { class B {\n int a;\n int b;\n int c;\n int d;\n int e;\n int f;\n int g;\n int h;\n int i;\n int j;\n int k;\n int l;\n int m;\n int n;\n int o;\n int p;\n int q;\n int r;\n int s;\n int t;\n int u;\n int v;\n int w;\n int x;\n int y;\n int z;\n } }",
            good: "class A { class B { int a; } }",
        }),
    },
    Rule {
        id: "java/too-many-methods",
        name: "Classes should not have too many methods",
        description: "A class with dozens of methods has several responsibilities.",
        message: "Split the class.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 60,
        sonar: &[exact("S1448")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Keep(has_too_many_methods)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void a1() {} void a2() {} void a3() {} void a4() {} void a5() {} void a6() {} void a7() {} void a8() {} void a9() {} void a10() {} void a11() {} void a12() {} void a13() {} void a14() {} void a15() {} void a16() {} void a17() {} void a18() {} void a19() {} void a20() {} void a21() {} void a22() {} void a23() {} void a24() {} void a25() {} void a26() {} void a27() {} void a28() {} void a29() {} void a30() {} void a31() {} void a32() {} void a33() {} void a34() {} void a35() {} void a36() {} }",
            good: "class A { void a1() {} }",
        }),
    },
    Rule {
        id: "java/statements-on-one-line",
        name: "Statements should be on separate lines",
        description: "Several statements on one line are easy to misread.",
        message: "Put each statement on its own line.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 1,
        sonar: &[exact("S122")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(block) @match"#,
            filter: Some(Find(statements_share_a_line)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { a(); b();\n } }",
            good: "class A { void f() {\n a();\n b();\n } }",
        }),
    },
    Rule {
        id: "java/equality-in-loop-condition",
        name: "Equality operators should not be used in for loop termination conditions",
        description: "If the counter skips the bound, the loop never ends.",
        message: "Use <, <=, > or >=.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S888")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(for_statement condition: (binary_expression operator: ["==" "!="]) @match)"#,
            filter: Some(Keep(compares_with_a_number)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(int n) { for (int i = 0; i != n; i += 2) { g(); } } }",
            good: "class A { void f(int n) { for (int i = 0; i < n; i += 2) { g(); } } }",
        }),
    },
    Rule {
        id: "java/varargs-declared",
        name: "Functions should not be defined with a variable number of arguments",
        description: "Varargs hide the arity and defeat overloading.",
        message: "Take an array or a collection.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S923")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(spread_parameter) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(String... names) {} }",
            good: "class A { void f(String[] names) {} }",
        }),
    },
    Rule {
        id: "java/ternary-operator",
        name: "The ternary operator should not be used",
        description: "Nested or long ternaries are hard to read.",
        message: "Use an if statement.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1774")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(ternary_expression) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { int f(boolean b) { return b ? 1 : 2; } }",
            good: "class A { int f(boolean b) { if (b) { return 1; } return 2; } }",
        }),
    },
    Rule {
        id: "java/floating-point-equality",
        name: "Floating point numbers should not be tested for equality",
        description: "Rounding makes two mathematically equal results differ in the last bits.",
        message: "Compare with a tolerance.",
        category: Bug,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S1244")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(binary_expression operator: ["==" "!="]) @match"#,
            filter: Some(Keep(compares_floating_point)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { boolean f(double a, double b) { return a == b; } }",
            good: "class A { boolean f(double a, double b) { return Math.abs(a - b) < 1e-9; } }",
        }),
    },
    Rule {
        id: "java/float-increment",
        name: "Increment and decrement operators should not be used with floating point variables",
        description: "x++ on a double adds exactly 1, which drifts for large values.",
        message: "Use x += 1.0.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S8346")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(update_expression) @match"#,
            filter: Some(Keep(increments_a_float)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(double d) { d++; } }",
            good: "class A { void f(double d) { d += 1.0; } }",
        }),
    },
    Rule {
        id: "java/deprecated-documentation",
        name: "Deprecated elements should have both the annotation and the Javadoc tag",
        description: "One without the other leaves tools or readers uninformed.",
        message: "Add both.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1123")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match
(method_declaration) @match
(field_declaration) @match
(interface_declaration) @match"#,
            filter: Some(Keep(deprecation_is_half_documented)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { @Deprecated void f() {} }",
            good: "class A { /** @deprecated use g */ @Deprecated void f() {} }",
        }),
    },
    Rule {
        id: "java/serial-version-uid",
        name: "Serializable classes should have a serialVersionUID",
        description: "Without one the compiler computes it, and any change breaks old data.",
        message: "Declare serialVersionUID.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S2057")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Keep(serializable_without_uid)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A implements Serializable {}",
            good: "class A implements Serializable { private static final long serialVersionUID = 1L; }",
        }),
    },
    Rule {
        id: "java/comparator-serializable",
        name: "Comparators should be Serializable",
        description: "A TreeMap with a non-serializable comparator can't be serialized.",
        message: "Implement Serializable.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S2063")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration interfaces: (super_interfaces (type_list (generic_type (type_identifier) @i (#eq? @i "Comparator"))))) @match"#,
            filter: Some(Keep(lacks_serializable)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A implements Comparator<String> {}",
            good: "class A implements Comparator<String>, Serializable {}",
        }),
    },
    Rule {
        id: "java/main-throws",
        name: "main should not throw anything",
        description: "An uncaught exception from main kills the program with a stack trace.",
        message: "Handle the exception.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2096")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration name: (identifier) @n (#eq? @n "main") (throws)) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { public static void main(String[] a) throws Exception {} }",
            good: "class A { public static void main(String[] a) {} }",
        }),
    },
    Rule {
        id: "java/string-switch",
        name: "Switches should be used for sequences of simple String tests",
        description: "A chain of equals comparisons is a switch.",
        message: "Use a switch.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S2196")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(if_statement) @match"#,
            filter: Some(Keep(is_string_equals_chain)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(String s) { if (s.equals(\"a\")) { x(); } else if (s.equals(\"b\")) { y(); } else if (s.equals(\"c\")) { z(); } } }",
            good: "class A { void f(String s) { switch (s) { case \"a\": x(); break; default: break; } } }",
        }),
    },
    Rule {
        id: "java/wildcard-import",
        name: "Wildcard imports should not be used",
        description: "They hide where names come from.",
        message: "Import the types you use.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 2,
        sonar: &[exact("S2208")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(import_declaration (asterisk)) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "import java.util.*;",
            good: "import java.util.List;",
        }),
    },
    Rule {
        id: "java/utility-class-instantiated",
        name: "Classes with only static methods should not be instantiated",
        description: "There is nothing for an instance to hold.",
        message: "Call the static methods.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2440")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(program) @match"#,
            filter: Some(Find(instantiates_a_utility_class)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class U { static void f() {} }\nclass A { void g() { new U(); } }",
            good: "class U { static void f() {} }\nclass A { void g() { U.f(); } }",
        }),
    },
    Rule {
        id: "java/final-class-private-constructors",
        name: "Classes without public constructors should be final",
        description: "Nothing outside can extend it.",
        message: "Make it final.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S2974")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Keep(only_private_constructors_not_final)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { private A() {} }",
            good: "final class A { private A() {} }",
        }),
    },
    Rule {
        id: "java/static-field-name",
        name: "Static non-final field names should comply with a naming convention",
        description: "camelCase tells readers it isn't a constant.",
        message: "Rename it.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S3008")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(field_declaration) @match"#,
            filter: Some(Find(static_field_name_is_wrong)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { static int My_Count; }",
            good: "class A { static int myCount; }",
        }),
    },
    Rule {
        id: "java/static-imports-many",
        name: "Classes should not have too many static imports",
        description: "Many static imports hide where names come from.",
        message: "Import the class.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3030")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(program) @match"#,
            filter: Some(Keep(has_many_static_imports)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "import static a.A.a1;\nimport static a.A.a2;\nimport static a.A.a3;\nimport static a.A.a4;\nimport static a.A.a5;\nclass A {}",
            good: "import static a.A.a1;\nclass A {}",
        }),
    },
    Rule {
        id: "java/controller-scope",
        name: "Spring @Controller classes should not use @Scope",
        description: "Controllers are singletons by design.",
        message: "Remove @Scope.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3750")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Keep(controller_has_scope)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "@Controller @Scope(\"session\") class A {}",
            good: "@Controller class A {}",
        }),
    },
    Rule {
        id: "java/input-stream-bulk-read",
        name: "read(byte[],int,int) should be overridden",
        description: "The default calls read() once per byte.",
        message: "Override the bulk read.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S4929")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration superclass: (superclass (type_identifier) @s (#eq? @s "InputStream"))) @match"#,
            filter: Some(Keep(stream_lacks_bulk_method)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A extends InputStream { public int read() { return -1; } }",
            good: "class A extends InputStream { public int read() { return -1; } public int read(byte[] b, int o, int l) { return -1; } }",
        }),
    },
    Rule {
        id: "java/output-stream-bulk-write",
        name: "write(byte[],int,int) should be overridden",
        description: "The default calls write() once per byte.",
        message: "Override the bulk write.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S4349")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration superclass: (superclass (type_identifier) @s (#eq? @s "OutputStream"))) @match"#,
            filter: Some(Keep(stream_lacks_bulk_method)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A extends OutputStream { public void write(int b) {} }",
            good: "class A extends OutputStream { public void write(int b) {} public void write(byte[] b, int o, int l) {} }",
        }),
    },
    Rule {
        id: "java/signed-byte-read",
        name: "InputStream.read() implementation should not return a signed byte",
        description: "read() must return 0 to 255, or -1.",
        message: "Mask with & 0xFF.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S4517")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration name: (identifier) @n (#eq? @n "read")) @match"#,
            filter: Some(Find(read_returns_a_signed_byte)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A extends InputStream { public int read() { byte b = next(); return b; } }",
            good: "class A extends InputStream { public int read() { byte b = next(); return b & 0xFF; } }",
        }),
    },
    Rule {
        id: "java/boxed-boolean-condition",
        name: "Avoid using boxed Boolean types directly in boolean expressions",
        description: "A null Boolean throws NullPointerException when unboxed.",
        message: "Test for null, or use Boolean.TRUE.equals.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5411")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(if_statement condition: (parenthesized_expression (identifier) @match))"#,
            filter: Some(Keep(is_boxed_boolean)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(Boolean b) { if (b) { g(); } } }",
            good: "class A { void f(Boolean b) { if (Boolean.TRUE.equals(b)) { g(); } } }",
        }),
    },
    Rule {
        id: "java/assert-multiple-calls",
        name: "Only one method invocation is expected when testing runtime exceptions",
        description: "Any other call in the lambda could be the one that throws.",
        message: "Keep only the call under test.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5778")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "assertThrows" "assertThrowsExactly")) @match"#,
            filter: Some(Keep(lambda_has_several_statements)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void t() { assertThrows(X.class, () -> { a(); b(); }); } }",
            good: "class A { void t() { a(); assertThrows(X.class, () -> b()); } }",
        }),
    },
    Rule {
        id: "java/assert-in-try",
        name: "Assertion methods should not be used within the try block of a try-catch catching an Error",
        description: "The AssertionError is caught, so the test passes.",
        message: "Move the assertion out of the try block.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5779")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(try_statement) @match"#,
            filter: Some(Find(assertion_inside_try_catching_error)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void t() { try { assertEquals(1, x()); } catch (AssertionError e) { log(); } } }",
            good: "class A { void t() { try { x(); } catch (AssertionError e) { log(); } assertEquals(1, y()); } }",
        }),
    },
    Rule {
        id: "java/lifecycle-annotation",
        name: "Methods setUp() and tearDown() should be correctly annotated starting with JUnit4",
        description: "JUnit 4 ignores them without @Before and @After.",
        message: "Add the annotation.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5826")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration name: (identifier) @n (#any-of? @n "setUp" "tearDown")) @match"#,
            filter: Some(Keep(lifecycle_method_unannotated)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void setUp() {} @Test void t() {} }",
            good: "class A { @Before void setUp() {} @Test void t() {} }",
        }),
    },
    Rule {
        id: "java/assertj-context-late",
        name: "AssertJ methods setting the assertion context should come before an assertion",
        description: "as() after the assertion has no effect on it.",
        message: "Move as() before the assertion.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5833")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (method_invocation name: (identifier) @a) name: (identifier) @n (#any-of? @n "as" "describedAs" "withFailMessage" "overridingErrorMessage") (#match? @a "^(is|has|contains|does|should)")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void t() { assertThat(x).isEqualTo(1).as(\"msg\"); } }",
            good: "class A { void t() { assertThat(x).as(\"msg\").isEqualTo(1); } }",
        }),
    },
    Rule {
        id: "java/assertj-empty-collection",
        name: "AssertJ assertions allMatch and doesNotContain should also test for emptiness",
        description: "They pass on an empty collection.",
        message: "Also assert that it is not empty.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5841")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "allMatch" "doesNotContain" "doesNotContainNull")) @match"#,
            filter: Some(Keep(chain_lacks_emptiness_check)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void t() { assertThat(list).allMatch(x -> x > 0); } }",
            good: "class A { void t() { assertThat(list).isNotEmpty().allMatch(x -> x > 0); } }",
        }),
    },
    Rule {
        id: "java/assert-incompatible-types",
        name: "Assertions comparing incompatible types should not be made",
        description: "Values of different kinds are never equal.",
        message: "Compare comparable values.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5845")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "assertEquals" "assertNotEquals" "assertSame")) @match"#,
            filter: Some(Keep(asserts_across_literal_kinds)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void t() { assertEquals(1, \"a\"); } }",
            good: "class A { void t() { assertEquals(1, x()); } }",
        }),
    },
    Rule {
        id: "java/mockito-annotations-uninitialized",
        name: "Annotated Mockito objects should be initialized",
        description: "@Mock fields stay null unless Mockito sets them up.",
        message: "Add the runner, extension or openMocks().",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5979")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Keep(mocks_never_initialized)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { @Mock B b; @Test void t() {} }",
            good: "@ExtendWith(MockitoExtension.class) class A { @Mock B b; @Test void t() {} }",
        }),
    },
    Rule {
        id: "java/mockito-matchers-mixed",
        name: "Mockito argument matchers should be used on all parameters",
        description: "Mixing matchers and raw values raises InvalidUseOfMatchersException.",
        message: "Wrap raw values in eq().",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6073")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation) @match"#,
            filter: Some(Keep(mixes_matchers_and_values)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void t() { verify(m).call(any(), 5); } }",
            good: "class A { void t() { verify(m).call(any(), eq(5)); } }",
        }),
    },
    Rule {
        id: "java/dangling-javadoc",
        name: "Dangling Javadoc comments should be removed",
        description: "A Javadoc comment that documents nothing is dead text.",
        message: "Remove it or attach it to a declaration.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S8491")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(block_comment) @match"#,
            filter: Some(Keep(javadoc_documents_nothing)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() {\n /** note */\n g();\n } }",
            good: "class A { void f() {\n // note\n g();\n } }",
        }),
    },
    Rule {
        id: "java/pattern-compiled-in-method",
        name: "Regex patterns should not be created needlessly",
        description: "Compiling on every call wastes time.",
        message: "Compile once into a static final field.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S4248")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) @o name: (identifier) @n (#eq? @o "Pattern") (#eq? @n "compile")) @match"#,
            filter: Some(Keep(compiles_a_literal_inside_a_method)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { boolean f(String s) { return Pattern.compile(\"a+\").matcher(s).matches(); } }",
            good: "class A { private static final Pattern P = Pattern.compile(\"a+\"); }",
        }),
    },
    Rule {
        id: "java/large-number-underscores",
        name: "Underscores should be used to make large numbers readable",
        description: "1000000 is easier to read as 1_000_000.",
        message: "Add underscores.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S2148")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(decimal_integer_literal) @match"#,
            filter: Some(Keep(long_number_without_underscores)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { int n = 1000000; }",
            good: "class A { int n = 1_000_000; }",
        }),
    },
    Rule {
        id: "java/test-method-name",
        name: "Test methods should comply with a naming convention",
        description: "Names that read as sentences are easy to scan.",
        message: "Rename the test.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S3578")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration name: (identifier) @n) @match"#,
            filter: Some(Keep(test_name_breaks_convention)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { @Test void Test_One() {} }",
            good: "class A { @Test void testOne() {} }",
        }),
    },
    Rule {
        id: "java/abstract-class-name",
        name: "Abstract class names should comply with a naming convention",
        description: "Abstract and the class name together say what it is.",
        message: "Start the name with Abstract.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S118")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration name: (identifier) @match) @c"#,
            filter: Some(Keep(abstract_class_name_is_wrong)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "abstract class Base {}",
            good: "abstract class AbstractBase {}",
        }),
    },
    Rule {
        id: "java/abstract-class-mixed",
        name: "An abstract class should have both abstract and concrete methods",
        description: "With only one kind it is an interface or a plain class.",
        message: "Use an interface, or make it concrete.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S1694")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Keep(abstract_class_has_one_kind)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "abstract class A { abstract void f(); abstract void g(); }",
            good: "abstract class A { abstract void f(); void g() {} }",
        }),
    },
    Rule {
        id: "java/public-api-undocumented",
        name: "Public types, methods and fields should be documented with Javadoc",
        description: "Callers read the Javadoc, not the code.",
        message: "Add Javadoc.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1176")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match
(method_declaration) @match"#,
            filter: Some(Find(public_member_lacks_javadoc)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "public class A { public void f() {} }",
            good: "class A { void f() { /** Doc. */ public class A { /** Doc. */ public void f() {} } } }",
        }),
    },
    Rule {
        id: "java/private-field-used-locally",
        name: "Private fields only used as local variables in methods should become local variables",
        description: "A field one method writes and reads is a local variable in disguise.",
        message: "Make it a local variable.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1450")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Find(private_field_used_in_one_method)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { private int tmp; void f() { tmp = 1; g(tmp); } void h() {} }",
            good: "class A { void f() { int tmp = 1; g(tmp); } void h() {} }",
        }),
    },
    Rule {
        id: "java/private-method-not-static",
        name: "private and final methods that don't access instance data should be static",
        description: "They don't need an instance.",
        message: "Make it static.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2325")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Keep(method_ignores_the_instance)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { private int twice(int x) { return x * 2; } }",
            good: "class A { private static int twice(int x) { return x * 2; } }",
        }),
    },
];

// ---------------------------------------------------- filters

const NESTED_SCOPES: &[&str] = &[
    "lambda_expression",
    "class_declaration",
    "interface_declaration",
    "enum_declaration",
    "record_declaration",
];

pub(super) fn count_nodes(root: Node, stops: &[&str], pred: impl Fn(Node) -> bool) -> usize {
    let mut count = 0;
    let mut cursor = root.walk();
    if !cursor.goto_first_child() {
        return 0;
    }
    loop {
        let n = cursor.node();
        if pred(n) {
            count += 1;
        }
        if !stops.contains(&n.kind()) && cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return count;
            }
        }
    }
}

pub(super) fn line_span(node: Node) -> usize {
    node.end_position().row - node.start_position().row + 1
}

fn compares_with_a_number(binary: Node, _: &[u8]) -> bool {
    let side = |n: Option<Node>| n.is_some_and(|n| n.kind() == "null_literal");
    !side(binary.child_by_field_name("left")) && !side(binary.child_by_field_name("right"))
}

fn has_many_returns(method: Node, _: &[u8]) -> bool {
    method
        .child_by_field_name("body")
        .is_some_and(|b| count_nodes(b, NESTED_SCOPES, |n| n.kind() == "return_statement") > 3)
}

fn is_nested_too_deeply(statement: Node, _: &[u8]) -> bool {
    const CONTROL: &[&str] = &[
        "if_statement",
        "for_statement",
        "enhanced_for_statement",
        "while_statement",
        "do_statement",
        "switch_expression",
        "try_statement",
    ];
    let mut depth = 0;
    let mut child = statement;
    let mut p = statement.parent();
    while let Some(n) = p {
        if matches!(
            n.kind(),
            "method_declaration" | "constructor_declaration" | "lambda_expression" | "class_body"
        ) {
            break;
        }
        // `else if` is the same level as its `if`
        let else_branch =
            n.kind() == "if_statement" && n.child_by_field_name("alternative") == Some(child);
        let continues_chain = statement.kind() == "if_statement"
            && n.kind() == "if_statement"
            && n.child_by_field_name("alternative") == Some(child);
        let _ = continues_chain;
        if CONTROL.contains(&n.kind()) && !(else_branch && child.kind() == "if_statement") {
            depth += 1;
        }
        child = n;
        p = n.parent();
    }
    // an `else if` is not nested in its `if`
    let is_else_if = statement.kind() == "if_statement"
        && statement.parent().is_some_and(|q| {
            q.kind() == "if_statement" && q.child_by_field_name("alternative") == Some(statement)
        });
    depth == 3 && !is_else_if
}

fn is_too_complex(method: Node, src: &[u8]) -> bool {
    let Some(body) = method.child_by_field_name("body") else {
        return false;
    };
    let branches = count_nodes(body, NESTED_SCOPES, |n| match n.kind() {
        "if_statement"
        | "for_statement"
        | "enhanced_for_statement"
        | "while_statement"
        | "do_statement"
        | "catch_clause"
        | "ternary_expression" => true,
        "switch_label" => text(n, src).starts_with(b"case"),
        "binary_expression" => matches!(
            n.child_by_field_name("operator")
                .map_or(&b""[..], |o| text(o, src)),
            b"&&" | b"||"
        ),
        _ => false,
    });
    branches + 1 > 10
}

fn is_too_complex_expression(binary: Node, src: &[u8]) -> bool {
    let logical = |n: Node| {
        n.kind() == "binary_expression"
            && matches!(
                n.child_by_field_name("operator")
                    .map_or(&b""[..], |o| text(o, src)),
                b"&&" | b"||"
            )
    };
    // only the outermost logical expression is judged
    let mut p = binary.parent();
    while let Some(n) = p {
        if n.kind() == "parenthesized_expression" {
            p = n.parent();
            continue;
        }
        if logical(n) {
            return false;
        }
        break;
    }
    count_nodes(binary, &[], logical) + 1 > 3
}

fn case_is_long(group: Node, _: &[u8]) -> bool {
    line_span(group) > 6
}

fn spans_over_twenty_lines(node: Node, _: &[u8]) -> bool {
    line_span(node) > 20
}

fn spans_over_ten_lines(node: Node, _: &[u8]) -> bool {
    line_span(node) > 10
}

fn spans_over_twenty_five_lines(node: Node, _: &[u8]) -> bool {
    line_span(node) > 25
}

fn has_too_many_methods(class: Node, _: &[u8]) -> bool {
    class_members(class)
        .iter()
        .filter(|m| m.kind() == "method_declaration")
        .count()
        > 35
}

fn statements_share_a_line<'t>(block: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    let items = statements(block);
    items
        .windows(2)
        .find(|w| w[0].end_position().row == w[1].start_position().row)
        .map(|w| w[1])
}

fn is_float_type(t: &[u8]) -> bool {
    matches!(t, b"double" | b"float" | b"Double" | b"Float")
}

fn compares_floating_point(binary: Node, src: &[u8]) -> bool {
    let is_float = |n: Option<Node>| {
        n.is_some_and(|n| {
            n.kind() == "decimal_floating_point_literal"
                || (n.kind() == "identifier"
                    && is_float_type(type_text(declared_type(binary, text(n, src), src), src)))
        })
    };
    is_float(binary.child_by_field_name("left")) || is_float(binary.child_by_field_name("right"))
}

fn increments_a_float(update: Node, src: &[u8]) -> bool {
    update.named_child(0).is_some_and(|n| {
        n.kind() == "identifier"
            && is_float_type(type_text(declared_type(update, text(n, src), src), src))
    })
}

fn deprecation_is_half_documented(declaration: Node, src: &[u8]) -> bool {
    let annotated = has_annotation(declaration, b"Deprecated", src);
    let documented = declaration
        .prev_named_sibling()
        .filter(|c| c.kind() == "block_comment" && text(*c, src).starts_with(b"/**"))
        .is_some_and(|c| text(c, src).windows(11).any(|w| w == b"@deprecated"));
    annotated != documented
}

fn implements_word(class: Node, word: &[u8], src: &[u8]) -> bool {
    class
        .child_by_field_name("interfaces")
        .is_some_and(|i| count_word(text(i, src), word) > 0)
}

fn serializable_without_uid(class: Node, src: &[u8]) -> bool {
    implements_word(class, b"Serializable", src)
        && declared_field(class, b"serialVersionUID", src).is_none()
}

fn lacks_serializable(class: Node, src: &[u8]) -> bool {
    !implements_word(class, b"Serializable", src)
}

fn is_string_equals_chain(if_statement: Node, src: &[u8]) -> bool {
    if if_statement.parent().is_some_and(|p| {
        p.kind() == "if_statement" && p.child_by_field_name("alternative") == Some(if_statement)
    }) {
        return false;
    }
    let tests_a_string = |cond: Node| {
        let inner = if cond.kind() == "parenthesized_expression" {
            cond.named_child(0)
        } else {
            Some(cond)
        };
        inner.is_some_and(|c| {
            c.kind() == "method_invocation"
                && method_name(c, src) == b"equals"
                && (c
                    .child_by_field_name("object")
                    .is_some_and(|o| o.kind() == "string_literal")
                    || call_arguments(c)
                        .first()
                        .is_some_and(|a| a.kind() == "string_literal"))
        })
    };
    let mut links = 0;
    let mut cur = if_statement;
    loop {
        if !cur
            .child_by_field_name("condition")
            .is_some_and(tests_a_string)
        {
            return false;
        }
        links += 1;
        match cur.child_by_field_name("alternative") {
            Some(next) if next.kind() == "if_statement" => cur = next,
            _ => break,
        }
    }
    links >= 3
}

fn instantiates_a_utility_class<'t>(program: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let classes = children_of_kind(program, "class_declaration");
    let utilities: Vec<&[u8]> = classes
        .iter()
        .filter(|c| {
            let members = class_members(**c);
            let methods = members
                .iter()
                .filter(|m| m.kind() == "method_declaration")
                .count();
            methods > 0
                && members.iter().all(|m| match m.kind() {
                    "method_declaration" | "field_declaration" => has_modifier(*m, "static"),
                    "constructor_declaration" => false,
                    _ => true,
                })
        })
        .map(|c| name_text(*c, src))
        .collect();
    find_node(program, |n| {
        n.kind() == "object_creation_expression"
            && n.child_by_field_name("type")
                .is_some_and(|t| utilities.contains(&text(t, src)))
            && enclosing_class(n).is_none_or(|c| !utilities.contains(&name_text(c, src)))
    })
}

fn only_private_constructors_not_final(class: Node, _: &[u8]) -> bool {
    if has_modifier(class, "final") || has_modifier(class, "abstract") {
        return false;
    }
    let ctors: Vec<Node> = class_members(class)
        .into_iter()
        .filter(|m| m.kind() == "constructor_declaration")
        .collect();
    !ctors.is_empty() && ctors.iter().all(|c| has_modifier(*c, "private"))
}

fn static_field_name_is_wrong<'t>(field: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !has_modifier(field, "static")
        || has_modifier(field, "final")
        || field
            .parent()
            .and_then(|b| b.parent())
            .is_none_or(|c| c.kind() != "class_declaration")
    {
        return None;
    }
    children_of_kind(field, "variable_declarator")
        .into_iter()
        .filter_map(|d| d.child_by_field_name("name"))
        .find(|n| {
            let t = text(*n, src);
            !(t.first().is_some_and(u8::is_ascii_lowercase)
                && t.iter().all(u8::is_ascii_alphanumeric))
        })
}

fn has_many_static_imports(program: Node, src: &[u8]) -> bool {
    children_of_kind(program, "import_declaration")
        .iter()
        .filter(|i| count_word(text(**i, src), b"static") > 0)
        .count()
        > 4
}

fn controller_has_scope(class: Node, src: &[u8]) -> bool {
    (has_annotation(class, b"Controller", src) || has_annotation(class, b"RestController", src))
        && has_annotation(class, b"Scope", src)
}

fn stream_lacks_bulk_method(class: Node, src: &[u8]) -> bool {
    let input = class
        .child_by_field_name("superclass")
        .is_some_and(|s| count_word(text(s, src), b"InputStream") > 0);
    let (single, bulk): (&[u8], &[u8]) = if input {
        (b"read", b"read")
    } else {
        (b"write", b"write")
    };
    let methods: Vec<Node> = class_members(class)
        .into_iter()
        .filter(|m| m.kind() == "method_declaration")
        .collect();
    let arity = |m: &Node| {
        m.child_by_field_name("parameters")
            .map_or(0, |p| p.named_child_count())
    };
    let has_single = methods
        .iter()
        .any(|m| name_text(*m, src) == single && arity(m) == if input { 0 } else { 1 });
    let has_bulk = methods
        .iter()
        .any(|m| name_text(*m, src) == bulk && arity(m) == 3);
    has_single && !has_bulk
}

fn read_returns_a_signed_byte<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if method
        .child_by_field_name("parameters")
        .is_some_and(|p| p.named_child_count() > 0)
    {
        return None;
    }
    find_node(method.child_by_field_name("body")?, |n| {
        n.kind() == "return_statement"
            && n.named_child(0).is_some_and(|v| match v.kind() {
                "cast_expression" => v
                    .child_by_field_name("type")
                    .is_some_and(|t| text(t, src) == b"byte"),
                "identifier" => type_text(declared_type(v, text(v, src), src), src) == b"byte",
                _ => false,
            })
    })
}

fn is_boxed_boolean(ident: Node, src: &[u8]) -> bool {
    type_text(declared_type(ident, text(ident, src), src), src) == b"Boolean"
}

fn lambda_has_several_statements(call: Node, _: &[u8]) -> bool {
    call_arguments(call).iter().any(|a| {
        a.kind() == "lambda_expression"
            && a.child_by_field_name("body")
                .is_some_and(|b| b.kind() == "block" && statements(b).len() > 1)
    })
}

fn assertion_inside_try_catching_error<'t>(
    try_statement: Node<'t>,
    src: &[u8],
) -> Option<Node<'t>> {
    let catches_error = children_of_kind(try_statement, "catch_clause")
        .iter()
        .any(|c| {
            c.named_child(0).is_some_and(|p| {
                let t = text(p, src);
                count_word(t, b"AssertionError") > 0
                    || count_word(t, b"Error") > 0
                    || count_word(t, b"Throwable") > 0
            })
        });
    if !catches_error {
        return None;
    }
    find_node(try_statement.child_by_field_name("body")?, |n| {
        n.kind() == "method_invocation" && {
            let m = method_name(n, src);
            m.starts_with(b"assert") || m == b"fail"
        }
    })
}

fn lifecycle_method_unannotated(method: Node, src: &[u8]) -> bool {
    let Some(class) = enclosing_class(method) else {
        return false;
    };
    if class
        .child_by_field_name("superclass")
        .is_some_and(|s| count_word(text(s, src), b"TestCase") > 0)
    {
        return false;
    }
    let annotated = [
        &b"Before"[..],
        b"After",
        b"BeforeEach",
        b"AfterEach",
        b"BeforeClass",
        b"AfterClass",
        b"BeforeAll",
        b"AfterAll",
        b"Override",
    ]
    .iter()
    .any(|a| has_annotation(method, a, src));
    !annotated
        && class_members(class)
            .iter()
            .any(|m| m.kind() == "method_declaration" && has_annotation(*m, b"Test", src))
}

fn chain_lacks_emptiness_check(call: Node, src: &[u8]) -> bool {
    let mut names: Vec<&[u8]> = Vec::new();
    let mut cur = Some(call);
    let mut from_assert_that = false;
    while let Some(c) = cur {
        if c.kind() != "method_invocation" {
            break;
        }
        let m = method_name(c, src);
        names.push(m);
        if m == b"assertThat" {
            from_assert_that = true;
        }
        cur = c.child_by_field_name("object");
    }
    // the assertion may continue past this call
    let mut up = call.parent();
    while let Some(p) = up {
        if p.kind() == "method_invocation" && p.child_by_field_name("object").is_some() {
            names.push(method_name(p, src));
            up = p.parent();
        } else {
            break;
        }
    }
    from_assert_that
        && !names.iter().any(|n| {
            matches!(
                *n,
                b"isNotEmpty"
                    | b"hasSize"
                    | b"hasSizeGreaterThan"
                    | b"hasSizeBetween"
                    | b"isNotNull"
            )
        })
}

pub(super) fn literal_kind(node: Node) -> Option<&'static str> {
    match node.kind() {
        "string_literal" => Some("string"),
        "decimal_integer_literal" | "hex_integer_literal" | "decimal_floating_point_literal" => {
            Some("number")
        }
        "true" | "false" => Some("bool"),
        "character_literal" => Some("char"),
        _ => None,
    }
}

fn asserts_across_literal_kinds(call: Node, _: &[u8]) -> bool {
    let args = call_arguments(call);
    let pair = match args.len() {
        2 => Some((args[0], args[1])),
        3 if args[0].kind() == "string_literal" => Some((args[1], args[2])),
        3 => Some((args[0], args[1])),
        _ => None,
    };
    pair.is_some_and(|(a, b)| match (literal_kind(a), literal_kind(b)) {
        (Some(x), Some(y)) => x != y,
        _ => false,
    })
}

fn mocks_never_initialized(class: Node, src: &[u8]) -> bool {
    let has_mock = class_members(class).iter().any(|m| {
        m.kind() == "field_declaration"
            && [&b"Mock"[..], b"InjectMocks", b"Spy", b"Captor"]
                .iter()
                .any(|a| has_annotation(*m, a, src))
    });
    if !has_mock {
        return false;
    }
    let whole = text(class, src);
    let outer = class.parent().map_or(&b""[..], |p| text(p, src));
    ![
        &b"MockitoJUnitRunner"[..],
        b"MockitoExtension",
        b"openMocks",
        b"initMocks",
        b"MockitoRule",
        b"MockitoJUnit",
        b"SpringRunner",
        b"SpringExtension",
        b"MockitoTestExecutionListener",
    ]
    .iter()
    .any(|w| count_word(whole, w) > 0 || count_word(outer, w) > 0)
}

fn is_matcher_call(node: Node, src: &[u8]) -> bool {
    node.kind() == "method_invocation" && {
        let m = method_name(node, src);
        m.starts_with(b"any")
            || matches!(
                m,
                b"eq"
                    | b"isA"
                    | b"isNull"
                    | b"notNull"
                    | b"isNotNull"
                    | b"same"
                    | b"argThat"
                    | b"nullable"
                    | b"startsWith"
                    | b"endsWith"
                    | b"contains"
                    | b"matches"
                    | b"refEq"
                    | b"intThat"
                    | b"longThat"
            )
    }
}

fn mixes_matchers_and_values(call: Node, src: &[u8]) -> bool {
    if is_matcher_call(call, src) {
        return false;
    }
    let name = method_name(call, src);
    if name.starts_with(b"assert")
        || matches!(
            name,
            b"when" | b"verify" | b"thenReturn" | b"asList" | b"of"
        )
    {
        return false;
    }
    let args = call_arguments(call);
    let matchers = args.iter().filter(|a| is_matcher_call(**a, src)).count();
    matchers > 0
        && args.iter().any(|a| {
            literal_kind(*a).is_some() || matches!(a.kind(), "null_literal" | "identifier")
        })
}

fn javadoc_documents_nothing(comment: Node, src: &[u8]) -> bool {
    if !text(comment, src).starts_with(b"/**") {
        return false;
    }
    match comment.next_named_sibling() {
        Some(next) => !matches!(
            next.kind(),
            "class_declaration"
                | "interface_declaration"
                | "enum_declaration"
                | "record_declaration"
                | "annotation_type_declaration"
                | "method_declaration"
                | "constructor_declaration"
                | "compact_constructor_declaration"
                | "field_declaration"
                | "constant_declaration"
                | "enum_constant"
                | "package_declaration"
                | "import_declaration"
                | "module_declaration"
                | "annotation_type_element_declaration"
                | "static_initializer"
                | "line_comment"
                | "block_comment"
                | "enum_body_declarations"
        ),
        None => comment.parent().is_some_and(|p| p.kind() == "block"),
    }
}

fn compiles_a_literal_inside_a_method(call: Node, _: &[u8]) -> bool {
    if !call_arguments(call)
        .first()
        .is_some_and(|a| a.kind() == "string_literal")
    {
        return false;
    }
    let mut p = call.parent();
    while let Some(n) = p {
        match n.kind() {
            "field_declaration" | "static_initializer" => return false,
            "method_declaration" | "constructor_declaration" => return true,
            _ => {}
        }
        p = n.parent();
    }
    false
}

fn long_number_without_underscores(literal: Node, src: &[u8]) -> bool {
    let t = text(literal, src);
    let digits = t.iter().filter(|b| b.is_ascii_digit()).count();
    digits >= 6 && !t.contains(&b'_')
}

fn test_name_breaks_convention(method: Node, src: &[u8]) -> bool {
    if !has_annotation(method, b"Test", src)
        && !has_annotation(method, b"ParameterizedTest", src)
        && !has_annotation(method, b"RepeatedTest", src)
    {
        return false;
    }
    let n = name_text(method, src);
    !(n.first().is_some_and(u8::is_ascii_lowercase) && n.iter().all(u8::is_ascii_alphanumeric))
}

fn abstract_class_name_is_wrong(name: Node, src: &[u8]) -> bool {
    let Some(class) = name.parent() else {
        return false;
    };
    let t = text(name, src);
    has_modifier(class, "abstract")
        && !(t.starts_with(b"Abstract") && t.get(8).is_some_and(u8::is_ascii_uppercase))
}

fn abstract_class_has_one_kind(class: Node, _: &[u8]) -> bool {
    if !has_modifier(class, "abstract") {
        return false;
    }
    let methods: Vec<Node> = class_members(class)
        .into_iter()
        .filter(|m| m.kind() == "method_declaration")
        .collect();
    let abstract_count = methods
        .iter()
        .filter(|m| has_modifier(**m, "abstract"))
        .count();
    !methods.is_empty() && (abstract_count == 0 || abstract_count == methods.len())
}

fn public_member_lacks_javadoc<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !has_modifier(node, "public") || has_annotation(node, b"Override", src) {
        return None;
    }
    let documented = node
        .prev_named_sibling()
        .is_some_and(|c| c.kind() == "block_comment" && text(c, src).starts_with(b"/**"));
    (!documented)
        .then(|| node.child_by_field_name("name"))
        .flatten()
}

fn private_field_used_in_one_method<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let members = class_members(class);
    let whole = text(class, src);
    members.iter().find_map(|f| {
        if f.kind() != "field_declaration"
            || !has_modifier(*f, "private")
            || has_modifier(*f, "static")
            || has_modifier(*f, "final")
            || f.child_by_field_name("type").is_none()
        {
            return None;
        }
        let modifiers = f.child(0).filter(|m| m.kind() == "modifiers");
        if modifiers.is_some_and(|m| {
            count_word(text(m, src), b"Autowired") + count_word(text(m, src), b"Inject") > 0
        }) || modifiers.is_some_and(|m| {
            m.named_child_count() > 1 && m.child_count() > 1 && text(m, src).contains(&b'@')
        }) {
            return None;
        }
        let declarator = children_of_kind(*f, "variable_declarator")
            .into_iter()
            .next()?;
        if declarator.child_by_field_name("value").is_some() {
            return None;
        }
        let name = text(declarator.child_by_field_name("name")?, src);
        let users: Vec<&Node> = members
            .iter()
            .filter(|m| {
                matches!(m.kind(), "method_declaration" | "constructor_declaration")
                    && count_word(text(**m, src), name) > 0
            })
            .collect();
        let [user] = users.as_slice() else {
            return None;
        };
        if user.kind() != "method_declaration"
            || count_word(whole, name) != count_word(text(**user, src), name) + 1
        {
            return None;
        }
        let first_use = find_node(user.child_by_field_name("body")?, |n| {
            n.kind() == "identifier" && text(n, src) == name
        })?;
        let assigned = first_use.parent().is_some_and(|p| {
            (p.kind() == "assignment_expression"
                && p.child_by_field_name("left") == Some(first_use)
                && text(p, src)[first_use.end_byte() - p.start_byte()..]
                    .trim_ascii_start()
                    .starts_with(b"="))
                || (p.kind() == "field_access"
                    && p.parent().is_some_and(|q| {
                        q.kind() == "assignment_expression"
                            && q.child_by_field_name("left") == Some(p)
                    }))
        });
        assigned
            .then(|| declarator.child_by_field_name("name"))
            .flatten()
    })
}

fn method_ignores_the_instance(method: Node, src: &[u8]) -> bool {
    if has_modifier(method, "static")
        || has_modifier(method, "abstract")
        || !(has_modifier(method, "private") || has_modifier(method, "final"))
        || has_annotation(method, b"Override", src)
        || matches!(
            name_text(method, src),
            b"readResolve" | b"writeReplace" | b"readObject" | b"writeObject" | b"readObjectNoData"
        )
    {
        return false;
    }
    let (Some(body), Some(class)) = (method.child_by_field_name("body"), enclosing_class(method))
    else {
        return false;
    };
    if statements(body).is_empty()
        || find_node(body, |n| matches!(n.kind(), "this" | "super")).is_some()
    {
        return false;
    }
    let whole = text(body, src);
    let instance_names: Vec<&[u8]> = class_members(class)
        .iter()
        .flat_map(|m| match m.kind() {
            "field_declaration" if !has_modifier(*m, "static") => declarator_names(*m, src),
            "method_declaration" if !has_modifier(*m, "static") && *m != method => {
                vec![name_text(*m, src)]
            }
            _ => Vec::new(),
        })
        .collect();
    !instance_names.iter().any(|n| count_word(whole, n) > 0)
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
    fn nesting_and_returns() {
        let src = "class A {\n void f() {\n  if (a) {\n   if (b) {\n    if (c) {\n     if (d) { g(); }\n    }\n   }\n  }\n  if (a) { } else if (b) { } else if (c) { } else if (d) { h(); }\n }\n}";
        assert_eq!(flagged("java/nesting-depth", src), [6]);
    }

    #[test]
    fn floats_and_formats() {
        let src = "class A {\n void f(double d, int i) {\n  boolean a = d == 1.5;\n  boolean b = i == 2;\n  d++;\n  i++;\n  String.format(\"%s %d\", d);\n  String.format(\"%s %d\", d, i);\n  String.format(\"%%s\");\n  System.out.printf(\"%n\");\n }\n}";
        assert_eq!(flagged("java/floating-point-equality", src), [3]);
        assert_eq!(flagged("java/float-increment", src), [5]);
    }

    #[test]
    fn serialization_and_classes() {
        let src = "class A implements Serializable {\n class B implements Serializable {}\n static class C implements Serializable { private static final long serialVersionUID = 1L; }\n}\nabstract class Base {}\nclass U { static void f() {} }\nclass V { void g() { new U(); } }";
        assert_eq!(flagged("java/serial-version-uid", src), [1, 2]);
        assert_eq!(flagged("java/abstract-class-name", src), [5]);
        assert_eq!(flagged("java/utility-class-instantiated", src), [7]);
    }

    #[test]
    fn test_libraries() {
        let src = "class A {\n @Mock B b;\n @Test void t() {\n  assertThat(l).allMatch(x -> true);\n  assertThat(l).isNotEmpty().allMatch(x -> true);\n  verify(m).call(any(), 5);\n  verify(m).call(any(), eq(5));\n  assertEquals(1, \"a\");\n  assertEquals(\"msg\", 1, 2);\n  assertThrows(X.class, () -> { a(); b(); });\n }\n}";
        assert_eq!(flagged("java/mockito-annotations-uninitialized", src), [1]);
        assert_eq!(flagged("java/assertj-empty-collection", src), [4]);
        assert_eq!(flagged("java/mockito-matchers-mixed", src), [6]);
        assert_eq!(flagged("java/assert-incompatible-types", src), [8]);
        assert_eq!(flagged("java/assert-multiple-calls", src), [10]);
    }

    #[test]
    fn javadoc_and_private_fields() {
        let src = "/** Header. */\npackage p;\nclass A {\n private int tmp;\n private int shared;\n /** Doc. */\n void a() {\n  /** stray */\n  tmp = 1;\n  g(tmp);\n }\n void b() { shared = 2; }\n void c() { g(shared); }\n}";
        assert_eq!(flagged("java/dangling-javadoc", src), [8]);
        assert_eq!(flagged("java/private-field-used-locally", src), [4]);
    }
}
