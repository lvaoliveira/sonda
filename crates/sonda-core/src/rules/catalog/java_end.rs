//! The last Java rules that a single file's syntax can answer (ADR-0007,
//! batch 17): XML parser hardening, entity binding, concurrency and
//! serialization checks against the classes declared in the same file,
//! newer-Java idioms, test and mobile checks. Each one stays silent when
//! the answer depends on code it cannot see.

use super::java_bugs::{has_annotation, has_modifier, modifiers_of, statements};
use super::java_extra::{class_members, declared_type, name_text, type_text};
use super::java_final::{base_type, root_of};
use super::java_flow::{
    enclosing_method, find_declared_type, has_method, nodes_in, superclass_name,
};
use super::java_last::literal_kind;
use super::java_security::{call_arguments, find_node, method_name, text};
use super::java_smells::{children_of_kind, count_word, declarator_names, enclosing_class};
use super::*;

/// This module's rules that are off unless `rules.enabled` lists them
/// (see `catalog::OFF_BY_DEFAULT`).
pub(super) static OFF_BY_DEFAULT: &[&str] = &[
    // Batch 17: outside SonarQube's default profile, or tied to a Java version.
    "java/lazy-static-unsynchronized",
    "java/float-arithmetic",
    "java/redundant-nullability",
    "java/collect-redundant",
    "java/enum-equals",
    "java/random-test-data",
    "java/location-manager-updates",
    "java/bluetooth-low-latency",
    "java/private-fields-no-constructor",
    "java/declared-too-early",
    "java/class-could-be-record",
];

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "java/object-stream-append",
        name: "Files opened in append mode should not be used with ObjectOutputStream",
        description: "Each append writes a new stream header, which readers choke on.",
        message: "Rewrite the file, or use a different format.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S2689")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(object_creation_expression type: (type_identifier) @t (#eq? @t "ObjectOutputStream") arguments: (argument_list (object_creation_expression type: (type_identifier) @i (#eq? @i "FileOutputStream") arguments: (argument_list (_) (true))))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { ObjectOutputStream o = new ObjectOutputStream(new FileOutputStream(\"f\", true)); } }",
            good: "class A { void f() { ObjectOutputStream o = new ObjectOutputStream(new FileOutputStream(\"f\")); } }",
        }),
    },
    Rule {
        id: "java/non-null-set-to-null",
        name: "@NonNull values should not be set to null",
        description: "The annotation promises a value, and null breaks it.",
        message: "Assign a value.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2637")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(local_variable_declaration (modifiers (marker_annotation name: (identifier) @a (#any-of? @a "NonNull" "Nonnull" "NotNull"))) declarator: (variable_declarator value: (null_literal))) @match
(field_declaration (modifiers (marker_annotation name: (identifier) @a (#any-of? @a "NonNull" "Nonnull" "NotNull"))) declarator: (variable_declarator value: (null_literal))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "@NonNull String s = null;",
            good: "@NonNull String s = \"a\";",
        }),
    },
    Rule {
        id: "java/xml-parser-xxe",
        name: "XML parsers should not be vulnerable to XXE attacks",
        description: "An XML parser with external entities lets a document read local files.",
        message: "Disable DTDs and external entities.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 15,
        sonar: &[exact("S2755")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "newInstance" "newFactory" "createXMLReader" "newDefaultInstance")) @match"#,
            filter: Some(Keep(xml_factory_is_unprotected)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { DocumentBuilderFactory f = DocumentBuilderFactory.newInstance(); } }",
            good: "class A { void f() { DocumentBuilderFactory f = DocumentBuilderFactory.newInstance(); f.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true); } }",
        }),
    },
    Rule {
        id: "java/xml-xinclude",
        name: "XML parsers should not allow inclusion of arbitrary files",
        description: "XInclude pulls files into the document.",
        message: "Don't enable XInclude.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 10,
        sonar: &[exact("S6373")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "setXIncludeAware") arguments: (argument_list (true))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { f.setXIncludeAware(true); } }",
            good: "class A { void f() { f.setXIncludeAware(false); } }",
        }),
    },
    Rule {
        id: "java/xml-entity-expansion",
        name: "XML parsers should not be vulnerable to Denial of Service attacks",
        description: "Turning off secure processing lets a small document expand into gigabytes.",
        message: "Keep secure processing on.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S6376")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "setFeature") arguments: (argument_list (_) @a (false))) @match"#,
            filter: Some(Keep(turns_secure_processing_off)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, false); } }",
            good: "class A { void f() { f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true); } }",
        }),
    },
    Rule {
        id: "java/xml-signature-validation",
        name: "XML signatures should be validated securely",
        description: "Without secure validation a crafted signature can exhaust memory or read files.",
        message: "Leave org.jcp.xml.dsig.secureValidation on.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S6377")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "setProperty") arguments: (argument_list (string_literal) @k (false))) @match"#,
            filter: Some(Keep(disables_secure_validation)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { ctx.setProperty(\"org.jcp.xml.dsig.secureValidation\", false); } }",
            good: "class A { void f() { ctx.setProperty(\"org.jcp.xml.dsig.secureValidation\", true); } }",
        }),
    },
    Rule {
        id: "java/entity-bound-to-request",
        name: "Database Operations should not be vulnerable to mass assignment",
        description: "Binding a request straight onto an entity lets a caller set any field.",
        message: "Bind a dedicated DTO.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 15,
        sonar: &[exact("S4684")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Find(request_is_bound_to_an_entity)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "@Entity class User { String role; }\nclass A { @PostMapping(\"/u\") void save(@RequestBody User u) {} }",
            good: "class UserDto { String name; }\nclass A { @PostMapping(\"/u\") void save(@RequestBody UserDto u) {} }",
        }),
    },
    Rule {
        id: "java/ejb-thread",
        name: "JEE applications should not use threads or synchronization",
        description: "The container manages threads and concurrency for its components.",
        message: "Use the container's facilities.",
        category: Bug,
        severity: Major,
        effort_minutes: 15,
        sonar: &[exact("S2654")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Find(ejb_creates_threads)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "@Stateless class A { void f() { new Thread(r).start(); } }",
            good: "@Stateless class A { void f() { executor.submit(r); } }",
        }),
    },
    Rule {
        id: "java/serialization-parent-constructor",
        name: "The non-serializable super class of a Serializable class should have a no-argument constructor",
        description: "Deserialization calls it to build the non-serializable part.",
        message: "Add a no-argument constructor.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S2055")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Keep(parent_lacks_a_no_argument_constructor)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class P { P(int x) {} }\nclass C extends P implements Serializable { C() { super(1); } }",
            good: "class P { P() {} P(int x) {} }\nclass C extends P implements Serializable { C() { super(1); } }",
        }),
    },
    Rule {
        id: "java/write-non-serializable",
        name: "writeObject argument must implement Serializable",
        description: "ObjectOutputStream throws NotSerializableException at runtime.",
        message: "Make the class Serializable.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2118")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "writeObject") arguments: (argument_list (object_creation_expression) @c)) @match"#,
            filter: Some(Keep(writes_a_non_serializable_class)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class P {}\nclass A { void f(ObjectOutputStream o) { o.writeObject(new P()); } }",
            good: "class P implements Serializable {}\nclass A { void f(ObjectOutputStream o) { o.writeObject(new P()); } }",
        }),
    },
    Rule {
        id: "java/runtime-annotation-check",
        name: "Reflection should not be used to check non-runtime annotations",
        description: "An annotation without RUNTIME retention is invisible to reflection.",
        message: "Add @Retention(RUNTIME).",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2109")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "isAnnotationPresent" "getAnnotation")) @match"#,
            filter: Some(Keep(checks_a_source_retention_annotation)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "@interface Marker {}\nclass A { boolean f(Class<?> c) { return c.isAnnotationPresent(Marker.class); } }",
            good: "@Retention(RetentionPolicy.RUNTIME) @interface Marker {}\nclass A { boolean f(Class<?> c) { return c.isAnnotationPresent(Marker.class); } }",
        }),
    },
    Rule {
        id: "java/transaction-modes-differ",
        name: "Methods should not call same-class methods with incompatible @Transactional values",
        description: "A call inside the class bypasses the proxy, so the second annotation is ignored.",
        message: "Move the method to another bean.",
        category: Bug,
        severity: Major,
        effort_minutes: 15,
        sonar: &[exact("S2229")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation) @match"#,
            filter: Some(Keep(calls_a_method_with_another_transaction)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "@Service class A { @Transactional void f() { g(); } @Transactional(propagation = Propagation.REQUIRES_NEW) void g() {} }",
            good: "@Service class A { @Transactional void f() { g(); } @Transactional void g() {} }",
        }),
    },
    Rule {
        id: "java/arguments-in-wrong-order",
        name: "Parameters should be passed in the correct order",
        description: "Passing a, b to a method declared (b, a) swaps their meaning.",
        message: "Swap the arguments.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2234")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation) @match"#,
            filter: Some(Keep(arguments_swap_the_parameters)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void m(int width, int height) {} void f(int width, int height) { m(height, width); } }",
            good: "class A { void m(int width, int height) {} void f(int width, int height) { m(width, height); } }",
        }),
    },
    Rule {
        id: "java/static-init-uses-subclass",
        name: "Classes should not access their own subclasses during class initialization",
        description: "The subclass's initializer runs before the parent's finishes.",
        message: "Move the instance out of the static initializer.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S2390")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(field_declaration) @match"#,
            filter: Some(Keep(static_field_creates_a_subclass)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class P { static final P DEFAULT = new C(); }\nclass C extends P {}",
            good: "class P { static P make() { return new C(); } }\nclass C extends P {}",
        }),
    },
    Rule {
        id: "java/lazy-static-unsynchronized",
        name: "Lazy initialization of static fields should be synchronized",
        description: "Two threads can both see null and both initialize.",
        message: "Synchronize the method.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S2444")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Find(lazy_static_init_is_unsynchronized)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { static Object inst; static Object get() { if (inst == null) { inst = new Object(); } return inst; } }",
            good: "class A { static Object inst; static synchronized Object get() { if (inst == null) { inst = new Object(); } return inst; } }",
        }),
    },
    Rule {
        id: "java/double-checked-publication",
        name: "Assignment of lazy-initialized members should be the last step with double-checked locking",
        description: "Other threads can see the half-built object.",
        message: "Assign it last.",
        category: Bug,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S3064")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(synchronized_statement) @match"#,
            filter: Some(Find(publishes_before_initializing)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { Foo inst; Foo get() { if (inst == null) { synchronized (this) { if (inst == null) { inst = new Foo(); inst.init(); } } } return inst; } }",
            good: "class A { Foo inst; Foo get() { if (inst == null) { synchronized (this) { if (inst == null) { Foo f = new Foo(); f.init(); inst = f; } } } return inst; } }",
        }),
    },
    Rule {
        id: "java/wait-under-several-locks",
        name: "wait should not be called when multiple locks are held",
        description: "wait releases only one lock, so the others stay held and can deadlock.",
        message: "Don't nest the locks.",
        category: Bug,
        severity: Major,
        effort_minutes: 15,
        sonar: &[exact("S3046")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "wait")) @match"#,
            filter: Some(Keep(waits_inside_nested_synchronized)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() throws Exception { synchronized (a) { synchronized (b) { b.wait(); } } } }",
            good: "class A { void f() throws Exception { synchronized (b) { b.wait(); } } }",
        }),
    },
    Rule {
        id: "java/write-object-only-synchronized",
        name: "writeObject should not be the only synchronized code in a class",
        description: "State written under a lock that nothing else takes is not protected.",
        message: "Synchronize the other accessors, or drop it.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3042")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Keep(only_write_object_is_synchronized)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A implements Serializable { private synchronized void writeObject(ObjectOutputStream o) {} void g() {} }",
            good: "class A implements Serializable { private synchronized void writeObject(ObjectOutputStream o) {} synchronized void g() {} }",
        }),
    },
    Rule {
        id: "java/visible-for-testing-used",
        name: "Class members annotated with @VisibleForTesting should not be accessed from production code",
        description: "The annotation says the member is public only for tests.",
        message: "Use a production API.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5803")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation) @match"#,
            filter: Some(Keep(calls_visible_for_testing_member)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class B { @VisibleForTesting void hook() {} }\nclass A { void f(B b) { b.hook(); } }",
            good: "class B { void hook() {} }\nclass A { void f(B b) { b.hook(); } }",
        }),
    },
    Rule {
        id: "java/collection-call-type",
        name: "Inappropriate Collection calls should not be made",
        description: "Asking a List<String> whether it contains an int is always false.",
        message: "Pass the element type.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2175")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "contains" "remove" "indexOf")) @match"#,
            filter: Some(Keep(argument_cannot_be_an_element)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { boolean f(List<String> l) { return l.contains(1); } }",
            good: "class A { boolean f(List<String> l) { return l.contains(\"a\"); } }",
        }),
    },
    Rule {
        id: "java/for-each-narrowing",
        name: "An iteration on a Collection should be performed on the type handled by the Collection",
        description: "The loop variable is cast on every pass and fails when the type is wrong.",
        message: "Declare the element type.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S4838")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(enhanced_for_statement) @match"#,
            filter: Some(Keep(loop_variable_narrows_the_elements)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(List<Object> l) { for (String s : l) { g(s); } } }",
            good: "class A { void f(List<String> l) { for (String s : l) { g(s); } } }",
        }),
    },
    Rule {
        id: "java/primitive-array-stream",
        name: "Arrays.stream should be used for primitive arrays",
        description: "Stream.of(intArray) gives a stream of one array.",
        message: "Use Arrays.stream or IntStream.of.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S3631")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) @o name: (identifier) @n (#eq? @o "Stream") (#eq? @n "of")) @match"#,
            filter: Some(Keep(passes_a_primitive_array)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { Object f(int[] a) { return Stream.of(a); } }",
            good: "class A { Object f(int[] a) { return Arrays.stream(a); } }",
        }),
    },
    Rule {
        id: "java/float-arithmetic",
        name: "Math should not be performed on floats",
        description: "float has about 7 digits, so sums lose precision quickly.",
        message: "Use double.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2164")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(binary_expression operator: ["+" "-" "*" "/"]) @match"#,
            filter: Some(Keep(operand_is_a_float)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { float f(float a, float b) { return a + b; } }",
            good: "class A { double f(double a, double b) { return a + b; } }",
        }),
    },
    Rule {
        id: "java/hash-capacity",
        name: "Hash-based collections with known capacity should be initialized with the proper related size",
        description: "new HashMap<>(n) resizes before holding n entries, because the load factor is 0.75.",
        message: "Use HashMap.newHashMap(n).",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6485")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(object_creation_expression type: (generic_type (type_identifier) @t (#any-of? @t "HashMap" "HashSet" "LinkedHashMap" "LinkedHashSet")) arguments: (argument_list (method_invocation name: (identifier) @n (#eq? @n "size")))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Map<String, String> m = new HashMap<>(list.size()); } }",
            good: "class A { void f() { Map<String, String> m = HashMap.newHashMap(list.size()); } }",
        }),
    },
    Rule {
        id: "java/class-coupling",
        name: "Classes should not depend on an excessive number of classes",
        description: "A class that touches dozens of types does too much.",
        message: "Split the class.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 60,
        sonar: &[exact("S6539"), exact("S1200")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Keep(depends_on_many_types)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { B1 a1; B2 a2; B3 a3; B4 a4; B5 a5; B6 a6; B7 a7; B8 a8; B9 a9; B10 a10; B11 a11; B12 a12; B13 a13; B14 a14; B15 a15; B16 a16; B17 a17; B18 a18; B19 a19; B20 a20; B21 a21; }",
            good: "class A { B1 a1; }",
        }),
    },
    Rule {
        id: "java/redundant-nullability",
        name: "Redundant nullability annotations should be removed",
        description: "A primitive can't be null.",
        message: "Remove the annotation.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S6665")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(formal_parameter) @match
(field_declaration) @match"#,
            filter: Some(Keep(annotates_a_primitive_with_nullability)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(@Nullable int x) {} }",
            good: "class A { void f(int x) {} }",
        }),
    },
    Rule {
        id: "java/collect-redundant",
        name: "Stream.collect calls should not be redundant",
        description: "A dedicated terminal operation does the same.",
        message: "Use count(), min() or max().",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S4266")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "collect") arguments: (argument_list (method_invocation object: (identifier) @c name: (identifier) @m (#eq? @c "Collectors") (#any-of? @m "counting" "minBy" "maxBy" "mapping" "filtering")))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { long n = stream.collect(Collectors.counting()); } }",
            good: "class A { void f() { long n = stream.count(); } }",
        }),
    },
    Rule {
        id: "java/file-delete",
        name: "java.nio.Files#delete should be preferred",
        description: "File.delete() returns false on failure instead of saying why.",
        message: "Use Files.delete.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S4042")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "delete") arguments: (argument_list)) @match"#,
            filter: Some(Keep(deletes_a_file_object)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(File file) { file.delete(); } }",
            good: "class A { void f(Path p) throws IOException { Files.delete(p); } }",
        }),
    },
    Rule {
        id: "java/hex-of-byte",
        name: "Integer.toHexString should not be used to build hexadecimal strings",
        description: "A negative byte prints as ffffff80, and a small one loses its leading zero.",
        message: "Use String.format(\"%02x\") or HexFormat.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S4425")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) @o name: (identifier) @n (#eq? @o "Integer") (#eq? @n "toHexString")) @match"#,
            filter: Some(Keep(formats_a_byte)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { String f(byte b) { return Integer.toHexString(b); } }",
            good: "class A { String f(byte b) { return String.format(\"%02x\", b); } }",
        }),
    },
    Rule {
        id: "java/enum-equals",
        name: "Enum values should be compared with ==",
        description: "equals on an enum is the same check, slower and null-unsafe on one side.",
        message: "Use ==.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S4551")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "equals") arguments: (argument_list (field_access object: (identifier) @e))) @match"#,
            filter: Some(Keep(compares_an_enum_with_equals)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "enum Color { RED }\nclass A { boolean f(Color c) { return c.equals(Color.RED); } }",
            good: "enum Color { RED }\nclass A { boolean f(Color c) { return c == Color.RED; } }",
        }),
    },
    Rule {
        id: "java/text-block-escapes",
        name: "Escape sequences should not be used in text blocks",
        description: "A text block can hold the line break and the quote as they are.",
        message: "Remove the escape.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S5665")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(string_literal) @match"#,
            filter: Some(Keep(text_block_has_escapes)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { String s = \"\"\"\n a\\nb\n \"\"\"; }",
            good: "class A { String s = \"\"\"\n a\n b\n \"\"\"; }",
        }),
    },
    Rule {
        id: "java/text-block-indent",
        name: "Whitespace for text block indent should be consistent",
        description: "Mixed tabs and spaces change the stripped indent unpredictably.",
        message: "Use one kind of whitespace.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S5664")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(string_literal) @match"#,
            filter: Some(Keep(text_block_mixes_indent)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { String s = \"\"\"\n	a\n  b\n  \"\"\"; }",
            good: "class A { String s = \"\"\"\n  a\n  b\n  \"\"\"; }",
        }),
    },
    Rule {
        id: "java/switch-rule-break",
        name: "Switch arrow labels should not use redundant keywords",
        description: "An arrow case doesn't fall through, so break is redundant.",
        message: "Remove it.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S6205")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(switch_rule (block) @match)"#,
            filter: Some(Keep(block_ends_with_break)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(int x) { switch (x) { case 1 -> { g(); break; } default -> h(); } } }",
            good: "class A { void f(int x) { switch (x) { case 1 -> { g(); } default -> h(); } } }",
        }),
    },
    Rule {
        id: "java/readln-boilerplate",
        name: "Prefer IO.readln() over BufferedReader boilerplate",
        description: "Java 25's IO class reads a line without the wrappers.",
        message: "Use IO.readln().",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S8450")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(object_creation_expression type: (type_identifier) @t (#eq? @t "BufferedReader") arguments: (argument_list (object_creation_expression type: (type_identifier) @i (#eq? @i "InputStreamReader") arguments: (argument_list (field_access object: (identifier) @o field: (identifier) @f (#eq? @o "System") (#eq? @f "in")))))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { BufferedReader r = new BufferedReader(new InputStreamReader(System.in)); } }",
            good: "class A { void f() { String line = IO.readln(); } }",
        }),
    },
    Rule {
        id: "java/scoped-value-not-stable",
        name: "ScopedValue instances should be assigned to a stable reference",
        description: "A mutable field lets the identity of the key change.",
        message: "Make it static final.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S8465")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(field_declaration declarator: (variable_declarator value: (method_invocation object: (identifier) @o name: (identifier) @n (#eq? @o "ScopedValue") (#eq? @n "newInstance")))) @match"#,
            filter: Some(Keep(field_is_not_static_final)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { ScopedValue<String> v = ScopedValue.newInstance(); }",
            good: "class A { static final ScopedValue<String> V = ScopedValue.newInstance(); }",
        }),
    },
    Rule {
        id: "java/duration-between-local",
        name: "Time zone-aware types should be used to compute durations",
        description: "A LocalDateTime difference ignores daylight-saving changes.",
        message: "Use ZonedDateTime or Instant.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S8700")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) @o name: (identifier) @n (#eq? @o "Duration") (#eq? @n "between")) @match"#,
            filter: Some(Keep(subtracts_local_date_times)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { Duration f(LocalDateTime a, LocalDateTime b) { return Duration.between(a, b); } }",
            good: "class A { Duration f(Instant a, Instant b) { return Duration.between(a, b); } }",
        }),
    },
    Rule {
        id: "java/system-default-zone",
        name: "Conversions between local and timezone-aware types should use explicit timezone handling",
        description: "The default zone differs between machines.",
        message: "Name the zone.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S8220")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) @o name: (identifier) @n (#eq? @o "ZoneId") (#eq? @n "systemDefault")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { ZoneId z = ZoneId.systemDefault(); } }",
            good: "class A { void f() { ZoneId z = ZoneId.of(\"UTC\"); } }",
        }),
    },
    Rule {
        id: "java/junit-rule-field",
        name: "JUnit rules should be used",
        description: "TemporaryFolder and similar need @Rule to be set up.",
        message: "Add @Rule.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2924")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(field_declaration type: (type_identifier) @t (#any-of? @t "TemporaryFolder" "ExpectedException" "TestName" "Timeout" "ErrorCollector")) @match"#,
            filter: Some(Keep(rule_field_lacks_rule_annotation)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { TemporaryFolder folder = new TemporaryFolder(); }",
            good: "class A { @Rule TemporaryFolder folder = new TemporaryFolder(); }",
        }),
    },
    Rule {
        id: "java/random-test-data",
        name: "Tests should use fixed data instead of randomized data",
        description: "A test that fails on a random value can't be reproduced.",
        message: "Use a fixed value or a seeded generator.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S5977")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) @o name: (identifier) @n (#eq? @o "Math") (#eq? @n "random")) @match
(object_creation_expression type: (type_identifier) @t (#eq? @t "Random") arguments: (argument_list) @a) @match"#,
            filter: Some(Keep(is_inside_a_test)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { @Test void t() { double d = Math.random(); } }",
            good: "class A { @Test void t() { double d = 0.5; } }",
        }),
    },
    Rule {
        id: "java/assertj-empty-consumer",
        name: "AssertJ assertions with Consumer arguments should contain assertion inside consumers",
        description: "A consumer with no assertion passes whatever the value is.",
        message: "Assert inside the consumer.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6103")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "satisfies" "allSatisfy" "anySatisfy" "noneSatisfy" "hasValueSatisfying") arguments: (argument_list (lambda_expression) @l)) @match"#,
            filter: Some(Keep(consumer_asserts_nothing)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void t() { assertThat(x).satisfies(v -> v.size()); } }",
            good: "class A { void t() { assertThat(x).satisfies(v -> assertThat(v).isNotEmpty()); } }",
        }),
    },
    Rule {
        id: "java/exception-handler-status",
        name: "Set appropriate Status Codes on HTTP responses",
        description: "An @ExceptionHandler that returns a body answers 200 unless told otherwise.",
        message: "Add @ResponseStatus or return a ResponseEntity.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6863")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Keep(handler_sends_ok_for_an_error)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { @ExceptionHandler(Exception.class) String handle(Exception e) { return \"error\"; } }",
            good: "class A { @ExceptionHandler(Exception.class) @ResponseStatus(HttpStatus.BAD_REQUEST) String handle(Exception e) { return \"error\"; } }",
        }),
    },
    Rule {
        id: "java/lambda-handler-client",
        name: "Reusable resources should be initialized at construction time of Lambda functions",
        description: "A client built per invocation wastes the warm start.",
        message: "Create it in the constructor or a static field.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6243")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration name: (identifier) @n (#eq? @n "handleRequest")) @match"#,
            filter: Some(Find(handler_builds_a_client)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A implements RequestHandler<String, String> { public String handleRequest(String in, Context c) { S3Client s = S3Client.builder().build(); return in; } }",
            good: "class A implements RequestHandler<String, String> { private final S3Client s = S3Client.builder().build(); public String handleRequest(String in, Context c) { return in; } }",
        }),
    },
    Rule {
        id: "java/lambda-handler-invoke",
        name: "Lambdas should not invoke other lambdas synchronously",
        description: "The caller pays for the callee's whole run time.",
        message: "Invoke asynchronously, or use a queue.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S6246")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration name: (identifier) @n (#eq? @n "handleRequest")) @match"#,
            filter: Some(Find(handler_invokes_lambda_synchronously)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A implements RequestHandler<String, String> { public String handleRequest(String in, Context c) { lambdaClient.invoke(req); return in; } }",
            good: "class A implements RequestHandler<String, String> { public String handleRequest(String in, Context c) { return in; } }",
        }),
    },
    Rule {
        id: "java/consumer-builder",
        name: "Consumer Builders should be used",
        description: "The SDK builds the request for you when you pass a lambda.",
        message: "Use the Consumer overload.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6244")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation arguments: (argument_list (method_invocation name: (identifier) @b (#eq? @b "build")) @arg)) @match"#,
            filter: Some(Keep(passes_a_built_request_to_a_client)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { s3Client.getObject(GetObjectRequest.builder().bucket(\"b\").key(\"k\").build()); } }",
            good: "class A { void f() { s3Client.getObject(r -> r.bucket(\"b\").key(\"k\")); } }",
        }),
    },
    Rule {
        id: "java/sensor-listener-leak",
        name: "Proper Sensor Resource Management",
        description: "A registered listener keeps the sensor on until it is unregistered.",
        message: "Unregister it, usually in onPause.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6889")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Find(sensor_listener_never_unregistered)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { sensorManager.registerListener(l, s, 0); } }",
            good: "class A { void f() { sensorManager.registerListener(l, s, 0); } void g() { sensorManager.unregisterListener(l); } }",
        }),
    },
    Rule {
        id: "java/location-manager-updates",
        name: "Use Fused Location to optimize battery power",
        description: "LocationManager polls providers one by one.",
        message: "Use FusedLocationProviderClient.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S6914")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "requestLocationUpdates")) @match"#,
            filter: Some(Keep(receiver_is_a_location_manager)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { locationManager.requestLocationUpdates(\"gps\", 0, 0, l); } }",
            good: "class A { void f() { fusedClient.requestLocationUpdates(req, cb, looper); } }",
        }),
    },
    Rule {
        id: "java/bluetooth-low-latency",
        name: "Bluetooth should be configured to use low power",
        description: "Low-latency scanning drains the battery.",
        message: "Use SCAN_MODE_LOW_POWER.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6926")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(field_access field: (identifier) @f (#eq? @f "SCAN_MODE_LOW_LATENCY")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { int m = ScanSettings.SCAN_MODE_LOW_LATENCY; } }",
            good: "class A { void f() { int m = ScanSettings.SCAN_MODE_LOW_POWER; } }",
        }),
    },
    Rule {
        id: "java/prepared-constant-in-loop",
        name: "Constant parameters in a PreparedStatement should not be set more than once",
        description: "A parameter that doesn't change can be set before the loop.",
        message: "Set it once.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6909")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#match? @n "^set(String|Int|Long|Boolean|Double)$")) @match"#,
            filter: Some(Keep(sets_a_constant_in_a_loop)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { for (int i = 0; i < 3; i++) { ps.setString(1, \"x\"); } } }",
            good: "class A { void f() { ps.setString(1, \"x\"); for (int i = 0; i < 3; i++) { ps.setInt(2, i); } } }",
        }),
    },
    Rule {
        id: "java/reverse-index-loop",
        name: "Reverse iteration should utilize reversed view",
        description: "Java 21's reversed() says what the loop does.",
        message: "Use list.reversed().",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6876")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(for_statement) @match"#,
            filter: Some(Keep(counts_down_through_a_list)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(List<String> l) { for (int i = l.size() - 1; i >= 0; i--) { g(l.get(i)); } } }",
            good: "class A { void f(List<String> l) { for (String s : l.reversed()) { g(s); } } }",
        }),
    },
    Rule {
        id: "java/virtual-thread-settings",
        name: "setDaemon, setPriority and getThreadGroup should not be invoked on virtual threads",
        description: "Virtual threads are always daemon, with a fixed priority and group.",
        message: "Remove the call.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6901")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "setDaemon" "setPriority" "getThreadGroup")) @match"#,
            filter: Some(Keep(receiver_is_a_virtual_thread)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Thread.ofVirtual().unstarted(r).setDaemon(true); } }",
            good: "class A { void f() { Thread.ofVirtual().start(r); } }",
        }),
    },
    Rule {
        id: "java/private-fields-no-constructor",
        name: "Classes and enums with private members should have a constructor",
        description: "A class that only has defaults for its private state is probably missing its setup.",
        message: "Add a constructor.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S1258")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Keep(private_fields_without_constructor)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { private int n; }",
            good: "class A { private int n; A(int n) { this.n = n; } }",
        }),
    },
    Rule {
        id: "java/declared-too-early",
        name: "Variables should not be declared before they are relevant",
        description: "A variable declared far from its first use is hard to follow.",
        message: "Declare it where it is used.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S1941")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(block) @match"#,
            filter: Some(Find(declaration_far_from_use)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { int x = 1; a(); b(); c(); d(); g(x); } }",
            good: "class A { void f() { a(); b(); c(); d(); int x = 1; g(x); } }",
        }),
    },
    Rule {
        id: "java/record-constructor-redundant",
        name: "Redundant constructors and methods should be avoided in records",
        description: "The compiler generates the canonical constructor.",
        message: "Remove it.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6207")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(record_declaration) @match"#,
            filter: Some(Find(record_declares_trivial_constructor)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "record R(int x) { R(int x) { this.x = x; } }",
            good: "record R(int x) { }",
        }),
    },
    Rule {
        id: "java/class-could-be-record",
        name: "Records should be used instead of ordinary classes when representing immutable data structures",
        description: "A record states the intent and writes the boilerplate.",
        message: "Use a record.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 10,
        sonar: &[exact("S6206")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Keep(is_an_immutable_data_class)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class P { private final int x; P(int x) { this.x = x; } int getX() { return x; } }",
            good: "record P(int x) { }",
        }),
    },
];

// ---------------------------------------------------- filters

const LOOPS: &[&str] = &[
    "for_statement",
    "enhanced_for_statement",
    "while_statement",
    "do_statement",
];

fn chain_names<'s>(call: Node, src: &'s [u8]) -> Vec<&'s [u8]> {
    let mut names = Vec::new();
    let mut cur = Some(call);
    while let Some(c) = cur.filter(|c| c.kind() == "method_invocation") {
        names.push(method_name(c, src));
        cur = c.child_by_field_name("object");
    }
    names
}

fn is_in_a_loop(node: Node) -> bool {
    let mut p = node.parent();
    while let Some(n) = p {
        if LOOPS.contains(&n.kind()) {
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

fn is_primitive_type(kind: &str) -> bool {
    matches!(
        kind,
        "integral_type" | "floating_point_type" | "boolean_type"
    )
}

fn annotation_text<'s>(declaration: Node, name: &[u8], src: &'s [u8]) -> Option<&'s [u8]> {
    let mods = modifiers_of(declaration)?;
    let mut cursor = mods.walk();
    mods.children(&mut cursor)
        .find(|a| {
            matches!(a.kind(), "marker_annotation" | "annotation")
                && a.child_by_field_name("name")
                    .is_some_and(|n| text(n, src) == name)
        })
        .map(|a| text(a, src))
}

// ---- XML and security

fn xml_factory_is_unprotected(call: Node, src: &[u8]) -> bool {
    const FACTORIES: &[&[u8]] = &[
        b"DocumentBuilderFactory",
        b"SAXParserFactory",
        b"TransformerFactory",
        b"SchemaFactory",
        b"XMLInputFactory",
        b"XMLReaderFactory",
        b"SAXTransformerFactory",
    ];
    if !call
        .child_by_field_name("object")
        .is_some_and(|o| FACTORIES.contains(&text(o, src)))
    {
        return false;
    }
    let scope = enclosing_class(call).unwrap_or(root_of(call));
    let whole = text(scope, src);
    ![
        "disallow-doctype-decl",
        "FEATURE_SECURE_PROCESSING",
        "ACCESS_EXTERNAL_DTD",
        "ACCESS_EXTERNAL_STYLESHEET",
        "ACCESS_EXTERNAL_SCHEMA",
        "IS_SUPPORTING_EXTERNAL_ENTITIES",
        "SUPPORT_DTD",
        "external-general-entities",
        "setExpandEntityReferences",
    ]
    .iter()
    .any(|w| count_word(whole, w.as_bytes()) > 0)
}

fn turns_secure_processing_off(call: Node, src: &[u8]) -> bool {
    call_arguments(call).first().is_some_and(|a| {
        let t = text(*a, src);
        count_word(t, b"FEATURE_SECURE_PROCESSING") > 0
            || t.windows(17).any(|w| w == b"secure-processing")
    })
}

fn disables_secure_validation(call: Node, src: &[u8]) -> bool {
    call_arguments(call)
        .first()
        .is_some_and(|a| count_word(text(*a, src), b"secureValidation") > 0)
}

fn request_is_bound_to_an_entity<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    const MAPPINGS: &[&[u8]] = &[
        b"GetMapping",
        b"PostMapping",
        b"PutMapping",
        b"PatchMapping",
        b"DeleteMapping",
        b"RequestMapping",
    ];
    if !MAPPINGS.iter().any(|m| has_annotation(method, m, src)) {
        return None;
    }
    let root = root_of(method);
    method
        .child_by_field_name("parameters")?
        .named_children(&mut method.walk())
        .find(|p| {
            p.kind() == "formal_parameter"
                && (has_annotation(*p, b"RequestBody", src)
                    || has_annotation(*p, b"ModelAttribute", src))
                && p.child_by_field_name("type").is_some_and(|t| {
                    find_declared_type(root, base_type(text(t, src)), src)
                        .is_some_and(|c| has_annotation(c, b"Entity", src))
                })
        })
}

// ---- concurrency and serialization

fn ejb_creates_threads<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    const EJB: &[&[u8]] = &[b"Stateless", b"Stateful", b"Singleton", b"MessageDriven"];
    if !EJB.iter().any(|a| has_annotation(class, a, src)) {
        return None;
    }
    find_node(class, |n| {
        (n.kind() == "object_creation_expression"
            && n.child_by_field_name("type")
                .is_some_and(|t| text(t, src) == b"Thread"))
            || n.kind() == "synchronized_statement"
            || (n.kind() == "method_declaration" && has_modifier(n, "synchronized"))
    })
}

fn parent_lacks_a_no_argument_constructor(class: Node, src: &[u8]) -> bool {
    let serializable = |c: Node| {
        c.child_by_field_name("interfaces")
            .is_some_and(|i| count_word(text(i, src), b"Serializable") > 0)
    };
    if !serializable(class) {
        return false;
    }
    let Some(parent) =
        superclass_name(class, src).and_then(|n| find_declared_type(root_of(class), n, src))
    else {
        return false;
    };
    if serializable(parent) {
        return false;
    }
    let ctors: Vec<Node> = class_members(parent)
        .into_iter()
        .filter(|m| m.kind() == "constructor_declaration")
        .collect();
    !ctors.is_empty()
        && !ctors.iter().any(|c| {
            !has_modifier(*c, "private")
                && c.child_by_field_name("parameters")
                    .is_none_or(|p| p.named_child_count() == 0)
        })
}

fn is_non_serializable_file_class(created: Node, src: &[u8]) -> bool {
    let Some(t) = created.child_by_field_name("type") else {
        return false;
    };
    find_declared_type(root_of(created), base_type(text(t, src)), src).is_some_and(|c| {
        c.kind() == "class_declaration"
            && c.child_by_field_name("superclass").is_none()
            && c.child_by_field_name("interfaces")
                .is_none_or(|i| count_word(text(i, src), b"Serializable") == 0)
    })
}

fn writes_a_non_serializable_class(call: Node, src: &[u8]) -> bool {
    call_arguments(call).first().is_some_and(|c| {
        c.kind() == "object_creation_expression" && is_non_serializable_file_class(*c, src)
    })
}

fn checks_a_source_retention_annotation(call: Node, src: &[u8]) -> bool {
    let Some(arg) = call_arguments(call)
        .into_iter()
        .next()
        .filter(|a| a.kind() == "class_literal")
    else {
        return false;
    };
    let t = text(arg, src);
    let name = t.strip_suffix(b".class").unwrap_or(t);
    find_node(root_of(call), |n| {
        n.kind() == "annotation_type_declaration"
            && name_text(n, src) == name
            && modifiers_of(n).is_none_or(|m| count_word(text(m, src), b"RUNTIME") == 0)
    })
    .is_some()
}

fn calls_a_method_with_another_transaction(call: Node, src: &[u8]) -> bool {
    if call.child_by_field_name("object").is_some() {
        return false;
    }
    let (Some(caller), Some(class)) = (enclosing_method(call), enclosing_class(call)) else {
        return false;
    };
    let Some(from) = annotation_text(caller, b"Transactional", src) else {
        return false;
    };
    has_method(class, method_name(call, src), src)
        .iter()
        .any(|m| {
            *m != caller && annotation_text(*m, b"Transactional", src).is_some_and(|to| to != from)
        })
}

fn arguments_swap_the_parameters(call: Node, src: &[u8]) -> bool {
    if call.child_by_field_name("object").is_some() {
        return false;
    }
    let Some(class) = enclosing_class(call) else {
        return false;
    };
    let args = call_arguments(call);
    if args.len() < 2 || args.iter().any(|a| a.kind() != "identifier") {
        return false;
    }
    let names: Vec<&[u8]> = args.iter().map(|a| text(*a, src)).collect();
    let methods = has_method(class, method_name(call, src), src);
    let [method] = methods.as_slice() else {
        return false;
    };
    let params: Vec<&[u8]> = method
        .child_by_field_name("parameters")
        .map(|p| {
            p.named_children(&mut p.walk())
                .filter_map(|x| x.child_by_field_name("name").map(|n| text(n, src)))
                .collect()
        })
        .unwrap_or_default();
    if params.len() != names.len() || params == names {
        return false;
    }
    // m(a, b) || m(b, a) is a deliberately symmetric use
    if enclosing_method(call).is_some_and(|m| {
        nodes_in(m, &[], |n| {
            n.kind() == "method_invocation"
                && method_name(n, src) == method_name(call, src)
                && n != call
                && n.child_by_field_name("object").is_none()
        })
        .iter()
        .any(|o| {
            call_arguments(*o)
                .iter()
                .map(|a| text(*a, src))
                .eq(params.iter().copied())
        })
    }) {
        return false;
    }
    let mut a = names.clone();
    let mut b = params.clone();
    a.sort();
    b.sort();
    a == b
}

fn static_field_creates_a_subclass(field: Node, src: &[u8]) -> bool {
    if !has_modifier(field, "static") {
        return false;
    }
    let Some(class) = enclosing_class(field) else {
        return false;
    };
    let owner = name_text(class, src);
    children_of_kind(field, "variable_declarator")
        .iter()
        .any(|d| {
            d.child_by_field_name("value")
                .filter(|v| v.kind() == "object_creation_expression")
                .and_then(|v| v.child_by_field_name("type"))
                .is_some_and(|t| {
                    find_declared_type(root_of(field), base_type(text(t, src)), src)
                        .is_some_and(|sub| superclass_name(sub, src) == Some(owner))
                })
        })
}

fn lazy_static_init_is_unsynchronized<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !has_modifier(method, "static") || has_modifier(method, "synchronized") {
        return None;
    }
    let class = enclosing_class(method)?;
    let statics: Vec<&[u8]> = class_members(class)
        .iter()
        .filter(|m| {
            m.kind() == "field_declaration"
                && has_modifier(**m, "static")
                && !has_modifier(**m, "final")
        })
        .flat_map(|m| declarator_names(*m, src))
        .collect();
    let body = method.child_by_field_name("body")?;
    if find_node(body, |n| n.kind() == "synchronized_statement").is_some() {
        return None;
    }
    find_node(body, |n| {
        n.kind() == "if_statement"
            && n.child_by_field_name("condition").is_some_and(|c| {
                let t = text(c, src);
                statics.iter().any(|s| {
                    let mut needle = s.to_vec();
                    needle.extend_from_slice(b" == null");
                    t.windows(needle.len()).any(|w| w == needle.as_slice())
                })
            })
            && n.child_by_field_name("consequence").is_some_and(|c| {
                find_node(c, |a| {
                    a.kind() == "assignment_expression"
                        && a.child_by_field_name("left")
                            .is_some_and(|l| statics.contains(&text(l, src)))
                })
                .is_some()
            })
    })
}

fn publishes_before_initializing<'t>(sync: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let assignment = find_node(sync, |n| {
        n.kind() == "assignment_expression"
            && n.child_by_field_name("left")
                .is_some_and(|l| l.kind() == "identifier")
            && n.child_by_field_name("right")
                .is_some_and(|r| r.kind() == "object_creation_expression")
            && n.parent()
                .is_some_and(|p| p.kind() == "expression_statement")
    })?;
    let statement = assignment.parent()?;
    let name = text(assignment.child_by_field_name("left")?, src);
    let next = statement.next_named_sibling()?;
    (count_word(text(next, src), name) > 0).then_some(assignment)
}

fn waits_inside_nested_synchronized(call: Node, _: &[u8]) -> bool {
    let mut depth = 0;
    let mut p = call.parent();
    while let Some(n) = p {
        match n.kind() {
            "synchronized_statement" => depth += 1,
            "method_declaration" | "constructor_declaration" | "lambda_expression" => break,
            _ => {}
        }
        p = n.parent();
    }
    depth >= 2
}

fn only_write_object_is_synchronized(class: Node, src: &[u8]) -> bool {
    let methods: Vec<Node> = class_members(class)
        .into_iter()
        .filter(|m| m.kind() == "method_declaration" && has_modifier(*m, "synchronized"))
        .collect();
    methods.len() == 1
        && name_text(methods[0], src) == b"writeObject"
        && find_node(class, |n| n.kind() == "synchronized_statement").is_none()
}

fn calls_visible_for_testing_member(call: Node, src: &[u8]) -> bool {
    let name = method_name(call, src);
    let Some(caller_class) = enclosing_class(call) else {
        return false;
    };
    if enclosing_method(call).is_some_and(|m| has_annotation(m, b"Test", src))
        || name_text(caller_class, src).ends_with(b"Test")
        || name_text(caller_class, src).ends_with(b"Tests")
    {
        return false;
    }
    find_node(root_of(call), |n| {
        n.kind() == "method_declaration"
            && name_text(n, src) == name
            && has_annotation(n, b"VisibleForTesting", src)
            && enclosing_class(n).is_some_and(|c| c != caller_class)
    })
    .is_some()
}

// ---- collections and types

fn type_argument(t: &[u8]) -> Option<&[u8]> {
    let start = t.iter().position(|&b| b == b'<')?;
    let end = t.iter().rposition(|&b| b == b'>')?;
    (end > start + 1).then(|| &t[start + 1..end])
}

fn argument_cannot_be_an_element(call: Node, src: &[u8]) -> bool {
    let Some(object) = call
        .child_by_field_name("object")
        .filter(|o| o.kind() == "identifier")
    else {
        return false;
    };
    let declared = type_text(declared_type(call, text(object, src), src), src);
    if !matches!(
        base_type(declared),
        b"List" | b"Set" | b"Collection" | b"ArrayList" | b"HashSet"
    ) {
        return false;
    }
    let Some(element) = type_argument(declared) else {
        return false;
    };
    let Some(arg) = call_arguments(call).into_iter().next() else {
        return false;
    };
    // List.remove(int) removes by index
    if method_name(call, src) == b"remove" && matches!(base_type(declared), b"List" | b"ArrayList")
    {
        return false;
    }
    matches!(
        (element, literal_kind(arg)),
        (b"String", Some("number" | "bool")) | (b"Integer" | b"Long" | b"Double", Some("string"))
    )
}

fn loop_variable_narrows_the_elements(for_statement: Node, src: &[u8]) -> bool {
    let (Some(t), Some(value)) = (
        for_statement.child_by_field_name("type"),
        for_statement
            .child_by_field_name("value")
            .filter(|v| v.kind() == "identifier"),
    ) else {
        return false;
    };
    let declared = type_text(declared_type(for_statement, text(value, src), src), src);
    type_argument(declared) == Some(b"Object") && !matches!(text(t, src), b"Object" | b"var")
}

fn passes_a_primitive_array(call: Node, src: &[u8]) -> bool {
    let args = call_arguments(call);
    let [only] = args.as_slice() else {
        return false;
    };
    if only.kind() != "identifier" {
        return false;
    }
    let t = type_text(declared_type(call, text(*only, src), src), src);
    [
        &b"int["[..],
        b"long[",
        b"double[",
        b"char[",
        b"byte[",
        b"short[",
        b"float[",
        b"boolean[",
    ]
    .iter()
    .any(|p| t.starts_with(p))
}

fn operand_is_a_float(binary: Node, src: &[u8]) -> bool {
    let is_float = |n: Option<Node>| {
        n.is_some_and(|n| match n.kind() {
            "decimal_floating_point_literal" => {
                matches!(text(n, src).last(), Some(b'f' | b'F'))
            }
            "identifier" => matches!(
                type_text(declared_type(binary, text(n, src), src), src),
                b"float" | b"Float"
            ),
            _ => false,
        })
    };
    is_float(binary.child_by_field_name("left")) || is_float(binary.child_by_field_name("right"))
}

fn depends_on_many_types(class: Node, src: &[u8]) -> bool {
    const TRIVIAL: &[&[u8]] = &[
        b"String",
        b"Object",
        b"Integer",
        b"Long",
        b"Boolean",
        b"Double",
        b"Float",
        b"Short",
        b"Byte",
        b"Character",
        b"Void",
        b"Override",
        b"Deprecated",
        b"FunctionalInterface",
    ];
    let own = name_text(class, src);
    let mut seen: Vec<&[u8]> = Vec::new();
    for n in nodes_in(class, &[], |n| n.kind() == "type_identifier") {
        let t = text(n, src);
        if t != own && !TRIVIAL.contains(&t) && !seen.contains(&t) {
            seen.push(t);
        }
    }
    seen.len() > 20
}

fn annotates_a_primitive_with_nullability(declaration: Node, src: &[u8]) -> bool {
    let annotated = [
        &b"Nullable"[..],
        b"NonNull",
        b"Nonnull",
        b"NotNull",
        b"CheckForNull",
    ]
    .iter()
    .any(|a| has_annotation(declaration, a, src));
    annotated
        && declaration
            .child_by_field_name("type")
            .is_some_and(|t| is_primitive_type(t.kind()))
}

fn formats_a_byte(call: Node, src: &[u8]) -> bool {
    call_arguments(call)
        .first()
        .is_some_and(|a| match a.kind() {
            "identifier" => type_text(declared_type(call, text(*a, src), src), src) == b"byte",
            "cast_expression" => a
                .child_by_field_name("type")
                .is_some_and(|t| text(t, src) == b"byte"),
            _ => false,
        })
}

fn deletes_a_file_object(call: Node, src: &[u8]) -> bool {
    call.child_by_field_name("object").is_some_and(|o| {
        o.kind() == "identifier"
            && type_text(declared_type(call, text(o, src), src), src) == b"File"
    })
}

fn compares_an_enum_with_equals(call: Node, src: &[u8]) -> bool {
    let Some(arg) = call_arguments(call)
        .into_iter()
        .next()
        .filter(|a| a.kind() == "field_access")
    else {
        return false;
    };
    arg.child_by_field_name("object").is_some_and(|o| {
        find_declared_type(root_of(call), text(o, src), src)
            .is_some_and(|d| d.kind() == "enum_declaration")
    })
}

// ---- text blocks, switches, constructors, newer Java

fn text_block_has_escapes(literal: Node, src: &[u8]) -> bool {
    let t = text(literal, src);
    t.starts_with(b"\"\"\"")
        && (t.windows(2).any(|w| w == b"\\n") || t.windows(2).any(|w| w == b"\\\""))
}

fn text_block_mixes_indent(literal: Node, src: &[u8]) -> bool {
    let t = text(literal, src);
    if !t.starts_with(b"\"\"\"") {
        return false;
    }
    let lines: Vec<&[u8]> = t.split(|&b| b == b'\n').skip(1).collect();
    lines.iter().any(|l| l.first() == Some(&b'\t'))
        && lines.iter().any(|l| l.first() == Some(&b' '))
}

fn block_ends_with_break(block: Node, _: &[u8]) -> bool {
    statements(block)
        .last()
        .is_some_and(|s| s.kind() == "break_statement")
}

fn field_is_not_static_final(field: Node, _: &[u8]) -> bool {
    !(has_modifier(field, "static") && has_modifier(field, "final"))
}

fn subtracts_local_date_times(call: Node, src: &[u8]) -> bool {
    let args = call_arguments(call);
    args.len() == 2
        && args.iter().all(|a| {
            a.kind() == "identifier"
                && type_text(declared_type(call, text(*a, src), src), src) == b"LocalDateTime"
        })
}

// ---- tests, Spring, AWS, mobile

fn rule_field_lacks_rule_annotation(field: Node, src: &[u8]) -> bool {
    !has_annotation(field, b"Rule", src) && !has_annotation(field, b"ClassRule", src)
}

fn is_inside_a_test(node: Node, src: &[u8]) -> bool {
    if node.kind() == "object_creation_expression" && !call_arguments(node).is_empty() {
        return false;
    }
    enclosing_method(node).is_some_and(|m| has_annotation(m, b"Test", src))
}

fn consumer_asserts_nothing(call: Node, src: &[u8]) -> bool {
    call_arguments(call).iter().any(|a| {
        a.kind() == "lambda_expression" && {
            let t = text(*a, src);
            !t.windows(6).any(|w| w.eq_ignore_ascii_case(b"assert"))
                && ![
                    &b"isEqualTo"[..],
                    b"isTrue",
                    b"isFalse",
                    b"isNotNull",
                    b"isNull",
                    b"hasSize",
                    b"isEmpty",
                    b"isNotEmpty",
                    b"contains",
                    b"matches",
                    b"startsWith",
                    b"endsWith",
                ]
                .iter()
                .any(|w| count_word(t, w) > 0)
        }
    })
}

fn handler_sends_ok_for_an_error(method: Node, src: &[u8]) -> bool {
    let returns = method
        .child_by_field_name("type")
        .map_or(&b""[..], |t| text(t, src));
    has_annotation(method, b"ExceptionHandler", src)
        && !has_annotation(method, b"ResponseStatus", src)
        && returns != b"void"
        && !returns.starts_with(b"ResponseEntity")
}

fn handler_builds_a_client<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_node(method.child_by_field_name("body")?, |n| {
        (n.kind() == "object_creation_expression"
            && n.child_by_field_name("type")
                .is_some_and(|t| text(t, src).ends_with(b"Client")))
            || (n.kind() == "method_invocation" && {
                let names = chain_names(n, src);
                (names.first() == Some(&&b"build"[..]) && names.contains(&&b"builder"[..]))
                    || method_name(n, src) == b"defaultClient"
            })
    })
}

fn handler_invokes_lambda_synchronously<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_node(method.child_by_field_name("body")?, |n| {
        n.kind() == "method_invocation"
            && method_name(n, src) == b"invoke"
            && n.child_by_field_name("object").is_some_and(|o| {
                super::java_security::contains_ignoring_case(text(o, src), b"lambda")
            })
            && count_word(text(n, src), b"Event") == 0
    })
}

fn passes_a_built_request_to_a_client(call: Node, src: &[u8]) -> bool {
    let receiver = call
        .child_by_field_name("object")
        .map_or(&b""[..], |o| text(o, src));
    super::java_security::contains_ignoring_case(receiver, b"client")
        && call_arguments(call).first().is_some_and(|a| {
            a.kind() == "method_invocation" && chain_names(*a, src).contains(&&b"builder"[..])
        })
}

fn sensor_listener_never_unregistered<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if count_word(text(class, src), b"unregisterListener") > 0 {
        return None;
    }
    find_node(class, |n| {
        n.kind() == "method_invocation" && method_name(n, src) == b"registerListener"
    })
}

fn receiver_is_a_location_manager(call: Node, src: &[u8]) -> bool {
    call.child_by_field_name("object").is_some_and(|o| {
        super::java_security::contains_ignoring_case(text(o, src), b"locationmanager")
    })
}

fn sets_a_constant_in_a_loop(call: Node, _: &[u8]) -> bool {
    let args = call_arguments(call);
    args.len() == 2 && literal_kind(args[1]).is_some() && is_in_a_loop(call)
}

fn counts_down_through_a_list(for_statement: Node, src: &[u8]) -> bool {
    let (Some(init), Some(body)) = (
        for_statement.child_by_field_name("init"),
        for_statement.child_by_field_name("body"),
    ) else {
        return false;
    };
    let Some(declarator) = children_of_kind(init, "variable_declarator")
        .into_iter()
        .next()
    else {
        return false;
    };
    let (Some(var), Some(value)) = (
        declarator.child_by_field_name("name"),
        declarator.child_by_field_name("value"),
    ) else {
        return false;
    };
    let vt = text(value, src);
    let Some(list_end) = vt.windows(8).position(|w| w == b".size() ") else {
        return false;
    };
    let list = &vt[..list_end];
    let mut cursor = for_statement.walk();
    let descending = for_statement
        .children_by_field_name("update", &mut cursor)
        .any(|u| text(u, src).ends_with(b"--") || text(u, src).starts_with(b"--"));
    let mut get = list.to_vec();
    get.extend_from_slice(b".get(");
    get.extend_from_slice(text(var, src));
    get.push(b')');
    descending
        && text(body, src)
            .windows(get.len())
            .any(|w| w == get.as_slice())
}

fn receiver_is_a_virtual_thread(call: Node, src: &[u8]) -> bool {
    chain_names(call, src).iter().any(|n| {
        matches!(
            *n,
            b"ofVirtual" | b"startVirtualThread" | b"newVirtualThread"
        )
    })
}

// ---- conventions

fn private_fields_without_constructor(class: Node, src: &[u8]) -> bool {
    if has_modifier(class, "abstract")
        || modifiers_of(class).is_some_and(|m| text(m, src).contains(&b'@'))
    {
        return false;
    }
    let members = class_members(class);
    !members
        .iter()
        .any(|m| m.kind() == "constructor_declaration")
        && members.iter().any(|m| {
            m.kind() == "field_declaration"
                && has_modifier(*m, "private")
                && !has_modifier(*m, "static")
                && !has_modifier(*m, "final")
                && children_of_kind(*m, "variable_declarator")
                    .iter()
                    .all(|d| d.child_by_field_name("value").is_none())
        })
}

fn declaration_far_from_use<'t>(block: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let items = statements(block);
    items.iter().enumerate().find_map(|(i, s)| {
        if s.kind() != "local_variable_declaration" {
            return None;
        }
        let name = declarator_names(*s, src).into_iter().next()?;
        let first = items[i + 1..]
            .iter()
            .position(|later| count_word(text(*later, src), name) > 0)?;
        (first > 3).then_some(*s)
    })
}

fn record_declares_trivial_constructor<'t>(record: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let components = record
        .child_by_field_name("parameters")?
        .named_child_count();
    class_members(record).into_iter().find(|m| {
        m.kind() == "constructor_declaration"
            && m.child_by_field_name("parameters")
                .is_some_and(|p| p.named_child_count() == components)
            && m.child_by_field_name("body").is_some_and(|b| {
                let items = statements(b);
                items.len() == components
                    && items.iter().all(|s| {
                        s.named_child(0).is_some_and(|a| {
                            a.kind() == "assignment_expression"
                                && a.child_by_field_name("left")
                                    .is_some_and(|l| l.kind() == "field_access")
                                && a.child_by_field_name("right").is_some_and(|r| {
                                    r.kind() == "identifier"
                                        && a.child_by_field_name("left")
                                            .and_then(|l| l.child_by_field_name("field"))
                                            .is_some_and(|f| text(f, src) == text(r, src))
                                })
                        })
                    })
            })
    })
}

fn is_an_immutable_data_class(class: Node, src: &[u8]) -> bool {
    if class.child_by_field_name("superclass").is_some()
        || class.child_by_field_name("interfaces").is_some()
        || has_modifier(class, "abstract")
        || modifiers_of(class).is_some_and(|m| text(m, src).contains(&b'@'))
    {
        return false;
    }
    let members = class_members(class);
    let fields: Vec<&[u8]> = members
        .iter()
        .filter(|m| m.kind() == "field_declaration")
        .flat_map(|m| declarator_names(*m, src))
        .collect();
    if fields.is_empty()
        || !members
            .iter()
            .filter(|m| m.kind() == "field_declaration")
            .all(|m| {
                has_modifier(*m, "private")
                    && has_modifier(*m, "final")
                    && !has_modifier(*m, "static")
            })
    {
        return false;
    }
    let ctors: Vec<&Node> = members
        .iter()
        .filter(|m| m.kind() == "constructor_declaration")
        .collect();
    let [ctor] = ctors.as_slice() else {
        return false;
    };
    let assigned = ctor.child_by_field_name("body").map_or(0, |b| {
        statements(b)
            .iter()
            .filter(|s| {
                s.named_child(0)
                    .is_some_and(|a| a.kind() == "assignment_expression")
            })
            .count()
    });
    assigned == fields.len()
        && members.iter().all(|m| match m.kind() {
            "field_declaration" | "constructor_declaration" => true,
            "method_declaration" => {
                let n = name_text(*m, src);
                let property = n
                    .strip_prefix(b"get")
                    .or_else(|| n.strip_prefix(b"is"))
                    .unwrap_or(n);
                matches!(n, b"equals" | b"hashCode" | b"toString")
                    || fields.iter().any(|f| f.eq_ignore_ascii_case(property))
            }
            _ => false,
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
    fn xml_and_entities() {
        let src = "class A {\n void f() {\n  DocumentBuilderFactory a = DocumentBuilderFactory.newInstance();\n }\n}\nclass B {\n void f() {\n  DocumentBuilderFactory a = DocumentBuilderFactory.newInstance();\n  a.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n }\n}";
        assert_eq!(flagged("java/xml-parser-xxe", src), [3]);
    }

    #[test]
    fn concurrency() {
        let src = "class A {\n static Object inst;\n static Object lazy() {\n  if (inst == null) { inst = new Object(); }\n  return inst;\n }\n static synchronized Object safe() {\n  if (inst == null) { inst = new Object(); }\n  return inst;\n }\n void w() throws Exception {\n  synchronized (a) { synchronized (b) { b.wait(); } }\n  synchronized (c) { c.wait(); }\n }\n}";
        assert_eq!(flagged("java/lazy-static-unsynchronized", src), [4]);
        assert_eq!(flagged("java/wait-under-several-locks", src), [12]);
    }

    #[test]
    fn collections_and_types() {
        let src = "class A {\n void f(List<String> l, List<Object> o, int[] a, byte b, File file) {\n  l.contains(1);\n  l.contains(\"x\");\n  for (String s : o) { g(s); }\n  Stream.of(a);\n  Integer.toHexString(b);\n  file.delete();\n }\n}";
        assert_eq!(flagged("java/collection-call-type", src), [3]);
        assert_eq!(flagged("java/for-each-narrowing", src), [5]);
        assert_eq!(flagged("java/primitive-array-stream", src), [6]);
        assert_eq!(flagged("java/hex-of-byte", src), [7]);
        assert_eq!(flagged("java/file-delete", src), [8]);
    }

    #[test]
    fn classes_and_records() {
        let src = "class P {\n private final int x;\n P(int x) { this.x = x; }\n int getX() { return x; }\n}\nrecord R(int a) {\n R(int a) { this.a = a; }\n}\nclass S {\n private int n;\n}";
        assert_eq!(flagged("java/class-could-be-record", src), [1]);
        assert_eq!(flagged("java/record-constructor-redundant", src), [7]);
        assert_eq!(flagged("java/private-fields-no-constructor", src), [9]);
    }

    #[test]
    fn loops_and_swaps() {
        let src = "class A {\n void m(int width, int height) {}\n void f(int width, int height, List<String> l) {\n  m(height, width);\n  for (int i = l.size() - 1; i >= 0; i--) { g(l.get(i)); }\n  for (int i = 0; i < 3; i++) { ps.setString(1, \"x\"); }\n }\n}";
        assert_eq!(flagged("java/arguments-in-wrong-order", src), [4]);
        assert_eq!(flagged("java/reverse-index-loop", src), [5]);
        assert_eq!(flagged("java/prepared-constant-in-loop", src), [6]);
    }
}
