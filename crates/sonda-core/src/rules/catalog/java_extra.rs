//! Java rules, part 4 (ADR-0007, batch 11): declarations, exceptions,
//! concurrency, collections and a few conventions. Queries stay cheap on
//! deep trees: see `js_modern.rs`; whole-class checks are `Find` filters.

use super::java_bugs::{has_annotation, has_modifier};
use super::java_security::{call_arguments, find_node, method_name, text};
use super::java_smells::{
    children_of_kind, count_word, declarator_names, enclosing_class, members,
};
use super::*;

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "java/instanceof-in-catch",
        name: "Exception types should not be tested using instanceof in catch blocks",
        description: "Separate catch clauses state the same thing and let the compiler check them.",
        message: "Use one catch clause per type.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1193")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(catch_clause) @match"#,
            filter: Some(Keep(catch_tests_exception_type)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { try { f(); } catch (Exception e) { if (e instanceof IOException) { g(); } } } }",
            good: "class A { void f() { try { f(); } catch (IOException e) { g(); } } }",
        }),
    },
    Rule {
        id: "java/catch-drops-cause",
        name: "Exception handlers should preserve the original exceptions",
        description: "A new exception thrown from a handler loses the stack trace unless it carries the cause.",
        message: "Pass the caught exception as the cause.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1166")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(catch_clause) @match"#,
            filter: Some(Find(rethrows_without_cause)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { try { f(); } catch (IOException e) { throw new IllegalStateException(\"failed\"); } } }",
            good: "class A { void f() { try { f(); } catch (IOException e) { throw new IllegalStateException(\"failed\", e); } } }",
        }),
    },
    Rule {
        id: "java/error-extended",
        name: "java.lang.Error should not be extended",
        description: "Error is for the JVM; application failures are exceptions.",
        message: "Extend Exception or RuntimeException.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S1194")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration superclass: (superclass (type_identifier) @s (#eq? @s "Error"))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class MyError extends Error {}",
            good: "class MyException extends RuntimeException {}",
        }),
    },
    Rule {
        id: "java/throw-null-pointer",
        name: "NullPointerException should not be explicitly thrown",
        description: "It signals a bug the JVM found; callers can't tell yours from theirs.",
        message: "Throw IllegalArgumentException or use Objects.requireNonNull.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1695")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(throw_statement (object_creation_expression type: (type_identifier) @t (#eq? @t "NullPointerException"))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { throw new NullPointerException(); } }",
            good: "class A { void f() { Objects.requireNonNull(x); } }",
        }),
    },
    Rule {
        id: "java/catch-null-pointer",
        name: "NullPointerException should not be caught",
        description: "Fix the null instead of hiding the crash.",
        message: "Check for null before the call.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S1696")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(catch_type (type_identifier) @match (#eq? @match "NullPointerException"))"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { try { f(); } catch (NullPointerException e) { g(); } } }",
            good: "class A { void f() { if (x != null) { f(); } } }",
        }),
    },
    Rule {
        id: "java/superfluous-throws",
        name: "Exceptions in throws clauses should not be superfluous",
        description: "Unchecked exceptions need no declaration, and a listed subclass is covered by its parent.",
        message: "Remove it from the throws clause.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S1130")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(throws) @match"#,
            filter: Some(Keep(throws_is_superfluous)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void g() throws IOException, RuntimeException {} }",
            good: "class A { void g() throws IOException {} }",
        }),
    },
    Rule {
        id: "java/future-keyword-name",
        name: "Restricted identifiers should not be used as identifiers",
        description: "var, yield, record and sealed are contextual keywords; reusing them as names breaks on newer Java.",
        message: "Rename it.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6213"), related("S1190")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(local_variable_declaration declarator: (variable_declarator name: (identifier) @match (#any-of? @match "yield" "record" "sealed")))
(formal_parameter name: (identifier) @match (#any-of? @match "yield" "record" "sealed"))"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { int record = 1; } }",
            good: "class A { void f() { int rec = 1; } }",
        }),
    },
    Rule {
        id: "java/clone-without-cloneable",
        name: "Classes that override clone should be Cloneable and call super.clone()",
        description: "Without both, clone() throws or returns an object of the wrong class.",
        message: "Implement Cloneable and call super.clone().",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1182")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration name: (identifier) @n (#eq? @n "clone")) @match"#,
            filter: Some(Keep(clone_breaks_contract)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { public Object clone() { return new A(); } }",
            good: "class A implements Cloneable { public Object clone() throws CloneNotSupportedException { return super.clone(); } }",
        }),
    },
    Rule {
        id: "java/cloneable-without-clone",
        name: "Cloneables should implement clone",
        description: "Object.clone is protected, so a Cloneable class that doesn't expose it can't be cloned by callers.",
        message: "Implement clone().",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2157")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration interfaces: (super_interfaces (type_list (type_identifier) @i (#eq? @i "Cloneable")))) @match"#,
            filter: Some(Keep(class_lacks_clone)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A implements Cloneable {}",
            good: "class A implements Cloneable { public Object clone() { return null; } }",
        }),
    },
    Rule {
        id: "java/url-in-hash",
        name: "URL.hashCode and URL.equals should be avoided",
        description: "Both resolve the host name, which blocks and gives different answers over time.",
        message: "Use URI.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2112")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(generic_type (type_identifier) @c (#any-of? @c "Set" "HashSet" "Map" "HashMap") (type_arguments . (type_identifier) @a (#eq? @a "URL"))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { Set<URL> urls; }",
            good: "class A { Set<URI> urls; }",
        }),
    },
    Rule {
        id: "java/array-to-string",
        name: "hashCode and toString should not be called on array instances",
        description: "They return the identity, not the content.",
        message: "Use Arrays.hashCode or Arrays.toString.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2116")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) name: (identifier) @n (#any-of? @n "hashCode" "toString")) @match"#,
            filter: Some(Keep(call_on_array_variable)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(int[] a) { a.toString(); } }",
            good: "class A { void f(int[] a) { Arrays.toString(a); } }",
        }),
    },
    Rule {
        id: "java/long-bits-int",
        name: "Double.longBitsToDouble should take long as argument",
        description: "An int argument is widened and gives a tiny number, not the bit pattern.",
        message: "Pass a long literal.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2127")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) @o name: (identifier) @n (#eq? @o "Double") (#eq? @n "longBitsToDouble")) @match"#,
            filter: Some(Keep(argument_is_int_literal)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { double d = Double.longBitsToDouble(1); } }",
            good: "class A { void f() { double d = Double.longBitsToDouble(1L); } }",
        }),
    },
    Rule {
        id: "java/parse-by-boxing",
        name: "Parsing should be used to convert Strings to primitives",
        description: "valueOf builds a wrapper object only to unwrap it again.",
        message: "Use parseInt, parseLong and so on.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2130")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (method_invocation name: (identifier) @v (#eq? @v "valueOf")) name: (identifier) @n (#any-of? @n "intValue" "longValue" "doubleValue" "floatValue" "shortValue" "byteValue" "booleanValue")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { int i = Integer.valueOf(s).intValue(); } }",
            good: "class A { void f() { int i = Integer.parseInt(s); } }",
        }),
    },
    Rule {
        id: "java/random-float-as-int",
        name: "Methods of Random that return floating point values should not be used in random integer generation",
        description: "Casting a double to int to get a random integer is biased and slower than nextInt.",
        message: "Use nextInt(bound).",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2140")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(cast_expression type: (integral_type) value: (_) @v) @match"#,
            filter: Some(Keep(casts_random_double)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { int i = (int) (Math.random() * 10); } }",
            good: "class A { void f() { int i = new Random().nextInt(10); } }",
        }),
    },
    Rule {
        id: "java/final-protected",
        name: "final classes should not have protected members",
        description: "Nothing can subclass a final class, so protected means package.",
        message: "Make it private or package-private.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2156")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Find(final_class_protected_member)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "final class A { protected int x; }",
            good: "final class A { private int x; }",
        }),
    },
    Rule {
        id: "java/atomic-equals",
        name: ".equals() should not be used to test the values of Atomic classes",
        description: "Atomic classes compare by identity.",
        message: "Compare get() results.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2204")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) name: (identifier) @n (#eq? @n "equals")) @match"#,
            filter: Some(Keep(equals_on_atomic)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { AtomicInteger a; boolean f(AtomicInteger b) { return a.equals(b); } }",
            good: "class A { AtomicInteger a; boolean f(AtomicInteger b) { return a.get() == b.get(); } }",
        }),
    },
    Rule {
        id: "java/diamond-operator",
        name: "The diamond operator should be used",
        description: "Repeating the type arguments on both sides adds noise.",
        message: "Use <>.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S2293")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(local_variable_declaration type: (generic_type) declarator: (variable_declarator value: (object_creation_expression type: (generic_type (type_arguments (_)))) @match))"#,
            filter: Some(Keep(creation_repeats_type_arguments)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { List<String> l = new ArrayList<String>(); } }",
            good: "class A { void f() { List<String> l = new ArrayList<>(); } }",
        }),
    },
    Rule {
        id: "java/boolean-selector",
        name: "Public methods should not contain selector arguments",
        description: "A boolean flag means the method does two things.",
        message: "Split it into two methods.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 15,
        sonar: &[exact("S2301")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Find(public_method_has_boolean_parameter)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { public void run(boolean fast) { if (fast) { go(); } else { slow(); } } }",
            good: "class A { public void runFast() { go(); } public void runSlow() { slow(); } }",
        }),
    },
    Rule {
        id: "java/delete-on-exit",
        name: "deleteOnExit should not be used",
        description: "It leaks memory for the life of the JVM and does not run on a crash.",
        message: "Delete the file in a finally block.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2308")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "deleteOnExit")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { f.deleteOnExit(); } }",
            good: "class A { void f() { f.delete(); } }",
        }),
    },
    Rule {
        id: "java/empty-file",
        name: "Files should not be empty",
        description: "A file with no declaration is dead weight.",
        message: "Remove it, or add the code.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2309")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(program) @match"#,
            filter: Some(Keep(program_declares_nothing)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "import java.util.List;\n",
            good: "import java.util.List;\nclass A { List<String> l; }\n",
        }),
    },
    Rule {
        id: "java/redundant-modifier",
        name: "Redundant modifiers should not be used",
        description: "The language already implies them.",
        message: "Remove the modifier.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S2333")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(interface_declaration) @match
(class_declaration) @match"#,
            filter: Some(Find(redundant_modifier_in)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "interface A { public void f(); }",
            good: "interface A { void f(); }",
        }),
    },
    Rule {
        id: "java/exposes-internal-state",
        name: "Private mutable members should not be stored or returned directly",
        description: "A caller can change the object's state through the returned reference.",
        message: "Return a copy.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S2384")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Find(returns_private_mutable_field)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { private int[] a; int[] get() { return a; } }",
            good: "class A { private int[] a; int[] get() { return a.clone(); } }",
        }),
    },
    Rule {
        id: "java/field-shadows-parent",
        name: "Child class fields should not shadow parent class fields",
        description: "The same name for two fields invites reading the wrong one.",
        message: "Rename the field.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2387")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(program) @match"#,
            filter: Some(Find(field_shadows_parent_field)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class P { int x; }\nclass C extends P { int x; }",
            good: "class P { int x; }\nclass C extends P { int y; }",
        }),
    },
    Rule {
        id: "java/thread-as-runnable",
        name: "Thread should not be used where a Runnable argument is expected",
        description: "A Thread is a Runnable, but passing one wastes it and invites start() confusion.",
        message: "Pass the Runnable.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2438")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "execute" "submit" "schedule") arguments: (argument_list (object_creation_expression type: (type_identifier) @t (#eq? @t "Thread")))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { executor.submit(new Thread(task)); } }",
            good: "class A { void f() { executor.submit(task); } }",
        }),
    },
    Rule {
        id: "java/synchronize-on-lock",
        name: "Synchronizing on a Lock object should be avoided",
        description: "Lock has its own lock() method; synchronized uses its monitor instead.",
        message: "Call lock() and unlock().",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2442")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(synchronized_statement (parenthesized_expression (identifier) @match))"#,
            filter: Some(Keep(is_lock_variable)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { Lock l; void f() { synchronized (l) { g(); } } }",
            good: "class A { Lock l; void f() { l.lock(); } }",
        }),
    },
    Rule {
        id: "java/synchronize-on-public-field",
        name: "Blocks should be synchronized on private final fields",
        description: "Other code can reassign or lock on a non-private field, breaking mutual exclusion.",
        message: "Lock on a private final field.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2445")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(synchronized_statement (parenthesized_expression (identifier) @match))"#,
            filter: Some(Keep(is_unsafe_lock_field)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { Object lock = new Object(); void f() { synchronized (lock) { g(); } } }",
            good: "class A { private final Object lock = new Object(); void f() { synchronized (lock) { g(); } } }",
        }),
    },
    Rule {
        id: "java/thread-in-constructor",
        name: "Threads should not be started in constructors",
        description: "The new thread can see a half-built object.",
        message: "Start it after construction.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2693")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(constructor_declaration) @match"#,
            filter: Some(Find(constructor_starts_a_thread)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { A() { new Thread(this::run).start(); } }",
            good: "class A { A() {} void begin() { new Thread(this::run).start(); } }",
        }),
    },
    Rule {
        id: "java/instance-writes-static",
        name: "Instance methods should not write to static fields",
        description: "Every instance changes shared state, which is a race.",
        message: "Make the method static or the field an instance field.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S2696")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Find(instance_method_writes_static)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { static int n; void f() { n = 1; } }",
            good: "class A { static int n; static void f() { n = 1; } }",
        }),
    },
    Rule {
        id: "java/literal-assertion",
        name: "Literal boolean values and nulls should not be used in assertions",
        description: "The assertion's result doesn't depend on the code under test.",
        message: "Assert on a real value.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2701")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "assertTrue" "assertFalse" "assertNull" "assertNotNull") arguments: (argument_list . [(true) (false) (null_literal)] @match))"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { assertTrue(true); } }",
            good: "class A { void f() { assertTrue(x > 0); } }",
        }),
    },
    Rule {
        id: "java/getter-setter-sync",
        name: "Getters and setters should be synchronized in pairs",
        description: "Only one side synchronized still allows a stale read or a torn write.",
        message: "Synchronize both.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2886")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Find(accessor_sync_mismatch)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { private int n; public synchronized int getN() { return n; } public void setN(int v) { n = v; } }",
            good: "class A { private int n; public synchronized int getN() { return n; } public synchronized void setN(int v) { n = v; } }",
        }),
    },
    Rule {
        id: "java/unnecessary-semicolon",
        name: "Unnecessary semicolons should be omitted",
        description: "An extra ; after a member or type declaration does nothing.",
        message: "Remove it.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S2959")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_body ";" @match)
(program ";" @match)"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { int x;; }",
            good: "class A { int x; }",
        }),
    },
    Rule {
        id: "java/unicode-escape",
        name: "Escaped Unicode characters should not be used",
        description: "\\u00e9 is harder to read than é.",
        message: "Write the character.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S2973")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(string_literal) @match"#,
            filter: Some(Keep(has_printable_unicode_escape)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { String s = \"\\u00e9\"; } }",
            good: "class A { void f() { String s = \"é\"; } }",
        }),
    },
    Rule {
        id: "java/static-field-updated-in-constructor",
        name: "Static fields should not be updated in constructors",
        description: "Each new instance rewrites state shared by all of them.",
        message: "Update an instance field, or do it in a static method.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S3010")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(constructor_declaration) @match"#,
            filter: Some(Find(constructor_writes_static)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { static int n; A() { n++; } }",
            good: "class A { int n; A() { n++; } }",
        }),
    },
    Rule {
        id: "java/string-builder-empty",
        name: "isEmpty should be used to test for the emptiness of StringBuffers and Builders",
        description: "It states the intent.",
        message: "Use isEmpty().",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S3033")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(binary_expression left: (method_invocation object: (identifier) @o name: (identifier) @n (#eq? @n "length")) operator: "==" right: (decimal_integer_literal) @z (#eq? @z "0")) @match"#,
            filter: Some(Keep(builder_length_compared_to_zero)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { boolean f(StringBuilder sb) { return sb.length() == 0; } }",
            good: "class A { boolean f(StringBuilder sb) { return sb.isEmpty(); } }",
        }),
    },
    Rule {
        id: "java/main-signature",
        name: "main should have the right signature",
        description: "The JVM only launches public static void main(String[]).",
        message: "Fix the signature.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3051")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration name: (identifier) @n (#eq? @n "main")) @match"#,
            filter: Some(Keep(main_signature_is_wrong)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void main(String[] args) {} }",
            good: "class A { public static void main(String[] args) {} }",
        }),
    },
    Rule {
        id: "java/default-field-value",
        name: "Fields should not be initialized to default values",
        description: "The JVM already does it.",
        message: "Remove the initializer.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S3052")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(field_declaration declarator: (variable_declarator value: [(decimal_integer_literal) (decimal_floating_point_literal) (false) (null_literal)] @match))"#,
            filter: Some(Keep(is_default_value_field)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { int n = 0; }",
            good: "class A { int n; }",
        }),
    },
    Rule {
        id: "java/optional-parameter",
        name: "Optional should not be used for parameters",
        description: "It makes callers wrap values, and null is still possible.",
        message: "Use an overload, or a nullable parameter.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3553")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(formal_parameter type: (generic_type (type_identifier) @t (#eq? @t "Optional"))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { void f(Optional<String> s) {} } }",
            good: "class A { void f() { void f(String s) {} } }",
        }),
    },
    Rule {
        id: "java/files-exists",
        name: "Java 8's Files.exists should not be used",
        description: "It is slow and its answer is stale on return.",
        message: "Catch the exception from the operation itself.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S3725")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) @o name: (identifier) @n (#eq? @o "Files") (#any-of? @n "exists" "notExists" "isDirectory" "isRegularFile")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { boolean b = Files.exists(p); } }",
            good: "class A { void f() { byte[] b = Files.readAllBytes(p); } }",
        }),
    },
    Rule {
        id: "java/raw-type",
        name: "Raw types should not be used",
        description: "Without type arguments the compiler can't check the contents.",
        message: "Add the type arguments.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3740")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(local_variable_declaration type: (type_identifier) @match (#any-of? @match "List" "ArrayList" "LinkedList" "Map" "HashMap" "TreeMap" "Set" "HashSet" "TreeSet" "Collection" "Iterator" "Optional" "Comparable" "Class"))
(field_declaration type: (type_identifier) @match (#any-of? @match "List" "ArrayList" "LinkedList" "Map" "HashMap" "TreeMap" "Set" "HashSet" "TreeSet" "Collection" "Iterator" "Optional" "Comparable" "Class"))
(formal_parameter type: (type_identifier) @match (#any-of? @match "List" "ArrayList" "LinkedList" "Map" "HashMap" "TreeMap" "Set" "HashSet" "TreeSet" "Collection" "Iterator" "Optional" "Comparable" "Class"))"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { List l = new ArrayList(); } }",
            good: "class A { void f() { List<String> l = new ArrayList<>(); } }",
        }),
    },
    Rule {
        id: "java/this-escapes-constructor",
        name: "this should not be exposed from constructors",
        description: "Another object sees this before construction finishes.",
        message: "Do it after construction.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3366")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(constructor_declaration) @match"#,
            filter: Some(Find(constructor_passes_this)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { A(Registry r) { r.add(this); } }",
            good: "class A { A() {} }",
        }),
    },
    Rule {
        id: "java/synchronized-collections",
        name: "Synchronized classes Vector, Hashtable, Stack and StringBuffer should not be used",
        description: "They lock every call, and still don't make compound operations safe.",
        message: "Use ArrayList, HashMap, ArrayDeque or StringBuilder.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S1149")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(object_creation_expression type: (type_identifier) @match (#any-of? @match "Vector" "Hashtable" "Stack" "StringBuffer"))
(object_creation_expression type: (generic_type (type_identifier) @match (#any-of? @match "Vector" "Hashtable" "Stack")))"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Vector<String> v = new Vector<>(); } }",
            good: "class A { void f() { List<String> v = new ArrayList<>(); } }",
        }),
    },
    Rule {
        id: "java/public-field",
        name: "Class variable fields should not have public accessibility",
        description: "Callers can change it without the class noticing.",
        message: "Make it private and add accessors.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 10,
        sonar: &[exact("S1104")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(field_declaration) @match"#,
            filter: Some(Keep(is_public_mutable_field)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { public int n; }",
            good: "class A { private int n; }",
        }),
    },
    Rule {
        id: "java/public-static-not-final",
        name: "public static fields should be constant",
        description: "Anyone can reassign it.",
        message: "Make it final.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S1444")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(field_declaration) @match"#,
            filter: Some(Keep(is_public_static_not_final)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { public static int n; }",
            good: "class A { public static final int N = 1; }",
        }),
    },
    Rule {
        id: "java/missing-braces",
        name: "Control structures should use curly braces",
        description: "A one-line body invites the dangling-statement bug.",
        message: "Add braces.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 2,
        sonar: &[exact("S121")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(if_statement consequence: (_) @match)
(while_statement body: (_) @match)
(for_statement body: (_) @match)
(enhanced_for_statement body: (_) @match)"#,
            filter: Some(Keep(body_is_not_a_block)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { if (x) f(); } }",
            good: "class A { void f() { if (x) { f(); } } }",
        }),
    },
    Rule {
        id: "java/if-else-if-without-else",
        name: "if ... else if constructs should end with else clauses",
        description: "The last branch is where the unexpected case lands.",
        message: "Add an else.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S126")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(if_statement alternative: (if_statement)) @match"#,
            filter: Some(Keep(chain_lacks_final_else)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { if (a) { f(); } else if (b) { g(); } } }",
            good: "class A { void f() { if (a) { f(); } else if (b) { g(); } else { h(); } } }",
        }),
    },
    Rule {
        id: "java/literal-suffix-case",
        name: "Literal suffixes should be upper case",
        description: "l looks like 1.",
        message: "Use L, F or D.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S818")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(decimal_integer_literal) @match"#,
            filter: Some(Keep(has_lowercase_suffix)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { long n = 10l; } }",
            good: "class A { void f() { long n = 10L; } }",
        }),
    },
    Rule {
        id: "java/octal-literal",
        name: "Octal values should not be used",
        description: "010 is 8, which surprises readers.",
        message: "Use decimal.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 2,
        sonar: &[exact("S1314")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(octal_integer_literal) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { int n = 010; } }",
            good: "class A { void f() { int n = 8; } }",
        }),
    },
    Rule {
        id: "java/literal-on-the-right",
        name: "String literals should be placed on the left side when checking for equality",
        description: "\"x\".equals(s) can't throw NullPointerException.",
        message: "Put the literal first.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S1132")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) name: (identifier) @n (#eq? @n "equals") arguments: (argument_list (string_literal))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { boolean b = s.equals(\"x\"); } }",
            good: "class A { void f() { boolean b = \"x\".equals(s); } }",
        }),
    },
    Rule {
        id: "java/constructor-calls-overridable",
        name: "Constructors should only call non-overridable methods",
        description: "A subclass override runs before the subclass is constructed.",
        message: "Call a private or final method.",
        category: Bug,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S1699")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(constructor_declaration) @match"#,
            filter: Some(Find(constructor_calls_overridable)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { A() { init(); } void init() {} }",
            good: "class A { A() { init(); } private void init() {} }",
        }),
    },
    Rule {
        id: "java/too-many-fields",
        name: "Classes should not have too many fields",
        description: "A class with dozens of fields has several responsibilities.",
        message: "Split the class.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 60,
        sonar: &[exact("S1820")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Keep(has_too_many_fields)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { int a1; int a2; int a3; int a4; int a5; int a6; int a7; int a8; int a9; int a10; int a11; int a12; int a13; int a14; int a15; int a16; int a17; int a18; int a19; int a20; int a21; }",
            good: "class A { int a1; }",
        }),
    },
    Rule {
        id: "java/nested-switch",
        name: "switch statements and expressions should not be nested",
        description: "Nested switches are hard to read.",
        message: "Extract a method.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 20,
        sonar: &[exact("S1821")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(switch_expression (switch_block (switch_block_statement_group (switch_expression) @match)))
(switch_expression (switch_block (switch_block_statement_group (expression_statement (switch_expression) @match))))"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { switch (a) { case 1: switch (b) { case 2: f(); } } } }",
            good: "class A { void f() { switch (a) { case 1: g(b); } } }",
        }),
    },
    Rule {
        id: "java/redundant-extends-object",
        name: "Extensions and implementations should not be redundant",
        description: "Every class extends Object.",
        message: "Remove the extends clause.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S1939")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration superclass: (superclass (type_identifier) @match (#eq? @match "Object")))"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A extends Object {}",
            good: "class A {}",
        }),
    },
    Rule {
        id: "java/ends-with-else-switch-labels",
        name: "Comma-separated labels should be used in Switch with colon case",
        description: "Empty case groups fall through; one label list says it better.",
        message: "Use `case 1, 2:`.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6208")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(switch_block_statement_group) @match"#,
            filter: Some(Keep(group_has_only_labels)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { switch (x) { case 1: case 2: f(); break; } } }",
            good: "class A { void f() { switch (x) { case 1, 2: f(); break; } } }",
        }),
    },
    Rule {
        id: "java/modulus-equals-one",
        name: "Modulus results should not be checked for direct equality",
        description: "x % 2 == 1 is false for negative odd numbers.",
        message: "Compare with != 0.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2197")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(binary_expression left: (binary_expression operator: "%") operator: "==" right: (decimal_integer_literal) @r (#eq? @r "1")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { boolean odd = n % 2 == 1; } }",
            good: "class A { void f() { boolean odd = n % 2 != 0; } }",
        }),
    },
    Rule {
        id: "java/default-locale",
        name: "String operations should not rely on the default system locale",
        description: "toUpperCase() gives different results in Turkish.",
        message: "Pass Locale.ROOT or the right locale.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S1449")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "toUpperCase" "toLowerCase") arguments: (argument_list) @a) @match"#,
            filter: Some(Keep(has_no_arguments)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { String s = x.toUpperCase(); } }",
            good: "class A { void f() { String s = x.toUpperCase(Locale.ROOT); } }",
        }),
    },
    Rule {
        id: "java/default-charset",
        name: "Classes and methods that rely on the default system encoding should not be used",
        description: "The result changes from machine to machine.",
        message: "Name the charset.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1943")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "getBytes") arguments: (argument_list) @a) @match
(object_creation_expression type: (type_identifier) @t (#any-of? @t "InputStreamReader" "OutputStreamWriter" "FileReader" "FileWriter") arguments: (argument_list . (_) .)) @match"#,
            filter: Some(Keep(relies_on_default_charset)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { byte[] b = s.getBytes(); } }",
            good: "class A { void f() { byte[] b = s.getBytes(StandardCharsets.UTF_8); } }",
        }),
    },
    Rule {
        id: "java/suppress-warnings",
        name: "Track uses of @SuppressWarnings annotations",
        description: "Each one silences a check.",
        message: "Review this suppression.",
        category: CodeSmell,
        severity: Info,
        effort_minutes: 1,
        sonar: &[exact("S1309")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(annotation name: (identifier) @n (#eq? @n "SuppressWarnings")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "@SuppressWarnings(\"unchecked\") class A {}",
            good: "class A {}",
        }),
    },
    Rule {
        id: "java/nopmd-comment",
        name: "Track uses of NOPMD suppression comments",
        description: "Each one silences a check.",
        message: "Review this suppression.",
        category: CodeSmell,
        severity: Info,
        effort_minutes: 1,
        sonar: &[exact("S1310")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(line_comment) @match
(block_comment) @match"#,
            filter: Some(Keep(is_nopmd)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { int x; // NOPMD\n}",
            good: "class A { int x; }",
        }),
    },
    Rule {
        id: "java/checkstyle-off",
        name: "Track uses of CHECKSTYLE:OFF suppression comments",
        description: "Each one silences a check.",
        message: "Review this suppression.",
        category: CodeSmell,
        severity: Info,
        effort_minutes: 1,
        sonar: &[exact("S1315")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(line_comment) @match
(block_comment) @match"#,
            filter: Some(Keep(is_checkstyle_off)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { int x; // CHECKSTYLE:OFF\n}",
            good: "class A { int x; }",
        }),
    },
    Rule {
        id: "java/logger-field",
        name: "Loggers should be private static final and should share a naming convention",
        description: "A logger shared or reassigned is a leak.",
        message: "Make it private static final LOGGER.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S1312")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(field_declaration type: (type_identifier) @t (#any-of? @t "Logger" "Log")) @match"#,
            filter: Some(Keep(logger_is_not_private_static_final)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { Logger log = null; }",
            good: "class A { private static final Logger LOG = null; }",
        }),
    },
    Rule {
        id: "java/eager-fetch",
        name: "Avoid using FetchType.EAGER",
        description: "It loads the whole object graph on every query.",
        message: "Use LAZY and fetch what you need.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S6904")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(field_access object: (identifier) @o field: (identifier) @f (#eq? @o "FetchType") (#eq? @f "EAGER")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { @OneToMany(fetch = FetchType.EAGER) List<B> bs; }",
            good: "class A { @OneToMany(fetch = FetchType.LAZY) List<B> bs; }",
        }),
    },
    Rule {
        id: "java/type-parameter-shadowed",
        name: "Type parameters should not shadow other type parameters",
        description: "The inner T hides the outer T.",
        message: "Rename it.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S4977")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration type_parameters: (type_parameters (type_parameter (type_identifier) @n))) @match"#,
            filter: Some(Keep(shadows_class_type_parameter)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A<T> { <T> void f(T x) {} }",
            good: "class A<T> { <U> void f(U x) {} }",
        }),
    },
    Rule {
        id: "java/final-upper-bound",
        name: "The upper bound of type variables and wildcards should not be final",
        description: "A final bound allows only that type.",
        message: "Use the type directly.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S4968")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(type_parameter (type_bound (type_identifier) @match (#any-of? @match "String" "Integer" "Long" "Double" "Boolean" "Character")))"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A<T extends String> {}",
            good: "class A<T extends CharSequence> {}",
        }),
    },
    Rule {
        id: "java/unused-type-parameter",
        name: "Unused type parameters should be removed",
        description: "A type parameter nothing refers to is noise.",
        message: "Remove it.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2326")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Find(method_has_unused_type_parameter)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { <T> void f() {} }",
            good: "class A { <T> void f(T x) {} }",
        }),
    },
    Rule {
        id: "java/unnecessary-bit-operation",
        name: "Unnecessary bit operations should not be performed",
        description: "x | 0 and x & -1 return x.",
        message: "Remove the operation.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2437")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(binary_expression operator: ["|" "^" "<<" ">>"] right: (decimal_integer_literal) @r (#eq? @r "0")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { int y = x | 0; } }",
            good: "class A { void f() { int y = x; } }",
        }),
    },
    Rule {
        id: "java/redundant-close",
        name: "close() calls should not be redundant",
        description: "try-with-resources already closes the resource.",
        message: "Remove the call.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S4087")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(try_with_resources_statement) @match"#,
            filter: Some(Find(closes_a_managed_resource)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { try (Reader r = open()) { r.close(); } } }",
            good: "class A { void f() { try (Reader r = open()) { r.read(); } } }",
        }),
    },
    Rule {
        id: "java/servlet-throws",
        name: "Exceptions should not be thrown from servlet methods",
        description: "An uncaught exception shows the client a stack trace.",
        message: "Handle it and send an error response.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S1989")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration name: (identifier) @n (#any-of? @n "doGet" "doPost" "doPut" "doDelete")) @match"#,
            filter: Some(Find(servlet_method_throws)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A extends HttpServlet { void doGet(HttpServletRequest r, HttpServletResponse s) { throw new RuntimeException(); } }",
            good: "class A extends HttpServlet { void doGet(HttpServletRequest r, HttpServletResponse s) { s.sendError(500); } }",
        }),
    },
    Rule {
        id: "java/static-iv",
        name: "Counter Mode initialization vectors should not be reused",
        description: "A fixed IV in CTR or GCM mode breaks confidentiality.",
        message: "Generate the IV randomly for every message.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 30,
        sonar: &[exact("S6432")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(object_creation_expression type: (type_identifier) @t (#any-of? @t "IvParameterSpec" "GCMParameterSpec")) @match"#,
            filter: Some(Keep(iv_is_a_literal)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { IvParameterSpec iv = new IvParameterSpec(new byte[16]); } }",
            good: "class A { void f() { IvParameterSpec iv = new IvParameterSpec(random); } }",
        }),
    },
];

// ---------------------------------------------------- filters

fn class_body(class: Node) -> Option<Node> {
    class.child_by_field_name("body")
}

pub(super) fn class_members(class: Node) -> Vec<Node> {
    class_body(class).map(members).unwrap_or_default()
}

pub(super) fn named_children(node: Node) -> Vec<Node> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

/// The declared type of `name` as seen from `from`: a parameter, a local
/// or a field of the enclosing classes.
pub(super) fn declared_type<'t>(from: Node<'t>, name: &[u8], src: &[u8]) -> Option<Node<'t>> {
    let mut p = from.parent();
    while let Some(n) = p {
        match n.kind() {
            "method_declaration" | "constructor_declaration" => {
                if let Some(params) = n.child_by_field_name("parameters") {
                    for fp in named_children(params) {
                        if fp
                            .child_by_field_name("name")
                            .is_some_and(|x| text(x, src) == name)
                        {
                            return fp.child_by_field_name("type");
                        }
                    }
                }
                if let Some(body) = n.child_by_field_name("body") {
                    let local = find_node(body, |x| {
                        x.kind() == "local_variable_declaration"
                            && declarator_names(x, src).contains(&name)
                    });
                    if let Some(l) = local {
                        return l.child_by_field_name("type");
                    }
                }
            }
            "class_declaration" | "enum_declaration" | "record_declaration" => {
                if let Some(f) = declared_field(n, name, src) {
                    return f.child_by_field_name("type");
                }
            }
            _ => {}
        }
        p = n.parent();
    }
    None
}

pub(super) fn declared_field<'t>(class: Node<'t>, name: &[u8], src: &[u8]) -> Option<Node<'t>> {
    class_members(class)
        .into_iter()
        .find(|m| m.kind() == "field_declaration" && declarator_names(*m, src).contains(&name))
}

pub(super) fn type_text<'s>(node: Option<Node>, src: &'s [u8]) -> &'s [u8] {
    node.map_or(&b""[..], |n| text(n, src))
}

fn catch_parameter_name<'s>(catch: Node, src: &'s [u8]) -> Option<&'s [u8]> {
    let param = children_of_kind(catch, "catch_formal_parameter")
        .into_iter()
        .next()?;
    param.child_by_field_name("name").map(|n| text(n, src))
}

fn catch_tests_exception_type(catch: Node, src: &[u8]) -> bool {
    let (Some(name), Some(body)) = (
        catch_parameter_name(catch, src),
        catch.child_by_field_name("body"),
    ) else {
        return false;
    };
    find_node(body, |n| {
        n.kind() == "instanceof_expression"
            && n.child_by_field_name("left")
                .is_some_and(|l| text(l, src) == name)
    })
    .is_some()
}

fn rethrows_without_cause<'t>(catch: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let name = catch_parameter_name(catch, src)?;
    let body = catch.child_by_field_name("body")?;
    if count_word(text(body, src), b"initCause") > 0 {
        return None;
    }
    find_node(body, |n| {
        n.kind() == "throw_statement"
            && n.named_child(0).is_some_and(|c| {
                c.kind() == "object_creation_expression"
                    && c.child_by_field_name("arguments")
                        .is_none_or(|a| count_word(text(a, src), name) == 0)
            })
    })
}

fn throws_is_superfluous(throws: Node, src: &[u8]) -> bool {
    const UNCHECKED: &[&[u8]] = &[
        b"RuntimeException",
        b"IllegalArgumentException",
        b"IllegalStateException",
        b"NullPointerException",
        b"UnsupportedOperationException",
        b"IndexOutOfBoundsException",
        b"ArrayIndexOutOfBoundsException",
        b"ArithmeticException",
        b"ClassCastException",
        b"SecurityException",
        b"NumberFormatException",
        b"ConcurrentModificationException",
        b"Error",
        b"AssertionError",
        b"OutOfMemoryError",
        b"StackOverflowError",
    ];
    let names: Vec<&[u8]> = named_children(throws)
        .iter()
        .map(|n| text(*n, src))
        .collect();
    names.iter().enumerate().any(|(i, n)| {
        UNCHECKED.contains(n)
            || names[..i].contains(n)
            || (*n != b"Exception" && names.contains(&&b"Exception"[..]) && *n != b"Throwable")
    })
}

fn clone_breaks_contract(method: Node, src: &[u8]) -> bool {
    if method
        .child_by_field_name("parameters")
        .is_some_and(|p| p.named_child_count() > 0)
    {
        return false;
    }
    let Some(class) = enclosing_class(method) else {
        return false;
    };
    let cloneable = count_word(
        class
            .child_by_field_name("interfaces")
            .map_or(&b""[..], |i| text(i, src)),
        b"Cloneable",
    ) > 0;
    let calls_super = method.child_by_field_name("body").is_some_and(|b| {
        find_node(b, |n| {
            n.kind() == "method_invocation"
                && method_name(n, src) == b"clone"
                && n.child_by_field_name("object")
                    .is_some_and(|o| o.kind() == "super")
        })
        .is_some()
    });
    let builds_new = method
        .child_by_field_name("body")
        .is_some_and(|b| find_node(b, |n| n.kind() == "object_creation_expression").is_some());
    !cloneable || (!calls_super && builds_new)
}

fn class_lacks_clone(class: Node, src: &[u8]) -> bool {
    !class_members(class)
        .iter()
        .any(|m| m.kind() == "method_declaration" && name_text(*m, src) == b"clone")
}

pub(super) fn name_text<'s>(node: Node, src: &'s [u8]) -> &'s [u8] {
    node.child_by_field_name("name")
        .map_or(&b""[..], |n| text(n, src))
}

fn call_on_array_variable(call: Node, src: &[u8]) -> bool {
    if !call_arguments(call).is_empty() {
        return false;
    }
    let Some(object) = call.child_by_field_name("object") else {
        return false;
    };
    type_text(declared_type(call, text(object, src), src), src).ends_with(b"[]")
}

fn argument_is_int_literal(call: Node, src: &[u8]) -> bool {
    call_arguments(call).first().is_some_and(|a| {
        matches!(a.kind(), "decimal_integer_literal" | "hex_integer_literal")
            && !text(*a, src).ends_with(b"L")
            && !text(*a, src).ends_with(b"l")
    })
}

fn casts_random_double(cast: Node, src: &[u8]) -> bool {
    let Some(value) = cast.child_by_field_name("value") else {
        return false;
    };
    let t = text(value, src);
    t.windows(11).any(|w| w == b"Math.random")
        || count_word(t, b"nextDouble") > 0
        || count_word(t, b"nextFloat") > 0
}

fn final_class_protected_member<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !has_modifier(class, "final") {
        return None;
    }
    class_members(class).into_iter().find(|m| {
        has_modifier(*m, "protected")
            && !has_annotation(*m, b"Override", src)
            && name_text(*m, src) != b"finalize"
    })
}

fn equals_on_atomic(call: Node, src: &[u8]) -> bool {
    let Some(object) = call.child_by_field_name("object") else {
        return false;
    };
    type_text(declared_type(call, text(object, src), src), src).starts_with(b"Atomic")
}

fn creation_repeats_type_arguments(creation: Node, _: &[u8]) -> bool {
    children_of_kind(creation, "class_body").is_empty()
}

fn public_method_has_boolean_parameter<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let name = name_text(method, src);
    if !has_modifier(method, "public")
        || has_annotation(method, b"Override", src)
        || name.starts_with(b"set")
    {
        return None;
    }
    let params = method.child_by_field_name("parameters")?;
    let body = method.child_by_field_name("body")?;
    named_children(params).into_iter().find(|p| {
        p.kind() == "formal_parameter"
            && p.child_by_field_name("type")
                .is_some_and(|t| t.kind() == "boolean_type")
            && p.child_by_field_name("name").is_some_and(|n| {
                let name = text(n, src);
                // a selector steers control flow
                find_node(body, |c| {
                    matches!(
                        c.kind(),
                        "if_statement" | "ternary_expression" | "while_statement"
                    ) && c
                        .child_by_field_name("condition")
                        .is_some_and(|cond| count_word(text(cond, src), name) > 0)
                })
                .is_some()
            })
    })
}

fn program_declares_nothing(program: Node, _: &[u8]) -> bool {
    let kids = named_children(program);
    // package-info.java holds a package declaration and documentation only
    if kids.iter().any(|k| k.kind() == "package_declaration") {
        return false;
    }
    let declares = kids.iter().any(|k| {
        matches!(
            k.kind(),
            "class_declaration"
                | "interface_declaration"
                | "enum_declaration"
                | "record_declaration"
                | "annotation_type_declaration"
        )
    });
    let annotated_package = kids.iter().any(|k| {
        k.kind() == "package_declaration" && !children_of_kind(*k, "marker_annotation").is_empty()
    });
    !declares && !annotated_package
}

fn redundant_modifier_in<'t>(declaration: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let _ = src;
    if declaration.kind() == "interface_declaration" {
        return class_members(declaration)
            .into_iter()
            .find(|m| match m.kind() {
                "method_declaration" => has_modifier(*m, "public") || has_modifier(*m, "abstract"),
                "field_declaration" => {
                    has_modifier(*m, "public")
                        || has_modifier(*m, "static")
                        || has_modifier(*m, "final")
                }
                "class_declaration" | "interface_declaration" | "enum_declaration" => {
                    has_modifier(*m, "public") || has_modifier(*m, "static")
                }
                _ => false,
            });
    }
    if has_modifier(declaration, "final") {
        return class_members(declaration)
            .into_iter()
            .find(|m| m.kind() == "method_declaration" && has_modifier(*m, "final"));
    }
    None
}

fn returns_private_mutable_field<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if has_modifier(method, "private") {
        return None;
    }
    let class = enclosing_class(method)?;
    let body = method.child_by_field_name("body")?;
    find_node(body, |n| {
        if n.kind() != "return_statement" {
            return false;
        }
        let Some(value) = n.named_child(0) else {
            return false;
        };
        let name = match value.kind() {
            "identifier" => text(value, src),
            "field_access" => value
                .child_by_field_name("field")
                .map_or(&b""[..], |f| text(f, src)),
            _ => return false,
        };
        declared_field(class, name, src).is_some_and(|f| {
            let t = type_text(f.child_by_field_name("type"), src);
            has_modifier(f, "private")
                && !(has_modifier(f, "static") && has_modifier(f, "final"))
                && (t.ends_with(b"[]")
                    || [
                        &b"List"[..],
                        b"Map",
                        b"Set",
                        b"Collection",
                        b"Date",
                        b"ArrayList",
                        b"HashMap",
                        b"HashSet",
                        b"Deque",
                        b"Queue",
                    ]
                    .iter()
                    .any(|w| t.starts_with(w)))
        })
    })
}

fn field_shadows_parent_field<'t>(program: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let classes = children_of_kind(program, "class_declaration");
    for child in &classes {
        let Some(sup) = child.child_by_field_name("superclass") else {
            continue;
        };
        let Some(parent) = classes
            .iter()
            .find(|c| count_word(text(sup, src), name_text(**c, src)) > 0 && **c != *child)
        else {
            continue;
        };
        let inherited: Vec<&[u8]> = class_members(*parent)
            .iter()
            .filter(|m| m.kind() == "field_declaration" && !has_modifier(**m, "private"))
            .flat_map(|m| declarator_names(*m, src))
            .collect();
        let hit = class_members(*child).into_iter().find(|m| {
            m.kind() == "field_declaration"
                && declarator_names(*m, src)
                    .iter()
                    .any(|n| inherited.contains(n))
        });
        if hit.is_some() {
            return hit;
        }
    }
    None
}

fn is_lock_variable(ident: Node, src: &[u8]) -> bool {
    matches!(
        type_text(declared_type(ident, text(ident, src), src), src),
        b"Lock" | b"ReentrantLock" | b"ReadWriteLock" | b"ReentrantReadWriteLock" | b"StampedLock"
    )
}

fn is_unsafe_lock_field(ident: Node, src: &[u8]) -> bool {
    let name = text(ident, src);
    let mut p = ident.parent();
    while let Some(n) = p {
        if matches!(n.kind(), "method_declaration" | "constructor_declaration") {
            let local = n.child_by_field_name("parameters").is_some_and(|ps| {
                named_children(ps).iter().any(|fp| {
                    fp.child_by_field_name("name")
                        .is_some_and(|x| text(x, src) == name)
                })
            }) || n.child_by_field_name("body").is_some_and(|b| {
                find_node(b, |x| {
                    x.kind() == "local_variable_declaration"
                        && declarator_names(x, src).contains(&name)
                })
                .is_some()
            });
            if local {
                return false;
            }
        }
        if n.kind() == "class_declaration" {
            return declared_field(n, name, src)
                .is_some_and(|f| !(has_modifier(f, "private") && has_modifier(f, "final")));
        }
        p = n.parent();
    }
    false
}

fn constructor_starts_a_thread<'t>(ctor: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let body = ctor.child_by_field_name("body")?;
    find_node(body, |n| {
        n.kind() == "method_invocation"
            && method_name(n, src) == b"start"
            && call_arguments(n).is_empty()
            && n.child_by_field_name("object")
                .is_some_and(|o| match o.kind() {
                    "object_creation_expression" => count_word(text(o, src), b"Thread") > 0,
                    "identifier" => {
                        type_text(declared_type(n, text(o, src), src), src) == b"Thread"
                    }
                    _ => false,
                })
    })
}

fn static_field_names<'s>(class: Node, src: &'s [u8]) -> Vec<&'s [u8]> {
    class_members(class)
        .iter()
        .filter(|m| {
            m.kind() == "field_declaration"
                && has_modifier(**m, "static")
                && !has_modifier(**m, "final")
        })
        .flat_map(|m| declarator_names(*m, src))
        .collect()
}

fn writes_static<'t>(body: Node<'t>, names: &[&[u8]], src: &[u8]) -> Option<Node<'t>> {
    find_node(body, |n| {
        let target = match n.kind() {
            "assignment_expression" => n.child_by_field_name("left"),
            "update_expression" => n.named_child(0),
            _ => None,
        };
        target.is_some_and(|t| t.kind() == "identifier" && names.contains(&text(t, src)))
    })
}

fn instance_method_writes_static<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if has_modifier(method, "static") {
        return None;
    }
    let names = static_field_names(enclosing_class(method)?, src);
    writes_static(method.child_by_field_name("body")?, &names, src)
}

fn constructor_writes_static<'t>(ctor: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let names = static_field_names(enclosing_class(ctor)?, src);
    writes_static(ctor.child_by_field_name("body")?, &names, src)
}

fn accessor_sync_mismatch<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let methods: Vec<Node> = class_members(class)
        .into_iter()
        .filter(|m| m.kind() == "method_declaration")
        .collect();
    for g in &methods {
        let name = name_text(*g, src);
        let property = name
            .strip_prefix(b"get")
            .or_else(|| name.strip_prefix(b"is"))
            .filter(|p| !p.is_empty());
        let Some(property) = property else { continue };
        for s in &methods {
            let sname = name_text(*s, src);
            if sname
                .strip_prefix(b"set")
                .is_some_and(|p| p.eq_ignore_ascii_case(property))
                && has_modifier(*g, "synchronized") != has_modifier(*s, "synchronized")
            {
                return Some(if has_modifier(*g, "synchronized") {
                    *s
                } else {
                    *g
                });
            }
        }
    }
    None
}

fn has_printable_unicode_escape(string: Node, src: &[u8]) -> bool {
    let t = text(string, src);
    t.windows(6).enumerate().any(|(i, w)| {
        w[0] == b'\\'
            && w[1] == b'u'
            && (i == 0 || t[i - 1] != b'\\')
            && std::str::from_utf8(&w[2..6])
                .ok()
                .and_then(|h| u32::from_str_radix(h, 16).ok())
                .is_some_and(|v| v >= 0x20 && v != 0x7f && !(0xd800..=0xdfff).contains(&v))
    })
}

fn builder_length_compared_to_zero(binary: Node, src: &[u8]) -> bool {
    let Some(call) = binary.child_by_field_name("left") else {
        return false;
    };
    let Some(object) = call.child_by_field_name("object") else {
        return false;
    };
    matches!(
        type_text(declared_type(binary, text(object, src), src), src),
        b"StringBuilder" | b"StringBuffer"
    )
}

fn main_signature_is_wrong(method: Node, src: &[u8]) -> bool {
    let Some(params) = method.child_by_field_name("parameters") else {
        return false;
    };
    let items = named_children(params);
    let [only] = items.as_slice() else {
        return false;
    };
    let t = type_text(only.child_by_field_name("type"), src);
    if t != b"String[]" && !(only.kind() == "spread_parameter" && t.starts_with(b"String")) {
        return false;
    }
    !(has_modifier(method, "public")
        && has_modifier(method, "static")
        && method
            .child_by_field_name("type")
            .is_some_and(|r| r.kind() == "void_type"))
}

fn is_default_value_field(value: Node, src: &[u8]) -> bool {
    let t = text(value, src);
    let default = match value.kind() {
        "decimal_integer_literal" => t == b"0" || t == b"0L",
        "decimal_floating_point_literal" => {
            matches!(t, b"0.0" | b"0.0f" | b"0.0F" | b"0f" | b"0d" | b"0.0d")
        }
        _ => true,
    };
    let Some(field) = value.parent().and_then(|d| d.parent()) else {
        return false;
    };
    default
        && !has_modifier(field, "final")
        && field
            .parent()
            .is_some_and(|b| b.parent().is_some_and(|c| c.kind() == "class_declaration"))
}

fn constructor_passes_this<'t>(ctor: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    let body = ctor.child_by_field_name("body")?;
    find_node(body, |n| {
        n.kind() == "this"
            && n.parent().is_some_and(|p| {
                p.kind() == "argument_list"
                    && p.parent().is_some_and(|c| {
                        matches!(c.kind(), "method_invocation" | "object_creation_expression")
                    })
            })
    })
}

fn is_public_mutable_field(field: Node, _: &[u8]) -> bool {
    has_modifier(field, "public")
        && !has_modifier(field, "final")
        && field
            .parent()
            .and_then(|b| b.parent())
            .is_some_and(|c| c.kind() == "class_declaration")
}

fn is_public_static_not_final(field: Node, _: &[u8]) -> bool {
    has_modifier(field, "public") && has_modifier(field, "static") && !has_modifier(field, "final")
}

fn body_is_not_a_block(body: Node, _: &[u8]) -> bool {
    !matches!(body.kind(), "block" | "line_comment" | "block_comment")
}

fn chain_lacks_final_else(if_statement: Node, _: &[u8]) -> bool {
    if if_statement.parent().is_some_and(|p| {
        p.kind() == "if_statement" && p.child_by_field_name("alternative") == Some(if_statement)
    }) {
        return false;
    }
    let mut cur = if_statement;
    while let Some(alt) = cur.child_by_field_name("alternative") {
        if alt.kind() != "if_statement" {
            return false;
        }
        cur = alt;
    }
    true
}

fn has_lowercase_suffix(literal: Node, src: &[u8]) -> bool {
    text(literal, src).ends_with(b"l")
}

fn constructor_calls_overridable<'t>(ctor: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let class = enclosing_class(ctor)?;
    if has_modifier(class, "final") || class.kind() != "class_declaration" {
        return None;
    }
    let overridable: Vec<&[u8]> = class_members(class)
        .iter()
        .filter(|m| {
            m.kind() == "method_declaration"
                && !has_modifier(**m, "private")
                && !has_modifier(**m, "final")
                && !has_modifier(**m, "static")
        })
        .map(|m| name_text(*m, src))
        .collect();
    find_node(ctor.child_by_field_name("body")?, |n| {
        n.kind() == "method_invocation"
            && n.child_by_field_name("object")
                .is_none_or(|o| o.kind() == "this")
            && overridable.contains(&method_name(n, src))
    })
}

fn has_too_many_fields(class: Node, src: &[u8]) -> bool {
    class_members(class)
        .iter()
        .filter(|m| m.kind() == "field_declaration")
        .map(|m| declarator_names(*m, src).len())
        .sum::<usize>()
        > 20
}

fn group_has_only_labels(group: Node, src: &[u8]) -> bool {
    let labels = children_of_kind(group, "switch_label");
    let case_labels = labels
        .iter()
        .filter(|l| text(**l, src).starts_with(b"case"))
        .count();
    if labels.len() >= 2 && case_labels == labels.len() {
        return true;
    }
    labels.len() == 1
        && case_labels == 1
        && named_children(group).len() == 1
        && group
            .next_named_sibling()
            .is_some_and(|n| n.kind() == "switch_block_statement_group")
}

fn has_no_arguments(call: Node, _: &[u8]) -> bool {
    call_arguments(call).is_empty()
}

fn relies_on_default_charset(node: Node, _: &[u8]) -> bool {
    node.kind() == "object_creation_expression" || call_arguments(node).is_empty()
}

fn is_nopmd(comment: Node, src: &[u8]) -> bool {
    count_word(text(comment, src), b"NOPMD") > 0
}

fn is_checkstyle_off(comment: Node, src: &[u8]) -> bool {
    text(comment, src)
        .windows(14)
        .any(|w| w.eq_ignore_ascii_case(b"CHECKSTYLE:OFF"))
}

fn logger_is_not_private_static_final(field: Node, _: &[u8]) -> bool {
    !(has_modifier(field, "private")
        && has_modifier(field, "static")
        && has_modifier(field, "final"))
}

fn type_parameter_names<'s>(declaration: Node, src: &'s [u8]) -> Vec<&'s [u8]> {
    declaration
        .child_by_field_name("type_parameters")
        .map(|tp| {
            children_of_kind(tp, "type_parameter")
                .iter()
                .filter_map(|p| p.named_child(0).map(|n| text(n, src)))
                .collect()
        })
        .unwrap_or_default()
}

fn shadows_class_type_parameter(method: Node, src: &[u8]) -> bool {
    // A static method can't use the class's type parameters.
    if has_modifier(method, "static") {
        return false;
    }
    let Some(class) = enclosing_class(method) else {
        return false;
    };
    let outer = type_parameter_names(class, src);
    type_parameter_names(method, src)
        .iter()
        .any(|n| outer.contains(n))
}

fn method_has_unused_type_parameter<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let tp = method.child_by_field_name("type_parameters")?;
    children_of_kind(tp, "type_parameter")
        .into_iter()
        .find(|p| {
            p.named_child(0)
                .is_some_and(|n| count_word(text(method, src), text(n, src)) == 1)
        })
}

fn closes_a_managed_resource<'t>(try_statement: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let resources = try_statement.child_by_field_name("resources")?;
    let names: Vec<&[u8]> = named_children(resources)
        .iter()
        .filter_map(|r| r.child_by_field_name("name").map(|n| text(n, src)))
        .collect();
    find_node(try_statement.child_by_field_name("body")?, |n| {
        n.kind() == "method_invocation"
            && method_name(n, src) == b"close"
            && n.child_by_field_name("object")
                .is_some_and(|o| names.contains(&text(o, src)))
    })
}

fn servlet_method_throws<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let class = enclosing_class(method)?;
    let supers = class.child_by_field_name("superclass")?;
    if count_word(text(supers, src), b"HttpServlet") == 0 {
        return None;
    }
    let body = method.child_by_field_name("body")?;
    find_node(body, |n| {
        n.kind() == "throw_statement" && {
            let mut p = n.parent();
            let mut guarded = false;
            while let Some(a) = p {
                if a == body {
                    break;
                }
                if a.kind() == "try_statement" && !children_of_kind(a, "catch_clause").is_empty() {
                    guarded = true;
                }
                p = a.parent();
            }
            !guarded
        }
    })
}

fn iv_is_a_literal(creation: Node, src: &[u8]) -> bool {
    call_arguments(creation).iter().any(|a| match a.kind() {
        "array_creation_expression" => true,
        "method_invocation" => {
            method_name(*a, src) == b"getBytes"
                && a.child_by_field_name("object")
                    .is_some_and(|o| o.kind() == "string_literal")
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
    fn exceptions() {
        let src = "class A {\n void a() throws IOException, RuntimeException {}\n void b() throws IOException {}\n void c() throws Exception, IOException {}\n void d() {\n  try { f(); } catch (IOException e) { throw new X(\"m\"); }\n  try { f(); } catch (IOException e) { throw new X(\"m\", e); }\n }\n}";
        assert_eq!(flagged("java/superfluous-throws", src), [2, 4]);
        assert_eq!(flagged("java/catch-drops-cause", src), [6]);
    }

    #[test]
    fn declared_types() {
        let src = "class A {\n AtomicInteger a;\n int[] arr;\n boolean f(AtomicInteger b, String s) {\n  a.equals(b);\n  s.equals(b);\n  arr.toString();\n  s.toString();\n  return false;\n }\n}";
        assert_eq!(flagged("java/atomic-equals", src), [5]);
        assert_eq!(flagged("java/array-to-string", src), [7]);
    }

    #[test]
    fn classes() {
        let src = "class P { int x; }\nclass C extends P { int x; }\nfinal class F { protected int p; private int q; }\nclass G { private int[] a; private int b; int[] get() { return a; } int get2() { return b; } }\nclass H { static int n; H() { n++; } void f() { n = 2; } static void g() { n = 3; } }";
        assert_eq!(flagged("java/field-shadows-parent", src), [2]);
        assert_eq!(flagged("java/final-protected", src), [3]);
        assert_eq!(flagged("java/exposes-internal-state", src), [4]);
        assert_eq!(
            flagged("java/static-field-updated-in-constructor", src),
            [5]
        );
        assert_eq!(flagged("java/instance-writes-static", src), [5]);
    }

    #[test]
    fn syntax_conventions() {
        let src = "class A {\n int n = 0;\n int m = 1;\n final int k = 0;\n long l = 10l;\n int o = 010;\n void f(boolean b) { if (b) g(); if (b) { g(); } else if (b) { g(); } }\n}";
        assert_eq!(flagged("java/default-field-value", src), [2]);
        assert_eq!(flagged("java/literal-suffix-case", src), [5]);
        assert_eq!(flagged("java/octal-literal", src), [6]);
        assert_eq!(flagged("java/missing-braces", src), [7]);
        assert_eq!(flagged("java/if-else-if-without-else", src), [7]);
    }
}
