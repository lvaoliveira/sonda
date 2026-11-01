//! Java bug rules (ADR-0007, batch 7). Queries stay cheap on deep trees: see
//! the notes in `js_modern.rs`.

use super::java_security::{
    call_arguments, contains_ignoring_case, find_node, method_name, string_value, text,
};
use super::*;

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "java/finalize-called",
        name: "Object.finalize() should not be called",
        description: "Calling finalize by hand runs cleanup that the garbage collector will run again.",
        message: "Remove this call to finalize().",
        category: Bug,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S1111")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "finalize")) @match"#,
            filter: Some(Keep(finalize_called_directly)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { obj.finalize(); } }",
            good: "class A { void f() { obj.close(); } }",
        }),
    },
    Rule {
        id: "java/finalize-signature",
        name: "The signature of finalize() should match that of Object.finalize()",
        description: "A method named finalize with another signature is never called by the JVM.",
        message: "Make this finalize() match Object.finalize().",
        category: Bug,
        severity: Blocker,
        effort_minutes: 5,
        sonar: &[exact("S1175")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration name: (identifier) @n (#eq? @n "finalize")) @match"#,
            filter: Some(Keep(finalize_has_wrong_signature)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void finalize(int x) {} }",
            good: "class A { protected void finalize() throws Throwable {} }",
        }),
    },
    Rule {
        id: "java/equals-parameter",
        name: "equals overrides should accept Object parameters",
        description: "An equals(Foo) overloads equals instead of overriding it, so collections never call it.",
        message: "Change the parameter to Object.",
        category: Bug,
        severity: Blocker,
        effort_minutes: 5,
        sonar: &[exact("S1201")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration name: (identifier) @n (#eq? @n "equals")) @match"#,
            filter: Some(Keep(equals_takes_another_type)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { public boolean equals(A other) { return true; } }",
            good: "class A { public boolean equals(Object other) { return true; } }",
        }),
    },
    Rule {
        id: "java/equals-without-hashcode",
        name: "equals and hashCode should be overridden in pairs",
        description: "Objects that are equal must have the same hash code, or hash-based collections misbehave.",
        message: "Override both equals(Object) and hashCode().",
        category: Bug,
        severity: Blocker,
        effort_minutes: 10,
        sonar: &[exact("S1206")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_body) @match"#,
            filter: Some(Find(equals_hashcode_unpaired)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { public boolean equals(Object o) { return true; } }",
            good: "class A { public boolean equals(Object o) { return true; } public int hashCode() { return 1; } }",
        }),
    },
    Rule {
        id: "java/thread-run-direct",
        name: "Thread.run() should not be called directly",
        description: "Calling run() executes the code on the current thread; start() starts a new one.",
        message: "Call start() instead.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S1217")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (object_creation_expression type: (type_identifier) @t (#eq? @t "Thread")) name: (identifier) @n (#eq? @n "run")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { new Thread(task).run(); } }",
            good: "class A { void f() { new Thread(task).start(); } }",
        }),
    },
    Rule {
        id: "java/misspelled-method-name",
        name: "Methods should not be named tostring, hashcode or equal",
        description: "These names look like the Object methods but are different methods that nothing calls.",
        message: "Fix the name's capitalization.",
        category: Bug,
        severity: Blocker,
        effort_minutes: 2,
        sonar: &[exact("S1221")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration name: (identifier) @n (#match? @n "(?i)^(tostring|hashcode|equal)$")) @match"#,
            filter: Some(Keep(name_is_a_near_miss)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { public String tostring() { return \"\"; } }",
            good: "class A { public String toString() { return \"\"; } }",
        }),
    },
    Rule {
        id: "java/string-builder-char",
        name: "StringBuilder and StringBuffer should not be instantiated with a character",
        description: "new StringBuilder('x') creates a builder with the char's numeric value as its capacity.",
        message: "Pass a String instead.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S1317")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(object_creation_expression type: (type_identifier) @t (#any-of? @t "StringBuilder" "StringBuffer") arguments: (argument_list (character_literal))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { StringBuilder sb = new StringBuilder('x'); } }",
            good: "class A { void f() { StringBuilder sb = new StringBuilder(\"x\"); } }",
        }),
    },
    Rule {
        id: "java/self-assignment",
        name: "Variables should not be self-assigned",
        description: "Assigning a value to itself does nothing and usually hides a typo.",
        message: "Remove this self-assignment, or fix the name.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S1656")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(assignment_expression) @match"#,
            filter: Some(Keep(assigns_to_itself)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { int x; void f() { x = x; } }",
            good: "class A { int x; void f(int y) { x = y; } }",
        }),
    },
    Rule {
        id: "java/single-iteration-loop",
        name: "Loops with at most one iteration should be refactored",
        description: "A loop whose body always ends in a jump runs its body once.",
        message: "Replace this loop with an if, or fix the jump.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1751")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(for_statement) @match
(enhanced_for_statement) @match
(while_statement) @match
(do_statement) @match"#,
            filter: Some(Keep(loop_always_exits)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { for (int i = 0; i < n; i++) { return i; } } }",
            good: "class A { void f() { for (int i = 0; i < n; i++) { if (ok(i)) { return i; } } } }",
        }),
    },
    Rule {
        id: "java/identical-operands",
        name: "Identical expressions should not be used on both sides of a binary operator",
        description: "`a == a` is always true and `a - a` always zero: one side is almost certainly a typo.",
        message: "Fix one of these identical operands.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1764")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(binary_expression) @match"#,
            filter: Some(Keep(operands_are_identical)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { boolean r = a > a; } }",
            good: "class A { void f() { boolean r = a > b; } }",
        }),
    },
    Rule {
        id: "java/hasnext-calls-next",
        name: "Iterator.hasNext() should not call Iterator.next()",
        description: "hasNext must not change the iterator's state, or checking twice skips an element.",
        message: "Don't call next() in hasNext().",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S1849")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration name: (identifier) @n (#eq? @n "hasNext")) @match"#,
            filter: Some(Find(calls_next)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { public boolean hasNext() { return it.next() != null; } }",
            good: "class A { public boolean hasNext() { return it.hasNext(); } }",
        }),
    },
    Rule {
        id: "java/synchronized-on-literal",
        name: "Synchronization should not be done on shared literals or boxed values",
        description: "Equal literals and cached boxes are the same object everywhere, so unrelated code shares the lock.",
        message: "Synchronize on a private final object.",
        category: Bug,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S1860")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(synchronized_statement) @match"#,
            filter: Some(Keep(locks_on_shared_value)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { synchronized (\"lock\") { work(); } } }",
            good: "class A { void f() { synchronized (lock) { work(); } } }",
        }),
    },
    Rule {
        id: "java/duplicate-condition",
        name: "Related if/else if statements should not have the same condition",
        description: "The second branch can never run.",
        message: "Change or remove the repeated condition.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1862")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(if_statement) @match"#,
            filter: Some(Find(repeated_branch_condition)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { if (a) { f(); } else if (b) { g(); } else if (a) { h(); } } }",
            good: "class A { void f() { if (a) { f(); } else if (b) { g(); } else if (c) { h(); } } }",
        }),
    },
    Rule {
        id: "java/class-compared-by-name",
        name: "Classes should not be compared by name",
        description: "Two different classes can share a name when loaded by different class loaders.",
        message: "Compare the Class objects.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1872")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (method_invocation object: (method_invocation name: (identifier) @c (#eq? @c "getClass")) name: (identifier) @g (#any-of? @g "getName" "getSimpleName")) name: (identifier) @n (#eq? @n "equals")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { boolean r = a.getClass().getName().equals(b); } }",
            good: "class A { void f() { boolean r = a.getClass() == b.getClass(); } }",
        }),
    },
    Rule {
        id: "java/serialization-signature",
        name: "Custom serialization methods should have the required signatures",
        description: "The JVM only calls writeObject, readObject and friends when their signatures are exact.",
        message: "Fix this method's signature.",
        category: Bug,
        severity: Blocker,
        effort_minutes: 5,
        sonar: &[exact("S2061")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration name: (identifier) @n (#any-of? @n "writeObject" "readObject" "readObjectNoData" "writeReplace" "readResolve")) @match"#,
            filter: Some(Keep(serialization_signature_is_wrong)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A implements Serializable { void writeObject(ObjectOutputStream o) {} }",
            good: "class A implements Serializable { private void writeObject(ObjectOutputStream o) {} }",
        }),
    },
    Rule {
        id: "java/invalid-date",
        name: "Invalid Date values should not be used",
        description: "Month 12 or day 32 silently rolls over into the next period.",
        message: "Use a valid month (0-11) and day (1-31).",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2110")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(object_creation_expression type: (type_identifier) @t (#eq? @t "Date") arguments: (argument_list (_) (_) (_))) @match"#,
            filter: Some(Keep(date_fields_out_of_range)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Date d = new Date(2024, 12, 1); } }",
            good: "class A { void f() { Date d = new Date(2024, 11, 1); } }",
        }),
    },
    Rule {
        id: "java/bigdecimal-double",
        name: "BigDecimal(double) should not be used",
        description: "The double is already inexact, and BigDecimal faithfully keeps every wrong digit.",
        message: "Use BigDecimal.valueOf or a String.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2111")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(object_creation_expression type: (type_identifier) @t (#eq? @t "BigDecimal") arguments: (argument_list . (decimal_floating_point_literal))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { BigDecimal b = new BigDecimal(0.1); } }",
            good: "class A { void f() { BigDecimal b = new BigDecimal(\"0.1\"); } }",
        }),
    },
    Rule {
        id: "java/collection-self-argument",
        name: "Collections should not be passed as arguments to their own methods",
        description: "list.removeAll(list) empties it and list.addAll(list) doubles it, which is rarely intended.",
        message: "Pass another collection.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2114")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) @o name: (identifier) @n arguments: (argument_list . (identifier) @a) (#any-of? @n "addAll" "removeAll" "retainAll" "containsAll")) @match"#,
            filter: Some(Keep(argument_is_the_receiver)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { list.addAll(list); } }",
            good: "class A { void f() { list.addAll(other); } }",
        }),
    },
    Rule {
        id: "java/random-per-call",
        name: "Random objects should be reused",
        description: "A new Random each time can return the same value when created in the same millisecond.",
        message: "Create the Random once and reuse it.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2119")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (object_creation_expression type: (type_identifier) @t (#eq? @t "Random")) name: (identifier) @n (#match? @n "^next")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { int n = new Random().nextInt(10); } }",
            good: "class A { void f() { int n = random.nextInt(10); } }",
        }),
    },
    Rule {
        id: "java/scheduled-zero-threads",
        name: "ScheduledThreadPoolExecutor should not have 0 core threads",
        description: "With no core threads, scheduled tasks never run.",
        message: "Use at least one core thread.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2122")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(object_creation_expression type: (type_identifier) @t (#eq? @t "ScheduledThreadPoolExecutor") arguments: (argument_list . (decimal_integer_literal) @n (#eq? @n "0"))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { new ScheduledThreadPoolExecutor(0); } }",
            good: "class A { void f() { new ScheduledThreadPoolExecutor(1); } }",
        }),
    },
    Rule {
        id: "java/useless-increment",
        name: "Values should not be uselessly incremented",
        description: "`i = i++` assigns the old value back, so the increment is lost.",
        message: "Remove the assignment, or the increment.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2123")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(assignment_expression left: (identifier) right: (update_expression)) @match"#,
            filter: Some(Keep(assigns_postfix_to_itself)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { int i = 0; i = i++; } }",
            good: "class A { void f() { int i = 0; i++; } }",
        }),
    },
    Rule {
        id: "java/thread-without-run",
        name: "Classes extending Thread should provide a specific run behavior",
        description: "A Thread subclass that doesn't override run does nothing when started.",
        message: "Override run().",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2134")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration (superclass (type_identifier) @s (#eq? @s "Thread"))) @match"#,
            filter: Some(Keep(thread_has_no_run)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class W extends Thread { void other() {} }",
            good: "class W extends Thread { public void run() { work(); } }",
        }),
    },
    Rule {
        id: "java/interrupt-swallowed",
        name: "InterruptedException should not be ignored",
        description: "Swallowing the interrupt hides a request to stop from the code above.",
        message: "Re-interrupt the thread, or rethrow.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2142")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(catch_clause) @match"#,
            filter: Some(Keep(swallows_interrupt)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { try { work(); } catch (InterruptedException e) { log(e); } } }",
            good: "class A { void f() { try { work(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); } } }",
        }),
    },
    Rule {
        id: "java/run-finalizers-on-exit",
        name: "runFinalizersOnExit should not be called",
        description: "It is deprecated, unsafe and was removed.",
        message: "Remove this call.",
        category: Bug,
        severity: Blocker,
        effort_minutes: 2,
        sonar: &[exact("S2151")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "runFinalizersOnExit")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { System.runFinalizersOnExit(true); } }",
            good: "class A { void f() { System.exit(0); } }",
        }),
    },
    Rule {
        id: "java/boxing-roundtrip",
        name: "Unnecessary boxing and unboxing should be avoided",
        description: "Boxing a value only to unbox it again wastes time.",
        message: "Use the primitive directly.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2153")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: [(method_invocation name: (identifier) @v (#eq? @v "valueOf")) (object_creation_expression type: (type_identifier) @bt (#any-of? @bt "Integer" "Long" "Double" "Float" "Short" "Byte" "Boolean" "Character"))] name: (identifier) @n (#match? @n "^(int|long|double|float|short|byte|boolean|char)Value$")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { int n = Integer.valueOf(s).intValue(); } }",
            good: "class A { void f() { int n = Integer.parseInt(s); } }",
        }),
    },
    Rule {
        id: "java/compareto-min-value",
        name: "compareTo should not return Integer.MIN_VALUE",
        description: "Negating or taking the absolute value of MIN_VALUE overflows.",
        message: "Return -1 instead.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2167")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration name: (identifier) @n (#eq? @n "compareTo")) @match"#,
            filter: Some(Find(returns_min_value)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { public int compareTo(A o) { return Integer.MIN_VALUE; } }",
            good: "class A { public int compareTo(A o) { return -1; } }",
        }),
    },
    Rule {
        id: "java/double-checked-locking",
        name: "Double-checked locking should not be used",
        description: "Without volatile, another thread can see a half-built object.",
        message: "Make the field volatile, or use a holder class.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S2168")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(if_statement) @match"#,
            filter: Some(Keep(is_double_checked_locking)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { static Object inst; static Object get() { if (inst == null) { synchronized (A.class) { if (inst == null) { inst = new Object(); } } } return inst; } }",
            good: "class A { static volatile Object inst; static Object get() { if (inst == null) { synchronized (A.class) { if (inst == null) { inst = new Object(); } } } return inst; } }",
        }),
    },
    Rule {
        id: "java/shift-out-of-range",
        name: "Ints and longs should not be shifted by zero or more than their number of bits",
        description: "Shifting by 0 does nothing, and shifting by 64 or more is the same as shifting by the remainder.",
        message: "Use a shift amount in range.",
        category: Bug,
        severity: Blocker,
        effort_minutes: 2,
        sonar: &[exact("S2183")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(binary_expression) @match"#,
            filter: Some(Keep(shift_amount_is_out_of_range)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { int r = x << 0; } }",
            good: "class A { void f() { int r = x << 3; } }",
        }),
    },
    Rule {
        id: "java/compareto-specific-value",
        name: "compareTo results should not be checked for specific values",
        description: "compareTo may return any negative or positive number, not just -1 and 1.",
        message: "Compare the result with 0.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2200")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(binary_expression left: (method_invocation name: (identifier) @n (#eq? @n "compareTo"))) @match"#,
            filter: Some(Keep(compares_result_with_one)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { boolean r = a.compareTo(b) == 1; } }",
            good: "class A { void f() { boolean r = a.compareTo(b) > 0; } }",
        }),
    },
    Rule {
        id: "java/null-returned-by-object-method",
        name: "toString and clone should not return null",
        description: "Callers use the result without checking it.",
        message: "Return a value.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2225")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration name: (identifier) @n (#any-of? @n "toString" "clone")) @match"#,
            filter: Some(Find(returns_null)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { public String toString() { return null; } }",
            good: "class A { public String toString() { return \"\"; } }",
        }),
    },
    Rule {
        id: "java/loop-direction",
        name: "A for loop update clause should move the counter in the right direction",
        description: "A counter that moves away from its bound loops until it overflows.",
        message: "Fix the update clause.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2251")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(for_statement) @match"#,
            filter: Some(Keep(counter_moves_away_from_bound)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { for (int i = 0; i < 10; i--) {} } }",
            good: "class A { void f() { for (int i = 0; i < 10; i++) {} } }",
        }),
    },
    Rule {
        id: "java/iterator-next-exception",
        name: "Iterator.next() methods should throw NoSuchElementException",
        description: "The Iterator contract requires it when no element is left.",
        message: "Throw NoSuchElementException.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2272")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration (super_interfaces) @i) @match"#,
            filter: Some(Find(next_never_throws)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A implements Iterator<String> { public boolean hasNext() { return true; } public String next() { return \"\"; } }",
            good: "class A implements Iterator<String> { public boolean hasNext() { return true; } public String next() { throw new NoSuchElementException(); } }",
        }),
    },
    Rule {
        id: "java/format-arguments",
        name: "Printf-style format strings should not lead to unexpected behavior at runtime",
        description: "Too few arguments throw at runtime, and extra ones are silently ignored.",
        message: "Make the number of arguments match the format.",
        category: Bug,
        severity: Blocker,
        effort_minutes: 5,
        sonar: &[exact("S2275"), exact("S3457")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "format" "printf" "formatted")) @match"#,
            filter: Some(Keep(format_arguments_mismatch)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { String s = String.format(\"%s and %s and %s\", a, b); } }",
            good: "class A { void f() { String s = String.format(\"%s and %s\", a, b); } }",
        }),
    },
    Rule {
        id: "java/sleep-while-locked",
        name: "wait(...) should be used instead of Thread.sleep(...) when a lock is held",
        description: "sleep keeps the lock while it waits, blocking everyone else.",
        message: "Use wait() so the lock is released.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2276")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) @o name: (identifier) @n (#eq? @o "Thread") (#eq? @n "sleep")) @match"#,
            filter: Some(Keep(inside_synchronized_block)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { synchronized (lock) { Thread.sleep(10); } } }",
            good: "class A { void f() { synchronized (lock) { lock.wait(10); } } }",
        }),
    },
    Rule {
        id: "java/notify-single",
        name: "notifyAll() should be preferred over notify()",
        description: "notify wakes one arbitrary waiter, which may not be the one that can proceed.",
        message: "Use notifyAll().",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2446")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "notify")) @match"#,
            filter: Some(Keep(no_arguments)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { lock.notify(); } }",
            good: "class A { void f() { lock.notifyAll(); } }",
        }),
    },
    Rule {
        id: "java/regex-metacharacter",
        name: "Inappropriate regular expressions should not be used",
        description: "split(\".\") splits on every character and split(\"|\") on every position, both giving unexpected results.",
        message: "Escape the character.",
        category: Bug,
        severity: Blocker,
        effort_minutes: 2,
        sonar: &[exact("S2639")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "split" "replaceAll" "replaceFirst")) @match"#,
            filter: Some(Keep(regex_is_a_bare_metacharacter)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { String[] p = s.split(\".\"); } }",
            good: "class A { void f() { String[] p = s.split(\"\\\\.\"); } }",
        }),
    },
    Rule {
        id: "java/read-result-ignored",
        name: "The value returned from a stream read should be checked",
        description: "read(buffer) may fill only part of the buffer, and readLine returns null at the end.",
        message: "Use the returned value.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2674"), exact("S2677")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(expression_statement (method_invocation name: (identifier) @n (#any-of? @n "read" "readLine"))) @match"#,
            filter: Some(Keep(read_discards_result)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { in.read(buffer); } }",
            good: "class A { void f() { int n = in.read(buffer); } }",
        }),
    },
    Rule {
        id: "java/abs-of-unbounded",
        name: "Math.abs and negation should not be used on numbers that could be MIN_VALUE",
        description: "abs(Integer.MIN_VALUE) is still negative, and hashCode and nextInt can return it.",
        message: "Use a safe alternative such as Math.floorMod.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2676")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) @o name: (identifier) @n arguments: (argument_list . (method_invocation name: (identifier) @i)) (#eq? @o "Math") (#eq? @n "abs") (#any-of? @i "hashCode" "nextInt" "nextLong")) @match"#,
            filter: Some(Keep(abs_of_unbounded_call)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { int i = Math.abs(key.hashCode()); } }",
            good: "class A { void f() { int i = Math.floorMod(key.hashCode(), size); } }",
        }),
    },
    Rule {
        id: "java/prepared-statement-index",
        name: "PreparedStatement methods should be called with valid indices",
        description: "Parameter indices start at 1; index 0 throws.",
        message: "Use an index of 1 or more.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2695")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n arguments: (argument_list . (decimal_integer_literal) @i (#eq? @i "0"))) @match"#,
            filter: Some(Keep(sets_parameter_zero)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { ps.setString(0, name); } }",
            good: "class A { void f() { ps.setString(1, name); } }",
        }),
    },
    Rule {
        id: "java/repeated-unary-operator",
        name: "Unary prefix operators should not be repeated",
        description: "`!!x` and `~~x` cancel out.",
        message: "Remove the repeated operator.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2761")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(unary_expression operator: "!" operand: (unary_expression operator: "!")) @match
(unary_expression operator: "~" operand: (unary_expression operator: "~")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { boolean r = !!flag; } }",
            good: "class A { void f() { boolean r = flag; } }",
        }),
    },
    Rule {
        id: "java/optional-null",
        name: "null should not be used with Optional",
        description: "An Optional that can itself be null defeats its purpose.",
        message: "Use Optional.empty().",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2789")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(variable_declarator value: (null_literal)) @match
(method_declaration type: (generic_type (type_identifier) @t (#eq? @t "Optional"))) @match"#,
            filter: Some(Find(null_where_optional_is_expected)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Optional<String> o = null; } }",
            good: "class A { void f() { Optional<String> o = Optional.empty(); } }",
        }),
    },
    Rule {
        id: "java/non-thread-safe-static",
        name: "Non-thread-safe fields should not be static",
        description: "SimpleDateFormat and Calendar keep internal state, so sharing one corrupts results.",
        message: "Create the instance per use, or use java.time.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S2885")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(field_declaration) @match"#,
            filter: Some(Keep(shares_non_thread_safe_type)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { static final SimpleDateFormat F = new SimpleDateFormat(\"yyyy\"); }",
            good: "class A { static final DateTimeFormatter F = DateTimeFormatter.ISO_DATE; }",
        }),
    },
    Rule {
        id: "java/volatile-mutable-field",
        name: "Non-primitive fields should not be volatile",
        description: "volatile protects the reference, not the contents of a collection or array.",
        message: "Use a thread-safe class, or synchronize.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S3077")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(field_declaration) @match"#,
            filter: Some(Keep(volatile_holds_mutable_state)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { volatile List<String> items; }",
            good: "class A { volatile boolean ready; }",
        }),
    },
    Rule {
        id: "java/assert-side-effects",
        name: "Expressions used in assert should not produce side effects",
        description: "Assertions are disabled by default, so code relying on their side effects silently doesn't run.",
        message: "Move the side effect out of the assert.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3346")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(assert_statement) @match"#,
            filter: Some(Keep(assert_has_side_effects)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { assert list.remove(x); } }",
            good: "class A { void f() { boolean removed = list.remove(x); assert removed; } }",
        }),
    },
    Rule {
        id: "java/double-brace-initialization",
        name: "Double Brace Initialization should not be used",
        description: "It creates an anonymous subclass for every use and keeps the enclosing instance alive.",
        message: "Fill the collection with ordinary calls or List.of.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3599")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(object_creation_expression (class_body (block))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { List<String> l = new ArrayList<>() {{ add(\"a\"); }}; } }",
            good: "class A { void f() { List<String> l = List.of(\"a\"); } }",
        }),
    },
    Rule {
        id: "java/size-comparison",
        name: "Collection sizes and array length comparisons should make sense",
        description: "A size is never negative, so `size() < 0` is always false and `size() >= 0` always true.",
        message: "Fix this comparison.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S3981")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(binary_expression) @match"#,
            filter: Some(Keep(compares_size_with_zero_nonsensically)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { boolean r = list.size() < 0; } }",
            good: "class A { void f() { boolean r = list.isEmpty(); } }",
        }),
    },
    Rule {
        id: "java/exception-not-thrown",
        name: "Exceptions should not be created without being thrown",
        description: "`new IllegalStateException(...)` on its own builds an object and drops it.",
        message: "Throw this exception.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S3984")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(expression_statement (object_creation_expression type: (type_identifier) @t (#match? @t "(Exception|Error)$"))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { new IllegalStateException(\"bad\"); } }",
            good: "class A { void f() { throw new IllegalStateException(\"bad\"); } }",
        }),
    },
    Rule {
        id: "java/week-year",
        name: "Week Year (YYYY) should not be used for date formatting",
        description: "YYYY is the week-based year, which differs from the calendar year in the last days of December.",
        message: "Use yyyy.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S3986")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(object_creation_expression type: (type_identifier) @t (#eq? @t "SimpleDateFormat") arguments: (argument_list . (string_literal) @p)) @match
(method_invocation name: (identifier) @n (#eq? @n "ofPattern") arguments: (argument_list . (string_literal) @p2)) @match"#,
            filter: Some(Keep(pattern_uses_week_year)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { SimpleDateFormat f = new SimpleDateFormat(\"YYYY-MM-dd\"); } }",
            good: "class A { void f() { SimpleDateFormat f = new SimpleDateFormat(\"yyyy-MM-dd\"); } }",
        }),
    },
    Rule {
        id: "java/map-value-replaced",
        name: "Map values should not be replaced unconditionally",
        description: "Putting twice under the same key discards the first value.",
        message: "Remove the first put, or use another key.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S4143")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(block) @match"#,
            filter: Some(Find(map_key_put_twice)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { m.put(k, 1); m.put(k, 2); } }",
            good: "class A { void f() { m.put(k, 1); m.put(j, 2); } }",
        }),
    },
    Rule {
        id: "java/iterator-returns-this",
        name: "iterator() should not return this",
        description: "A second iteration would continue where the first stopped.",
        message: "Return a new iterator each time.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S4348")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration name: (identifier) @n (#eq? @n "iterator")) @match"#,
            filter: Some(Find(returns_this)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A implements Iterable<String>, Iterator<String> { public Iterator<String> iterator() { return this; } public boolean hasNext() { return false; } public String next() { return \"\"; } }",
            good: "class A implements Iterable<String> { public Iterator<String> iterator() { return list.iterator(); } }",
        }),
    },
    Rule {
        id: "java/assertion-compares-same-object",
        name: "Assertions should not compare an object to itself",
        description: "assertEquals(x, x) always passes.",
        message: "Compare against the expected value.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5863")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "assertEquals" "assertNotEquals" "assertSame" "assertNotSame")) @match"#,
            filter: Some(Keep(assertion_arguments_are_identical)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { assertEquals(actual, actual); } }",
            good: "class A { void f() { assertEquals(expected, actual); } }",
        }),
    },
    Rule {
        id: "java/record-array-component",
        name: "Equals should be overridden in records containing array fields",
        description: "The generated equals compares arrays by reference.",
        message: "Override equals and hashCode.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S6218")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(record_declaration) @match"#,
            filter: Some(Keep(record_has_array_without_equals)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "record R(int[] values) {}",
            good: "record R(int[] values) { public boolean equals(Object o) { return true; } }",
        }),
    },
    Rule {
        id: "java/async-return-type",
        name: "Async methods should return void or Future",
        description: "The caller can't see the result of any other return type.",
        message: "Return void, Future or CompletableFuture.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6810")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Keep(async_returns_a_plain_value)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { @Async String work() { return \"\"; } }",
            good: "class A { @Async CompletableFuture<String> work() { return null; } }",
        }),
    },
    Rule {
        id: "java/autowired-constructors",
        name: "@Autowired should only be used on a single constructor",
        description: "Spring can't choose between several required constructors.",
        message: "Annotate one constructor.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6818")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Find(second_autowired_constructor)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { @Autowired A(B b) {} @Autowired A(C c) {} }",
            good: "class A { @Autowired A(B b) {} A(C c) {} }",
        }),
    },
    Rule {
        id: "java/qualifier-on-bean",
        name: "@Qualifier should not be used on @Bean methods",
        description: "On a @Bean method it has no effect.",
        message: "Use @Bean(name=...) or put @Qualifier on the injection point.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6831")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(marker_annotation name: (identifier) @a (#eq? @a "Bean")) @match"#,
            filter: Some(Keep(sibling_is_qualifier)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { @Bean @Qualifier(\"x\") B b() { return null; } }",
            good: "class A { @Bean B b() { return null; } }",
        }),
    },
    Rule {
        id: "java/scheduled-with-arguments",
        name: "@Scheduled annotation should only be applied to no-arg methods",
        description: "Spring can't supply arguments to a scheduled call.",
        message: "Remove the parameters.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7184")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(marker_annotation name: (identifier) @a (#eq? @a "Scheduled")) @match
(annotation name: (identifier) @a2 (#eq? @a2 "Scheduled")) @match"#,
            filter: Some(Keep(annotated_method_has_parameters)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { @Scheduled(fixedRate = 1000) void tick(int x) {} }",
            good: "class A { @Scheduled(fixedRate = 1000) void tick() {} }",
        }),
    },
    Rule {
        id: "java/event-listener-parameters",
        name: "@EventListener methods should have one parameter at most",
        description: "Spring passes the event as the only argument.",
        message: "Take the event as the only parameter.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7185")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(marker_annotation name: (identifier) @a (#eq? @a "EventListener")) @match
(annotation name: (identifier) @a2 (#eq? @a2 "EventListener")) @match"#,
            filter: Some(Keep(listener_has_too_many_parameters)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { @EventListener void on(Foo f, Bar b) {} }",
            good: "class A { @EventListener void on(Foo f) {} }",
        }),
    },
    Rule {
        id: "java/clamp-range",
        name: "Math.clamp should be used with correct ranges",
        description: "clamp throws when the minimum is above the maximum.",
        message: "Swap the bounds.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6913")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) @o name: (identifier) @n (#eq? @o "Math") (#eq? @n "clamp")) @match"#,
            filter: Some(Keep(clamp_bounds_are_reversed)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { int r = Math.clamp(v, 10, 1); } }",
            good: "class A { void f() { int r = Math.clamp(v, 1, 10); } }",
        }),
    },
];

// ---------------------------------------------------- filters

const LOOP_STOPS: &[&str] = &[
    "for_statement",
    "enhanced_for_statement",
    "while_statement",
    "do_statement",
    "lambda_expression",
    "class_body",
];
pub(super) const SCOPE_STOPS: &[&str] = &["lambda_expression", "class_body", "method_declaration"];

pub(super) fn is_comment(node: Node) -> bool {
    matches!(node.kind(), "line_comment" | "block_comment")
}

pub(super) fn statements(block: Node) -> Vec<Node> {
    let mut cursor = block.walk();
    block
        .named_children(&mut cursor)
        .filter(|n| !is_comment(*n))
        .collect()
}

/// The first node below `root` that satisfies `pred`, not descending into
/// nodes whose kind is in `stops` (they are still tested themselves).
pub(super) fn find_in_scope<'t>(
    root: Node<'t>,
    stops: &[&str],
    pred: impl Fn(Node<'t>) -> bool,
) -> Option<Node<'t>> {
    let mut cursor = root.walk();
    if !cursor.goto_first_child() {
        return None;
    }
    loop {
        let n = cursor.node();
        if pred(n) {
            return Some(n);
        }
        if !stops.contains(&n.kind()) && cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return None;
            }
        }
    }
}

pub(super) fn operator_text<'a>(node: Node, src: &'a [u8]) -> &'a [u8] {
    node.child_by_field_name("operator")
        .map_or(&b""[..], |o| text(o, src))
}

pub(super) fn modifiers_of(declaration: Node) -> Option<Node> {
    let mut cursor = declaration.walk();
    declaration
        .children(&mut cursor)
        .find(|c| c.kind() == "modifiers")
}

pub(super) fn has_modifier(declaration: Node, word: &str) -> bool {
    modifiers_of(declaration).is_some_and(|m| {
        let mut cursor = m.walk();
        m.children(&mut cursor).any(|c| c.kind() == word)
    })
}

pub(super) fn parameter_types<'s>(method: Node, src: &'s [u8]) -> Vec<&'s [u8]> {
    let Some(params) = method.child_by_field_name("parameters") else {
        return Vec::new();
    };
    let mut cursor = params.walk();
    params
        .named_children(&mut cursor)
        .filter_map(|p| p.child_by_field_name("type").map(|t| text(t, src)))
        .collect()
}

fn finalize_called_directly(call: Node, src: &[u8]) -> bool {
    call_arguments(call).is_empty()
        && call
            .child_by_field_name("object")
            .is_none_or(|o| text(o, src) != b"super")
}

fn finalize_has_wrong_signature(method: Node, src: &[u8]) -> bool {
    let returns_void = method
        .child_by_field_name("type")
        .is_some_and(|t| text(t, src) == b"void");
    !parameter_types(method, src).is_empty() || !returns_void
}

fn equals_takes_another_type(method: Node, src: &[u8]) -> bool {
    // An overload next to the real equals(Object) is deliberate.
    if let Some(body) = method.parent() {
        let mut cursor = body.walk();
        if body.named_children(&mut cursor).any(|m| {
            m.kind() == "method_declaration"
                && m.child_by_field_name("name")
                    .is_some_and(|n| text(n, src) == b"equals")
                && parameter_types(m, src) == [&b"Object"[..]]
        }) {
            return false;
        }
    }
    let types = parameter_types(method, src);
    let returns_boolean = method
        .child_by_field_name("type")
        .is_some_and(|t| text(t, src) == b"boolean");
    returns_boolean
        && matches!(types.as_slice(), [t] if *t != b"Object" && *t != b"java.lang.Object")
}

fn equals_hashcode_unpaired<'t>(body: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    // Records get both for free.
    if body
        .parent()
        .is_some_and(|p| p.kind() == "record_declaration")
    {
        return None;
    }
    let mut equals = None;
    let mut hash_code = false;
    let mut cursor = body.walk();
    for member in body.named_children(&mut cursor) {
        if member.kind() != "method_declaration" {
            continue;
        }
        let name = member
            .child_by_field_name("name")
            .map_or(&b""[..], |n| text(n, src));
        let types = parameter_types(member, src);
        if name == b"equals" && matches!(types.as_slice(), [t] if *t == b"Object") {
            equals = Some(member);
        } else if name == b"hashCode" && types.is_empty() {
            hash_code = true;
        }
    }
    match (equals, hash_code) {
        (Some(m), false) => Some(m),
        _ => None,
    }
}

fn name_is_a_near_miss(method: Node, src: &[u8]) -> bool {
    let Some(name) = method.child_by_field_name("name") else {
        return false;
    };
    match text(name, src) {
        n if n.eq_ignore_ascii_case(b"tostring") => n != b"toString",
        n if n.eq_ignore_ascii_case(b"hashcode") => n != b"hashCode",
        n if n.eq_ignore_ascii_case(b"equal") => parameter_types(method, src).len() == 1,
        _ => false,
    }
}

fn assigns_to_itself(assignment: Node, src: &[u8]) -> bool {
    let (Some(left), Some(right)) = (
        assignment.child_by_field_name("left"),
        assignment.child_by_field_name("right"),
    ) else {
        return false;
    };
    operator_text(assignment, src) == b"="
        && matches!(left.kind(), "identifier" | "field_access" | "array_access")
        && text(left, src) == text(right, src)
}

fn loop_always_exits(loop_: Node, _: &[u8]) -> bool {
    let Some(body) = loop_.child_by_field_name("body") else {
        return false;
    };
    let items = if body.kind() == "block" {
        statements(body)
    } else {
        vec![body]
    };
    items.last().is_some_and(|s| {
        matches!(
            s.kind(),
            "break_statement" | "return_statement" | "throw_statement"
        )
    }) && find_in_scope(body, LOOP_STOPS, |n| n.kind() == "continue_statement").is_none()
        // `continue outer;` from a nested loop continues this one.
        && find_in_scope(body, &["lambda_expression", "class_body"], |n| {
            n.kind() == "continue_statement" && n.named_child_count() > 0
        })
        .is_none()
}

fn operands_are_identical(binary: Node, src: &[u8]) -> bool {
    let (Some(left), Some(right)) = (
        binary.child_by_field_name("left"),
        binary.child_by_field_name("right"),
    ) else {
        return false;
    };
    let op = operator_text(binary, src);
    if !matches!(
        op,
        b"=="
            | b"!="
            | b"<"
            | b">"
            | b"<="
            | b">="
            | b"-"
            | b"/"
            | b"%"
            | b"&"
            | b"|"
            | b"^"
            | b"&&"
            | b"||"
    ) {
        return false;
    }
    // `x != x` is how NaN is tested for.
    if matches!(op, b"==" | b"!=") && matches!(left.kind(), "identifier" | "field_access") {
        return false;
    }
    let literal = matches!(
        left.kind(),
        "true"
            | "false"
            | "decimal_integer_literal"
            | "string_literal"
            | "character_literal"
            | "null_literal"
    );
    !literal
        && text(left, src) == text(right, src)
        && find_node(left, |n| {
            matches!(
                n.kind(),
                "method_invocation"
                    | "update_expression"
                    | "assignment_expression"
                    | "object_creation_expression"
            )
        })
        .is_none()
        && !matches!(
            left.kind(),
            "method_invocation" | "object_creation_expression"
        )
}

fn calls_next<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let body = method.child_by_field_name("body")?;
    find_in_scope(body, SCOPE_STOPS, |n| {
        n.kind() == "method_invocation"
            && method_name(n, src) == b"next"
            && call_arguments(n).is_empty()
    })
}

fn locks_on_shared_value(sync: Node, src: &[u8]) -> bool {
    let Some(lock) = sync.named_child(0).and_then(|p| {
        if p.kind() == "parenthesized_expression" {
            p.named_child(0)
        } else {
            Some(p)
        }
    }) else {
        return false;
    };
    match lock.kind() {
        "string_literal" | "decimal_integer_literal" | "character_literal" | "true" | "false" => {
            true
        }
        "method_invocation" => {
            method_name(lock, src) == b"valueOf"
                && lock.child_by_field_name("object").is_some_and(|o| {
                    matches!(
                        text(o, src),
                        b"Integer"
                            | b"Long"
                            | b"Boolean"
                            | b"String"
                            | b"Short"
                            | b"Byte"
                            | b"Character"
                    )
                })
        }
        "object_creation_expression" => lock.child_by_field_name("type").is_some_and(|t| {
            matches!(
                text(t, src),
                b"Integer" | b"Long" | b"Boolean" | b"String" | b"Short" | b"Byte" | b"Character"
            )
        }),
        _ => false,
    }
}

fn repeated_branch_condition<'t>(statement: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    // Only the head of an else-if chain walks the chain.
    if statement.parent().is_some_and(|p| {
        p.kind() == "if_statement" && p.child_by_field_name("alternative") == Some(statement)
    }) {
        return None;
    }
    let mut seen: Vec<&[u8]> = Vec::new();
    let mut current = Some(statement);
    while let Some(branch) = current {
        let condition = branch.child_by_field_name("condition")?;
        let t = text(condition, src);
        if seen.contains(&t) {
            return Some(condition);
        }
        seen.push(t);
        current = branch
            .child_by_field_name("alternative")
            .filter(|a| a.kind() == "if_statement");
    }
    None
}

fn enclosing_implements(method: Node, src: &[u8], interface: &[u8]) -> bool {
    method
        .parent()
        .and_then(|b| b.parent())
        .filter(|c| {
            matches!(
                c.kind(),
                "class_declaration" | "enum_declaration" | "record_declaration"
            )
        })
        .is_some_and(|c| {
            let mut cursor = c.walk();
            c.children(&mut cursor).any(|i| {
                i.kind() == "super_interfaces"
                    && text(i, src)
                        .windows(interface.len())
                        .any(|w| w == interface)
            })
        })
}

fn serialization_signature_is_wrong(method: Node, src: &[u8]) -> bool {
    if !(enclosing_implements(method, src, b"Serializable")
        || enclosing_implements(method, src, b"Externalizable"))
    {
        return false;
    }
    let name = method
        .child_by_field_name("name")
        .map_or(&b""[..], |n| text(n, src));
    let ty = method
        .child_by_field_name("type")
        .map_or(&b""[..], |t| text(t, src));
    let params = parameter_types(method, src);
    let private = has_modifier(method, "private");
    let is_static = has_modifier(method, "static");
    let ok = match name {
        b"writeObject" => {
            private
                && !is_static
                && ty == b"void"
                && matches!(params.as_slice(), [p] if p.ends_with(b"ObjectOutputStream"))
        }
        b"readObject" => {
            private
                && !is_static
                && ty == b"void"
                && matches!(params.as_slice(), [p] if p.ends_with(b"ObjectInputStream"))
        }
        b"readObjectNoData" => private && !is_static && ty == b"void" && params.is_empty(),
        _ => !is_static && ty == b"Object" && params.is_empty(),
    };
    !ok
}

fn date_fields_out_of_range(creation: Node, src: &[u8]) -> bool {
    let args = call_arguments(creation);
    let value = |n: Node| -> Option<u64> {
        (n.kind() == "decimal_integer_literal")
            .then(|| String::from_utf8_lossy(text(n, src)).parse().ok())
            .flatten()
    };
    value(args[1]).is_some_and(|m| m > 11) || value(args[2]).is_some_and(|d| d > 31)
}

fn argument_is_the_receiver(call: Node, src: &[u8]) -> bool {
    let (Some(object), Some(arg)) = (
        call.child_by_field_name("object"),
        call_arguments(call).first().copied(),
    ) else {
        return false;
    };
    text(object, src) == text(arg, src)
}

fn assigns_postfix_to_itself(assignment: Node, src: &[u8]) -> bool {
    let (Some(left), Some(right)) = (
        assignment.child_by_field_name("left"),
        assignment.child_by_field_name("right"),
    ) else {
        return false;
    };
    let t = text(right, src);
    let name = text(left, src);
    t.starts_with(name) && (t.ends_with(b"++") || t.ends_with(b"--"))
}

fn thread_has_no_run(class: Node, src: &[u8]) -> bool {
    let Some(body) = class.child_by_field_name("body") else {
        return false;
    };
    let mut cursor = body.walk();
    let overrides_run = body.named_children(&mut cursor).any(|m| {
        m.kind() == "method_declaration"
            && m.child_by_field_name("name")
                .is_some_and(|n| text(n, src) == b"run")
    });
    !overrides_run && !text(body, src).windows(6).any(|w| w == b"super(")
}

fn swallows_interrupt(catch: Node, src: &[u8]) -> bool {
    let Some(param) = catch
        .named_child(0)
        .filter(|p| p.kind() == "catch_formal_parameter")
    else {
        return false;
    };
    if !text(param, src)
        .windows(20)
        .any(|w| w == b"InterruptedException")
    {
        return false;
    }
    let Some(body) = catch.child_by_field_name("body") else {
        return false;
    };
    let t = text(body, src);
    !t.windows(11).any(|w| w == b"interrupt()")
        && find_node(body, |n| n.kind() == "throw_statement").is_none()
}

fn returns_min_value<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let body = method.child_by_field_name("body")?;
    find_in_scope(body, SCOPE_STOPS, |n| {
        n.kind() == "return_statement"
            && n.named_child(0)
                .is_some_and(|v| text(v, src).ends_with(b"MIN_VALUE"))
    })
}

fn variable_names_declared<'a>(for_loop: Node, src: &'a [u8]) -> Vec<&'a [u8]> {
    let mut names = Vec::new();
    if let Some(init) = for_loop.child_by_field_name("init")
        && let Some(d) = find_node(init, |n| n.kind() == "variable_declarator")
        && let Some(n) = d.child_by_field_name("name")
    {
        names.push(text(n, src));
    }
    names
}

fn counter_moves_away_from_bound(for_loop: Node, src: &[u8]) -> bool {
    let names = variable_names_declared(for_loop, src);
    let (Some(counter), Some(condition), Some(update)) = (
        names.first(),
        for_loop.child_by_field_name("condition"),
        for_loop.child_by_field_name("update"),
    ) else {
        return false;
    };
    if condition.kind() != "binary_expression" {
        return false;
    }
    let (Some(left), Some(right)) = (
        condition.child_by_field_name("left"),
        condition.child_by_field_name("right"),
    ) else {
        return false;
    };
    let op = operator_text(condition, src);
    let counter_on_left = text(left, src) == *counter;
    if !counter_on_left && text(right, src) != *counter {
        return false;
    }
    // The direction in which the counter must move to approach the bound.
    let wants_increase = match (op, counter_on_left) {
        (b"<" | b"<=", true) | (b">" | b">=", false) => true,
        (b">" | b">=", true) | (b"<" | b"<=", false) => false,
        _ => return false,
    };
    let t = text(update, src);
    let moves_up = t.windows(2).any(|w| w == b"++") || t.windows(2).any(|w| w == b"+=");
    let moves_down = t.windows(2).any(|w| w == b"--") || t.windows(2).any(|w| w == b"-=");
    t.windows(counter.len()).any(|w| w == *counter)
        && ((wants_increase && moves_down && !moves_up)
            || (!wants_increase && moves_up && !moves_down))
}

fn next_never_throws<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut cursor = class.walk();
    let implements_iterator = class.children(&mut cursor).any(|i| {
        i.kind() == "super_interfaces" && text(i, src).windows(9).any(|w| w == b"Iterator<")
    });
    if !implements_iterator {
        return None;
    }
    let body = class.child_by_field_name("body")?;
    let mut c = body.walk();
    body.named_children(&mut c).find(|m| {
        m.kind() == "method_declaration"
            && m.child_by_field_name("name")
                .is_some_and(|n| text(n, src) == b"next")
            && parameter_types(*m, src).is_empty()
            && m.child_by_field_name("body").is_some_and(|b| {
                let t = text(b, src);
                !t.windows(21).any(|w| w == b"NoSuchElementException")
                    && find_node(b, |n| n.kind() == "throw_statement").is_none()
            })
    })
}

/// How many arguments a printf-style format consumes; None when it uses
/// positional (`%1$s`) or relative (`%<s`) indices.
fn format_specifiers(format: &[u8]) -> Option<usize> {
    let mut count = 0;
    let mut i = 0;
    while i < format.len() {
        if format[i] != b'%' {
            i += 1;
            continue;
        }
        i += 1;
        let start = i;
        while i < format.len() && !format[i].is_ascii_alphabetic() && format[i] != b'%' {
            i += 1;
        }
        if i >= format.len() {
            return None;
        }
        if format[start..i].iter().any(|&b| b == b'$' || b == b'<') {
            return None;
        }
        if !matches!(format[i], b'%' | b'n') {
            count += 1;
        }
        i += 1;
    }
    Some(count)
}

fn format_arguments_mismatch(call: Node, src: &[u8]) -> bool {
    let name = method_name(call, src);
    let mut args = call_arguments(call);
    let object = call.child_by_field_name("object");
    let format = if name == b"formatted" {
        object.and_then(|o| string_value(o, src))
    } else {
        // String.format(Locale, fmt, ...) puts the locale first.
        if args.first().is_some_and(|a| a.kind() != "string_literal")
            && args.get(1).is_some_and(|a| a.kind() == "string_literal")
        {
            args.remove(0);
        }
        if name == b"format" && object.is_some_and(|o| text(o, src) != b"String") {
            return false;
        }
        if args.is_empty() {
            return false;
        }
        let first = args.remove(0);
        string_value(first, src)
    };
    let Some(specifiers) = format.and_then(format_specifiers) else {
        return false;
    };
    // A lone non-literal argument may be an Object[] spread into the varargs.
    if args.len() == 1
        && !matches!(
            args[0].kind(),
            "string_literal" | "decimal_integer_literal" | "true" | "false" | "character_literal"
        )
    {
        return false;
    }
    specifiers != args.len()
}

fn inside_synchronized_block(call: Node, _: &[u8]) -> bool {
    let mut p = call.parent();
    let mut hops = 0;
    while let Some(n) = p {
        match n.kind() {
            "synchronized_statement" => return true,
            "method_declaration" | "lambda_expression" | "constructor_declaration" => return false,
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

pub(super) fn no_arguments(call: Node, _: &[u8]) -> bool {
    call_arguments(call).is_empty()
}

fn regex_is_a_bare_metacharacter(call: Node, src: &[u8]) -> bool {
    call_arguments(call)
        .first()
        .and_then(|a| string_value(*a, src))
        .is_some_and(|v| v == b"." || v == b"|")
}

fn read_discards_result(call: Node, src: &[u8]) -> bool {
    let Some(invocation) = call.named_child(0) else {
        return false;
    };
    match method_name(invocation, src) {
        b"readLine" => call_arguments(invocation).is_empty(),
        _ => !call_arguments(invocation).is_empty(),
    }
}

fn abs_of_unbounded_call(call: Node, src: &[u8]) -> bool {
    let Some(inner) = call_arguments(call).into_iter().next() else {
        return false;
    };
    match method_name(inner, src) {
        b"hashCode" => call_arguments(inner).is_empty(),
        _ => call_arguments(inner).is_empty(),
    }
}

fn sets_parameter_zero(call: Node, src: &[u8]) -> bool {
    let receiver = call
        .child_by_field_name("object")
        .map(|o| text(o, src).to_ascii_lowercase())
        .unwrap_or_default();
    let looks_like_statement = matches!(receiver.as_slice(), b"ps" | b"st" | b"stmt" | b"pstmt")
        || receiver.windows(9).any(|w| w == b"statement")
        || receiver.windows(8).any(|w| w == b"prepared")
        || receiver.windows(4).any(|w| w == b"stmt");
    looks_like_statement
        && matches!(
            method_name(call, src),
            b"setString"
                | b"setInt"
                | b"setLong"
                | b"setDouble"
                | b"setBoolean"
                | b"setDate"
                | b"setTimestamp"
                | b"setObject"
                | b"setNull"
                | b"setBytes"
                | b"setFloat"
                | b"setShort"
                | b"setBigDecimal"
                | b"setTime"
        )
        && call_arguments(call).len() >= 2
}

fn null_where_optional_is_expected<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if node.kind() == "variable_declarator" {
        let declaration = node.parent()?;
        let ty = declaration.child_by_field_name("type")?;
        return text(ty, src).starts_with(b"Optional").then_some(node);
    }
    let body = node.child_by_field_name("body")?;
    find_in_scope(body, SCOPE_STOPS, |n| {
        n.kind() == "return_statement"
            && n.named_child(0).is_some_and(|v| v.kind() == "null_literal")
    })
}

fn shares_non_thread_safe_type(field: Node, src: &[u8]) -> bool {
    has_modifier(field, "static")
        && field.child_by_field_name("type").is_some_and(|t| {
            matches!(
                text(t, src),
                b"SimpleDateFormat"
                    | b"DateFormat"
                    | b"Calendar"
                    | b"NumberFormat"
                    | b"DecimalFormat"
            )
        })
}

fn volatile_holds_mutable_state(field: Node, src: &[u8]) -> bool {
    if !has_modifier(field, "volatile") {
        return false;
    }
    let Some(ty) = field.child_by_field_name("type") else {
        return false;
    };
    if ty.kind() == "array_type" {
        return true;
    }
    let head = text(ty, src)
        .split(|&b| b == b'<')
        .next()
        .unwrap_or(&b""[..]);
    matches!(
        head,
        b"List"
            | b"ArrayList"
            | b"LinkedList"
            | b"Map"
            | b"HashMap"
            | b"TreeMap"
            | b"Set"
            | b"HashSet"
            | b"TreeSet"
            | b"Collection"
            | b"Date"
            | b"StringBuilder"
            | b"StringBuffer"
    )
}

fn assert_has_side_effects(assertion: Node, src: &[u8]) -> bool {
    find_node(assertion, |n| match n.kind() {
        "assignment_expression" | "update_expression" => true,
        "method_invocation" => matches!(
            method_name(n, src),
            b"remove"
                | b"add"
                | b"put"
                | b"set"
                | b"poll"
                | b"pop"
                | b"push"
                | b"offer"
                | b"clear"
                | b"delete"
                | b"next"
                | b"incrementAndGet"
                | b"getAndIncrement"
                | b"decrementAndGet"
                | b"getAndDecrement"
        ),
        _ => false,
    })
    .is_some()
}

fn compares_size_with_zero_nonsensically(binary: Node, src: &[u8]) -> bool {
    let (Some(left), Some(right)) = (
        binary.child_by_field_name("left"),
        binary.child_by_field_name("right"),
    ) else {
        return false;
    };
    let is_size = match left.kind() {
        "method_invocation" => {
            matches!(method_name(left, src), b"size" | b"length") && call_arguments(left).is_empty()
        }
        "field_access" => left
            .child_by_field_name("field")
            .is_some_and(|f| text(f, src) == b"length"),
        _ => false,
    };
    let zero = right.kind() == "decimal_integer_literal" && text(right, src) == b"0";
    is_size && zero && matches!(operator_text(binary, src), b"<" | b">=")
}

fn pattern_uses_week_year(node: Node, src: &[u8]) -> bool {
    call_arguments(node)
        .first()
        .and_then(|a| string_value(*a, src))
        .is_some_and(|p| p.windows(4).any(|w| w == b"YYYY") && !p.windows(2).any(|w| w == b"ww"))
}

fn map_key_put_twice<'t>(block: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let items = statements(block);
    items.windows(2).find_map(|pair| {
        let put = |s: Node<'t>| -> Option<(&[u8], &[u8])> {
            let call = (s.kind() == "expression_statement")
                .then(|| s.named_child(0))
                .flatten()
                .filter(|c| c.kind() == "method_invocation" && method_name(*c, src) == b"put")?;
            let object = call.child_by_field_name("object")?;
            let key = call_arguments(call).first().copied()?;
            Some((text(object, src), text(key, src)))
        };
        let (a, b) = (put(pair[0])?, put(pair[1])?);
        (a == b).then_some(pair[1])
    })
}

fn returns_this<'t>(method: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    let body = method.child_by_field_name("body")?;
    find_in_scope(body, SCOPE_STOPS, |n| {
        n.kind() == "return_statement" && n.named_child(0).is_some_and(|v| v.kind() == "this")
    })
}

pub(super) fn returns_null<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    // `toString(Object)` and other overloads are ordinary methods.
    if !parameter_types(method, src).is_empty() {
        return None;
    }
    let body = method.child_by_field_name("body")?;
    find_in_scope(body, SCOPE_STOPS, |n| {
        n.kind() == "return_statement"
            && n.named_child(0).is_some_and(|v| v.kind() == "null_literal")
    })
}

fn assertion_arguments_are_identical(call: Node, src: &[u8]) -> bool {
    // A test of equals() or compareTo() compares an object with itself on purpose.
    let mut p = call.parent();
    let mut hops = 0;
    while let Some(n) = p {
        if n.kind() == "method_declaration" {
            let name = n
                .child_by_field_name("name")
                .map_or(&b""[..], |x| text(x, src));
            if [
                &b"equal"[..],
                b"hash",
                b"compare",
                b"same",
                b"identity",
                b"reflex",
                b"symmetr",
            ]
            .iter()
            .any(|w| contains_ignoring_case(name, w))
            {
                return false;
            }
            break;
        }
        hops += 1;
        if hops > 64 {
            break;
        }
        p = n.parent();
    }
    let mut args = call_arguments(call);
    // JUnit 4 puts an optional message first.
    if args.len() >= 3 && args[0].kind() == "string_literal" {
        args.remove(0);
    }
    matches!(args.as_slice(), [a, b, ..]
        if matches!(a.kind(), "identifier" | "field_access") && text(*a, src) == text(*b, src))
}

fn record_has_array_without_equals(record: Node, src: &[u8]) -> bool {
    let Some(params) = record.child_by_field_name("parameters") else {
        return false;
    };
    let mut cursor = params.walk();
    let has_array = params.named_children(&mut cursor).any(|p| {
        p.child_by_field_name("type")
            .is_some_and(|t| t.kind() == "array_type")
    });
    let Some(body) = record.child_by_field_name("body") else {
        return false;
    };
    let mut c = body.walk();
    let has_equals = body.named_children(&mut c).any(|m| {
        m.kind() == "method_declaration"
            && m.child_by_field_name("name")
                .is_some_and(|n| text(n, src) == b"equals")
    });
    has_array && !has_equals
}

pub(super) fn has_annotation(declaration: Node, name: &[u8], src: &[u8]) -> bool {
    let Some(mods) = modifiers_of(declaration) else {
        return false;
    };
    let mut cursor = mods.walk();
    mods.children(&mut cursor).any(|a| {
        matches!(a.kind(), "marker_annotation" | "annotation")
            && a.child_by_field_name("name")
                .is_some_and(|n| text(n, src) == name)
    })
}

fn async_returns_a_plain_value(method: Node, src: &[u8]) -> bool {
    if !has_annotation(method, b"Async", src) {
        return false;
    }
    let Some(ty) = method.child_by_field_name("type") else {
        return false;
    };
    let head = text(ty, src)
        .split(|&b| b == b'<')
        .next()
        .unwrap_or(&b""[..]);
    !matches!(
        head,
        b"void" | b"Future" | b"CompletableFuture" | b"ListenableFuture" | b"CompletionStage"
    )
}

fn second_autowired_constructor<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let body = class.child_by_field_name("body")?;
    let mut cursor = body.walk();
    body.named_children(&mut cursor)
        .filter(|m| m.kind() == "constructor_declaration" && has_annotation(*m, b"Autowired", src))
        .nth(1)
}

pub(super) fn owning_declaration(annotation: Node) -> Option<Node> {
    annotation
        .parent()
        .filter(|m| m.kind() == "modifiers")
        .and_then(|m| m.parent())
}

fn sibling_is_qualifier(annotation: Node, src: &[u8]) -> bool {
    owning_declaration(annotation)
        .is_some_and(|d| d.kind() == "method_declaration" && has_annotation(d, b"Qualifier", src))
}

fn annotated_method_has_parameters(annotation: Node, _: &[u8]) -> bool {
    owning_declaration(annotation)
        .filter(|d| d.kind() == "method_declaration")
        .and_then(|d| d.child_by_field_name("parameters"))
        .is_some_and(|p| p.named_child_count() > 0)
}

fn listener_has_too_many_parameters(annotation: Node, _: &[u8]) -> bool {
    owning_declaration(annotation)
        .filter(|d| d.kind() == "method_declaration")
        .and_then(|d| d.child_by_field_name("parameters"))
        .is_some_and(|p| p.named_child_count() > 1)
}

fn clamp_bounds_are_reversed(call: Node, src: &[u8]) -> bool {
    let args = call_arguments(call);
    let [_, min, max] = args.as_slice() else {
        return false;
    };
    let value = |n: &Node| -> Option<i64> {
        (n.kind() == "decimal_integer_literal")
            .then(|| {
                String::from_utf8_lossy(text(*n, src))
                    .trim_end_matches(['l', 'L'])
                    .parse()
                    .ok()
            })
            .flatten()
    };
    matches!((value(min), value(max)), (Some(a), Some(b)) if a > b)
}

fn compares_result_with_one(binary: Node, src: &[u8]) -> bool {
    let Some(right) = binary.child_by_field_name("right") else {
        return false;
    };
    matches!(operator_text(binary, src), b"==" | b"!=") && matches!(text(right, src), b"1" | b"-1")
}

fn shift_amount_is_out_of_range(binary: Node, src: &[u8]) -> bool {
    let Some(right) = binary.child_by_field_name("right") else {
        return false;
    };
    matches!(operator_text(binary, src), b"<<" | b">>" | b">>>")
        && right.kind() == "decimal_integer_literal"
        && String::from_utf8_lossy(text(right, src))
            .parse::<u64>()
            .is_ok_and(|n| n == 0 || n >= 64)
}

fn is_double_checked_locking(statement: Node, src: &[u8]) -> bool {
    let (Some(condition), Some(body)) = (
        statement.child_by_field_name("condition"),
        statement.child_by_field_name("consequence"),
    ) else {
        return false;
    };
    let is_null_check = |c: Node| {
        let inner = if c.kind() == "parenthesized_expression" {
            c.named_child(0)
        } else {
            Some(c)
        };
        inner.is_some_and(|i| {
            i.kind() == "binary_expression"
                && operator_text(i, src) == b"=="
                && i.child_by_field_name("right")
                    .is_some_and(|r| r.kind() == "null_literal")
        })
    };
    if !is_null_check(condition) {
        return false;
    }
    let field = condition
        .named_child(0)
        .and_then(|c| c.child_by_field_name("left"))
        .map_or(&b""[..], |l| text(l, src));
    // A volatile field makes the idiom correct.
    let volatile = src.split(|&b| b == b'\n').any(|line| {
        line.windows(8).any(|w| w == b"volatile")
            && line.windows(field.len().max(1)).any(|w| w == field)
    });
    if volatile {
        return false;
    }
    let Some(sync) = find_node(body, |n| n.kind() == "synchronized_statement") else {
        return false;
    };
    find_node(sync, |n| {
        n.kind() == "if_statement"
            && n.child_by_field_name("condition")
                .is_some_and(|c| text(c, src) == text(condition, src))
    })
    .is_some()
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
    fn equals_and_hash_code() {
        let src = "class A {\npublic boolean equals(A o) { return true; }\n}\nclass B {\npublic boolean equals(Object o) { return true; }\n}\nclass C {\npublic boolean equals(Object o) { return true; }\npublic int hashCode() { return 1; }\n}\nrecord R(int x) {\npublic boolean equals(Object o) { return true; }\n}";
        assert_eq!(flagged("java/equals-parameter", src), [2]);
        assert_eq!(flagged("java/equals-without-hashcode", src), [5]);
    }

    #[test]
    fn method_names_and_finalize() {
        let src = "class A {\npublic String tostring() { return \"\"; }\npublic String toString() { return \"\"; }\npublic int hashcode() { return 1; }\npublic boolean equal(Object o) { return true; }\nprotected void finalize() throws Throwable {}\nvoid finalize(int x) {}\nvoid g() { x.finalize(); super.finalize(); }\n}";
        assert_eq!(flagged("java/misspelled-method-name", src), [2, 4, 5]);
        assert_eq!(flagged("java/finalize-signature", src), [7]);
        assert_eq!(flagged("java/finalize-called", src), [8]);
    }

    #[test]
    fn loops_and_conditions() {
        let src = "class A { void f() {\nfor (int i = 0; i < n; i++) { return; }\nfor (int i = 0; i < n; i++) { if (a) { return; } }\nfor (int i = 0; i < n; i++) { for (;;) { continue; } break; }\nwhile (true) { work(); break; }\nfor (int i = 0; i < 10; i--) {}\nfor (int i = 10; i > 0; i--) {}\nfor (int i = 10; i > 0; i++) {}\nif (a) { f(); } else if (b) { g(); } else if (a) { h(); }\nif (c) { f(); } else if (d) { g(); }\n} }";
        assert_eq!(flagged("java/single-iteration-loop", src), [2, 4, 5]);
        assert_eq!(flagged("java/loop-direction", src), [6, 8]);
        assert_eq!(flagged("java/duplicate-condition", src), [9]);
    }

    #[test]
    fn operands_and_assignments() {
        let src = "class A { int x; void f(int y) {\nboolean r = a > a;\nboolean s = a != a;\nboolean t = f() > f();\nint u = a - a;\nx = x;\nx = y;\nint i = 0; i = i++;\ni = j++;\n} }";
        assert_eq!(flagged("java/identical-operands", src), [2, 5]);
        assert_eq!(flagged("java/self-assignment", src), [6]);
        assert_eq!(flagged("java/useless-increment", src), [8]);
    }

    #[test]
    fn format_strings() {
        let src = "class A { void f() {\nString.format(\"%s and %s\", a);\nString.format(\"%s and %s\", a, b);\nString.format(\"%s\", a, b);\nString.format(\"%d%%\", 5);\nString.format(\"%s %s\", args);\nSystem.out.printf(\"%s\\n\", a, b);\n\"%s %s\".formatted(a);\nString.format(\"%1$s %1$s\", a);\nlog.format(\"%s\", a, b);\n} }";
        assert_eq!(flagged("java/format-arguments", src), [4, 7]);
    }

    #[test]
    fn interrupts_and_locks() {
        let src = "class A { void f() {\ntry { w(); } catch (InterruptedException e) { log(e); }\ntry { w(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }\ntry { w(); } catch (InterruptedException e) { throw new RuntimeException(e); }\nsynchronized (lock) { Thread.sleep(1); }\nThread.sleep(1);\nsynchronized (\"x\") { }\nsynchronized (lock) { }\n} }";
        assert_eq!(flagged("java/interrupt-swallowed", src), [2]);
        assert_eq!(flagged("java/sleep-while-locked", src), [5]);
        assert_eq!(flagged("java/synchronized-on-literal", src), [7]);
    }

    #[test]
    fn double_checked_locking_needs_a_non_volatile_field() {
        let bad = "class A {\nstatic Object inst;\nstatic Object get() {\nif (inst == null) {\nsynchronized (A.class) {\nif (inst == null) { inst = new Object(); }\n}\n}\nreturn inst;\n}\n}";
        assert_eq!(flagged("java/double-checked-locking", bad), [4]);
        let good = bad.replace("static Object inst;", "static volatile Object inst;");
        assert!(flagged("java/double-checked-locking", &good).is_empty());
    }

    #[test]
    fn iterators() {
        let src = "class A implements Iterator<String> {\npublic boolean hasNext() { return it.next() != null; }\npublic String next() { return \"\"; }\n}\nclass B implements Iterator<String> {\npublic boolean hasNext() { return true; }\npublic String next() { throw new NoSuchElementException(); }\n}\nclass C implements Iterable<String>, Iterator<String> {\npublic Iterator<String> iterator() { return this; }\npublic boolean hasNext() { return false; }\npublic String next() { throw new NoSuchElementException(); }\n}";
        assert_eq!(flagged("java/hasnext-calls-next", src), [2]);
        assert_eq!(flagged("java/iterator-next-exception", src), [3]);
        assert_eq!(flagged("java/iterator-returns-this", src), [10]);
    }

    #[test]
    fn serialization_signatures() {
        let src = "class A implements Serializable {\nvoid writeObject(ObjectOutputStream o) {}\nprivate void readObject(ObjectInputStream i) {}\nObject readResolve() { return this; }\nint readResolve(int x) { return 1; }\n}\nclass B {\nvoid writeObject(ObjectOutputStream o) {}\n}";
        assert_eq!(flagged("java/serialization-signature", src), [2, 5]);
    }

    #[test]
    fn small_checks() {
        let src = "class A { void f() {\nnew Date(2024, 12, 1);\nnew Date(2024, 11, 31);\nnew BigDecimal(0.1);\nnew BigDecimal(\"0.1\");\nlist.addAll(list);\nlist.addAll(other);\nnew Random().nextInt(5);\nMath.abs(k.hashCode());\nMath.abs(r.nextInt(5));\nMath.abs(r.nextInt());\nps.setString(0, a);\nps.setString(1, a);\nx.compareTo(y) == 1;\nx.compareTo(y) > 0;\nint s = a << 0;\nint t = a << 70;\nint u = a << 3;\n} }";
        assert_eq!(flagged("java/invalid-date", src), [2]);
        assert_eq!(flagged("java/bigdecimal-double", src), [4]);
        assert_eq!(flagged("java/collection-self-argument", src), [6]);
        assert_eq!(flagged("java/random-per-call", src), [8]);
        assert_eq!(flagged("java/abs-of-unbounded", src), [9, 11]);
        assert_eq!(flagged("java/prepared-statement-index", src), [12]);
        assert_eq!(flagged("java/compareto-specific-value", src), [14]);
        assert_eq!(flagged("java/shift-out-of-range", src), [16, 17]);
    }

    #[test]
    fn fields_and_declarations() {
        let src = "class A {\nstatic final SimpleDateFormat F = new SimpleDateFormat(\"yyyy\");\nstatic final DateTimeFormatter G = null;\nvolatile List<String> items;\nvolatile boolean ready;\nvolatile String name;\nOptional<String> o = null;\nOptional<String> p = Optional.empty();\nString q = null;\nOptional<String> get() { return null; }\nOptional<String> ok() { return Optional.empty(); }\n}";
        assert_eq!(flagged("java/non-thread-safe-static", src), [2]);
        assert_eq!(flagged("java/volatile-mutable-field", src), [4]);
        assert_eq!(flagged("java/optional-null", src), [7, 10]);
    }

    #[test]
    fn dates_maps_and_asserts() {
        let src = "class A { void f() {\nnew SimpleDateFormat(\"YYYY-MM-dd\");\nnew SimpleDateFormat(\"YYYY-ww\");\nDateTimeFormatter.ofPattern(\"YYYY\");\nm.put(k, 1);\nm.put(k, 2);\nm.put(k, 3);\nm.put(j, 3);\nassertEquals(a, a);\nassertEquals(\"msg\", a, a);\nassertEquals(a, b);\nassert list.remove(x);\nassert list.isEmpty();\nboolean z = list.size() < 0;\nboolean y = list.size() > 0;\nboolean w = arr.length >= 0;\n} }";
        assert_eq!(flagged("java/week-year", src), [2, 4]);
        assert_eq!(flagged("java/map-value-replaced", src), [6]);
        assert_eq!(flagged("java/assertion-compares-same-object", src), [9, 10]);
        assert_eq!(flagged("java/assert-side-effects", src), [12]);
        assert_eq!(flagged("java/size-comparison", src), [14, 16]);
    }

    #[test]
    fn spring_checks() {
        let src = "class A {\n@Async String work() { return \"\"; }\n@Async CompletableFuture<String> ok() { return null; }\n@Async void v() {}\n@Autowired A(B b) {}\n@Autowired A(C c) {}\n@Bean @Qualifier(\"x\") B b() { return null; }\n@Bean B c() { return null; }\n@Scheduled(fixedRate = 1) void tick(int x) {}\n@Scheduled(fixedRate = 1) void tock() {}\n@EventListener void on(Foo f, Bar b) {}\n@EventListener void one(Foo f) {}\n}";
        assert_eq!(flagged("java/async-return-type", src), [2]);
        assert_eq!(flagged("java/autowired-constructors", src), [6]);
        assert_eq!(flagged("java/qualifier-on-bean", src), [7]);
        assert_eq!(flagged("java/scheduled-with-arguments", src), [9]);
        assert_eq!(flagged("java/event-listener-parameters", src), [11]);
    }

    #[test]
    fn miscellaneous() {
        let src = "class A { void f() {\ns.split(\".\");\ns.split(\"\\\\.\");\ns.replaceAll(\"|\", \"x\");\nin.read(buf);\nint n = in.read(buf);\nin.readLine();\nString l = in.readLine();\nlock.notify();\nlock.notifyAll();\nnew Thread(r).run();\nnew Thread(r).start();\nnew IllegalStateException(\"x\");\nthrow new IllegalStateException(\"x\");\nMath.clamp(v, 10, 1);\nMath.clamp(v, 1, 10);\nboolean r = !!flag;\nint s = Integer.valueOf(x).intValue();\nnew StringBuilder('c');\n} }";
        assert_eq!(flagged("java/regex-metacharacter", src), [2, 4]);
        assert_eq!(flagged("java/read-result-ignored", src), [5, 7]);
        assert_eq!(flagged("java/notify-single", src), [9]);
        assert_eq!(flagged("java/thread-run-direct", src), [11]);
        assert_eq!(flagged("java/exception-not-thrown", src), [13]);
        assert_eq!(flagged("java/clamp-range", src), [15]);
        assert_eq!(flagged("java/repeated-unary-operator", src), [17]);
        assert_eq!(flagged("java/boxing-roundtrip", src), [18]);
        assert_eq!(flagged("java/string-builder-char", src), [19]);
    }

    #[test]
    fn false_positives_found_in_real_code() {
        let src = "class T {\nvoid testEquals() { assertEquals(a, a); }\nvoid testIt() { assertEquals(a, a); }\nvoid g() { boolean r = false ^ false; }\nString toString(Object o) { return null; }\nvoid h() { bf.setBoolean(0, true); stmt.setBoolean(0, true); }\nvoid i() { outer: for (int k = 0; k < n; k++) { for (int j = 0; j < m; j++) { continue outer; } break; } }\n}\nclass U {\npublic boolean equals(U o) { return true; }\npublic boolean equals(Object o) { return true; }\npublic int hashCode() { return 1; }\n}";
        assert_eq!(flagged("java/assertion-compares-same-object", src), [3]);
        assert!(flagged("java/identical-operands", src).is_empty());
        assert!(flagged("java/null-returned-by-object-method", src).is_empty());
        assert_eq!(flagged("java/prepared-statement-index", src), [6]);
        assert!(flagged("java/single-iteration-loop", src).is_empty());
        assert!(flagged("java/equals-parameter", src).is_empty());
    }

    #[test]
    fn thread_subclasses_and_records() {
        let src = "class W extends Thread { void other() {} }\nclass X extends Thread { public void run() {} }\nclass Y extends Thread { Y(Runnable r) { super(r); } }\nrecord R(int[] v) {}\nrecord S(int[] v) { public boolean equals(Object o) { return true; } }\nrecord T(int v) {}";
        assert_eq!(flagged("java/thread-without-run", src), [1]);
        assert_eq!(flagged("java/record-array-component", src), [4]);
    }
}
