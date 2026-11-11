//! Java code-smell rules, part 1 (ADR-0007, batch 8): naming, structure and
//! common idioms. Queries stay cheap on deep trees: see `js_modern.rs`.

use super::java_bugs::{
    find_in_scope, has_annotation, has_modifier, modifiers_of, no_arguments, operator_text,
    owning_declaration, parameter_types, statements,
};
use super::java_extra::{declared_type, type_text};
use super::java_security::{
    call_arguments, contains_ignoring_case, find_node, is_all_literals, method_name, string_value,
    text,
};
use super::prelude::*;

/// This module's rules that are off unless `rules.enabled` lists them
/// (see `catalog::OFF_BY_DEFAULT`).
pub(super) static OFF_BY_DEFAULT: &[&str] = &[
    // Pattern matching for instanceof and Stream.toList() need Java 16, and
    // sonda cannot see which version a project targets.
    "java/instanceof-then-cast",
    "java/collectors-to-list",
];

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "java/class-name",
        name: "Class names should comply with a naming convention",
        description: "PascalCase marks a name as a type.",
        message: "Rename this class to PascalCase.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S101")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration name: (identifier) @n) @match"#,
            filter: Some(Keep(class_name_not_pascal)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class my_widget {}",
            good: "class MyWidget {}",
        }),
    },
    Rule {
        id: "java/interface-name",
        name: "Interface names should comply with a naming convention",
        description: "PascalCase marks a name as a type.",
        message: "Rename this interface to PascalCase.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S114")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(interface_declaration name: (identifier) @n) @match"#,
            filter: Some(Keep(class_name_not_pascal)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "interface my_api {}",
            good: "interface MyApi {}",
        }),
    },
    Rule {
        id: "java/method-name",
        name: "Method names should comply with a naming convention",
        description: "Methods are camelCase, which tells them apart from types.",
        message: "Rename this method to camelCase.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S100")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration name: (identifier) @n) @match"#,
            filter: Some(Keep(method_name_not_camel_case)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void Do_it() {} }",
            good: "class A { void doIt() {} }",
        }),
    },
    Rule {
        id: "java/constant-name",
        name: "Constant names should comply with a naming convention",
        description: "UPPER_SNAKE_CASE marks a static final field as a constant.",
        message: "Rename this constant to UPPER_SNAKE_CASE.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S115")],
        check: Check::Query {
            langs: JAVA,
            query: r#"[(field_declaration) (constant_declaration) (enum_constant)] @match"#,
            filter: Some(Keep(constant_name_not_upper_snake)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { static final int maxSize = 3; }",
            good: "class A { static final int MAX_SIZE = 3; }",
        }),
    },
    Rule {
        id: "java/field-name",
        name: "Field names should comply with a naming convention",
        description: "Fields are camelCase.",
        message: "Rename this field to camelCase.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S116")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(field_declaration) @match"#,
            filter: Some(Keep(field_name_not_camel_case)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { int My_field; }",
            good: "class A { int myField; }",
        }),
    },
    Rule {
        id: "java/local-variable-name",
        name: "Local variable and parameter names should comply with a naming convention",
        description: "Variables are camelCase.",
        message: "Rename this variable to camelCase.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S117")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(variable_declarator name: (identifier) @n) @match
(formal_parameter name: (identifier) @n2) @match
(inferred_parameters (identifier) @match)
(lambda_expression parameters: (identifier) @match)"#,
            filter: Some(Keep(local_name_not_camel_case)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(int My_param) {} }",
            good: "class A { void f(int myParam) {} }",
        }),
    },
    Rule {
        id: "java/type-parameter-name",
        name: "Type parameter names should comply with a naming convention",
        description: "A single capital letter, optionally followed by a digit, is the convention.",
        message: "Rename this type parameter.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S119")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(type_parameter (type_identifier) @n) @match"#,
            filter: Some(Keep(type_parameter_name_is_unconventional)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A<Item> {}",
            good: "class A<T> {}",
        }),
    },
    Rule {
        id: "java/utility-class-constructor",
        name: "Utility classes should not have public constructors",
        description: "A class with only static members is never instantiated.",
        message: "Add a private constructor.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1118")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Find(utility_class_constructor_or_class)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class Util { static int f() { return 1; } }",
            good: "class Util { private Util() {} static int f() { return 1; } }",
        }),
    },
    Rule {
        id: "java/labels",
        name: "Labels should not be used",
        description: "Labels make the control flow hard to follow.",
        message: "Restructure this code to avoid the label.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S1119")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(labeled_statement) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { outer: for (;;) { break outer; } } }",
            good: "class A { void f() { for (;;) { break; } } }",
        }),
    },
    Rule {
        id: "java/assignment-in-subexpression",
        name: "Assignments should not be made from within sub-expressions",
        description: "`if ((x = f()) > 0)` hides an assignment in a condition.",
        message: "Move this assignment out of the expression.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1121")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(assignment_expression) @match"#,
            filter: Some(Keep(assigns_inside_an_expression)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { int x; if ((x = g()) > 0) {} } }",
            good: "class A { void f() { int x = g(); if (x > 0) {} } }",
        }),
    },
    Rule {
        id: "java/modifier-order",
        name: "Modifiers should be declared in the correct order",
        description: "The Java Language Specification recommends public, protected, private, abstract, static, final, transient, volatile, synchronized, native, strictfp.",
        message: "Reorder these modifiers.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S1124")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(modifiers) @match"#,
            filter: Some(Keep(modifiers_out_of_order)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { final static int X = 1; }",
            good: "class A { static final int X = 1; }",
        }),
    },
    Rule {
        id: "java/redundant-boolean-literal",
        name: "Boolean literals should not be redundant",
        description: "`x == true` is `x`, and `cond ? true : false` is `cond`.",
        message: "Remove the boolean literal.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S1125")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(binary_expression) @match
(ternary_expression consequence: [(true) (false)] alternative: [(true) (false)]) @match"#,
            filter: Some(Keep(boolean_literal_is_redundant)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { boolean f(boolean x) { return x == true; } }",
            good: "class A { boolean f(boolean x) { return x; } }",
        }),
    },
    Rule {
        id: "java/return-boolean-if",
        name: "Return of boolean expressions should not be wrapped into an if-then-else",
        description: "`if (c) return true; else return false;` is `return c;`.",
        message: "Return the condition directly.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S1126")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(if_statement) @match"#,
            filter: Some(Keep(returns_boolean_from_both_branches)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { boolean f(int x) { if (x > 1) { return true; } else { return false; } } }",
            good: "class A { boolean f(int x) { return x > 1; } }",
        }),
    },
    Rule {
        id: "java/unused-import",
        name: "Unnecessary imports should be removed",
        description: "An unused import misleads readers about the file's dependencies.",
        message: "Remove this unused import.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S1128")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(program) @match"#,
            filter: Some(Find(first_unused_import)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "import java.util.List;\nclass A {}",
            good: "import java.util.List;\nclass A { List<String> l; }",
        }),
    },
    Rule {
        id: "java/nested-try",
        name: "Try-catch blocks should not be nested",
        description: "A try-catch inside a try block is easier to follow as its own method.",
        message: "Extract the nested try-catch.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S1141")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(try_statement body: (block (try_statement) @match))"#,
            filter: Some(Keep(nested_try_has_catch)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { try { try { g(); } catch (Exception e) {} } catch (Error e) {} } }",
            good: "class A { void f() { try { g(); } catch (Exception e) {} } }",
        }),
    },
    Rule {
        id: "java/enumeration",
        name: "Enumeration should not be implemented",
        description: "Enumeration is a legacy interface; Iterator replaced it.",
        message: "Implement Iterator instead.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S1150")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration (super_interfaces) @i) @match"#,
            filter: Some(Keep(implements_enumeration)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A implements Enumeration<String> { public boolean hasMoreElements() { return false; } public String nextElement() { return null; } }",
            good: "class A implements Iterator<String> { public boolean hasNext() { return false; } public String next() { return null; } }",
        }),
    },
    Rule {
        id: "java/value-of-in-concatenation",
        name: "String.valueOf() should not be appended to a String",
        description: "Concatenation already converts the value.",
        message: "Remove the String.valueOf() call.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S1153")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(binary_expression) @match"#,
            filter: Some(Keep(appends_string_value_of)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { String f(int x) { return \"a\" + String.valueOf(x); } }",
            good: "class A { String f(int x) { return \"a\" + x; } }",
        }),
    },
    Rule {
        id: "java/size-compared-to-zero",
        name: "Collection.isEmpty() should be used to test for emptiness",
        description: "isEmpty() says what is meant, and is cheaper on some collections.",
        message: "Use isEmpty().",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S1155")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(binary_expression) @match"#,
            filter: Some(Keep(compares_size_with_zero_for_emptiness)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { boolean f(List<String> l) { return l.size() == 0; } }",
            good: "class A { boolean f(List<String> l) { return l.isEmpty(); } }",
        }),
    },
    Rule {
        id: "java/case-conversion-before-equals",
        name: "Case insensitive string comparisons should be made without intermediate allocations",
        description: "`a.toLowerCase().equals(b)` builds a throwaway string.",
        message: "Use equalsIgnoreCase().",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S1157")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (method_invocation name: (identifier) @c (#any-of? @c "toLowerCase" "toUpperCase")) name: (identifier) @n (#eq? @n "equals")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { boolean f(String a, String b) { return a.toLowerCase().equals(b); } }",
            good: "class A { boolean f(String a, String b) { return a.equalsIgnoreCase(b); } }",
        }),
    },
    Rule {
        id: "java/boxing-for-to-string",
        name: "Primitive wrappers should not be instantiated only for toString",
        description: "`new Integer(x).toString()` is `Integer.toString(x)`.",
        message: "Call the static toString.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S1158")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (object_creation_expression type: (type_identifier) @t (#any-of? @t "Integer" "Long" "Double" "Float" "Short" "Byte" "Boolean" "Character")) name: (identifier) @n (#eq? @n "toString")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { String f(int x) { return new Integer(x).toString(); } }",
            good: "class A { String f(int x) { return Integer.toString(x); } }",
        }),
    },
    Rule {
        id: "java/throw-in-finally",
        name: "Exceptions should not be thrown in finally blocks",
        description: "A throw in finally replaces any exception already propagating.",
        message: "Remove the throw from the finally block.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S1163")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(finally_clause) @match"#,
            filter: Some(Find(throw_in_finally)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { try { g(); } finally { throw new RuntimeException(); } } }",
            good: "class A { void f() { try { g(); } finally { close(); } } }",
        }),
    },
    Rule {
        id: "java/exception-field-not-final",
        name: "Exception classes should have final fields",
        description: "Exceptions are passed between threads; mutable state in them invites races.",
        message: "Make this field final.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S1165")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration superclass: (superclass (type_identifier) @s (#match? @s "(Exception|Error)$"))) @match"#,
            filter: Some(Find(non_final_instance_field)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class MyException extends Exception { int code; }",
            good: "class MyException extends Exception { final int code = 1; }",
        }),
    },
    Rule {
        id: "java/null-instead-of-empty",
        name: "Empty arrays and collections should be returned instead of null",
        description: "Callers must then null-check before every use.",
        message: "Return an empty array or collection.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1168")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(return_statement (null_literal)) @match"#,
            filter: Some(Keep(returns_null_for_collection)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { List<String> f() { return null; } }",
            good: "class A { List<String> f() { return List.of(); } }",
        }),
    },
    Rule {
        id: "java/final-field-should-be-static",
        name: "Public constants and fields initialized at declaration should be static final",
        description: "A final field with a constant value is the same in every instance.",
        message: "Make this field static.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S1170")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(field_declaration) @match"#,
            filter: Some(Keep(final_literal_field_is_not_static)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { public final int MAX = 3; }",
            good: "class A { public static final int MAX = 3; }",
        }),
    },
    Rule {
        id: "java/instance-initializer",
        name: "Only static class initializers should be used",
        description: "An instance initializer block runs before every constructor and is easy to overlook.",
        message: "Move this code into a constructor.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1171")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_body (block) @match)"#,
            filter: Some(Keep(initializer_of_named_class)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { { init(); } }",
            good: "class A { A() { init(); } }",
        }),
    },
    Rule {
        id: "java/throwable-caught",
        name: "Throwable and Error should not be caught",
        description: "They include out-of-memory and other unrecoverable conditions.",
        message: "Catch a narrower type.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S1181")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(catch_clause) @match"#,
            filter: Some(Keep(catches_throwable)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { try { g(); } catch (Throwable t) {} } }",
            good: "class A { void f() { try { g(); } catch (IOException e) {} } }",
        }),
    },
    Rule {
        id: "java/useless-override",
        name: "Overriding methods should do more than simply call the same method in the super class",
        description: "An override that only forwards adds nothing.",
        message: "Remove this method.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S1185")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Keep(override_only_calls_super)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { @Override public String toString() { return super.toString(); } }",
            good: "class A { @Override public String toString() { return \"A\"; } }",
        }),
    },
    Rule {
        id: "java/empty-method",
        name: "Methods should not be empty",
        description: "An empty body gives no hint whether it is unfinished or deliberate.",
        message: "Implement this method, or say why it is empty.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1186")],
        check: Check::Query {
            langs: JAVA,
            query: r#"[(method_declaration) (constructor_declaration)] @match"#,
            filter: Some(Keep(method_is_empty)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() {} }",
            good: "class A { void f() { /* intentionally empty */ } }",
        }),
    },
    Rule {
        id: "java/sun-package",
        name: "Classes from sun.* packages should not be used",
        description: "They are internal, unsupported and removed in newer JDKs.",
        message: "Use the public API.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 20,
        sonar: &[exact("S1191")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(import_declaration) @match"#,
            filter: Some(Keep(imports_from_sun)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "import sun.misc.Unsafe;\nclass A {}",
            good: "import java.util.List;\nclass A {}",
        }),
    },
    Rule {
        id: "java/array-designator-on-method",
        name: "Array designators [] should be located after the type in method signatures",
        description: "`int foo()[]` is legal but obscure.",
        message: "Put [] after the return type.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S1195")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration dimensions: (dimensions)) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { int foo()[] { return null; } }",
            good: "class A { int[] foo() { return null; } }",
        }),
    },
    Rule {
        id: "java/array-designator-on-variable",
        name: "Array designators [] should be on the type, not the variable",
        description: "`int a[]` mixes the type into the name.",
        message: "Put [] on the type.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S1197")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(variable_declarator dimensions: (dimensions)) @match
(formal_parameter dimensions: (dimensions)) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(String args[]) {} }",
            good: "class A { void f(String[] args) {} }",
        }),
    },
    Rule {
        id: "java/nested-block",
        name: "Nested code blocks should not be used",
        description: "A bare block inside a block adds a level of nesting without meaning.",
        message: "Remove the nested block.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S1199")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(block (block) @match)"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { { g(); } } }",
            good: "class A { void f() { g(); } }",
        }),
    },
    Rule {
        id: "java/compareto-without-equals",
        name: "equals(Object) should be overridden along with compareTo",
        description: "compareTo that disagrees with equals makes sorted collections behave differently from hash collections.",
        message: "Override equals as well.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S1210")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_body) @match"#,
            filter: Some(Find(compare_to_without_equals)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A implements Comparable<A> { public int compareTo(A o) { return 0; } }",
            good: "class A implements Comparable<A> { public int compareTo(A o) { return 0; } public boolean equals(Object o) { return true; } }",
        }),
    },
    Rule {
        id: "java/constants-interface",
        name: "Interfaces should not solely consist of constants",
        description: "An interface is a contract, not a place to hold constants.",
        message: "Use a final class with a private constructor.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 10,
        sonar: &[exact("S1214")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(interface_declaration) @match"#,
            filter: Some(Keep(interface_only_holds_constants)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "interface K { int A = 1; }",
            good: "interface K { void f(); }",
        }),
    },
    Rule {
        id: "java/explicit-gc",
        name: "Execution of the Garbage Collector should be triggered only by the JVM",
        description: "Forcing a collection hurts performance and rarely helps.",
        message: "Remove this gc() call.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S1215")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "gc")) @match"#,
            filter: Some(Keep(is_system_or_runtime_gc)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { System.gc(); } }",
            good: "class A { void f() { g(); } }",
        }),
    },
    Rule {
        id: "java/default-package",
        name: "The default unnamed package should not be used",
        description: "Classes in the default package cannot be imported from named packages.",
        message: "Declare a package.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S1220")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(program) @match"#,
            filter: Some(Find(class_without_package)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A {}",
            good: "package com.acme;\nclass A {}",
        }),
    },
    Rule {
        id: "java/method-named-like-class",
        name: "Non-constructor methods should not have the same name as the enclosing class",
        description: "It reads like a constructor but is not one.",
        message: "Rename this method.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S1223")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Keep(method_named_like_its_class)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void A() {} }",
            good: "class A { void init() {} }",
        }),
    },
    Rule {
        id: "java/for-as-while",
        name: "A while loop should be used instead of a for loop",
        description: "A for with only a condition is a while.",
        message: "Use while.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S1264")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(for_statement) @match"#,
            filter: Some(Keep(for_has_only_a_condition)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { for (; i < 3; ) { i++; } } }",
            good: "class A { void f() { while (i < 3) { i++; } } }",
        }),
    },
    Rule {
        id: "java/switch-too-few-cases",
        name: "switch statements should have at least 3 case clauses",
        description: "A switch with one or two cases is an if.",
        message: "Use if instead.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S1301")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(switch_expression) @match"#,
            filter: Some(Keep(switch_has_fewer_than_three_cases)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(int x) { switch (x) { case 1: g(); break; default: h(); } } }",
            good: "class A { void f(int x) { if (x == 1) { g(); } else { h(); } } }",
        }),
    },
    Rule {
        id: "java/concrete-collection-type",
        name: "Declarations should use Java collection interfaces",
        description: "Declaring ArrayList or HashMap ties the code to one implementation.",
        message: "Declare the interface type.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S1319")],
        check: Check::Query {
            langs: JAVA,
            query: r#"((type_identifier) @match (#any-of? @match "ArrayList" "LinkedList" "HashMap" "LinkedHashMap" "TreeMap" "HashSet" "LinkedHashSet" "TreeSet" "Vector" "Hashtable" "EnumSet" "EnumMap" "IdentityHashMap"))"#,
            filter: Some(Keep(is_a_declared_type)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { ArrayList<String> items; }",
            good: "class A { List<String> items; }",
        }),
    },
    Rule {
        id: "java/wildcard-return-type",
        name: "Generic wildcard types should not be used in return types",
        description: "The caller can't do much with a wildcard result.",
        message: "Return a specific type.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S1452")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration type: (generic_type (type_arguments (wildcard)))) @match"#,
            filter: Some(Keep(wildcard_is_not_a_class)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { List<?> f() { return null; } }",
            good: "class A { List<String> f() { return null; } }",
        }),
    },
    Rule {
        id: "java/switch-too-many-cases",
        name: "switch statements should not have too many case clauses",
        description: "A very long switch is hard to read.",
        message: "Split this switch up.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 30,
        sonar: &[exact("S1479")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(switch_expression) @match"#,
            filter: Some(Keep(switch_has_many_cases)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(int x) { switch (x) { case 0: g(); break; case 1: g(); break; case 2: g(); break; case 3: g(); break; case 4: g(); break; case 5: g(); break; case 6: g(); break; case 7: g(); break; case 8: g(); break; case 9: g(); break; case 10: g(); break; case 11: g(); break; case 12: g(); break; case 13: g(); break; case 14: g(); break; case 15: g(); break; case 16: g(); break; case 17: g(); break; case 18: g(); break; case 19: g(); break; case 20: g(); break; case 21: g(); break; case 22: g(); break; case 23: g(); break; case 24: g(); break; case 25: g(); break; case 26: g(); break; case 27: g(); break; case 28: g(); break; case 29: g(); break; case 30: g(); break; default: h(); } } }",
            good: "class A { void f(int x) { switch (x) { case 1: g(); break; default: h(); } } }",
        }),
    },
    Rule {
        id: "java/return-after-assignment",
        name: "Local variables should not be declared and then immediately returned",
        description: "The variable adds nothing.",
        message: "Return the expression directly.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S1488")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(block) @match"#,
            filter: Some(Find(variable_returned_immediately)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { int f() { int x = g(); return x; } }",
            good: "class A { int f() { return g(); } }",
        }),
    },
    Rule {
        id: "java/empty-collection-constant",
        name: "Collections.EMPTY_LIST, EMPTY_MAP and EMPTY_SET should not be used",
        description: "They are raw types that lose their generics.",
        message: "Use Collections.emptyList(), emptyMap() or emptySet().",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 2,
        sonar: &[exact("S1596")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(field_access object: (identifier) @o field: (identifier) @f (#eq? @o "Collections") (#any-of? @f "EMPTY_LIST" "EMPTY_MAP" "EMPTY_SET")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { Object f() { return Collections.EMPTY_LIST; } }",
            good: "class A { Object f() { return Collections.emptyList(); } }",
        }),
    },
    Rule {
        id: "java/lambda-single-statement-block",
        name: "Lambdas containing only one statement should not nest this statement in a block",
        description: "`x -> { return f(x); }` is `x -> f(x)`.",
        message: "Use the expression form.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S1602")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(lambda_expression body: (block)) @match"#,
            filter: Some(Keep(lambda_block_holds_one_statement)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { run(x -> { return g(x); }); } }",
            good: "class A { void f() { run(x -> g(x)); } }",
        }),
    },
    Rule {
        id: "java/anonymous-class-to-lambda",
        name: "Anonymous inner classes containing only one method should become lambdas",
        description: "A lambda is shorter and says the same.",
        message: "Use a lambda.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1604")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(object_creation_expression type: (type_identifier) @t (#any-of? @t "Runnable" "Callable" "Comparator" "Supplier" "Consumer" "Function" "Predicate" "BiFunction" "BiConsumer" "UnaryOperator" "BinaryOperator") (class_body)) @match"#,
            filter: Some(Keep(anonymous_class_has_one_method)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { Runnable r = new Runnable() { public void run() { g(); } }; }",
            good: "class A { Runnable r = () -> g(); }",
        }),
    },
    Rule {
        id: "java/lambda-parenthesized-parameter",
        name: "Parentheses should be removed from a single lambda parameter when its type is inferred",
        description: "`(x) -> ...` is `x -> ...`.",
        message: "Remove the parentheses.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S1611")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(lambda_expression parameters: (inferred_parameters)) @match"#,
            filter: Some(Keep(single_parenthesized_parameter)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { run((x) -> g(x)); } }",
            good: "class A { void f() { run(x -> g(x)); } }",
        }),
    },
    Rule {
        id: "java/lambda-to-method-reference",
        name: "Lambdas should be replaced with method references",
        description: "`x -> f(x)` is `this::f`, and `x -> x.m()` is `X::m`.",
        message: "Use a method reference.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S1612")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(lambda_expression) @match"#,
            filter: Some(Keep(lambda_only_forwards_its_parameter)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { run(x -> g(x)); } }",
            good: "class A { void f() { run(this::g); } }",
        }),
    },
    Rule {
        id: "java/string-concatenation-in-loop",
        name: "Strings should not be concatenated using + in a loop",
        description: "Each += copies the whole string again.",
        message: "Use a StringBuilder.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S1643")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(assignment_expression left: (identifier) operator: "+=") @match"#,
            filter: Some(Keep(concatenates_a_string_in_a_loop)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { String f() { String s = \"\"; for (int i = 0; i < 9; i++) { s += \"x\"; } return s; } }",
            good: "class A { String f() { StringBuilder s = new StringBuilder(); for (int i = 0; i < 9; i++) { s.append(\"x\"); } return s.toString(); } }",
        }),
    },
    Rule {
        id: "java/multiple-variables-per-line",
        name: "Multiple variables should not be declared on the same line",
        description: "One declaration per line is easier to read and to change.",
        message: "Declare each variable separately.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S1659")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(local_variable_declaration) @match
(field_declaration) @match"#,
            filter: Some(Keep(declares_several_variables)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { int a = 1, b = 2; } }",
            good: "class A { void f() { int a = 1; int b = 2; } }",
        }),
    },
    Rule {
        id: "java/field-named-like-class",
        name: "A field should not duplicate the name of its containing class",
        description: "It reads like a constructor call or a type.",
        message: "Rename this field.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S1700")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(field_declaration) @match"#,
            filter: Some(Keep(field_named_like_its_class)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { int A; }",
            good: "class A { int count; }",
        }),
    },
    Rule {
        id: "java/names-differ-by-case",
        name: "Method and field names should not be the same or differ only by capitalization",
        description: "`getValue` and `getvalue` are easy to confuse.",
        message: "Rename one of them.",
        category: CodeSmell,
        severity: Blocker,
        effort_minutes: 5,
        sonar: &[exact("S1845")],
        check: Check::Query {
            langs: JAVA,
            query: r#"[(field_declaration) (constant_declaration) (method_declaration)] @match"#,
            filter: Some(Keep(name_differs_by_case_only)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { int value; int Value() { return 0; } }",
            good: "class A { int value; int size() { return 0; } }",
        }),
    },
    Rule {
        id: "java/to-string-on-string",
        name: "toString() should never be called on a String object",
        description: "It returns the same string.",
        message: "Remove the toString() call.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 1,
        sonar: &[exact("S1858")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (string_literal) name: (identifier) @n (#eq? @n "toString")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { String f() { return \"x\".toString(); } }",
            good: "class A { String f() { return \"x\"; } }",
        }),
    },
    Rule {
        id: "java/inverted-boolean",
        name: "Boolean checks should not be inverted",
        description: "`!(a == b)` is `a != b`.",
        message: "Use the opposite operator.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S1940")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(unary_expression operator: "!" operand: (parenthesized_expression (binary_expression))) @match"#,
            filter: Some(Keep(negates_a_comparison)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { boolean f(int a, int b) { return !(a == b); } }",
            good: "class A { boolean f(int a, int b) { return a != b; } }",
        }),
    },
    Rule {
        id: "java/empty-class",
        name: "Classes should not be empty",
        description: "An empty class gives no hint what it is for.",
        message: "Add members or remove the class.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2094")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Keep(class_is_empty)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class Empty {}",
            good: "class Marker { int id; }",
        }),
    },
    Rule {
        id: "java/wrapper-constructor",
        name: "Constructors should not be used to instantiate String and primitive wrappers",
        description: "They always create a new object, where valueOf can share one.",
        message: "Use a literal or valueOf.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2129")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(object_creation_expression type: (type_identifier) @t (#any-of? @t "String" "Integer" "Long" "Double" "Float" "Short" "Byte" "Boolean" "Character" "BigInteger" "BigDecimal")) @match"#,
            filter: Some(Keep(literal_or_value_of_would_do)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { String f() { return new String(\"x\"); } }",
            good: "class A { String f() { return \"x\"; } }",
        }),
    },
    Rule {
        id: "java/object-for-get-class",
        name: "Objects should not be created only to invoke getClass",
        description: "Use the class literal.",
        message: "Use Foo.class.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2133")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (object_creation_expression) name: (identifier) @n (#eq? @n "getClass")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { Object f() { return new Date().getClass(); } }",
            good: "class A { Object f() { return Date.class; } }",
        }),
    },
    Rule {
        id: "java/legacy-date-time",
        name: "java.time classes should be used for dates and times",
        description: "Date and Calendar are mutable and error-prone.",
        message: "Use java.time.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 15,
        sonar: &[exact("S2143")],
        check: Check::Query {
            langs: JAVA,
            query: r#"((type_identifier) @match (#any-of? @match "Date" "Calendar" "GregorianCalendar" "SimpleDateFormat"))
(method_invocation object: (identifier) @o name: (identifier) @n (#eq? @o "Calendar") (#eq? @n "getInstance")) @match"#,
            filter: Some(Keep(first_legacy_date_in_file)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { Object f() { return new Date(); } }",
            good: "class A { Object f() { return Instant.now(); } }",
        }),
    },
    Rule {
        id: "java/combine-catches",
        name: "Catches should be combined",
        description: "Catch blocks with the same body can use a multi-catch.",
        message: "Combine these catch blocks.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2147")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(try_statement) @match"#,
            filter: Some(Find(catch_with_same_body_as_previous)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { try { g(); } catch (IOException e) { log(e); } catch (SQLException e) { log(e); } } }",
            good: "class A { void f() { try { g(); } catch (IOException | SQLException e) { log(e); } } }",
        }),
    },
    Rule {
        id: "java/exception-class-name",
        name: "Classes named like Exception should extend Exception or a subclass",
        description: "A name ending in Exception promises something it doesn't deliver.",
        message: "Extend Exception, or rename.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2166")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration name: (identifier) @n (#match? @n "Exception$")) @match"#,
            filter: Some(Keep(has_no_superclass)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class FooException {}",
            good: "class FooException extends Exception {}",
        }),
    },
    Rule {
        id: "java/class-name-shadows-java-lang",
        name: "Class names should not shadow interfaces or superclasses",
        description: "A class named String or List confuses every reader.",
        message: "Rename this class.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S2176")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration name: (identifier) @n (#any-of? @n "String" "Object" "List" "Map" "Set" "Integer" "Long" "Exception" "Thread" "Runnable" "Iterator" "Collection")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class List {}",
            good: "class Items {}",
        }),
    },
    Rule {
        id: "java/non-short-circuit",
        name: "Short-circuit logic should be used in boolean contexts",
        description: "& and | evaluate both sides, even when the first decides the result.",
        message: "Use && or ||.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 2,
        sonar: &[exact("S2178")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(binary_expression) @match"#,
            filter: Some(Keep(uses_non_short_circuit_operator)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { boolean f(int a, int b) { return a > 1 & b > 1; } }",
            good: "class A { boolean f(int a, int b) { return a > 1 && b > 1; } }",
        }),
    },
    Rule {
        id: "java/result-set-is-last",
        name: "ResultSet.isLast() should not be used",
        description: "It is not supported by all drivers and can be expensive.",
        message: "Use next() instead.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2232")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "isLast")) @match"#,
            filter: Some(Keep(no_arguments)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { boolean f(ResultSet rs) throws Exception { return rs.isLast(); } }",
            good: "class A { boolean f(ResultSet rs) throws Exception { return rs.next(); } }",
        }),
    },
    Rule {
        id: "java/illegal-monitor-caught",
        name: "IllegalMonitorStateException should not be caught",
        description: "It signals a programming error, not a condition to handle.",
        message: "Fix the locking instead.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S2235")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(catch_clause) @match"#,
            filter: Some(Keep(catches_illegal_monitor_state)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { try { w(); } catch (IllegalMonitorStateException e) {} } }",
            good: "class A { void f() { try { w(); } catch (InterruptedException e) {} } }",
        }),
    },
    Rule {
        id: "java/mutable-public-static",
        name: "Mutable fields should not be public static",
        description: "Anyone can change the array or collection, for everyone.",
        message: "Make it private or wrap it in an unmodifiable view.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S2386")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(field_declaration) @match"#,
            filter: Some(Keep(public_static_holds_mutable_state)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { public static final String[] NAMES = { \"a\" }; }",
            good: "class A { private static final String[] NAMES = { \"a\" }; }",
        }),
    },
    Rule {
        id: "java/null-from-boolean-method",
        name: "null should not be returned from a Boolean method",
        description: "A caller that unboxes the result gets a NullPointerException.",
        message: "Return true or false.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S2447")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(return_statement (null_literal)) @match"#,
            filter: Some(Keep(returns_null_from_boolean_method)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { Boolean f() { return null; } }",
            good: "class A { Boolean f() { return false; } }",
        }),
    },
    Rule {
        id: "java/control-character-in-literal",
        name: "Whitespace and control characters in literals should be explicit",
        description: "A literal tab or other invisible character is easy to lose in an editor.",
        message: "Use \\t.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2479")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(string_literal) @match"#,
            filter: Some(Keep(contains_a_tab_character)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { String s = \"a	b\"; }",
            good: "class A { String s = \"a\\tb\"; }",
        }),
    },
    Rule {
        id: "java/log-argument-concatenation",
        name: "Logging arguments should not require evaluation",
        description: "A concatenated message is built even when the level is off.",
        message: "Use placeholders.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S2629")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "trace" "debug" "info" "warn" "error")) @match"#,
            filter: Some(Keep(logs_a_concatenated_message)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(int id) { logger.debug(\"id=\" + id); } }",
            good: "class A { void f(int id) { logger.debug(\"id={}\", id); } }",
        }),
    },
    Rule {
        id: "java/index-of-positive",
        name: "indexOf checks should not be for positive numbers",
        description: "`indexOf(x) > 0` misses a match at index 0.",
        message: "Compare with -1 or use contains().",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2692")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(binary_expression) @match"#,
            filter: Some(Keep(checks_index_of_for_positive)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { boolean f(String s) { return s.indexOf(\"x\") > 0; } }",
            good: "class A { boolean f(String s) { return s.contains(\"x\"); } }",
        }),
    },
    Rule {
        id: "java/catch-only-rethrows",
        name: "catch clauses should do more than rethrow",
        description: "A catch that just rethrows is noise.",
        message: "Remove this catch clause.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S2737")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(catch_clause) @match"#,
            filter: Some(Keep(catch_only_rethrows)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { try { g(); } catch (IOException e) { throw e; } } }",
            good: "class A { void f() { try { g(); } catch (IOException e) { log(e); throw e; } } }",
        }),
    },
    Rule {
        id: "java/nested-enum-static",
        name: "Nested enums should not be declared static",
        description: "Nested enums are implicitly static.",
        message: "Remove static.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S2786")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(enum_declaration) @match"#,
            filter: Some(Keep(has_static_modifier)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { static enum E { X } }",
            good: "class A { enum E { X } }",
        }),
    },
    Rule {
        id: "java/key-set-iteration",
        name: "entrySet() should be iterated when both the key and value are needed",
        description: "Looking each key up again costs a second hash lookup.",
        message: "Iterate the entrySet().",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2864")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(enhanced_for_statement) @match"#,
            filter: Some(Keep(iterates_keys_and_looks_up_values)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(Map<String, String> m) { for (String k : m.keySet()) { use(m.get(k)); } } }",
            good: "class A { void f(Map<String, String> m) { for (Map.Entry<String, String> e : m.entrySet()) { use(e.getValue()); } } }",
        }),
    },
    Rule {
        id: "java/clone-overridden",
        name: "clone should not be overridden",
        description: "clone is fragile; a copy constructor is clearer.",
        message: "Provide a copy constructor instead.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 15,
        sonar: &[exact("S2975")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration name: (identifier) @n (#eq? @n "clone")) @match"#,
            filter: Some(Keep(takes_no_parameters)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { public Object clone() { return null; } }",
            good: "class A { A(A other) {} }",
        }),
    },
    Rule {
        id: "java/set-accessible",
        name: "Reflection should not be used to increase accessibility",
        description: "setAccessible(true) bypasses the access rules the author set.",
        message: "Don't bypass access control.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 15,
        sonar: &[exact("S3011")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "setAccessible") arguments: (argument_list (true))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(Field fld) { fld.setAccessible(true); } }",
            good: "class A { void f(Field fld) { g(fld); } }",
        }),
    },
    Rule {
        id: "java/thread-group",
        name: "ThreadGroup should not be used",
        description: "Its methods are deprecated or unsafe.",
        message: "Use an ExecutorService.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 15,
        sonar: &[exact("S3014")],
        check: Check::Query {
            langs: JAVA,
            query: r#"((type_identifier) @match (#eq? @match "ThreadGroup"))"#,
            filter: Some(Keep(declares_a_thread_group)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { ThreadGroup g; }",
            good: "class A { ExecutorService e; }",
        }),
    },
    Rule {
        id: "java/append-concatenation",
        name: "Arguments to append should not be concatenated",
        description: "`sb.append(a + b)` builds a string just to copy it.",
        message: "Chain append() calls.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S3024")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "append")) @match"#,
            filter: Some(Keep(appends_a_concatenation)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(StringBuilder sb, int id) { sb.append(\"id=\" + id); } }",
            good: "class A { void f(StringBuilder sb, int id) { sb.append(\"id=\").append(id); } }",
        }),
    },
    Rule {
        id: "java/enum-public-mutable-field",
        name: "enum fields should not be publicly mutable",
        description: "Shared constants should not change.",
        message: "Make the field private or final.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3066")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(enum_declaration) @match"#,
            filter: Some(Find(mutable_public_enum_field)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "enum E { X; public int count; }",
            good: "enum E { X; private int count; }",
        }),
    },
    Rule {
        id: "java/nested-ternary",
        name: "Ternary operators should not be nested",
        description: "A ternary inside a ternary is hard to read.",
        message: "Use if statements, or a variable.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S3358")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(ternary_expression) @match"#,
            filter: Some(Keep(contains_a_nested_ternary)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { int f(int a) { return a > 1 ? 1 : a > 0 ? 2 : 3; } }",
            good: "class A { int f(int a) { return a > 1 ? 1 : 2; } }",
        }),
    },
    Rule {
        id: "java/method-returns-constant",
        name: "Methods should not return constants",
        description: "A private method that returns a literal could be a constant.",
        message: "Use a constant.",
        category: CodeSmell,
        severity: Info,
        effort_minutes: 5,
        sonar: &[exact("S3400")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Keep(private_method_returns_a_literal)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { private int f() { return 3; } }",
            good: "class A { private int f() { return g(); } }",
        }),
    },
    Rule {
        id: "java/logger-class",
        name: "Loggers should be named for their enclosing classes",
        description: "A logger named for another class sends output to the wrong place.",
        message: "Name the logger after this class.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S3416")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "getLogger") arguments: (argument_list (class_literal))) @match"#,
            filter: Some(Keep(logger_names_another_class)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { Logger l = LoggerFactory.getLogger(Other.class); }",
            good: "class A { Logger l = LoggerFactory.getLogger(A.class); }",
        }),
    },
    Rule {
        id: "java/redundant-jump",
        name: "Jump statements should not be redundant",
        description: "A return at the end of a void method, or a continue at the end of a loop, changes nothing.",
        message: "Remove this jump.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S3626")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(return_statement) @match
(continue_statement) @match"#,
            filter: Some(Keep(jump_is_redundant)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { g(); return; } }",
            good: "class A { void f() { g(); } }",
        }),
    },
    Rule {
        id: "java/stream-for-each",
        name: "stream should not be used for Collection forEach calls",
        description: "Collection.forEach does the same without the stream.",
        message: "Call forEach on the collection.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S3706")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (method_invocation name: (identifier) @s (#eq? @s "stream")) name: (identifier) @n (#eq? @n "forEach")) @match"#,
            filter: Some(Keep(streams_a_collection)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(List<String> l) { l.stream().forEach(g); } }",
            good: "class A { void f(List<String> l) { l.forEach(g); } }",
        }),
    },
    Rule {
        id: "java/private-request-mapping",
        name: "@RequestMapping methods should not be private",
        description: "Spring's proxies can't call a private method.",
        message: "Make this method public.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S3751")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Keep(private_mapped_method)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { @GetMapping(\"/x\") private String f() { return \"\"; } }",
            good: "class A { @GetMapping(\"/x\") public String f() { return \"\"; } }",
        }),
    },
    Rule {
        id: "java/stream-peek",
        name: "Stream.peek should be used with caution",
        description: "peek may not run at all if the stream ends without needing the element.",
        message: "Use map or forEach.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3864")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "peek")) @match"#,
            filter: Some(Keep(one_argument)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(Stream<String> s) { s.peek(System.out::println).count(); } }",
            good: "class A { void f(Stream<String> s) { s.forEach(System.out::println); } }",
        }),
    },
    Rule {
        id: "java/conditional-on-new-line",
        name: "Conditionals should start on new lines",
        description: "`if (a) {} if (b) {}` on one line reads like a missing else.",
        message: "Move this if to its own line.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 2,
        sonar: &[exact("S3972")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(block) @match"#,
            filter: Some(Find(if_on_line_where_previous_ended)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { if (a) { g(); } if (b) { h(); } } }",
            good: "class A { void f() { if (a) { g(); }\nif (b) { h(); } } }",
        }),
    },
    Rule {
        id: "java/stream-find-first-present",
        name: "Stream call chains should be simplified when possible",
        description: "`filter(p).findFirst().isPresent()` is `anyMatch(p)`.",
        message: "Use anyMatch().",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S4034")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (method_invocation object: (method_invocation name: (identifier) @f (#eq? @f "filter")) name: (identifier) @ff (#eq? @ff "findFirst")) name: (identifier) @ip (#eq? @ip "isPresent")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { boolean f(Stream<String> s) { return s.filter(x -> x.isEmpty()).findFirst().isPresent(); } }",
            good: "class A { boolean f(Stream<String> s) { return s.anyMatch(x -> x.isEmpty()); } }",
        }),
    },
    Rule {
        id: "java/thread-local-initial-value",
        name: "ThreadLocal.withInitial should be preferred",
        description: "An anonymous subclass just to set the initial value is heavy.",
        message: "Use ThreadLocal.withInitial.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S4065")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(object_creation_expression type: (generic_type (type_identifier) @t (#eq? @t "ThreadLocal")) (class_body)) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { ThreadLocal<String> t = new ThreadLocal<String>() { protected String initialValue() { return \"\"; } }; }",
            good: "class A { ThreadLocal<String> t = ThreadLocal.withInitial(() -> \"\"); }",
        }),
    },
    Rule {
        id: "java/identical-methods",
        name: "Methods should not have identical implementations",
        description: "Two methods with the same body are one method written twice.",
        message: "Reuse the other method.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 15,
        sonar: &[exact("S4144")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Keep(method_duplicates_another)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A {\nint a() {\nint x = 1;\nreturn x + 1;\n}\nint b() {\nint x = 1;\nreturn x + 1;\n}\n}",
            good: "class A {\nint a() {\nint x = 1;\nreturn x + 1;\n}\nint b() {\nreturn 2;\n}\n}",
        }),
    },
    Rule {
        id: "java/null-check-with-instanceof",
        name: "Null checks should not be used with instanceof",
        description: "instanceof is already false for null.",
        message: "Remove the null check.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S4201")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(binary_expression) @match"#,
            filter: Some(Keep(null_check_before_instanceof)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { boolean f(Object o) { return o != null && o instanceof String; } }",
            good: "class A { boolean f(Object o) { return o instanceof String; } }",
        }),
    },
    Rule {
        id: "java/specialised-functional-interface",
        name: "Functional interfaces should be as specialised as possible",
        description: "`Function<T, Boolean>` is a Predicate and `Function<T, T>` a UnaryOperator.",
        message: "Use the specialised interface.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S4276")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(generic_type (type_identifier) @t (#any-of? @t "Function" "BiFunction" "Supplier")) @match"#,
            filter: Some(Keep(has_a_specialised_form)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { Function<String, Boolean> f; }",
            good: "class A { Predicate<String> f; }",
        }),
    },
    Rule {
        id: "java/default-not-last",
        name: "default clauses should be last",
        description: "A default in the middle is easy to miss.",
        message: "Move the default clause to the end.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S4524")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(switch_expression) @match"#,
            filter: Some(Keep(default_is_not_last)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(int x) { switch (x) { default: g(); break; case 1: h(); break; } } }",
            good: "class A { void f(int x) { switch (x) { case 1: h(); break; default: g(); break; } } }",
        }),
    },
    Rule {
        id: "java/charset-constant",
        name: "StandardCharsets constants should be preferred",
        description: "A charset name in a string can be misspelled; a constant cannot.",
        message: "Use StandardCharsets.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S4719")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "forName" "getBytes") arguments: (argument_list (string_literal) @c (#match? @c "^\"(UTF-8|UTF-16|US-ASCII|ISO-8859-1)\"$"))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { byte[] f(String s) throws Exception { return s.getBytes(\"UTF-8\"); } }",
            good: "class A { byte[] f(String s) { return s.getBytes(StandardCharsets.UTF_8); } }",
        }),
    },
    Rule {
        id: "java/dangling-else",
        name: "else statements should be clearly matched with an if",
        description: "Without braces, an else binds to the nearest if.",
        message: "Add braces.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 2,
        sonar: &[exact("S5261")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(if_statement) @match"#,
            filter: Some(Keep(else_binds_to_inner_if)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { if (a) if (b) g(); else h(); } }",
            good: "class A { void f() { if (a) { if (b) { g(); } else { h(); } } } }",
        }),
    },
    Rule {
        id: "java/replace-all-literal",
        name: "String#replace should be preferred to String#replaceAll",
        description: "With a plain-text pattern, replace is simpler and faster.",
        message: "Use replace().",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S5361")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "replaceAll")) @match"#,
            filter: Some(Keep(replace_pattern_is_plain_text)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { String f(String s) { return s.replaceAll(\"a\", \"b\"); } }",
            good: "class A { String f(String s) { return s.replace(\"a\", \"b\"); } }",
        }),
    },
    Rule {
        id: "java/junit-assert-simplifiable",
        name: "JUnit assertTrue/assertFalse should be simplified to the corresponding dedicated assertion",
        description: "assertEquals shows both values when it fails; assertTrue(a == b) shows only false.",
        message: "Use assertEquals, assertNull or similar.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S5785")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "assertTrue" "assertFalse")) @match"#,
            filter: Some(Keep(asserts_a_comparison)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { assertTrue(a == b); } }",
            good: "class A { void f() { assertEquals(a, b); } }",
        }),
    },
    Rule {
        id: "java/abstract-class-public-constructor",
        name: "Constructors of an abstract class should not be declared public",
        description: "Only subclasses can call them.",
        message: "Make the constructor protected.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S5993")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Find(public_constructor_of_abstract_class)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "abstract class A { public A() {} }",
            good: "abstract class A { protected A() {} }",
        }),
    },
    Rule {
        id: "java/class-isinstance",
        name: "Operator instanceof should be used instead of A.class.isInstance()",
        description: "instanceof is shorter and checked at compile time.",
        message: "Use instanceof.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6202")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (class_literal) name: (identifier) @n (#eq? @n "isInstance")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { boolean f(Object o) { return String.class.isInstance(o); } }",
            good: "class A { boolean f(Object o) { return o instanceof String; } }",
        }),
    },
    Rule {
        id: "java/collectors-to-list",
        name: "Stream.toList() should be used instead of collectors when unmodifiable lists are fine",
        description: "Stream.toList() is shorter.",
        message: "Use toList().",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6204")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "collect") arguments: (argument_list (method_invocation object: (identifier) @o name: (identifier) @t (#eq? @o "Collectors") (#eq? @t "toList")))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { List<String> f(Stream<String> s) { return s.collect(Collectors.toList()); } }",
            good: "class A { List<String> f(Stream<String> s) { return s.toList(); } }",
        }),
    },
    Rule {
        id: "java/deprecated-without-reason",
        name: "Deprecated annotations should include explanations",
        description: "Without a reason or a replacement, callers don't know what to do.",
        message: "Say why, and what to use instead.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6355")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(marker_annotation name: (identifier) @n (#eq? @n "Deprecated")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { @Deprecated void f() {} }",
            good: "class A { @Deprecated(since = \"2.0\", forRemoval = true) void f() {} }",
        }),
    },
    Rule {
        id: "java/field-injection",
        name: "Field dependency injection should be avoided",
        description: "Constructor injection makes dependencies visible and testable.",
        message: "Inject through the constructor.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S6813"), related("S3306"), related("S4288")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(marker_annotation name: (identifier) @n (#eq? @n "Autowired")) @match"#,
            filter: Some(Keep(annotates_a_field)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { @Autowired private B b; }",
            good: "class A { private final B b; A(B b) { this.b = b; } }",
        }),
    },
    Rule {
        id: "java/redundant-response-body",
        name: "Superfluous @ResponseBody annotations should be removed",
        description: "@RestController already applies it to every method.",
        message: "Remove @ResponseBody.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 1,
        sonar: &[exact("S6837")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(marker_annotation name: (identifier) @n (#eq? @n "ResponseBody")) @match"#,
            filter: Some(Keep(on_rest_controller_method)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "@RestController class A { @ResponseBody String f() { return \"\"; } }",
            good: "@RestController class A { String f() { return \"\"; } }",
        }),
    },
    Rule {
        id: "java/static-field-injection",
        name: "Injecting data into static fields is not supported by Spring",
        description: "Spring injects instances, so the static field is never set.",
        message: "Inject an instance field.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7178")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(marker_annotation name: (identifier) @n (#eq? @n "Autowired")) @match
(annotation name: (identifier) @n2 (#eq? @n2 "Value")) @match"#,
            filter: Some(Keep(annotates_a_static_field)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { @Autowired static B b; }",
            good: "class A { @Autowired B b; }",
        }),
    },
    Rule {
        id: "java/init-binder-return",
        name: "@InitBinder methods should have void return type",
        description: "Spring ignores any other return value.",
        message: "Return void.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S7183")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Keep(init_binder_returns_a_value)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { @InitBinder String f() { return \"\"; } }",
            good: "class A { @InitBinder void f() {} }",
        }),
    },
    Rule {
        id: "java/now-without-zone",
        name: "Time-based .now() methods should specify a ZoneId or a Clock",
        description: "The system default zone makes results depend on the server.",
        message: "Pass a ZoneId or a Clock.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S8688")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) @o name: (identifier) @n (#any-of? @o "LocalDate" "LocalDateTime" "LocalTime" "ZonedDateTime" "OffsetDateTime" "Year" "YearMonth") (#eq? @n "now")) @match"#,
            filter: Some(Keep(no_arguments)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { Object f() { return LocalDate.now(); } }",
            good: "class A { Object f() { return LocalDate.now(clock); } }",
        }),
    },
    Rule {
        id: "java/generic-exception-thrown",
        name: "Generic exceptions should never be thrown",
        description: "Callers can't catch a generic exception without catching everything.",
        message: "Throw a more specific exception.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 15,
        sonar: &[exact("S112")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(throw_statement (object_creation_expression type: (type_identifier) @t (#any-of? @t "Exception" "RuntimeException" "Throwable" "Error"))) @match
(throws (type_identifier) @match (#any-of? @match "Throwable" "RuntimeException" "Error"))"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { throw new RuntimeException(\"x\"); } }",
            good: "class A { void f() { throw new IllegalStateException(\"x\"); } }",
        }),
    },
    Rule {
        id: "java/unused-label",
        name: "Unused labels should be removed",
        description: "A label that nothing jumps to is noise.",
        message: "Remove this label.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 1,
        sonar: &[exact("S1065")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(labeled_statement) @match"#,
            filter: Some(Keep(label_is_unused)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { outer: for (;;) { break; } } }",
            good: "class A { void f() { outer: for (;;) { break outer; } } }",
        }),
    },
    Rule {
        id: "java/mergeable-if",
        name: "Mergeable if statements should be combined",
        description: "An if whose only content is another if can use &&.",
        message: "Merge these conditions.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S1066")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(if_statement) @match"#,
            filter: Some(Find(if_only_wraps_another_if)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { if (a) { if (b) { g(); } } } }",
            good: "class A { void f() { if (a && b) { g(); } } }",
        }),
    },
    Rule {
        id: "java/redundant-parentheses",
        name: "Unnecessary parentheses should be removed",
        description: "Parentheses around a whole expression add noise.",
        message: "Remove the parentheses.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 1,
        sonar: &[exact("S1110")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(return_statement (parenthesized_expression) @match)
(variable_declarator value: (parenthesized_expression) @match)"#,
            filter: Some(Keep(parentheses_fit_on_one_line)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { int f() { return (1 + 2); } }",
            good: "class A { int f() { return 1 + 2; } }",
        }),
    },
    Rule {
        id: "java/finalize-overridden",
        name: "Object.finalize() should not be overridden",
        description: "Finalizers run unpredictably and are deprecated for removal.",
        message: "Use try-with-resources or a Cleaner.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 15,
        sonar: &[exact("S1113")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration name: (identifier) @n (#eq? @n "finalize")) @match"#,
            filter: Some(Keep(takes_no_parameters)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { protected void finalize() {} }",
            good: "class A { void close() {} }",
        }),
    },
    Rule {
        id: "java/finalize-visibility",
        name: "Object.finalize() should remain protected when overridden",
        description: "Public finalize invites callers to run it.",
        message: "Make finalize protected.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 2,
        sonar: &[exact("S1174")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration name: (identifier) @n (#eq? @n "finalize")) @match"#,
            filter: Some(Keep(finalize_is_public)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { public void finalize() {} }",
            good: "class A { protected void finalize() {} }",
        }),
    },
    Rule {
        id: "java/deprecated-code",
        name: "Deprecated code should be removed",
        description: "Deprecated code that stays forever is clutter.",
        message: "Remove this deprecated code once it is unused.",
        category: CodeSmell,
        severity: Info,
        effort_minutes: 15,
        sonar: &[exact("S1133")],
        check: Check::Query {
            langs: JAVA,
            query: r#"[(method_declaration) (constructor_declaration) (class_declaration) (interface_declaration) (enum_declaration) (record_declaration) (field_declaration)] @match"#,
            filter: Some(Find(deprecated_declaration_name)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { @Deprecated void f() {} }",
            good: "class A { void f() {} }",
        }),
    },
    Rule {
        id: "java/identical-branches-in-chain",
        name: "Two branches in a conditional structure should not have exactly the same implementation",
        description: "Repeating a block in two branches suggests they should be merged.",
        message: "Merge these branches.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1871")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(if_statement) @match"#,
            filter: Some(Find(chain_repeats_a_branch)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { if (a) { g(); h(); } else if (b) { g(); h(); } } }",
            good: "class A { void f() { if (a || b) { g(); h(); } } }",
        }),
    },
    Rule {
        id: "java/switch-without-default",
        name: "switch statements should have default clauses",
        description: "Without a default, an unexpected value is silently ignored.",
        message: "Add a default clause.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S131")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(switch_expression) @match"#,
            filter: Some(Keep(switch_statement_lacks_default)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(int x) { switch (x) { case 1: g(); break; case 2: h(); break; case 3: i(); break; } } }",
            good: "class A { void f(int x) { switch (x) { case 1: g(); break; default: h(); } } }",
        }),
    },
    Rule {
        id: "java/multiple-jumps-in-loop",
        name: "Loops should not contain more than a single break or continue statement",
        description: "Several exits make a loop hard to follow.",
        message: "Restructure the loop.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 15,
        sonar: &[exact("S135")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(for_statement) @match
(enhanced_for_statement) @match
(while_statement) @match
(do_statement) @match"#,
            filter: Some(Keep(loop_has_several_jumps)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { for (;;) { if (a) { break; } if (b) { continue; } } } }",
            good: "class A { void f() { for (;;) { if (a) { break; } } } }",
        }),
    },
    Rule {
        id: "java/unused-private-method",
        name: "Unused private methods should be removed",
        description: "Nothing calls it.",
        message: "Remove this unused private method.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1144")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Keep(private_method_is_never_used)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { private void f() {} }",
            good: "class A { private void f() {} void g() { f(); } }",
        }),
    },
    Rule {
        id: "java/unused-private-field",
        name: "Unused private fields should be removed",
        description: "Nothing reads or writes it.",
        message: "Remove this unused private field.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1068")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(field_declaration) @match"#,
            filter: Some(Keep(private_field_is_never_used)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { private int count; }",
            good: "class A { private int count; int get() { return count; } }",
        }),
    },
    Rule {
        id: "java/unused-private-class",
        name: "Unused private classes should be removed",
        description: "Nothing instantiates it.",
        message: "Remove this unused private class.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3985")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Keep(private_class_is_never_used)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { private static class B {} }",
            good: "class A { private static class B {} B b; }",
        }),
    },
    Rule {
        id: "java/unused-local-variable",
        name: "Unused local variables should be removed",
        description: "A variable nothing reads is dead code.",
        message: "Remove this unused local variable.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S1481")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(local_variable_declaration (variable_declarator name: (identifier) @n)) @match"#,
            filter: Some(Keep(local_is_never_used)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { int unused = 3; } }",
            good: "class A { int f() { int used = 3; return used; } }",
        }),
    },
    Rule {
        id: "java/duplicated-string",
        name: "String literals should not be duplicated",
        description: "A literal repeated across the file is easy to change in one place and miss in the others.",
        message: "Define a constant for this string.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S1192")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(string_literal) @match"#,
            filter: Some(Keep(is_first_of_a_repeated_string)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { String a = \"connection failed\"; String b = \"connection failed\"; String c = \"connection failed\"; }",
            good: "class A { static final String MSG = \"connection failed\"; String a = MSG; String b = MSG; }",
        }),
    },
    Rule {
        id: "java/instanceof-then-cast",
        name: "Pattern matching for instanceof should be used instead of a separate cast",
        description: "`if (o instanceof Foo f)` binds the cast value for you.",
        message: "Use a pattern variable.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6201")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(if_statement) @match"#,
            filter: Some(Keep(casts_after_instanceof)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(Object o) { if (o instanceof String) { String s = (String) o; use(s); } } }",
            good: "class A { void f(Object o) { if (o instanceof String s) { use(s); } } }",
        }),
    },
    Rule {
        id: "java/autowired-with-many-constructors",
        name: "@Autowired should be used when multiple constructors are provided",
        description: "Spring needs to be told which constructor to use.",
        message: "Annotate one constructor.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6829")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Find(several_constructors_without_autowired)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "@Component class A { A() {} A(B b) {} }",
            good: "@Component class A { A() {} @Autowired A(B b) {} }",
        }),
    },
    Rule {
        id: "java/empty-string-comparison",
        name: "String.isEmpty() should be used to test for emptiness",
        description: "isEmpty() says what is meant.",
        message: "Use isEmpty().",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S7158")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(binary_expression) @match
(method_invocation name: (identifier) @n (#eq? @n "equals") arguments: (argument_list (string_literal) @s (#eq? @s "\"\""))) @match"#,
            filter: Some(Keep(compares_with_empty_string)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { boolean f(String s) { return s.length() == 0; } }",
            good: "class A { boolean f(String s) { return s.isEmpty(); } }",
        }),
    },
];

// ---------------------------------------------------- filters

pub(super) const LOOPS: &[&str] = &[
    "for_statement",
    "enhanced_for_statement",
    "while_statement",
    "do_statement",
];

pub(super) fn children_of_kind<'t>(node: Node<'t>, kind: &str) -> Vec<Node<'t>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|n| n.kind() == kind)
        .collect()
}

pub(super) fn members(body: Node) -> Vec<Node> {
    statements(body)
}

/// How many times `word` occurs in `haystack` as a whole identifier.
pub(super) fn count_word(haystack: &[u8], word: &[u8]) -> usize {
    if word.is_empty() {
        return 0;
    }
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'$';
    let mut count = 0;
    let mut i = 0;
    while i + word.len() <= haystack.len() {
        if &haystack[i..i + word.len()] == word
            && (i == 0 || !is_ident(haystack[i - 1]))
            && haystack.get(i + word.len()).is_none_or(|&b| !is_ident(b))
        {
            count += 1;
            i += word.len();
        } else {
            i += 1;
        }
    }
    count
}

fn is_literal_value(node: Node) -> bool {
    matches!(
        node.kind(),
        "decimal_integer_literal"
            | "decimal_floating_point_literal"
            | "hex_integer_literal"
            | "string_literal"
            | "character_literal"
            | "true"
            | "false"
    )
}

pub(super) fn declarator_names<'a>(declaration: Node, src: &'a [u8]) -> Vec<&'a [u8]> {
    children_of_kind(declaration, "variable_declarator")
        .into_iter()
        .filter_map(|d| d.child_by_field_name("name").map(|n| text(n, src)))
        .collect()
}

pub(super) fn enclosing_class(node: Node) -> Option<Node> {
    let mut p = node.parent();
    let mut hops = 0;
    while let Some(n) = p {
        if matches!(
            n.kind(),
            "class_declaration"
                | "enum_declaration"
                | "record_declaration"
                | "interface_declaration"
        ) {
            return Some(n);
        }
        hops += 1;
        if hops > 64 {
            return None;
        }
        p = n.parent();
    }
    None
}

fn class_name_not_pascal(node: Node, src: &[u8]) -> bool {
    let Some(name) = node.child_by_field_name("name") else {
        return false;
    };
    let t = text(name, src);
    !(t.first().is_some_and(u8::is_ascii_uppercase) && t.iter().all(u8::is_ascii_alphanumeric))
}

fn method_name_not_camel_case(method: Node, src: &[u8]) -> bool {
    let Some(name) = method.child_by_field_name("name") else {
        return false;
    };
    let t = text(name, src);
    !(t.first().is_some_and(u8::is_ascii_lowercase) && t.iter().all(u8::is_ascii_alphanumeric))
}

fn is_valid_constant(name: &[u8]) -> bool {
    !name.is_empty()
        && name[0].is_ascii_uppercase()
        && name
            .iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_')
        && !name.ends_with(b"_")
        && !name.windows(2).any(|w| w == b"__")
}

fn constant_name_not_upper_snake(field: Node, src: &[u8]) -> bool {
    if field.kind() == "enum_constant" {
        return field
            .child_by_field_name("name")
            .is_some_and(|n| !is_valid_constant(text(n, src)));
    }
    // Interface constants are static and final without saying so.
    if field.kind() != "constant_declaration"
        && !(has_modifier(field, "static") && has_modifier(field, "final"))
    {
        return false;
    }
    // Only plain values read as constants; a `static final` map or set is
    // an ordinary object reference and SonarQube leaves its name alone.
    let is_plain_value = field.child_by_field_name("type").is_some_and(|t| {
        matches!(
            text(t, src),
            b"int"
                | b"long"
                | b"short"
                | b"byte"
                | b"char"
                | b"boolean"
                | b"float"
                | b"double"
                | b"String"
                | b"Integer"
                | b"Long"
                | b"Short"
                | b"Byte"
                | b"Character"
                | b"Boolean"
                | b"Float"
                | b"Double"
        )
    });
    is_plain_value
        && declarator_names(field, src)
            .iter()
            .any(|n| *n != b"serialVersionUID" && !is_valid_constant(n))
}

fn is_camel_case(name: &[u8]) -> bool {
    name.first().is_some_and(u8::is_ascii_lowercase) && name.iter().all(u8::is_ascii_alphanumeric)
}

fn field_name_not_camel_case(field: Node, src: &[u8]) -> bool {
    if has_modifier(field, "static") && has_modifier(field, "final") {
        return false;
    }
    declarator_names(field, src)
        .iter()
        .any(|n| *n != b"serialVersionUID" && !is_camel_case(n))
}

fn local_name_not_camel_case(node: Node, src: &[u8]) -> bool {
    if node.kind() == "identifier" {
        let t = text(node, src);
        return t != b"_" && !is_camel_case(t);
    }
    if node.kind() == "variable_declarator"
        && !node
            .parent()
            .is_some_and(|p| p.kind() == "local_variable_declaration")
    {
        return false;
    }
    let Some(name) = node.child_by_field_name("name") else {
        return false;
    };
    let t = text(name, src);
    t != b"_" && !is_camel_case(t)
}

fn type_parameter_name_is_unconventional(param: Node, src: &[u8]) -> bool {
    let Some(name) = param.named_child(0) else {
        return false;
    };
    let t = text(name, src);
    !(t.first().is_some_and(u8::is_ascii_uppercase)
        && (t.len() == 1 || (t.len() == 2 && t[1].is_ascii_digit())))
}

fn utility_class_is_instantiable(class: Node, src: &[u8]) -> bool {
    if annotated_or_abstract(class, src)
        || class.child_by_field_name("superclass").is_some()
        || class.child_by_field_name("interfaces").is_some()
    {
        return false;
    }
    let Some(body) = class.child_by_field_name("body") else {
        return false;
    };
    let mut has_member = false;
    let mut constructors = Vec::new();
    for member in members(body) {
        match member_kind(member, src) {
            MemberKind::Constructor => constructors.push(member),
            MemberKind::Static => has_member = true,
            MemberKind::Nested => {}
            MemberKind::Instance => return false,
        }
    }
    has_member
        && (constructors.is_empty() || constructors.iter().any(|c| !has_modifier(*c, "private")))
}

/// Abstract, or with an annotation other than `@Deprecated` and
/// `@SuppressWarnings`: a framework may make instances.
fn annotated_or_abstract(class: Node, src: &[u8]) -> bool {
    modifiers_of(class).is_some_and(|m| {
        let mut c = m.walk();
        m.children(&mut c).any(|k| {
            k.kind() == "abstract"
                || (matches!(k.kind(), "marker_annotation" | "annotation")
                    && !k.child_by_field_name("name").is_some_and(|n| {
                        matches!(text(n, src), b"Deprecated" | b"SuppressWarnings")
                    }))
        })
    })
}

/// What a member says about whether its class is a utility class.
enum MemberKind {
    Constructor,
    /// A static method, other than `main`, or a static field.
    Static,
    /// A nested type or a static initializer: neither way.
    Nested,
    /// Anything an instance would have, or `main`.
    Instance,
}

fn member_kind(member: Node, src: &[u8]) -> MemberKind {
    match member.kind() {
        "constructor_declaration" => MemberKind::Constructor,
        "method_declaration"
            if has_modifier(member, "static")
                && !member
                    .child_by_field_name("name")
                    .is_some_and(|n| text(n, src) == b"main") =>
        {
            MemberKind::Static
        }
        "field_declaration" if has_modifier(member, "static") => MemberKind::Static,
        "class_declaration"
        | "interface_declaration"
        | "enum_declaration"
        | "record_declaration"
        | "static_initializer" => MemberKind::Nested,
        _ => MemberKind::Instance,
    }
}

/// SonarQube reports a visible constructor where there is one, and the class
/// itself when the implicit constructor is the problem.
fn utility_class_constructor_or_class<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !utility_class_is_instantiable(class, src) {
        return None;
    }
    let body = class.child_by_field_name("body")?;
    let constructor = members(body)
        .into_iter()
        .find(|m| m.kind() == "constructor_declaration" && !has_modifier(*m, "private"));
    Some(constructor.unwrap_or(class))
}

fn assigns_inside_an_expression(assign: Node, _: &[u8]) -> bool {
    let Some(parent) = assign.parent() else {
        return false;
    };
    if matches!(
        parent.kind(),
        "expression_statement" | "lambda_expression" | "assignment_expression" | "for_statement"
    ) {
        return false;
    }
    // `while ((line = in.readLine()) != null)` is the accepted idiom.
    let mut p = Some(parent);
    for _ in 0..4 {
        let Some(n) = p else { break };
        if matches!(
            n.kind(),
            "while_statement" | "do_statement" | "for_statement"
        ) {
            return false;
        }
        p = n.parent();
    }
    true
}

fn modifiers_out_of_order(modifiers: Node, _: &[u8]) -> bool {
    let rank = |kind: &str| match kind {
        "public" | "protected" | "private" => Some(0),
        "abstract" => Some(1),
        "static" => Some(2),
        "final" => Some(3),
        "transient" => Some(4),
        "volatile" => Some(5),
        "synchronized" => Some(6),
        "native" => Some(7),
        "strictfp" => Some(8),
        _ => None,
    };
    let mut cursor = modifiers.walk();
    let ranks: Vec<i32> = modifiers
        .children(&mut cursor)
        .filter_map(|c| rank(c.kind()))
        .collect();
    ranks.windows(2).any(|w| w[0] > w[1])
}

fn boolean_literal_is_redundant(node: Node, src: &[u8]) -> bool {
    let is_bool = |n: Option<Node>| n.is_some_and(|n| matches!(n.kind(), "true" | "false"));
    if node.kind() == "ternary_expression" {
        return is_bool(node.child_by_field_name("consequence"))
            && is_bool(node.child_by_field_name("alternative"));
    }
    matches!(operator_text(node, src), b"==" | b"!=" | b"&&" | b"||")
        && (is_bool(node.child_by_field_name("left")) || is_bool(node.child_by_field_name("right")))
}

fn returned_bool(branch: Node) -> Option<bool> {
    let statement = if branch.kind() == "block" {
        let items = statements(branch);
        match items.as_slice() {
            [only] => *only,
            _ => return None,
        }
    } else {
        branch
    };
    if statement.kind() != "return_statement" {
        return None;
    }
    match statement.named_child(0)?.kind() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn returns_boolean_from_both_branches(statement: Node, _: &[u8]) -> bool {
    let (Some(a), Some(b)) = (
        statement
            .child_by_field_name("consequence")
            .and_then(returned_bool),
        statement
            .child_by_field_name("alternative")
            .and_then(returned_bool),
    ) else {
        return false;
    };
    a != b
}

fn first_unused_import<'t>(program: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut cursor = program.walk();
    for import in program.named_children(&mut cursor) {
        if import.kind() != "import_declaration" {
            continue;
        }
        let mut c = import.walk();
        if import.children(&mut c).any(|k| k.kind() == "asterisk") {
            continue;
        }
        let t = text(import, src);
        let path = t
            .strip_prefix(b"import")
            .unwrap_or(t)
            .trim_ascii()
            .trim_ascii_end();
        let path = path.strip_prefix(b"static").unwrap_or(path).trim_ascii();
        let path = path.strip_suffix(b";").unwrap_or(path);
        let name = path
            .rsplit(|&b| b == b'.')
            .next()
            .unwrap_or(path)
            .trim_ascii();
        if count_word(src, name) <= 1 {
            return Some(import);
        }
    }
    None
}

fn nested_try_has_catch(try_: Node, _: &[u8]) -> bool {
    !children_of_kind(try_, "catch_clause").is_empty()
}

fn implements_enumeration(interfaces: Node, src: &[u8]) -> bool {
    count_word(text(interfaces, src), b"Enumeration") > 0
}

fn appends_string_value_of(binary: Node, src: &[u8]) -> bool {
    let value_of = |n: Option<Node>| {
        n.is_some_and(|n| {
            n.kind() == "method_invocation"
                && method_name(n, src) == b"valueOf"
                && n.child_by_field_name("object")
                    .is_some_and(|o| text(o, src) == b"String")
                && call_arguments(n).len() == 1
        })
    };
    operator_text(binary, src) == b"+"
        && (value_of(binary.child_by_field_name("left"))
            || value_of(binary.child_by_field_name("right")))
}

fn compares_size_with_zero_for_emptiness(binary: Node, src: &[u8]) -> bool {
    let (Some(l), Some(r)) = (
        binary.child_by_field_name("left"),
        binary.child_by_field_name("right"),
    ) else {
        return false;
    };
    let is_size = |n: Node| {
        n.kind() == "method_invocation"
            && method_name(n, src) == b"size"
            && call_arguments(n).is_empty()
            && n.child_by_field_name("object").is_some()
    };
    if !is_size(l) {
        return false;
    }
    matches!(
        (operator_text(binary, src), text(r, src)),
        (b"==", b"0") | (b"!=", b"0") | (b">", b"0") | (b"<", b"1") | (b">=", b"1")
    )
}

fn throw_in_finally<'t>(finally: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    find_in_scope(finally, &["lambda_expression", "class_body"], |n| {
        n.kind() == "throw_statement"
    })
}

fn non_final_instance_field<'t>(class: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    let body = class.child_by_field_name("body")?;
    members(body).into_iter().find(|m| {
        m.kind() == "field_declaration" && !has_modifier(*m, "static") && !has_modifier(*m, "final")
    })
}

/// The method a `return` belongs to, unless a lambda or inner class intervenes.
fn method_returned_from(statement: Node) -> Option<Node> {
    let mut p = statement.parent();
    while let Some(n) = p {
        match n.kind() {
            "method_declaration" => return Some(n),
            "lambda_expression" | "class_body" | "constructor_declaration" => return None,
            _ => p = n.parent(),
        }
    }
    None
}

fn returns_null_for_collection(statement: Node, src: &[u8]) -> bool {
    let Some(ty) = method_returned_from(statement).and_then(|m| m.child_by_field_name("type"))
    else {
        return false;
    };
    let head = text(ty, src)
        .split(|&b| b == b'<')
        .next()
        .unwrap_or(&b""[..]);
    ty.kind() == "array_type"
        || matches!(
            head,
            b"List"
                | b"Set"
                | b"Map"
                | b"Collection"
                | b"ArrayList"
                | b"HashMap"
                | b"HashSet"
                | b"Iterable"
                | b"SortedSet"
                | b"SortedMap"
        )
}

fn returns_null_from_boolean_method(statement: Node, src: &[u8]) -> bool {
    method_returned_from(statement)
        .and_then(|m| m.child_by_field_name("type"))
        .is_some_and(|t| text(t, src) == b"Boolean")
}

fn final_literal_field_is_not_static(field: Node, _: &[u8]) -> bool {
    field.parent().is_some_and(|p| p.kind() == "class_body")
        && has_modifier(field, "final")
        && !has_modifier(field, "static")
        && children_of_kind(field, "variable_declarator")
            .iter()
            .any(|d| d.child_by_field_name("value").is_some_and(is_literal_value))
}

fn initializer_of_named_class(block: Node, _: &[u8]) -> bool {
    block.parent().and_then(|b| b.parent()).is_some_and(|c| {
        matches!(
            c.kind(),
            "class_declaration" | "enum_declaration" | "record_declaration"
        )
    })
}

fn catches_throwable(catch: Node, src: &[u8]) -> bool {
    catch
        .named_child(0)
        .filter(|p| p.kind() == "catch_formal_parameter")
        .is_some_and(|p| {
            let mut c = p.walk();
            p.named_children(&mut c)
                .filter(|k| k.kind() == "catch_type")
                .any(|t| {
                    text(t, src).split(|&b| b == b'|').any(|part| {
                        matches!(
                            part.trim_ascii(),
                            b"Throwable" | b"Error" | b"java.lang.Throwable" | b"java.lang.Error"
                        )
                    })
                })
        })
}

fn override_only_calls_super(method: Node, src: &[u8]) -> bool {
    if !has_annotation(method, b"Override", src) {
        return false;
    }
    let Some(body) = method.child_by_field_name("body") else {
        return false;
    };
    let items = statements(body);
    let [only] = items.as_slice() else {
        return false;
    };
    let call = match only.kind() {
        "expression_statement" | "return_statement" => only.named_child(0),
        _ => None,
    };
    let Some(call) = call.filter(|c| c.kind() == "method_invocation") else {
        return false;
    };
    let name = method
        .child_by_field_name("name")
        .map_or(&b""[..], |n| text(n, src));
    let params: Vec<&[u8]> = method
        .child_by_field_name("parameters")
        .map(|p| {
            let mut c = p.walk();
            p.named_children(&mut c)
                .filter_map(|x| x.child_by_field_name("name").map(|n| text(n, src)))
                .collect()
        })
        .unwrap_or_default();
    let args: Vec<&[u8]> = call_arguments(call).iter().map(|a| text(*a, src)).collect();
    call.child_by_field_name("object")
        .is_some_and(|o| o.kind() == "super")
        && method_name(call, src) == name
        && args == params
}

/// An empty constructor is only redundant when it stands alone: next to
/// others it is the no-argument variant callers can pick.
fn is_the_only_public_constructor(ctor: Node) -> bool {
    has_modifier(ctor, "public")
        && ctor.parent().is_some_and(|body| {
            members(body)
                .into_iter()
                .filter(|m| m.kind() == "constructor_declaration")
                .count()
                == 1
        })
}

/// The name of a declaration marked `@Deprecated`, where SonarQube reports it.
fn deprecated_declaration_name<'t>(declaration: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    // The annotation, or the Javadoc tag alone, as SonarQube reports both.
    let tag = declaration
        .prev_named_sibling()
        .filter(|c| c.kind() == "block_comment" && text(*c, src).starts_with(b"/**"))
        .and_then(|c| deprecated_tag(text(c, src)));
    if !has_annotation(declaration, b"Deprecated", src) && tag.is_none() {
        return None;
    }
    if tag.is_some_and(says_what_to_do) {
        return None;
    }
    if declaration.kind() == "field_declaration" {
        return children_of_kind(declaration, "variable_declarator")
            .first()
            .and_then(|d| d.child_by_field_name("name"));
    }
    declaration.child_by_field_name("name")
}

/// The text of a Javadoc's `@deprecated` tag, up to the next tag.
fn deprecated_tag(javadoc: &[u8]) -> Option<&[u8]> {
    let start = javadoc.windows(11).position(|w| w == b"@deprecated")? + 11;
    let rest = &javadoc[start..];
    let mut end = rest.len();
    let mut offset = 0;
    for line in rest.split_inclusive(|&b| b == b'\n') {
        let body = line.trim_ascii_start();
        let body = body.strip_prefix(b"*").unwrap_or(body).trim_ascii_start();
        if offset > 0 && body.starts_with(b"@") {
            end = offset;
            break;
        }
        offset += line.len();
    }
    Some(&rest[..end])
}

/// Whether a deprecation says what to use instead or when it goes, which
/// SonarQube 26.7 takes as enough: the text holds both "use" and "instead",
/// anywhere and in any case (even inside "because"), or "will be removed
/// in" or "to be removed in" on one line.
fn says_what_to_do(tag: &[u8]) -> bool {
    let tag = tag.to_ascii_lowercase();
    let has = |s: &[u8]| tag.windows(s.len()).any(|w| w == s);
    (has(b"use") && has(b"instead")) || has(b"will be removed in") || has(b"to be removed in")
}

fn concatenates_a_string_in_a_loop(assign: Node, src: &[u8]) -> bool {
    let is_text = assign
        .child_by_field_name("right")
        .is_some_and(|r| r.kind() == "string_literal")
        || assign
            .child_by_field_name("left")
            .is_some_and(|l| type_text(declared_type(assign, text(l, src), src), src) == b"String");
    is_text && inside_a_loop(assign, src)
}

fn method_is_empty(method: Node, _: &[u8]) -> bool {
    method
        .child_by_field_name("body")
        .is_some_and(|b| b.named_child_count() == 0)
        && (method.kind() != "constructor_declaration" || is_the_only_public_constructor(method))
}

fn imports_from_sun(import: Node, src: &[u8]) -> bool {
    let t = text(import, src);
    let t = t.strip_prefix(b"import").unwrap_or(t).trim_ascii();
    let t = t.strip_prefix(b"static").unwrap_or(t).trim_ascii();
    t.starts_with(b"sun.")
}

fn compare_to_without_equals<'t>(body: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut compare = None;
    let mut has_equals = false;
    for m in members(body) {
        if m.kind() != "method_declaration" {
            continue;
        }
        let name = m
            .child_by_field_name("name")
            .map_or(&b""[..], |n| text(n, src));
        let params = parameter_types(m, src);
        if name == b"compareTo" && params.len() == 1 {
            compare = Some(m);
        } else if name == b"equals" && params.len() == 1 {
            has_equals = true;
        }
    }
    if has_equals { None } else { compare }
}

fn interface_only_holds_constants(interface: Node, _: &[u8]) -> bool {
    interface.child_by_field_name("body").is_some_and(|b| {
        let items = members(b);
        !items.is_empty()
            && items
                .iter()
                .all(|m| m.kind() == "constant_declaration" || m.kind() == "field_declaration")
    })
}

fn is_system_or_runtime_gc(call: Node, src: &[u8]) -> bool {
    if !call_arguments(call).is_empty() {
        return false;
    }
    call.child_by_field_name("object").is_some_and(|o| {
        text(o, src) == b"System"
            || (o.kind() == "method_invocation" && method_name(o, src) == b"getRuntime")
    })
}

fn class_without_package<'t>(program: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    let mut cursor = program.walk();
    let mut first_type = None;
    for child in program.named_children(&mut cursor) {
        match child.kind() {
            "package_declaration" => return None,
            "class_declaration"
            | "interface_declaration"
            | "enum_declaration"
            | "record_declaration" => {
                first_type.get_or_insert(child);
            }
            _ => {}
        }
    }
    first_type
}

fn method_named_like_its_class(method: Node, src: &[u8]) -> bool {
    let (Some(name), Some(class)) = (
        method.child_by_field_name("name"),
        method.parent().and_then(|b| b.parent()),
    ) else {
        return false;
    };
    class.kind() == "class_declaration"
        && class
            .child_by_field_name("name")
            .is_some_and(|c| text(c, src) == text(name, src))
}

fn for_has_only_a_condition(for_: Node, _: &[u8]) -> bool {
    for_.child_by_field_name("init").is_none()
        && for_.child_by_field_name("update").is_none()
        && for_.child_by_field_name("condition").is_some()
}

fn case_labels<'t>(switch: Node<'t>) -> Vec<Node<'t>> {
    let mut labels = Vec::new();
    let Some(block) = switch.child_by_field_name("body") else {
        return labels;
    };
    let mut cursor = block.walk();
    for group in block.named_children(&mut cursor) {
        let mut c = group.walk();
        for child in group.named_children(&mut c) {
            if child.kind() == "switch_label" {
                labels.push(child);
            }
        }
    }
    labels
}

fn cases_of(switch: Node, src: &[u8]) -> usize {
    case_labels(switch)
        .iter()
        .filter(|l| text(**l, src).starts_with(b"case"))
        .count()
}

/// Fewer than three clauses, `default` included, as SonarQube counts them.
fn switch_has_fewer_than_three_cases(switch: Node, src: &[u8]) -> bool {
    let cases = cases_of(switch, src);
    let clauses = case_labels(switch)
        .iter()
        .filter(|l| {
            let t = text(**l, src);
            t.starts_with(b"case") || t.starts_with(b"default")
        })
        .count();
    cases >= 1 && clauses < 3
}

/// `Class<?>` is how a class of unknown type is written; other wildcard
/// return types aren't exempt.
fn wildcard_is_not_a_class(method: Node, src: &[u8]) -> bool {
    method
        .child_by_field_name("type")
        .and_then(|t| t.named_child(0))
        .is_none_or(|base| text(base, src) != b"Class")
}

/// A field, local or parameter declared `ThreadGroup`, as SonarQube reports
/// it: not as a type argument (`Predicate<ThreadGroup>`) or a parameter of
/// a method that overrides one.
fn declares_a_thread_group(ty: Node, src: &[u8]) -> bool {
    let Some(declaration) = ty.parent() else {
        return false;
    };
    match declaration.kind() {
        "local_variable_declaration" | "field_declaration" => true,
        "formal_parameter" | "spread_parameter" => declaration
            .parent()
            .and_then(|params| params.parent())
            .is_none_or(|method| !has_annotation(method, b"Override", src)),
        _ => false,
    }
}

/// `items.stream().forEach(...)`: a collection's own stream, not a static
/// helper such as `stream(items)`.
fn streams_a_collection(call: Node, src: &[u8]) -> bool {
    call.child_by_field_name("object").is_some_and(|stream| {
        stream.child_by_field_name("object").is_some()
            && call_arguments(stream).is_empty()
            && method_name(stream, src) == b"stream"
    })
}

/// The first legacy date or time in a file: SonarQube reports the file once.
fn first_legacy_date_in_file(node: Node, src: &[u8]) -> bool {
    // Any use of the types, as SonarQube reports the file.
    let is_legacy = |n: Node| match n.kind() {
        "type_identifier" => {
            matches!(
                text(n, src),
                b"Date" | b"Calendar" | b"GregorianCalendar" | b"SimpleDateFormat"
            )
        }
        "method_invocation" => {
            n.child_by_field_name("object")
                .is_some_and(|o| text(o, src) == b"Calendar")
                && method_name(n, src) == b"getInstance"
        }
        _ => false,
    };
    let mut cursor = super::java_final::root_of(node).walk();
    loop {
        let n = cursor.node();
        if is_legacy(n) {
            return n.id() == node.id();
        }
        if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return false;
            }
        }
    }
}

fn switch_has_many_cases(switch: Node, src: &[u8]) -> bool {
    cases_of(switch, src) > 30
}

fn is_a_declared_type(ty: Node, _: &[u8]) -> bool {
    let mut node = ty;
    let mut parent = ty.parent();
    if let Some(g) = parent.filter(|p| p.kind() == "generic_type") {
        node = g;
        parent = g.parent();
    }
    // A local's type is the method's own business: SonarQube looks at
    // what other code sees, fields, parameters and return types.
    parent.is_some_and(|p| {
        matches!(
            p.kind(),
            "field_declaration" | "formal_parameter" | "method_declaration" | "spread_parameter"
        ) && p.child_by_field_name("type") == Some(node)
    })
}

fn variable_returned_immediately<'t>(block: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let items = statements(block);
    items.windows(2).find_map(|pair| {
        let declaration = pair[0];
        if declaration.kind() != "local_variable_declaration"
            || pair[1].kind() != "return_statement"
        {
            return None;
        }
        let declarators = children_of_kind(declaration, "variable_declarator");
        let [only] = declarators.as_slice() else {
            return None;
        };
        let name = only.child_by_field_name("name")?;
        only.child_by_field_name("value")?;
        let returned = pair[1].named_child(0)?;
        (returned.kind() == "identifier" && text(returned, src) == text(name, src))
            .then_some(pair[1])
    })
}

fn lambda_block_holds_one_statement(lambda: Node, _: &[u8]) -> bool {
    let Some(body) = lambda
        .child_by_field_name("body")
        .filter(|b| b.kind() == "block")
    else {
        return false;
    };
    matches!(statements(body).as_slice(), [only]
        if only.kind() == "expression_statement"
            || (only.kind() == "return_statement" && only.named_child_count() == 1))
}

fn anonymous_class_has_one_method(creation: Node, _: &[u8]) -> bool {
    let mut cursor = creation.walk();
    let Some(body) = creation
        .children(&mut cursor)
        .find(|c| c.kind() == "class_body")
    else {
        return false;
    };
    matches!(members(body).as_slice(), [only] if only.kind() == "method_declaration")
}

fn lambda_parameter_names<'a>(lambda: Node, src: &'a [u8]) -> Option<(Vec<&'a [u8]>, bool)> {
    let params = lambda.child_by_field_name("parameters")?;
    match params.kind() {
        "identifier" => Some((vec![text(params, src)], false)),
        "inferred_parameters" => {
            let mut c = params.walk();
            Some((
                params
                    .named_children(&mut c)
                    .map(|n| text(n, src))
                    .collect(),
                true,
            ))
        }
        _ => None,
    }
}

fn single_parenthesized_parameter(lambda: Node, src: &[u8]) -> bool {
    matches!(lambda_parameter_names(lambda, src), Some((names, true)) if names.len() == 1)
}

fn lambda_only_forwards_its_parameter(lambda: Node, src: &[u8]) -> bool {
    let Some((names, _)) = lambda_parameter_names(lambda, src) else {
        return false;
    };
    let [p] = names.as_slice() else {
        return false;
    };
    let Some(body) = lambda
        .child_by_field_name("body")
        .filter(|b| b.kind() == "method_invocation")
    else {
        return false;
    };
    let args = call_arguments(body);
    let object = body.child_by_field_name("object");
    match (object, args.as_slice()) {
        // x -> foo(x)
        (None, [a]) => text(*a, src) == *p,
        // x -> x.foo()
        (Some(o), []) => o.kind() == "identifier" && text(o, src) == *p,
        // x -> obj.foo(x)
        (Some(o), [a]) => {
            matches!(o.kind(), "identifier" | "this" | "field_access")
                && text(o, src) != *p
                && text(*a, src) == *p
        }
        _ => false,
    }
}

fn inside_a_loop(node: Node, _: &[u8]) -> bool {
    let mut p = node.parent();
    let mut hops = 0;
    while let Some(n) = p {
        if LOOPS.contains(&n.kind()) {
            return true;
        }
        if matches!(
            n.kind(),
            "method_declaration" | "lambda_expression" | "class_body" | "constructor_declaration"
        ) {
            return false;
        }
        hops += 1;
        if hops > 64 {
            return false;
        }
        p = n.parent();
    }
    false
}

fn declares_several_variables(declaration: Node, _: &[u8]) -> bool {
    children_of_kind(declaration, "variable_declarator").len() > 1
        && !declaration
            .parent()
            .is_some_and(|p| p.kind() == "for_statement")
}

fn field_named_like_its_class(field: Node, src: &[u8]) -> bool {
    let Some(class) = field
        .parent()
        .and_then(|b| b.parent())
        .filter(|c| c.kind() == "class_declaration")
    else {
        return false;
    };
    let Some(class_name) = class.child_by_field_name("name") else {
        return false;
    };
    declarator_names(field, src).contains(&text(class_name, src))
}

/// A member whose name matches an earlier one in the class: the same name
/// for a field and a method, or names differing only by case. Private fields
/// only clash with other fields.
fn name_differs_by_case_only(member: Node, src: &[u8]) -> bool {
    let Some(body) = member
        .parent()
        .filter(|p| matches!(p.kind(), "class_body" | "interface_body" | "enum_body"))
    else {
        return false;
    };
    let is_method = |m: Node| m.kind() == "method_declaration";
    let names_of = |m: Node| -> Vec<&[u8]> {
        match m.kind() {
            "field_declaration" | "constant_declaration" => declarator_names(m, src),
            "method_declaration" => m
                .child_by_field_name("name")
                .map(|n| vec![text(n, src)])
                .unwrap_or_default(),
            _ => Vec::new(),
        }
    };
    let mine = names_of(member);
    members(body)
        .into_iter()
        .filter(|m| m.id() != member.id())
        .filter(|m| {
            // a method and a private field do not clash
            is_method(*m) == is_method(member)
                || !(has_modifier(*m, "private") && !is_method(*m)
                    || has_modifier(member, "private") && !is_method(member))
        })
        .flat_map(|m| {
            let earlier = m.start_byte() < member.start_byte();
            let method_vs_field = is_method(m) != is_method(member);
            names_of(m)
                .into_iter()
                .map(move |n| (n, earlier, method_vs_field))
        })
        .any(|(other, earlier, method_vs_field)| {
            mine.iter().any(|n| {
                earlier && n.eq_ignore_ascii_case(other) && (method_vs_field || *n != other)
            })
        })
}

fn negates_a_comparison(unary: Node, src: &[u8]) -> bool {
    unary
        .child_by_field_name("operand")
        .and_then(|p| p.named_child(0))
        .is_some_and(|b| {
            b.kind() == "binary_expression"
                && matches!(
                    operator_text(b, src),
                    b"==" | b"!=" | b"<" | b">" | b"<=" | b">="
                )
        })
}

fn class_is_empty(class: Node, _: &[u8]) -> bool {
    class.child_by_field_name("superclass").is_none()
        && class.child_by_field_name("interfaces").is_none()
        && modifiers_of(class).is_none_or(|m| {
            let mut c = m.walk();
            !m.children(&mut c)
                .any(|k| matches!(k.kind(), "marker_annotation" | "annotation"))
        })
        && class.child_by_field_name("body").is_some_and(|b| {
            let mut c = b.walk();
            !b.named_children(&mut c)
                .any(|k| !matches!(k.kind(), "line_comment" | "block_comment"))
        })
}

/// `new Integer(5)`, `new BigDecimal("1.5")`, `new String("x")` or
/// `new String()`: what a literal or `valueOf` says. `new String(chars, 0,
/// n)` converts, and is left alone.
fn literal_or_value_of_would_do(creation: Node, src: &[u8]) -> bool {
    let args = call_arguments(creation);
    let is_string = creation
        .child_by_field_name("type")
        .is_some_and(|t| text(t, src) == b"String");
    if is_string {
        return matches!(args.as_slice(), [] | [_])
            && args.first().is_none_or(|a| a.kind() == "string_literal");
    }
    !args.is_empty()
}

fn catch_with_same_body_as_previous<'t>(try_: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let catches = children_of_kind(try_, "catch_clause");
    catches.windows(2).find_map(|pair| {
        let (a, b) = (
            pair[0].child_by_field_name("body")?,
            pair[1].child_by_field_name("body")?,
        );
        (a.named_child_count() > 0 && text(a, src) == text(b, src)).then_some(pair[1])
    })
}

fn has_no_superclass(class: Node, _: &[u8]) -> bool {
    class.child_by_field_name("superclass").is_none()
}

fn uses_non_short_circuit_operator(binary: Node, src: &[u8]) -> bool {
    if !matches!(operator_text(binary, src), b"&" | b"|") {
        return false;
    }
    let boolean_like = |n: Option<Node>| {
        n.is_some_and(|n| match n.kind() {
            "binary_expression" => matches!(
                operator_text(n, src),
                b"==" | b"!=" | b"<" | b">" | b"<=" | b">=" | b"&&" | b"||"
            ),
            "unary_expression" => operator_text(n, src) == b"!",
            "true" | "false" => true,
            _ => false,
        })
    };
    boolean_like(binary.child_by_field_name("left"))
        && boolean_like(binary.child_by_field_name("right"))
}

fn catches_illegal_monitor_state(catch: Node, src: &[u8]) -> bool {
    count_word(
        text(catch.named_child(0).unwrap_or(catch), src),
        b"IllegalMonitorStateException",
    ) > 0
}

fn public_static_holds_mutable_state(field: Node, src: &[u8]) -> bool {
    if !(field.parent().is_some_and(|p| p.kind() == "class_body")
        && has_modifier(field, "public")
        && has_modifier(field, "static"))
    {
        return false;
    }
    let Some(ty) = field.child_by_field_name("type") else {
        return false;
    };
    let head = text(ty, src)
        .split(|&b| b == b'<')
        .next()
        .unwrap_or(&b""[..]);
    let mutable = ty.kind() == "array_type"
        || matches!(
            head,
            b"List"
                | b"ArrayList"
                | b"Map"
                | b"HashMap"
                | b"Set"
                | b"HashSet"
                | b"Collection"
                | b"Date"
                | b"StringBuilder"
        );
    let wrapped = children_of_kind(field, "variable_declarator")
        .iter()
        .any(|d| {
            d.child_by_field_name("value").is_some_and(|v| {
                v.kind() == "method_invocation"
                    && (v
                        .child_by_field_name("object")
                        .is_some_and(|o| text(o, src) == b"Collections")
                        || matches!(method_name(v, src), b"of" | b"copyOf" | b"ofEntries"))
            })
        });
    // A zero-length array has nothing to change.
    let empty_array = children_of_kind(field, "variable_declarator")
        .iter()
        .all(|d| {
            d.child_by_field_name("value")
                .is_some_and(|v| match v.kind() {
                    "array_initializer" => v.named_child_count() == 0,
                    "array_creation_expression" => {
                        find_node(v, |n| {
                            n.kind() == "array_initializer" && n.named_child_count() == 0
                        })
                        .is_some()
                            || find_node(v, |n| {
                                n.kind() == "dimensions_expr" && text(n, src) == b"[0]"
                            })
                            .is_some()
                    }
                    _ => false,
                })
        });
    mutable && !wrapped && !empty_array
}

fn contains_a_tab_character(string: Node, src: &[u8]) -> bool {
    // A raw tab, other control characters or an invisible Unicode separator.
    std::str::from_utf8(text(string, src)).is_ok_and(|t| {
        t.chars().any(|c| {
            (c.is_control() && !matches!(c, '\n' | '\r'))
                || matches!(
                    c,
                    '\u{200B}'..='\u{200F}' | '\u{2028}' | '\u{2029}' | '\u{2060}' | '\u{FEFF}'
                )
        })
    })
}

fn concatenates_text(arg: Node, src: &[u8]) -> bool {
    arg.kind() == "binary_expression"
        && operator_text(arg, src) == b"+"
        && !is_all_literals(arg)
        && find_node(arg, |n| n.kind() == "string_literal").is_some()
}

fn logs_a_concatenated_message(call: Node, src: &[u8]) -> bool {
    call.child_by_field_name("object")
        .is_some_and(|o| contains_ignoring_case(text(o, src), b"log"))
        && call_arguments(call)
            .first()
            .is_some_and(|a| concatenates_text(*a, src))
}

fn checks_index_of_for_positive(binary: Node, src: &[u8]) -> bool {
    let (Some(l), Some(r)) = (
        binary.child_by_field_name("left"),
        binary.child_by_field_name("right"),
    ) else {
        return false;
    };
    l.kind() == "method_invocation"
        && matches!(method_name(l, src), b"indexOf" | b"lastIndexOf")
        && operator_text(binary, src) == b">"
        && text(r, src) == b"0"
}

fn catch_only_rethrows(catch: Node, src: &[u8]) -> bool {
    let (Some(param), Some(body)) = (catch.named_child(0), catch.child_by_field_name("body"))
    else {
        return false;
    };
    let Some(name) = param.child_by_field_name("name") else {
        return false;
    };
    matches!(statements(body).as_slice(), [only]
        if only.kind() == "throw_statement"
            && only.named_child(0).is_some_and(|t| text(t, src) == text(name, src)))
}

fn has_static_modifier(declaration: Node, _: &[u8]) -> bool {
    has_modifier(declaration, "static")
}

fn iterates_keys_and_looks_up_values(for_: Node, src: &[u8]) -> bool {
    let (Some(value), Some(name), Some(body)) = (
        for_.child_by_field_name("value"),
        for_.child_by_field_name("name"),
        for_.child_by_field_name("body"),
    ) else {
        return false;
    };
    if value.kind() != "method_invocation" || method_name(value, src) != b"keySet" {
        return false;
    }
    let Some(map) = value.child_by_field_name("object") else {
        return false;
    };
    find_node(body, |n| {
        n.kind() == "method_invocation"
            && method_name(n, src) == b"get"
            && n.child_by_field_name("object")
                .is_some_and(|o| text(o, src) == text(map, src))
            && call_arguments(n)
                .first()
                .is_some_and(|a| text(*a, src) == text(name, src))
    })
    .is_some()
}

fn takes_no_parameters(method: Node, src: &[u8]) -> bool {
    parameter_types(method, src).is_empty()
}

fn appends_a_concatenation(call: Node, src: &[u8]) -> bool {
    call_arguments(call)
        .first()
        .is_some_and(|a| concatenates_text(*a, src))
}

fn mutable_public_enum_field<'t>(enum_: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    let body = enum_.child_by_field_name("body")?;
    // Members after the constants sit inside enum_body_declarations.
    children_of_kind(body, "enum_body_declarations")
        .into_iter()
        .flat_map(|d| children_of_kind(d, "field_declaration"))
        .find(|f| has_modifier(*f, "public") && !has_modifier(*f, "final"))
}

fn contains_a_nested_ternary(ternary: Node, _: &[u8]) -> bool {
    let nested = |n: Option<Node>| {
        n.is_some_and(|n| {
            let inner = if n.kind() == "parenthesized_expression" {
                n.named_child(0)
            } else {
                Some(n)
            };
            inner.is_some_and(|i| i.kind() == "ternary_expression")
        })
    };
    nested(ternary.child_by_field_name("consequence"))
        || nested(ternary.child_by_field_name("alternative"))
}

fn private_method_returns_a_literal(method: Node, src: &[u8]) -> bool {
    let sealed = has_modifier(method, "private")
        || has_modifier(method, "static")
        || has_modifier(method, "final")
        || enclosing_class(method).is_some_and(|c| has_modifier(c, "final"));
    if !sealed || has_annotation(method, b"Override", src) {
        return false;
    }
    let Some(body) = method.child_by_field_name("body") else {
        return false;
    };
    matches!(statements(body).as_slice(), [only]
        if only.kind() == "return_statement" && only.named_child(0).is_some_and(is_literal_value))
}

fn logger_names_another_class(call: Node, src: &[u8]) -> bool {
    let Some(literal) = call_arguments(call).first().copied() else {
        return false;
    };
    let t = text(literal, src);
    let named = t.strip_suffix(b".class").unwrap_or(t);
    let mut p = call.parent();
    let mut hops = 0;
    let mut found_class = false;
    while let Some(n) = p {
        if matches!(
            n.kind(),
            "class_declaration" | "enum_declaration" | "record_declaration"
        ) {
            found_class = true;
            if n.child_by_field_name("name")
                .is_some_and(|c| text(c, src) == named)
            {
                return false;
            }
        }
        hops += 1;
        if hops > 64 {
            return false;
        }
        p = n.parent();
    }
    found_class
}

fn jump_is_redundant(jump: Node, _: &[u8]) -> bool {
    let Some(block) = jump.parent().filter(|p| p.kind() == "block") else {
        return false;
    };
    if statements(block).last() != Some(&jump) {
        return false;
    }
    let Some(owner) = block.parent() else {
        return false;
    };
    if jump.kind() == "return_statement" {
        jump.named_child_count() == 0 && owner.kind() == "method_declaration"
    } else {
        LOOPS.contains(&owner.kind())
    }
}

fn private_mapped_method(method: Node, src: &[u8]) -> bool {
    has_modifier(method, "private")
        && [
            "RequestMapping",
            "GetMapping",
            "PostMapping",
            "PutMapping",
            "DeleteMapping",
            "PatchMapping",
        ]
        .iter()
        .any(|a| has_annotation(method, a.as_bytes(), src))
}

fn one_argument(call: Node, _: &[u8]) -> bool {
    call_arguments(call).len() == 1
}

fn if_on_line_where_previous_ended<'t>(block: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    let items = statements(block);
    items.windows(2).find_map(|pair| {
        (pair[0].kind() == "if_statement"
            && pair[1].kind() == "if_statement"
            && pair[0].end_position().row == pair[1].start_position().row)
            .then_some(pair[1])
    })
}

/// A method whose body repeats an earlier method's with the same parameter
/// types. Overloads that differ in their parameter types cannot be merged.
fn method_duplicates_another(method: Node, src: &[u8]) -> bool {
    let (Some(body), Some(class_body)) = (method.child_by_field_name("body"), method.parent())
    else {
        return false;
    };
    let substantial =
        |b: Node| b.named_child_count() >= 2 && b.end_position().row - b.start_position().row >= 2;
    if !substantial(body) {
        return false;
    }
    let key = (parameter_types(method, src), text(body, src));
    members(class_body)
        .into_iter()
        .take_while(|m| m.start_byte() < method.start_byte())
        .filter(|m| m.kind() == "method_declaration")
        .any(|m| {
            m.child_by_field_name("body")
                .is_some_and(|b| (parameter_types(m, src), text(b, src)) == key)
        })
}

fn null_check_before_instanceof(binary: Node, src: &[u8]) -> bool {
    if operator_text(binary, src) != b"&&" {
        return false;
    }
    let (Some(l), Some(r)) = (
        binary.child_by_field_name("left"),
        binary.child_by_field_name("right"),
    ) else {
        return false;
    };
    if l.kind() != "binary_expression"
        || operator_text(l, src) != b"!="
        || r.kind() != "instanceof_expression"
    {
        return false;
    }
    let (Some(a), Some(b)) = (
        l.child_by_field_name("left"),
        l.child_by_field_name("right"),
    ) else {
        return false;
    };
    let tested = if b.kind() == "null_literal" { a } else { b };
    (a.kind() == "null_literal" || b.kind() == "null_literal")
        && r.named_child(0)
            .is_some_and(|x| text(x, src) == text(tested, src))
}

fn has_a_specialised_form(generic: Node, src: &[u8]) -> bool {
    let Some(args) = generic
        .named_child(1)
        .filter(|a| a.kind() == "type_arguments")
    else {
        return false;
    };
    let mut c = args.walk();
    let types: Vec<&[u8]> = args.named_children(&mut c).map(|t| text(t, src)).collect();
    match (
        text(generic.named_child(0).unwrap_or(generic), src),
        types.as_slice(),
    ) {
        (b"Function", [a, b]) => *b == b"Boolean" || a == b,
        (b"BiFunction", [a, b, c]) => a == b && b == c,
        (b"Supplier", [a]) => *a == b"Boolean",
        _ => false,
    }
}

fn default_is_not_last(switch: Node, src: &[u8]) -> bool {
    let Some(block) = switch.child_by_field_name("body") else {
        return false;
    };
    let mut cursor = block.walk();
    let groups: Vec<Node> = block.named_children(&mut cursor).collect();
    groups
        .iter()
        .position(|g| {
            let mut c = g.walk();
            g.named_children(&mut c)
                .any(|l| l.kind() == "switch_label" && text(l, src).starts_with(b"default"))
        })
        .is_some_and(|i| i + 1 < groups.len())
}

fn else_binds_to_inner_if(statement: Node, _: &[u8]) -> bool {
    statement.child_by_field_name("alternative").is_none()
        && statement
            .child_by_field_name("consequence")
            .is_some_and(|c| {
                c.kind() == "if_statement" && c.child_by_field_name("alternative").is_some()
            })
}

fn replace_pattern_is_plain_text(call: Node, src: &[u8]) -> bool {
    let args = call_arguments(call);
    args.len() == 2
        && string_value(args[0], src)
            .is_some_and(|p| !p.is_empty() && !p.iter().any(|b| b".^$*+?{}[]\\|()".contains(b)))
}

fn asserts_a_comparison(call: Node, src: &[u8]) -> bool {
    let mut args = call_arguments(call);
    if args.len() == 2 && args[0].kind() == "string_literal" {
        args.remove(0);
    }
    let [condition] = args.as_slice() else {
        return false;
    };
    match condition.kind() {
        "binary_expression" => matches!(operator_text(*condition, src), b"==" | b"!="),
        "method_invocation" => {
            method_name(*condition, src) == b"equals"
                && call_arguments(*condition).len() == 1
                && condition.child_by_field_name("object").is_some()
        }
        _ => false,
    }
}

fn public_constructor_of_abstract_class<'t>(class: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    if !has_modifier(class, "abstract") {
        return None;
    }
    let body = class.child_by_field_name("body")?;
    members(body)
        .into_iter()
        .find(|m| m.kind() == "constructor_declaration" && has_modifier(*m, "public"))
}

fn annotates_a_field(annotation: Node, _: &[u8]) -> bool {
    owning_declaration(annotation).is_some_and(|d| d.kind() == "field_declaration")
}

fn on_rest_controller_method(annotation: Node, src: &[u8]) -> bool {
    owning_declaration(annotation)
        .filter(|d| d.kind() == "method_declaration")
        .and_then(enclosing_class)
        .is_some_and(|c| has_annotation(c, b"RestController", src))
}

fn annotates_a_static_field(annotation: Node, _: &[u8]) -> bool {
    owning_declaration(annotation)
        .is_some_and(|d| d.kind() == "field_declaration" && has_modifier(d, "static"))
}

fn init_binder_returns_a_value(method: Node, src: &[u8]) -> bool {
    has_annotation(method, b"InitBinder", src)
        && method
            .child_by_field_name("type")
            .is_some_and(|t| text(t, src) != b"void")
}

fn label_is_unused(labeled: Node, src: &[u8]) -> bool {
    let Some(label) = labeled.named_child(0).filter(|l| l.kind() == "identifier") else {
        return false;
    };
    find_node(labeled, |n| {
        matches!(n.kind(), "break_statement" | "continue_statement")
            && n.named_child(0)
                .is_some_and(|l| text(l, src) == text(label, src))
    })
    .is_none()
}

/// The inner `if`, where SonarQube reports the merge.
fn if_only_wraps_another_if<'t>(statement: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    statement
        .child_by_field_name("alternative")
        .is_none()
        .then_some(())?;
    let body = statement.child_by_field_name("consequence")?;
    let inner = if body.kind() == "block" {
        match statements(body).as_slice() {
            [only] => *only,
            _ => return None,
        }
    } else {
        body
    };
    (inner.kind() == "if_statement" && inner.child_by_field_name("alternative").is_none())
        .then_some(inner)
}

fn parentheses_fit_on_one_line(paren: Node, _: &[u8]) -> bool {
    paren.start_position().row == paren.end_position().row
}

fn finalize_is_public(method: Node, src: &[u8]) -> bool {
    has_modifier(method, "public") && parameter_types(method, src).is_empty()
}

fn chain_repeats_a_branch<'t>(statement: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if statement.parent().is_some_and(|p| {
        p.kind() == "if_statement" && p.child_by_field_name("alternative") == Some(statement)
    }) {
        return None;
    }
    let mut bodies: Vec<Node> = Vec::new();
    let mut current = Some(statement);
    while let Some(branch) = current {
        bodies.extend(branch.child_by_field_name("consequence"));
        match branch.child_by_field_name("alternative") {
            Some(a) if a.kind() == "if_statement" => current = Some(a),
            Some(a) => {
                bodies.push(a);
                current = None;
            }
            None => current = None,
        }
    }
    let mut seen: Vec<&[u8]> = Vec::new();
    for body in bodies {
        if body.kind() != "block" || body.named_child_count() < 2 {
            continue;
        }
        let t = text(body, src);
        if seen.contains(&t) {
            return Some(body);
        }
        seen.push(t);
    }
    None
}

fn switch_statement_lacks_default(switch: Node, src: &[u8]) -> bool {
    // A switch that produces a value must be exhaustive by itself.
    if switch.parent().is_some_and(|p| {
        !matches!(
            p.kind(),
            "expression_statement" | "block" | "switch_block_statement_group"
        )
    }) {
        return false;
    }
    let labels = case_labels(switch);
    !labels.is_empty() && !labels.iter().any(|l| text(*l, src).starts_with(b"default"))
}

fn loop_has_several_jumps(loop_: Node, _: &[u8]) -> bool {
    let Some(body) = loop_.child_by_field_name("body") else {
        return false;
    };
    let mut count = 0;
    let mut stack: Vec<(Node, bool)> = vec![(body, false)];
    while let Some((node, in_switch)) = stack.pop() {
        match node.kind() {
            "continue_statement" => count += 1,
            "break_statement" if !in_switch => count += 1,
            _ => {}
        }
        if LOOPS.contains(&node.kind()) && node != body
            || matches!(node.kind(), "lambda_expression" | "class_body")
        {
            continue;
        }
        let nested = in_switch || node.kind() == "switch_expression";
        let mut c = node.walk();
        for child in node.named_children(&mut c) {
            stack.push((child, nested));
        }
    }
    count > 1
}

fn private_method_is_never_used(method: Node, src: &[u8]) -> bool {
    if !has_modifier(method, "private") {
        return false;
    }
    if modifiers_of(method).is_some_and(|m| {
        let mut c = m.walk();
        m.children(&mut c)
            .any(|k| matches!(k.kind(), "marker_annotation" | "annotation"))
    }) {
        return false;
    }
    let Some(name) = method.child_by_field_name("name") else {
        return false;
    };
    let n = text(name, src);
    !matches!(
        n,
        b"readObject" | b"writeObject" | b"readResolve" | b"writeReplace" | b"readObjectNoData"
    ) && identifier_uses(super::java_final::root_of(method), n, src) == 1
}

fn private_field_is_never_used(field: Node, src: &[u8]) -> bool {
    if !has_modifier(field, "private") {
        return false;
    }
    if modifiers_of(field).is_some_and(|m| {
        let mut c = m.walk();
        m.children(&mut c)
            .any(|k| matches!(k.kind(), "marker_annotation" | "annotation"))
    }) {
        return false;
    }
    // Lombok and similar generate the accessors that use these fields.
    if enclosing_class(field).is_some_and(|c| {
        modifiers_of(c).is_some_and(|m| {
            let mut cur = m.walk();
            m.children(&mut cur)
                .any(|k| matches!(k.kind(), "marker_annotation" | "annotation"))
        })
    }) {
        return false;
    }
    // Another class in the file using the same name does not use this field;
    // only an access through an object (`x.name`) from outside could.
    let class = enclosing_class(field);
    declarator_names(field, src).iter().any(|n| {
        if *n == b"serialVersionUID" {
            return false;
        }
        match class {
            Some(c) => {
                !file_accesses_member(src, n)
                    && (identifier_uses(c, n, src) == 1 || field_is_only_written(c, n, src))
            }
            None => count_word(src, n) == 1,
        }
    })
}

/// Whether every use of the field inside the class is an assignment to it,
/// so nothing ever reads the value.
fn field_is_only_written(class: Node, name: &[u8], src: &[u8]) -> bool {
    let mut cursor = class.walk();
    let (mut writes, mut reads) = (0, 0);
    loop {
        let n = cursor.node();
        if n.kind() == "identifier" && text(n, src) == name {
            match field_use(n, name, src) {
                Some(FieldUse::Write) => writes += 1,
                Some(FieldUse::Read) => reads += 1,
                None => {}
            }
        }
        if cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return writes > 0 && reads == 0;
            }
        }
    }
}

enum FieldUse {
    Write,
    Read,
}

/// What the identifier `n`, named like the field, does with it: assigns
/// it, reads it, or neither (it declares the field, or a local shadows it).
fn field_use(n: Node, name: &[u8], src: &[u8]) -> Option<FieldUse> {
    let parent = n.parent();
    if parent.is_some_and(|p| p.kind() == "variable_declarator") {
        return None;
    }
    let is_this_field = parent.is_some_and(|p| {
        p.kind() == "field_access"
            && p.child_by_field_name("field")
                .is_some_and(|f| f.id() == n.id())
    });
    let target = if is_this_field { parent } else { Some(n) };
    let assigned = target
        .and_then(|t| t.parent().map(|p| (t, p)))
        .is_some_and(|(t, p)| {
            p.kind() == "assignment_expression"
                && operator_text(p, src) == b"="
                && p.child_by_field_name("left")
                    .is_some_and(|l| l.id() == t.id())
        });
    if assigned {
        Some(FieldUse::Write)
    } else if is_this_field || !name_is_shadowed(n, name, src) {
        Some(FieldUse::Read)
    } else {
        None
    }
}

/// Whether a parameter or local of this name is in scope at `use_site`.
fn name_is_shadowed(use_site: Node, name: &[u8], src: &[u8]) -> bool {
    let mut p = use_site.parent();
    while let Some(n) = p {
        if matches!(n.kind(), "method_declaration" | "constructor_declaration") {
            let param = n.child_by_field_name("parameters").is_some_and(|ps| {
                let mut c = ps.walk();
                ps.named_children(&mut c).any(|fp| {
                    fp.child_by_field_name("name")
                        .is_some_and(|x| text(x, src) == name)
                })
            });
            return param || count_word(text(n, src), name) > 0 && local_declares(n, name, src);
        }
        p = n.parent();
    }
    false
}

fn local_declares(scope: Node, name: &[u8], src: &[u8]) -> bool {
    find_node(scope, |x| {
        x.kind() == "local_variable_declaration" && declarator_names(x, src).contains(&name)
    })
    .is_some()
}

/// Whether `.name` appears anywhere in the file as a member access.
fn file_accesses_member(src: &[u8], name: &[u8]) -> bool {
    let mut dotted = Vec::with_capacity(name.len() + 1);
    dotted.push(b'.');
    dotted.extend_from_slice(name);
    let mut from = 0;
    while let Some(i) = src[from..].windows(dotted.len()).position(|w| w == dotted) {
        let end = from + i + dotted.len();
        let whole_word = !src
            .get(end)
            .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_');
        if whole_word && !src[..from + i].ends_with(b"this") {
            return true;
        }
        from = end;
    }
    false
}

fn private_class_is_never_used(class: Node, src: &[u8]) -> bool {
    has_modifier(class, "private")
        && class
            .child_by_field_name("name")
            .is_some_and(|n| count_word(src, text(n, src)) == 1)
}

fn local_is_never_used(declaration: Node, src: &[u8]) -> bool {
    if has_annotation(declaration, b"SuppressWarnings", src) {
        return false;
    }
    let mut owner = declaration.parent();
    let mut hops = 0;
    while let Some(n) = owner {
        if matches!(
            n.kind(),
            "method_declaration"
                | "constructor_declaration"
                | "lambda_expression"
                | "static_initializer"
        ) {
            break;
        }
        hops += 1;
        if hops > 64 {
            return false;
        }
        owner = n.parent();
    }
    let Some(scope) = owner else {
        return false;
    };
    declarator_names(declaration, src)
        .iter()
        .any(|n| *n != b"_" && identifier_uses(scope, n, src) == 1)
}

/// How many identifiers in `scope` carry this name; comments and string
/// contents that happen to contain it do not count as uses.
fn identifier_uses(scope: Node, name: &[u8], src: &[u8]) -> usize {
    let mut count = 0;
    let mut cursor = scope.walk();
    'walk: loop {
        let n = cursor.node();
        if n.kind() == "identifier" && text(n, src) == name {
            count += 1;
        }
        if cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() || cursor.node().id() == scope.id() {
                break 'walk;
            }
        }
    }
    count
}

/// Whether this is the first of three or more equal literals in the file,
/// as SonarQube counts them: five characters or more (quotes included in Sonar's seven), outside annotations.
fn is_first_of_a_repeated_string(string: Node, src: &[u8]) -> bool {
    use std::cell::RefCell;
    thread_local! {
        static CACHE: RefCell<Option<((usize, usize), StringCounts)>> = const { RefCell::new(None) };
    }
    let Some(mine) = countable_string(string, src) else {
        return false;
    };
    let key = (src.as_ptr() as usize, src.len());
    CACHE.with(|c| {
        let mut c = c.borrow_mut();
        if c.as_ref().is_none_or(|(k, _)| *k != key) {
            *c = Some((key, string_counts(string, src)));
        }
        c.as_ref()
            .and_then(|(_, counts)| counts.get(&mine))
            .is_some_and(|(count, first)| *count >= 3 && *first == string.start_byte())
    })
}

/// A literal passed to an exception's constructor, alone or concatenated.
fn is_exception_message(literal: Node, src: &[u8]) -> bool {
    let mut n = literal;
    while let Some(p) = n.parent().filter(|p| p.kind() == "binary_expression") {
        n = p;
    }
    n.parent()
        .filter(|a| a.kind() == "argument_list")
        .and_then(|a| a.parent())
        .filter(|c| c.kind() == "object_creation_expression")
        .and_then(|c| c.child_by_field_name("type"))
        .is_some_and(|t| {
            let t = text(t, src);
            t.ends_with(b"Exception") || t.ends_with(b"Error")
        })
}

/// Each countable string's value: how many times it occurs, and where first.
type StringCounts = std::collections::HashMap<Vec<u8>, (usize, usize)>;

/// A string literal's value, when it counts: five characters or more, not
/// in an annotation, and not an exception's message (`throw new
/// IllegalStateException("...")`), which SonarQube leaves out.
fn countable_string(n: Node, src: &[u8]) -> Option<Vec<u8>> {
    if n.kind() != "string_literal"
        || is_exception_message(n, src)
        || n.parent().is_some_and(|p| {
            matches!(
                p.kind(),
                "element_value_pair"
                    | "annotation_argument_list"
                    | "annotation"
                    | "marker_annotation"
            )
        })
    {
        return None;
    }
    string_value(n, src)
        .filter(|v| v.len() >= 5)
        .map(<[u8]>::to_vec)
}

/// The countable strings of the file `string` is in.
fn string_counts(string: Node, src: &[u8]) -> StringCounts {
    let mut counts = StringCounts::new();
    let mut root = string;
    while let Some(p) = root.parent() {
        root = p;
    }
    let mut cursor = root.walk();
    if !cursor.goto_first_child() {
        return counts;
    }
    loop {
        let n = cursor.node();
        if let Some(v) = countable_string(n, src) {
            counts.entry(v).or_insert((0, n.start_byte())).0 += 1;
        }
        if cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return counts;
            }
        }
    }
}

fn casts_after_instanceof(statement: Node, src: &[u8]) -> bool {
    let (Some(condition), Some(body)) = (
        statement.child_by_field_name("condition"),
        statement.child_by_field_name("consequence"),
    ) else {
        return false;
    };
    let test = if condition.kind() == "parenthesized_expression" {
        condition.named_child(0)
    } else {
        Some(condition)
    };
    let Some(test) = test.filter(|t| t.kind() == "instanceof_expression") else {
        return false;
    };
    // `x instanceof T t` already binds a variable.
    if test.named_child_count() != 2 {
        return false;
    }
    let (Some(value), Some(ty)) = (test.named_child(0), test.named_child(1)) else {
        return false;
    };
    find_node(body, |n| {
        n.kind() == "cast_expression"
            && n.child_by_field_name("type")
                .is_some_and(|t| text(t, src) == text(ty, src))
            && n.child_by_field_name("value")
                .is_some_and(|v| text(v, src) == text(value, src))
    })
    .is_some()
}

fn several_constructors_without_autowired<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if ![
        "Component",
        "Service",
        "Repository",
        "Controller",
        "RestController",
        "Configuration",
    ]
    .iter()
    .any(|a| has_annotation(class, a.as_bytes(), src))
    {
        return None;
    }
    let body = class.child_by_field_name("body")?;
    let constructors: Vec<Node> = members(body)
        .into_iter()
        .filter(|m| m.kind() == "constructor_declaration")
        .collect();
    if constructors.len() < 2
        || constructors
            .iter()
            .any(|c| has_annotation(*c, b"Autowired", src))
    {
        return None;
    }
    constructors.get(1).copied()
}

fn compares_with_empty_string(node: Node, src: &[u8]) -> bool {
    if node.kind() == "method_invocation" {
        return true;
    }
    let (Some(l), Some(r)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return false;
    };
    // A String's: CharSequence.isEmpty() needs Java 15, and the receiver's
    // type isn't known otherwise.
    let a_string = |o: Node| {
        o.kind() == "string_literal"
            || o.kind() == "identifier"
                && declared_type(o, text(o, src), src)
                    .is_some_and(|t| type_text(Some(t), src) == b"String")
    };
    l.kind() == "method_invocation"
        && method_name(l, src) == b"length"
        && call_arguments(l).is_empty()
        && l.child_by_field_name("object").is_some_and(a_string)
        && matches!(
            (operator_text(node, src), text(r, src)),
            (b"==", b"0") | (b"!=", b"0") | (b">", b"0")
        )
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
        // Rules that are off by default still have to work when enabled.
        cfg.rules.enabled = vec![
            "java/instanceof-then-cast".into(),
            "java/collectors-to-list".into(),
        ];
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let file = analyze("t", Lang::Java, src, &rules, &cfg, far_deadline()).unwrap();
        file.issues
            .iter()
            .filter(|i| i.rule == rule)
            .map(|i| i.line)
            .collect()
    }

    #[test]
    fn naming_conventions() {
        let src = "class my_class {\nstatic final int maxSize = 1;\nstatic final int MAX_SIZE = 1;\nstatic final Logger log = null;\nint My_field;\nint good;\nvoid Do_it(int Bad_param, int ok) { int Local_var = 1; int fine = 2; }\n@Test void should_work() {}\n}\ninterface lower {}\nclass Box<Item, T, T2> {}";
        assert_eq!(flagged("java/class-name", src), [1]);
        assert_eq!(flagged("java/interface-name", src), [10]);
        assert_eq!(flagged("java/constant-name", src), [2]);
        assert_eq!(flagged("java/field-name", src), [5]);
        assert_eq!(flagged("java/method-name", src), [7, 8]);
        assert_eq!(flagged("java/local-variable-name", src), [7, 7]);
        assert_eq!(flagged("java/type-parameter-name", src), [11]);
    }

    #[test]
    fn utility_classes() {
        let src = "class U { static int f() { return 1; } }\nclass V { private V() {} static int f() { return 1; } }\nclass W { int f() { return 1; } static int g() { return 1; } }\nclass M { public static void main(String[] a) {} }\nclass X extends Y { static int f() { return 1; } }\nclass P { public P() {} static int f() { return 1; } }";
        assert_eq!(flagged("java/utility-class-constructor", src), [1, 6]);
    }

    #[test]
    fn assignments_in_expressions() {
        let src = "class A { void f() {\nint x;\nx = 1;\nint a, b;\na = b = 2;\nif ((x = g()) > 0) {}\nwhile ((x = g()) > 0) {}\nfor (x = 0; x < 3; x = x + 1) {}\nrun(() -> x = 4);\n} }";
        assert_eq!(flagged("java/assignment-in-subexpression", src), [6]);
    }

    #[test]
    fn modifiers_and_booleans() {
        let src = "class A {\nfinal static int X = 1;\nstatic final int Y = 1;\npublic abstract void f();\nabstract public void g();\nboolean h(boolean b) { return b == true || b && false || b; }\nboolean i(boolean b) { return b ? true : false; }\nboolean j(boolean b) { return b ? true : b; }\n}";
        assert_eq!(flagged("java/modifier-order", src), [2, 5]);
        assert_eq!(flagged("java/redundant-boolean-literal", src), [6, 6, 7]);
    }

    #[test]
    fn unused_imports_and_privates() {
        let src = "import java.util.List;\nimport java.util.Map;\nimport static java.lang.Math.max;\nimport java.io.*;\nclass A {\nList<String> l;\nprivate int unusedField;\nprivate int usedField;\nprivate void unusedMethod() {}\nprivate void usedMethod() {}\nvoid f() { usedMethod(); usedField++; int unusedLocal = 1; int usedLocal = 2; use(usedLocal); }\nprivate static class Unused {}\nprivate static class Used {}\nUsed u;\n}";
        assert_eq!(flagged("java/unused-import", src), [2]);
        assert_eq!(flagged("java/unused-private-field", src), [7]);
        assert_eq!(flagged("java/unused-private-method", src), [9]);
        assert_eq!(flagged("java/unused-private-class", src), [12]);
        assert_eq!(flagged("java/unused-local-variable", src), [11]);
    }

    #[test]
    fn lambdas() {
        let src = "class A { void f() {\nrun(x -> g(x));\nrun(x -> x.foo());\nrun(x -> obj.m(x));\nrun(x -> g(x, 1));\nrun((x) -> x + 1);\nrun(x -> { return x; });\nrun(x -> { a(); b(); });\nrun((x, y) -> g(x));\n} }";
        assert_eq!(flagged("java/lambda-to-method-reference", src), [2, 3, 4]);
        assert_eq!(flagged("java/lambda-parenthesized-parameter", src), [6]);
        assert_eq!(flagged("java/lambda-single-statement-block", src), [7]);
    }

    #[test]
    fn switches() {
        let src = "class A { void f(int x) {\nswitch (x) { case 1: a(); break; case 2: b(); break; default: c(); }\nswitch (x) { case 1: a(); break; case 2: b(); break; case 3: c(); break; default: d(); }\nswitch (x) { case 1: a(); break; case 2: b(); break; case 3: c(); break; }\nswitch (x) { default: a(); break; case 1: b(); break; }\n} }";
        // Two cases and a default are three clauses, as SonarQube counts.
        assert_eq!(flagged("java/switch-too-few-cases", src), [5]);
        assert_eq!(flagged("java/switch-without-default", src), [4]);
        assert_eq!(flagged("java/default-not-last", src), [5]);
    }

    #[test]
    fn exceptions() {
        let src = "class A { void f() {\ntry { g(); } catch (IOException e) { log(e); } catch (SQLException e) { log(e); }\ntry { g(); } catch (Throwable t) {}\ntry { g(); } catch (IOException e) { throw e; }\ntry { g(); } finally { throw new IllegalStateException(); }\ntry { try { g(); } catch (Exception e) {} } catch (Error e) {}\nthrow new RuntimeException(\"x\");\nthrow new IllegalStateException(\"x\");\n} }";
        assert_eq!(flagged("java/combine-catches", src), [2]);
        assert_eq!(flagged("java/throwable-caught", src), [3, 6]);
        assert_eq!(flagged("java/catch-only-rethrows", src), [4]);
        assert_eq!(flagged("java/throw-in-finally", src), [5]);
        assert_eq!(flagged("java/nested-try", src), [6]);
        assert_eq!(flagged("java/generic-exception-thrown", src), [7]);
    }

    #[test]
    fn conditions_and_loops() {
        let src = "class A { boolean f(Object o, List l, String s) {\nif (a) { if (b) { g(); } }\nif (a) { g(); } else { h(); }\nif (!(a == b)) {}\nboolean r = o != null && o instanceof String;\nboolean t = l.size() == 0;\nboolean u = s.indexOf(\"x\") > 0;\nfor (; i < 3; ) {}\nfor (int k = 0; k < 3; k++) { String z = \"\"; z += \"a\"; }\nz += \"b\";\nreturn x;\n} }";
        assert_eq!(flagged("java/mergeable-if", src), [2]);
        assert_eq!(flagged("java/inverted-boolean", src), [4]);
        assert_eq!(flagged("java/null-check-with-instanceof", src), [5]);
        assert_eq!(flagged("java/size-compared-to-zero", src), [6]);
        assert_eq!(flagged("java/index-of-positive", src), [7]);
        assert_eq!(flagged("java/for-as-while", src), [8]);
        assert_eq!(flagged("java/string-concatenation-in-loop", src), [9]);
    }

    #[test]
    fn strings_and_logging() {
        let src = "class A { void f(int id) {\nlogger.debug(\"id=\" + id);\nlogger.debug(\"id={}\", id);\nlogger.debug(\"a\" + \"b\");\nsb.append(a + \"x\");\nsb.append(\"x\");\ns.replaceAll(\"a\", \"b\");\ns.replaceAll(\"a+\", \"b\");\ns.getBytes(\"UTF-8\");\nString t = \"a\tb\";\nString u = \"\" + String.valueOf(id);\nObject o = new Integer(3);\nObject p = new Integer();\n} }";
        assert_eq!(flagged("java/log-argument-concatenation", src), [2]);
        assert_eq!(flagged("java/append-concatenation", src), [5]);
        assert_eq!(flagged("java/replace-all-literal", src), [7]);
        assert_eq!(flagged("java/charset-constant", src), [9]);
        assert_eq!(flagged("java/control-character-in-literal", src), [10]);
        assert_eq!(flagged("java/value-of-in-concatenation", src), [11]);
        assert_eq!(flagged("java/wrapper-constructor", src), [12]);
    }

    #[test]
    fn classes_and_members() {
        let src = "abstract class A {\npublic A() {}\n}\nclass Empty {}\nclass Marker { int id; }\nclass FooException {}\nclass BarException extends Exception {}\nclass Dup { int value; int Value() { return 0; } }\nclass Own { int Own; }\nclass Cmp implements Comparable<Cmp> { public int compareTo(Cmp o) { return 0; } }\ninterface K { int A = 1; }\ninterface L { void f(); }";
        assert_eq!(flagged("java/abstract-class-public-constructor", src), [2]);
        assert_eq!(flagged("java/empty-class", src), [4, 6]);
        assert_eq!(flagged("java/exception-class-name", src), [6]);
        assert_eq!(flagged("java/names-differ-by-case", src), [8]);
        assert_eq!(flagged("java/field-named-like-class", src), [9]);
        assert_eq!(flagged("java/compareto-without-equals", src), [10]);
        assert_eq!(flagged("java/constants-interface", src), [11]);
    }

    #[test]
    fn spring_annotations() {
        let src = "@RestController class A {\n@Autowired private B b;\n@Autowired static C c;\n@ResponseBody String f() { return \"\"; }\n@GetMapping(\"/x\") private String g() { return \"\"; }\n@InitBinder String h() { return \"\"; }\n}\n@Component class D { D() {} D(B b) {} }\n@Component class E { E() {} @Autowired E(B b) {} }";
        assert_eq!(flagged("java/field-injection", src), [2, 3]);
        assert_eq!(flagged("java/static-field-injection", src), [3]);
        assert_eq!(flagged("java/redundant-response-body", src), [4]);
        assert_eq!(flagged("java/private-request-mapping", src), [5]);
        assert_eq!(flagged("java/init-binder-return", src), [6]);
        assert_eq!(flagged("java/autowired-with-many-constructors", src), [8]);
    }

    #[test]
    fn small_checks() {
        let src = "class A {\nObject f() { return Collections.EMPTY_LIST; }\nint a[];\nint b()[] { return null; }\nint c = 1, d = 2;\nvoid g() { { h(); } }\nint i(int a) { return a > 1 ? 1 : a > 0 ? 2 : 3; }\nprivate int j() { return 3; }\nvoid k() { System.gc(); }\nboolean l(int x, int y) { return x > 1 & y > 1; }\nint m() { int r = n(); return r; }\nvoid o() { return; }\nvoid p() { for (;;) { q(); continue; } }\nprotected void finalize() {}\npublic void finalize(int x) {}\n}";
        assert_eq!(flagged("java/empty-collection-constant", src), [2]);
        assert_eq!(flagged("java/array-designator-on-variable", src), [3]);
        assert_eq!(flagged("java/array-designator-on-method", src), [4]);
        assert_eq!(flagged("java/multiple-variables-per-line", src), [5]);
        assert_eq!(flagged("java/nested-block", src), [6]);
        assert_eq!(flagged("java/nested-ternary", src), [7]);
        assert_eq!(flagged("java/method-returns-constant", src), [8]);
        assert_eq!(flagged("java/explicit-gc", src), [9]);
        assert_eq!(flagged("java/non-short-circuit", src), [10]);
        assert_eq!(flagged("java/return-after-assignment", src), [11]);
        assert_eq!(flagged("java/redundant-jump", src), [12, 13]);
        assert_eq!(flagged("java/finalize-overridden", src), [14]);
    }

    #[test]
    fn duplicates() {
        let src = "class A {\nint a() {\nint x = 1;\nreturn x + 1;\n}\nint b() {\nint x = 1;\nreturn x + 1;\n}\nvoid f() {\nif (p) { g(); h(); } else if (q) { g(); h(); }\nif (r) { g(); } else if (s) { g(); }\n}\nString m() { return \"connection failed\" + \"connection failed\" + \"connection failed\"; }\n}";
        assert_eq!(flagged("java/identical-methods", src), [6]);
        assert_eq!(flagged("java/identical-branches-in-chain", src), [11]);
        assert_eq!(flagged("java/duplicated-string", src), [14]);
    }

    #[test]
    fn labels_and_jumps() {
        let src = "class A { void f() {\nouter: for (;;) { break outer; }\nunused: for (;;) { break; }\nfor (;;) { if (a) { break; } if (b) { continue; } }\nfor (;;) { switch (x) { case 1: break; } if (a) { break; } }\n} }";
        assert_eq!(flagged("java/labels", src), [2, 3]);
        assert_eq!(flagged("java/unused-label", src), [3]);
        assert_eq!(flagged("java/multiple-jumps-in-loop", src), [4]);
    }

    #[test]
    fn false_positives_found_in_real_code() {
        let src = "class A {\nint a(byte[] x) {\nint r = 0;\nreturn r + 1;\n}\nint a(char[] x) {\nint r = 0;\nreturn r + 1;\n}\npublic static final byte[] EMPTY = {};\npublic static final byte[] NONE = new byte[0];\npublic static final byte[] FULL = {1};\nvoid f() { @SuppressWarnings(\"unused\") int quiet = 1; int loud = 2; }\nObject g() { return new Object() { }.getClass(); }\nObject h() { return new Date().getClass(); }\nvoid i() { assertTrue(Util.equals(a, b)); assertTrue(a.equals(b)); }\n}";
        assert!(flagged("java/identical-methods", src).is_empty());
        assert_eq!(flagged("java/mutable-public-static", src), [12]);
        assert_eq!(flagged("java/unused-local-variable", src), [13]);
        assert_eq!(flagged("java/object-for-get-class", src), [14, 15]);
        assert_eq!(flagged("java/junit-assert-simplifiable", src), [16]);
    }

    #[test]
    fn unrelated_checks() {
        let src = "package p;\nclass A {\nObject f(Object o) { if (o instanceof String) { String s = (String) o; return s; } return null; }\nString g(String s) { return s.length() == 0 ? \"\" : s; }\nboolean h(String s) { return s.equals(\"\"); }\nBoolean i() { return null; }\nList<String> j() { return null; }\npublic final int MAX = 3;\n{ init(); }\nvoid k(Map<String, String> m) { for (String key : m.keySet()) { use(m.get(key)); } }\n}";
        assert_eq!(flagged("java/instanceof-then-cast", src), [3]);
        assert_eq!(flagged("java/empty-string-comparison", src), [4, 5]);
        assert_eq!(flagged("java/null-from-boolean-method", src), [6]);
        assert_eq!(flagged("java/null-instead-of-empty", src), [7]);
        assert_eq!(flagged("java/final-field-should-be-static", src), [8]);
        assert_eq!(flagged("java/instance-initializer", src), [9]);
        assert_eq!(flagged("java/key-set-iteration", src), [10]);
        assert!(flagged("java/default-package", src).is_empty());
    }

    #[test]
    fn write_only_private_fields_are_unused() {
        let src = "class A {\nprivate final Object written;\nprivate final Object read;\nA(Object written, Object read) { this.written = written; this.read = read; }\nObject get() { return read; }\n}";
        assert_eq!(flagged("java/unused-private-field", src), [2]);
    }

    #[test]
    fn string_names_compared_by_reference() {
        let src = "class A {\nboolean f(String a, String b, int n, int m) { return a == b; }\nboolean g(int n, int m) { return n == m; }\nboolean h(Integer a, String b) { return a == b; }\n}";
        assert_eq!(flagged("java/string-reference-equality", src), [2, 4]);
    }

    /// As SonarQube 26.7 reports these on Apache Commons Lang.
    #[test]
    fn java_cases_measured_on_sonarqube() {
        // S2129: a literal or valueOf would do; a conversion wouldn't.
        let src = "class A { Object f(char[] c, Integer i) {\nString a = new String(\"x\");\nString b = new String(c, 0, 2);\nreturn new Integer(5);\n} }";
        assert_eq!(flagged("java/wrapper-constructor", src), [2, 4]);
        // S1319: what other code sees, not a local.
        let src = "import java.util.*;\nclass A {\npublic HashMap<String, Integer> m() {\nHashMap<String, Integer> local = new HashMap<>();\nreturn local;\n}\n}";
        assert_eq!(flagged("java/concrete-collection-type", src), [3]);
        // S1452: Class<?> is fine.
        let src = "import java.util.*;\nclass A {\npublic Class<?> c() { return null; }\npublic List<?> l() { return null; }\n}";
        assert_eq!(flagged("java/wildcard-return-type", src), [4]);
        // S3014: a declaration, not a type argument or an override's parameter.
        let src = "import java.util.function.*;\nclass A implements Predicate<ThreadGroup> {\nThreadGroup g;\n@Override public boolean test(ThreadGroup t) { return true; }\nvoid f(ThreadGroup t) {}\n}";
        assert_eq!(flagged("java/thread-group", src), [3, 5]);
        // S3706: a collection's own stream, not a static stream(x).
        let src = "import java.util.*;\nclass A { void f(List<String> l) {\nl.stream().forEach(System.out::println);\nstream(l).forEach(System.out::println);\n} }";
        assert_eq!(flagged("java/stream-for-each", src), [3]);
        // S2143: once per file.
        let src = "import java.util.*;\nclass A {\nDate d;\nCalendar f() { return Calendar.getInstance(); }\n}";
        assert_eq!(flagged("java/legacy-date-time", src), [3]);
        // S7158: a String's length; a CharSequence's needs Java 15.
        let src = "class A { boolean f(String s, CharSequence cs) {\nreturn s.length() == 0 || cs.length() == 0;\n} }";
        assert_eq!(flagged("java/empty-string-comparison", src), [2]);
        // S1192: an exception's message doesn't count.
        let src = "class A { void f(int i) {\nif (i == 1) throw new IllegalStateException(\"shut down here\");\nif (i == 2) throw new IllegalStateException(\"shut down here\");\nif (i == 3) throw new IllegalStateException(\"shut down here\");\n} }";
        assert!(flagged("java/duplicated-string", src).is_empty());
    }

    /// Measured on SonarQube 26.7: a deprecation is reported unless its tag
    /// says what to use instead or when it goes.
    #[test]
    fn deprecations_that_say_what_to_do() {
        let case = |tag: &str| {
            let src = format!(
                "class A {{\n/**\n * Returns one.\n *\n * @deprecated {tag}\n */\n@Deprecated\nint old() {{ return 1; }}\n}}"
            );
            !flagged("java/deprecated-code", &src).is_empty()
        };
        // Reported.
        for tag in [
            "Use one.",
            "Prefer one instead.",
            "Instead, call one.",
            "Removed in 4.",
            "Will be removed.",
            "May be removed in a future release.",
            "Shall be removed in 4.",
            "Will be removed\n *     in 4.",
            "Old.\n * @see #one() Use one instead.",
        ] {
            assert!(case(tag), "{tag}");
        }
        // Not reported.
        for tag in [
            "Use {@link #one()} instead.",
            "Instead use one.",
            "Because of one, instead.",
            "USE ONE INSTEAD.",
            "Use one\n *     instead.",
            "Will be removed in 4.0.0.",
            "This feature will be removed in Lang 4, use one.",
            "Is to be removed in 4.",
        ] {
            assert!(!case(tag), "{tag}");
        }
        // The rest of the Javadoc doesn't count, and the tag alone deprecates.
        let src = "class A {\n/**\n * Use one instead.\n * @deprecated Old.\n */\n@Deprecated\nint old() { return 1; }\n/**\n * @deprecated Old.\n */\nint older() { return 1; }\n}";
        assert_eq!(flagged("java/deprecated-code", src), [7, 11]);
    }
}
