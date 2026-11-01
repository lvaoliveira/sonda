//! C# rules outside SonarQube's default profile, batch 8 (ADR-0007,
//! ADR-0015). Every rule here is opt-in: SonarQube's default ("Sonar way")
//! profile doesn't enable them, and they report style choices many codebases
//! make on purpose. Queries stay cheap on deep trees: see `js_modern.rs`.

use super::cs::{
    CS_SCOPE_STOPS, cs_has_modifier, cs_statements, cs_string_value, operand, simple_name,
    unparenthesized,
};
use super::cs_bugs::{attribute_names, cs_call_arguments};
use super::cs_extra::is_pascal_case;
use super::cs_more::{declarators, declared_type, enclosing_type, is_test_method, members};
use super::java_bugs::{find_in_scope, operator_text};
use super::java_security::text;
use super::java_smells::count_word;
use super::*;

/// Rules that are off unless `rules.enabled` lists them (see
/// `catalog::OFF_BY_DEFAULT`): all of this module's.
pub(super) static OFF_BY_DEFAULT: &[&str] = &[
    "cs/member-name-pascal-case",
    "cs/console-output",
    "cs/magic-number",
    "cs/missing-braces",
    "cs/statements-same-line",
    "cs/if-chain-without-else",
    "cs/switch-without-default",
    "cs/deep-nesting",
    "cs/increment-in-expression",
    "cs/complex-condition",
    "cs/closing-brace-position",
    "cs/environment-exit",
    "cs/long-switch-section",
    "cs/too-few-switch-cases",
    "cs/in-source-suppression",
    "cs/logger-not-static-readonly",
    "cs/culture-sensitive-case",
    "cs/multiple-declarations",
    "cs/nested-switch",
    "cs/large-number-without-separators",
    "cs/modulus-equality",
    "cs/catch-exception",
    "cs/use-nameof",
    "cs/public-constant",
    "cs/non-private-field",
    "cs/optional-parameter",
    "cs/repeated-condition-in-sequence",
    "cs/default-value-initializer",
    "cs/missing-configure-await",
    "cs/suppress-finalize-without-finalizer",
    "cs/redundant-parentheses-around-value",
    "cs/could-be-const",
    "cs/this-escapes-constructor",
    "cs/logger-for-other-type",
    "cs/empty-default-clause",
    "cs/not-implemented",
    "cs/parameter-named-like-method",
    "cs/out-ref-parameter",
    "cs/empty-finalizer",
    "cs/get-executing-assembly",
    "cs/static-readonly-could-be-const",
    "cs/multidimensional-array",
    "cs/reserved-enum-member",
    "cs/enum-storage-not-int",
    "cs/empty-interface",
];

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "cs/member-name-pascal-case",
        name: "Methods and properties should be named in PascalCase",
        description: "C# methods and properties are named in PascalCase, with acronyms of more than two letters \
                      written like words.",
        message: "Rename this member in PascalCase.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S100")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(method_declaration name: (identifier) @match) (property_declaration name: (identifier) @match)]",
            filter: Some(Keep(is_badly_cased_member)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void loadData() { G(); } }",
            good: "class A { void LoadData() { G(); } }",
        }),
    },
    Rule {
        id: "cs/console-output",
        name: "Console output should not be used for logging",
        description: "Console.Write and Console.WriteLine can't be filtered, formatted or routed like a logger's \
                      output.",
        message: "Use a logger instead of writing to the console.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S106")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(invocation_expression
                        function: (member_access_expression expression: (_) @t name: (identifier) @n)
                        (#match? @t "(^|\\.)Console(\\.(Out|Error))?$") (#any-of? @n "Write" "WriteLine")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F() { Console.WriteLine(\"saved\"); } }",
            good: "class A { void F(ILogger log) { log.LogInformation(\"saved\"); } }",
        }),
    },
    Rule {
        id: "cs/magic-number",
        name: "Magic numbers should not be used",
        description: "A bare number says nothing about what it means; a named constant does, and keeps every \
                      use of it in step.",
        message: "Replace this number with a named constant.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S109")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(integer_literal) (real_literal)] @match",
            filter: Some(Keep(is_magic_number)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { bool F(int n) { return n > 42; } }",
            good: "class A { const int Limit = 42; bool F(int n) { return n > Limit; } }",
        }),
    },
    Rule {
        id: "cs/missing-braces",
        name: "Control structures should use braces",
        description: "Without braces, a statement added under an if or loop silently isn't part of it.",
        message: "Add braces around this body.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 2,
        sonar: &[exact("S121")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(if_statement consequence: (_)) (for_statement body: (_)) (foreach_statement body: (_)) \
                     (while_statement body: (_)) (do_statement body: (_))] @match",
            filter: Some(Find(unbraced_body)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(bool b) { if (b) G(); } }",
            good: "class A { void F(bool b) { if (b) { G(); } } }",
        }),
    },
    Rule {
        id: "cs/statements-same-line",
        name: "Statements should be on separate lines",
        description: "Two statements on one line are easy to read as one, and diffs can't show which changed.",
        message: "Move this statement to its own line.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 1,
        sonar: &[exact("S122")],
        check: Check::Query {
            langs: CSHARP,
            query: "(block) @match",
            filter: Some(Find(second_statement_on_line)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F() {\n G(); H();\n} }",
            good: "class A { void F() {\n G();\n H();\n} }",
        }),
    },
    Rule {
        id: "cs/if-chain-without-else",
        name: "if ... else if chains should end with else",
        description: "A final `else` shows the remaining case was considered, even when it only says nothing \
                      happens.",
        message: "Add a final else clause.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S126")],
        check: Check::Query {
            langs: CSHARP,
            query: "(if_statement alternative: (if_statement)) @match",
            filter: Some(Find(chain_without_else)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(int x) { if (x > 0) { G(); } else if (x < 0) { H(); } } }",
            good: "class A { void F(int x) { if (x > 0) { G(); } else if (x < 0) { H(); } else { K(); } } }",
        }),
    },
    Rule {
        id: "cs/switch-without-default",
        name: "switch statements should have a default clause",
        description: "A `default` shows the other values were considered, and catches new ones added later.",
        message: "Add a default clause to this switch.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S131")],
        check: Check::Query {
            langs: CSHARP,
            query: "(switch_statement body: (switch_body)) @match",
            filter: Some(Keep(lacks_default)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(int x) { switch (x) { case 1: G(); break; } } }",
            good: "class A { void F(int x) { switch (x) { case 1: G(); break; default: break; } } }",
        }),
    },
    Rule {
        id: "cs/deep-nesting",
        name: "Control flow statements should not be nested too deeply",
        description: "Code nested more than three levels deep is hard to follow; early returns or extracted \
                      methods flatten it.",
        message: "Reduce the nesting here (more than 3 levels).",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S134")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(method_declaration body: (block)) (constructor_declaration body: (block)) \
                     (accessor_declaration body: (block)) (local_function_statement body: (block))] @match",
            filter: Some(Find(too_deep)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(bool a, bool b, bool c, bool d) { if (a) { if (b) { if (c) { if (d) { G(); } } } } } }",
            good: "class A { void F(bool a, bool b, bool c, bool d) { if (!a || !b) { return; } if (c && d) { G(); } } }",
        }),
    },
    Rule {
        id: "cs/increment-in-expression",
        name: "Increments should not be used inside other expressions",
        description: "`a[i++] = b[++j]` packs several changes in one line; separate statements say in which \
                      order they happen.",
        message: "Move this increment or decrement to its own statement.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S881")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(postfix_unary_expression) (prefix_unary_expression)] @match",
            filter: Some(Keep(nested_increment)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int F(int[] a, int i) { return a[i++]; } }",
            good: "class A { int F(int[] a, int i) { int v = a[i]; i++; return v; } }",
        }),
    },
    Rule {
        id: "cs/complex-condition",
        name: "Conditions should not combine too many operators",
        description: "More than three && and || in one expression are hard to read; named variables or a \
                      method make each part clear.",
        message: "Simplify this expression (more than 3 conditional operators).",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S1067")],
        check: Check::Query {
            langs: CSHARP,
            query: "(binary_expression) @match",
            filter: Some(Keep(too_many_conditions)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { bool F(bool a, bool b, bool c, bool d, bool e) { return a && b || c && d || e; } }",
            good: "class A { bool F(bool a, bool b, bool c) { return a && b || c; } }",
        }),
    },
    Rule {
        id: "cs/closing-brace-position",
        name: "A closing brace should start its line",
        description: "A `}` after code on the same line hides where the block ends.",
        message: "Move this closing brace to the beginning of its own line.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S1109")],
        check: Check::Query {
            langs: CSHARP,
            query: "(block) @match",
            filter: Some(Find(brace_after_code)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F() {\n G(); }\n}",
            good: "class A { void F() {\n G();\n }\n}",
        }),
    },
    Rule {
        id: "cs/environment-exit",
        name: "Environment.Exit should not be called",
        description: "Exiting the process from inside the code skips finally blocks and the host's shutdown, \
                      and makes the code impossible to reuse or test.",
        message: "Return or throw instead of exiting the process.",
        category: CodeSmell,
        severity: Blocker,
        effort_minutes: 10,
        sonar: &[exact("S1147")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(invocation_expression
                        function: (member_access_expression expression: (_) @t name: (identifier) @n)
                        (#match? @t "(^|\\.)(Environment|Application)$") (#eq? @n "Exit")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F() { Environment.Exit(1); } }",
            good: "class A { void F() { throw new InvalidOperationException(); } }",
        }),
    },
    Rule {
        id: "cs/long-switch-section",
        name: "switch sections should not have too many statements",
        description: "A case with more than eight statements belongs in a method of its own.",
        message: "Move this case's code into a method (more than 8 statements).",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S1151")],
        check: Check::Query {
            langs: CSHARP,
            query: "(switch_section) @match",
            filter: Some(Keep(long_section)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(int x) { switch (x) { case 1: G(); G(); G(); G(); G(); G(); G(); G(); G(); break; } } }",
            good: "class A { void F(int x) { switch (x) { case 1: Handle(); break; } } }",
        }),
    },
    Rule {
        id: "cs/too-few-switch-cases",
        name: "switch statements should have at least three cases",
        description: "A switch with one or two cases reads more simply as an if.",
        message: "Replace this switch with an if statement.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S1301")],
        check: Check::Query {
            langs: CSHARP,
            query: "(switch_statement body: (switch_body)) @match",
            filter: Some(Keep(too_few_cases)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(int x) { switch (x) { case 1: G(); break; default: H(); break; } } }",
            good: "class A { void F(int x) { if (x == 1) { G(); } else { H(); } } }",
        }),
    },
    Rule {
        id: "cs/in-source-suppression",
        name: "Suppressed warnings should be tracked",
        description: "`#pragma warning disable` and [SuppressMessage] silence a warning for good; listing them \
                      keeps them visible for review.",
        message: "Review this warning suppression.",
        category: CodeSmell,
        severity: Info,
        effort_minutes: 0,
        sonar: &[exact("S1309")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(preproc_pragma) (attribute name: (_))] @match",
            filter: Some(Keep(suppresses_warnings)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A {\n#pragma warning disable CS0168\n void F() { } }",
            good: "class A { void F() { } }",
        }),
    },
    Rule {
        id: "cs/logger-not-static-readonly",
        name: "Logger fields should be private static readonly",
        description: "One logger per type, never reassigned or shared outside it, is the convention most logging \
                      libraries expect.",
        message: "Make this logger field private static readonly.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[related("S1312")],
        check: Check::Query {
            langs: CSHARP,
            query: "(field_declaration (variable_declaration type: [(identifier) (generic_name) (qualified_name)])) @match",
            filter: Some(Find(loose_logger_field)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { public ILog Log = LogManager.GetLogger(typeof(A)); }",
            good: "class A { private static readonly ILog Log = LogManager.GetLogger(typeof(A)); }",
        }),
    },
    Rule {
        id: "cs/culture-sensitive-case",
        name: "Case conversion should state its culture",
        description: "ToLower() and ToUpper() use the current culture, so \"I\".ToLower() isn't \"i\" in Turkish. \
                      Say which culture is meant.",
        message: "Use ToLowerInvariant/ToUpperInvariant, or pass a CultureInfo.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[related("S1449")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(invocation_expression
                        function: (member_access_expression name: (identifier) @n)
                        arguments: (argument_list) @a
                        (#any-of? @n "ToLower" "ToUpper")) @match"#,
            filter: Some(Keep(no_arguments)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { string F(string s) { return s.ToLower(); } }",
            good: "class A { string F(string s) { return s.ToLowerInvariant(); } }",
        }),
    },
    Rule {
        id: "cs/multiple-declarations",
        name: "Each declaration should declare one variable",
        description: "`int a, b = 0;` reads as if both were 0; one declaration per line says what each is.",
        message: "Declare each variable on its own.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S1659")],
        check: Check::Query {
            langs: CSHARP,
            query: "(variable_declaration (variable_declarator) (variable_declarator) @match)",
            filter: None,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int a, b; }",
            good: "class A { int a; int b; }",
        }),
    },
    Rule {
        id: "cs/nested-switch",
        name: "switch statements should not be nested",
        description: "A switch inside another is hard to follow; the inner one belongs in a method.",
        message: "Move this nested switch into a method.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S1821")],
        check: Check::Query {
            langs: CSHARP,
            query: "(switch_statement body: (switch_body)) @match",
            filter: Some(Find(inner_switch)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(int x, int y) { switch (x) { case 1: switch (y) { case 2: G(); break; } break; } } }",
            good: "class A { void F(int x, int y) { switch (x) { case 1: Handle(y); break; } } }",
        }),
    },
    Rule {
        id: "cs/large-number-without-separators",
        name: "Large numbers should use digit separators",
        description: "`1_000_000` is easier to read, and to get right, than `1000000`.",
        message: "Group the digits of this number with '_'.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S2148")],
        check: Check::Query {
            langs: CSHARP,
            query: "(integer_literal) @match",
            filter: Some(Keep(long_number_without_separator)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { const int Max = 1000000; }",
            good: "class A { const int Max = 1_000_000; }",
        }),
    },
    Rule {
        id: "cs/modulus-equality",
        name: "Remainders should not be compared with 1 or -1",
        description: "`x % 2 == 1` is false for negative odd numbers, whose remainder is -1; `x % 2 != 0` \
                      holds for both.",
        message: "Compare the remainder with 0 instead.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 2,
        sonar: &[exact("S2197")],
        check: Check::Query {
            langs: CSHARP,
            query: "(binary_expression) @match",
            filter: Some(Keep(remainder_compared_with_one)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { bool Odd(int x) { return x % 2 == 1; } }",
            good: "class A { bool Odd(int x) { return x % 2 != 0; } }",
        }),
    },
    Rule {
        id: "cs/catch-exception",
        name: "Exception should not be caught",
        description: "Catching every exception also catches bugs and conditions the code can't recover from. \
                      Catch the exceptions the code expects.",
        message: "Catch a more specific exception.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 15,
        sonar: &[exact("S2221")],
        check: Check::Query {
            langs: CSHARP,
            query: "(catch_declaration type: (_) @match)",
            filter: Some(Keep(is_exception_type)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F() { try { G(); } catch (Exception e) { Log(e); } } }",
            good: "class A { void F() { try { G(); } catch (IOException e) { Log(e); } } }",
        }),
    },
    Rule {
        id: "cs/use-nameof",
        name: "nameof should be used for parameter names",
        description: "A parameter name written as a string goes out of date silently when the parameter is \
                      renamed; nameof(x) is checked by the compiler.",
        message: "Use nameof(...) instead of this string.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 2,
        sonar: &[exact("S2302")],
        check: Check::Query {
            langs: CSHARP,
            query: "(object_creation_expression arguments: (argument_list (argument (string_literal) @match)))",
            filter: Some(Keep(names_a_parameter)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(string name) { if (name == null) { throw new ArgumentNullException(\"name\"); } } }",
            good: "class A { void F(string name) { if (name == null) { throw new ArgumentNullException(nameof(name)); } } }",
        }),
    },
    Rule {
        id: "cs/public-constant",
        name: "Public constants should be static readonly fields",
        description: "A const is copied into every assembly that uses it, so changing its value means \
                      recompiling them all; a static readonly field is read at run time.",
        message: "Make this public constant a static readonly field, or a non-public const.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 2,
        sonar: &[exact("S2339")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(field_declaration (modifier) @m (#eq? @m "const")) @match"#,
            filter: Some(Find(public_const_name)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "public class A { public const int Version = 2; }",
            good: "public class A { public static readonly int Version = 2; }",
        }),
    },
    Rule {
        id: "cs/non-private-field",
        name: "Fields should be private",
        description: "A protected or internal field lets other code change it without the type knowing; a \
                      property keeps that under control.",
        message: "Make this field private and expose it through a property.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2357")],
        check: Check::Query {
            langs: CSHARP,
            query: "(field_declaration (modifier)) @match",
            filter: Some(Find(non_private_field_name)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { protected int count; }",
            good: "class A { private int count; protected int Count => count; }",
        }),
    },
    Rule {
        id: "cs/optional-parameter",
        name: "Optional parameters should not be used in public APIs",
        description: "A default value is compiled into every caller, so changing it later doesn't reach them \
                      until they're recompiled. Overloads don't have that problem.",
        message: "Replace this optional parameter with an overload.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S2360")],
        check: Check::Query {
            langs: CSHARP,
            query: "(method_declaration (modifier) parameters: (parameter_list (parameter) @match))",
            filter: Some(Keep(public_optional_parameter)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "public class A { public void Save(string path, bool force = false) { } }",
            good: "public class A { public void Save(string path) => Save(path, false); public void Save(string path, bool force) { } }",
        }),
    },
    Rule {
        id: "cs/repeated-condition-in-sequence",
        name: "Consecutive if statements should not test the same condition",
        description: "Two ifs in a row with the same condition are one if with both bodies, or one of them \
                      tests the wrong thing.",
        message: "Merge this if with the one above it, or fix its condition.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S2760")],
        check: Check::Query {
            langs: CSHARP,
            query: "(block (if_statement) (if_statement)) @match",
            filter: Some(Find(same_condition_twice)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(bool a) { if (a) { G(); } if (a) { H(); } } }",
            good: "class A { void F(bool a) { if (a) { G(); H(); } } }",
        }),
    },
    Rule {
        id: "cs/default-value-initializer",
        name: "Fields should not be initialized to their default value",
        description: "Fields already start at 0, false or null; writing it again is noise.",
        message: "Remove this initializer, which sets the default value.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S3052")],
        check: Check::Query {
            langs: CSHARP,
            query: "(field_declaration (variable_declaration (variable_declarator))) @match",
            filter: Some(Find(default_initializer)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int count = 0; bool done = false; }",
            good: "class A { int count; bool done; }",
        }),
    },
    Rule {
        id: "cs/missing-configure-await",
        name: "Library code should use ConfigureAwait(false)",
        description: "Without it, the continuation tries to resume on the caller's synchronization context, \
                      which costs time and can deadlock a caller that blocks.",
        message: "Add .ConfigureAwait(false) to this await.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 1,
        sonar: &[exact("S3216")],
        check: Check::Query {
            langs: CSHARP,
            query: "(await_expression) @match",
            filter: Some(Keep(awaits_without_configure)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { async Task F() { await G(); } }",
            good: "class A { async Task F() { await G().ConfigureAwait(false); } }",
        }),
    },
    Rule {
        id: "cs/suppress-finalize-without-finalizer",
        name: "GC.SuppressFinalize should only be called for types with finalizers",
        description: "In a sealed type without a finalizer there is nothing to suppress, so the call only \
                      adds noise.",
        message: "Remove this call, or add the finalizer it implies.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S3234")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration (modifier) body: (declaration_list)) @match",
            filter: Some(Find(pointless_suppress_finalize)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "sealed class A : IDisposable { public void Dispose() { GC.SuppressFinalize(this); } }",
            good: "sealed class A : IDisposable { public void Dispose() { Close(); } }",
        }),
    },
    Rule {
        id: "cs/redundant-parentheses-around-value",
        name: "Returned and assigned values should not be in parentheses",
        description: "`return (x);` and `y = (x);` don't need the parentheses.",
        message: "Remove these parentheses.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S3235")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(return_statement (parenthesized_expression) @match) \
                     (assignment_expression right: (parenthesized_expression) @match) \
                     (arrow_expression_clause (parenthesized_expression) @match)]",
            filter: Some(Keep(parentheses_add_nothing)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int F(int a) { return (a + 1); } }",
            good: "class A { int F(int a) { return a + 1; } }",
        }),
    },
    Rule {
        id: "cs/could-be-const",
        name: "Locals that never change should be const",
        description: "`const` says the value is fixed, and the compiler makes sure of it.",
        message: "Make this local a const.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 1,
        sonar: &[exact("S3353")],
        check: Check::Query {
            langs: CSHARP,
            query: "(local_declaration_statement (variable_declaration type: (predefined_type) (variable_declarator))) @match",
            filter: Some(Find(constant_local)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int F(int x) { int factor = 3; return x * factor; } }",
            good: "class A { int F(int x) { const int factor = 3; return x * factor; } }",
        }),
    },
    Rule {
        id: "cs/this-escapes-constructor",
        name: "Constructors should not pass this to other code",
        description: "Code that receives `this` before the constructor ends sees a half-initialized object, \
                      and a subclass's fields not set at all.",
        message: "Pass this out after construction, from a factory or an Initialize method.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S3366")],
        check: Check::Query {
            langs: CSHARP,
            query: "(constructor_declaration body: (block)) @match",
            filter: Some(Find(this_passed_out)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { public A(Registry r) { r.Add(this); } }",
            good: "class A { public static A Create(Registry r) { var a = new A(); r.Add(a); return a; } }",
        }),
    },
    Rule {
        id: "cs/logger-for-other-type",
        name: "Loggers should be named for their enclosing type",
        description: "A logger created for another type files this type's messages under the wrong name.",
        message: "Create this logger for the enclosing type.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S3416")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(invocation_expression
                        function: (member_access_expression name: (identifier) @n)
                        (#any-of? @n "GetLogger" "CreateLogger" "GetCurrentClassLogger")) @match"#,
            filter: Some(Find(logger_for_other_type)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class Orders { static readonly ILog Log = LogManager.GetLogger(typeof(Carts)); }",
            good: "class Orders { static readonly ILog Log = LogManager.GetLogger(typeof(Orders)); }",
        }),
    },
    Rule {
        id: "cs/empty-default-clause",
        name: "Empty default clauses should be removed",
        description: "A `default: break;` does what leaving it out does.",
        message: "Remove this empty default clause, or say why it's there.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S3532")],
        check: Check::Query {
            langs: CSHARP,
            query: "(switch_section) @match",
            filter: Some(Keep(empty_default)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(int x) { switch (x) { case 1: G(); break; default: break; } } }",
            good: "class A { void F(int x) { switch (x) { case 1: G(); break; } } }",
        }),
    },
    Rule {
        id: "cs/not-implemented",
        name: "NotImplementedException should be tracked",
        description: "A NotImplementedException marks unfinished code that will fail when called.",
        message: "Implement this, or throw NotSupportedException if it's not meant to be.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 0,
        sonar: &[exact("S3717")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(object_creation_expression type: (_) @t (#match? @t "NotImplementedException$")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F() { throw new NotImplementedException(); } }",
            good: "class A { void F() { throw new NotSupportedException(); } }",
        }),
    },
    Rule {
        id: "cs/parameter-named-like-method",
        name: "Parameters should not be named like their method",
        description: "`Format(string format)` makes the body harder to read, since the name means two things.",
        message: "Rename this parameter.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S3872")],
        check: Check::Query {
            langs: CSHARP,
            query: "(method_declaration name: (identifier) parameters: (parameter_list)) @match",
            filter: Some(Find(parameter_like_method)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void Login(string login) { G(login); } }",
            good: "class A { void Login(string userName) { G(userName); } }",
        }),
    },
    Rule {
        id: "cs/out-ref-parameter",
        name: "out and ref parameters should not be used in public methods",
        description: "They make methods harder to call and to compose; returning a tuple or a type is clearer.",
        message: "Return the value instead of using an out or ref parameter.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 15,
        sonar: &[exact("S3874")],
        check: Check::Query {
            langs: CSHARP,
            query: "(method_declaration (modifier) name: (identifier) parameters: (parameter_list)) @match",
            filter: Some(Find(public_out_parameter)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "public class A { public void Split(string s, out string a, out string b) { a = s; b = s; } }",
            good: "public class A { public (string, string) Split(string s) => (s, s); }",
        }),
    },
    Rule {
        id: "cs/empty-finalizer",
        name: "Finalizers should not be empty",
        description: "An empty finalizer puts every instance on the finalization queue for nothing, which \
                      slows garbage collection.",
        message: "Remove this empty finalizer.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S3880")],
        check: Check::Query {
            langs: CSHARP,
            query: "(destructor_declaration body: (block)) @match",
            filter: Some(Keep(empty_body)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { ~A() { } }",
            good: "class A { ~A() { Release(); } }",
        }),
    },
    Rule {
        id: "cs/get-executing-assembly",
        name: "Assembly.GetExecutingAssembly should not be called",
        description: "It's slower than typeof(T).Assembly and returns another assembly when the code is inlined \
                      into a caller.",
        message: "Use typeof(ThisType).Assembly instead.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S3902")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(invocation_expression
                        function: (member_access_expression expression: (_) @t name: (identifier) @n)
                        (#match? @t "(^|\\.)Assembly$") (#eq? @n "GetExecutingAssembly")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { Assembly F() { return Assembly.GetExecutingAssembly(); } }",
            good: "class A { Assembly F() { return typeof(A).Assembly; } }",
        }),
    },
    Rule {
        id: "cs/static-readonly-could-be-const",
        name: "static readonly fields with constant values should be const",
        description: "A private static readonly field set to a literal is a constant; `const` lets the compiler \
                      use it as one.",
        message: "Make this field const.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S3962")],
        check: Check::Query {
            langs: CSHARP,
            query: "(field_declaration (modifier) (variable_declaration type: (predefined_type))) @match",
            filter: Some(Find(constant_static_readonly)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { private static readonly int Max = 10; }",
            good: "class A { private const int Max = 10; }",
        }),
    },
    Rule {
        id: "cs/multidimensional-array",
        name: "Multidimensional arrays should not be used",
        description: "Jagged arrays (`int[][]`) are faster in .NET and easier to work with than `int[,]`.",
        message: "Use a jagged array instead.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 15,
        sonar: &[exact("S3967")],
        check: Check::Query {
            langs: CSHARP,
            query: "(array_type rank: (array_rank_specifier) @match)",
            filter: Some(Keep(has_several_dimensions)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int[,] grid = new int[3, 3]; }",
            good: "class A { int[][] grid = new int[3][]; }",
        }),
    },
    Rule {
        id: "cs/reserved-enum-member",
        name: "Enum members should not be named Reserved",
        description: "A placeholder member is never removed safely: adding the real one later is a breaking \
                      change anyway.",
        message: "Remove this placeholder member.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S4016")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(enum_member_declaration name: (identifier) @match (#match? @match "^Reserved"))"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "enum Mode { On, Off, Reserved }",
            good: "enum Mode { On, Off }",
        }),
    },
    Rule {
        id: "cs/enum-storage-not-int",
        name: "Enums should use Int32 storage",
        description: "A smaller storage type saves little and gets in the way of interop and of adding members \
                      later.",
        message: "Remove the storage type, unless interop requires it.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S4022")],
        check: Check::Query {
            langs: CSHARP,
            query: "(enum_declaration (base_list . (_) @match))",
            filter: Some(Keep(not_int_storage)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "enum Color : byte { Red, Green }",
            good: "enum Color { Red, Green }",
        }),
    },
    Rule {
        id: "cs/empty-interface",
        name: "Interfaces should not be empty",
        description: "An empty interface only marks types; an attribute does that without an empty contract.",
        message: "Add members to this interface, or use an attribute instead.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 10,
        sonar: &[exact("S4023")],
        check: Check::Query {
            langs: CSHARP,
            query: "(interface_declaration name: (identifier) body: (declaration_list)) @match",
            filter: Some(Find(empty_interface_name)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "interface IMarker { }",
            good: "interface IShape { double Area(); }",
        }),
    },
];

// ---------------------------------------------------- filters

fn is_badly_cased_member(name: Node, src: &[u8]) -> bool {
    let n = text(name, src);
    let Some(member) = name.parent() else {
        return false;
    };
    // Test names with underscores (Given_When_Then), operators and explicit
    // interface implementations of an external contract are left alone.
    if member.kind() == "method_declaration" && is_test_method(member, src) {
        return false;
    }
    let mut cursor = member.walk();
    if member
        .named_children(&mut cursor)
        .any(|c| c.kind() == "explicit_interface_specifier")
        || cs_has_modifier(member, "override", src)
        || cs_has_modifier(member, "extern", src)
    {
        return false;
    }
    !is_pascal_case(n)
}

fn is_magic_number(literal: Node, src: &[u8]) -> bool {
    let t = text(literal, src);
    let digits: Vec<u8> = t.iter().copied().filter(|b| b.is_ascii_digit()).collect();
    // 0, 1, 2 and the like are rarely magic; nor are hex masks of 0 and 1.
    if digits.iter().all(|d| *d == b'0')
        || matches!(digits.as_slice(), b"1" | b"2" | b"10" | b"100" | b"1000")
    {
        return false;
    }
    let mut current = literal.parent();
    for _ in 0..8 {
        let Some(n) = current else {
            return true;
        };
        match n.kind() {
            // Named already, or not a number about the domain.
            "field_declaration"
                if cs_has_modifier(n, "const", src) || cs_has_modifier(n, "readonly", src) =>
            {
                return false;
            }
            "local_declaration_statement" if text(n, src).starts_with(b"const ") => return false,
            // `int retries = 3;`: the variable names it.
            "variable_declarator"
            | "enum_member_declaration"
            | "attribute"
            | "attribute_argument"
            | "element_access_expression" => return false,
            "prefix_unary_expression"
            | "parenthesized_expression"
            | "argument"
            | "binary_expression"
            | "cast_expression" => {
                current = n.parent();
            }
            // GetHashCode multipliers and the like.
            "method_declaration" => {
                return !n
                    .child_by_field_name("name")
                    .is_some_and(|m| text(m, src) == b"GetHashCode");
            }
            _ => return true,
        }
    }
    true
}

fn unbraced_body<'t>(control: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    let field = if control.kind() == "if_statement" {
        "consequence"
    } else {
        "body"
    };
    let body = control.child_by_field_name(field)?;
    let unbraced = |b: Node| {
        !matches!(b.kind(), "block" | "if_statement" | "empty_statement")
            && !b.kind().starts_with("preproc")
    };
    if unbraced(body) {
        return Some(body);
    }
    // `else G();`; `else if` is fine.
    control
        .child_by_field_name("alternative")
        .filter(|a| control.kind() == "if_statement" && unbraced(*a))
}

fn second_statement_on_line<'t>(block: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    let stmts = cs_statements(block);
    // A block on one line (`{ G(); return; }`) is a deliberate one-liner.
    if block.start_position().row == block.end_position().row {
        return None;
    }
    stmts
        .windows(2)
        .find(|w| w[0].end_position().row == w[1].start_position().row)
        .map(|w| w[1])
}

fn chain_without_else<'t>(statement: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    let mut current = statement;
    while let Some(next) = current
        .child_by_field_name("alternative")
        .filter(|a| a.kind() == "if_statement")
    {
        current = next;
    }
    // Only the head of a chain reports; parent() costs depth, so after the walk.
    if current.child_by_field_name("alternative").is_some()
        || statement.parent().is_some_and(|p| {
            p.kind() == "if_statement" && p.child_by_field_name("alternative") == Some(statement)
        })
    {
        return None;
    }
    Some(current)
}

fn lacks_default(switch: Node, src: &[u8]) -> bool {
    switch.child_by_field_name("body").is_some_and(|b| {
        let mut cursor = b.walk();
        !b.named_children(&mut cursor)
            .any(|s| s.kind() == "switch_section" && text(s, src).starts_with(b"default"))
    })
}

const NESTING: &[&str] = &[
    "if_statement",
    "for_statement",
    "foreach_statement",
    "while_statement",
    "do_statement",
    "switch_statement",
    "try_statement",
];

fn too_deep<'t>(member: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    let body = member.child_by_field_name("body")?;
    // Iterative depth-first walk with the nesting level; an else-if doesn't
    // add a level.
    let mut stack = vec![(body, 0usize)];
    while let Some((n, depth)) = stack.pop() {
        let nested_if = n.kind() == "if_statement"
            && n.parent().is_some_and(|p| {
                p.kind() == "if_statement" && p.child_by_field_name("alternative") == Some(n)
            });
        let level = if NESTING.contains(&n.kind()) && !nested_if {
            depth + 1
        } else {
            depth
        };
        if level > 3 {
            return Some(n);
        }
        if CS_SCOPE_STOPS.contains(&n.kind()) && n != body {
            continue;
        }
        let mut c = n.walk();
        for child in n.named_children(&mut c) {
            stack.push((child, level));
        }
    }
    None
}

fn nested_increment(node: Node, src: &[u8]) -> bool {
    let t = text(node, src);
    if !(t.starts_with(b"++") || t.starts_with(b"--") || t.ends_with(b"++") || t.ends_with(b"--")) {
        return false;
    }
    // Alone in a statement or a for update it's fine.
    // `void Hit() => count++;` is a statement in expression form.
    !node.parent().is_some_and(|p| {
        matches!(
            p.kind(),
            "expression_statement" | "for_statement" | "arrow_expression_clause"
        )
    })
}

fn too_many_conditions(node: Node, src: &[u8]) -> bool {
    if !matches!(operator_text(node, src), b"&&" | b"||") {
        return false;
    }
    // Count from the top of a chain only.
    if node.parent().is_some_and(|p| {
        let p = if p.kind() == "parenthesized_expression" {
            p.parent().unwrap_or(p)
        } else {
            p
        };
        p.kind() == "binary_expression" && matches!(operator_text(p, src), b"&&" | b"||")
    }) {
        return false;
    }
    let mut count = 0;
    let mut stack = vec![node];
    while let Some(n) = stack.pop() {
        let n = unparenthesized(n);
        if n.kind() == "binary_expression" && matches!(operator_text(n, src), b"&&" | b"||") {
            count += 1;
            stack.extend(n.child_by_field_name("left"));
            stack.extend(n.child_by_field_name("right"));
        }
    }
    count > 3
}

fn brace_after_code<'t>(block: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if block.start_position().row == block.end_position().row {
        return None;
    }
    let close = block.child(block.child_count().checked_sub(1)?)?;
    (close.kind() == "}"
        && super::cs_final::line_indent(close, src) != close.start_position().column)
        .then_some(close)
}

fn long_section(section: Node, _: &[u8]) -> bool {
    let mut cursor = section.walk();
    section
        .named_children(&mut cursor)
        .filter(|c| c.kind().ends_with("_statement") || c.kind() == "block")
        .filter(|c| c.kind() != "break_statement")
        .count()
        > 8
}

fn too_few_cases(switch: Node, _: &[u8]) -> bool {
    switch.child_by_field_name("body").is_some_and(|b| {
        let mut cursor = b.walk();
        let sections = b
            .named_children(&mut cursor)
            .filter(|s| s.kind() == "switch_section")
            .count();
        sections < 3
    })
}

fn suppresses_warnings(node: Node, src: &[u8]) -> bool {
    if node.kind() == "preproc_pragma" {
        let t = text(node, src);
        return count_word(t, b"warning") > 0 && count_word(t, b"disable") > 0;
    }
    node.child_by_field_name("name").is_some_and(|n| {
        matches!(
            simple_name(n, src),
            b"SuppressMessage" | b"SuppressMessageAttribute"
        )
    })
}

fn is_logger_type(ty: Node, src: &[u8]) -> bool {
    matches!(simple_name(ty, src), b"ILog" | b"ILogger" | b"Logger")
}

fn loose_logger_field<'t>(field: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let ty = declared_type(field)?;
    if !is_logger_type(ty, src) {
        return None;
    }
    // Injected ILogger<T> instances are instance fields by design; this is
    // about loggers created by the type itself.
    let created_here = declarators(field).iter().any(|d| d.named_child_count() > 1);
    let tidy = cs_has_modifier(field, "static", src)
        && cs_has_modifier(field, "readonly", src)
        && !["public", "protected", "internal"]
            .iter()
            .any(|m| cs_has_modifier(field, m, src));
    (created_here && !tidy).then(|| declarators(field).into_iter().next())?
}

fn no_arguments(call: Node, _: &[u8]) -> bool {
    call.child_by_field_name("arguments")
        .is_some_and(|a| a.named_child_count() == 0)
}

fn inner_switch<'t>(switch: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    let body = switch.child_by_field_name("body")?;
    find_in_scope(body, CS_SCOPE_STOPS, |n| n.kind() == "switch_statement")
}

fn long_number_without_separator(literal: Node, src: &[u8]) -> bool {
    let t = text(literal, src);
    if t.contains(&b'_') || t.starts_with(b"0x") || t.starts_with(b"0X") || t.starts_with(b"0b") {
        return false;
    }
    t.iter().take_while(|b| b.is_ascii_digit()).count() >= 6
}

fn remainder_compared_with_one(node: Node, src: &[u8]) -> bool {
    if !matches!(operator_text(node, src), b"==" | b"!=") {
        return false;
    }
    let is_remainder = |n: Option<Node>| {
        n.map(unparenthesized)
            .is_some_and(|n| n.kind() == "binary_expression" && operator_text(n, src) == b"%")
    };
    let is_one = |n: Option<Node>| n.is_some_and(|n| matches!(text(n, src), b"1" | b"-1"));
    let (l, r) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    );
    (is_remainder(l) && is_one(r)) || (is_one(l) && is_remainder(r))
}

fn is_exception_type(ty: Node, src: &[u8]) -> bool {
    matches!(text(ty, src), b"Exception" | b"System.Exception")
}

fn names_a_parameter(literal: Node, src: &[u8]) -> bool {
    let Some(value) = cs_string_value(literal, src) else {
        return false;
    };
    if value.is_empty()
        || !value
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'_')
    {
        return false;
    }
    let mut current = literal.parent();
    for _ in 0..64 {
        let Some(n) = current else {
            return false;
        };
        if matches!(
            n.kind(),
            "method_declaration" | "constructor_declaration" | "local_function_statement"
        ) {
            let Some(params) = n.child_by_field_name("parameters") else {
                return false;
            };
            let mut c = params.walk();
            return params
                .named_children(&mut c)
                .filter_map(|p| p.child_by_field_name("name"))
                .any(|p| text(p, src) == value);
        }
        current = n.parent();
    }
    false
}

fn public_const_name<'t>(field: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    cs_has_modifier(field, "public", src).then(|| {
        declarators(field)
            .into_iter()
            .next()?
            .child_by_field_name("name")
    })?
}

fn non_private_field_name<'t>(field: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    // Public fields are cs/public-field's; constants and readonly fields are
    // safe to expose.
    let visible = ["protected", "internal"]
        .iter()
        .any(|m| cs_has_modifier(field, m, src))
        && !cs_has_modifier(field, "public", src);
    let fixed = ["const", "readonly"]
        .iter()
        .any(|m| cs_has_modifier(field, m, src));
    (visible && !fixed).then(|| {
        declarators(field)
            .into_iter()
            .next()?
            .child_by_field_name("name")
    })?
}

fn public_optional_parameter(parameter: Node, src: &[u8]) -> bool {
    let method = parameter.parent().and_then(|l| l.parent());
    text(parameter, src).contains(&b'=')
        && method.is_some_and(|m| {
            cs_has_modifier(m, "public", src) && !cs_has_modifier(m, "override", src)
        })
}

fn same_condition_twice<'t>(block: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let stmts = cs_statements(block);
    stmts.windows(2).find_map(|w| {
        let (Some(a), Some(b)) = (
            w[0].child_by_field_name("condition")
                .filter(|_| w[0].kind() == "if_statement"),
            w[1].child_by_field_name("condition")
                .filter(|_| w[1].kind() == "if_statement"),
        ) else {
            return None;
        };
        // The first if mustn't change what the condition reads.
        let first_body = w[0].child_by_field_name("consequence")?;
        let reads = super::cs::squeezed(a, src);
        let changed = find_in_scope(first_body, CS_SCOPE_STOPS, |n| {
            n.kind() == "assignment_expression"
                && n.child_by_field_name("left")
                    .is_some_and(|l| count_word(&reads, text(l, src)) > 0)
        })
        .is_some();
        (!changed
            && super::cs::same_code(a, b, src)
            && w[0].child_by_field_name("alternative").is_none())
        .then_some(b)
    })
}

fn default_initializer<'t>(field: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if cs_has_modifier(field, "const", src) {
        return None;
    }
    declarators(field).into_iter().find_map(|d| {
        let value = d
            .named_children(&mut d.walk())
            .last()
            .filter(|v| Some(*v) != d.child_by_field_name("name"))?;
        let t = text(value, src);
        let default = matches!(value.kind(), "null_literal")
            || t == b"false"
            || t == b"default"
            || (matches!(value.kind(), "integer_literal" | "real_literal")
                && t.iter().filter(|b| b.is_ascii_digit()).all(|b| *b == b'0'));
        default.then_some(value)
    })
}

fn awaits_without_configure(node: Node, src: &[u8]) -> bool {
    let Some(awaited) = operand(node) else {
        return false;
    };
    let t = text(awaited, src);
    // Task.Yield and await foreach/using are other things.
    !t.windows(15).any(|w| w == b"ConfigureAwait(") && !t.starts_with(b"Task.Yield")
}

fn pointless_suppress_finalize<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !cs_has_modifier(class, "sealed", src) {
        return None;
    }
    let ms = members(class);
    if ms.iter().any(|m| m.kind() == "destructor_declaration") {
        return None;
    }
    let body = class.child_by_field_name("body")?;
    find_in_scope(body, CS_SCOPE_STOPS, |n| {
        n.kind() == "invocation_expression"
            && n.child_by_field_name("function").is_some_and(|f| {
                matches!(
                    text(f, src),
                    b"GC.SuppressFinalize" | b"System.GC.SuppressFinalize"
                )
            })
            && cs_call_arguments(n)
                .first()
                .is_some_and(|a| text(*a, src) == b"this")
    })
}

fn parentheses_add_nothing(parens: Node, _: &[u8]) -> bool {
    // `(a as B)?.C` and casts need them; a plain returned value doesn't.
    operand(parens).is_some_and(|inner| {
        !matches!(
            inner.kind(),
            "conditional_expression"
                | "lambda_expression"
                | "as_expression"
                | "assignment_expression"
        )
    })
}

fn constant_local<'t>(statement: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if text(statement, src).starts_with(b"const ") || text(statement, src).starts_with(b"using ") {
        return None;
    }
    let declaration = operand(statement).filter(|d| d.kind() == "variable_declaration")?;
    let ty = text(declaration.child_by_field_name("type")?, src);
    if matches!(ty, b"object" | b"dynamic") {
        return None;
    }
    let mut cursor = declaration.walk();
    let declarators: Vec<Node<'t>> = declaration
        .named_children(&mut cursor)
        .filter(|d| d.kind() == "variable_declarator")
        .collect();
    let [declarator] = declarators.as_slice() else {
        return None;
    };
    let name = declarator.child_by_field_name("name")?;
    let mut c = declarator.walk();
    let value = declarator
        .named_children(&mut c)
        .filter(|v| *v != name)
        .last()?;
    if !matches!(
        value.kind(),
        "integer_literal"
            | "real_literal"
            | "string_literal"
            | "boolean_literal"
            | "character_literal"
    ) {
        return None;
    }
    // Never written again in the enclosing block.
    let scope = statement.parent()?;
    let n = text(name, src);
    let written = find_in_scope(scope, &[], |x| match x.kind() {
        "assignment_expression" => x
            .child_by_field_name("left")
            .is_some_and(|l| text(l, src) == n),
        "postfix_unary_expression" | "prefix_unary_expression" => {
            operand(x).is_some_and(|o| text(o, src) == n)
        }
        "argument" => {
            let t = text(x, src);
            (t.starts_with(b"ref ") || t.starts_with(b"out ") || t.starts_with(b"in "))
                && count_word(t, n) > 0
        }
        _ => false,
    })
    .is_some();
    (!written).then_some(name)
}

fn this_passed_out<'t>(constructor: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let body = constructor.child_by_field_name("body")?;
    find_in_scope(body, CS_SCOPE_STOPS, |n| {
        n.kind() == "argument"
            && text(n, src) == b"this"
            // Constructor chaining and event registration in the object itself
            // are different; an argument to another object's method isn't.
            && n.parent()
                .and_then(|l| l.parent())
                .is_some_and(|c| c.kind() == "invocation_expression" || c.kind() == "object_creation_expression")
    })
}

fn logger_for_other_type<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let class = enclosing_type(call)?;
    let own = text(class.child_by_field_name("name")?, src);
    let arg = *cs_call_arguments(call).first()?;
    let named = match arg.kind() {
        "typeof_expression" => simple_name(arg.child_by_field_name("type")?, src),
        _ => return None,
    };
    (named != own).then_some(arg)
}

fn empty_default(section: Node, src: &[u8]) -> bool {
    let t = text(section, src);
    if !t.starts_with(b"default") {
        return false;
    }
    let mut cursor = section.walk();
    let statements: Vec<Node> = section
        .named_children(&mut cursor)
        .filter(|c| {
            c.kind().ends_with("_statement") || c.kind() == "block" || c.kind() == "comment"
        })
        .collect();
    matches!(statements.as_slice(), [only] if only.kind() == "break_statement")
}

fn parameter_like_method<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let name = text(method.child_by_field_name("name")?, src).to_ascii_lowercase();
    let params = method.child_by_field_name("parameters")?;
    let mut cursor = params.walk();
    let list: Vec<Node<'t>> = params.named_children(&mut cursor).collect();
    list.into_iter()
        .filter_map(|p| p.child_by_field_name("name"))
        .find(|n| text(*n, src).to_ascii_lowercase() == name)
}

fn public_out_parameter<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !cs_has_modifier(method, "public", src) || cs_has_modifier(method, "override", src) {
        return None;
    }
    // TryParse-style methods are the accepted use of out.
    if method
        .child_by_field_name("name")
        .is_some_and(|n| text(n, src).starts_with(b"Try"))
    {
        return None;
    }
    let params = method.child_by_field_name("parameters")?;
    let mut cursor = params.walk();
    let list: Vec<Node<'t>> = params.named_children(&mut cursor).collect();
    list.into_iter().find(|p| {
        let mut c = p.walk();
        p.named_children(&mut c)
            .any(|m| m.kind() == "modifier" && matches!(text(m, src), b"out" | b"ref"))
    })
}

fn empty_body(node: Node, _: &[u8]) -> bool {
    node.child_by_field_name("body")
        .is_some_and(|b| b.named_child_count() == 0)
}

fn constant_static_readonly<'t>(field: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !cs_has_modifier(field, "static", src)
        || !cs_has_modifier(field, "readonly", src)
        || ["public", "protected", "internal"]
            .iter()
            .any(|m| cs_has_modifier(field, m, src))
    {
        return None;
    }
    declarators(field).into_iter().find_map(|d| {
        let name = d.child_by_field_name("name")?;
        let mut c = d.walk();
        let value = d.named_children(&mut c).filter(|v| *v != name).last()?;
        matches!(
            value.kind(),
            "integer_literal"
                | "real_literal"
                | "string_literal"
                | "boolean_literal"
                | "character_literal"
        )
        .then_some(name)
    })
}

fn has_several_dimensions(rank: Node, src: &[u8]) -> bool {
    text(rank, src).contains(&b',')
}

fn not_int_storage(base: Node, src: &[u8]) -> bool {
    !matches!(text(base, src), b"int" | b"Int32" | b"System.Int32")
}

fn empty_interface_name<'t>(interface: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut cursor = interface.walk();
    // An interface combining others (`IA : IB, IC`) is a contract in itself.
    let combines = interface
        .named_children(&mut cursor)
        .any(|c| c.kind() == "base_list");
    let empty = interface
        .child_by_field_name("body")
        .is_some_and(|b| b.named_child_count() == 0);
    (empty && !combines && attribute_names(interface, src).is_empty())
        .then(|| interface.child_by_field_name("name"))?
}

#[cfg(test)]
mod tests {
    use super::super::cs::tests::flagged;

    fn method(body: &str) -> String {
        format!("namespace N;\nclass A {{\nvoid F() {{\n{body}\n}}\n}}\n")
    }

    #[test]
    fn naming_and_output() {
        let src = "namespace N;\nclass A {\nvoid loadData() { }\nint count { get; set; }\nvoid LoadData() { }\n[Fact] public void Given_a_cart() { }\nvoid Login(string login) { }\nvoid G() { Console.WriteLine(\"x\"); Console.Error.WriteLine(\"y\"); Environment.Exit(1); }\n}";
        assert_eq!(flagged("cs/member-name-pascal-case", src), [3, 4]);
        assert_eq!(flagged("cs/parameter-named-like-method", src), [7]);
        assert_eq!(flagged("cs/console-output", src), [8, 8]);
        assert_eq!(flagged("cs/environment-exit", src), [8]);
    }

    #[test]
    fn numbers() {
        let src = "namespace N;\nclass A {\nconst int Max = 42;\nint x = 0;\nbool b = false;\nobject o = null;\nint y = 5;\nbool F(int n) { return n > 42 || n == 1 || n % 2 == 1; }\nint big = 1000000;\nint ok = 1_000_000;\npublic const int Version = 2;\nprivate static readonly int Limit = 10;\npublic static readonly int Shared = 10;\n}";
        assert_eq!(flagged("cs/magic-number", src), [8]);
        assert_eq!(flagged("cs/default-value-initializer", src), [4, 5, 6]);
        assert_eq!(flagged("cs/modulus-equality", src), [8]);
        assert_eq!(flagged("cs/large-number-without-separators", src), [9]);
        assert_eq!(flagged("cs/public-constant", src), [11]);
        assert_eq!(flagged("cs/static-readonly-could-be-const", src), [12]);
    }

    #[test]
    fn layout() {
        let src = "namespace N;\nclass A {\nvoid F(bool b) {\nif (a) G();\nif (b) { G(); } else H();\nif (b) { G(); } else if (c) { H(); }\nG(); H();\nif (b) { G(); }\nif (b) { H(); }\n{ G();\n K(); }\n}\n}";
        assert_eq!(flagged("cs/missing-braces", src), [4, 5]);
        assert_eq!(flagged("cs/statements-same-line", src), [7]);
        assert_eq!(flagged("cs/if-chain-without-else", src), [6]);
        assert_eq!(flagged("cs/repeated-condition-in-sequence", src), [9]);
        assert_eq!(flagged("cs/closing-brace-position", src), [11]);
    }

    #[test]
    fn switches_and_nesting() {
        let long: String = "G(); ".repeat(9);
        let src = method(&format!(
            "switch (x) {{ case 1: {long}break; case 2: break; default: break; }}\nswitch (x) {{ case 1: switch (y) {{ case 2: break; }} break; }}\nif (a) {{ if (b) {{ if (c) {{ if (d) {{ G(); }} }} }} }}\nif (a) {{ }} else if (b) {{ }} else if (c) {{ }} else if (d) {{ if (e) {{ G(); }} }}"
        ));
        assert_eq!(flagged("cs/long-switch-section", &src), [4]);
        assert_eq!(flagged("cs/switch-without-default", &src), [5, 5]);
        assert_eq!(flagged("cs/too-few-switch-cases", &src), [5, 5]);
        assert_eq!(flagged("cs/nested-switch", &src), [5]);
        assert_eq!(flagged("cs/empty-default-clause", &src), [4]);
        assert_eq!(flagged("cs/deep-nesting", &src), [6]);
    }

    #[test]
    fn expressions() {
        let src = method(
            "a[i++] = 1;\ni++;\nfor (int j = 0; j < 3; j++) { }\nb = a && b || c && d || e;\nb = a && b || c;\ns = s.ToLower();\ns = s.ToLower(CultureInfo.InvariantCulture);\nint m = 3, n = 4;\nreturn (a + 1);\nreturn (a as B)?.C;",
        );
        assert_eq!(flagged("cs/increment-in-expression", &src), [4]);
        let arrow = "namespace N;\nclass A { int n; void Hit() => n++; }";
        assert!(flagged("cs/increment-in-expression", arrow).is_empty());
        assert_eq!(flagged("cs/complex-condition", &src), [7]);
        assert_eq!(flagged("cs/culture-sensitive-case", &src), [9]);
        assert_eq!(flagged("cs/multiple-declarations", &src), [11]);
        assert_eq!(flagged("cs/redundant-parentheses-around-value", &src), [12]);
    }

    #[test]
    fn exceptions_and_suppressions() {
        let src = "namespace N;\nclass A {\n#pragma warning disable CS0168\n[SuppressMessage(\"x\", \"y\")] void F(string name) {\ntry { G(); } catch (Exception e) { }\ntry { G(); } catch (IOException e) { }\nthrow new ArgumentNullException(\"name\");\nthrow new ArgumentNullException(nameof(name));\nthrow new NotImplementedException();\n}\n}";
        assert_eq!(flagged("cs/in-source-suppression", src), [3, 4]);
        assert_eq!(flagged("cs/catch-exception", src), [5]);
        assert_eq!(flagged("cs/use-nameof", src), [7]);
        assert_eq!(flagged("cs/not-implemented", src), [9]);
    }

    #[test]
    fn fields_and_parameters() {
        let src = "namespace N;\npublic class A {\nprotected int count;\ninternal readonly int ok;\npublic ILog Log = LogManager.GetLogger(typeof(A));\nprivate static readonly ILog L2 = LogManager.GetLogger(typeof(B));\nprivate readonly ILogger<A> injected;\npublic void Save(string p, bool force = false) { }\npublic void Split(string s, out string a) { a = s; }\npublic bool TryParse(string s, out int v) { v = 0; return true; }\nint[,] grid;\nint[][] jagged;\n}";
        assert_eq!(flagged("cs/non-private-field", src), [3]);
        assert_eq!(flagged("cs/logger-not-static-readonly", src), [5]);
        assert_eq!(flagged("cs/logger-for-other-type", src), [6]);
        assert_eq!(flagged("cs/optional-parameter", src), [8]);
        assert_eq!(flagged("cs/out-ref-parameter", src), [9]);
        assert_eq!(flagged("cs/multidimensional-array", src), [11]);
    }

    #[test]
    fn async_constructors_types() {
        let src = "namespace N;\nsealed class A : IDisposable {\npublic A(Registry r) { r.Add(this); }\npublic void Dispose() { GC.SuppressFinalize(this); }\nasync Task F() { await G(); await G().ConfigureAwait(false); await Task.Yield(); }\nint H(int x) { int factor = 3; int moving = 1; moving++; return x * factor * moving; }\nAssembly K() => Assembly.GetExecutingAssembly();\n}\nclass B { ~B() { } }\nenum Mode : byte { On, Reserved1 }\nenum Ok : int { A }\ninterface IMarker { }\ninterface IBoth : IA, IB { }";
        assert_eq!(flagged("cs/this-escapes-constructor", src), [3]);
        assert_eq!(flagged("cs/suppress-finalize-without-finalizer", src), [4]);
        assert_eq!(flagged("cs/missing-configure-await", src), [5]);
        assert_eq!(flagged("cs/could-be-const", src), [6]);
        assert_eq!(flagged("cs/get-executing-assembly", src), [7]);
        assert_eq!(flagged("cs/empty-finalizer", src), [9]);
        assert_eq!(flagged("cs/reserved-enum-member", src), [10]);
        assert_eq!(flagged("cs/enum-storage-not-int", src), [10]);
        assert_eq!(flagged("cs/empty-interface", src), [12]);
    }
}
