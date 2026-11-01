//! C# rules (ADR-0007, ADR-0015, batch 1): bugs and code smells from
//! SonarQube's default profile that a syntax tree can check. Queries stay
//! cheap on deep trees: see the notes in `js_modern.rs`.

use super::java_bugs::{find_in_scope, operator_text};
use super::java_security::text;
use super::java_smells::count_word;
use super::*;

/// This module's rules that are off unless `rules.enabled` lists them
/// (see `catalog::OFF_BY_DEFAULT`).
pub(super) static OFF_BY_DEFAULT: &[&str] = &[
    // Outside SonarQube's default C# profile.
    "cs/protected-in-sealed",
    "cs/redundant-constructor",
    "cs/empty-string-comparison",
];

pub(super) static RULES: &[Rule] = &[
    // ---- Bugs ----
    Rule {
        id: "cs/self-assignment",
        name: "Variables should not be assigned to themselves",
        description: "Assigning a variable to itself does nothing; it usually means the wrong name was typed.",
        message: "Remove this self-assignment or assign the intended value.",
        category: Bug,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S1656")],
        check: Check::Query {
            langs: CSHARP,
            query: "(assignment_expression) @match",
            filter: Some(Keep(is_self_assignment)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int x; void F() { x = x; } }",
            good: "class A { int x; void F(int x) { this.x = x; } }",
        }),
    },
    Rule {
        id: "cs/lost-increment",
        name: "Increments and decrements should not be overwritten",
        description: "In `i = i++` the increment happens, then the old value is assigned back, so `i` does not change.",
        message: "Remove this assignment: use the increment or decrement on its own.",
        category: Bug,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S2123")],
        check: Check::Query {
            langs: CSHARP,
            query: "(assignment_expression right: (postfix_unary_expression)) @match",
            filter: Some(Keep(is_lost_increment)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(int i) { i = i++; } }",
            good: "class A { void F(int i) { i++; } }",
        }),
    },
    Rule {
        id: "cs/reversed-operator",
        name: "Assignment operators should not be reversed",
        description: "`x =+ 1` assigns `+1` to `x`; `x += 1` was almost certainly meant. The same goes for `=-` and `=!`.",
        message: "Did you mean the compound operator? Write it as '+=', '-=' or '= !' with the spacing that matches.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2757")],
        check: Check::Query {
            langs: CSHARP,
            query: "(assignment_expression right: (prefix_unary_expression)) @match",
            filter: Some(Keep(is_reversed_operator)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(int x) { x =+ 1; } }",
            good: "class A { void F(int x) { x += 1; } }",
        }),
    },
    Rule {
        id: "cs/double-unary",
        name: "'!' and '~' should not be doubled",
        description: "`!!x` is `x` and `~~x` is `x`: the doubled operator does nothing, or another operator was meant.",
        message: "Remove the doubled operator.",
        category: Bug,
        severity: Major,
        effort_minutes: 1,
        sonar: &[exact("S2761")],
        check: Check::Query {
            langs: CSHARP,
            query: "(prefix_unary_expression (prefix_unary_expression)) @match",
            filter: Some(Keep(is_doubled_unary)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { bool F(bool b) { return !!b; } }",
            good: "class A { bool F(bool b) { return b; } }",
        }),
    },
    Rule {
        id: "cs/for-loop-wrong-direction",
        name: "A for loop's update should move its counter towards the end condition",
        description: "A counter compared with `<` but decremented (or with `>` but incremented) never reaches the \
                      end, so the loop runs until the value wraps around.",
        message: "Change this update so the counter moves towards the loop's end condition.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2251")],
        check: Check::Query {
            langs: CSHARP,
            query: "(for_statement condition: (binary_expression)) @match",
            filter: Some(Find(wrong_direction_update)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(int n) { for (int i = 0; i < n; i--) { G(i); } } }",
            good: "class A { void F(int n) { for (int i = 0; i < n; i++) { G(i); } } }",
        }),
    },
    Rule {
        id: "cs/collection-size-sign",
        name: "Collection sizes should not be compared with negative bounds",
        description: "`Count`, `Length` and `Count()` are never negative, so `>= 0` is always true and `< 0` always false.",
        message: "This comparison always has the same result: compare with the bound you meant, such as '> 0'.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S3981")],
        check: Check::Query {
            langs: CSHARP,
            query: "(binary_expression) @match",
            filter: Some(Keep(compares_size_with_zero_uselessly)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { bool F(int[] a) { return a.Length >= 0; } }",
            good: "class A { bool F(int[] a) { return a.Length > 0; } }",
        }),
    },
    Rule {
        id: "cs/async-void",
        name: "Async methods should not return void",
        description: "Exceptions from an `async void` method can't be caught by the caller and crash the process, \
                      and the caller can't await it. Event handlers are the exception, since their signature is fixed.",
        message: "Return 'Task' instead of 'void'.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S3168")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(method_declaration (modifier) returns: (predefined_type)) \
                     (local_function_statement (modifier) type: (predefined_type))] @match",
            filter: Some(Find(async_void_name)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { async void Load() { await Task.Delay(1); } }",
            good: "class A { async Task Load() { await Task.Delay(1); } void OnClick(object sender, EventArgs e) { } async void OnLoad(object sender, EventArgs e) { await Load(); } }",
        }),
    },
    Rule {
        id: "cs/accessor-ignores-value",
        name: "Set, init, add and remove accessors should use 'value'",
        description: "An accessor that never reads `value` silently drops what the caller passed in.",
        message: "Use 'value' in this accessor, or throw if the operation isn't supported.",
        category: CodeSmell,
        severity: Blocker,
        effort_minutes: 5,
        sonar: &[exact("S3237")],
        check: Check::Query {
            langs: CSHARP,
            query: "(accessor_declaration body: (_)) @match",
            filter: Some(Keep(accessor_ignores_value)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int x; int X { get { return x; } set { x = 42; } } }",
            good: "class A { int x; int X { get { return x; } set { x = value; } } int Y { set => throw new NotSupportedException(); } }",
        }),
    },
    Rule {
        id: "cs/destructor-throws",
        name: "Finalizers should not throw exceptions",
        description: "An exception thrown from a finalizer terminates the process on .NET, unless it is caught.",
        message: "Don't throw from a finalizer: log the problem or ignore it.",
        category: Bug,
        severity: Blocker,
        effort_minutes: 10,
        sonar: &[exact("S1048")],
        check: Check::Query {
            langs: CSHARP,
            query: "(destructor_declaration body: (_) @match)",
            filter: Some(Find(throw_in_scope)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { ~A() { throw new InvalidOperationException(); } }",
            good: "class A { ~A() { Release(); } }",
        }),
    },
    Rule {
        id: "cs/to-string-returns-null",
        name: "ToString() should not return null",
        description: "Callers expect `ToString()` to return text; `null` makes string formatting and concatenation fail later.",
        message: "Return an empty string instead of null.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2225")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(method_declaration name: (identifier) @n (#eq? @n "ToString")) @match"#,
            filter: Some(Find(returned_null)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { public override string ToString() { return null; } }",
            good: "class A { public override string ToString() { return \"\"; } }",
        }),
    },
    Rule {
        id: "cs/identical-branches",
        name: "Every branch of a conditional should not do the same thing",
        description: "When the `if` and every `else`, or both sides of `?:`, are identical, the condition is \
                      pointless, or one branch has the wrong code.",
        message: "Remove the condition, or change the branch that should differ.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3923")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(if_statement alternative: (_)) (conditional_expression)] @match",
            filter: Some(Keep(all_branches_identical)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int F(bool b) { return b ? 1 : 1; } }",
            good: "class A { int F(bool b) { return b ? 1 : 2; } }",
        }),
    },
    Rule {
        id: "cs/anonymous-unsubscribe",
        name: "Anonymous functions should not be used to unsubscribe from events",
        description: "Each lambda or anonymous method is a new delegate, so `-=` with one removes nothing and the \
                      original handler stays subscribed.",
        message: "Keep the handler in a variable or method, and unsubscribe with that.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S3244")],
        check: Check::Query {
            langs: CSHARP,
            query: "(assignment_expression right: [(lambda_expression) (anonymous_method_expression)]) @match",
            filter: Some(Keep(is_unsubscription)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(B b) { b.Changed -= (s, e) => G(); } }",
            good: "class A { void F(B b) { b.Changed -= OnChanged; } }",
        }),
    },
    Rule {
        id: "cs/duplicate-condition",
        name: "Conditions in an if/else if chain should not repeat",
        description: "A condition already tested earlier in the chain never selects its branch, so that code is dead.",
        message: "This condition was already tested earlier in this chain: change it or remove the branch.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S1862")],
        check: Check::Query {
            langs: CSHARP,
            query: "(if_statement alternative: (if_statement)) @match",
            filter: Some(Find(repeated_condition)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(int a) { if (a == 1) { G(); } else if (a == 1) { H(); } } }",
            good: "class A { void F(int a) { if (a == 1) { G(); } else if (a == 2) { H(); } } }",
        }),
    },
    Rule {
        id: "cs/identical-operands",
        name: "Identical expressions should not be used on both sides of a binary operator",
        description: "`a == a` is always true and `a - a` always zero: one side is probably the wrong expression.",
        message: "Correct one of the identical operands, or simplify the expression.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S1764")],
        check: Check::Query {
            langs: CSHARP,
            query: "(binary_expression) @match",
            filter: Some(Keep(has_identical_operands)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { bool F(int a) { return a == a; } }",
            good: "class A { bool F(int a, int b) { return a == b; } }",
        }),
    },
    // ---- Code smells ----
    Rule {
        id: "cs/empty-block",
        name: "Nested blocks should not be left empty",
        description: "An empty `if`, loop, `try`, `catch` or `finally` block is either unfinished or unneeded. \
                      A comment explaining why it is empty is enough.",
        message: "Fill this block, remove it, or add a comment explaining why it is empty.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S108")],
        check: Check::Query {
            langs: CSHARP,
            query: "(block) @match",
            filter: Some(Keep(is_empty_nested_block)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F() { try { G(); } catch (IOException e) { } } }",
            good: "class A { void F() { try { G(); } catch (IOException e) { /* already logged by G */ } } }",
        }),
    },
    Rule {
        id: "cs/empty-method",
        name: "Methods should not be empty",
        description: "An empty method is unfinished or unneeded. If it is empty on purpose, say why in a comment, \
                      or throw `NotSupportedException` when callers shouldn't use it.",
        message: "Add a comment explaining why this method is empty, throw NotSupportedException, or complete it.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S1186")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(method_declaration body: (block) @b) (local_function_statement body: (block) @b)] @match",
            filter: Some(Find(empty_method_name)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { public void Reset() { } }",
            good: "class A { public void Reset() { /* stateless: nothing to reset */ } public virtual void OnStart() { } }",
        }),
    },
    Rule {
        id: "cs/rethrow-loses-stack",
        name: "Exceptions should be rethrown with 'throw;'",
        description: "`throw e;` restarts the exception's stack trace at this line, losing where it was first thrown.",
        message: "Use 'throw;' to rethrow, which keeps the original stack trace.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3445")],
        check: Check::Query {
            langs: CSHARP,
            query: "(catch_clause (catch_declaration name: (identifier)) body: (block)) @match",
            filter: Some(Find(rethrown_catch_variable)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F() { try { G(); } catch (IOException e) { Log(e); throw e; } } }",
            good: "class A { void F() { try { G(); } catch (IOException e) { Log(e); throw; } } }",
        }),
    },
    Rule {
        id: "cs/useless-catch",
        name: "Catch clauses should do more than rethrow",
        description: "A `catch` that only rethrows changes nothing; without it the exception propagates the same way.",
        message: "Remove this catch clause, or handle the exception in it.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S2737")],
        check: Check::Query {
            langs: CSHARP,
            query: "(catch_clause body: (block)) @match",
            filter: Some(Keep(only_rethrows)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F() { try { G(); } catch (IOException) { throw; } } }",
            good: "class A { void F() { try { G(); } catch (IOException) { throw; } catch (Exception e) { Log(e); } } }",
        }),
    },
    Rule {
        id: "cs/general-exception",
        name: "General or reserved exceptions should not be thrown",
        description: "Callers can't catch `Exception` or `ApplicationException` without catching everything else too, \
                      and the runtime reserves `NullReferenceException`, `IndexOutOfRangeException` and \
                      `OutOfMemoryException` for itself.",
        message: "Throw a more specific exception, such as ArgumentException or InvalidOperationException, or a custom one.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 20,
        sonar: &[exact("S112")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(throw_statement (object_creation_expression) @match) \
                     (throw_expression (object_creation_expression) @match)]",
            filter: Some(Keep(creates_general_exception)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F() { throw new Exception(\"failed\"); } }",
            good: "class A { void F() { throw new InvalidOperationException(\"failed\"); } }",
        }),
    },
    Rule {
        id: "cs/obsolete-without-explanation",
        name: "[Obsolete] should say what to use instead",
        description: "Callers warned that something is obsolete need to know what replaces it.",
        message: "Add a message to this [Obsolete] attribute naming the replacement.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1123")],
        check: Check::Query {
            langs: CSHARP,
            query: "(attribute name: (_)) @match",
            filter: Some(Keep(is_bare_obsolete)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { [Obsolete] void F() { G(); } }",
            good: "class A { [Obsolete(\"Use G instead.\")] void F() { G(); } }",
        }),
    },
    Rule {
        id: "cs/nested-ternary",
        name: "Ternary operators should not be nested",
        description: "A `?:` inside another is hard to read; an `if` chain or a `switch` expression is clearer.",
        message: "Extract this nested conditional into a separate statement or a switch expression.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3358")],
        check: Check::Query {
            langs: CSHARP,
            query: "(conditional_expression) @match",
            filter: Some(Find(nested_conditional)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int F(int a) { return a > 0 ? 1 : a < 0 ? -1 : 0; } }",
            good: "class A { int F(int a) { return Math.Sign(a); } }",
        }),
    },
    Rule {
        id: "cs/inverted-comparison",
        name: "Boolean checks should not be inverted",
        description: "`!(a == b)` reads worse than `a != b`, which says the same thing.",
        message: "Use the opposite operator instead of negating the comparison.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S1940")],
        check: Check::Query {
            langs: CSHARP,
            query: "(prefix_unary_expression (parenthesized_expression (binary_expression))) @match",
            filter: Some(Keep(negates_comparison)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { bool F(int a, int b) { return !(a == b); } }",
            good: "class A { bool F(int a, int b) { return a != b; } }",
        }),
    },
    Rule {
        id: "cs/redundant-boolean-literal",
        name: "Boolean literals should not be redundant",
        description: "`b ? true : false` is `b`, and `x && true` is `x`. Comparisons such as `x == true` are left \
                      alone: on a nullable `bool` they aren't redundant, and the syntax tree can't tell.",
        message: "Remove the boolean literal and simplify the expression.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[related("S1125")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(binary_expression) (conditional_expression) (prefix_unary_expression (boolean_literal))] @match",
            filter: Some(Keep(has_redundant_boolean_literal)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { bool F(bool b) { return b ? true : false; } }",
            good: "class A { bool F(bool b, bool? c) { return b || c == true; } }",
        }),
    },
    Rule {
        id: "cs/count-instead-of-any",
        name: "Any() should be used to test whether a sequence is empty",
        description: "`Count()` may enumerate the whole sequence to answer a yes-or-no question that `Any()` \
                      answers at the first element.",
        message: "Use 'Any()' instead of comparing 'Count()' with 0.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S1155")],
        check: Check::Query {
            langs: CSHARP,
            query: "(binary_expression) @match",
            filter: Some(Keep(compares_count_call_with_zero)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { bool F(IEnumerable<int> xs) { return xs.Count() > 0; } }",
            good: "class A { bool F(IEnumerable<int> xs) { return xs.Any(); } }",
        }),
    },
    Rule {
        id: "cs/where-then-predicate-method",
        name: "Where() should not be followed by a method that takes the predicate itself",
        description: "`xs.Where(p).First()` is `xs.First(p)`: one call is shorter and does the same.",
        message: "Pass the predicate to this method and remove the Where() call.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[related("S2971")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(invocation_expression
                        function: (member_access_expression
                          expression: (invocation_expression
                            function: (member_access_expression name: (identifier) @w))
                          name: (identifier) @n)
                        (#eq? @w "Where")
                        (#any-of? @n "Any" "Count" "LongCount" "First" "FirstOrDefault"
                                     "Last" "LastOrDefault" "Single" "SingleOrDefault")) @match"#,
            filter: Some(Keep(where_then_bare_call)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int F(List<int> xs) { return xs.Where(x => x > 0).First(); } }",
            good: "class A { int F(List<int> xs) { return xs.First(x => x > 0); } }",
        }),
    },
    Rule {
        id: "cs/gc-collect",
        name: "GC.Collect() should not be called",
        description: "Forcing a garbage collection pauses the application and usually makes overall performance \
                      worse than the runtime's own scheduling.",
        message: "Remove this call and let the runtime decide when to collect.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S1215")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(invocation_expression
                        function: (member_access_expression expression: (identifier) @o name: (identifier) @n)
                        (#eq? @o "GC") (#eq? @n "Collect")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F() { GC.Collect(); } }",
            good: "class A { void F() { GC.KeepAlive(this); } }",
        }),
    },
    Rule {
        id: "cs/visible-mutable-static-field",
        name: "Static fields visible outside their class should be constant or read-only",
        description: "Any code can change a public, protected or internal static field, so its value can't be \
                      relied on, and changes race between threads.",
        message: "Make this field 'readonly' or 'const', or private behind a property.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 20,
        sonar: &[exact("S2223")],
        check: Check::Query {
            langs: CSHARP,
            query: "(field_declaration (modifier)) @match",
            filter: Some(Keep(is_visible_mutable_static_field)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { public static int Limit = 10; }",
            good: "class A { public static readonly int Limit = 10; private static int count; }",
        }),
    },
    Rule {
        id: "cs/redundant-base-type",
        name: "Inheritance lists should not name the default base type",
        description: "Every class already derives from `object` and every enum is already backed by `int`.",
        message: "Remove this redundant base type.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S1939")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(class_declaration (base_list . (_) @match)) (enum_declaration (base_list . (_) @match))]",
            filter: Some(Keep(is_default_base_type)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "enum Color : int { Red, Green }",
            good: "enum Color : byte { Red, Green }",
        }),
    },
    Rule {
        id: "cs/empty-statement",
        name: "Empty statements should be removed",
        description: "A stray `;` does nothing, and can hide a mistake such as a semicolon after an `if`.",
        message: "Remove this empty statement.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S1116")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(block (empty_statement) @match) (switch_section (empty_statement) @match)]",
            filter: None,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F() { G();; } }",
            good: "class A { void F() { G(); while (Next()) ; } }",
        }),
    },
    Rule {
        id: "cs/redundant-jump",
        name: "Redundant return and continue statements should be removed",
        description: "A `return;` at the end of a method, or a `continue;` at the end of a loop, does what would \
                      happen anyway.",
        message: "Remove this redundant jump.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S3626")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(return_statement) (continue_statement)] @match",
            filter: Some(Keep(is_redundant_jump)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F() { G(); return; } }",
            good: "class A { void F(bool b) { if (b) { return; } G(); } }",
        }),
    },
    Rule {
        id: "cs/protected-in-sealed",
        name: "Sealed classes should not declare protected members",
        description: "A sealed class has no subclasses, so `protected` means `private` there and misleads readers.",
        message: "Make this member private, or unseal the class.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S2156")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration (modifier) body: (declaration_list)) @match",
            filter: Some(Find(protected_member_of_sealed_class)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "sealed class A { protected int count; }",
            good: "sealed class A : B { private int count; protected override void F() { } }",
        }),
    },
    Rule {
        id: "cs/abstract-class-public-constructor",
        name: "Abstract classes should not have public constructors",
        description: "Only subclasses can call an abstract class's constructor, so `public` promises more than it gives.",
        message: "Make this constructor protected.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S3442")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration (modifier) body: (declaration_list)) @match",
            filter: Some(Find(public_constructor_of_abstract_class)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "abstract class A { public A() { Init(); } }",
            good: "abstract class A { protected A() { Init(); } }",
        }),
    },
    Rule {
        id: "cs/redundant-constructor",
        name: "Redundant constructors and finalizers should be removed",
        description: "An empty public parameterless constructor, when it is the class's only constructor, is \
                      what the compiler generates anyway. An empty finalizer only slows garbage collection.",
        message: "Remove this redundant declaration.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S3253")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(constructor_declaration body: (block)) (destructor_declaration body: (block))] @match",
            filter: Some(Keep(is_redundant_constructor)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { public A() { } }",
            good: "class A { public A() { } public A(int x) { X = x; } int X; }",
        }),
    },
    Rule {
        id: "cs/mergeable-if",
        name: "Nested if statements should be merged",
        description: "An `if` whose only statement is another `if`, neither with an `else`, reads more simply as \
                      one condition joined with `&&`.",
        message: "Merge this if statement with the enclosing one.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1066")],
        check: Check::Query {
            langs: CSHARP,
            query: "(if_statement consequence: (_)) @match",
            filter: Some(Find(mergeable_inner_if)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(bool a, bool b) { if (a) { if (b) { G(); } } } }",
            good: "class A { void F(bool a, bool b) { if (a && b) { G(); } } }",
        }),
    },
    Rule {
        id: "cs/empty-string-comparison",
        name: "string.IsNullOrEmpty() should be used to test for empty strings",
        description: "`s == \"\"` misses `null`, which usually needs the same handling; `string.IsNullOrEmpty(s)` \
                      covers both and says what is meant.",
        message: "Use 'string.IsNullOrEmpty()' instead of comparing with an empty string.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S3256")],
        check: Check::Query {
            langs: CSHARP,
            query: "(binary_expression) @match",
            filter: Some(Keep(compares_with_empty_string)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { bool F(string s) { return s == \"\"; } }",
            good: "class A { bool F(string s) { return string.IsNullOrEmpty(s); } }",
        }),
    },
    Rule {
        id: "cs/enum-name-suffix",
        name: "Enum names should not end with 'Enum' or 'Flags'",
        description: "The suffix repeats what the declaration already says.",
        message: "Remove the 'Enum' or 'Flags' suffix from this name.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S2344")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(enum_declaration name: (identifier) @match (#match? @match ".(Enum|Flags)$"))"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "enum ColorEnum { Red, Green }",
            good: "enum Color { Red, Green }",
        }),
    },
];

// ---------------------------------------------------- shared C# helpers

/// Where a search for a function's own statements stops: nested functions
/// and types have their own.
pub(super) const CS_SCOPE_STOPS: &[&str] = &[
    "lambda_expression",
    "anonymous_method_expression",
    "local_function_statement",
    "class_declaration",
    "struct_declaration",
    "record_declaration",
    "interface_declaration",
];

/// The rightmost identifier of a type or member name: `Exception` for
/// `System.Exception`, `List` for `List<int>`.
pub(super) fn simple_name<'s>(node: Node, src: &'s [u8]) -> &'s [u8] {
    match node.kind() {
        "qualified_name" => node
            .child_by_field_name("name")
            .map_or(&b""[..], |n| simple_name(n, src)),
        "generic_name" => node.named_child(0).map_or(&b""[..], |n| text(n, src)),
        "member_access_expression" => node
            .child_by_field_name("name")
            .map_or(&b""[..], |n| simple_name(n, src)),
        _ => text(node, src),
    }
}

/// A regular or verbatim string literal's characters between its quotes;
/// None for interpolated and raw strings.
pub(super) fn cs_string_value<'s>(node: Node, src: &'s [u8]) -> Option<&'s [u8]> {
    let t = text(node, src);
    let t = t.strip_suffix(b"u8").unwrap_or(t);
    let body = match node.kind() {
        "string_literal" => t.strip_prefix(b"\"")?,
        "verbatim_string_literal" => t.strip_prefix(b"@\"")?,
        _ => return None,
    };
    body.strip_suffix(b"\"")
}

/// A block's or body's named children without comments. (C#'s grammar has
/// one `comment` kind, unlike Java's line and block comments.)
pub(super) fn cs_statements(block: Node) -> Vec<Node> {
    let mut cursor = block.walk();
    block
        .named_children(&mut cursor)
        .filter(|n| n.kind() != "comment")
        .collect()
}

/// Whether a declaration has `word` among its modifiers.
pub(super) fn cs_has_modifier(declaration: Node, word: &str, src: &[u8]) -> bool {
    let mut cursor = declaration.walk();
    declaration
        .children(&mut cursor)
        .any(|c| c.kind() == "modifier" && text(c, src) == word.as_bytes())
}

/// The operator of a prefix or postfix unary expression.
fn unary_operator<'t, 's>(node: Node<'t>, src: &'s [u8]) -> Option<(Node<'t>, &'s [u8])> {
    let mut cursor = node.walk();
    let op = node.children(&mut cursor).find(|c| !c.is_named())?;
    Some((op, text(op, src)))
}

/// The named operand of a unary expression, skipping comments.
pub(super) fn operand(node: Node) -> Option<Node> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|c| c.kind() != "comment")
}

/// Text with whitespace removed, to compare code that differs only in layout.
pub(super) fn squeezed(node: Node, src: &[u8]) -> Vec<u8> {
    text(node, src)
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect()
}

/// Whether two nodes hold the same code, ignoring layout. Comparing the
/// kinds first keeps chains such as `a - b - c - ...` linear: there, the
/// left side is a long expression and the right a name.
pub(super) fn same_code(a: Node, b: Node, src: &[u8]) -> bool {
    a.kind() == b.kind()
        && a.named_child_count() == b.named_child_count()
        && squeezed(a, src) == squeezed(b, src)
}

pub(super) fn unparenthesized(mut node: Node) -> Node {
    while node.kind() == "parenthesized_expression" {
        match operand(node) {
            Some(inner) => node = inner,
            None => break,
        }
    }
    node
}

fn is_member_named(node: Node, src: &[u8], names: &[&str]) -> bool {
    node.kind() == "member_access_expression"
        && node
            .child_by_field_name("name")
            .is_some_and(|n| names.iter().any(|name| text(n, src) == name.as_bytes()))
}

/// `x.Count()` and the like: a call of a member with one of `names`.
fn is_call_named(node: Node, src: &[u8], names: &[&str]) -> bool {
    node.kind() == "invocation_expression"
        && node
            .child_by_field_name("function")
            .is_some_and(|f| is_member_named(f, src, names))
}

fn is_zero(node: Node, src: &[u8]) -> bool {
    node.kind() == "integer_literal" && text(node, src) == b"0"
}

fn is_one(node: Node, src: &[u8]) -> bool {
    node.kind() == "integer_literal" && text(node, src) == b"1"
}

/// A comparison's operands and operator, with a constant on the right:
/// `0 < x` becomes `x > 0`.
fn normalized_comparison<'t>(
    node: Node<'t>,
    src: &[u8],
    is_constant: impl Fn(Node<'t>) -> bool,
) -> Option<(Node<'t>, &'static str, Node<'t>)> {
    let left = node.child_by_field_name("left")?;
    let right = node.child_by_field_name("right")?;
    let op = match operator_text(node, src) {
        b"==" => "==",
        b"!=" => "!=",
        b"<" => "<",
        b"<=" => "<=",
        b">" => ">",
        b">=" => ">=",
        _ => return None,
    };
    if is_constant(right) {
        return Some((left, op, right));
    }
    if is_constant(left) {
        let flipped = match op {
            "<" => ">",
            "<=" => ">=",
            ">" => "<",
            ">=" => "<=",
            same => same,
        };
        return Some((right, flipped, left));
    }
    None
}

// ---------------------------------------------------- bug filters

/// Object and `with` initializers assign the new object's member from the
/// surrounding scope, so `new P { Name = Name }` is fine.
fn in_initializer(node: Node) -> bool {
    node.parent()
        .is_some_and(|p| matches!(p.kind(), "initializer_expression" | "with_initializer"))
}

fn is_self_assignment(node: Node, src: &[u8]) -> bool {
    if operator_text(node, src) != b"=" {
        return false;
    }
    let same = match (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) {
        (Some(l), Some(r)) => same_code(l, r, src),
        _ => false,
    };
    // parent() costs the node's depth: test it last.
    same && !in_initializer(node)
}

fn is_lost_increment(node: Node, src: &[u8]) -> bool {
    if operator_text(node, src) != b"=" {
        return false;
    }
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return false;
    };
    unary_operator(right, src).is_some_and(|(_, op)| op == b"++" || op == b"--")
        && operand(right).is_some_and(|o| same_code(o, left, src))
}

/// `x =+ y`: no space between `=` and the unary operator, but a space after it.
fn is_reversed_operator(node: Node, src: &[u8]) -> bool {
    let (Some(eq), Some(right)) = (
        node.child_by_field_name("operator"),
        node.child_by_field_name("right"),
    ) else {
        return false;
    };
    if text(eq, src) != b"=" {
        return false;
    }
    let Some((op, op_text)) = unary_operator(right, src) else {
        return false;
    };
    let Some(value) = operand(right) else {
        return false;
    };
    matches!(op_text, b"+" | b"-" | b"!")
        && op.start_byte() == eq.end_byte()
        && value.start_byte() > op.end_byte()
}

fn is_doubled_unary(node: Node, src: &[u8]) -> bool {
    let Some((_, op)) = unary_operator(node, src) else {
        return false;
    };
    if !matches!(op, b"!" | b"~") {
        return false;
    }
    let same_op = |n: Node| {
        n.kind() == "prefix_unary_expression"
            && unary_operator(n, src).is_some_and(|(_, o)| o == op)
    };
    // `!!!x` is reported once, at its innermost pair: looking down rather than
    // up keeps long runs linear.
    operand(node).is_some_and(|inner| same_op(inner) && !operand(inner).is_some_and(same_op))
}

/// The update of a `for` loop that moves its counter away from the end
/// condition, such as `i--` in `for (...; i < n; i--)`.
fn wrong_direction_update<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let condition = node.child_by_field_name("condition")?;
    let left = condition.child_by_field_name("left")?;
    let right = condition.child_by_field_name("right")?;
    let mut cursor = node.walk();
    let updates: Vec<Node> = node.children_by_field_name("update", &mut cursor).collect();
    // The counter is whichever side the updates change: `n > i` reads as `i < n`.
    for (counter, op, _) in [
        normalized_comparison(condition, src, |n| n == right),
        normalized_comparison(condition, src, |n| n == left),
    ]
    .into_iter()
    .flatten()
    {
        let must_grow = match op {
            "<" | "<=" => true,
            ">" | ">=" => false,
            _ => return None,
        };
        if counter.kind() != "identifier" {
            continue;
        }
        let counter = text(counter, src);
        let moves: Vec<(Node, bool)> = updates
            .iter()
            .filter_map(|u| update_direction(*u, counter, src).map(|grows| (*u, grows)))
            .collect();
        if !moves.is_empty() {
            return moves
                .iter()
                .all(|(_, grows)| *grows != must_grow)
                .then(|| moves[0].0);
        }
    }
    None
}

/// Whether `update` increases (`Some(true)`) or decreases `counter`, when it
/// is a `++`, `--`, `+=` or `-=` of it by a literal.
fn update_direction(update: Node, counter: &[u8], src: &[u8]) -> Option<bool> {
    match update.kind() {
        "postfix_unary_expression" | "prefix_unary_expression" => {
            if operand(update).map(|o| text(o, src)) != Some(counter) {
                return None;
            }
            match unary_operator(update, src)?.1 {
                b"++" => Some(true),
                b"--" => Some(false),
                _ => None,
            }
        }
        "assignment_expression" => {
            let left = update.child_by_field_name("left")?;
            let right = update.child_by_field_name("right")?;
            if text(left, src) != counter || right.kind() != "integer_literal" {
                return None;
            }
            match operator_text(update, src) {
                b"+=" => Some(true),
                b"-=" => Some(false),
                _ => None,
            }
        }
        _ => None,
    }
}

fn is_size(node: Node, src: &[u8]) -> bool {
    is_member_named(node, src, &["Count", "Length", "LongLength"])
        || is_call_named(node, src, &["Count", "LongCount"])
}

fn compares_size_with_zero_uselessly(node: Node, src: &[u8]) -> bool {
    normalized_comparison(node, src, |n| is_zero(n, src))
        .is_some_and(|(size, op, _)| matches!(op, ">=" | "<") && is_size(size, src))
}

fn async_void_name<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let returns = node
        .child_by_field_name("returns")
        .or_else(|| node.child_by_field_name("type"))?;
    if text(returns, src) != b"void"
        || !cs_has_modifier(node, "async", src)
        || cs_has_modifier(node, "override", src)
        || is_event_handler(node, src)
    {
        return None;
    }
    node.child_by_field_name("name")
}

/// `(object sender, EventArgs e)` and the like: the shape .NET events require.
fn is_event_handler(method: Node, src: &[u8]) -> bool {
    let Some(params) = method.child_by_field_name("parameters") else {
        return false;
    };
    let mut cursor = params.walk();
    let types: Vec<&[u8]> = params
        .named_children(&mut cursor)
        .filter(|p| p.kind() == "parameter")
        .filter_map(|p| p.child_by_field_name("type").map(|t| simple_name(t, src)))
        .collect();
    types.len() == 2 && types[1].ends_with(b"Args")
}

fn accessor_ignores_value(node: Node, src: &[u8]) -> bool {
    let keyword = node
        .child_by_field_name("name")
        .map_or(&b""[..], |k| text(k, src));
    if !matches!(keyword, b"set" | b"init" | b"add" | b"remove") {
        return false;
    }
    let Some(body) = node.child_by_field_name("body") else {
        return false;
    };
    let only_throws = match body.kind() {
        "block" => {
            let stmts = cs_statements(body);
            stmts.is_empty() || (stmts.len() == 1 && stmts[0].kind() == "throw_statement")
        }
        _ => operand(body).is_some_and(|e| e.kind() == "throw_expression"),
    };
    !only_throws && count_word(text(body, src), b"value") == 0
}

fn throw_in_scope<'t>(body: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    find_in_scope(body, CS_SCOPE_STOPS, |n| {
        matches!(n.kind(), "throw_statement" | "throw_expression")
    })
}

fn returned_null<'t>(method: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    // `string?` declares that null is a possible result.
    if method
        .child_by_field_name("parameters")
        .is_some_and(|p| p.named_child_count() != 0)
        || method
            .child_by_field_name("returns")
            .is_some_and(|r| r.kind() == "nullable_type")
    {
        return None;
    }
    let body = method.child_by_field_name("body")?;
    if body.kind() == "arrow_expression_clause" {
        return operand(body).filter(|e| e.kind() == "null_literal");
    }
    find_in_scope(body, CS_SCOPE_STOPS, |n| {
        n.kind() == "return_statement" && operand(n).is_some_and(|e| e.kind() == "null_literal")
    })
}

fn all_branches_identical(node: Node, src: &[u8]) -> bool {
    if node.kind() == "conditional_expression" {
        return match (
            node.child_by_field_name("consequence"),
            node.child_by_field_name("alternative"),
        ) {
            (Some(a), Some(b)) => same_code(a, b, src),
            _ => false,
        };
    }
    // Only the head of a chain: an else-if is part of its parent's chain.
    if node.parent().is_some_and(|p| {
        p.kind() == "if_statement" && p.child_by_field_name("alternative") == Some(node)
    }) {
        return false;
    }
    let Some(first) = node.child_by_field_name("consequence") else {
        return false;
    };
    let first = squeezed(first, src);
    let mut current = node;
    loop {
        let Some(alternative) = current.child_by_field_name("alternative") else {
            // No final else: when no condition holds, nothing runs.
            return false;
        };
        if alternative.kind() == "if_statement" {
            let same = alternative
                .child_by_field_name("consequence")
                .is_some_and(|c| squeezed(c, src) == first);
            if !same {
                return false;
            }
            current = alternative;
        } else {
            return squeezed(alternative, src) == first;
        }
    }
}

fn is_unsubscription(node: Node, src: &[u8]) -> bool {
    operator_text(node, src) == b"-="
}

fn repeated_condition<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if node.parent().is_some_and(|p| {
        p.kind() == "if_statement" && p.child_by_field_name("alternative") == Some(node)
    }) {
        return None;
    }
    let mut seen: Vec<Vec<u8>> = Vec::new();
    let mut current = Some(node);
    while let Some(stmt) = current.filter(|n| n.kind() == "if_statement") {
        let condition = stmt.child_by_field_name("condition")?;
        let key = squeezed(condition, src);
        if seen.contains(&key) {
            return Some(condition);
        }
        seen.push(key);
        current = stmt.child_by_field_name("alternative");
    }
    None
}

fn has_identical_operands(node: Node, src: &[u8]) -> bool {
    if !matches!(
        operator_text(node, src),
        b"=="
            | b"!="
            | b"<"
            | b"<="
            | b">"
            | b">="
            | b"&&"
            | b"||"
            | b"&"
            | b"|"
            | b"^"
            | b"-"
            | b"/"
            | b"%"
            | b"??"
    ) {
        return false;
    }
    let (Some(l), Some(r)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return false;
    };
    // Calls may return something different each time.
    let has_call = |n: Node| {
        find_in_scope(n, &[], |c| {
            matches!(
                c.kind(),
                "invocation_expression" | "object_creation_expression"
            )
        })
        .is_some()
            || matches!(
                n.kind(),
                "invocation_expression" | "object_creation_expression"
            )
    };
    same_code(l, r, src) && !has_call(l)
}

// ---------------------------------------------------- code smell filters

/// `using (...) { }` and `lock (...) { }` are left alone: they run for the
/// acquire and release.
fn is_empty_nested_block(node: Node, _: &[u8]) -> bool {
    if node.named_child_count() != 0 {
        return false;
    }
    node.parent().is_some_and(|p| {
        matches!(
            p.kind(),
            "if_statement"
                | "for_statement"
                | "foreach_statement"
                | "while_statement"
                | "do_statement"
                | "try_statement"
                | "catch_clause"
                | "finally_clause"
                | "checked_statement"
                | "unsafe_statement"
                | "block"
        )
    })
}

fn empty_method_name<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let body = node.child_by_field_name("body")?;
    if body.named_child_count() != 0
        || ["virtual", "override", "abstract", "partial", "extern"]
            .iter()
            .any(|m| cs_has_modifier(node, m, src))
    {
        return None;
    }
    node.child_by_field_name("name")
}

fn rethrown_catch_variable<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut cursor = node.walk();
    let declaration = node
        .named_children(&mut cursor)
        .find(|c| c.kind() == "catch_declaration")?;
    let name = text(declaration.child_by_field_name("name")?, src);
    let body = node.child_by_field_name("body")?;
    find_in_scope(body, CS_SCOPE_STOPS, |n| {
        n.kind() == "throw_statement"
            && operand(n).is_some_and(|e| e.kind() == "identifier" && text(e, src) == name)
    })
}

fn only_rethrows(node: Node, _: &[u8]) -> bool {
    let Some(body) = node.child_by_field_name("body") else {
        return false;
    };
    let stmts = cs_statements(body);
    let rethrows =
        stmts.len() == 1 && stmts[0].kind() == "throw_statement" && operand(stmts[0]).is_none();
    if !rethrows {
        return false;
    }
    let mut cursor = node.walk();
    if node
        .named_children(&mut cursor)
        .any(|c| c.kind() == "catch_filter_clause")
    {
        return false;
    }
    // A later, more general catch is skipped thanks to this one.
    let mut next = node.next_named_sibling();
    while let Some(sibling) = next {
        if sibling.kind() == "catch_clause" {
            return false;
        }
        next = sibling.next_named_sibling();
    }
    true
}

fn creates_general_exception(node: Node, src: &[u8]) -> bool {
    node.child_by_field_name("type").is_some_and(|t| {
        matches!(
            simple_name(t, src),
            b"Exception"
                | b"SystemException"
                | b"ApplicationException"
                | b"IndexOutOfRangeException"
                | b"NullReferenceException"
                | b"OutOfMemoryException"
                | b"ExecutionEngineException"
        )
    })
}

fn is_bare_obsolete(node: Node, src: &[u8]) -> bool {
    let named_obsolete = node
        .child_by_field_name("name")
        .is_some_and(|n| matches!(simple_name(n, src), b"Obsolete" | b"ObsoleteAttribute"));
    let mut cursor = node.walk();
    let has_arguments = node
        .named_children(&mut cursor)
        .any(|c| c.kind() == "attribute_argument_list" && c.named_child_count() > 0);
    named_obsolete && !has_arguments
}

/// A conditional directly inside this one. Looking down rather than up
/// keeps long chains linear.
fn nested_conditional<'t>(node: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    ["condition", "consequence", "alternative"]
        .into_iter()
        .filter_map(|f| node.child_by_field_name(f).map(unparenthesized))
        .find(|n| n.kind() == "conditional_expression")
}

fn negates_comparison(node: Node, src: &[u8]) -> bool {
    if unary_operator(node, src).map(|(_, op)| op) != Some(b"!") {
        return false;
    }
    operand(node).map(unparenthesized).is_some_and(|inner| {
        inner.kind() == "binary_expression"
            && matches!(
                operator_text(inner, src),
                b"==" | b"!=" | b"<" | b"<=" | b">" | b">="
            )
    })
}

fn has_redundant_boolean_literal(node: Node, src: &[u8]) -> bool {
    let is_bool =
        |n: Option<Node>| n.is_some_and(|n| unparenthesized(n).kind() == "boolean_literal");
    match node.kind() {
        "conditional_expression" => {
            is_bool(node.child_by_field_name("consequence"))
                && is_bool(node.child_by_field_name("alternative"))
        }
        "binary_expression" => {
            matches!(operator_text(node, src), b"&&" | b"||")
                && (is_bool(node.child_by_field_name("left"))
                    || is_bool(node.child_by_field_name("right")))
                // tree-sitter-c-sharp reads `x is true || y` as `x is (true || y)`.
                // parent() costs the node's depth: test it last.
                && !node.parent().is_some_and(|p| p.kind() == "constant_pattern")
        }
        _ => unary_operator(node, src).is_some_and(|(_, op)| op == b"!"),
    }
}

fn compares_count_call_with_zero(node: Node, src: &[u8]) -> bool {
    let empty_count_call = |n: Node| {
        is_call_named(n, src, &["Count"])
            && n.child_by_field_name("arguments")
                .is_some_and(|a| a.named_child_count() == 0)
    };
    normalized_comparison(node, src, |n| is_zero(n, src))
        .is_some_and(|(call, op, _)| matches!(op, "==" | "!=" | ">") && empty_count_call(call))
        || normalized_comparison(node, src, |n| is_one(n, src))
            .is_some_and(|(call, op, _)| matches!(op, ">=" | "<") && empty_count_call(call))
}

fn is_visible_mutable_static_field(node: Node, src: &[u8]) -> bool {
    cs_has_modifier(node, "static", src)
        && ["public", "protected", "internal"]
            .iter()
            .any(|m| cs_has_modifier(node, m, src))
        && !["readonly", "const"]
            .iter()
            .any(|m| cs_has_modifier(node, m, src))
        && !cs_has_modifier(node, "private", src)
}

fn is_default_base_type(node: Node, src: &[u8]) -> bool {
    let in_enum = node
        .parent()
        .and_then(|b| b.parent())
        .is_some_and(|d| d.kind() == "enum_declaration");
    let t = text(node, src);
    if in_enum {
        matches!(t, b"int" | b"Int32" | b"System.Int32")
    } else {
        matches!(t, b"object" | b"Object" | b"System.Object")
    }
}

fn is_redundant_jump(node: Node, _: &[u8]) -> bool {
    // A bare `return;`. `this` is an unnamed token, so count every child.
    if node.kind() == "return_statement" && node.child_count() > 2 {
        return false;
    }
    // The last statement of its block.
    let mut next = node.next_named_sibling();
    while let Some(n) = next {
        if n.kind() != "comment" {
            return false;
        }
        next = n.next_named_sibling();
    }
    let Some(block) = node.parent().filter(|p| p.kind() == "block") else {
        return false;
    };
    let Some(owner) = block.parent() else {
        return false;
    };
    if node.kind() == "continue_statement" {
        return matches!(
            owner.kind(),
            "for_statement" | "foreach_statement" | "while_statement"
        );
    }
    matches!(
        owner.kind(),
        "method_declaration"
            | "local_function_statement"
            | "constructor_declaration"
            | "destructor_declaration"
            | "accessor_declaration"
    )
}

fn class_members(class: Node) -> Vec<Node> {
    class
        .child_by_field_name("body")
        .map(cs_statements)
        .unwrap_or_default()
}

fn protected_member_of_sealed_class<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !cs_has_modifier(class, "sealed", src) {
        return None;
    }
    class_members(class)
        .into_iter()
        .find(|m| cs_has_modifier(*m, "protected", src) && !cs_has_modifier(*m, "override", src))
}

fn public_constructor_of_abstract_class<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !cs_has_modifier(class, "abstract", src) {
        return None;
    }
    class_members(class)
        .into_iter()
        .find(|m| m.kind() == "constructor_declaration" && cs_has_modifier(*m, "public", src))
}

fn is_redundant_constructor(node: Node, src: &[u8]) -> bool {
    let empty = |field: &str| {
        node.child_by_field_name(field)
            .is_some_and(|n| n.named_child_count() == 0)
    };
    if !empty("body") {
        return false;
    }
    if node.kind() == "destructor_declaration" {
        return true;
    }
    let mut cursor = node.walk();
    let has_initializer = node
        .named_children(&mut cursor)
        .any(|c| c.kind() == "constructor_initializer");
    // An attribute such as [JsonConstructor] gives it a purpose.
    let has_attribute = {
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .any(|c| c.kind() == "attribute_list")
    };
    if has_initializer
        || has_attribute
        || !empty("parameters")
        || !cs_has_modifier(node, "public", src)
    {
        return false;
    }
    // Only in a class (a struct's parameterless constructor has meaning)
    // without a primary constructor, and when it's the only instance one.
    let Some(class) = node
        .parent()
        .and_then(|b| b.parent())
        .filter(|c| c.kind() == "class_declaration")
    else {
        return false;
    };
    let mut cursor = class.walk();
    if class
        .named_children(&mut cursor)
        .any(|c| c.kind() == "parameter_list")
    {
        return false;
    }
    class_members(class)
        .into_iter()
        .filter(|m| m.kind() == "constructor_declaration" && !cs_has_modifier(*m, "static", src))
        .count()
        == 1
}

fn mergeable_inner_if<'t>(node: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    if node.child_by_field_name("alternative").is_some() {
        return None;
    }
    let consequence = node.child_by_field_name("consequence")?;
    let inner = if consequence.kind() == "block" {
        // A comment in the outer block is a reason to keep them apart.
        (consequence.named_child_count() == 1)
            .then(|| consequence.named_child(0))
            .flatten()?
    } else {
        consequence
    };
    if inner.kind() != "if_statement" || inner.child_by_field_name("alternative").is_some() {
        return None;
    }
    // Not an else-if. parent() costs the node's depth: test it last.
    let is_else_if = node.parent().is_some_and(|p| {
        p.kind() == "if_statement" && p.child_by_field_name("alternative") == Some(node)
    });
    (!is_else_if).then_some(inner)
}

fn where_then_bare_call(node: Node, _: &[u8]) -> bool {
    let arguments = |call: Node| {
        call.child_by_field_name("arguments")
            .map_or(0, |a| a.named_child_count())
    };
    let inner = node
        .child_by_field_name("function")
        .and_then(|f| f.child_by_field_name("expression"));
    arguments(node) == 0 && inner.is_some_and(|w| arguments(w) == 1)
}

fn compares_with_empty_string(node: Node, src: &[u8]) -> bool {
    let is_empty_string = |n: Node| {
        text(n, src) == b"\"\""
            || (n.kind() == "member_access_expression"
                && matches!(text(n, src), b"string.Empty" | b"String.Empty"))
    };
    if !matches!(operator_text(node, src), b"==" | b"!=") {
        return false;
    }
    let (Some(l), Some(r)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return false;
    };
    is_empty_string(l) != is_empty_string(r)
}

#[cfg(test)]
pub(super) mod tests {
    use crate::analysis::analyze;
    use crate::analysis::tests::far_deadline;
    use crate::config::Config;
    use crate::lang::Lang;
    use crate::rules::RuleSet;

    pub(crate) fn flagged(rule: &str, src: &str) -> Vec<usize> {
        let mut cfg = Config::default();
        // Rules that are off by default still have to work when enabled.
        cfg.rules.enabled = vec![rule.to_string()];
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let file = analyze("t.cs", Lang::CSharp, src, &rules, &cfg, far_deadline()).unwrap();
        file.issues
            .iter()
            .filter(|i| i.rule == rule)
            .map(|i| i.line)
            .collect()
    }

    fn method(body: &str) -> String {
        format!("class A {{\nvoid F() {{\n{body}\n}}\n}}\n")
    }

    #[test]
    fn large_and_deep_code_stays_fast() {
        let n = 20_000;
        let diff: String = (0..n).map(|i| format!("a{i} - ")).collect();
        // Every level is an issue, and building issues isn't what this test is
        // about: fewer levels, one per line. Each issue fingerprints its whole
        // line, so thousands of them on one huge line are slow on their own.
        let ternary: String = (0..5_000).map(|i| format!("x == {i} ? {i} :\n")).collect();
        let assign: String = (0..n).map(|i| format!("a{i} = ")).collect();
        let nots = "!".repeat(n);
        let cases: String = (0..5_000)
            .map(|i| format!("case {i}: F(); break; "))
            .collect();
        let chain: String = (0..2_000)
            .map(|i| format!("if (x == {i}) {{ F(); }} else "))
            .collect();
        // Each level is a mergeable-if issue: one per line, like the ternary.
        let nested = format!("{}return;{}", "if (a) {\n".repeat(2_000), "}".repeat(2_000));
        let src = format!(
            "class A {{ void F() {{ y = {diff}0; y = {ternary}0; {assign}0; b = {nots}c; switch (x) {{ {cases} }} {chain}{{ F(); }} {nested} }} }}\n"
        );
        let cfg = Config::default();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        // As for the JavaScript test in js.rs: this guards against quadratic
        // blowups, so debug builds get more time.
        let limit = if cfg!(debug_assertions) { 30 } else { 10 };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(limit);
        let file =
            analyze("t.cs", Lang::CSharp, &src, &rules, &cfg, deadline).expect("finishes in time");
        assert!(file.issues.iter().any(|i| i.rule == "cs/nested-ternary"));
    }

    #[test]
    fn assignments() {
        let src = method(
            "x = x;\nthis.x = this.x;\nx = y;\nvar p = new P { Name = Name };\ni = i++;\ni = j++;\nx =+ 1;\nx = +1;\nx += 1;\nx=-1;\nb =! c;\nb = !c;",
        );
        assert_eq!(flagged("cs/self-assignment", &src), [3, 4]);
        assert_eq!(flagged("cs/lost-increment", &src), [7]);
        assert_eq!(flagged("cs/reversed-operator", &src), [9, 13]);
    }

    #[test]
    fn unary_and_identical_operands() {
        let src = method(
            "a = !!b;\na = !!!b;\na = ~~b;\na = !b;\nc = a == a;\nc = a - a;\nc = a + a;\nc = F() == F();\nc = a.B == a.B;\nc = a == b;",
        );
        assert_eq!(flagged("cs/double-unary", &src), [3, 4, 5]);
        assert_eq!(flagged("cs/identical-operands", &src), [7, 8, 11]);
    }

    #[test]
    fn for_loop_direction() {
        let src = method(
            "for (int i = 0; i < n; i--) { }\nfor (int i = n; i > 0; i++) { }\nfor (int i = 0; n > i; i -= 1) { }\nfor (int i = 0; i < n; i++) { }\nfor (int i = n; i >= 0; --i) { }\nfor (int i = 0; i < n; j--) { }",
        );
        assert_eq!(flagged("cs/for-loop-wrong-direction", &src), [3, 4, 5]);
    }

    #[test]
    fn sizes_and_counts() {
        let src = method(
            "b = a.Length >= 0;\nb = list.Count < 0;\nb = 0 <= xs.Count();\nb = a.Length > 0;\nb = xs.Count() == 0;\nb = xs.Count() >= 1;\nb = xs.Count(p) > 0;\nb = xs.Count > 0;",
        );
        assert_eq!(flagged("cs/collection-size-sign", &src), [3, 4, 5]);
        assert_eq!(flagged("cs/count-instead-of-any", &src), [7, 8]);
    }

    #[test]
    fn async_void() {
        let src = "class A {\nasync void A1() { }\nasync Task A2() { }\nasync void Click(object s, RoutedEventArgs e) { }\npublic override async void A3() { }\nvoid A4() { async void Local() { } }\n}";
        assert_eq!(flagged("cs/async-void", src), [2, 6]);
    }

    #[test]
    fn accessors() {
        let src = "class A {\nint X { get => x; set { x = 1; } }\nint Y { get; set; }\nint Z { set { } }\nint W { set => throw new NotSupportedException(); }\nint V { init => x = value; }\nevent EventHandler E { add { } remove { h -= value; } }\nevent EventHandler E2 { add { Log(); } remove { } }\n}";
        assert_eq!(flagged("cs/accessor-ignores-value", src), [2, 8]);
    }

    #[test]
    fn finalizers_and_to_string() {
        let src = "class A {\n~A() {\nif (x) throw new E();\nAction a = () => throw new E();\n}\npublic override string ToString() => null;\npublic string ToString(int x) { return null; }\npublic override string ToString() {\nFunc<string> f = () => null;\nreturn null;\n}\npublic override string? ToString() => null;\n}";
        assert_eq!(flagged("cs/destructor-throws", src), [3]);
        assert_eq!(flagged("cs/to-string-returns-null", src), [6, 10]);
    }

    #[test]
    fn if_chains() {
        let src = method(
            "if (a) { F(); } else { F(); }\nif (a) { F(); } else if (b) { F(); }\nif (a) { F(); } else if (b) { F(); } else { F(); }\nx = a ? 1 : 1;\nif (a == 1) { } else if (b) { } else if (a == 1) { }\nif (a) { G(); } else { F(); }",
        );
        assert_eq!(flagged("cs/identical-branches", &src), [3, 5, 6]);
        assert_eq!(flagged("cs/duplicate-condition", &src), [7]);
    }

    #[test]
    fn events() {
        let src =
            method("e -= (s, a) => G();\ne -= delegate { G(); };\ne += (s, a) => G();\ne -= OnE;");
        assert_eq!(flagged("cs/anonymous-unsubscribe", &src), [3, 4]);
    }

    #[test]
    fn empty_blocks_and_methods() {
        let src = "class A {\nvoid M() { }\nvirtual void N() { }\nvoid O() {\nif (a) { }\nwhile (b) { /* wait */ }\ntry { G(); } finally { }\nusing (Push()) { }\nlock (o) { }\n}\npartial void P();\noverride void Q() { }\n}";
        assert_eq!(flagged("cs/empty-block", src), [5, 7]);
        assert_eq!(flagged("cs/empty-method", src), [2]);
    }

    #[test]
    fn catches_and_throws() {
        let src = method(
            "try { G(); } catch (IOException e) { throw e; }\ntry { G(); } catch (IOException e) { throw; }\ntry { G(); } catch (IOException) { throw; } catch (Exception e) { Log(e); }\ntry { G(); } catch (IOException e) when (e.HResult == 1) { throw; }\nthrow new Exception();\nthrow new System.ApplicationException(\"x\");\nx = y ?? throw new NullReferenceException();\nthrow new ArgumentException();",
        );
        assert_eq!(flagged("cs/rethrow-loses-stack", &src), [3]);
        assert_eq!(flagged("cs/useless-catch", &src), [4]);
        assert_eq!(flagged("cs/general-exception", &src), [7, 8, 9]);
    }

    #[test]
    fn attributes_and_declarations() {
        let src = "[Obsolete]\nclass A : object {\n[System.Obsolete()] void F() { G(); }\n[Obsolete(\"Use G.\")] void H() { G(); }\npublic static int A1;\ninternal static int A2 = 1;\npublic static readonly int A3;\nprivate static int A4;\npublic const int A5 = 1;\nstatic int A6;\n}\nenum ColorEnum : int { }\nenum Flags : byte { }\nclass B : Object, I { }";
        assert_eq!(flagged("cs/obsolete-without-explanation", src), [1, 3]);
        assert_eq!(flagged("cs/visible-mutable-static-field", src), [5, 6]);
        assert_eq!(flagged("cs/redundant-base-type", src), [2, 12, 14]);
        assert_eq!(flagged("cs/enum-name-suffix", src), [12]);
    }

    #[test]
    fn expressions() {
        let src = method(
            "x = a ? 1 : b ? 2 : 3;\nx = a ? (b ? 1 : 2) : 3;\nx = a ? 1 : 2;\nc = !(a == b);\nc = !(a && b);\nc = !a;\nc = a ? true : false;\nc = a && true;\nc = !false;\nc = a == true;\nc = a ? true : b;\nc = u is true || !d;",
        );
        assert_eq!(flagged("cs/nested-ternary", &src), [3, 4]);
        assert_eq!(flagged("cs/inverted-comparison", &src), [6]);
        assert_eq!(flagged("cs/redundant-boolean-literal", &src), [9, 10, 11]);
    }

    #[test]
    fn linq_and_gc() {
        let src = method(
            "x = xs.Where(p).First();\nx = xs.Where(p).ToList();\nx = xs.Where(p).Any(q);\nGC.Collect();\nGC.KeepAlive(o);",
        );
        assert_eq!(flagged("cs/where-then-predicate-method", &src), [3]);
        assert_eq!(flagged("cs/gc-collect", &src), [6]);
    }

    #[test]
    fn statements_and_jumps() {
        let src = "class A {\nvoid F() {\nG();;\nwhile (Next()) ;\nforeach (var x in xs) { G(); continue; }\nfor (;;) { if (a) { continue; } G(); }\nreturn;\n}\nint H() { return 1; }\nvoid I() { if (a) { return; } G(); }\nA J() { G(); return this; }\n}";
        assert_eq!(flagged("cs/empty-statement", src), [3]);
        assert_eq!(flagged("cs/redundant-jump", src), [5, 7]);
    }

    #[test]
    fn class_shapes() {
        let src = "sealed class A {\nprotected int a;\nprotected override void F() { }\n}\nabstract class B {\npublic B() { G(); }\nprotected B(int x) { G(); }\n}\nclass C { public C() { } }\nclass D { public D() { } public D(int x) { G(); } }\nstruct E { public E() { } }\nclass F { public F() : base() { } }\nclass G { ~G() { } }\nclass H(int x) { public H() : this(1) { } }\nclass I { [JsonConstructor] public I() { } }";
        assert_eq!(flagged("cs/protected-in-sealed", src), [2]);
        assert_eq!(flagged("cs/abstract-class-public-constructor", src), [6]);
        assert_eq!(flagged("cs/redundant-constructor", src), [9, 13]);
    }

    #[test]
    fn nested_ifs_and_empty_strings() {
        let src = method(
            "if (a) { if (b) { G(); } }\nif (a) if (b) G();\nif (a) { if (b) { G(); } else { H(); } }\nif (a) { // why\n if (b) { G(); } }\nif (a) { G(); } else if (b) { if (c) { H(); } }\nc = s == \"\";\nc = \"\" != s;\nc = s == string.Empty;\nc = s == \"x\";",
        );
        assert_eq!(flagged("cs/mergeable-if", &src), [3, 4]);
        assert_eq!(flagged("cs/empty-string-comparison", &src), [9, 10, 11]);
    }
}
