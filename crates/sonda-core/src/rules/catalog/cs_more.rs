//! C# rules, batch 4 (ADR-0007, ADR-0015): tests, logging, equality,
//! locking, unused and duplicated code. Queries stay cheap on deep trees:
//! see the notes in `js_modern.rs`.

use super::cs::{
    CS_SCOPE_STOPS, cs_has_modifier, cs_statements, cs_string_value, operand, simple_name,
    unparenthesized,
};
use super::cs_bugs::{attribute_names, cs_call_arguments, find_attribute};
use super::java_bugs::{find_in_scope, operator_text};
use super::java_more::is_routable_ipv4;
use super::java_security::text;
use super::java_smells::count_word;
use super::*;

/// Rules that are off unless `rules.enabled` lists them (see
/// `catalog::OFF_BY_DEFAULT`).
pub(super) static OFF_BY_DEFAULT: &[&str] = &[];

pub(super) static RULES: &[Rule] = &[
    // ---- Bugs ----
    Rule {
        id: "cs/float-equality",
        name: "Floating-point values should not be compared for exact equality",
        description: "Most decimal fractions have no exact binary representation, so `x == 0.1` can be false \
                      for a value that prints as 0.1.",
        message: "Compare with a tolerance, such as Math.Abs(x - 0.1) < 1e-9.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[related("S1244")],
        check: Check::Query {
            langs: CSHARP,
            query: "(binary_expression right: (_)) @match",
            filter: Some(Keep(compares_fraction_exactly)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { bool F(double x) { return x == 0.1; } }",
            good: "class A { bool F(double x) { return Math.Abs(x - 0.1) < 1e-9 || x == 0.0; } }",
        }),
    },
    Rule {
        id: "cs/hashcode-mutable-field",
        name: "GetHashCode should not use mutable fields",
        description: "If a field the hash depends on changes while the object is in a dictionary or set, the \
                      object can't be found there any more.",
        message: "Base GetHashCode on readonly fields only.",
        category: Bug,
        severity: Minor,
        effort_minutes: 15,
        sonar: &[exact("S2328")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(class_declaration body: (declaration_list)) (struct_declaration body: (declaration_list))] @match",
            filter: Some(Find(hash_reads_mutable_field)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class P { int id; public override int GetHashCode() => id; public override bool Equals(object o) => o is P p && p.id == id; }",
            good: "class P { readonly int id; public override int GetHashCode() => id; public override bool Equals(object o) => o is P p && p.id == id; }",
        }),
    },
    Rule {
        id: "cs/lock-on-mutable-field",
        name: "Locks should be taken on readonly fields",
        description: "Locking a field that can be reassigned, or a new object, lets two threads hold \"the\" lock \
                      at the same time, each on a different object.",
        message: "Lock on a private readonly field instead.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2445")],
        check: Check::Query {
            langs: CSHARP,
            query: "(lock_statement) @match",
            filter: Some(Find(lock_on_mutable)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { object sync = new object(); void F() { lock (sync) { G(); } } }",
            good: "class A { readonly object sync = new object(); void F() { lock (sync) { G(); } } }",
        }),
    },
    Rule {
        id: "cs/assert-side-effects",
        name: "Debug.Assert should not have side effects",
        description: "Debug.Assert calls are removed from release builds, and their side effects with them, so \
                      the program behaves differently in release.",
        message: "Move this side effect out of the assertion.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3346")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(invocation_expression
                        function: (member_access_expression expression: (_) @t name: (identifier) @n)
                        (#match? @t "(^|\\.)Debug$") (#eq? @n "Assert")) @match"#,
            filter: Some(Find(assertion_side_effect)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(List<int> xs) { Debug.Assert(xs.Remove(1)); } }",
            good: "class A { void F(List<int> xs) { bool removed = xs.Remove(1); Debug.Assert(removed); } }",
        }),
    },
    Rule {
        id: "cs/public-readonly-mutable",
        name: "Visible readonly fields should not hold mutable collections",
        description: "`readonly` only stops the field being reassigned; callers can still change the array or \
                      list it holds.",
        message: "Expose a read-only view (IReadOnlyList<T>, ImmutableArray<T>) instead.",
        category: Bug,
        severity: Minor,
        effort_minutes: 10,
        sonar: &[exact("S3887")],
        check: Check::Query {
            langs: CSHARP,
            query: "(field_declaration (modifier)) @match",
            filter: Some(Find(visible_readonly_collection)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { public readonly List<string> Names = new List<string>(); }",
            good: "class A { public IReadOnlyList<string> Names { get; } = new List<string>(); }",
        }),
    },
    Rule {
        id: "cs/log-template-duplicate-placeholder",
        name: "Log message templates should not repeat placeholder names",
        description: "Placeholders are matched to arguments by position, but structured logging stores them by \
                      name; a repeated name keeps only one of the values.",
        message: "Give each placeholder in this template a distinct name.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6677")],
        check: Check::Query {
            langs: CSHARP,
            query: "(invocation_expression function: (member_access_expression name: (identifier)) arguments: (argument_list)) @match",
            filter: Some(Find(template_repeats_placeholder)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(ILogger log, int a, int b) { log.LogInformation(\"Moved {Id} to {Id}\", a, b); } }",
            good: "class A { void F(ILogger log, int a, int b) { log.LogInformation(\"Moved {From} to {To}\", a, b); } }",
        }),
    },
    Rule {
        id: "cs/log-template-syntax",
        name: "Log message templates should be well formed",
        description: "An unbalanced brace or an empty placeholder makes the logger misread the template, so the \
                      message or its values are lost.",
        message: "Fix this message template: a brace isn't balanced or a placeholder is empty.",
        category: Bug,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S6674")],
        check: Check::Query {
            langs: CSHARP,
            query: "(invocation_expression function: (member_access_expression name: (identifier)) arguments: (argument_list)) @match",
            filter: Some(Find(malformed_template)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(ILogger log, int id) { log.LogInformation(\"Saved {Id\", id); } }",
            good: "class A { void F(ILogger log, int id) { log.LogInformation(\"Saved {Id}\", id); } }",
        }),
    },
    // ---- Vulnerabilities ----
    Rule {
        id: "cs/world-permissions",
        name: "Files should not be readable or writable by everyone",
        description: "Permissions for \"other\" users or for Everyone let any account on the machine read or \
                      change the file.",
        message: "Grant these permissions only to the users and groups that need them.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S2612")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(member_access_expression name: (identifier)) (object_creation_expression arguments: (argument_list))] @match",
            filter: Some(Keep(grants_everyone)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(string p) { File.SetUnixFileMode(p, UnixFileMode.UserRead | UnixFileMode.OtherWrite); } }",
            good: "class A { void F(string p) { File.SetUnixFileMode(p, UnixFileMode.UserRead | UnixFileMode.UserWrite); } }",
        }),
    },
    // ---- Code smells ----
    Rule {
        id: "cs/hardcoded-ip",
        name: "IP addresses should not be hard-coded",
        description: "A literal address breaks when the network changes and can't be overridden per environment.",
        message: "Move this address to configuration.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S1313")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"((string_literal) @match (#match? @match "^\"[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+\"$"))"#,
            filter: Some(Keep(is_hardcoded_ip)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { string Host() => \"203.0.113.7\"; }",
            good: "class A { string Host(IConfiguration c) => c[\"Host\"]; string Local() => \"127.0.0.1\"; }",
        }),
    },
    Rule {
        id: "cs/duplicated-string",
        name: "String literals should not be duplicated",
        description: "A literal repeated across a file is easy to change in one place and miss in the others.",
        message: "Define a constant for this string, which appears three times or more.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 10,
        sonar: &[exact("S1192")],
        check: Check::Query {
            langs: CSHARP,
            query: "(compilation_unit) @match",
            filter: Some(Find(string_repeated_often)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { string a = \"connection failed\"; string b = \"connection failed\"; string c = \"connection failed\"; }",
            good: "class A { const string Failed = \"connection failed\"; string a = Failed; string b = Failed; }",
        }),
    },
    Rule {
        id: "cs/unused-local-variable",
        name: "Unused local variables should be removed",
        description: "A variable nothing reads is dead code.",
        message: "Remove this unused local variable.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S1481")],
        check: Check::Query {
            langs: CSHARP,
            query: "(local_declaration_statement (variable_declaration (variable_declarator name: (identifier) @match)))",
            filter: Some(Keep(local_is_never_used)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F() { int unused = 3; G(); } }",
            good: "class A { int F() { int used = 3; using var lease = Acquire(); return used; } }",
        }),
    },
    Rule {
        id: "cs/local-shadows-field",
        name: "Local variables should not shadow fields or properties",
        description: "A local with a member's name hides it: code meant for the member silently uses the local.",
        message: "Rename this local variable, which hides a member of the same name.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1117")],
        check: Check::Query {
            langs: CSHARP,
            query: "(local_declaration_statement (variable_declaration (variable_declarator name: (identifier) @match)))",
            filter: Some(Keep(shadows_member)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int count; void F() { int count = 0; G(count); } }",
            good: "class A { int count; void F() { int total = 0; G(total); } }",
        }),
    },
    Rule {
        id: "cs/unused-private-member",
        name: "Unused private members should be removed",
        description: "A private method, field or property that nothing in its class uses is dead code.",
        message: "Remove this unused private member.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1144")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration name: (identifier) body: (declaration_list)) @match",
            filter: Some(Find(unused_private_member)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { private int Helper() => 1; public int F() => 2; }",
            good: "class A { private int Helper() => 1; public int F() => Helper() + 1; }",
        }),
    },
    Rule {
        id: "cs/log-and-rethrow",
        name: "Exceptions should be either logged or rethrown, not both",
        description: "Logging an exception and then rethrowing it logs it again wherever it's finally handled, \
                      so one failure shows up several times.",
        message: "Either log this exception and handle it, or rethrow it without logging.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S2139")],
        check: Check::Query {
            langs: CSHARP,
            query: "(catch_clause (catch_declaration name: (identifier)) body: (block)) @match",
            filter: Some(Keep(logs_and_rethrows)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(ILogger log) { try { G(); } catch (IOException e) { log.LogError(e, \"Failed\"); throw; } } }",
            good: "class A { void F(ILogger log) { try { G(); } catch (IOException e) { log.LogError(e, \"Failed\"); Retry(); } } }",
        }),
    },
    Rule {
        id: "cs/non-short-circuit-logic",
        name: "Boolean conditions should use && and ||",
        description: "`&` and `|` evaluate both sides even when the result is already known, so a guard such as \
                      `x != null & x.Ok` still throws.",
        message: "Use '&&' or '||' instead.",
        category: CodeSmell,
        severity: Blocker,
        effort_minutes: 2,
        sonar: &[related("S2178")],
        check: Check::Query {
            langs: CSHARP,
            query: "(binary_expression) @match",
            filter: Some(Keep(non_short_circuit_on_bools)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { bool F(B b) { return b != null & b.Ok; } }",
            good: "class A { bool F(B b) { return b != null && b.Ok; } }",
        }),
    },
    Rule {
        id: "cs/test-class-without-tests",
        name: "Test classes should contain tests",
        description: "A class marked [TestClass] or [TestFixture] without a test method runs nothing; tests were \
                      removed or mis-attributed.",
        message: "Add test methods to this class, or remove the test attribute.",
        category: CodeSmell,
        severity: Blocker,
        effort_minutes: 5,
        sonar: &[exact("S2187")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration (attribute_list) name: (identifier) body: (declaration_list)) @match",
            filter: Some(Find(test_class_without_tests)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "[TestClass] public class CartTests { public void Totals() { } }",
            good: "[TestClass] public class CartTests { [TestMethod] public void Totals() { } }",
        }),
    },
    Rule {
        id: "cs/type-check-simplify",
        name: "Runtime type checks should use is",
        description: "`typeof(T).IsInstanceOfType(x)` and `x as T != null` are longer ways to write `x is T`.",
        message: "Use 'x is T' instead.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S2219")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(invocation_expression function: (member_access_expression expression: (typeof_expression))) \
                     (binary_expression)] @match",
            filter: Some(Keep(roundabout_type_check)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { bool F(object o) { return typeof(string).IsInstanceOfType(o); } }",
            good: "class A { bool F(object o) { return o is string; } }",
        }),
    },
    Rule {
        id: "cs/public-static-mutable-collection",
        name: "Visible static readonly fields should not hold mutable collections",
        description: "`static readonly` only stops the field being reassigned; any code can still change the \
                      shared array or list, for every caller at once.",
        message: "Expose a read-only collection (IReadOnlyList<T>, ImmutableArray<T>) instead.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 15,
        sonar: &[exact("S2386")],
        check: Check::Query {
            langs: CSHARP,
            query: "(field_declaration (modifier)) @match",
            filter: Some(Find(visible_static_collection)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { public static readonly string[] Codes = { \"a\", \"b\" }; }",
            good: "class A { public static readonly IReadOnlyList<string> Codes = new[] { \"a\", \"b\" }; }",
        }),
    },
    Rule {
        id: "cs/control-char-in-string",
        name: "Control characters in string literals should be escaped",
        description: "A raw tab or other control character in a literal is invisible in the source, and editors \
                      may change it without anyone noticing.",
        message: "Write this control character as an escape sequence, such as \\t.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 2,
        sonar: &[exact("S2479")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(string_literal) (verbatim_string_literal) (character_literal)] @match",
            filter: Some(Keep(has_raw_control_char)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { const string Sep = \"a\tb\"; }",
            good: "class A { const string Sep = \"a\\tb\"; }",
        }),
    },
    Rule {
        id: "cs/generic-exception-ignored",
        name: "General exceptions should not be ignored",
        description: "An empty `catch` for every exception hides all failures, including bugs and out-of-memory \
                      conditions.",
        message: "Catch a specific exception, or handle and log this one.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 15,
        sonar: &[exact("S2486")],
        check: Check::Query {
            langs: CSHARP,
            query: "(catch_clause body: (block)) @match",
            filter: Some(Keep(ignores_everything)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F() { try { G(); } catch (Exception) { } } }",
            good: "class A { void F() { try { G(); } catch (IOException) { /* the file is optional */ } } }",
        }),
    },
    Rule {
        id: "cs/assertion-boolean-literal",
        name: "Assertions should not compare with boolean literals",
        description: "`Assert.AreEqual(true, x)` is `Assert.IsTrue(x)` written the long way, with a less useful \
                      failure message.",
        message: "Use IsTrue/IsFalse (or True/False) instead of comparing with a boolean literal.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 2,
        sonar: &[exact("S2701")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(invocation_expression
                        function: (member_access_expression expression: (_) @t name: (identifier) @n)
                        (#match? @t "(^|\\.)Assert$")
                        (#any-of? @n "AreEqual" "AreNotEqual" "Equal" "NotEqual" "IsTrue" "IsFalse" "True" "False")) @match"#,
            filter: Some(Keep(asserts_boolean_literal)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class T { void F(bool ok) { Assert.AreEqual(true, ok); } }",
            good: "class T { void F(bool ok) { Assert.IsTrue(ok); } }",
        }),
    },
    Rule {
        id: "cs/static-field-in-generic",
        name: "Generic classes should not have static fields that don't use their type parameters",
        description: "Each constructed type (`Cache<int>`, `Cache<string>`) gets its own copy of the static \
                      field, which is rarely what a field unrelated to T is meant to do.",
        message: "Move this static field to a non-generic class, or make it depend on the type parameter.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S2743")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration (type_parameter_list) body: (declaration_list)) @match",
            filter: Some(Find(static_field_ignoring_type_parameters)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class Cache<T> { static int hits; T Get() => default; }",
            good: "class Cache<T> { static T last; T Get() => last; }",
        }),
    },
    Rule {
        id: "cs/thread-sleep-in-test",
        name: "Tests should not use Thread.Sleep",
        description: "Sleeping makes tests slow and flaky: too short fails on a busy machine, too long wastes \
                      every run. Wait for the condition itself instead.",
        message: "Wait for the expected condition instead of sleeping.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S2925")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(method_declaration (attribute_list) body: (_)) @match"#,
            filter: Some(Find(sleep_in_test)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class T { [Fact] public void Waits() { Start(); Thread.Sleep(500); Check(); } }",
            good: "class T { [Fact] public async Task Waits() { Start(); await done.Task; Check(); } }",
        }),
    },
    Rule {
        id: "cs/dispose-without-idisposable",
        name: "Dispose methods should implement IDisposable",
        description: "A `Dispose()` method on a type that doesn't implement IDisposable is never called by \
                      `using` or by containers, so its cleanup doesn't happen.",
        message: "Implement IDisposable, or rename this method.",
        category: CodeSmell,
        severity: Blocker,
        effort_minutes: 5,
        sonar: &[exact("S2953")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(class_declaration name: (identifier) body: (declaration_list)) \
                     (struct_declaration name: (identifier) body: (declaration_list))] @match",
            filter: Some(Find(dispose_without_interface)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class Conn { public void Dispose() { Close(); } }",
            good: "class Conn : IDisposable { public void Dispose() { Close(); } }",
        }),
    },
    Rule {
        id: "cs/incomplete-assertion",
        name: "Assertions should be complete",
        description: "`x.Should()` on its own asserts nothing: the check that should follow it is missing.",
        message: "Complete this assertion, for example with .Be(...).",
        category: CodeSmell,
        severity: Blocker,
        effort_minutes: 2,
        sonar: &[exact("S2970")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(expression_statement (invocation_expression
                        function: (member_access_expression name: (identifier) @n)
                        arguments: (argument_list) @a
                        (#eq? @n "Should")) @match)"#,
            filter: Some(Keep(no_arguments)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class T { void F(int total) { total.Should(); } }",
            good: "class T { void F(int total) { total.Should().Be(3); } }",
        }),
    },
    Rule {
        id: "cs/assertion-argument-order",
        name: "Assertions should pass the expected value first",
        description: "Assert.AreEqual and Assert.Equal take the expected value first; swapped arguments give a \
                      failure message that says the opposite of what happened.",
        message: "Swap these arguments: the expected value comes first.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S3415")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(invocation_expression
                        function: (member_access_expression expression: (_) @t name: (identifier) @n)
                        (#match? @t "(^|\\.)Assert$")
                        (#any-of? @n "AreEqual" "AreNotEqual" "AreSame" "AreNotSame" "Equal" "NotEqual" "Same" "NotSame")) @match"#,
            filter: Some(Keep(expected_value_second)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class T { void F(int total) { Assert.AreEqual(total, 3); } }",
            good: "class T { void F(int total) { Assert.AreEqual(3, total); } }",
        }),
    },
    Rule {
        id: "cs/expected-exception-attribute",
        name: "[ExpectedException] should not be used",
        description: "The attribute passes when any line of the test throws, so it can pass for the wrong \
                      reason. Assert.ThrowsException points at the call that should throw.",
        message: "Use Assert.ThrowsException (or Assert.Throws) around the call that should throw.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3431")],
        check: Check::Query {
            langs: CSHARP,
            query: "(attribute name: (_)) @match",
            filter: Some(Keep(is_expected_exception)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class T { [TestMethod, ExpectedException(typeof(ArgumentException))] public void F() { Parse(\"\"); } }",
            good: "class T { [TestMethod] public void F() { Assert.ThrowsException<ArgumentException>(() => Parse(\"\")); } }",
        }),
    },
    Rule {
        id: "cs/test-method-signature",
        name: "Test methods should be public and not async void",
        description: "Test frameworks skip non-public test methods, and can't wait for an `async void` one, so \
                      its failures go unreported.",
        message: "Make this test method public, and return Task if it's async.",
        category: CodeSmell,
        severity: Blocker,
        effort_minutes: 2,
        sonar: &[exact("S3433")],
        check: Check::Query {
            langs: CSHARP,
            query: "(method_declaration (attribute_list) name: (identifier)) @match",
            filter: Some(Find(bad_test_signature)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class T { [TestMethod] async void Loads() { await Load(); } }",
            good: "class T { [TestMethod] public async Task Loads() { await Load(); } }",
        }),
    },
    Rule {
        id: "cs/type-of-type",
        name: "GetType() should not be called on a Type",
        description: "`typeof(X).GetType()` and `x.GetType().GetType()` return `System.RuntimeType`, not the \
                      type that was meant.",
        message: "Remove this GetType() call.",
        category: CodeSmell,
        severity: Blocker,
        effort_minutes: 2,
        sonar: &[exact("S3443")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(invocation_expression
                        function: (member_access_expression expression: (_) @r name: (identifier) @n)
                        arguments: (argument_list) @a
                        (#eq? @n "GetType")) @match"#,
            filter: Some(Keep(gets_type_of_type)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { Type F() { return typeof(A).GetType(); } }",
            good: "class A { Type F() { return typeof(A); } }",
        }),
    },
    Rule {
        id: "cs/optional-on-ref-out",
        name: "[Optional] should not be used on ref or out parameters",
        description: "A ref or out parameter must always be passed, so [Optional] can't make it optional.",
        message: "Remove [Optional] from this parameter.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 2,
        sonar: &[exact("S3447")],
        check: Check::Query {
            langs: CSHARP,
            query: "(parameter (attribute_list) (modifier)) @match",
            filter: Some(Keep(optional_ref_out)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F([Optional] ref int x) { x++; } }",
            good: "class A { void F(ref int x) { x++; } }",
        }),
    },
    Rule {
        id: "cs/default-parameter-value-without-optional",
        name: "[DefaultParameterValue] should be used with [Optional]",
        description: "Without [Optional], callers must still pass the argument, so the default value is never used.",
        message: "Add [Optional] to this parameter.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S3450")],
        check: Check::Query {
            langs: CSHARP,
            query: "(parameter (attribute_list)) @match",
            filter: Some(Keep(default_without_optional)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F([DefaultParameterValue(5)] int x) { G(x); } }",
            good: "class A { void F([Optional, DefaultParameterValue(5)] int x) { G(x); } }",
        }),
    },
    Rule {
        id: "cs/default-value-on-parameter",
        name: "[DefaultValue] should not be used on parameters",
        description: "System.ComponentModel's [DefaultValue] is for designers and serializers; on a parameter it \
                      has no effect. [DefaultParameterValue] or a C# default value was meant.",
        message: "Use a default value (or [DefaultParameterValue]) instead of [DefaultValue].",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 2,
        sonar: &[exact("S3451")],
        check: Check::Query {
            langs: CSHARP,
            query: "(parameter (attribute_list)) @match",
            filter: Some(Keep(has_default_value_attribute)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F([Optional, DefaultValue(5)] int x) { G(x); } }",
            good: "class A { void F(int x = 5) { G(x); } }",
        }),
    },
    Rule {
        id: "cs/service-contract-without-operations",
        name: "Service contracts should have operations",
        description: "A [ServiceContract] without any [OperationContract] member exposes nothing, and WCF \
                      rejects it when the host starts.",
        message: "Mark the operations of this contract with [OperationContract].",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3597")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(interface_declaration (attribute_list) name: (identifier)) \
                     (class_declaration (attribute_list) name: (identifier))] @match",
            filter: Some(Find(contract_without_operations)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "[ServiceContract] interface IOrders { int Count(); }",
            good: "[ServiceContract] interface IOrders { [OperationContract] int Count(); }",
        }),
    },
    Rule {
        id: "cs/equals-without-iequatable",
        name: "Types with Equals(T) should implement IEquatable<T>",
        description: "Collections and LINQ only use a typed Equals through IEquatable<T>; without it they fall \
                      back to Equals(object).",
        message: "Implement IEquatable<T> for this Equals method.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S3897")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(class_declaration name: (identifier) body: (declaration_list)) \
                     (struct_declaration name: (identifier) body: (declaration_list))] @match",
            filter: Some(Find(typed_equals_without_interface)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class P { int id; public bool Equals(P other) => other != null && other.id == id; }",
            good: "class P : IEquatable<P> { int id; public bool Equals(P other) => other != null && other.id == id; }",
        }),
    },
    Rule {
        id: "cs/iequatable-not-sealed",
        name: "Classes implementing IEquatable<T> should be sealed",
        description: "A subclass inherits Equals(T) without being able to compare its own fields through it, \
                      so equality silently ignores them.",
        message: "Seal this class.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S4035")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration name: (identifier) (base_list)) @match",
            filter: Some(Find(unsealed_equatable)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class P : IEquatable<P> { public bool Equals(P o) => true; }",
            good: "sealed class P : IEquatable<P> { public bool Equals(P o) => true; }",
        }),
    },
    Rule {
        id: "cs/starts-with-single-char",
        name: "StartsWith and EndsWith should take a char for one character",
        description: "The char overloads are faster and don't depend on the current culture, which the string \
                      overloads do.",
        message: "Pass a char ('x') instead of a one-character string.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S6610")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(invocation_expression
                        function: (member_access_expression name: (identifier) @n)
                        arguments: (argument_list . (argument (string_literal)) .)
                        (#any-of? @n "StartsWith" "EndsWith")) @match"#,
            filter: Some(Keep(single_char_argument)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { bool F(string s) { return s.StartsWith(\"/\"); } }",
            good: "class A { bool F(string s) { return s.StartsWith('/'); } }",
        }),
    },
    Rule {
        id: "cs/any-instead-of-contains",
        name: "Contains should be used to test for one value",
        description: "`xs.Any(x => x == y)` is `xs.Contains(y)` written the long way, and slower on sets.",
        message: "Use Contains(...) instead of Any with an equality lambda.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[related("S6617")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(invocation_expression
                        function: (member_access_expression name: (identifier) @n)
                        arguments: (argument_list (argument (lambda_expression)) .)
                        (#eq? @n "Any")) @match"#,
            filter: Some(Keep(any_with_equality)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { bool F(List<int> xs, int y) { return xs.Any(x => x == y); } }",
            good: "class A { bool F(List<int> xs, int y) { return xs.Contains(y); } }",
        }),
    },
    Rule {
        id: "cs/logger-category-mismatch",
        name: "ILogger<T> should be typed with its own class",
        description: "The type argument is the log category; `ILogger<OtherClass>` files this class's messages \
                      under another class's name.",
        message: "Use ILogger<T> with this class as T.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6672")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration name: (identifier) body: (declaration_list)) @match",
            filter: Some(Find(foreign_logger_category)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class Orders { public Orders(ILogger<Carts> log) { } }",
            good: "class Orders { public Orders(ILogger<Orders> log) { } }",
        }),
    },
    Rule {
        id: "cs/log-placeholder-pascal-case",
        name: "Log template placeholders should be PascalCase",
        description: "Structured logging stores each placeholder as a property; PascalCase names match the \
                      other properties and are easier to query.",
        message: "Name this template's placeholders in PascalCase.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6678")],
        check: Check::Query {
            langs: CSHARP,
            query: "(invocation_expression function: (member_access_expression name: (identifier)) arguments: (argument_list)) @match",
            filter: Some(Find(template_with_camel_placeholder)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(ILogger log, int id) { log.LogInformation(\"Saved {orderId}\", id); } }",
            good: "class A { void F(ILogger log, int id) { log.LogInformation(\"Saved {OrderId}\", id); } }",
        }),
    },
    Rule {
        id: "cs/ignored-test",
        name: "Ignored tests should say why",
        description: "A test switched off without a reason is easily forgotten; the reason tells the next reader \
                      when it can come back.",
        message: "Give a reason in [Ignore(\"...\")], or fix and re-enable this test.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1607")],
        check: Check::Query {
            langs: CSHARP,
            query: "(attribute name: (_)) @match",
            filter: Some(Keep(ignore_without_reason)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class T { [TestMethod, Ignore] public void Slow() { Run(); } }",
            good: "class T { [TestMethod, Ignore(\"Needs the staging database, see #42\")] public void Slow() { Run(); } }",
        }),
    },
    Rule {
        id: "cs/conditions-same-line",
        name: "An if should not start on the line where the previous one ends",
        description: "`} if (b) {` reads like an `else if` that lost its `else`; either it is one, or it belongs \
                      on its own line.",
        message: "Add 'else', or move this if statement to its own line.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 1,
        sonar: &[exact("S3972")],
        check: Check::Query {
            langs: CSHARP,
            query: "(block (if_statement) (if_statement)) @match",
            filter: Some(Find(if_after_if_same_line)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(bool a, bool b) {\n if (a) { G(); } if (b) { H(); }\n} }",
            good: "class A { void F(bool a, bool b) {\n if (a) { G(); }\n if (b) { H(); }\n} }",
        }),
    },
];

// ---------------------------------------------------- helpers

const TEST_ATTRIBUTES: &[&[u8]] = &[
    b"TestMethod",
    b"DataTestMethod",
    b"Test",
    b"TestCase",
    b"TestCaseSource",
    b"Theory",
    b"Fact",
];

pub(super) fn is_test_method(method: Node, src: &[u8]) -> bool {
    attribute_names(method, src)
        .iter()
        .any(|(_, n)| TEST_ATTRIBUTES.contains(n))
}

pub(super) fn members(declaration: Node) -> Vec<Node> {
    declaration
        .child_by_field_name("body")
        .map(cs_statements)
        .unwrap_or_default()
}

pub(super) fn declarators(field: Node) -> Vec<Node> {
    let mut cursor = field.walk();
    let Some(declaration) = field
        .named_children(&mut cursor)
        .find(|c| c.kind() == "variable_declaration")
    else {
        return Vec::new();
    };
    let mut inner = declaration.walk();
    declaration
        .named_children(&mut inner)
        .filter(|d| d.kind() == "variable_declarator")
        .collect()
}

/// The names of a type's fields that can change: not readonly or const.
fn mutable_fields<'s>(declaration: Node, src: &'s [u8], statics: bool) -> Vec<&'s [u8]> {
    members(declaration)
        .into_iter()
        .filter(|m| {
            m.kind() == "field_declaration"
                && !cs_has_modifier(*m, "readonly", src)
                && !cs_has_modifier(*m, "const", src)
                && cs_has_modifier(*m, "static", src) == statics
        })
        .flat_map(declarators)
        .filter_map(|d| d.child_by_field_name("name").map(|n| text(n, src)))
        .collect()
}

/// The class or struct around a node, a few dozen levels up at most.
pub(super) fn enclosing_type(node: Node) -> Option<Node> {
    let mut current = node.parent();
    for _ in 0..128 {
        let n = current?;
        if matches!(
            n.kind(),
            "class_declaration" | "struct_declaration" | "record_declaration"
        ) {
            return Some(n);
        }
        current = n.parent();
    }
    None
}

/// The method-like member around a node.
fn enclosing_member(node: Node) -> Option<Node> {
    let mut current = node.parent();
    for _ in 0..128 {
        let n = current?;
        if matches!(
            n.kind(),
            "method_declaration"
                | "constructor_declaration"
                | "destructor_declaration"
                | "accessor_declaration"
                | "operator_declaration"
                | "conversion_operator_declaration"
                | "local_function_statement"
                | "lambda_expression"
                | "anonymous_method_expression"
                | "global_statement"
        ) {
            return Some(n);
        }
        if matches!(n.kind(), "class_declaration" | "struct_declaration") {
            return None;
        }
        current = n.parent();
    }
    None
}

const MUTABLE_COLLECTIONS: &[&[u8]] = &[
    b"List",
    b"Dictionary",
    b"HashSet",
    b"SortedSet",
    b"SortedList",
    b"SortedDictionary",
    b"LinkedList",
    b"Queue",
    b"Stack",
    b"ObservableCollection",
    b"Collection",
    b"ArrayList",
    b"Hashtable",
];

fn is_mutable_collection_type(ty: Node, src: &[u8]) -> bool {
    ty.kind() == "array_type" || MUTABLE_COLLECTIONS.contains(&simple_name(ty, src))
}

pub(super) fn declared_type(field: Node) -> Option<Node> {
    let mut cursor = field.walk();
    field
        .named_children(&mut cursor)
        .find(|c| c.kind() == "variable_declaration")
        .and_then(|d| d.child_by_field_name("type"))
}

/// The message template of a logging call: its first string argument
/// among the first three (after an EventId and an exception), when the
/// receiver looks like a logger.
pub(super) fn log_template<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let function = call.child_by_field_name("function")?;
    let method = text(function.child_by_field_name("name")?, src);
    let receiver = function.child_by_field_name("expression")?;
    let mel = matches!(
        method,
        b"Log"
            | b"LogTrace"
            | b"LogDebug"
            | b"LogInformation"
            | b"LogWarning"
            | b"LogError"
            | b"LogCritical"
    );
    let serilog = matches!(
        method,
        b"Verbose" | b"Debug" | b"Information" | b"Warning" | b"Error" | b"Fatal"
    ) && super::java_security::contains_ignoring_case(text(receiver, src), b"log");
    if !(mel || serilog) {
        return None;
    }
    cs_call_arguments(call)
        .into_iter()
        .take(3)
        .find(|a| a.kind() == "string_literal" || a.kind() == "verbatim_string_literal")
}

/// Placeholder names in a message template (`{Name}`, `{@Name}`,
/// `{Name:format}`), or Err when braces don't balance or one is empty.
pub(super) fn template_placeholders(value: &[u8]) -> Result<Vec<&[u8]>, ()> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < value.len() {
        match value[i] {
            b'{' if value.get(i + 1) == Some(&b'{') => i += 2,
            b'}' if value.get(i + 1) == Some(&b'}') => i += 2,
            b'}' => return Err(()),
            b'{' => {
                let end = value[i..].iter().position(|&b| b == b'}').ok_or(())? + i;
                let inner = &value[i + 1..end];
                if inner.contains(&b'{') {
                    return Err(());
                }
                let name = inner
                    .split(|&b| b == b':' || b == b',')
                    .next()
                    .unwrap_or_default();
                let name = name
                    .strip_prefix(b"@")
                    .or_else(|| name.strip_prefix(b"$"))
                    .unwrap_or(name);
                if name.is_empty() {
                    return Err(());
                }
                out.push(name);
                i = end + 1;
            }
            _ => i += 1,
        }
    }
    Ok(out)
}

// ---------------------------------------------------- filters

/// An IPv4-looking literal, unless the code around it is about versions:
/// `new Version("1.2.3.4")`, `[AssemblyVersion("1.0.0.0")]`.
fn is_hardcoded_ip(node: Node, src: &[u8]) -> bool {
    if !is_routable_ipv4(node, src) {
        return false;
    }
    let mut current = node.parent();
    for _ in 0..6 {
        let Some(n) = current else {
            break;
        };
        // Attribute arguments hold versions ([GeneratedCode("tool", "4.0.0.0")]),
        // not addresses.
        if n.kind() == "attribute" {
            return false;
        }
        let t = text(n, src);
        if t.len() < 400 && super::java_security::contains_ignoring_case(t, b"version") {
            return false;
        }
        // Only the literal's own statement or declaration says what it is.
        if n.kind().ends_with("_statement")
            || n.kind().ends_with("_declaration")
            || matches!(
                n.kind(),
                "attribute" | "argument_list" | "initializer_expression"
            ) && n.parent().is_some_and(|p| p.kind().ends_with("_statement"))
        {
            break;
        }
        current = n.parent();
    }
    true
}

fn compares_fraction_exactly(node: Node, src: &[u8]) -> bool {
    if !matches!(operator_text(node, src), b"==" | b"!=") {
        return false;
    }
    let is_fraction = |n: Option<Node>| {
        n.map(unparenthesized).is_some_and(|n| {
            n.kind() == "real_literal"
                // Decimals (1.1m) are exact.
                && !text(n, src).ends_with(b"m")
                && !text(n, src).ends_with(b"M")
                && {
                // Zero is exact; testing for it is deliberate.
                let digits: Vec<u8> = text(n, src)
                    .iter()
                    .copied()
                    .filter(|b| b.is_ascii_digit() || *b == b'.')
                    .collect();
                digits.iter().any(|b| matches!(b, b'1'..=b'9'))
            }
        })
    };
    is_fraction(node.child_by_field_name("left")) || is_fraction(node.child_by_field_name("right"))
}

fn hash_reads_mutable_field<'t>(declaration: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let fields = mutable_fields(declaration, src, false);
    if fields.is_empty() {
        return None;
    }
    let method = members(declaration).into_iter().find(|m| {
        m.kind() == "method_declaration"
            && cs_has_modifier(*m, "override", src)
            && m.child_by_field_name("name")
                .is_some_and(|n| text(n, src) == b"GetHashCode")
    })?;
    let body = method.child_by_field_name("body")?;
    find_in_scope(body, &[], |n| {
        n.kind() == "identifier"
            && fields.contains(&text(n, src))
            && n.parent().is_none_or(|p| {
                // `other.id` reads another object's field; `this.id` is ours.
                p.kind() != "member_access_expression"
                    || p.child_by_field_name("name") != Some(n)
                    || text(p, src).starts_with(b"this.")
            })
    })
}

fn lock_on_mutable<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut cursor = node.walk();
    let locked = node
        .named_children(&mut cursor)
        .find(|c| c.kind() != "block" && c.kind() != "comment")?;
    if locked.kind() == "object_creation_expression" {
        return Some(locked);
    }
    let name = match locked.kind() {
        "identifier" => text(locked, src),
        "member_access_expression" => text(locked, src).strip_prefix(b"this.")?,
        _ => return None,
    };
    let declaration = enclosing_type(node)?;
    let mutable = mutable_fields(declaration, src, false)
        .into_iter()
        .chain(mutable_fields(declaration, src, true))
        .any(|f| f == name);
    mutable.then_some(locked)
}

const MUTATING_METHODS: &[&[u8]] = &[
    b"Add",
    b"AddRange",
    b"Remove",
    b"RemoveAt",
    b"RemoveAll",
    b"Clear",
    b"Insert",
    b"Push",
    b"Pop",
    b"Enqueue",
    b"Dequeue",
    b"TryAdd",
    b"TryRemove",
    b"TryDequeue",
    b"TryPop",
    b"MoveNext",
    b"Dispose",
];

fn assertion_side_effect<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let condition = *cs_call_arguments(call).first()?;
    let has_effect = |n: Node| match n.kind() {
        "assignment_expression" => true,
        "postfix_unary_expression" | "prefix_unary_expression" => {
            let t = text(n, src);
            t.starts_with(b"++") || t.starts_with(b"--") || t.ends_with(b"++") || t.ends_with(b"--")
        }
        "invocation_expression" => n
            .child_by_field_name("function")
            .and_then(|f| f.child_by_field_name("name"))
            .is_some_and(|m| MUTATING_METHODS.contains(&text(m, src))),
        _ => false,
    };
    if has_effect(condition) {
        return Some(condition);
    }
    find_in_scope(condition, CS_SCOPE_STOPS, has_effect)
}

fn visible_readonly_collection<'t>(field: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !cs_has_modifier(field, "readonly", src)
        || cs_has_modifier(field, "static", src)
        || cs_has_modifier(field, "private", src)
        || !["public", "protected", "internal"]
            .iter()
            .any(|m| cs_has_modifier(field, m, src))
    {
        return None;
    }
    let ty = declared_type(field)?;
    is_mutable_collection_type(ty, src)
        .then(|| declarators(field).into_iter().next())
        .flatten()
}

fn template_repeats_placeholder<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let template = log_template(call, src)?;
    let names = template_placeholders(cs_string_value(template, src)?).ok()?;
    let repeated = names
        .iter()
        .enumerate()
        .any(|(i, n)| !n.iter().all(u8::is_ascii_digit) && names[..i].contains(n));
    repeated.then_some(template)
}

fn malformed_template<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let template = log_template(call, src)?;
    template_placeholders(cs_string_value(template, src)?)
        .is_err()
        .then_some(template)
}

fn grants_everyone(node: Node, src: &[u8]) -> bool {
    if node.kind() == "member_access_expression" {
        let Some(receiver) = node.child_by_field_name("expression") else {
            return false;
        };
        let member = node
            .child_by_field_name("name")
            .map_or(&b""[..], |n| text(n, src));
        return match simple_name(receiver, src) {
            b"UnixFileMode" => matches!(member, b"OtherRead" | b"OtherWrite" | b"OtherExecute"),
            b"WellKnownSidType" => member == b"WorldSid",
            _ => false,
        };
    }
    node.child_by_field_name("type").is_some_and(|t| {
        matches!(
            simple_name(t, src),
            b"FileSystemAccessRule" | b"FileSystemAuditRule"
        )
    }) && cs_call_arguments(node)
        .first()
        .and_then(|a| cs_string_value(*a, src))
        .is_some_and(|v| v.eq_ignore_ascii_case(b"Everyone"))
}

fn string_repeated_often<'t>(unit: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut counts: std::collections::HashMap<&[u8], (usize, Node<'t>)> =
        std::collections::HashMap::new();
    let mut cursor = unit.walk();
    if !cursor.goto_first_child() {
        return None;
    }
    loop {
        let n = cursor.node();
        // Attribute arguments are often the same on purpose: [Category("Slow")].
        if n.kind() == "attribute_list" {
            if !cursor.goto_next_sibling() {
                while !cursor.goto_next_sibling() {
                    if !cursor.goto_parent() {
                        return smallest(&counts);
                    }
                }
            }
            continue;
        }
        if matches!(n.kind(), "string_literal" | "verbatim_string_literal")
            && let Some(value) = cs_string_value(n, src).filter(|v| v.len() >= 10)
        {
            counts
                .entry(value)
                .and_modify(|e| e.0 += 1)
                .or_insert((1, n));
        }
        if cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return smallest(&counts);
            }
        }
    }
}

/// The first literal (by position) that occurs three times or more.
/// HashMap order never reaches the output: the minimum is unique.
fn smallest<'t>(counts: &std::collections::HashMap<&[u8], (usize, Node<'t>)>) -> Option<Node<'t>> {
    counts
        .values()
        .filter(|(count, _)| *count >= 3)
        .map(|(_, node)| *node)
        .min_by_key(|n| n.start_byte())
}

fn local_is_never_used(name: Node, src: &[u8]) -> bool {
    let n = text(name, src);
    if n == b"_" {
        return false;
    }
    // `using var lease = ...;` is there to be disposed.
    let Some(statement) = name
        .parent()
        .and_then(|d| d.parent())
        .and_then(|v| v.parent())
    else {
        return false;
    };
    let mut cursor = statement.walk();
    if statement
        .children(&mut cursor)
        .any(|c| !c.is_named() && text(c, src) == b"using")
    {
        return false;
    }
    // A parse error (an #if splitting the method, say) hides the rest of it.
    enclosing_member(name)
        .is_some_and(|scope| !scope.has_error() && count_word(text(scope, src), n) == 1)
}

fn shadows_member(name: Node, src: &[u8]) -> bool {
    let n = text(name, src);
    let Some(declaration) = enclosing_type(name).filter(|d| !d.has_error()) else {
        return false;
    };
    members(declaration).into_iter().any(|m| match m.kind() {
        "field_declaration" => declarators(m).iter().any(|d| {
            d.child_by_field_name("name")
                .is_some_and(|f| text(f, src) == n)
        }),
        "property_declaration" => m
            .child_by_field_name("name")
            .is_some_and(|p| text(p, src) == n),
        _ => false,
    })
}

fn unused_private_member<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    // Partial classes are spread over files, and attributes such as
    // [Serializable] or [DataContract] mean members are used by reflection.
    // A parse error (an #if splitting the class) hides part of its text.
    if cs_has_modifier(class, "partial", src) || class.has_error() {
        return None;
    }
    let mut cursor = class.walk();
    if class
        .named_children(&mut cursor)
        .any(|c| c.kind() == "attribute_list")
    {
        return None;
    }
    let whole = text(class, src);
    members(class).into_iter().find_map(|m| {
        if !matches!(
            m.kind(),
            "method_declaration" | "field_declaration" | "property_declaration"
        ) {
            return None;
        }
        let mut c = m.walk();
        let visible = ["public", "protected", "internal"]
            .iter()
            .any(|v| cs_has_modifier(m, v, src));
        let special = m
            .named_children(&mut c)
            .any(|x| matches!(x.kind(), "attribute_list" | "explicit_interface_specifier"))
            || ["override", "virtual", "abstract", "extern", "partial"]
                .iter()
                .any(|v| cs_has_modifier(m, v, src));
        if visible || special {
            return None;
        }
        let names: Vec<Node<'t>> = if m.kind() == "field_declaration" {
            declarators(m)
                .into_iter()
                .filter_map(|d| d.child_by_field_name("name"))
                .collect()
        } else {
            m.child_by_field_name("name").into_iter().collect()
        };
        names.into_iter().find(|n| {
            let name = text(*n, src);
            // An entry point or a deconstructor is called by the runtime.
            !matches!(name, b"Main" | b"Deconstruct") && count_word(whole, name) == 1
        })
    })
}

fn logs_and_rethrows(catch: Node, src: &[u8]) -> bool {
    let mut cursor = catch.walk();
    let Some(name) = catch
        .named_children(&mut cursor)
        .find(|c| c.kind() == "catch_declaration")
        .and_then(|d| d.child_by_field_name("name"))
        .map(|n| text(n, src))
    else {
        return false;
    };
    let Some(body) = catch.child_by_field_name("body") else {
        return false;
    };
    let logs = find_in_scope(body, CS_SCOPE_STOPS, |n| {
        n.kind() == "invocation_expression" && log_template(n, src).is_some()
            || n.kind() == "invocation_expression"
                && n.child_by_field_name("function")
                    .and_then(|f| f.child_by_field_name("name"))
                    .is_some_and(|m| {
                        matches!(
                            text(m, src),
                            b"LogError"
                                | b"LogWarning"
                                | b"LogCritical"
                                | b"Error"
                                | b"Fatal"
                                | b"Warning"
                        )
                    })
                && cs_call_arguments(n).iter().any(|a| text(*a, src) == name)
    })
    .is_some();
    let rethrows = find_in_scope(body, CS_SCOPE_STOPS, |n| {
        n.kind() == "throw_statement" && operand(n).is_none_or(|e| text(e, src) == name)
    })
    .is_some();
    logs && rethrows
}

fn is_boolean_expression(n: Node, src: &[u8]) -> bool {
    let n = unparenthesized(n);
    match n.kind() {
        "boolean_literal" | "is_pattern_expression" | "is_expression" => true,
        "prefix_unary_expression" => text(n, src).starts_with(b"!"),
        "binary_expression" => matches!(
            operator_text(n, src),
            b"==" | b"!=" | b"<" | b"<=" | b">" | b">=" | b"&&" | b"||"
        ),
        _ => false,
    }
}

/// `&` or `|` with a boolean on either side: C# has no `bool & int`, so the
/// other side is a boolean too.
fn non_short_circuit_on_bools(node: Node, src: &[u8]) -> bool {
    matches!(operator_text(node, src), b"&" | b"|")
        && (node
            .child_by_field_name("left")
            .is_some_and(|l| is_boolean_expression(l, src))
            || node
                .child_by_field_name("right")
                .is_some_and(|r| is_boolean_expression(r, src)))
}

fn test_class_without_tests<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let marked = attribute_names(class, src)
        .iter()
        .any(|(_, n)| matches!(*n, b"TestClass" | b"TestFixture"));
    let mut cursor = class.walk();
    let inherits = class
        .named_children(&mut cursor)
        .any(|c| c.kind() == "base_list");
    if !marked || inherits || cs_has_modifier(class, "abstract", src) {
        return None;
    }
    // Test methods may sit inside #if blocks, so look below the members too.
    // A class holding [AssemblyInitialize] setup has no tests by design.
    let body = class.child_by_field_name("body")?;
    let has_test = find_in_scope(body, &["class_declaration"], |n| {
        n.kind() == "method_declaration"
            && (is_test_method(n, src)
                || attribute_names(n, src)
                    .iter()
                    .any(|(_, a)| matches!(*a, b"AssemblyInitialize" | b"AssemblyCleanup")))
    })
    .is_some();
    (!has_test).then(|| class.child_by_field_name("name"))?
}

fn roundabout_type_check(node: Node, src: &[u8]) -> bool {
    if node.kind() == "binary_expression" {
        // (x as T) != null
        let is_as = |n: Option<Node>| {
            n.map(unparenthesized)
                .is_some_and(|n| n.kind() == "as_expression")
        };
        let is_null = |n: Option<Node>| n.is_some_and(|n| n.kind() == "null_literal");
        let (l, r) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        );
        return matches!(operator_text(node, src), b"==" | b"!=")
            && ((is_as(l) && is_null(r)) || (is_null(l) && is_as(r)));
    }
    let Some(function) = node.child_by_field_name("function") else {
        return false;
    };
    match function.child_by_field_name("name").map(|n| text(n, src)) {
        Some(b"IsInstanceOfType") => true,
        // typeof(T).IsAssignableFrom(x.GetType())
        Some(b"IsAssignableFrom") => cs_call_arguments(node).first().is_some_and(|a| {
            a.kind() == "invocation_expression"
                && a.child_by_field_name("function")
                    .and_then(|f| f.child_by_field_name("name"))
                    .is_some_and(|m| text(m, src) == b"GetType")
        }),
        _ => false,
    }
}

fn visible_static_collection<'t>(field: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !cs_has_modifier(field, "static", src)
        || !cs_has_modifier(field, "readonly", src)
        || !["public", "protected"]
            .iter()
            .any(|m| cs_has_modifier(field, m, src))
    {
        return None;
    }
    let ty = declared_type(field)?;
    is_mutable_collection_type(ty, src)
        .then(|| declarators(field).into_iter().next())
        .flatten()
}

fn has_raw_control_char(node: Node, src: &[u8]) -> bool {
    let t = text(node, src);
    // A verbatim string spans lines and keeps their indentation.
    let layout_allowed = node.kind() == "verbatim_string_literal";
    t.iter()
        .any(|&b| b < 0x20 && !(layout_allowed && matches!(b, b'\n' | b'\r' | b'\t')))
}

fn ignores_everything(catch: Node, src: &[u8]) -> bool {
    let Some(body) = catch.child_by_field_name("body") else {
        return false;
    };
    if body.named_child_count() != 0 {
        return false;
    }
    let mut cursor = catch.walk();
    let children: Vec<Node> = catch.named_children(&mut cursor).collect();
    // `catch (Exception e) when (Record(e))` handles it in the filter.
    if children.iter().any(|c| c.kind() == "catch_filter_clause") {
        return false;
    }
    let declaration = children
        .into_iter()
        .find(|c| c.kind() == "catch_declaration");
    match declaration.and_then(|d| d.child_by_field_name("type")) {
        None => true,
        Some(t) => matches!(simple_name(t, src), b"Exception" | b"SystemException"),
    }
}

fn asserts_boolean_literal(call: Node, _: &[u8]) -> bool {
    cs_call_arguments(call)
        .iter()
        .take(2)
        .any(|a| unparenthesized(*a).kind() == "boolean_literal")
}

fn static_field_ignoring_type_parameters<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut cursor = class.walk();
    let list = class
        .named_children(&mut cursor)
        .find(|c| c.kind() == "type_parameter_list")?;
    let mut inner = list.walk();
    let params: Vec<&[u8]> = list
        .named_children(&mut inner)
        .filter(|p| p.kind() == "type_parameter")
        .map(|p| text(p, src))
        .collect();
    members(class).into_iter().find_map(|m| {
        if m.kind() != "field_declaration"
            || !cs_has_modifier(m, "static", src)
            || cs_has_modifier(m, "const", src)
        {
            return None;
        }
        // Its type, or its initializer (`typeof(Mapper<T>).GetMethod(...)`),
        // depends on T: one value per T is then the point.
        let field = text(m, src);
        let uses_parameter = params
            .iter()
            .any(|p| count_word(field, p.rsplit(|&b| b == b' ').next().unwrap_or(p)) > 0);
        (!uses_parameter).then(|| declarators(m).into_iter().next())?
    })
}

fn sleep_in_test<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !is_test_method(method, src) {
        return None;
    }
    let body = method.child_by_field_name("body")?;
    find_in_scope(body, CS_SCOPE_STOPS, |n| {
        n.kind() == "invocation_expression"
            && n.child_by_field_name("function").is_some_and(|f| {
                matches!(
                    text(f, src),
                    b"Thread.Sleep" | b"System.Threading.Thread.Sleep"
                )
            })
    })
}

fn dispose_without_interface<'t>(declaration: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut cursor = declaration.walk();
    if declaration
        .named_children(&mut cursor)
        .any(|c| c.kind() == "base_list")
        || cs_has_modifier(declaration, "partial", src)
    {
        return None;
    }
    members(declaration).into_iter().find_map(|m| {
        let name = m.child_by_field_name("name")?;
        let no_params = m
            .child_by_field_name("parameters")
            .is_some_and(|p| p.named_child_count() == 0);
        (m.kind() == "method_declaration"
            && text(name, src) == b"Dispose"
            && no_params
            && cs_has_modifier(m, "public", src)
            && !cs_has_modifier(m, "static", src))
        .then_some(name)
    })
}

fn no_arguments(call: Node, _: &[u8]) -> bool {
    call.child_by_field_name("arguments")
        .is_some_and(|a| a.named_child_count() == 0)
}

fn is_literal(n: Node) -> bool {
    matches!(
        unparenthesized(n).kind(),
        "string_literal"
            | "verbatim_string_literal"
            | "integer_literal"
            | "real_literal"
            | "character_literal"
            | "boolean_literal"
            | "null_literal"
    )
}

fn expected_value_second(call: Node, _: &[u8]) -> bool {
    let args = cs_call_arguments(call);
    matches!(args.as_slice(), [first, second, ..] if !is_literal(*first) && is_literal(*second))
}

fn is_expected_exception(attribute: Node, src: &[u8]) -> bool {
    attribute.child_by_field_name("name").is_some_and(|n| {
        matches!(
            simple_name(n, src),
            b"ExpectedException" | b"ExpectedExceptionAttribute"
        )
    })
}

fn bad_test_signature<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !is_test_method(method, src) {
        return None;
    }
    let async_void = cs_has_modifier(method, "async", src)
        && method.child_by_field_name("returns").map(|r| text(r, src)) == Some(b"void");
    // xUnit runs non-public tests too; MSTest and NUnit skip them.
    let xunit = attribute_names(method, src)
        .iter()
        .any(|(_, n)| matches!(*n, b"Fact" | b"Theory"));
    let hidden = !xunit && !cs_has_modifier(method, "public", src);
    (async_void || hidden).then(|| method.child_by_field_name("name"))?
}

fn gets_type_of_type(call: Node, src: &[u8]) -> bool {
    let Some(receiver) = call
        .child_by_field_name("function")
        .and_then(|f| f.child_by_field_name("expression"))
    else {
        return false;
    };
    no_arguments(call, src)
        && (receiver.kind() == "typeof_expression"
            || (receiver.kind() == "invocation_expression"
                && receiver
                    .child_by_field_name("function")
                    .and_then(|f| f.child_by_field_name("name"))
                    .is_some_and(|m| text(m, src) == b"GetType")
                && no_arguments(receiver, src)))
}

fn parameter_attributes<'s>(parameter: Node, src: &'s [u8]) -> Vec<&'s [u8]> {
    attribute_names(parameter, src)
        .into_iter()
        .map(|(_, n)| n)
        .collect()
}

fn optional_ref_out(parameter: Node, src: &[u8]) -> bool {
    let mut cursor = parameter.walk();
    let by_reference = parameter
        .named_children(&mut cursor)
        .any(|m| m.kind() == "modifier" && matches!(text(m, src), b"ref" | b"out"));
    by_reference && parameter_attributes(parameter, src).contains(&&b"Optional"[..])
}

fn default_without_optional(parameter: Node, src: &[u8]) -> bool {
    let attrs = parameter_attributes(parameter, src);
    attrs.contains(&&b"DefaultParameterValue"[..]) && !attrs.contains(&&b"Optional"[..])
}

fn has_default_value_attribute(parameter: Node, src: &[u8]) -> bool {
    parameter_attributes(parameter, src).contains(&&b"DefaultValue"[..])
}

fn contract_without_operations<'t>(declaration: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_attribute(declaration, "ServiceContract", src)?;
    let has_operation = members(declaration)
        .iter()
        .any(|m| find_attribute(*m, "OperationContract", src).is_some());
    (!has_operation).then(|| declaration.child_by_field_name("name"))?
}

fn implements_iequatable(declaration: Node, src: &[u8]) -> bool {
    let mut cursor = declaration.walk();
    declaration
        .named_children(&mut cursor)
        .filter(|c| c.kind() == "base_list")
        .any(|b| text(b, src).windows(10).any(|w| w == b"IEquatable"))
}

fn typed_equals_without_interface<'t>(declaration: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if implements_iequatable(declaration, src) || cs_has_modifier(declaration, "partial", src) {
        return None;
    }
    let own = text(declaration.child_by_field_name("name")?, src);
    members(declaration).into_iter().find_map(|m| {
        let name = m.child_by_field_name("name")?;
        if m.kind() != "method_declaration"
            || text(name, src) != b"Equals"
            || !cs_has_modifier(m, "public", src)
        {
            return None;
        }
        let params = m.child_by_field_name("parameters")?;
        let mut cursor = params.walk();
        let types: Vec<&[u8]> = params
            .named_children(&mut cursor)
            .filter(|p| p.kind() == "parameter")
            .filter_map(|p| p.child_by_field_name("type"))
            .map(|t| {
                let t = text(t, src);
                t.strip_suffix(b"?").unwrap_or(t)
            })
            .collect();
        (types == [own]).then_some(name)
    })
}

fn unsealed_equatable<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    (implements_iequatable(class, src)
        && !["sealed", "abstract", "static"]
            .iter()
            .any(|m| cs_has_modifier(class, m, src)))
    .then(|| class.child_by_field_name("name"))?
}

fn single_char_argument(call: Node, src: &[u8]) -> bool {
    cs_call_arguments(call)
        .first()
        .and_then(|a| cs_string_value(*a, src))
        // One plain character, or one escape such as "\\" or "\"".
        .is_some_and(|v| {
            (v.len() == 1 && v[0] != b'\\') || (v.len() == 2 && v[0] == b'\\' && v[1] != b'u')
        })
}

fn any_with_equality(call: Node, src: &[u8]) -> bool {
    let Some(lambda) = cs_call_arguments(call).first().copied() else {
        return false;
    };
    let Some(parameter) = lambda
        .child_by_field_name("parameters")
        .map(|p| text(p, src).trim_ascii())
        .map(|p| {
            p.strip_prefix(b"(")
                .and_then(|p| p.strip_suffix(b")"))
                .unwrap_or(p)
        })
    else {
        return false;
    };
    let Some(body) = lambda.child_by_field_name("body") else {
        return false;
    };
    if body.kind() != "binary_expression" || operator_text(body, src) != b"==" {
        return false;
    }
    let side = |f: &str| body.child_by_field_name(f).map(|n| text(n, src));
    let (Some(l), Some(r)) = (side("left"), side("right")) else {
        return false;
    };
    // `x => x == y`, but not `x => x.Id == y`, which Contains can't express.
    (l == parameter) != (r == parameter)
        && count_word(if l == parameter { r } else { l }, parameter) == 0
}

fn foreign_logger_category<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let own = text(class.child_by_field_name("name")?, src);
    // `ILogger<TRequest>` in `Behaviour<TRequest>` logs under the request
    // type on purpose.
    let type_parameters: Vec<&[u8]> = {
        let mut cursor = class.walk();
        class
            .named_children(&mut cursor)
            .filter(|c| c.kind() == "type_parameter_list")
            .flat_map(|l| {
                let mut c = l.walk();
                l.named_children(&mut c)
                    .map(|p| text(p, src))
                    .collect::<Vec<_>>()
            })
            .collect()
    };
    let mut lists: Vec<Node<'t>> = Vec::new();
    let mut cursor = class.walk();
    lists.extend(
        class
            .named_children(&mut cursor)
            .filter(|c| c.kind() == "parameter_list"),
    );
    for m in members(class) {
        if m.kind() == "constructor_declaration" {
            lists.extend(m.child_by_field_name("parameters"));
        }
    }
    lists.into_iter().find_map(|list| {
        let mut c = list.walk();
        let params: Vec<Node<'t>> = list.named_children(&mut c).collect();
        params.into_iter().find_map(|p| {
            let ty = p.child_by_field_name("type")?;
            if ty.kind() != "generic_name" || simple_name(ty, src) != b"ILogger" {
                return None;
            }
            let mut tc = ty.walk();
            let arg = ty
                .named_children(&mut tc)
                .find(|c| c.kind() == "type_argument_list")?
                .named_child(0)?;
            let category = simple_name(arg, src);
            (category != own && !type_parameters.contains(&category)).then_some(ty)
        })
    })
}

fn template_with_camel_placeholder<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let template = log_template(call, src)?;
    let names = template_placeholders(cs_string_value(template, src)?).ok()?;
    names
        .iter()
        .any(|n| n.first().is_some_and(|b| b.is_ascii_lowercase()))
        .then_some(template)
}

fn ignore_without_reason(attribute: Node, src: &[u8]) -> bool {
    let named = attribute
        .child_by_field_name("name")
        .is_some_and(|n| matches!(simple_name(n, src), b"Ignore" | b"IgnoreAttribute"));
    let mut cursor = attribute.walk();
    let has_reason = attribute
        .named_children(&mut cursor)
        .any(|c| c.kind() == "attribute_argument_list" && c.named_child_count() > 0);
    // Only on test methods: [Ignore] also exists in serializers.
    let on_test = attribute
        .parent()
        .and_then(|list| list.parent())
        .is_some_and(|m| m.kind() == "method_declaration" && is_test_method(m, src));
    named && !has_reason && on_test
}

fn if_after_if_same_line<'t>(block: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    let stmts = cs_statements(block);
    stmts.windows(2).find_map(|w| {
        (w[0].kind() == "if_statement"
            && w[1].kind() == "if_statement"
            && w[0].end_position().row == w[1].start_position().row)
            .then_some(w[1])
    })
}

#[cfg(test)]
mod tests {
    use super::super::cs::tests::flagged;
    use super::template_placeholders;

    fn class(body: &str) -> String {
        format!("namespace N;\nclass A {{\n{body}\n}}\n")
    }

    fn method(body: &str) -> String {
        format!("namespace N;\nclass A {{\nvoid F() {{\n{body}\n}}\n}}\n")
    }

    #[test]
    fn floats_and_hashes() {
        let src = method(
            "b = x == 0.1;\nb = x != 2.5f;\nb = x == 0.0;\nb = x == 0d;\nb = x == 1;\nb = x == 1.1m;",
        );
        assert_eq!(flagged("cs/float-equality", &src), [4, 5]);
        let hash = "namespace N;\nclass P { int id; readonly int k; public override int GetHashCode() => id; }\nclass Q { readonly int k; int n; public override int GetHashCode() => k; }\nclass R { int id; public override int GetHashCode() => this.id ^ other.id; }";
        assert_eq!(flagged("cs/hashcode-mutable-field", hash), [2, 4]);
    }

    #[test]
    fn locks() {
        let src = class(
            "object a = new object();\nreadonly object b = new object();\nstatic object c;\nvoid F() {\nlock (a) { }\nlock (b) { }\nlock (this.a) { }\nlock (c) { }\nlock (new object()) { }\n}",
        );
        assert_eq!(flagged("cs/lock-on-mutable-field", &src), [7, 9, 10, 11]);
    }

    #[test]
    fn assertions_with_effects() {
        let src = method(
            "Debug.Assert(xs.Remove(1));\nDebug.Assert(i++ > 0);\nDebug.Assert((x = 2) > 1);\nDebug.Assert(xs.Count > 0);\nDebug.Assert(xs.Contains(1));\nTrace.Assert(xs.Remove(1));",
        );
        assert_eq!(flagged("cs/assert-side-effects", &src), [4, 5, 6]);
    }

    #[test]
    fn collection_fields() {
        let src = class(
            "public readonly List<int> A = new();\npublic readonly int[] B;\nprivate readonly List<int> C;\npublic readonly IReadOnlyList<int> D;\npublic static readonly string[] E = { };\nprotected static readonly Dictionary<int, int> F = new();\ninternal static readonly int[] G;\npublic static readonly IReadOnlyList<int> H;",
        );
        assert_eq!(flagged("cs/public-readonly-mutable", &src), [3, 4]);
        assert_eq!(flagged("cs/public-static-mutable-collection", &src), [7, 8]);
    }

    #[test]
    fn templates() {
        assert_eq!(
            template_placeholders(b"A {Id} {@Order} {Total:N2} {{x}}"),
            Ok(vec![&b"Id"[..], b"Order", b"Total"])
        );
        assert_eq!(template_placeholders(b"A {Id"), Err(()));
        assert_eq!(template_placeholders(b"A {}"), Err(()));
        let src = method(
            "log.LogInformation(\"Moved {Id} to {Id}\", a, b);\nlog.LogInformation(\"Moved {From} to {To}\", a, b);\nlog.LogWarning(\"Bad {Id\", a);\n_logger.LogError(ex, \"Failed {orderId}\", id);\nLog.Information(\"User {userId}\", u);\nConsole.Error(\"{x\");\nlog.LogDebug(\"{0} {1}\", a, b);",
        );
        assert_eq!(flagged("cs/log-template-duplicate-placeholder", &src), [4]);
        assert_eq!(flagged("cs/log-template-syntax", &src), [6]);
        assert_eq!(flagged("cs/log-placeholder-pascal-case", &src), [7, 8]);
    }

    #[test]
    fn permissions_ips_strings() {
        let src = method(
            "File.SetUnixFileMode(p, UnixFileMode.UserRead | UnixFileMode.OtherWrite);\nvar sid = new SecurityIdentifier(WellKnownSidType.WorldSid, null);\nvar rule = new FileSystemAccessRule(\"Everyone\", FileSystemRights.Read, AccessControlType.Allow);\nvar ip = \"203.0.113.7\";\nvar lo = \"127.0.0.1\";\nvar v = \"1.2.3.4.5\";\nvar ver = new Version(\"1.2.3.4\");",
        );
        assert_eq!(flagged("cs/world-permissions", &src), [4, 5, 6]);
        assert_eq!(flagged("cs/hardcoded-ip", &src), [7]);
        let dup = "namespace N;\nclass A {\n[Category(\"integration\")] void A1() { G(\"connection failed\"); }\n[Category(\"integration\")] void A2() { G(\"connection failed\"); }\n[Category(\"integration\")] void A3() { G(\"connection failed\"); }\nvoid A4() { G(\"short\"); G(\"short\"); G(\"short\"); }\n}";
        assert_eq!(flagged("cs/duplicated-string", dup), [3]);
    }

    #[test]
    fn ip_like_versions() {
        let src = "namespace N;\nclass A {\n[GeneratedCode(\"tool\", \"4.0.0.0\")] void G() { }\nstring ip = \"203.0.113.7\";\n}";
        assert_eq!(flagged("cs/hardcoded-ip", src), [4]);
    }

    #[test]
    fn locals_and_members() {
        let src = "namespace N;\nclass A {\nint count;\nint Total { get; set; }\nprivate int Helper() => 1;\nprivate int used;\nint unusedField;\nprivate void Unused() { }\n[Obsolete] private void Kept() { }\npublic int F() {\nint x = 1;\nint y = 2;\nint count = 3;\nusing var lease = Acquire();\nvar _ = G();\nint Total = 4;\nreturn y + used + Helper() + Total;\n}\n}";
        assert_eq!(flagged("cs/unused-local-variable", src), [11, 13]);
        assert_eq!(flagged("cs/local-shadows-field", src), [13, 16]);
        assert_eq!(flagged("cs/unused-private-member", src), [7]);
    }

    #[test]
    fn catches() {
        let src = method(
            "try { G(); } catch (IOException e) { log.LogError(e, \"Failed\"); throw; }\ntry { G(); } catch (IOException e) { log.LogError(e, \"Failed\"); }\ntry { G(); } catch (Exception) { }\ntry { G(); } catch { }\ntry { G(); } catch (IOException) { }\ntry { G(); } catch (Exception) { /* optional */ }\ntry { G(); } catch (Exception e) when (Record(e)) { }",
        );
        assert_eq!(flagged("cs/log-and-rethrow", &src), [4]);
        assert_eq!(flagged("cs/generic-exception-ignored", &src), [6, 7]);
    }

    #[test]
    fn logic_and_type_checks() {
        let src = method(
            "b = x != null & x.Ok;\nb = a | b;\nb = (a > 1) | !c;\nb = flags & Mask;\nb = typeof(string).IsInstanceOfType(o);\nb = typeof(B).IsAssignableFrom(o.GetType());\nb = (o as B) != null;\nb = o is B;\nt = typeof(A).GetType();\nt = o.GetType().GetType();\nt = o.GetType();",
        );
        assert_eq!(flagged("cs/non-short-circuit-logic", &src), [4, 6]);
        assert_eq!(flagged("cs/type-check-simplify", &src), [8, 9, 10]);
        assert_eq!(flagged("cs/type-of-type", &src), [12, 13]);
    }

    #[test]
    fn tests_and_assertions() {
        let src = "namespace N;\n[TestClass] public class A { public void Helper() { } }\n[TestClass] public class B { [TestMethod] public void T() { Thread.Sleep(10); } }\n[TestFixture] public abstract class C { }\n[TestClass] public class D : Base { }\n[TestFixture] public class F {\n#if NET\n[Test] public void T() { }\n#endif\n}\n[TestClass] public class G { [AssemblyInitialize] public static void Init(TestContext c) { } }\npublic class E {\n[Fact] void X() { Assert.Equal(true, ok); total.Should(); total.Should().Be(3); }\n[TestMethod] async void Y() { Assert.AreEqual(total, 3); Assert.AreEqual(3, total); Assert.IsTrue(ok); }\n[TestMethod, ExpectedException(typeof(E))] public void Z() { }\n[Test, Ignore] public void W() { }\n[Test, Ignore(\"slow\")] public void V() { }\n[TestMethod] void U() { }\n}";
        assert_eq!(flagged("cs/test-class-without-tests", src), [2]);
        assert_eq!(flagged("cs/thread-sleep-in-test", src), [3]);
        assert_eq!(flagged("cs/assertion-boolean-literal", src), [13]);
        assert_eq!(flagged("cs/incomplete-assertion", src), [13]);
        assert_eq!(flagged("cs/assertion-argument-order", src), [14]);
        assert_eq!(flagged("cs/expected-exception-attribute", src), [15]);
        assert_eq!(flagged("cs/ignored-test", src), [16]);
        assert_eq!(flagged("cs/test-method-signature", src), [14, 18]);
    }

    #[test]
    fn generics_dispose_parameters() {
        let src = "namespace N;\nclass Cache<T> { static int hits; static T last; static List<T> all; const int Max = 1; static readonly MethodInfo M = typeof(Cache<T>).GetMethod(\"Get\"); }\nclass Conn { public void Dispose() { } }\nclass Ok : IDisposable { public void Dispose() { } }\nclass P {\nvoid A([Optional] ref int x) { }\nvoid B([DefaultParameterValue(5)] int x) { }\nvoid C([Optional, DefaultParameterValue(5)] int x) { }\nvoid D([Optional, DefaultValue(5)] int x) { }\n}";
        assert_eq!(flagged("cs/static-field-in-generic", src), [2]);
        assert_eq!(flagged("cs/dispose-without-idisposable", src), [3]);
        assert_eq!(flagged("cs/optional-on-ref-out", src), [6]);
        assert_eq!(
            flagged("cs/default-parameter-value-without-optional", src),
            [7]
        );
        assert_eq!(flagged("cs/default-value-on-parameter", src), [9]);
    }

    #[test]
    fn contracts_and_equality() {
        let src = "namespace N;\n[ServiceContract] interface IA { int Count(); }\n[ServiceContract] interface IB { [OperationContract] int Count(); }\nclass P { public bool Equals(P other) => true; }\nclass Q : IEquatable<Q> { public bool Equals(Q other) => true; }\nsealed class R : IEquatable<R> { public bool Equals(R? other) => true; }\nstruct S { public bool Equals(S other) => true; }";
        assert_eq!(flagged("cs/service-contract-without-operations", src), [2]);
        assert_eq!(flagged("cs/equals-without-iequatable", src), [4, 7]);
        assert_eq!(flagged("cs/iequatable-not-sealed", src), [5]);
    }

    #[test]
    fn idioms() {
        let src = method(
            "b = s.StartsWith(\"/\");\nb = s.EndsWith(\"\\\\\");\nb = s.StartsWith(\"ab\");\nb = s.StartsWith(\"/\", StringComparison.Ordinal);\nb = xs.Any(x => x == y);\nb = xs.Any(x => x.Id == y);\nb = xs.Any(x => y == x);\nb = xs.Any();\nif (a) { G(); } if (b) { H(); }\nif (c) { G(); }\nif (d) { H(); }",
        );
        assert_eq!(flagged("cs/starts-with-single-char", &src), [4, 5]);
        assert_eq!(flagged("cs/any-instead-of-contains", &src), [8, 10]);
        assert_eq!(flagged("cs/conditions-same-line", &src), [12]);
    }

    #[test]
    fn logger_categories() {
        let src = "namespace N;\nclass Orders { public Orders(ILogger<Carts> log) { } }\nclass Carts(ILogger<Carts> log) { }\nclass Items(ILogger<Orders> log) { }\nclass Behaviour<TRequest>(ILogger<TRequest> log) { }";
        assert_eq!(flagged("cs/logger-category-mismatch", src), [2, 4]);
    }

    #[test]
    fn control_characters() {
        let src = "namespace N;\nclass A {\nstring a = \"x\ty\";\nstring b = \"x\\ty\";\nstring c = @\"line\nline\";\nstring d = @\"<a>\n\t<b/>\n</a>\";\n}";
        assert_eq!(flagged("cs/control-char-in-string", src), [3]);
    }
}
