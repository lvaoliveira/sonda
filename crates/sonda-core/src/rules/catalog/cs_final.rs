//! C# rules, batch 6 (ADR-0007, ADR-0015): fields and parameters, tests,
//! serialization, Azure Functions, regular expressions and dates. Queries
//! stay cheap on deep trees: see the notes in `js_modern.rs`.

use super::cs::{
    CS_SCOPE_STOPS, cs_has_modifier, cs_statements, cs_string_value, operand, simple_name,
};
use super::cs_bugs::{attribute_arguments, attribute_names, cs_call_arguments, find_attribute};
use super::cs_more::{declarators, enclosing_type, is_test_method, log_template, members};
use super::java_bugs::{find_in_scope, operator_text};
use super::java_security::{contains_ignoring_case, text};
use super::java_smells::count_word;
use super::*;

/// Rules that are off unless `rules.enabled` lists them (see
/// `catalog::OFF_BY_DEFAULT`).
pub(super) static OFF_BY_DEFAULT: &[&str] = &[];

pub(super) static RULES: &[Rule] = &[
    // ---- Bugs ----
    Rule {
        id: "cs/generic-null-comparison",
        name: "Unconstrained type parameters should not be compared to null",
        description: "When T can be a value type, `x == null` is always false for it, so the check doesn't do \
                      what it seems to for every T.",
        message: "Constrain T to a reference type ('where T : class'), or use 'x is null' knowingly.",
        category: Bug,
        severity: Minor,
        effort_minutes: 10,
        sonar: &[exact("S2955")],
        check: Check::Query {
            langs: CSHARP,
            query: "(method_declaration parameters: (parameter_list) body: (_)) @match",
            filter: Some(Find(unconstrained_null_check)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { bool F<T>(T x) { return x == null; } }",
            good: "class A { bool F<T>(T x) where T : class { return x == null; } }",
        }),
    },
    Rule {
        id: "cs/optional-field-without-callbacks",
        name: "[OptionalField] members should get a value when deserialized",
        description: "Data serialized by an older version has no value for an [OptionalField] member; without \
                      an [OnDeserializing] or [OnDeserialized] method to set one, it stays at its default.",
        message: "Add an [OnDeserialized] (or [OnDeserializing]) method that sets this field.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S3926")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration name: (identifier) body: (declaration_list)) @match",
            filter: Some(Find(optional_field_without_callback)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "[Serializable] class P { [OptionalField] int version; }",
            good: "[Serializable] class P { [OptionalField] int version; [OnDeserialized] void Restore(StreamingContext c) { version = 2; } }",
        }),
    },
    Rule {
        id: "cs/accessor-wrong-field",
        name: "Getters and setters should use the field of their property",
        description: "A property `Name` whose accessor reads or writes `count` instead of `name` was probably \
                      copied from another property and not updated.",
        message: "Use the field that belongs to this property.",
        category: Bug,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S4275")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration name: (identifier) body: (declaration_list)) @match",
            filter: Some(Find(accessor_uses_other_field)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int name; int count; public int Name { get { return count; } set { name = value; } } }",
            good: "class A { int name; int count; public int Name { get { return name; } set { name = value; } } }",
        }),
    },
    Rule {
        id: "cs/query-parameter-unsupported-type",
        name: "[SupplyParameterFromQuery] properties should have a supported type",
        description: "Blazor only binds query string values to simple types such as int, string, Guid and \
                      DateTime (and their nullable and array forms); other types fail at run time.",
        message: "Use a type Blazor can read from the query string.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6797")],
        check: Check::Query {
            langs: CSHARP,
            query: "(property_declaration (attribute_list) type: (_) @match)",
            filter: Some(Keep(unsupported_query_parameter)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class P { [Parameter, SupplyParameterFromQuery] public List<int> Ids { get; set; } }",
            good: "class P { [Parameter, SupplyParameterFromQuery] public int[] Ids { get; set; } }",
        }),
    },
    // ---- Vulnerabilities ----
    Rule {
        id: "cs/regex-without-timeout",
        name: "Regular expressions should have a timeout",
        description: "Without a timeout, a crafted input can make a backtracking pattern run for minutes, \
                      blocking a thread per request (ReDoS).",
        message: "Pass a match timeout, or use RegexOptions.NonBacktracking.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6444")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(object_creation_expression arguments: (argument_list)) \
                     (invocation_expression function: (member_access_expression))] @match",
            filter: Some(Keep(regex_without_timeout)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { bool F(string s) { return new Regex(\"(a+)+$\").IsMatch(s); } }",
            good: "class A { bool F(string s) { return new Regex(\"(a+)+$\", RegexOptions.None, TimeSpan.FromSeconds(1)).IsMatch(s); } }",
        }),
    },
    Rule {
        id: "cs/random-secret",
        name: "System.Random should not produce secrets",
        description: "Random is predictable: values derived from it, such as tokens, passwords or salts, can be \
                      guessed. RandomNumberGenerator is made for that.",
        message: "Use RandomNumberGenerator for this value.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 10,
        sonar: &[related("S2245")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(variable_declarator name: (identifier)) (assignment_expression left: (_))] @match",
            filter: Some(Keep(random_feeds_secret)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { string F() { var token = new Random().Next().ToString(); return token; } }",
            good: "class A { string F() { var token = RandomNumberGenerator.GetInt32(int.MaxValue).ToString(); return token; } }",
        }),
    },
    // ---- Code smells ----
    Rule {
        id: "cs/hardcoded-uri",
        name: "URIs and file paths should not be hard-coded",
        description: "An absolute URL or path in the code breaks when the environment changes and can't be \
                      configured per deployment.",
        message: "Move this location to configuration, or build it from a configured base.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 20,
        sonar: &[exact("S1075")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(string_literal) (verbatim_string_literal)] @match",
            filter: Some(Keep(is_hardcoded_location)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F() { var uploadPath = \"/var/data/uploads\"; G(uploadPath); } }",
            good: "class A { void F(IConfiguration c) { var uploadPath = c[\"UploadPath\"]; G(uploadPath); } }",
        }),
    },
    Rule {
        id: "cs/unused-parameter",
        name: "Unused parameters of private methods should be removed",
        description: "A parameter a private method never reads makes every call pass something for nothing.",
        message: "Remove this unused parameter.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1172")],
        check: Check::Query {
            langs: CSHARP,
            query: "(method_declaration parameters: (parameter_list) body: (_)) @match",
            filter: Some(Find(unused_private_parameter)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { public int F() => G(1, 2); private int G(int a, int b) => a; }",
            good: "class A { public int F() => G(1); private int G(int a) => a; }",
        }),
    },
    Rule {
        id: "cs/string-concat-in-loop",
        name: "Strings should not be built with += in a loop",
        description: "Each `+=` copies the whole string, so building one in a loop takes time proportional to \
                      the square of its length. StringBuilder appends in place.",
        message: "Use a StringBuilder to build this string.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 10,
        sonar: &[exact("S1643")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(for_statement body: (_) @b) (foreach_statement body: (_) @b) (while_statement body: (_) @b) (do_statement body: (_) @b)] @match",
            filter: Some(Find(string_appended_in_loop)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { string F(int[] xs) { string s = \"\"; foreach (var x in xs) { s += x; } return s; } }",
            good: "class A { string F(int[] xs) { var sb = new StringBuilder(); foreach (var x in xs) { sb.Append(x); } return sb.ToString(); } }",
        }),
    },
    Rule {
        id: "cs/abstract-class-only-abstract",
        name: "Abstract classes with only abstract members should be interfaces",
        description: "An abstract class without fields or implemented members is an interface that uses up the \
                      single base class a type can have.",
        message: "Turn this abstract class into an interface.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 10,
        sonar: &[related("S1694")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration (modifier) name: (identifier) body: (declaration_list)) @match",
            filter: Some(Find(interface_shaped_abstract_class)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "abstract class Shape { public abstract double Area(); }",
            good: "interface IShape { double Area(); }",
        }),
    },
    Rule {
        id: "cs/test-without-assertion",
        name: "Tests should assert something",
        description: "A test that asserts nothing passes as long as nothing throws, so it doesn't check the \
                      behaviour it's named after.",
        message: "Add an assertion to this test.",
        category: CodeSmell,
        severity: Blocker,
        effort_minutes: 10,
        sonar: &[exact("S2699")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration body: (declaration_list)) @match",
            filter: Some(Find(test_without_assertion)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class T { [Fact] public void Totals() { var cart = new Cart(); cart.Add(3); } }",
            good: "class T { [Fact] public void Totals() { var cart = new Cart(); cart.Add(3); Assert.Equal(3, cart.Total); } }",
        }),
    },
    Rule {
        id: "cs/field-could-be-readonly",
        name: "Private fields only assigned in constructors should be readonly",
        description: "`readonly` documents that the field doesn't change after construction, and the compiler \
                      then makes sure of it.",
        message: "Make this field readonly.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2933")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration name: (identifier) body: (declaration_list)) @match",
            filter: Some(Find(field_only_set_at_construction)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { private int size; public A(int s) { size = s; } public int Size => size; }",
            good: "class A { private readonly int size; public A(int s) { size = s; } public int Size => size; }",
        }),
    },
    Rule {
        id: "cs/optional-overload-collision",
        name: "Optional parameters should not make an overload unreachable",
        description: "When `F(int a, int b = 0)` and `F(int a)` both exist, a call `F(1)` always picks the \
                      second, so the default value is never used.",
        message: "Remove the optional parameter or the overload that hides it.",
        category: CodeSmell,
        severity: Blocker,
        effort_minutes: 10,
        sonar: &[exact("S3427")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(class_declaration body: (declaration_list)) (struct_declaration body: (declaration_list)) \
                     (interface_declaration body: (declaration_list))] @match",
            filter: Some(Find(overload_hides_optional)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(int a) { } void F(int a, int b = 0) { } }",
            good: "class A { void F(int a, int b = 0) { } }",
        }),
    },
    Rule {
        id: "cs/field-never-assigned",
        name: "Private fields should be assigned before they're read",
        description: "A private field that is read but never assigned always holds its default value; the \
                      assignment was forgotten, or the field isn't needed.",
        message: "Assign this field, or replace its uses with the default value.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S3459")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration name: (identifier) body: (declaration_list)) @match",
            filter: Some(Find(field_never_assigned)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { private int limit; public bool Over(int x) => x > limit; }",
            good: "class A { private int limit = 10; public bool Over(int x) => x > limit; }",
        }),
    },
    Rule {
        id: "cs/redundant-field-initializer",
        name: "Fields should not be initialized when every constructor sets them",
        description: "An initializer that every constructor overwrites runs for nothing and misleads readers \
                      about the starting value.",
        message: "Remove this initializer, which every constructor overwrites.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S3604")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration name: (identifier) body: (declaration_list)) @match",
            filter: Some(Find(overwritten_initializer)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int size = 10; public A(int s) { size = s; } }",
            good: "class A { int size; public A(int s) { size = s; } }",
        }),
    },
    Rule {
        id: "cs/iserializable-without-constructor",
        name: "ISerializable types should have a deserialization constructor",
        description: "The serializer calls a constructor taking (SerializationInfo, StreamingContext); without \
                      it, deserialization fails at run time.",
        message: "Add a constructor taking (SerializationInfo info, StreamingContext context).",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[related("S3925")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration (attribute_list) name: (identifier) (base_list)) @match",
            filter: Some(Find(serializable_without_constructor)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "[Serializable] class P : ISerializable { public void GetObjectData(SerializationInfo i, StreamingContext c) { } }",
            good: "[Serializable] class P : ISerializable { protected P(SerializationInfo i, StreamingContext c) { } public void GetObjectData(SerializationInfo i, StreamingContext c) { } }",
        }),
    },
    Rule {
        id: "cs/unbraced-body-not-indented",
        name: "The statement controlled by an unbraced if or loop should be indented",
        description: "A body on the next line at the same indentation as its `if` reads like code that always \
                      runs.",
        message: "Indent this statement under its if or loop, or add braces.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 1,
        sonar: &[exact("S3973")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(if_statement consequence: (_) @b) (for_statement body: (_) @b) \
                     (foreach_statement body: (_) @b) (while_statement body: (_) @b)] @match",
            filter: Some(Find(unindented_body)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(bool b) {\n    if (b)\n    G();\n} }",
            good: "class A { void F(bool b) {\n    if (b)\n        G();\n} }",
        }),
    },
    Rule {
        id: "cs/operator-without-equals",
        name: "Types overloading operators should override Equals",
        description: "A type with its own `==`, `+` or `-` defines what its values mean; without matching \
                      Equals and GetHashCode, collections and LINQ compare them differently.",
        message: "Override Equals and GetHashCode for this type.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S4050")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(class_declaration name: (identifier) body: (declaration_list)) \
                     (struct_declaration name: (identifier) body: (declaration_list))] @match",
            filter: Some(Find(operators_without_equals)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "struct Money { public static Money operator +(Money a, Money b) => a; }",
            good: "struct Money { public static Money operator +(Money a, Money b) => a; public override bool Equals(object o) => false; public override int GetHashCode() => 0; }",
        }),
    },
    Rule {
        id: "cs/iterator-argument-validation",
        name: "Iterator methods should validate their arguments eagerly",
        description: "The body of a `yield` method only runs when the result is enumerated, so its argument \
                      checks throw later, far from the bad call.",
        message: "Move the checks into a non-iterator method that then calls the iterator.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S4456")],
        check: Check::Query {
            langs: CSHARP,
            query: "(method_declaration name: (identifier) body: (block)) @match",
            filter: Some(Find(deferred_validation)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { IEnumerable<int> F(int[] xs) { if (xs == null) { throw new ArgumentNullException(nameof(xs)); } foreach (var x in xs) { yield return x; } } }",
            good: "class A { IEnumerable<int> F(int[] xs) { if (xs == null) { throw new ArgumentNullException(nameof(xs)); } return Iterate(xs); } IEnumerable<int> Iterate(int[] xs) { foreach (var x in xs) { yield return x; } } }",
        }),
    },
    Rule {
        id: "cs/unread-private-field",
        name: "Private fields that are written but never read should be removed",
        description: "A field only ever assigned is dead state: whatever it holds is never used.",
        message: "Remove this field, or use its value.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S4487")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration name: (identifier) body: (declaration_list)) @match",
            filter: Some(Find(field_never_read)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { private int last; public void Set(int x) { last = x; } }",
            good: "class A { private int last; public void Set(int x) { last = x; } public int Last => last; }",
        }),
    },
    Rule {
        id: "cs/debugger-display-unknown-member",
        name: "[DebuggerDisplay] should refer to existing members",
        description: "The debugger shows an error instead of the value when a {placeholder} names a member \
                      the type doesn't have.",
        message: "Name an existing member in this [DebuggerDisplay] placeholder.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S4545")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(class_declaration (attribute_list) body: (declaration_list)) \
                     (struct_declaration (attribute_list) body: (declaration_list))] @match",
            filter: Some(Find(debugger_display_unknown_member)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "[DebuggerDisplay(\"{Nmae}\")] class P { public string Name { get; set; } }",
            good: "[DebuggerDisplay(\"{Name}\")] class P { public string Name { get; set; } }",
        }),
    },
    Rule {
        id: "cs/azure-function-client-recreated",
        name: "Azure Functions should reuse their clients",
        description: "Creating an HttpClient or a storage, Cosmos or Service Bus client on every invocation \
                      exhausts connections under load; create it once and reuse it.",
        message: "Create this client once (a static field or dependency injection) and reuse it.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 15,
        sonar: &[exact("S6420")],
        check: Check::Query {
            langs: CSHARP,
            query: "(method_declaration (attribute_list) body: (_)) @match",
            filter: Some(Find(client_created_per_invocation)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class F { [FunctionName(\"Run\")] public async Task Run() { var http = new HttpClient(); await http.GetAsync(\"https://a.example\"); } }",
            good: "class F { static readonly HttpClient Http = new HttpClient(); [FunctionName(\"Run\")] public async Task Run() { await Http.GetAsync(\"https://a.example\"); } }",
        }),
    },
    Rule {
        id: "cs/azure-function-blocking",
        name: "Azure Functions should not block on async calls",
        description: ".Result and .Wait() hold a thread while the call runs, which starves the Functions host \
                      under load and can deadlock.",
        message: "Make this function async and await the call.",
        category: CodeSmell,
        severity: Blocker,
        effort_minutes: 10,
        sonar: &[exact("S6422")],
        check: Check::Query {
            langs: CSHARP,
            query: "(method_declaration (attribute_list) body: (_)) @match",
            filter: Some(Find(blocking_in_function)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class F { [FunctionName(\"Run\")] public string Run(HttpClient h) { return h.GetStringAsync(\"https://a.example\").Result; } }",
            good: "class F { [FunctionName(\"Run\")] public async Task<string> Run(HttpClient h) { return await h.GetStringAsync(\"https://a.example\"); } }",
        }),
    },
    Rule {
        id: "cs/datetime-without-kind",
        name: "New DateTime values should say their DateTimeKind",
        description: "Without a kind the value is Unspecified, and conversions to and from UTC then guess \
                      which time zone it was in.",
        message: "Pass a DateTimeKind (Utc or Local) to this constructor.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6562")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(object_creation_expression type: (_) @t arguments: (argument_list)
                        (#match? @t "^(System\\.)?DateTime$")) @match"#,
            filter: Some(Keep(date_without_kind)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { DateTime F() { return new DateTime(2024, 1, 31); } }",
            good: "class A { DateTime F() { return new DateTime(2024, 1, 31, 0, 0, 0, DateTimeKind.Utc); } }",
        }),
    },
    Rule {
        id: "cs/parse-without-culture",
        name: "Dates should be parsed with a format provider",
        description: "Without one, parsing uses the current culture, so the same string means another date (or \
                      fails) on a machine with other regional settings.",
        message: "Pass a format provider such as CultureInfo.InvariantCulture.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6580")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(invocation_expression
                        function: (member_access_expression expression: (_) @t name: (identifier) @n)
                        (#match? @t "^(System\\.)?(DateTime|DateTimeOffset|DateOnly|TimeOnly|TimeSpan)$")
                        (#any-of? @n "Parse" "TryParse")) @match"#,
            filter: Some(Keep(parses_without_provider)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { DateTime F(string s) { return DateTime.Parse(s); } }",
            good: "class A { DateTime F(string s) { return DateTime.Parse(s, CultureInfo.InvariantCulture); } }",
        }),
    },
    Rule {
        id: "cs/too-many-log-calls",
        name: "Blocks should not contain too many logging calls",
        description: "More than four logging calls in one block drown the code it logs, and usually log the \
                      same thing several ways.",
        message: "Reduce the logging calls in this block to four or fewer.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 10,
        sonar: &[exact("S6664")],
        check: Check::Query {
            langs: CSHARP,
            query: "(block) @match",
            filter: Some(Find(fifth_log_call)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(ILogger log) { log.LogInformation(\"a\"); log.LogInformation(\"b\"); log.LogInformation(\"c\"); log.LogInformation(\"d\"); log.LogInformation(\"e\"); } }",
            good: "class A { void F(ILogger log) { log.LogInformation(\"a\"); log.LogInformation(\"b\"); } }",
        }),
    },
    Rule {
        id: "cs/exception-as-template-argument",
        name: "Exceptions should be passed to the logger as the exception argument",
        description: "An exception passed after the message template is only formatted into the text; the \
                      logger's exception parameter keeps its type and stack trace.",
        message: "Pass the exception as the first argument, before the message template.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6668")],
        check: Check::Query {
            langs: CSHARP,
            query: "(catch_clause (catch_declaration name: (identifier)) body: (block)) @match",
            filter: Some(Find(exception_after_template)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(ILogger log) { try { G(); } catch (IOException e) { log.LogError(\"Failed: {Error}\", e); } } }",
            good: "class A { void F(ILogger log) { try { G(); } catch (IOException e) { log.LogError(e, \"Failed\"); } } }",
        }),
    },
    Rule {
        id: "cs/raw-request-data-in-controller",
        name: "Controllers should use model binding instead of reading the raw request",
        description: "Reading Request.Form, Query or RouteValues by hand skips validation, type conversion and \
                      API descriptions, which model binding gives for free.",
        message: "Bind this value through an action parameter instead.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S6932")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration name: (identifier) (base_list) body: (declaration_list)) @match",
            filter: Some(Find(raw_request_read)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class OrdersController : ControllerBase { [HttpGet] public IActionResult Find() { var id = Request.Query[\"id\"]; return Ok(id); } }",
            good: "class OrdersController : ControllerBase { [HttpGet] public IActionResult Find([FromQuery] int id) { return Ok(id); } }",
        }),
    },
];

// ---------------------------------------------------- helpers

/// A private field: (name, field declaration, declarator). Fields with
/// attributes are left out: serializers and frameworks set and read them.
fn plain_private_fields<'s, 't>(
    class: Node<'t>,
    src: &'s [u8],
) -> Vec<(&'s [u8], Node<'t>, Node<'t>)> {
    members(class)
        .into_iter()
        .filter(|m| {
            m.kind() == "field_declaration"
                && !["public", "protected", "internal", "const"]
                    .iter()
                    .any(|x| cs_has_modifier(*m, x, src))
                && attribute_names(*m, src).is_empty()
        })
        .flat_map(|m| {
            declarators(m)
                .into_iter()
                .filter_map(move |d| d.child_by_field_name("name").map(|n| (text(n, src), m, d)))
        })
        .collect()
}

/// Whether `n` changes the field `name`: an assignment to it (`name = ...`,
/// `this.name += ...`), an increment, or passing it by `ref` or `out`.
fn writes_field(n: Node, name: &[u8], src: &[u8]) -> bool {
    let is_target = |t: Node| {
        let t = text(t, src);
        t == name || t.strip_prefix(b"this.") == Some(name)
    };
    match n.kind() {
        // `(a, b) = F()` writes each element.
        "assignment_expression" => n.child_by_field_name("left").is_some_and(|l| {
            is_target(l)
                || l.kind() == "tuple_expression" && {
                    let mut cursor = l.walk();
                    l.named_children(&mut cursor)
                        .any(|a| a.named_child(0).is_some_and(is_target))
                }
        }),
        "postfix_unary_expression" | "prefix_unary_expression" => {
            let t = text(n, src);
            (t.starts_with(b"++")
                || t.starts_with(b"--")
                || t.ends_with(b"++")
                || t.ends_with(b"--"))
                && operand(n).is_some_and(is_target)
        }
        "argument" => {
            let t = text(n, src);
            [&b"ref "[..], b"out ", b"in "].iter().any(|p| {
                t.strip_prefix(*p).is_some_and(|rest| {
                    rest.trim_ascii() == name
                        || rest.trim_ascii().strip_prefix(b"this.") == Some(name)
                })
            })
        }
        _ => false,
    }
}

/// Whether a class can be judged from its own text: not partial and without
/// parse errors (an #if splitting it hides part of it).
fn self_contained(class: Node, src: &[u8]) -> bool {
    !class.has_error() && !cs_has_modifier(class, "partial", src)
}

// ---------------------------------------------------- filters

fn unconstrained_null_check<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    // Type parameters of the method and of its class, with their constraints.
    let mut parameters: Vec<&[u8]> = Vec::new();
    let mut constrained: Vec<&[u8]> = Vec::new();
    let mut owners = vec![method];
    owners.extend(enclosing_type(method));
    for owner in owners {
        let mut cursor = owner.walk();
        for child in owner.named_children(&mut cursor) {
            match child.kind() {
                "type_parameter_list" => {
                    let mut c = child.walk();
                    parameters.extend(
                        child
                            .named_children(&mut c)
                            .filter(|p| p.kind() == "type_parameter")
                            .filter_map(|p| p.child_by_field_name("name").map(|n| text(n, src))),
                    );
                }
                "type_parameter_constraints_clause" => {
                    let t = text(child, src);
                    let reference = [&b"class"[..], b"struct", b"unmanaged"]
                        .iter()
                        .any(|k| count_word(t, k) > 0);
                    if reference {
                        let mut c = child.walk();
                        constrained
                            .extend(child.named_children(&mut c).next().map(|n| text(n, src)));
                    }
                }
                _ => {}
            }
        }
    }
    let free: Vec<&[u8]> = parameters
        .into_iter()
        .filter(|p| !constrained.contains(p))
        .collect();
    if free.is_empty() {
        return None;
    }
    let params = method.child_by_field_name("parameters")?;
    let mut cursor = params.walk();
    let values: Vec<&[u8]> = params
        .named_children(&mut cursor)
        .filter(|p| {
            p.child_by_field_name("type")
                .is_some_and(|t| free.contains(&text(t, src)))
        })
        .filter_map(|p| p.child_by_field_name("name").map(|n| text(n, src)))
        .collect();
    if values.is_empty() {
        return None;
    }
    let body = method.child_by_field_name("body")?;
    find_in_scope(body, CS_SCOPE_STOPS, |n| {
        n.kind() == "binary_expression" && matches!(operator_text(n, src), b"==" | b"!=") && {
            let side = |f: &str| n.child_by_field_name(f);
            let is_null = |x: Option<Node>| x.is_some_and(|x| x.kind() == "null_literal");
            let is_value = |x: Option<Node>| x.is_some_and(|x| values.contains(&text(x, src)));
            (is_null(side("left")) && is_value(side("right")))
                || (is_value(side("left")) && is_null(side("right")))
        }
    })
}

fn optional_field_without_callback<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let ms = members(class);
    let has_callback = ms.iter().any(|m| {
        attribute_names(*m, src)
            .iter()
            .any(|(_, n)| matches!(*n, b"OnDeserializing" | b"OnDeserialized"))
    });
    if has_callback {
        return None;
    }
    ms.into_iter()
        .filter(|m| {
            m.kind() == "field_declaration" && find_attribute(*m, "OptionalField", src).is_some()
        })
        .flat_map(declarators)
        .next()
}

/// The field a property's name points to: `name`, `_name` or `m_name`.
fn matching_field<'s>(property: &[u8], fields: &[&'s [u8]]) -> Option<&'s [u8]> {
    let wanted = property.to_ascii_lowercase();
    fields.iter().copied().find(|f| {
        let f = f.to_ascii_lowercase();
        let f = f
            .strip_prefix(b"m_")
            .or_else(|| f.strip_prefix(b"_"))
            .unwrap_or(&f)
            .to_vec();
        f == wanted
    })
}

fn accessor_uses_other_field<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let fields: Vec<&[u8]> = members(class)
        .into_iter()
        .filter(|m| m.kind() == "field_declaration")
        .flat_map(declarators)
        .filter_map(|d| d.child_by_field_name("name").map(|n| text(n, src)))
        .collect();
    members(class)
        .into_iter()
        .filter(|m| m.kind() == "property_declaration")
        .find_map(|p| {
            let own = matching_field(text(p.child_by_field_name("name")?, src), &fields)?;
            let accessors = p.child_by_field_name("accessors")?;
            let mut cursor = accessors.walk();
            let list: Vec<Node<'t>> = accessors
                .named_children(&mut cursor)
                .filter(|a| a.kind() == "accessor_declaration")
                .collect();
            list.into_iter().find_map(|a| {
                let body = a.child_by_field_name("body")?;
                let expr = match body.kind() {
                    "arrow_expression_clause" => operand(body)?,
                    // `return f;` in a getter, `f = value;` in a setter; not
                    // `lock (sync) { ... }`, whose first child is the lock object.
                    "block" => match cs_statements(body).as_slice() {
                        [s] if matches!(s.kind(), "return_statement" | "expression_statement") => {
                            operand(*s)?
                        }
                        _ => return None,
                    },
                    _ => return None,
                };
                let used = match a.child_by_field_name("name").map(|k| text(k, src)) {
                    Some(b"get") => expr,
                    Some(b"set" | b"init") if expr.kind() == "assignment_expression" => {
                        expr.child_by_field_name("left")?
                    }
                    _ => return None,
                };
                let name = text(used, src);
                let name = name.strip_prefix(b"this.").unwrap_or(name);
                (fields.contains(&name) && name != own).then_some(used)
            })
        })
}

fn unsupported_query_parameter(ty: Node, src: &[u8]) -> bool {
    let Some(property) = ty.parent() else {
        return false;
    };
    if find_attribute(property, "SupplyParameterFromQuery", src).is_none() {
        return false;
    }
    let t = text(ty, src);
    let t = t.strip_suffix(b"[]").unwrap_or(t);
    let t = t.strip_suffix(b"?").unwrap_or(t);
    !matches!(
        t,
        b"bool"
            | b"DateTime"
            | b"decimal"
            | b"double"
            | b"float"
            | b"Guid"
            | b"int"
            | b"long"
            | b"string"
            | b"DateOnly"
            | b"TimeOnly"
            | b"Boolean"
            | b"Decimal"
            | b"Double"
            | b"Single"
            | b"Int32"
            | b"Int64"
            | b"String"
    )
}

fn regex_without_timeout(node: Node, src: &[u8]) -> bool {
    let args = cs_call_arguments(node);
    let non_backtracking = args
        .iter()
        .any(|a| contains_ignoring_case(text(*a, src), b"NonBacktracking"));
    if non_backtracking {
        return false;
    }
    if node.kind() == "object_creation_expression" {
        let is_regex = node
            .child_by_field_name("type")
            .is_some_and(|t| simple_name(t, src) == b"Regex");
        // new Regex(pattern[, options[, timeout]])
        return is_regex && !args.is_empty() && args.len() < 3;
    }
    let Some(function) = node.child_by_field_name("function") else {
        return false;
    };
    let receiver = function
        .child_by_field_name("expression")
        .map(|e| simple_name(e, src));
    if receiver != Some(b"Regex") {
        return false;
    }
    let method = function
        .child_by_field_name("name")
        .map_or(&b""[..], |n| text(n, src));
    // Regex.Replace(input, pattern, replacement[, options[, timeout]]);
    // the others (input, pattern[, options[, timeout]]).
    match method {
        b"IsMatch" | b"Match" | b"Matches" | b"Split" | b"Count" | b"EnumerateMatches" => {
            args.len() >= 2 && args.len() < 4
        }
        b"Replace" => args.len() >= 3 && args.len() < 5,
        _ => false,
    }
}

const SECRET_WORDS: &[&[u8]] = &[
    b"token",
    b"password",
    b"secret",
    b"salt",
    b"nonce",
    b"otp",
    b"apikey",
    b"api_key",
    b"pin",
    b"key",
];

fn random_feeds_secret(node: Node, src: &[u8]) -> bool {
    let (name, value) = if node.kind() == "variable_declarator" {
        let name = node.child_by_field_name("name");
        let mut cursor = node.walk();
        let value = node
            .named_children(&mut cursor)
            .filter(|c| Some(*c) != name)
            .last();
        (name, value)
    } else {
        if operator_text(node, src) != b"=" {
            return false;
        }
        (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        )
    };
    let (Some(name), Some(value)) = (name, value) else {
        return false;
    };
    let lowered = text(name, src).to_ascii_lowercase();
    let secret = SECRET_WORDS.iter().any(|w| {
        // `key` alone or as a word end ("apiKey", "privateKey"), not "keyboard".
        if *w == b"key" || *w == b"pin" {
            lowered.ends_with(w)
        } else {
            lowered.windows(w.len()).any(|x| x == *w)
        }
    });
    let v = text(value, src);
    secret
        && (v.windows(10).any(|x| x == b"new Random")
            || v.windows(13).any(|x| x == b"Random.Shared"))
        && !v.windows(21).any(|x| x == b"RandomNumberGenerator")
}

fn is_hardcoded_location(literal: Node, src: &[u8]) -> bool {
    let Some(value) = cs_string_value(literal, src) else {
        return false;
    };
    let is_uri = value.windows(3).any(|w| w == b"://")
        && !value.starts_with(b"http://localhost")
        && !value.starts_with(b"https://localhost");
    let is_path = (value.len() > 3 && value[1] == b':' && matches!(value[2], b'\\' | b'/') && value[0].is_ascii_alphabetic())
        // Unix paths under a filesystem root; "/Account/Login" is a route.
        || ([&b"/var/"[..], b"/usr/", b"/etc/", b"/home/", b"/opt/", b"/srv/", b"/mnt/", b"/tmp/", b"/Users/", b"/data/"]
            .iter()
            .any(|root| value.starts_with(root)))
        || value.starts_with(b"\\\\");
    if !(is_uri || is_path) || value.contains(&b'{') {
        return false;
    }
    // Only when the code says it's a location: assigned to, or passed as, a
    // name such as `url`, `uri`, `path`, `file`, `folder` or `dir`.
    let location = |n: &[u8]| {
        let l = n.to_ascii_lowercase();
        [&b"url"[..], b"uri", b"path", b"file", b"folder", b"dir"]
            .iter()
            .any(|w| l.windows(w.len()).any(|x| x == *w))
    };
    let Some(parent) = literal.parent() else {
        return false;
    };
    let name = match parent.kind() {
        "variable_declarator" => parent.child_by_field_name("name"),
        "assignment_expression" => parent.child_by_field_name("left"),
        "argument" => parent.child_by_field_name("name"),
        _ => None,
    };
    // Constants are already named and in one place.
    let in_const = parent
        .parent()
        .and_then(|d| d.parent())
        .is_some_and(|f| f.kind() == "field_declaration" && cs_has_modifier(f, "const", src));
    name.is_some_and(|n| location(text(n, src))) && !in_const
}

fn unused_private_parameter<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let private = cs_has_modifier(method, "private", src)
        || !["public", "protected", "internal"]
            .iter()
            .any(|m| cs_has_modifier(method, m, src));
    let special = ["override", "virtual", "abstract", "extern", "partial"]
        .iter()
        .any(|m| cs_has_modifier(method, m, src));
    let mut cursor = method.walk();
    let explicit = method
        .named_children(&mut cursor)
        .any(|c| matches!(c.kind(), "explicit_interface_specifier" | "attribute_list"));
    // Main's args are the runtime's signature.
    let is_main = method
        .child_by_field_name("name")
        .is_some_and(|n| text(n, src) == b"Main");
    if !private || special || explicit || is_main || method.has_error() {
        return None;
    }
    // A class member only: interface members and local functions differ.
    let declaration = method.parent()?.parent()?;
    if !matches!(
        declaration.kind(),
        "class_declaration" | "struct_declaration" | "record_declaration"
    ) {
        return None;
    }
    let body = method.child_by_field_name("body")?;
    let body_text = text(body, src);
    // A method that only throws is a stub; its parameters are its signature.
    if body.kind() == "block"
        && matches!(cs_statements(body).as_slice(), [s] if s.kind() == "throw_statement")
        || body.kind() == "arrow_expression_clause"
            && operand(body).is_some_and(|e| e.kind() == "throw_expression")
    {
        return None;
    }
    let params = method.child_by_field_name("parameters")?;
    let mut c = params.walk();
    let list: Vec<Node<'t>> = params
        .named_children(&mut c)
        .filter(|p| p.kind() == "parameter")
        .collect();
    // (object sender, EventArgs e) is the shape events require.
    let handler = list.len() == 2
        && list[1]
            .child_by_field_name("type")
            .is_some_and(|t| simple_name(t, src).ends_with(b"Args"));
    if handler {
        return None;
    }
    list.into_iter().find_map(|p| {
        let name = p.child_by_field_name("name")?;
        let n = text(name, src);
        let this_parameter = text(p, src).starts_with(b"this ");
        (!n.starts_with(b"_") && !this_parameter && count_word(body_text, n) == 0).then_some(name)
    })
}

fn string_appended_in_loop<'t>(loop_node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    // Strings declared in the enclosing member, before the loop.
    let mut owner = loop_node.parent();
    for _ in 0..64 {
        match owner {
            Some(n)
                if matches!(
                    n.kind(),
                    "method_declaration"
                        | "accessor_declaration"
                        | "constructor_declaration"
                        | "local_function_statement"
                        | "lambda_expression"
                ) =>
            {
                break;
            }
            Some(n) => owner = n.parent(),
            None => return None,
        }
    }
    let owner = owner?;
    let strings: Vec<&[u8]> = {
        let mut out = Vec::new();
        let body = owner.child_by_field_name("body")?;
        // Declarations before the loop, outside nested functions.
        let mut stack = vec![body];
        while let Some(n) = stack.pop() {
            if n.start_byte() >= loop_node.start_byte() {
                continue;
            }
            if n.kind() == "variable_declaration"
                && n.child_by_field_name("type")
                    .is_some_and(|t| text(t, src) == b"string")
            {
                let mut c = n.walk();
                out.extend(
                    n.named_children(&mut c)
                        .filter(|d| d.kind() == "variable_declarator")
                        .filter_map(|d| d.child_by_field_name("name").map(|x| text(x, src))),
                );
            }
            if CS_SCOPE_STOPS.contains(&n.kind()) && n != body {
                continue;
            }
            let mut c = n.walk();
            stack.extend(n.named_children(&mut c));
        }
        out
    };
    if strings.is_empty() {
        return None;
    }
    let body = loop_node.child_by_field_name("body")?;
    find_in_scope(body, CS_SCOPE_STOPS, |n| {
        n.kind() == "assignment_expression"
            && n.child_by_field_name("left")
                .is_some_and(|l| strings.contains(&text(l, src)))
            && (operator_text(n, src) == b"+="
                || operator_text(n, src) == b"="
                    && n.child_by_field_name("right").is_some_and(|r| {
                        r.kind() == "binary_expression"
                            && operator_text(r, src) == b"+"
                            && n.child_by_field_name("left")
                                .is_some_and(|l| text(r, src).starts_with(text(l, src)))
                    }))
    })
}

fn interface_shaped_abstract_class<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut cursor = class.walk();
    let derives = class
        .named_children(&mut cursor)
        .any(|c| c.kind() == "base_list");
    if !cs_has_modifier(class, "abstract", src) || derives {
        return None;
    }
    let ms = members(class);
    let all_abstract = !ms.is_empty()
        && ms.iter().all(|m| {
            matches!(
                m.kind(),
                "method_declaration"
                    | "property_declaration"
                    | "event_declaration"
                    | "indexer_declaration"
            ) && cs_has_modifier(*m, "abstract", src)
                && cs_has_modifier(*m, "public", src)
        });
    all_abstract.then(|| class.child_by_field_name("name"))?
}

const ASSERTION_WORDS: &[&[u8]] = &[
    b"assert",
    b"should",
    b"verify",
    b"expect",
    b"throws",
    b"received",
    b"fail",
    b"approve",
    b"snapshot",
    b"match",
];

fn mentions_assertion(t: &[u8]) -> bool {
    let lower = t.to_ascii_lowercase();
    ASSERTION_WORDS
        .iter()
        .any(|w| lower.windows(w.len()).any(|x| x == *w))
}

fn test_without_assertion<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if class.has_error() {
        return None;
    }
    let ms = members(class);
    // Helpers in the class that assert, called by name from a test, count.
    let asserting_helpers: Vec<&[u8]> = ms
        .iter()
        .filter(|m| m.kind() == "method_declaration" && !is_test_method(**m, src))
        .filter(|m| {
            m.child_by_field_name("body")
                .is_some_and(|b| mentions_assertion(text(b, src)))
        })
        .filter_map(|m| m.child_by_field_name("name").map(|n| text(n, src)))
        .collect();
    ms.into_iter().find_map(|m| {
        if m.kind() != "method_declaration" || !is_test_method(m, src) {
            return None;
        }
        // [ExpectedException] is the assertion.
        if attribute_names(m, src)
            .iter()
            .any(|(_, n)| *n == b"ExpectedException")
        {
            return None;
        }
        let body = text(m.child_by_field_name("body")?, src);
        let asserts =
            mentions_assertion(body) || asserting_helpers.iter().any(|h| count_word(body, h) > 0);
        (!asserts).then(|| m.child_by_field_name("name"))?
    })
}

fn field_only_set_at_construction<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !self_contained(class, src) {
        return None;
    }
    let body = class.child_by_field_name("body")?;
    plain_private_fields(class, src)
        .into_iter()
        .find_map(|(name, field, declarator)| {
            if cs_has_modifier(field, "readonly", src) || cs_has_modifier(field, "volatile", src) {
                return None;
            }
            // A readonly field of a mutable struct makes every call on it work on
            // a copy, which changes behaviour (a lazy value never caches, say).
            // Without types, only suggest it for types known to be safe.
            let mut fc = field.walk();
            let ty = field
                .named_children(&mut fc)
                .find(|c| c.kind() == "variable_declaration")
                .and_then(|d| d.child_by_field_name("type"))?;
            if !is_reference_like(ty, src) {
                return None;
            }
            let is_static = cs_has_modifier(field, "static", src);
            // Writes anywhere but in the matching constructors. Lambdas inside a
            // constructor can run later, so they count as anywhere.
            let in_constructor = |n: Node| {
                let mut current = n.parent();
                for _ in 0..64 {
                    match current {
                        Some(c) if c.kind() == "constructor_declaration" => {
                            return cs_has_modifier(c, "static", src) == is_static;
                        }
                        Some(c)
                            if matches!(
                                c.kind(),
                                "lambda_expression"
                                    | "anonymous_method_expression"
                                    | "local_function_statement"
                                    | "method_declaration"
                                    | "accessor_declaration"
                            ) =>
                        {
                            return false;
                        }
                        Some(c) => current = c.parent(),
                        None => return false,
                    }
                }
                false
            };
            let written_elsewhere = find_in_scope(body, &[], |n| {
                writes_field(n, name, src) && !in_constructor(n)
            })
            .is_some();
            let written_in_constructor = find_in_scope(body, &[], |n| {
                writes_field(n, name, src) && in_constructor(n)
            })
            .is_some();
            let initialized = declarator.named_child_count() > 1;
            (!written_elsewhere && (written_in_constructor || initialized))
                .then(|| declarator.child_by_field_name("name"))?
        })
}

/// Types whose fields can be readonly without copies: built-in types,
/// strings, arrays, interfaces and the common collections and delegates.
fn is_reference_like(ty: Node, src: &[u8]) -> bool {
    let name = simple_name(ty, src);
    match ty.kind() {
        "predefined_type" | "array_type" => true,
        "nullable_type" => false,
        _ => {
            (name.len() > 1 && name[0] == b'I' && name[1].is_ascii_uppercase())
                || matches!(
                    name,
                    b"List"
                        | b"Dictionary"
                        | b"HashSet"
                        | b"Queue"
                        | b"Stack"
                        | b"ConcurrentDictionary"
                        | b"ConcurrentQueue"
                        | b"StringBuilder"
                        | b"Func"
                        | b"Action"
                        | b"Task"
                        | b"object"
                        | b"string"
                        | b"Type"
                        | b"Regex"
                        | b"Random"
                        | b"Lazy"
                        | b"SemaphoreSlim"
                        | b"CancellationTokenSource"
                        | b"HttpClient"
                        | b"Stopwatch"
                )
        }
    }
}

fn parameter_types<'s>(method: Node, src: &'s [u8]) -> Vec<(&'s [u8], bool)> {
    let Some(params) = method.child_by_field_name("parameters") else {
        return Vec::new();
    };
    let mut cursor = params.walk();
    params
        .named_children(&mut cursor)
        .filter(|p| p.kind() == "parameter")
        .map(|p| {
            let ty = p
                .child_by_field_name("type")
                .map_or(&b""[..], |t| text(t, src));
            // `int b = 0`; `out bool x` has three named children but no default.
            let optional = text(p, src).contains(&b'=');
            (ty, optional)
        })
        .collect()
}

fn overload_hides_optional<'t>(declaration: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let methods: Vec<Node<'t>> = members(declaration)
        .into_iter()
        .filter(|m| {
            m.kind() == "method_declaration" && m.child_by_field_name("type_parameters").is_none()
        })
        .collect();
    for m in &methods {
        let name = text(m.child_by_field_name("name")?, src);
        let params = parameter_types(*m, src);
        let required: Vec<&[u8]> = params.iter().filter(|(_, o)| !o).map(|(t, _)| *t).collect();
        if required.len() == params.len() {
            continue;
        }
        let hidden = methods.iter().any(|other| {
            other != m
                && other
                    .child_by_field_name("name")
                    .is_some_and(|n| text(n, src) == name)
                && {
                    let o = parameter_types(*other, src);
                    o.iter().all(|(_, opt)| !opt)
                        && o.iter().map(|(t, _)| *t).collect::<Vec<_>>() == required
                }
        });
        if hidden {
            return m.child_by_field_name("name");
        }
    }
    None
}

fn field_never_assigned<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !self_contained(class, src) || class.kind() == "struct_declaration" {
        return None;
    }
    let body = class.child_by_field_name("body")?;
    let whole = text(class, src);
    plain_private_fields(class, src)
        .into_iter()
        .find_map(|(name, _, declarator)| {
            let initialized = declarator.named_child_count() > 1;
            if initialized {
                return None;
            }
            let written = find_in_scope(body, &[], |n| writes_field(n, name, src)).is_some();
            // Read at least once besides its declaration.
            let read = count_word(whole, name) > 1;
            (!written && read).then(|| declarator.child_by_field_name("name"))?
        })
}

fn overwritten_initializer<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !self_contained(class, src) {
        return None;
    }
    let ms = members(class);
    let constructors: Vec<Node<'t>> = ms
        .iter()
        .copied()
        .filter(|m| m.kind() == "constructor_declaration" && !cs_has_modifier(*m, "static", src))
        .collect();
    if constructors.is_empty() {
        return None;
    }
    // A constructor chaining to `this(...)` sets nothing itself; skip those
    // classes rather than follow the chain.
    let chains = constructors.iter().any(|c| {
        let mut cursor = c.walk();
        c.named_children(&mut cursor).any(|x| {
            x.kind() == "constructor_initializer"
                && text(x, src).trim_ascii_start().starts_with(b": this")
        })
    });
    if chains {
        return None;
    }
    plain_private_fields(class, src)
        .into_iter()
        .find_map(|(name, field, declarator)| {
            if cs_has_modifier(field, "static", src) || declarator.named_child_count() < 2 {
                return None;
            }
            // Every constructor assigns it in a top-level statement.
            let always = constructors.iter().all(|c| {
                c.child_by_field_name("body").is_some_and(|b| {
                    cs_statements(b).iter().any(|s| {
                        operand(*s).is_some_and(|e| {
                            writes_field(e, name, src) && operator_text(e, src) == b"="
                        })
                    })
                })
            });
            always.then(|| declarator.child_by_field_name("name"))?
        })
}

fn serializable_without_constructor<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_attribute(class, "Serializable", src)?;
    let mut cursor = class.walk();
    let implements = class
        .named_children(&mut cursor)
        .filter(|c| c.kind() == "base_list")
        .any(|b| count_word(text(b, src), b"ISerializable") > 0);
    if !implements {
        return None;
    }
    let has_constructor = members(class).iter().any(|m| {
        m.kind() == "constructor_declaration"
            && m.child_by_field_name("parameters")
                .is_some_and(|p| count_word(text(p, src), b"SerializationInfo") > 0)
    });
    (!has_constructor).then(|| class.child_by_field_name("name"))?
}

/// The indentation of the line a node starts on, so an `else if` is measured
/// from the `else`, not from the `if` in the middle of the line.
pub(super) fn line_indent(node: Node, src: &[u8]) -> usize {
    let start = node.start_byte();
    let line_start = src[..start]
        .iter()
        .rposition(|&b| b == b'\n')
        .map_or(0, |i| i + 1);
    src[line_start..start]
        .iter()
        .take_while(|b| **b == b' ' || **b == b'\t')
        .count()
}

fn unindented_body<'t>(control: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let field = if control.kind() == "if_statement" {
        "consequence"
    } else {
        "body"
    };
    let body = control.child_by_field_name(field)?;
    // An #if directive between the header and the body is laid out apart.
    (body.kind() != "block"
        && !body.kind().starts_with("preproc")
        && body.start_position().row > control.start_position().row
        && body.start_position().column <= line_indent(control, src))
    .then_some(body)
}

fn operators_without_equals<'t>(declaration: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let ms = members(declaration);
    let overloads = ms.iter().any(|m| {
        m.kind() == "operator_declaration" && {
            let mut cursor = m.walk();
            m.children(&mut cursor)
                .any(|c| !c.is_named() && matches!(text(c, src), b"==" | b"+" | b"-"))
        }
    });
    let equals = ms.iter().any(|m| {
        m.kind() == "method_declaration"
            && cs_has_modifier(*m, "override", src)
            && m.child_by_field_name("name")
                .is_some_and(|n| text(n, src) == b"Equals")
    });
    (overloads && !equals).then(|| declaration.child_by_field_name("name"))?
}

fn deferred_validation<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let body = method.child_by_field_name("body")?;
    let yields = find_in_scope(body, CS_SCOPE_STOPS, |n| n.kind() == "yield_statement").is_some();
    if !yields || cs_has_modifier(method, "async", src) {
        return None;
    }
    // A top-level `if (...) throw new Argument...Exception(...)` before the
    // first yield.
    cs_statements(body)
        .into_iter()
        .take_while(|s| {
            find_in_scope(*s, CS_SCOPE_STOPS, |n| n.kind() == "yield_statement").is_none()
        })
        .find_map(|s| {
            if s.kind() != "if_statement" {
                return None;
            }
            find_in_scope(s, CS_SCOPE_STOPS, |n| {
                matches!(n.kind(), "throw_statement" | "throw_expression")
                    && operand(n).is_some_and(|c| {
                        c.child_by_field_name("type")
                            .is_some_and(|t| simple_name(t, src).starts_with(b"Argument"))
                    })
            })
        })
}

fn field_never_read<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !self_contained(class, src) {
        return None;
    }
    let body = class.child_by_field_name("body")?;
    let whole = text(class, src);
    plain_private_fields(class, src)
        .into_iter()
        .find_map(|(name, field, declarator)| {
            // A field that holds a disposable or a timer may be there to keep it alive.
            let ty = field
                .named_children(&mut field.walk())
                .find(|c| c.kind() == "variable_declaration")
                .and_then(|d| d.child_by_field_name("type"))
                .map_or(&b""[..], |t| simple_name(t, src));
            if matches!(
                ty,
                b"Timer" | b"GCHandle" | b"CancellationTokenRegistration"
            ) {
                return None;
            }
            // Every occurrence besides the declaration is a plain assignment target.
            let occurrences = count_word(whole, name);
            let mut writes = 0;
            let mut stack = vec![body];
            while let Some(n) = stack.pop() {
                if n.kind() == "assignment_expression"
                    && operator_text(n, src) == b"="
                    && n.child_by_field_name("left").is_some_and(|l| {
                        let t = text(l, src);
                        t == name || t.strip_prefix(b"this.") == Some(name)
                    })
                {
                    writes += 1;
                }
                let mut c = n.walk();
                stack.extend(n.named_children(&mut c));
            }
            (writes > 0 && occurrences == writes + 1)
                .then(|| declarator.child_by_field_name("name"))?
        })
}

fn debugger_display_unknown_member<'t>(declaration: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let attribute = find_attribute(declaration, "DebuggerDisplay", src)?;
    let (_, value) = attribute_arguments(attribute).into_iter().next()?;
    let display = cs_string_value(value, src)?;
    let body = text(declaration.child_by_field_name("body")?, src);
    let mut i = 0;
    while let Some(open) = display[i..].iter().position(|&b| b == b'{').map(|p| p + i) {
        let close = display[open..].iter().position(|&b| b == b'}')? + open;
        let inner = &display[open + 1..close];
        let name: Vec<u8> = inner
            .iter()
            .copied()
            .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
            .collect();
        // `{GetType().Name}` or `{x,nq}`: only plain names are checked; a
        // name may also come from a base class, which isn't visible here.
        if !name.is_empty() && !name[0].is_ascii_digit() && count_word(body, &name) == 0 {
            let mut cursor = declaration.walk();
            let derives = declaration
                .named_children(&mut cursor)
                .any(|c| c.kind() == "base_list");
            if !derives {
                return Some(value);
            }
        }
        i = close + 1;
    }
    None
}

pub(super) fn is_azure_function(method: Node, src: &[u8]) -> bool {
    attribute_names(method, src)
        .iter()
        .any(|(_, n)| matches!(*n, b"FunctionName" | b"Function"))
}

const CLIENT_TYPES: &[&[u8]] = &[
    b"HttpClient",
    b"CosmosClient",
    b"DocumentClient",
    b"BlobServiceClient",
    b"BlobContainerClient",
    b"QueueClient",
    b"TableClient",
    b"ServiceBusClient",
    b"EventHubProducerClient",
    b"SecretClient",
    b"CloudStorageAccount",
];

fn client_created_per_invocation<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !is_azure_function(method, src) {
        return None;
    }
    let body = method.child_by_field_name("body")?;
    find_in_scope(body, CS_SCOPE_STOPS, |n| {
        n.kind() == "object_creation_expression"
            && n.child_by_field_name("type")
                .is_some_and(|t| CLIENT_TYPES.contains(&simple_name(t, src)))
    })
}

fn blocking_in_function<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !is_azure_function(method, src) {
        return None;
    }
    let body = method.child_by_field_name("body")?;
    find_in_scope(body, CS_SCOPE_STOPS, |n| match n.kind() {
        "member_access_expression" => {
            n.child_by_field_name("name")
                .is_some_and(|m| text(m, src) == b"Result")
                && !n
                    .parent()
                    .is_some_and(|p| p.kind() == "invocation_expression")
        }
        "invocation_expression" => n
            .child_by_field_name("function")
            .and_then(|f| f.child_by_field_name("name"))
            .is_some_and(|m| matches!(text(m, src), b"Wait" | b"WaitAll" | b"GetResult")),
        _ => false,
    })
}

fn date_without_kind(creation: Node, src: &[u8]) -> bool {
    let args = cs_call_arguments(creation);
    // new DateTime() is MinValue, and a Calendar argument is about something else.
    !args.is_empty()
        && args.len() >= 3
        && !args.iter().any(|a| {
            let t = text(*a, src);
            contains_ignoring_case(t, b"DateTimeKind") || contains_ignoring_case(t, b"Calendar")
        })
}

fn parses_without_provider(call: Node, src: &[u8]) -> bool {
    let method = call
        .child_by_field_name("function")
        .and_then(|f| f.child_by_field_name("name"))
        .map_or(&b""[..], |n| text(n, src));
    let args = cs_call_arguments(call);
    match method {
        b"Parse" => args.len() == 1,
        b"TryParse" => args.len() == 2,
        _ => false,
    }
}

fn fifth_log_call<'t>(block: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let calls: Vec<Node<'t>> = cs_statements(block)
        .into_iter()
        .filter_map(|s| {
            operand(s)
                .filter(|e| e.kind() == "invocation_expression" && log_template(*e, src).is_some())
        })
        .collect();
    calls.get(4).copied()
}

fn exception_after_template<'t>(catch: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut cursor = catch.walk();
    let name = catch
        .named_children(&mut cursor)
        .find(|c| c.kind() == "catch_declaration")
        .and_then(|d| d.child_by_field_name("name"))
        .map(|n| text(n, src))?;
    let body = catch.child_by_field_name("body")?;
    find_in_scope(body, CS_SCOPE_STOPS, |n| {
        if n.kind() != "invocation_expression" {
            return false;
        }
        let Some(template) = log_template(n, src) else {
            return false;
        };
        let args = cs_call_arguments(n);
        let Some(position) = args.iter().position(|a| *a == template) else {
            return false;
        };
        args[position + 1..].iter().any(|a| text(*a, src) == name)
    })
}

fn raw_request_read<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut cursor = class.walk();
    let controller = class
        .named_children(&mut cursor)
        .filter(|c| c.kind() == "base_list")
        .any(|b| {
            let mut c = b.walk();
            b.named_children(&mut c)
                .any(|t| matches!(simple_name(t, src), b"Controller" | b"ControllerBase"))
        });
    if !controller {
        return None;
    }
    let body = class.child_by_field_name("body")?;
    find_in_scope(body, &[], |n| {
        n.kind() == "member_access_expression"
            && n.child_by_field_name("name")
                .is_some_and(|m| matches!(text(m, src), b"Form" | b"Query" | b"RouteValues"))
            && n.child_by_field_name("expression").is_some_and(|e| {
                matches!(
                    text(e, src),
                    b"Request" | b"HttpContext.Request" | b"this.Request"
                )
            })
    })
}

#[cfg(test)]
mod tests {
    use super::super::cs::tests::flagged;

    #[test]
    fn generics_and_serialization() {
        let src = "namespace N;\nclass A<K> {\nbool F<T>(T x) { return x == null; }\nbool G<T>(T x) where T : class { return x == null; }\nbool H(K k) { return k != null; }\nbool I<T>(T x) where T : IFoo { return null == x; }\nbool J<T>(T x) where T : struct { return x.Equals(default); }\n}\n[Serializable] class P { [OptionalField] int v; }\n[Serializable] class Q { [OptionalField] int v; [OnDeserialized] void R(StreamingContext c) { v = 1; } }";
        assert_eq!(flagged("cs/generic-null-comparison", src), [3, 5, 6]);
        assert_eq!(flagged("cs/optional-field-without-callbacks", src), [9]);
    }

    #[test]
    fn accessors_and_query_parameters() {
        let src = "namespace N;\nclass A { int name; int _count; public int Name { get { return _count; } set { name = value; } } public int Count { get => _count; set => _count = value; } }\nclass B { int x; public int Name { get => x; } }\nclass C { object _sync; int _c; public int Count { get { lock (_sync) { return _c; } } } }\nclass P { [SupplyParameterFromQuery] public List<int> Ids { get; set; } [SupplyParameterFromQuery] public int? Page { get; set; } [SupplyParameterFromQuery] public string[] Tags { get; set; } }";
        assert_eq!(flagged("cs/accessor-wrong-field", src), [2]);
        assert_eq!(flagged("cs/query-parameter-unsupported-type", src), [5]);
    }

    #[test]
    fn regexes_and_randoms() {
        let src = "namespace N;\nclass A {\nvoid F() {\nvar r1 = new Regex(p);\nvar r2 = new Regex(p, RegexOptions.None, TimeSpan.FromSeconds(1));\nvar r3 = new Regex(p, RegexOptions.NonBacktracking);\nvar m = Regex.IsMatch(s, p);\nvar n = Regex.IsMatch(s, p, RegexOptions.None, TimeSpan.FromSeconds(1));\nvar o = Regex.Replace(s, p, \"x\");\nvar token = new Random().Next().ToString();\nvar dice = new Random().Next(6);\nvar apiKey = Random.Shared.Next();\nvar keyboard = new Random().Next();\n}\n}";
        assert_eq!(flagged("cs/regex-without-timeout", src), [4, 7, 9]);
        assert_eq!(flagged("cs/random-secret", src), [10, 12]);
    }

    #[test]
    fn locations_and_parameters() {
        let src = "namespace N;\nclass A {\nconst string Root = \"/var/data/root\";\nvoid F() {\nvar uploadPath = \"/var/data/uploads\";\nvar apiUrl = \"https://api.payments.com/v1\";\nvar local = \"http://localhost:5000\";\nvar label = \"https://example.com\";\nvar dir = @\"C:\\Temp\\x\";\nvar loginPath = \"/Account/Login\";\n}\nprivate int G(int a, int b) => a;\nprivate int H(int a, int _b) => a;\npublic int I(int a, int b) => a;\nprivate void J(object sender, EventArgs e) { }\nprivate int K(int a) => throw new NotImplementedException();\nstatic void Main(string[] args) { }\n}";
        assert_eq!(flagged("cs/hardcoded-uri", src), [5, 6, 9]);
        assert_eq!(flagged("cs/unused-parameter", src), [12]);
    }

    #[test]
    fn loops_and_abstract_classes() {
        let src = "namespace N;\nclass A {\nstring F(int[] xs) {\nstring s = \"\";\nforeach (var x in xs) { s += x; }\nvar t = \"\";\nforeach (var x in xs) { t += x; }\nstring u = \"\";\nfor (int i = 0; i < 3; i++) { u = u + i; }\nreturn s + t + u;\n}\n}\nabstract class Shape { public abstract double Area(); }\nabstract class Base { public abstract double Area(); protected int x; }\nabstract class Derived : Shape { public abstract double Volume(); }";
        assert_eq!(flagged("cs/string-concat-in-loop", src), [5, 9]);
        assert_eq!(flagged("cs/abstract-class-only-abstract", src), [13]);
    }

    #[test]
    fn tests_without_assertions() {
        let src = "namespace N;\nclass T {\n[Fact] public void A() { var c = new Cart(); c.Add(1); }\n[Fact] public void B() { Assert.Equal(1, 1); }\n[Fact] public void C() { Check(); }\n[TestMethod, ExpectedException(typeof(E))] public void D() { G(); }\n[Fact] public void E() { x.Should().Be(1); }\nvoid Check() { Assert.True(true); }\n}";
        assert_eq!(flagged("cs/test-without-assertion", src), [3]);
    }

    #[test]
    fn fields() {
        let src = "namespace N;\nclass A {\nprivate int size;\nprivate int count;\nprivate int limit;\nprivate int last;\nprivate int keep = 5;\nprivate int init = 1;\nprivate static int shared;\n[SerializeField] private int unity;\npublic A(int s) { size = s; keep = 2; init = 3; }\npublic A() : base() { size = 1; keep = 1; init = 4; }\npublic void Hit() { count++; last = 1; }\npublic int Read() => size + count + limit + keep + init + unity;\n}\nclass B {\nprivate LazyValue<int> lazy;\nprivate readonly SemaphoreSlim a;\npublic B(LazyValue<int> l) { lazy = l; (a, _) = Make(); }\npublic int Get() => lazy.Value + a.CurrentCount;\n}";
        assert_eq!(flagged("cs/field-could-be-readonly", src), [3]);
        assert_eq!(flagged("cs/field-never-assigned", src), [5]);
        assert_eq!(flagged("cs/redundant-field-initializer", src), [7]);
        assert_eq!(flagged("cs/unread-private-field", src), [6]);
    }

    #[test]
    fn overloads_serializable_indentation() {
        let src = "namespace N;\nclass A {\nvoid F(int a) { }\nvoid F(int a, int b = 0) { }\nvoid G(int a, string s = null) { }\nvoid G(string s) { }\nvoid H(int a, out bool e) { e = true; }\nvoid H(int a) { }\n}\n[Serializable] class P : ISerializable { public void GetObjectData(SerializationInfo i, StreamingContext c) { } }\n[Serializable] class Q : ISerializable { protected Q(SerializationInfo i, StreamingContext c) { } public void GetObjectData(SerializationInfo i, StreamingContext c) { } }\nclass R {\nvoid F(bool b) {\n    if (b)\n    G();\n    if (b)\n        G();\n    if (b)\n        G();\n    else if (c)\n        H();\n}\n}";
        assert_eq!(flagged("cs/optional-overload-collision", src), [4]);
        assert_eq!(flagged("cs/iserializable-without-constructor", src), [10]);
        assert_eq!(flagged("cs/unbraced-body-not-indented", src), [15]);
    }

    #[test]
    fn operators_iterators_debugger() {
        let src = "namespace N;\nstruct M { public static M operator +(M a, M b) => a; }\nstruct K { public static K operator +(K a, K b) => a; public override bool Equals(object o) => false; public override int GetHashCode() => 0; }\nclass I {\nIEnumerable<int> F(int[] xs) {\nif (xs == null) { throw new ArgumentNullException(nameof(xs)); }\nforeach (var x in xs) { yield return x; }\n}\nIEnumerable<int> G(int[] xs) { foreach (var x in xs) { yield return x; } }\n}\n[DebuggerDisplay(\"{Nmae} {Count,nq}\")] class D { public string Name { get; set; } public int Count; }\n[DebuggerDisplay(\"{Name}\")] class D2 { public string Name { get; set; } }";
        assert_eq!(flagged("cs/operator-without-equals", src), [2]);
        assert_eq!(flagged("cs/iterator-argument-validation", src), [6]);
        assert_eq!(flagged("cs/debugger-display-unknown-member", src), [11]);
    }

    #[test]
    fn azure_functions() {
        let src = "namespace N;\nclass F {\n[FunctionName(\"A\")] public async Task A() { var h = new HttpClient(); await h.GetAsync(u); }\n[FunctionName(\"B\")] public string B(HttpClient h) { return h.GetStringAsync(u).Result; }\n[Function(\"C\")] public void C(Task t) { t.Wait(); }\n[FunctionName(\"D\")] public async Task D(HttpClient h) { await h.GetAsync(u); }\npublic string E(Task<string> t) { return t.Result; }\n}";
        assert_eq!(flagged("cs/azure-function-client-recreated", src), [3]);
        assert_eq!(flagged("cs/azure-function-blocking", src), [4, 5]);
    }

    #[test]
    fn dates() {
        let src = "namespace N;\nclass A {\nvoid F() {\nvar a = new DateTime(2024, 1, 31);\nvar b = new DateTime(2024, 1, 31, 0, 0, 0, DateTimeKind.Utc);\nvar c = new DateTime(ticks);\nvar d = DateTime.Parse(s);\nvar e = DateTime.Parse(s, CultureInfo.InvariantCulture);\nvar f = DateTime.TryParse(s, out var g);\nvar h = int.Parse(s);\n}\n}";
        assert_eq!(flagged("cs/datetime-without-kind", src), [4]);
        assert_eq!(flagged("cs/parse-without-culture", src), [7, 9]);
    }

    #[test]
    fn logging_and_controllers() {
        let src = "namespace N;\nclass A {\nvoid F(ILogger log) {\nlog.LogInformation(\"a\"); log.LogInformation(\"b\"); log.LogInformation(\"c\"); log.LogInformation(\"d\");\nlog.LogInformation(\"e\");\ntry { G(); } catch (IOException e) { log.LogError(\"Failed: {Error}\", e); }\ntry { G(); } catch (IOException e) { log.LogError(e, \"Failed\"); }\n}\n}\nclass OrdersController : ControllerBase { [HttpGet] public IActionResult Find() { var id = Request.Query[\"id\"]; return Ok(id); } }\nclass Other { void F() { var q = Request.Query; } }";
        assert_eq!(flagged("cs/too-many-log-calls", src), [5]);
        assert_eq!(flagged("cs/exception-as-template-argument", src), [6]);
        assert_eq!(flagged("cs/raw-request-data-in-controller", src), [10]);
    }
}
