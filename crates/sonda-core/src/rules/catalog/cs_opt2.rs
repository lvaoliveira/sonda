//! C# rules outside SonarQube's default profile, batch 9 (ADR-0007,
//! ADR-0015): API design, culture and dates, async, and a few opt-in bugs.
//! Every rule here is off unless `rules.enabled` lists it. Queries stay cheap
//! on deep trees: see the notes in `js_modern.rs`.

use super::cs::{
    CS_SCOPE_STOPS, cs_has_modifier, cs_statements, cs_string_value, operand, same_code,
    simple_name, unparenthesized,
};
use super::cs_bugs::{attribute_arguments, attribute_names, cs_call_arguments};
use super::cs_more::{declarators, declared_type, enclosing_type, is_test_method, members};
use super::cs_tail::{awaited_by_when_all, looks_like_task};
use super::java_bugs::{find_in_scope, operator_text};
use super::java_security::{contains_ignoring_case, text};
use super::java_smells::count_word;
use super::*;

/// Rules that are off unless `rules.enabled` lists them (see
/// `catalog::OFF_BY_DEFAULT`): all of this module's.
pub(super) static OFF_BY_DEFAULT: &[&str] = &[
    "cs/parameter-overwritten",
    "cs/disposable-fields-without-idisposable",
    "cs/lock-on-local",
    "cs/redundant-to-string",
    "cs/use-null-coalescing",
    "cs/default-argument-passed",
    "cs/explicit-delegate-creation",
    "cs/redundant-anonymous-property-name",
    "cs/indexer-parameter-type",
    "cs/struct-without-iequatable",
    "cs/custom-event-handler-delegate",
    "cs/non-generic-collection",
    "cs/irregular-digit-groups",
    "cs/list-in-public-api",
    "cs/string-uri-parameter",
    "cs/string-uri-return",
    "cs/string-uri-property",
    "cs/settable-collection-property",
    "cs/nested-generic-signature",
    "cs/uninferable-type-parameter",
    "cs/exception-standard-constructors",
    "cs/normalize-to-upper",
    "cs/type-named-like-namespace",
    "cs/ref-object-parameter",
    "cs/get-method-could-be-property",
    "cs/string-comparison-overload",
    "cs/property-and-get-method",
    "cs/attribute-not-sealed",
    "cs/operator-without-named-alternative",
    "cs/extension-on-object",
    "cs/async-method-name",
    "cs/async-argument-validation",
    "cs/blocking-async-call",
    "cs/untestable-clock",
    "cs/exclude-from-coverage-without-justification",
    "cs/local-time-recorded",
    "cs/datetime-instead-of-offset",
    "cs/hardcoded-date-format",
];

pub(super) static RULES: &[Rule] = &[
    // ---- Bugs ----
    Rule {
        id: "cs/parameter-overwritten",
        name: "Parameters should not be overwritten before they're read",
        description: "Assigning a parameter before reading it throws away the caller's argument; the method \
                      probably meant a local.",
        message: "Read this parameter before overwriting it, or use a local variable.",
        category: Bug,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[related("S1226")],
        check: Check::Query {
            langs: CSHARP,
            query: "(method_declaration parameters: (parameter_list) body: (block)) @match",
            filter: Some(Find(overwritten_parameter)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int F(int limit) { limit = 10; return limit * 2; } }",
            good: "class A { int F(int limit) { limit = Math.Min(limit, 10); return limit * 2; } }",
        }),
    },
    Rule {
        id: "cs/disposable-fields-without-idisposable",
        name: "Classes with disposable fields should be disposable",
        description: "A class that creates a stream, timer or client and keeps it in a field must dispose of it, \
                      which callers can only trigger through IDisposable.",
        message: "Implement IDisposable and dispose of this field.",
        category: Bug,
        severity: Blocker,
        effort_minutes: 15,
        sonar: &[related("S2931")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration name: (identifier) body: (declaration_list)) @match",
            filter: Some(Find(owned_disposable_field)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class Log { private readonly FileStream file = File.OpenWrite(\"log\"); }",
            good: "class Log : IDisposable { private readonly FileStream file = File.OpenWrite(\"log\"); public void Dispose() => file.Dispose(); }",
        }),
    },
    Rule {
        id: "cs/lock-on-local",
        name: "Locks should not be taken on local variables",
        description: "Each call has its own local, so a lock on it never makes another thread wait.",
        message: "Lock on a private readonly field shared by the threads instead.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6507")],
        check: Check::Query {
            langs: CSHARP,
            query: "(lock_statement (identifier) @match)",
            filter: Some(Keep(is_local_variable)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F() { var sync = new object(); lock (sync) { G(); } } }",
            good: "class A { readonly object sync = new object(); void F() { lock (sync) { G(); } } }",
        }),
    },
    // ---- Code smells ----
    Rule {
        id: "cs/redundant-to-string",
        name: "ToString() should not be called when concatenating",
        description: "String concatenation and interpolation already call ToString().",
        message: "Remove this ToString() call.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[related("S1858")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(invocation_expression
                        function: (member_access_expression name: (identifier) @n)
                        arguments: (argument_list) @a
                        (#eq? @n "ToString")) @match"#,
            filter: Some(Keep(to_string_in_concatenation)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { string F(int n) { return \"n = \" + n.ToString(); } }",
            good: "class A { string F(int n) { return \"n = \" + n; } }",
        }),
    },
    Rule {
        id: "cs/use-null-coalescing",
        name: "?? should be used instead of a null-checking conditional",
        description: "`a != null ? a : b` is `a ?? b`.",
        message: "Use '??' instead of this conditional.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[related("S3240")],
        check: Check::Query {
            langs: CSHARP,
            query: "(conditional_expression condition: (binary_expression)) @match",
            filter: Some(Keep(is_null_coalescing_shape)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { string F(string a) { return a != null ? a : \"\"; } }",
            good: "class A { string F(string a) { return a ?? \"\"; } }",
        }),
    },
    Rule {
        id: "cs/default-argument-passed",
        name: "Default parameter values should not be passed explicitly",
        description: "Passing the default value says nothing the declaration doesn't, and stops following a \
                      change of the default.",
        message: "Leave this argument out; it's the parameter's default.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[related("S3254")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration body: (declaration_list)) @match",
            filter: Some(Find(default_passed_explicitly)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void Save(string p, bool force = false) { } void F() { Save(\"x\", false); } }",
            good: "class A { void Save(string p, bool force = false) { } void F() { Save(\"x\"); } }",
        }),
    },
    Rule {
        id: "cs/explicit-delegate-creation",
        name: "Delegates should not be created explicitly",
        description: "`new EventHandler(OnClick)` is what `OnClick` alone becomes; the explicit form is noise.",
        message: "Pass the method group directly.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[related("S3257")],
        check: Check::Query {
            langs: CSHARP,
            query: "(object_creation_expression type: (_) arguments: (argument_list (argument (identifier)) .)) @match",
            filter: Some(Keep(wraps_method_group)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(B b) { b.Clicked += new EventHandler(OnClick); } }",
            good: "class A { void F(B b) { b.Clicked += OnClick; } }",
        }),
    },
    Rule {
        id: "cs/redundant-anonymous-property-name",
        name: "Anonymous type properties should not repeat their value's name",
        description: "`new { Name = p.Name }` is `new { p.Name }`; the compiler takes the name from the member.",
        message: "Remove the redundant property name.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S3441")],
        check: Check::Query {
            langs: CSHARP,
            query: "(anonymous_object_creation_expression) @match",
            filter: Some(Find(repeated_anonymous_name)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { object F(P p) { return new { Name = p.Name }; } }",
            good: "class A { object F(P p) { return new { p.Name, Total = p.Count }; } }",
        }),
    },
    Rule {
        id: "cs/indexer-parameter-type",
        name: "Indexers should take strings or integers",
        description: "An indexer looks like an array or dictionary lookup; other parameter types make a method \
                      clearer.",
        message: "Use a method instead of an indexer with this parameter type.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S3876")],
        check: Check::Query {
            langs: CSHARP,
            query: "(indexer_declaration parameters: (bracketed_parameter_list (parameter type: (_) @match)))",
            filter: Some(Keep(unusual_index_type)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int this[double d] => 0; }",
            good: "class A { int this[int i] => 0; }",
        }),
    },
    Rule {
        id: "cs/struct-without-iequatable",
        name: "Structs should implement IEquatable<T>",
        description: "Without it, Equals(object) boxes the struct and compares field by field through \
                      reflection, which is slow.",
        message: "Implement IEquatable<T> for this struct.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[related("S3898")],
        check: Check::Query {
            langs: CSHARP,
            query: "(struct_declaration name: (identifier) @match body: (declaration_list))",
            filter: Some(Keep(struct_lacks_iequatable)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "struct Point { public int X; public override bool Equals(object o) => false; public override int GetHashCode() => X; }",
            good: "struct Point : IEquatable<Point> { public int X; public bool Equals(Point p) => p.X == X; public override bool Equals(object o) => o is Point p && Equals(p); public override int GetHashCode() => X; }",
        }),
    },
    Rule {
        id: "cs/custom-event-handler-delegate",
        name: "Events should use EventHandler<T>",
        description: "A custom delegate with the (sender, args) shape is EventHandler<TArgs> written by hand.",
        message: "Declare this event as EventHandler<T> and remove the custom delegate.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[related("S3908")],
        check: Check::Query {
            langs: CSHARP,
            query: "(compilation_unit) @match",
            filter: Some(Find(event_of_custom_handler)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "delegate void SavedHandler(object sender, SavedEventArgs e); class A { public event SavedHandler Saved; }",
            good: "class A { public event EventHandler<SavedEventArgs> Saved; }",
        }),
    },
    Rule {
        id: "cs/non-generic-collection",
        name: "Collections should implement the generic interfaces",
        description: "A collection that only implements IEnumerable or ICollection hands out objects, so every \
                      caller casts and LINQ can't infer the element type.",
        message: "Implement IEnumerable<T> (or ICollection<T>, IList<T>) as well.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 15,
        sonar: &[exact("S3909")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration name: (identifier) @match (base_list))",
            filter: Some(Keep(only_non_generic_collection)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class Bag : IEnumerable { public IEnumerator GetEnumerator() => null; }",
            good: "class Bag : IEnumerable<int> { public IEnumerator<int> GetEnumerator() => null; IEnumerator IEnumerable.GetEnumerator() => GetEnumerator(); }",
        }),
    },
    Rule {
        id: "cs/irregular-digit-groups",
        name: "Digit separators should group regularly",
        description: "`1_00_000` hides the magnitude the separators are there to show.",
        message: "Group the digits in threes (or nibbles and bytes for hex and binary).",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 1,
        sonar: &[exact("S3937")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(integer_literal) (real_literal)] @match",
            filter: Some(Keep(irregular_groups)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { const int Max = 1_00_000; }",
            good: "class A { const int Max = 100_000; }",
        }),
    },
    Rule {
        id: "cs/list-in-public-api",
        name: "List<T> should not be exposed by public APIs",
        description: "List<T> can't be extended or observed; a public API that exposes it can't change that \
                      later. Use IList<T>, IReadOnlyList<T> or Collection<T>.",
        message: "Expose an interface such as IReadOnlyList<T> or IList<T> instead.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S3956")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(method_declaration (modifier) returns: (generic_name) @match) \
                     (property_declaration (modifier) type: (generic_name) @match) \
                     (method_declaration (modifier) parameters: (parameter_list (parameter type: (generic_name) @match)))]",
            filter: Some(Keep(public_list)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "public class A { public List<int> Items { get; } = new(); }",
            good: "public class A { public IReadOnlyList<int> Items { get; } = new List<int>(); }",
        }),
    },
    Rule {
        id: "cs/string-uri-parameter",
        name: "URI parameters should be System.Uri",
        description: "A Uri is validated when it's created and offers the parts of the address; a string is \
                      checked nowhere.",
        message: "Make this parameter a System.Uri.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S3994")],
        check: Check::Query {
            langs: CSHARP,
            query: "(method_declaration (modifier) parameters: (parameter_list (parameter type: (predefined_type) name: (identifier) @match)))",
            filter: Some(Keep(public_string_uri_parameter)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "public class A { public void Fetch(string url) { } }",
            good: "public class A { public void Fetch(Uri url) { } }",
        }),
    },
    Rule {
        id: "cs/string-uri-return",
        name: "Methods returning URIs should return System.Uri",
        description: "Callers of a method named like a URL getter expect a Uri, with its parts and validation.",
        message: "Return a System.Uri.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S3995")],
        check: Check::Query {
            langs: CSHARP,
            query: "(method_declaration (modifier) returns: (predefined_type) name: (identifier) @match)",
            filter: Some(Keep(public_string_uri_member)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "public class A { public string GetUrl() => \"https://a.example\"; }",
            good: "public class A { public Uri GetUrl() => new Uri(\"https://a.example\"); }",
        }),
    },
    Rule {
        id: "cs/string-uri-property",
        name: "URI properties should be System.Uri",
        description: "A Uri property is validated when set and offers the parts of the address; a string isn't.",
        message: "Make this property a System.Uri.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S3996")],
        check: Check::Query {
            langs: CSHARP,
            query: "(property_declaration (modifier) type: (predefined_type) name: (identifier) @match)",
            filter: Some(Keep(public_string_uri_member)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "public class A { public string HomeUrl { get; set; } }",
            good: "public class A { public Uri HomeUrl { get; set; } }",
        }),
    },
    Rule {
        id: "cs/settable-collection-property",
        name: "Collection properties should be read-only",
        description: "A settable collection property lets callers replace the whole collection, which is rarely \
                      wanted; they can still add and remove through the getter.",
        message: "Remove this property's setter.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S4004")],
        check: Check::Query {
            langs: CSHARP,
            query: "(property_declaration (modifier) type: (generic_name) name: (identifier) accessors: (accessor_list)) @match",
            filter: Some(Find(public_collection_setter)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "public class A { public List<int> Items { get; set; } = new(); }",
            good: "public class A { public List<int> Items { get; } = new(); }",
        }),
    },
    Rule {
        id: "cs/nested-generic-signature",
        name: "Public signatures should not nest generic types",
        description: "`List<Dictionary<string, int>>` in a public signature is hard to read and to call; a named \
                      type says what it holds.",
        message: "Replace this nested generic type with a named type.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S4017")],
        check: Check::Query {
            langs: CSHARP,
            query: "(method_declaration (modifier) parameters: (parameter_list (parameter type: (generic_name) @match)))",
            filter: Some(Keep(public_nested_generic)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "public class A { public void Load(List<Dictionary<string, int>> rows) { } }",
            good: "public class A { public void Load(IEnumerable<Row> rows) { } }",
        }),
    },
    Rule {
        id: "cs/uninferable-type-parameter",
        name: "Generic methods should let callers infer their type parameters",
        description: "A type parameter that no parameter uses must always be written out by the caller.",
        message: "Use this type parameter in the parameter list, so calls can infer it.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 10,
        sonar: &[exact("S4018")],
        check: Check::Query {
            langs: CSHARP,
            query: "(method_declaration type_parameters: (type_parameter_list) parameters: (parameter_list)) @match",
            filter: Some(Find(type_parameter_not_in_parameters)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { T Read<T>(string key) => default; }",
            good: "class A { T Read<T>(string key, T fallback) => fallback; }",
        }),
    },
    Rule {
        id: "cs/exception-standard-constructors",
        name: "Exceptions should provide the standard constructors",
        description: "Callers and serializers expect (), (string message) and (string message, Exception inner).",
        message: "Add the missing standard constructors to this exception.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 10,
        sonar: &[exact("S4027")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration name: (identifier) @match (base_list) body: (declaration_list))",
            filter: Some(Keep(missing_standard_constructors)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "public class QuotaException : Exception { public QuotaException(string m) : base(m) { } }",
            good: "public class QuotaException : Exception { public QuotaException() { } public QuotaException(string m) : base(m) { } public QuotaException(string m, Exception i) : base(m, i) { } }",
        }),
    },
    Rule {
        id: "cs/normalize-to-upper",
        name: "Strings should be normalized to upper case",
        description: "Some characters don't round-trip through lower case; upper-case normalization is the \
                      safe one for comparisons.",
        message: "Use ToUpperInvariant() to normalize this string.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S4040")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(invocation_expression function: (member_access_expression expression: (_) @r name: (identifier) @n)
                        (#eq? @n "ToLowerInvariant") (#not-match? @r "^(char|Char)$")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { string F(string s) { return s.ToLowerInvariant(); } }",
            good: "class A { string F(string s) { return s.ToUpperInvariant(); } }",
        }),
    },
    Rule {
        id: "cs/type-named-like-namespace",
        name: "Types should not be named like well-known namespaces",
        description: "A type called `Collections` or `Linq` collides with the namespace in using directives and \
                      confuses readers.",
        message: "Rename this type.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S4041")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(class_declaration name: (identifier) @match) (struct_declaration name: (identifier) @match) \
                     (interface_declaration name: (identifier) @match) (enum_declaration name: (identifier) @match)]",
            filter: Some(Keep(is_namespace_name)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class Collections { }",
            good: "class CollectionHelpers { }",
        }),
    },
    Rule {
        id: "cs/ref-object-parameter",
        name: "Generics should be used instead of ref object parameters",
        description: "A `ref object` parameter takes any type and makes callers cast; a generic `ref T` keeps \
                      the type.",
        message: "Make this a generic 'ref T' parameter.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 10,
        sonar: &[exact("S4047")],
        check: Check::Query {
            langs: CSHARP,
            query: "(parameter (modifier) type: (predefined_type) @match)",
            filter: Some(Keep(is_ref_object)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void Swap(ref object a, ref object b) { } }",
            good: "class A { void Swap<T>(ref T a, ref T b) { } }",
        }),
    },
    Rule {
        id: "cs/get-method-could-be-property",
        name: "Simple getter methods should be properties",
        description: "A public `GetName()` without parameters or side effects reads better as a `Name` property.",
        message: "Turn this method into a property.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S4049")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(method_declaration (modifier) name: (identifier) @match parameters: (parameter_list) body: (_)
                        (#match? @match "^Get[A-Z]"))"#,
            filter: Some(Keep(trivial_getter_method)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "public class A { string name; public string GetName() { return name; } }",
            good: "public class A { string name; public string Name => name; }",
        }),
    },
    Rule {
        id: "cs/string-comparison-overload",
        name: "String comparisons should state how they compare",
        description: "Without a StringComparison, Compare, StartsWith, EndsWith and IndexOf(string) depend on the \
                      current culture.",
        message: "Pass a StringComparison, such as StringComparison.Ordinal.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[related("S4058")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(invocation_expression function: (member_access_expression name: (identifier) @n)
                        (#any-of? @n "StartsWith" "EndsWith" "IndexOf" "LastIndexOf" "Compare")) @match"#,
            filter: Some(Keep(culture_dependent_comparison)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { bool F(string s) { return s.StartsWith(\"abc\"); } }",
            good: "class A { bool F(string s) { return s.StartsWith(\"abc\", StringComparison.Ordinal); } }",
        }),
    },
    Rule {
        id: "cs/property-and-get-method",
        name: "Types should not have both a property X and a method GetX",
        description: "Two ways to read the same thing make readers wonder how they differ.",
        message: "Remove one of the two, or rename the method to say how it differs.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S4059")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration body: (declaration_list)) @match",
            filter: Some(Find(property_with_get_method)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { public int Count => 1; public int GetCount() => 1; }",
            good: "class A { public int Count => 1; }",
        }),
    },
    Rule {
        id: "cs/attribute-not-sealed",
        name: "Attribute classes should be sealed",
        description: "Looking up a sealed attribute is faster, and attributes are rarely designed to be \
                      inherited.",
        message: "Seal this attribute class, or make it abstract.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S4060")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration name: (identifier) @match (base_list))",
            filter: Some(Keep(unsealed_attribute)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class RetryAttribute : Attribute { }",
            good: "sealed class RetryAttribute : Attribute { }",
        }),
    },
    Rule {
        id: "cs/operator-without-named-alternative",
        name: "Operator overloads should have named alternatives",
        description: "Languages without operator overloading can only call `Add` or `Subtract`, not `+` or `-`.",
        message: "Add a method such as Add, Subtract or Multiply that does the same.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 10,
        sonar: &[exact("S4069")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(class_declaration name: (identifier) body: (declaration_list)) (struct_declaration name: (identifier) body: (declaration_list))] @match",
            filter: Some(Find(operator_without_alternative)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "struct Money { public static Money operator +(Money a, Money b) => a; }",
            good: "struct Money { public static Money operator +(Money a, Money b) => Add(a, b); public static Money Add(Money a, Money b) => a; }",
        }),
    },
    Rule {
        id: "cs/extension-on-object",
        name: "Extension methods should not extend object",
        description: "An extension on object shows up on every value in the codebase, including where it makes \
                      no sense.",
        message: "Extend a more specific type.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S4225")],
        check: Check::Query {
            langs: CSHARP,
            query: "(method_declaration (modifier) parameters: (parameter_list . (parameter (modifier) type: (predefined_type) @match)))",
            filter: Some(Keep(extends_object)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "static class X { public static string Dump(this object o) => o.ToString(); }",
            good: "static class X { public static string Dump(this Order o) => o.ToString(); }",
        }),
    },
    Rule {
        id: "cs/async-method-name",
        name: "Asynchronous methods should end with Async",
        description: "The suffix tells callers to await the result, and sets it apart from a synchronous \
                      method of the same name.",
        message: "Add the 'Async' suffix to this method's name.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[related("S4261")],
        check: Check::Query {
            langs: CSHARP,
            query: "(method_declaration returns: (_) name: (identifier) @match)",
            filter: Some(Keep(async_without_suffix)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { async Task Save() { await G(); } }",
            good: "class A { async Task SaveAsync() { await G(); } }",
        }),
    },
    Rule {
        id: "cs/async-argument-validation",
        name: "Async methods should validate their arguments before the first await",
        description: "An async method's exceptions end up in the returned task, so an argument check throws \
                      only when the task is awaited, far from the bad call.",
        message: "Validate in a non-async wrapper that then calls the async implementation.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S4457")],
        check: Check::Query {
            langs: CSHARP,
            query: "(method_declaration (modifier) name: (identifier) body: (block)) @match",
            filter: Some(Find(async_argument_check)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { async Task F(string s) { if (s == null) { throw new ArgumentNullException(nameof(s)); } await G(s); } }",
            good: "class A { Task F(string s) { if (s == null) { throw new ArgumentNullException(nameof(s)); } return FCore(s); } async Task FCore(string s) { await G(s); } }",
        }),
    },
    Rule {
        id: "cs/blocking-async-call",
        name: "Async calls should not be blocked on",
        description: "`.Result`, `.Wait()` and `.GetAwaiter().GetResult()` hold a thread while the task runs, \
                      and can deadlock where a synchronization context is in use.",
        message: "Await this task instead of blocking on it.",
        category: CodeSmell,
        severity: Blocker,
        effort_minutes: 10,
        sonar: &[related("S4462")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(member_access_expression name: (identifier)) (invocation_expression function: (member_access_expression))] @match",
            filter: Some(Keep(blocks_on_task)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { string F(HttpClient h) { return h.GetStringAsync(\"https://a.example\").Result; } }",
            good: "class A { async Task<string> F(HttpClient h) { return await h.GetStringAsync(\"https://a.example\"); } }",
        }),
    },
    Rule {
        id: "cs/untestable-clock",
        name: "Code should take the current time from a provider",
        description: "DateTime.Now and UtcNow can't be controlled in tests; a TimeProvider or clock interface \
                      can.",
        message: "Get the current time from an injected TimeProvider.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S6354")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(member_access_expression expression: (_) @t name: (identifier) @n
                        (#match? @t "(^|\\.)(DateTime|DateTimeOffset)$") (#any-of? @n "Now" "UtcNow" "Today")) @match"#,
            filter: Some(Keep(outside_clock)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { bool Expired(DateTime at) { return at < DateTime.UtcNow; } }",
            good: "class A { bool Expired(DateTime at, TimeProvider clock) { return at < clock.GetUtcNow(); } }",
        }),
    },
    Rule {
        id: "cs/exclude-from-coverage-without-justification",
        name: "[ExcludeFromCodeCoverage] should give a justification",
        description: "The justification tells reviewers why the code doesn't need tests.",
        message: "Add Justification = \"...\" to this attribute.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6513")],
        check: Check::Query {
            langs: CSHARP,
            query: "(attribute name: (_)) @match",
            filter: Some(Keep(unjustified_exclusion)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "[ExcludeFromCodeCoverage] class Startup { }",
            good: "[ExcludeFromCodeCoverage(Justification = \"Composition root, covered by integration tests\")] class Startup { }",
        }),
    },
    Rule {
        id: "cs/local-time-recorded",
        name: "Instants should be recorded in UTC",
        description: "DateTime.Now changes with daylight saving and the server's zone, so stored or compared \
                      times drift. UtcNow doesn't.",
        message: "Use DateTime.UtcNow.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6563")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(member_access_expression expression: (_) @t name: (identifier) @n
                        (#match? @t "(^|\\.)DateTime$") (#eq? @n "Now")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { DateTime Stamp() { return DateTime.Now; } }",
            good: "class A { DateTime Stamp() { return DateTime.UtcNow; } }",
        }),
    },
    Rule {
        id: "cs/datetime-instead-of-offset",
        name: "DateTimeOffset should be used instead of DateTime",
        description: "A DateTime doesn't carry its offset, so the same value can mean different instants; a \
                      DateTimeOffset can't be misread that way.",
        message: "Use DateTimeOffset here.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S6566")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(member_access_expression expression: (_) @t name: (identifier) @n
                        (#match? @t "^(System\\.)?DateTime$") (#any-of? @n "Now" "UtcNow")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { DateTime Stamp() { return DateTime.UtcNow; } }",
            good: "class A { DateTimeOffset Stamp() { return DateTimeOffset.UtcNow; } }",
        }),
    },
    Rule {
        id: "cs/hardcoded-date-format",
        name: "Date formats should not be hard-coded",
        description: "A fixed format such as \"MM/dd/yyyy\" reads wrong for users of other cultures; standard \
                      format specifiers adapt.",
        message: "Use a standard format (\"d\", \"D\", \"o\") or the culture's patterns.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[related("S6585")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(invocation_expression function: (member_access_expression name: (identifier) @n)
                        arguments: (argument_list . (argument (string_literal) @match))
                        (#eq? @n "ToString"))"#,
            filter: Some(Keep(is_custom_date_format)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { string F(DateTime d) { return d.ToString(\"MM/dd/yyyy\"); } }",
            good: "class A { string F(DateTime d) { return d.ToString(\"d\"); } }",
        }),
    },
];

// ---------------------------------------------------- filters

fn overwritten_parameter<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let params = method.child_by_field_name("parameters")?;
    let mut cursor = params.walk();
    // ref and out parameters are written on purpose.
    let names: Vec<&[u8]> = params
        .named_children(&mut cursor)
        .filter(|p| p.kind() == "parameter" && !has_parameter_modifier(*p, &[b"ref", b"out"], src))
        .filter_map(|p| p.child_by_field_name("name").map(|n| text(n, src)))
        .collect();
    let body = method.child_by_field_name("body")?;
    let first = *cs_statements(body).first()?;
    let assignment = operand(first)
        .filter(|e| e.kind() == "assignment_expression" && operator_text(*e, src) == b"=")?;
    let target = text(assignment.child_by_field_name("left")?, src);
    let value = assignment.child_by_field_name("right")?;
    (names.contains(&target) && count_word(text(value, src), target) == 0).then_some(assignment)
}

/// `ref`, `out`, `this`... on a parameter, past any attributes.
pub(super) fn has_parameter_modifier(parameter: Node, wanted: &[&[u8]], src: &[u8]) -> bool {
    let mut cursor = parameter.walk();
    parameter
        .named_children(&mut cursor)
        .any(|m| m.kind() == "modifier" && wanted.contains(&text(m, src)))
}

pub(super) const DISPOSABLE_TYPES: &[&[u8]] = &[
    b"Stream",
    b"FileStream",
    b"MemoryStream",
    b"StreamReader",
    b"StreamWriter",
    b"Timer",
    b"HttpClient",
    b"SqlConnection",
    b"DbConnection",
    b"Process",
    b"CancellationTokenSource",
    b"SemaphoreSlim",
    b"Socket",
    b"TcpClient",
    b"BinaryReader",
    b"BinaryWriter",
    b"ManualResetEvent",
    b"AutoResetEvent",
];

fn owned_disposable_field<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut cursor = class.walk();
    if class
        .named_children(&mut cursor)
        .any(|c| c.kind() == "base_list")
        || cs_has_modifier(class, "static", src)
    {
        return None;
    }
    // Fields the class creates itself (an initializer with `new` or a
    // factory call), not ones it was given.
    members(class)
        .into_iter()
        .filter(|m| m.kind() == "field_declaration" && !cs_has_modifier(*m, "static", src))
        .find_map(|f| {
            let ty = declared_type(f)?;
            if !DISPOSABLE_TYPES.contains(&simple_name(ty, src)) {
                return None;
            }
            declarators(f).into_iter().find(|d| {
                let value = text(*d, src);
                value.windows(4).any(|w| w == b"new ")
                    || value.windows(5).any(|w| w == b"Open(")
                    || value.windows(9).any(|w| w == b"OpenWrite")
            })
        })
}

fn is_local_variable(name: Node, src: &[u8]) -> bool {
    let n = text(name, src);
    let mut current = name.parent();
    for _ in 0..64 {
        let Some(scope) = current else {
            return false;
        };
        if matches!(
            scope.kind(),
            "method_declaration"
                | "accessor_declaration"
                | "constructor_declaration"
                | "local_function_statement"
                | "lambda_expression"
        ) {
            let Some(body) = scope.child_by_field_name("body") else {
                return false;
            };
            // Only a local the method creates: `var sync = GetShared();` can
            // hold an object other threads lock on too.
            return find_in_scope(body, CS_SCOPE_STOPS, |d| {
                d.kind() == "variable_declarator"
                    && d.end_byte() <= name.start_byte()
                    && d.child_by_field_name("name")
                        .is_some_and(|x| text(x, src) == n)
                    && d.named_child(d.named_child_count().saturating_sub(1) as u32)
                        .is_some_and(|v| {
                            matches!(
                                unparenthesized(v).kind(),
                                "object_creation_expression"
                                    | "implicit_object_creation_expression"
                                    | "string_literal"
                            )
                        })
            })
            .is_some();
        }
        current = scope.parent();
    }
    false
}

fn to_string_in_concatenation(call: Node, src: &[u8]) -> bool {
    let no_args = call
        .child_by_field_name("arguments")
        .is_some_and(|a| a.named_child_count() == 0);
    let Some(parent) = call.parent() else {
        return false;
    };
    // `"x" + n.ToString()`: the other operand is a string literal.
    let concatenated = parent.kind() == "binary_expression"
        && operator_text(parent, src) == b"+"
        && ["left", "right"].iter().any(|f| {
            parent.child_by_field_name(f).is_some_and(|o| {
                o != call
                    && matches!(
                        o.kind(),
                        "string_literal" | "interpolated_string_expression"
                    )
            })
        });
    // `$"{n.ToString()}"`
    let interpolated = parent.kind() == "interpolation";
    no_args && (concatenated || interpolated)
}

fn is_null_coalescing_shape(node: Node, src: &[u8]) -> bool {
    let Some(condition) = node.child_by_field_name("condition").map(unparenthesized) else {
        return false;
    };
    let op = operator_text(condition, src);
    if !matches!(op, b"!=" | b"==") {
        return false;
    }
    let (Some(l), Some(r)) = (
        condition.child_by_field_name("left"),
        condition.child_by_field_name("right"),
    ) else {
        return false;
    };
    let subject = if r.kind() == "null_literal" {
        l
    } else if l.kind() == "null_literal" {
        r
    } else {
        return false;
    };
    // `a != null ? a : b` or `a == null ? b : a`.
    let kept = node.child_by_field_name(if op == b"!=" {
        "consequence"
    } else {
        "alternative"
    });
    kept.is_some_and(|k| same_code(unparenthesized(k), subject, src))
}

/// An optional parameter: its position and its default value's text.
type OptionalParameter<'s> = (usize, &'s [u8]);

fn default_passed_explicitly<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    // Methods of this class: name, and (position, default text) of their
    // optional parameters. Overloaded names are skipped: which one a call
    // picks takes types.
    let methods: Vec<Node<'t>> = members(class)
        .into_iter()
        .filter(|m| m.kind() == "method_declaration")
        .collect();
    let defaults: Vec<(&[u8], Vec<OptionalParameter>)> = methods
        .iter()
        .filter_map(|m| {
            let name = text(m.child_by_field_name("name")?, src);
            if methods
                .iter()
                .filter(|o| {
                    o.child_by_field_name("name")
                        .is_some_and(|n| text(n, src) == name)
                })
                .count()
                > 1
            {
                return None;
            }
            let params = m.child_by_field_name("parameters")?;
            let mut c = params.walk();
            let list: Vec<(usize, &[u8])> = params
                .named_children(&mut c)
                .filter(|p| p.kind() == "parameter")
                .enumerate()
                .filter_map(|(i, p)| {
                    let t = text(p, src);
                    let eq = t.iter().position(|b| *b == b'=')?;
                    Some((i, t[eq + 1..].trim_ascii()))
                })
                .collect();
            (!list.is_empty()).then_some((name, list))
        })
        .collect();
    if defaults.is_empty() {
        return None;
    }
    let body = class.child_by_field_name("body")?;
    find_in_scope(body, &[], |n| {
        if n.kind() != "invocation_expression" {
            return false;
        }
        let Some(name) = n.child_by_field_name("function").map(|f| text(f, src)) else {
            return false;
        };
        let args = cs_call_arguments(n);
        defaults.iter().any(|(m, optional)| {
            *m == name
                && optional.iter().any(|(i, value)| {
                    // The last argument passed positionally, equal to its default.
                    *i + 1 == args.len()
                        && args.get(*i).is_some_and(|a| text(*a, src) == *value)
                        && args[*i]
                            .parent()
                            .is_some_and(|p| p.child_by_field_name("name").is_none())
                })
        })
    })
}

fn wraps_method_group(creation: Node, src: &[u8]) -> bool {
    let delegate = creation.child_by_field_name("type").is_some_and(|t| {
        let name = simple_name(t, src);
        [
            &b"Handler"[..],
            b"Action",
            b"Func",
            b"Predicate",
            b"Callback",
        ]
        .iter()
        .any(|s| name.ends_with(s))
    });
    // `new Action(Validate).ShouldThrow()`: a method group has no members, so
    // the explicit delegate is needed there.
    let receiver = creation.parent().is_some_and(|p| {
        p.kind() == "member_access_expression"
            && p.child_by_field_name("expression") == Some(creation)
    });
    // `new EventHandler(OnClick)`: one argument, a bare method name.
    let args = cs_call_arguments(creation);
    delegate
        && !receiver
        && matches!(args.as_slice(), [a] if a.kind() == "identifier" && text(*a, src).first().is_some_and(u8::is_ascii_uppercase))
}

fn repeated_anonymous_name<'t>(creation: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    // Children read `Name = value, Other = value, Bare`: a name followed by
    // `=` and its value.
    let mut cursor = creation.walk();
    let children: Vec<Node<'t>> = creation.children(&mut cursor).collect();
    children.windows(3).find_map(|w| {
        let (name, eq, value) = (w[0], w[1], w[2]);
        (name.kind() == "identifier"
            && !eq.is_named()
            && text(eq, src) == b"="
            && value.kind() == "member_access_expression"
            && value
                .child_by_field_name("name")
                .is_some_and(|m| text(m, src) == text(name, src)))
        .then_some(name)
    })
}

fn unusual_index_type(ty: Node, src: &[u8]) -> bool {
    let t = text(ty, src);
    let t = t.strip_suffix(b"?").unwrap_or(t);
    !matches!(
        t,
        b"int"
            | b"long"
            | b"short"
            | b"uint"
            | b"ulong"
            | b"ushort"
            | b"byte"
            | b"sbyte"
            | b"string"
            | b"char"
            | b"Index"
            | b"Range"
            | b"object"
    ) && !is_type_parameter_name(t)
}

/// `T`, `TKey`, `TValue`: by convention a generic type parameter.
pub(super) fn is_type_parameter_name(t: &[u8]) -> bool {
    t == b"T"
        || (t.len() > 1 && t[0] == b'T' && t[1].is_ascii_uppercase())
        || (t.len() <= 2 && t.first().is_some_and(u8::is_ascii_uppercase))
}

fn implements(declaration: Node, src: &[u8], interface: &[u8]) -> bool {
    let mut cursor = declaration.walk();
    declaration
        .named_children(&mut cursor)
        .filter(|c| c.kind() == "base_list")
        .any(|b| count_word(text(b, src), interface) > 0)
}

fn struct_lacks_iequatable(name: Node, src: &[u8]) -> bool {
    let Some(declaration) = name.parent() else {
        return false;
    };
    // Only structs that define equality: one that doesn't uses the default.
    let overrides_equals = members(declaration).iter().any(|m| {
        m.kind() == "method_declaration"
            && cs_has_modifier(*m, "override", src)
            && m.child_by_field_name("name")
                .is_some_and(|n| text(n, src) == b"Equals")
    });
    overrides_equals && !implements(declaration, src, b"IEquatable")
}

fn event_of_custom_handler<'t>(unit: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    // Delegates declared in this file with the (object sender, TArgs e) shape.
    let mut handlers: Vec<&[u8]> = Vec::new();
    let mut stack = vec![unit];
    while let Some(n) = stack.pop() {
        if n.kind() == "delegate_declaration" {
            let params = n.child_by_field_name("parameters");
            let shape = params.is_some_and(|p| {
                let mut c = p.walk();
                let types: Vec<&[u8]> = p
                    .named_children(&mut c)
                    .filter_map(|x| x.child_by_field_name("type").map(|t| simple_name(t, src)))
                    .collect();
                types.len() == 2 && types[0] == b"object" && types[1].ends_with(b"EventArgs")
            });
            if shape && let Some(name) = n.child_by_field_name("name") {
                handlers.push(text(name, src));
            }
            continue;
        }
        if matches!(n.kind(), "block" | "method_declaration") {
            continue;
        }
        let mut c = n.walk();
        stack.extend(n.named_children(&mut c));
    }
    if handlers.is_empty() {
        return None;
    }
    find_in_scope(unit, &["block"], |n| {
        n.kind() == "event_field_declaration"
            && declared_type(n).is_some_and(|t| handlers.contains(&text(t, src)))
    })
}

fn only_non_generic_collection(name: Node, src: &[u8]) -> bool {
    let Some(class) = name.parent() else {
        return false;
    };
    let mut cursor = class.walk();
    let Some(bases) = class
        .named_children(&mut cursor)
        .find(|c| c.kind() == "base_list")
    else {
        return false;
    };
    let mut c = bases.walk();
    let list: Vec<Node> = bases.named_children(&mut c).collect();
    let non_generic = list.iter().any(|b| {
        b.kind() == "identifier"
            && matches!(text(*b, src), b"IEnumerable" | b"ICollection" | b"IList")
    });
    let generic = list.iter().any(|b| b.kind() == "generic_name");
    non_generic && !generic
}

fn irregular_groups(literal: Node, src: &[u8]) -> bool {
    let t = text(literal, src);
    if !t.contains(&b'_') {
        return false;
    }
    let lower = t.to_ascii_lowercase();
    let (digits, size) = if let Some(rest) = lower.strip_prefix(b"0x") {
        (rest.to_vec(), None)
    } else if let Some(rest) = lower.strip_prefix(b"0b") {
        (rest.to_vec(), None)
    } else {
        // Decimal: the integer part, without a suffix.
        let int: Vec<u8> = lower
            .iter()
            .copied()
            .take_while(|b| b.is_ascii_digit() || *b == b'_')
            .collect();
        (int, Some(3))
    };
    let groups: Vec<&[u8]> = digits
        .split(|b| *b == b'_')
        .map(|g| {
            let end = g
                .iter()
                .position(|b| !b.is_ascii_hexdigit())
                .unwrap_or(g.len());
            &g[..end]
        })
        .collect();
    if groups.len() < 2 {
        return false;
    }
    let tail: Vec<usize> = groups[1..].iter().map(|g| g.len()).collect();
    match size {
        Some(n) => tail.iter().any(|l| *l != n) || groups[0].len() > n || groups[0].is_empty(),
        // Hex and binary: every group after the first the same size.
        None => tail.windows(2).any(|w| w[0] != w[1]) || groups[0].len() > tail[0],
    }
}

fn is_public(declaration: Node, src: &[u8]) -> bool {
    cs_has_modifier(declaration, "public", src) && !cs_has_modifier(declaration, "override", src)
}

/// Overrides and interface implementations take their name and signature
/// from the contract. Without types, a public instance method of a type with
/// base types may be one.
pub(super) fn may_implement_contract(method: Node, src: &[u8]) -> bool {
    let mut cursor = method.walk();
    let explicit = method
        .named_children(&mut cursor)
        .any(|c| c.kind() == "explicit_interface_specifier");
    let implicit = cs_has_modifier(method, "public", src)
        && !cs_has_modifier(method, "static", src)
        && enclosing_type(method).is_some_and(|t| {
            let mut c = t.walk();
            t.named_children(&mut c).any(|b| b.kind() == "base_list")
        });
    explicit || implicit || cs_has_modifier(method, "override", src)
}

fn public_list(ty: Node, src: &[u8]) -> bool {
    if simple_name(ty, src) != b"List" {
        return false;
    }
    let mut owner = ty.parent();
    for _ in 0..4 {
        match owner {
            Some(o) if matches!(o.kind(), "method_declaration" | "property_declaration") => {
                return is_public(o, src);
            }
            Some(o) => owner = o.parent(),
            None => return false,
        }
    }
    false
}

const URI_WORDS: &[&[u8]] = &[b"uri", b"url", b"urn"];

fn names_uri(name: &[u8]) -> bool {
    let lower = name.to_ascii_lowercase();
    // An XML namespace URI is an identifier, conventionally a string.
    URI_WORDS
        .iter()
        .any(|w| lower.windows(w.len()).any(|x| x == *w))
        && !lower.starts_with(b"namespace")
        && !lower.starts_with(b"xmlns")
}

fn public_string_uri_parameter(name: Node, src: &[u8]) -> bool {
    let parameter = name.parent();
    let method = parameter.and_then(|p| p.parent()).and_then(|l| l.parent());
    parameter
        .and_then(|p| p.child_by_field_name("type"))
        .is_some_and(|t| text(t, src) == b"string")
        && names_uri(text(name, src))
        && method.is_some_and(|m| is_public(m, src))
}

fn public_string_uri_member(name: Node, src: &[u8]) -> bool {
    let Some(member) = name.parent() else {
        return false;
    };
    let ty = member
        .child_by_field_name("returns")
        .or_else(|| member.child_by_field_name("type"));
    ty.is_some_and(|t| text(t, src) == b"string")
        && names_uri(text(name, src))
        && is_public(member, src)
}

const COLLECTIONS: &[&[u8]] = &[
    b"List",
    b"IList",
    b"ICollection",
    b"Collection",
    b"Dictionary",
    b"IDictionary",
    b"HashSet",
    b"ISet",
];

fn public_collection_setter<'t>(property: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !is_public(property, src)
        || !COLLECTIONS.contains(&simple_name(property.child_by_field_name("type")?, src))
    {
        return None;
    }
    // Data-transfer and serialization classes set collections on purpose, and
    // ORM navigation properties are virtual so proxies can set them.
    if enclosing_type(property).is_some_and(|c| !attribute_names(c, src).is_empty())
        || !attribute_names(property, src).is_empty()
        || cs_has_modifier(property, "virtual", src)
    {
        return None;
    }
    let accessors = property.child_by_field_name("accessors")?;
    let mut cursor = accessors.walk();
    let list: Vec<Node<'t>> = accessors.named_children(&mut cursor).collect();
    list.into_iter().find(|a| {
        a.child_by_field_name("name")
            .is_some_and(|k| text(k, src) == b"set")
            && !a
                .named_children(&mut a.walk())
                .any(|m| m.kind() == "modifier")
    })
}

fn public_nested_generic(ty: Node, src: &[u8]) -> bool {
    let method = ty
        .parent()
        .and_then(|p| p.parent())
        .and_then(|l| l.parent());
    let mut cursor = ty.walk();
    let nested = ty
        .named_children(&mut cursor)
        .filter(|c| c.kind() == "type_argument_list")
        .any(|args| {
            let mut c = args.walk();
            args.named_children(&mut c)
                .any(|a| a.kind() == "generic_name")
        });
    // Func<...> and Expression<Func<...>> are how callbacks are typed.
    let callback = matches!(
        simple_name(ty, src),
        b"Func" | b"Action" | b"Expression" | b"Predicate"
    );
    nested
        && !callback
        && method.is_some_and(|m| is_public(m, src) && !may_implement_contract(m, src))
}

fn type_parameter_not_in_parameters<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let params = text(method.child_by_field_name("parameters")?, src);
    // Some APIs are built to be called with explicit type arguments, and
    // overrides and explicit implementations can't change their signature.
    let mut c = method.walk();
    let explicit = method
        .named_children(&mut c)
        .any(|x| x.kind() == "explicit_interface_specifier");
    if params.len() <= 2 || explicit || cs_has_modifier(method, "override", src) {
        return None;
    }
    let list = method.child_by_field_name("type_parameters")?;
    let mut cursor = list.walk();
    let names: Vec<Node<'t>> = list
        .named_children(&mut cursor)
        .filter(|p| p.kind() == "type_parameter")
        .filter_map(|p| p.child_by_field_name("name"))
        .collect();
    names
        .into_iter()
        .find(|n| count_word(params, text(*n, src)) == 0)
}

fn missing_standard_constructors(name: Node, src: &[u8]) -> bool {
    let Some(class) = name.parent() else {
        return false;
    };
    let derives_exception = {
        let mut cursor = class.walk();
        class
            .named_children(&mut cursor)
            .find(|c| c.kind() == "base_list")
            .and_then(|b| b.named_child(0))
            .is_some_and(|b| simple_name(b, src).ends_with(b"Exception"))
    };
    if !derives_exception || !cs_has_modifier(class, "public", src) {
        return false;
    }
    let shapes: Vec<Vec<u8>> = members(class)
        .iter()
        .filter(|m| m.kind() == "constructor_declaration" && !cs_has_modifier(**m, "static", src))
        .filter_map(|m| m.child_by_field_name("parameters"))
        .map(|p| {
            let mut c = p.walk();
            p.named_children(&mut c)
                .filter_map(|x| {
                    x.child_by_field_name("type")
                        .map(|t| simple_name(t, src).to_vec())
                })
                .collect::<Vec<_>>()
                .join(&b',')
        })
        .collect();
    let has = |s: &[u8]| shapes.iter().any(|x| x == s);
    !(has(b"") && has(b"string") && has(b"string,Exception"))
}

fn is_namespace_name(name: Node, src: &[u8]) -> bool {
    matches!(
        text(name, src),
        b"System"
            | b"Collections"
            | b"Generic"
            | b"Linq"
            | b"IO"
            | b"Text"
            | b"Threading"
            | b"Tasks"
            | b"Net"
            | b"Http"
            | b"Data"
            | b"Xml"
            | b"Diagnostics"
            | b"Reflection"
            | b"Runtime"
            | b"Security"
            | b"Globalization"
            | b"Microsoft"
    )
}

fn is_ref_object(ty: Node, src: &[u8]) -> bool {
    text(ty, src) == b"object"
        && ty
            .parent()
            .is_some_and(|p| has_parameter_modifier(p, &[b"ref"], src))
}

fn trivial_getter_method(name: Node, src: &[u8]) -> bool {
    let Some(method) = name.parent() else {
        return false;
    };
    let no_params = method
        .child_by_field_name("parameters")
        .is_some_and(|p| p.named_child_count() == 0);
    let returns_value = method
        .child_by_field_name("returns")
        .is_some_and(|r| !matches!(text(r, src), b"void" | b"Task"));
    let Some(body) = method.child_by_field_name("body") else {
        return false;
    };
    // One return of a field or member, nothing computed.
    let value = match body.kind() {
        "arrow_expression_clause" => operand(body),
        _ => match cs_statements(body).as_slice() {
            [s] if s.kind() == "return_statement" => operand(*s),
            _ => None,
        },
    };
    is_public(method, src)
        && no_params
        && returns_value
        && method.child_by_field_name("type_parameters").is_none()
        && value.is_some_and(|v| matches!(v.kind(), "identifier" | "member_access_expression"))
}

fn culture_dependent_comparison(call: Node, src: &[u8]) -> bool {
    let method = call
        .child_by_field_name("function")
        .and_then(|f| f.child_by_field_name("name"))
        .map_or(&b""[..], |n| text(n, src));
    let args = cs_call_arguments(call);
    if args.iter().any(|a| {
        contains_ignoring_case(text(*a, src), b"StringComparison")
            || contains_ignoring_case(text(*a, src), b"Culture")
    }) {
        return false;
    }
    match method {
        // string.Compare(a, b)
        b"Compare" => {
            call.child_by_field_name("function")
                .and_then(|f| f.child_by_field_name("expression"))
                .is_some_and(|r| matches!(text(r, src), b"string" | b"String"))
                && args.len() == 2
        }
        // The char overloads are ordinal; only string arguments depend on culture.
        _ => {
            args.len() == 1
                && matches!(
                    args[0].kind(),
                    "string_literal" | "interpolated_string_expression" | "verbatim_string_literal"
                )
                && cs_string_value(args[0], src).is_none_or(|v| v.len() != 1)
        }
    }
}

fn property_with_get_method<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let ms = members(class);
    let properties: Vec<&[u8]> = ms
        .iter()
        .filter(|m| m.kind() == "property_declaration")
        .filter_map(|m| m.child_by_field_name("name").map(|n| text(n, src)))
        .collect();
    // Only methods callers see next to the property; one that takes
    // arguments reads something the property can't.
    let visible = |m: &Node| {
        (cs_has_modifier(*m, "public", src) || cs_has_modifier(*m, "protected", src))
            && m.child_by_field_name("parameters")
                .is_some_and(|p| p.named_child_count() == 0)
    };
    ms.iter()
        .filter(|m| m.kind() == "method_declaration" && visible(m))
        .find_map(|m| {
            let name = m.child_by_field_name("name")?;
            let rest = text(name, src).strip_prefix(b"Get")?;
            properties.contains(&rest).then_some(name)
        })
}

fn unsealed_attribute(name: Node, src: &[u8]) -> bool {
    let Some(class) = name.parent() else {
        return false;
    };
    let base_is_attribute = {
        let mut cursor = class.walk();
        class
            .named_children(&mut cursor)
            .find(|c| c.kind() == "base_list")
            .and_then(|b| b.named_child(0))
            .is_some_and(|b| simple_name(b, src).ends_with(b"Attribute"))
    };
    base_is_attribute
        && !["sealed", "abstract", "static"]
            .iter()
            .any(|m| cs_has_modifier(class, m, src))
}

fn operator_without_alternative<'t>(declaration: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let ms = members(declaration);
    let method_names: Vec<&[u8]> = ms
        .iter()
        .filter(|m| m.kind() == "method_declaration")
        .filter_map(|m| m.child_by_field_name("name").map(|n| text(n, src)))
        .collect();
    ms.iter()
        .filter(|m| m.kind() == "operator_declaration")
        .find_map(|op| {
            let mut cursor = op.walk();
            let token = op.children(&mut cursor).find(|c| {
                !c.is_named() && matches!(text(*c, src), b"+" | b"-" | b"*" | b"/" | b"%")
            })?;
            let wanted: &[&[u8]] = match text(token, src) {
                b"+" => &[b"Add", b"Plus"],
                b"-" => &[b"Subtract", b"Minus", b"Negate"],
                b"*" => &[b"Multiply"],
                b"/" => &[b"Divide"],
                _ => &[b"Mod", b"Remainder"],
            };
            (!wanted.iter().any(|w| method_names.contains(w))).then_some(token)
        })
}

fn extends_object(ty: Node, src: &[u8]) -> bool {
    text(ty, src) == b"object"
        && ty
            .parent()
            .is_some_and(|p| has_parameter_modifier(p, &[b"this"], src))
}

fn async_without_suffix(name: Node, src: &[u8]) -> bool {
    let Some(method) = name.parent() else {
        return false;
    };
    let n = text(name, src);
    let returns = method
        .child_by_field_name("returns")
        .map(|r| simple_name(r, src));
    let awaitable =
        matches!(returns, Some(b"Task" | b"ValueTask")) || cs_has_modifier(method, "async", src);
    // Overrides and interface implementations keep their contract's name;
    // entry points, tests and controller actions are named for their role.
    let exempt = may_implement_contract(method, src)
        || n == b"Main"
        || !attribute_names(method, src).is_empty()
        || returns == Some(b"void");
    awaitable && !exempt && !n.ends_with(b"Async")
}

fn async_argument_check<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !cs_has_modifier(method, "async", src) {
        return None;
    }
    let params = method.child_by_field_name("parameters")?;
    let mut cursor = params.walk();
    let names: Vec<&[u8]> = params
        .named_children(&mut cursor)
        .filter_map(|p| p.child_by_field_name("name").map(|n| text(n, src)))
        .collect();
    let body = method.child_by_field_name("body")?;
    // `if (Name == "2") throw new ArgumentException(...)` checks state, not an
    // argument.
    let checks_argument = |s: &Node| {
        s.child_by_field_name("condition")
            .is_some_and(|c| names.iter().any(|n| count_word(text(c, src), n) > 0))
    };
    cs_statements(body)
        .into_iter()
        .take_while(|s| {
            find_in_scope(*s, CS_SCOPE_STOPS, |n| n.kind() == "await_expression").is_none()
        })
        .filter(|s| s.kind() == "if_statement" && checks_argument(s))
        .find_map(|s| {
            find_in_scope(s, CS_SCOPE_STOPS, |n| {
                matches!(n.kind(), "throw_statement" | "throw_expression")
                    && operand(n).is_some_and(|c| {
                        c.child_by_field_name("type")
                            .is_some_and(|t| simple_name(t, src).starts_with(b"Argument"))
                    })
            })
        })
}

fn blocks_on_task(node: Node, src: &[u8]) -> bool {
    let blocks = if node.kind() == "member_access_expression" {
        node.child_by_field_name("name")
            .is_some_and(|m| text(m, src) == b"Result")
            && !node.parent().is_some_and(|p| {
                p.kind() == "invocation_expression"
                    && p.child_by_field_name("function") == Some(node)
            })
            && node
                .child_by_field_name("expression")
                .is_some_and(|r| looks_like_task(r, src))
    } else {
        let Some(function) = node.child_by_field_name("function") else {
            return false;
        };
        let method = function.child_by_field_name("name").map(|n| text(n, src));
        let receiver = function.child_by_field_name("expression");
        match method {
            Some(b"Wait") => {
                cs_call_arguments(node).is_empty()
                    && receiver.is_some_and(|r| looks_like_task(r, src))
            }
            Some(b"GetResult") => {
                receiver.is_some_and(|r| text(r, src).ends_with(b".GetAwaiter()"))
            }
            _ => false,
        }
    };
    // Rare enough that walking up to the method is cheap: tests block on
    // purpose, and a task awaited by Task.WhenAll has finished.
    blocks
        && !enclosing_method(node).is_some_and(|m| {
            is_test_method(m, src)
                || (node.kind() == "member_access_expression"
                    && m.child_by_field_name("body")
                        .zip(node.child_by_field_name("expression"))
                        .is_some_and(|(body, task)| awaited_by_when_all(body, task, node, src)))
        })
}

pub(super) fn enclosing_method(node: Node) -> Option<Node> {
    let mut current = node.parent();
    for _ in 0..128 {
        let n = current?;
        if matches!(
            n.kind(),
            "method_declaration" | "local_function_statement" | "constructor_declaration"
        ) {
            return Some(n);
        }
        current = n.parent();
    }
    None
}

/// The clock or time provider itself has to read the system time.
fn outside_clock(node: Node, src: &[u8]) -> bool {
    !enclosing_type(node)
        .and_then(|t| t.child_by_field_name("name"))
        .is_some_and(|n| {
            let name = text(n, src);
            contains_ignoring_case(name, b"Clock") || contains_ignoring_case(name, b"TimeProvider")
        })
}

fn unjustified_exclusion(attribute: Node, src: &[u8]) -> bool {
    let named = attribute.child_by_field_name("name").is_some_and(|n| {
        matches!(
            simple_name(n, src),
            b"ExcludeFromCodeCoverage" | b"ExcludeFromCodeCoverageAttribute"
        )
    });
    named
        && !attribute_arguments(attribute)
            .iter()
            .any(|(n, _)| n.is_some_and(|n| text(n, src) == b"Justification"))
}

fn is_custom_date_format(literal: Node, src: &[u8]) -> bool {
    let Some(value) = cs_string_value(literal, src) else {
        return false;
    };
    // Formatting with the invariant culture writes for machines, not users.
    let invariant = literal
        .parent()
        .and_then(|a| a.parent())
        .is_some_and(|args| contains_ignoring_case(text(args, src), b"InvariantCulture"));
    let value: Vec<u8> = value.iter().copied().filter(|b| *b != b'\'').collect();
    // A custom pattern with day, month and year parts; single-letter standard
    // specifiers and round-trip formats are fine, and so are ISO 8601 ones.
    let custom = !invariant
        && value.len() > 2
        && value.windows(2).any(|w| w == b"dd")
        && (value.windows(2).any(|w| w == b"MM") || value.windows(3).any(|w| w == b"MMM"))
        && value.windows(2).any(|w| w == b"yy");
    let iso = value.starts_with(b"yyyy-MM-dd");
    custom && !iso
}

#[cfg(test)]
mod tests {
    use super::super::cs::tests::flagged;

    fn class(body: &str) -> String {
        format!("namespace N;\npublic class A {{\n{body}\n}}\n")
    }

    #[test]
    fn opt_in_bugs() {
        let src = class(
            "int F(int limit) { limit = 10; return limit; }\nint G(int limit) { limit = Math.Min(limit, 10); return limit; }\nvoid H() { var sync = new object(); lock (sync) { } lock (field) { } }",
        );
        assert_eq!(flagged("cs/parameter-overwritten", &src), [3]);
        assert_eq!(flagged("cs/lock-on-local", &src), [5]);
        let d = "namespace N;\nclass Log { private readonly FileStream file = File.OpenWrite(\"x\"); }\nclass Ok : IDisposable { private Timer t = new Timer(); public void Dispose() { } }\nclass Given { private readonly Stream s; public Given(Stream s) { this.s = s; } }";
        assert_eq!(flagged("cs/disposable-fields-without-idisposable", d), [2]);
    }

    #[test]
    fn expressions() {
        let src = class(
            "string F(int n, string a) {\nvar s = \"n=\" + n.ToString();\nvar t = $\"{n.ToString()}\";\nvar u = n.ToString();\nvar v = a != null ? a : \"\";\nvar w = a == null ? \"\" : a;\nvar x = a != null ? a.Length : 0;\nreturn s;\n}",
        );
        assert_eq!(flagged("cs/redundant-to-string", &src), [4, 5]);
        assert_eq!(flagged("cs/use-null-coalescing", &src), [7, 8]);
    }

    #[test]
    fn calls_and_delegates() {
        let src = class(
            "void Save(string p, bool force = false) { }\nvoid F(B b) {\nSave(\"x\", false);\nSave(\"x\", true);\nSave(\"x\");\nb.Clicked += new EventHandler(OnClick);\nb.Clicked += OnClick;\nvar o = new { Name = p.Name, Total = p.Count, p.Id };\n}",
        );
        assert_eq!(flagged("cs/default-argument-passed", &src), [5]);
        assert_eq!(flagged("cs/explicit-delegate-creation", &src), [8]);
        assert_eq!(flagged("cs/redundant-anonymous-property-name", &src), [10]);
    }

    #[test]
    fn types() {
        let src = "namespace N;\nclass I { int this[double d] => 0; int this[int i] => 0; int this[string s] => 0; }\nstruct P { public int X; public override bool Equals(object o) => false; public override int GetHashCode() => 0; }\nstruct Q : IEquatable<Q> { public override bool Equals(object o) => false; public override int GetHashCode() => 0; public bool Equals(Q q) => true; }\ndelegate void SavedHandler(object sender, SavedEventArgs e);\nclass E { public event SavedHandler Saved; public event EventHandler<SavedEventArgs> Ok; }\nclass Bag : IEnumerable { }\nclass Good : IEnumerable<int>, IEnumerable { }\nclass Collections { }\nclass RetryAttribute : Attribute { }\nsealed class OkAttribute : Attribute { }";
        assert_eq!(flagged("cs/indexer-parameter-type", src), [2]);
        assert_eq!(flagged("cs/struct-without-iequatable", src), [3]);
        assert_eq!(flagged("cs/custom-event-handler-delegate", src), [6]);
        assert_eq!(flagged("cs/non-generic-collection", src), [7]);
        assert_eq!(flagged("cs/type-named-like-namespace", src), [9]);
        assert_eq!(flagged("cs/attribute-not-sealed", src), [10]);
    }

    #[test]
    fn numbers_and_dates() {
        let src = class(
            "int a = 1_00_000;\nint b = 100_000;\nint c = 0x_FF_FF;\nint d = 0xF_FF_F;\nvoid F(DateTime d) {\nvar n = DateTime.Now;\nvar u = DateTime.UtcNow;\nvar s = d.ToString(\"MM/dd/yyyy\");\nvar i = d.ToString(\"yyyy-MM-ddTHH:mm\");\nvar k = d.ToString(\"d\");\n}",
        );
        assert_eq!(flagged("cs/irregular-digit-groups", &src), [3, 6]);
        assert_eq!(flagged("cs/untestable-clock", &src), [8, 9]);
        assert_eq!(flagged("cs/local-time-recorded", &src), [8]);
        assert_eq!(flagged("cs/datetime-instead-of-offset", &src), [8, 9]);
        assert_eq!(flagged("cs/hardcoded-date-format", &src), [10]);
    }

    #[test]
    fn public_api() {
        let src = class(
            "public List<int> Items { get; set; } = new();\npublic IReadOnlyList<int> View => Items;\npublic List<int> Load(string url) => null;\npublic void Fetch(Uri uri, string homeUrl) { }\npublic string GetUrl() => \"\";\npublic string HomeUrl { get; set; }\npublic void Rows(List<Dictionary<string, int>> rows) { }\npublic void Map(Expression<Func<A, int>> f) { }\nT Read<T>(string key) => default;\nT ReadOr<T>(string key, T fallback) => fallback;",
        );
        assert_eq!(flagged("cs/list-in-public-api", &src), [3, 5, 9]);
        assert_eq!(flagged("cs/settable-collection-property", &src), [3]);
        assert_eq!(flagged("cs/string-uri-parameter", &src), [5, 6]);
        assert_eq!(flagged("cs/string-uri-return", &src), [7]);
        assert_eq!(flagged("cs/string-uri-property", &src), [8]);
        assert_eq!(flagged("cs/nested-generic-signature", &src), [9]);
        assert_eq!(flagged("cs/uninferable-type-parameter", &src), [11]);
    }

    #[test]
    fn exceptions_and_members() {
        let src = "namespace N;\npublic class QuotaException : Exception { public QuotaException(string m) : base(m) { } }\npublic class FullException : Exception { public FullException() { } public FullException(string m) : base(m) { } public FullException(string m, Exception i) : base(m, i) { } }\npublic class A {\nstring name;\npublic string GetName() { return name; }\npublic string GetComputed() => name + \"x\";\npublic int Count => 1;\npublic int GetCount() => 1;\nvoid Swap(ref object a, ref object b) { }\npublic static Money operator +(Money a, Money b) => a;\n}\nstatic class X { public static string Dump(this object o) => \"\"; public static string Dump2(this A a) => \"\"; }";
        assert_eq!(flagged("cs/exception-standard-constructors", src), [2]);
        assert_eq!(flagged("cs/get-method-could-be-property", src), [6]);
        assert_eq!(flagged("cs/property-and-get-method", src), [9]);
        assert_eq!(flagged("cs/ref-object-parameter", src), [10, 10]);
        assert_eq!(flagged("cs/operator-without-named-alternative", src), [11]);
        assert_eq!(flagged("cs/extension-on-object", src), [13]);
    }

    #[test]
    fn strings_and_async() {
        let src = class(
            "bool F(string s) {\nvar a = s.StartsWith(\"abc\");\nvar b = s.StartsWith(\"abc\", StringComparison.Ordinal);\nvar c = s.StartsWith('a');\nvar d = string.Compare(s, \"x\");\nvar e = s.ToLowerInvariant();\nreturn a;\n}\nasync Task Save() { await G(); }\nasync Task SaveAsync() { await G(); }\npublic override async Task Run() { await G(); }\nasync Task Load(string s) { if (s == null) { throw new ArgumentNullException(nameof(s)); } await G(); }\nstring H(HttpClient h) { var x = h.GetStringAsync(u).Result; GetAsync().Wait(); return x; }\n[ExcludeFromCodeCoverage] void K() { }\n[ExcludeFromCodeCoverage(Justification = \"x\")] void L() { }",
        );
        assert_eq!(flagged("cs/string-comparison-overload", &src), [4, 7]);
        assert_eq!(flagged("cs/normalize-to-upper", &src), [8]);
        assert_eq!(flagged("cs/async-method-name", &src), [11, 14]);
        assert_eq!(flagged("cs/async-argument-validation", &src), [14]);
        assert_eq!(flagged("cs/blocking-async-call", &src), [15, 15]);
        assert_eq!(
            flagged("cs/exclude-from-coverage-without-justification", &src),
            [16]
        );
    }

    /// Shapes found reviewing the rules on real code, none of them reported.
    #[test]
    fn corpus_false_positives() {
        let src = "namespace N;\n\
            class H : IRequestHandler<Ping> { public async Task Handle(Ping p) { await G(); } public Task<List<T>> Run(RequestHandlerDelegate<List<T>> next) => next(); }\n\
            class C : I { TDest I.Plan<TSrc, TDest>(in MapRequest r) => default; }\n\
            class S { bool Bind(string name, [NotNullWhen(true)] out Prop? p) { p = null; return false; } }\n\
            class L { void F() { var table = GetTable(); lock (table) { } } }\n\
            class V { void F() { var e = new Action(Validate).ShouldThrow<E>(); var s = new ThreadSafeStore<string, Func<int>>(Create); } }\n\
            class D<TKey, TValue> { public TValue this[TKey key] => default; }\n\
            class E { public virtual ICollection<Foo> Foos { get; set; } }\n\
            public class X { public IXmlElement CreateElement(string name, string namespaceUri) => null; }\n\
            class P { public int Id => 1; internal int GetId() => 1; private static int GetCount() => 1; public int Count => 1; public static string Key => \"\"; public static string GetKey(Type t) => \"\"; }\n\
            class U { string F(DateTime d, char c) { var a = d.ToString(\"yyyy'-'MM'-'dd\", CultureInfo.InvariantCulture); var b = char.ToLowerInvariant(c); return a; } }\n\
            class Q { public string Name; async Task FAsync(int n) { if (Name == \"2\") { throw new ArgumentException(\"no\"); } await G(n); } }\n\
            class W { async Task FAsync() { var t = LoadTask(); await Task.WhenAll(t); var r = t.Result; } [Fact] public void T() { var r = GetAsync().Result; } }\n\
            class SystemTimeProvider { public DateTimeOffset GetLocalNow() => DateTimeOffset.Now; }";
        for rule in [
            "cs/async-method-name",
            "cs/nested-generic-signature",
            "cs/uninferable-type-parameter",
            "cs/parameter-overwritten",
            "cs/lock-on-local",
            "cs/explicit-delegate-creation",
            "cs/indexer-parameter-type",
            "cs/settable-collection-property",
            "cs/string-uri-parameter",
            "cs/property-and-get-method",
            "cs/hardcoded-date-format",
            "cs/normalize-to-upper",
            "cs/async-argument-validation",
            "cs/blocking-async-call",
            "cs/untestable-clock",
        ] {
            assert_eq!(flagged(rule, src), [0usize; 0], "{rule}");
        }
    }
}
