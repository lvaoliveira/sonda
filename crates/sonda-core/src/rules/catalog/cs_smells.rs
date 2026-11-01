//! C# code smell rules (ADR-0007, ADR-0015, batch 3). Queries stay cheap on
//! deep trees: see the notes in `js_modern.rs`.

use super::cs::{
    CS_SCOPE_STOPS, cs_has_modifier, cs_statements, cs_string_value, operand, same_code,
    simple_name,
};
use super::cs_bugs::{attribute_names, cs_call_arguments, cs_integer, find_attribute};
use super::java_bugs::{find_in_scope, operator_text};
use super::java_security::text;
use super::java_smells::count_word;
use super::*;

/// Rules that are off unless `rules.enabled` lists them (see
/// `catalog::OFF_BY_DEFAULT`).
pub(super) static OFF_BY_DEFAULT: &[&str] = &[];

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "cs/for-counter-modified-in-body",
        name: "A for loop's counter should not be changed in its body",
        description: "The header says how the loop advances; changing the counter in the body as well makes \
                      the iteration hard to follow and easy to break.",
        message: "Don't change the loop counter here; use a while loop if the steps vary.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S127")],
        check: Check::Query {
            langs: CSHARP,
            query: "(for_statement update: (_) body: (block)) @match",
            filter: Some(Find(counter_changed_in_body)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(int n) { for (int i = 0; i < n; i++) { if (G(i)) { i++; } } } }",
            good: "class A { void F(int n) { int i = 0; while (i < n) { i += G(i) ? 2 : 1; } } }",
        }),
    },
    Rule {
        id: "cs/goto",
        name: "goto should not be used",
        description: "`goto` jumps make the flow of a method hard to follow; loops, `break` and methods say the \
                      same more clearly.",
        message: "Replace this goto with a loop, a break or a method call.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S907")],
        check: Check::Query {
            langs: CSHARP,
            query: "(goto_statement) @match",
            filter: Some(Keep(is_plain_goto)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F() { retry: if (!G()) { goto retry; } } }",
            good: "class A { void F() { while (!G()) { } switch (x) { case 1: H(); goto case 2; case 2: break; } } }",
        }),
    },
    Rule {
        id: "cs/public-field",
        name: "Fields should not be public",
        description: "A public field can't be validated, observed or changed into a computed value later without \
                      breaking callers; a property can.",
        message: "Make this field private and expose it through a property.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S1104")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration body: (declaration_list (field_declaration (modifier)) @match))",
            filter: Some(Keep(is_public_instance_field)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { public int Count; }",
            good: "class A { public int Count { get; set; } public const int Max = 10; public readonly int Id; }",
        }),
    },
    Rule {
        id: "cs/redundant-parentheses",
        name: "Expressions should not be wrapped in two pairs of parentheses",
        description: "`((x))` is `(x)`; the extra pair adds nothing.",
        message: "Remove the redundant pair of parentheses.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S1110")],
        check: Check::Query {
            langs: CSHARP,
            query: "(parenthesized_expression (parenthesized_expression) @match)",
            filter: None,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int F(int a) { return ((a + 1)); } }",
            good: "class A { int F(int a) { return (a + 1) * 2; } }",
        }),
    },
    Rule {
        id: "cs/instantiable-utility-class",
        name: "Classes with only static members should be static",
        description: "Nothing is gained by creating an instance of a class whose members are all static; \
                      declaring the class static says so and stops it.",
        message: "Make this class static.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1118")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration name: (identifier) body: (declaration_list)) @match",
            filter: Some(Find(utility_class_name)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class Paths { public static string Root() => \"/\"; }",
            good: "static class Paths { public static string Root() => \"/\"; }",
        }),
    },
    Rule {
        id: "cs/obsolete-code",
        name: "Obsolete code should eventually be removed",
        description: "Code marked [Obsolete] is meant to go away; this marks where it still is.",
        message: "Remove this obsolete code once its callers have moved on.",
        category: CodeSmell,
        severity: Info,
        effort_minutes: 15,
        sonar: &[exact("S1133")],
        check: Check::Query {
            langs: CSHARP,
            query: "(attribute name: (_)) @match",
            filter: Some(Keep(is_obsolete_attribute)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { [Obsolete(\"Use G.\")] void F() { G(); } }",
            good: "class A { void G() { H(); } }",
        }),
    },
    Rule {
        id: "cs/throw-in-finally",
        name: "Exceptions should not be thrown from finally blocks",
        description: "An exception thrown in `finally` replaces the one that may already be on its way, which \
                      is then lost.",
        message: "Don't throw from this finally block.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S1163")],
        check: Check::Query {
            langs: CSHARP,
            query: "(finally_clause (block) @match)",
            filter: Some(Find(uncaught_throw)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F() { try { G(); } finally { throw new IOException(); } } }",
            good: "class A { void F() { try { G(); } finally { Close(); } } }",
        }),
    },
    Rule {
        id: "cs/null-instead-of-empty-collection",
        name: "Methods returning collections should return empty ones, not null",
        description: "Callers iterate the result; returning null makes each of them check for it, and the one \
                      that forgets throws a NullReferenceException.",
        message: "Return an empty collection instead of null.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1168")],
        check: Check::Query {
            langs: CSHARP,
            query: "(method_declaration returns: [(array_type) (generic_name) (qualified_name)]) @match",
            filter: Some(Find(collection_null)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int[] F(bool b) { if (b) { return null; } return G(); } }",
            good: "class A { int[] F(bool b) { if (b) { return Array.Empty<int>(); } return G(); } }",
        }),
    },
    Rule {
        id: "cs/override-only-calls-base",
        name: "Overrides should do more than call the base member",
        description: "An override that only forwards to `base` with the same arguments changes nothing.",
        message: "Remove this override, which only calls the base implementation.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S1185")],
        check: Check::Query {
            langs: CSHARP,
            query: "(method_declaration (modifier) name: (identifier) body: (_)) @match",
            filter: Some(Find(only_calls_base)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A : B { public override void Save(int x) { base.Save(x); } }",
            good: "class A : B { public override void Save(int x) { Log(x); base.Save(x); } }",
        }),
    },
    Rule {
        id: "cs/nested-block",
        name: "Bare nested blocks should be removed",
        description: "A `{ ... }` block on its own suggests a forgotten condition, or a method waiting to be extracted.",
        message: "Remove this nested block, or extract it into a method.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S1199")],
        check: Check::Query {
            langs: CSHARP,
            query: "(block (block) @match)",
            filter: None,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F() { G(); { H(); } } }",
            good: "class A { void F() { G(); H(); } }",
        }),
    },
    Rule {
        id: "cs/for-as-while",
        name: "A for loop without initializer and update should be a while loop",
        description: "`for (; cond; )` is a `while (cond)` written in a harder way.",
        message: "Replace this for loop with a while loop.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S1264")],
        check: Check::Query {
            langs: CSHARP,
            query: "(for_statement condition: (_)) @match",
            filter: Some(Keep(only_condition)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F() { for (; More();) { G(); } } }",
            good: "class A { void F() { while (More()) { G(); } } }",
        }),
    },
    Rule {
        id: "cs/too-many-switch-cases",
        name: "switch statements should not have too many cases",
        description: "More than 30 cases are hard to read; a dictionary or polymorphism usually expresses the \
                      mapping better.",
        message: "Reduce the number of cases in this switch (more than 30).",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 30,
        sonar: &[exact("S1479")],
        check: Check::Query {
            langs: CSHARP,
            query: "(switch_statement body: (switch_body)) @match",
            filter: Some(Keep(has_too_many_cases)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int F(int x) { switch (x) { case 0: case 1: case 2: case 3: case 4: case 5: case 6: case 7: \
                  case 8: case 9: case 10: case 11: case 12: case 13: case 14: case 15: case 16: case 17: case 18: case 19: \
                  case 20: case 21: case 22: case 23: case 24: case 25: case 26: case 27: case 28: case 29: case 30: return 1; \
                  default: return 0; } } }",
            good: "class A { int F(int x) { switch (x) { case 0: return 1; default: return 0; } } }",
        }),
    },
    Rule {
        id: "cs/catch-null-reference",
        name: "NullReferenceException should not be caught",
        description: "A NullReferenceException is a bug in the code that threw it; catching it hides the bug \
                      instead of fixing it.",
        message: "Check for null where it can occur instead of catching NullReferenceException.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1696")],
        check: Check::Query {
            langs: CSHARP,
            query: "(catch_declaration type: (_) @match)",
            filter: Some(Keep(is_null_reference_type)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(B b) { try { b.G(); } catch (NullReferenceException) { } } }",
            good: "class A { void F(B b) { b?.G(); } }",
        }),
    },
    Rule {
        id: "cs/constructor-calls-virtual",
        name: "Constructors should not call overridable methods",
        description: "A subclass's override runs before the subclass's constructor, on an object that isn't \
                      initialized yet.",
        message: "Don't call this virtual method from the constructor, or make it non-virtual.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S1699")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration body: (declaration_list)) @match",
            filter: Some(Find(virtual_call_in_constructor)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { public A() { Init(); } protected virtual void Init() { } }",
            good: "class A { public A() { Init(); } private void Init() { G(); } }",
        }),
    },
    Rule {
        id: "cs/identical-branches-in-chain",
        name: "Two branches of an if chain should not have the same implementation",
        description: "Repeating a block in two branches suggests they should be merged into one condition.",
        message: "Merge this branch with the identical one above it.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S1871")],
        check: Check::Query {
            langs: CSHARP,
            query: "(if_statement alternative: (_)) @match",
            filter: Some(Find(chain_repeats_a_branch)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(bool a, bool b) { if (a) { G(); H(); } else if (b) { G(); H(); } } }",
            good: "class A { void F(bool a, bool b) { if (a || b) { G(); H(); } } }",
        }),
    },
    Rule {
        id: "cs/for-update-other-variable",
        name: "A for loop should update the variable its condition tests",
        description: "When the condition tests one variable and the update changes another, the loop probably \
                      updates the wrong one and never ends.",
        message: "Update the variable the loop condition tests.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S1994")],
        check: Check::Query {
            langs: CSHARP,
            query: "(for_statement condition: (_) update: (_)) @match",
            filter: Some(Find(update_misses_condition)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(int n, int j) { for (int i = 0; i < n; j++) { G(i); } } }",
            good: "class A { void F(int n) { for (int i = 0; i < n; i++) { G(i); } } }",
        }),
    },
    Rule {
        id: "cs/empty-class",
        name: "Classes should not be empty",
        description: "An empty class has no behaviour and no data; an interface or an attribute usually says \
                      what it is for.",
        message: "Remove this empty class, or give it members.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S2094")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration name: (identifier) body: (declaration_list)) @match",
            filter: Some(Find(empty_class_name)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class Marker { }",
            good: "interface IMarker { } class Failure : Exception { } [Serializable] class Tag { }",
        }),
    },
    Rule {
        id: "cs/exception-name-without-base",
        name: "Classes named like exceptions should derive from Exception",
        description: "A class called `...Exception` that isn't one can't be thrown or caught, which surprises \
                      everyone who reads the name.",
        message: "Derive this class from Exception, or rename it.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2166")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(class_declaration name: (identifier) @match (#match? @match "Exception$"))"#,
            filter: Some(Keep(class_has_no_base)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class ParseException { public string Reason; }",
            good: "class ParseException : Exception { }",
        }),
    },
    Rule {
        id: "cs/virtual-field-event",
        name: "Field-like events should not be virtual",
        description: "The compiler doesn't handle overridden field-like events as expected: subscribers to the \
                      base event aren't raised by the override.",
        message: "Make this event non-virtual, or declare add and remove accessors.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S2290")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(event_field_declaration (modifier) @m (#eq? @m "virtual")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { public virtual event EventHandler Changed; }",
            good: "class A { public event EventHandler Changed; }",
        }),
    },
    Rule {
        id: "cs/unused-type-parameter",
        name: "Type parameters should be used",
        description: "A type parameter that appears nowhere in its declaration makes callers specify a type \
                      for nothing.",
        message: "Remove this unused type parameter.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2326")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(method_declaration type_parameters: (_)) (class_declaration (type_parameter_list))] @match",
            filter: Some(Find(unused_type_parameter)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F<T>(int x) { G(x); } }",
            good: "class A { void F<T>(T x) { G(x); } }",
        }),
    },
    Rule {
        id: "cs/flags-zero-not-none",
        name: "[Flags] enums should name their zero member None",
        description: "Zero means no flag is set; calling it anything else suggests it's a flag of its own.",
        message: "Name this zero-valued member 'None'.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 2,
        sonar: &[exact("S2346")],
        check: Check::Query {
            langs: CSHARP,
            query: "(enum_declaration (attribute_list) body: (enum_member_declaration_list)) @match",
            filter: Some(Find(zero_flag_not_none)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "[Flags] enum Access { Nothing = 0, Read = 1, Write = 2 }",
            good: "[Flags] enum Access { None = 0, Read = 1, Write = 2 }",
        }),
    },
    Rule {
        id: "cs/multidimensional-array-parameter",
        name: "Public methods should not take multidimensional or jagged arrays",
        description: "`int[,]` and `int[][]` parameters are awkward to build and easy to misuse; a dedicated \
                      type or a collection of collections is clearer.",
        message: "Replace this multidimensional array parameter with a clearer type.",
        category: CodeSmell,
        severity: Blocker,
        effort_minutes: 10,
        sonar: &[exact("S2368")],
        check: Check::Query {
            langs: CSHARP,
            query: "(method_declaration (modifier) parameters: (parameter_list (parameter type: (array_type) @match)))",
            filter: Some(Keep(is_public_multidimensional)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { public void Load(int[,] grid) { G(grid); } }",
            good: "class A { public void Load(Grid grid) { G(grid); } }",
        }),
    },
    Rule {
        id: "cs/property-getter-throws",
        name: "Property getters should not throw unexpected exceptions",
        description: "Reading a property is expected to be safe; debuggers and serializers read them freely. \
                      Throw from a method instead, or only InvalidOperationException, NotSupportedException \
                      or ObjectDisposedException.",
        message: "Make this a method, or throw InvalidOperationException instead.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S2372")],
        check: Check::Query {
            langs: CSHARP,
            query: "(property_declaration) @match",
            filter: Some(Find(getter_throw)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int x; public int X { get { if (x < 0) { throw new ArgumentException(); } return x; } } }",
            good: "class A { int x; public int X { get { if (x < 0) { throw new InvalidOperationException(); } return x; } } }",
        }),
    },
    Rule {
        id: "cs/write-only-property",
        name: "Properties should not be write-only",
        description: "A property that can be set but not read surprises callers; a method such as `SetX` says \
                      what it does.",
        message: "Add a getter, or replace this property with a method.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2376")],
        check: Check::Query {
            langs: CSHARP,
            query: "(property_declaration name: (identifier) accessors: (accessor_list)) @match",
            filter: Some(Find(write_only_name)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int x; public int X { set { x = value; } } }",
            good: "class A { int x; public int X { get => x; set => x = value; } }",
        }),
    },
    Rule {
        id: "cs/too-many-type-parameters",
        name: "Generic types and methods should not have too many type parameters",
        description: "More than two type parameters on a class, or three on a method, make it hard to use and \
                      to read.",
        message: "Reduce the number of type parameters.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 15,
        sonar: &[exact("S2436")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(method_declaration type_parameters: (_)) (class_declaration (type_parameter_list))] @match",
            filter: Some(Find(too_many_type_parameters)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class Mapper<A, B, C> { }",
            good: "class Mapper<TIn, TOut> { }",
        }),
    },
    Rule {
        id: "cs/useless-bitwise",
        name: "Bitwise operations should not have no effect",
        description: "`x | 0`, `x ^ 0` and `x & -1` all equal `x`: another operand was probably meant.",
        message: "Remove this operation, which doesn't change the value, or fix its operand.",
        category: CodeSmell,
        severity: Blocker,
        effort_minutes: 2,
        sonar: &[exact("S2437")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(binary_expression) (assignment_expression)] @match",
            filter: Some(Keep(is_useless_bitwise)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int F(int x) { return x | 0; } }",
            good: "class A { int F(int x) { return x | 1; } }",
        }),
    },
    Rule {
        id: "cs/index-of-positive",
        name: "IndexOf results should be tested with >= 0",
        description: "`IndexOf` returns 0 when the value is found at the start, so `> 0` misses that case.",
        message: "Test for '>= 0' (or '!= -1'), which includes a match at the first position.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 2,
        sonar: &[exact("S2692")],
        check: Check::Query {
            langs: CSHARP,
            query: "(binary_expression) @match",
            filter: Some(Keep(tests_index_of_positive)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { bool F(string s) { return s.IndexOf(\"x\") > 0; } }",
            good: "class A { bool F(string s) { return s.IndexOf(\"x\") >= 0; } }",
        }),
    },
    Rule {
        id: "cs/reflection-non-public",
        name: "Reflection should not reach non-public members",
        description: "BindingFlags.NonPublic bypasses accessibility: the code depends on another type's \
                      internals, which may change or be protected for a reason.",
        message: "Use the public API instead of reaching non-public members.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 15,
        sonar: &[exact("S3011")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(member_access_expression expression: (_) @t name: (identifier) @n
                        (#match? @t "(^|\\.)BindingFlags$") (#eq? @n "NonPublic")) @match"#,
            filter: Some(Keep(not_negated)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { object F(Type t) { return t.GetField(\"x\", BindingFlags.NonPublic | BindingFlags.Instance); } }",
            good: "class A { object F(Type t) { return t.GetProperty(\"X\", BindingFlags.Public | BindingFlags.Instance); } }",
        }),
    },
    Rule {
        id: "cs/this-is-type",
        name: "this should not be tested for its own subtypes",
        description: "A class testing `this is Derived` knows about its subclasses; virtual members let each \
                      subclass do its part instead.",
        message: "Move this subtype-specific behaviour into an overridden member.",
        category: CodeSmell,
        severity: Blocker,
        effort_minutes: 10,
        sonar: &[exact("S3060")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(is_pattern_expression) (is_expression)] @match",
            filter: Some(Keep(tests_this)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int F() { return this is B ? 1 : 0; } }",
            good: "class A { protected virtual int F() { return 0; } }",
        }),
    },
    Rule {
        id: "cs/repeated-order-by",
        name: "OrderBy should not be called twice in a row",
        description: "The second `OrderBy` discards the first ordering; `ThenBy` adds a secondary key instead.",
        message: "Use ThenBy (or ThenByDescending) for the secondary ordering.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S3169")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(invocation_expression
                        function: (member_access_expression
                          expression: (invocation_expression
                            function: (member_access_expression name: (identifier) @a))
                          name: (identifier) @b)
                        (#match? @a "^OrderBy(Descending)?$")
                        (#match? @b "^OrderBy(Descending)?$")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { object F(List<P> ps) { return ps.OrderBy(p => p.Last).OrderBy(p => p.First); } }",
            good: "class A { object F(List<P> ps) { return ps.OrderBy(p => p.Last).ThenBy(p => p.First); } }",
        }),
    },
    Rule {
        id: "cs/duplicate-cast",
        name: "A type check should not be followed by a cast to the same type",
        description: "`if (x is T) { var t = (T)x; }` checks the type twice; `if (x is T t)` does it once.",
        message: "Use a pattern ('x is T t') instead of checking and then casting.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S3247")],
        check: Check::Query {
            langs: CSHARP,
            query: "(if_statement condition: [(is_pattern_expression) (is_expression)] consequence: (_)) @match",
            filter: Some(Find(cast_after_type_check)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(object o) { if (o is string) { var s = (string)o; G(s); } } }",
            good: "class A { void F(object o) { if (o is string s) { G(s); } } }",
        }),
    },
    Rule {
        id: "cs/empty-namespace",
        name: "Namespaces should not be empty",
        description: "An empty namespace declaration is a leftover.",
        message: "Remove this empty namespace.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S3261")],
        check: Check::Query {
            langs: CSHARP,
            query: "(namespace_declaration name: (_) @match body: (declaration_list) @b)",
            filter: Some(Keep(namespace_is_empty)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "namespace Shop.Legacy { }",
            good: "namespace Shop { class Cart { } }",
        }),
    },
    Rule {
        id: "cs/type-suffix-from-base",
        name: "Attributes, EventArgs and exceptions should be named after their base",
        description: "By convention, attribute classes end in `Attribute`, event data in `EventArgs` and \
                      exceptions in `Exception`; tools and readers rely on it.",
        message: "Add the suffix of the base type to this class's name.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S3376")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration name: (identifier) (base_list)) @match",
            filter: Some(Find(missing_conventional_suffix)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class Retry : Attribute { }",
            good: "class RetryAttribute : Attribute { }",
        }),
    },
    Rule {
        id: "cs/check-before-assign",
        name: "A variable should not be checked against the value it is about to get",
        description: "`if (x != 1) { x = 1; }` gives the same result as `x = 1;` alone.",
        message: "Remove this check and assign unconditionally.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S3440")],
        check: Check::Query {
            langs: CSHARP,
            query: "(if_statement condition: (binary_expression) consequence: (_)) @match",
            filter: Some(Keep(checks_before_assigning)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int x; void F() { if (x != 1) { x = 1; } } }",
            good: "class A { int x; void F() { x = 1; } }",
        }),
    },
    Rule {
        id: "cs/empty-case-before-default",
        name: "Empty case labels that fall into default should be removed",
        description: "A `case` with no code of its own that falls into `default:` behaves like the default and \
                      adds nothing.",
        message: "Remove this case label, which is covered by default.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S3458")],
        check: Check::Query {
            langs: CSHARP,
            query: "(switch_body) @match",
            filter: Some(Find(empty_case_before_default)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int F(int x) { switch (x) { case 1: return 1; case 2: default: return 0; } } }",
            good: "class A { int F(int x) { switch (x) { case 1: return 1; default: return 0; } } }",
        }),
    },
    Rule {
        id: "cs/non-public-exception",
        name: "Exception types should be public",
        description: "Callers outside the assembly can't catch a non-public exception by its type, only as a \
                      general Exception.",
        message: "Make this exception class public.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 2,
        sonar: &[exact("S3871")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration name: (identifier) (base_list)) @match",
            filter: Some(Find(non_public_exception_name)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "namespace N { internal class QuotaException : Exception { } }",
            good: "namespace N { public class QuotaException : Exception { } }",
        }),
    },
    Rule {
        id: "cs/class-equality-operator",
        name: "operator== should not be overloaded on classes",
        description: "Readers expect `==` on a class to compare references; overloading it changes that \
                      silently. Override Equals instead, or use a record or struct.",
        message: "Override Equals instead of overloading operator== on this class.",
        category: CodeSmell,
        severity: Blocker,
        effort_minutes: 10,
        sonar: &[exact("S3875")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration body: (declaration_list (operator_declaration) @match))",
            filter: Some(Keep(overloads_equality)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class Money { public static bool operator ==(Money a, Money b) => true; public static bool operator !=(Money a, Money b) => false; }",
            good: "record Money(decimal Amount);",
        }),
    },
    Rule {
        id: "cs/throw-in-unexpected-method",
        name: "Exceptions should not be thrown from methods expected to be safe",
        description: "`ToString`, `Equals`, `GetHashCode`, `Dispose`, implicit conversions, static constructors \
                      and finalizers are called implicitly, often where an exception isn't expected or can't \
                      be handled.",
        message: "Don't throw from this method.",
        category: CodeSmell,
        severity: Blocker,
        effort_minutes: 10,
        sonar: &[exact("S3877")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(method_declaration body: (_)) (conversion_operator_declaration body: (_)) \
                     (constructor_declaration body: (_))] @match",
            filter: Some(Find(throw_in_safe_method)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { public override string ToString() { throw new InvalidOperationException(); } }",
            good: "class A { public override string ToString() { return \"A\"; } }",
        }),
    },
    Rule {
        id: "cs/assembly-load-from",
        name: "Assembly.LoadFrom, LoadFile and LoadWithPartialName should not be used",
        description: "They load assemblies outside the normal binding context, which leads to type identity \
                      problems and loading the wrong version.",
        message: "Use Assembly.Load with the assembly's full name.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S3885")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(invocation_expression
                        function: (member_access_expression expression: (_) @t name: (identifier) @n)
                        (#match? @t "(^|\\.)Assembly$")
                        (#any-of? @n "LoadFrom" "LoadFile" "LoadWithPartialName")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { Assembly F(string p) { return Assembly.LoadFrom(p); } }",
            good: "class A { Assembly F(string name) { return Assembly.Load(name); } }",
        }),
    },
    Rule {
        id: "cs/argument-exception-param-name",
        name: "ArgumentException parameter names should name a parameter",
        description: "The parameter name tells the caller which argument was wrong; one that doesn't exist \
                      points them nowhere.",
        message: "Pass the name of one of this method's parameters, preferably with nameof().",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S3928")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(object_creation_expression type: (_) @t arguments: (argument_list)
                        (#match? @t "Argument(Null|OutOfRange)?Exception$")) @match"#,
            filter: Some(Find(unknown_parameter_name)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(string name) { if (name == null) { throw new ArgumentNullException(\"nmae\"); } } }",
            good: "class A { void F(string name) { if (name == null) { throw new ArgumentNullException(nameof(name)); } } }",
        }),
    },
    Rule {
        id: "cs/suppress-finalize-outside-dispose",
        name: "GC.SuppressFinalize should only be called from Dispose",
        description: "Suppressing finalization anywhere else can skip cleanup of an object that wasn't disposed.",
        message: "Call GC.SuppressFinalize(this) only in Dispose().",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3971")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(method_declaration name: (identifier) @n body: (_) @b
                        (#not-any-of? @n "Dispose" "DisposeAsync" "DisposeAsyncCore")) @match"#,
            filter: Some(Find(suppress_finalize_call)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A : IDisposable { public void Close() { GC.SuppressFinalize(this); } public void Dispose() { Close(); } }",
            good: "class A : IDisposable { public void Dispose() { Close(); GC.SuppressFinalize(this); } }",
        }),
    },
    Rule {
        id: "cs/attribute-usage-missing",
        name: "Custom attributes should declare [AttributeUsage]",
        description: "Without it the attribute can go on any target, once, and is inherited, which is rarely \
                      what was intended.",
        message: "Add [AttributeUsage] stating where this attribute applies.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S3993")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration name: (identifier) (base_list)) @match",
            filter: Some(Find(attribute_without_usage)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "sealed class RetryAttribute : Attribute { }",
            good: "[AttributeUsage(AttributeTargets.Method)] sealed class RetryAttribute : Attribute { }",
        }),
    },
    Rule {
        id: "cs/outdated-base-type",
        name: "Types should not derive from outdated base types",
        description: "ApplicationException, CollectionBase, DictionaryBase and the non-generic collections are \
                      kept for compatibility; Exception and the generic collections replace them.",
        message: "Derive from the modern equivalent of this base type.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 10,
        sonar: &[exact("S4052")],
        check: Check::Query {
            langs: CSHARP,
            query: "(base_list (_) @match)",
            filter: Some(Keep(is_outdated_base)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class QuotaException : ApplicationException { }",
            good: "class QuotaException : Exception { }",
        }),
    },
    Rule {
        id: "cs/overloads-not-adjacent",
        name: "Method overloads should be declared together",
        description: "Overloads spread across a class are easy to miss when reading or changing one of them.",
        message: "Move this overload next to the other ones.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S4136")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(class_declaration body: (declaration_list)) (struct_declaration body: (declaration_list)) \
                     (interface_declaration body: (declaration_list))] @match",
            filter: Some(Find(separated_overload)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(int x) { } void G() { } void F(string s) { } }",
            good: "class A { void F(int x) { } void F(string s) { } void G() { } }",
        }),
    },
    Rule {
        id: "cs/default-not-first-or-last",
        name: "default clauses should be first or last",
        description: "A `default:` in the middle of the cases is easy to overlook.",
        message: "Move this default clause to the beginning or the end of the switch.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 2,
        sonar: &[exact("S4524")],
        check: Check::Query {
            langs: CSHARP,
            query: "(switch_body) @match",
            filter: Some(Find(default_in_the_middle)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int F(int x) { switch (x) { case 1: return 1; default: return 0; case 2: return 2; } } }",
            good: "class A { int F(int x) { switch (x) { case 1: return 1; case 2: return 2; default: return 0; } } }",
        }),
    },
    Rule {
        id: "cs/new-guid",
        name: "new Guid() should not be used",
        description: "`new Guid()` is the all-zero Guid, not a new unique one; that is rarely what's meant.",
        message: "Use Guid.NewGuid() for a new value, or Guid.Empty for the empty one.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S4581")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(object_creation_expression type: (_) @t arguments: (argument_list) @a
                        (#match? @t "^(System\\.)?Guid$")) @match"#,
            filter: Some(Keep(no_arguments_or_initializer)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { Guid F() { return new Guid(); } }",
            good: "class A { Guid F() { return Guid.NewGuid(); } }",
        }),
    },
    Rule {
        id: "cs/substring-then-search",
        name: "Strings should be searched with a start index, not after Substring",
        description: "`s.Substring(i).IndexOf(x)` copies the string and returns a position relative to `i`; \
                      `s.IndexOf(x, i)` does neither.",
        message: "Pass the start index to the search method instead of calling Substring.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S4635")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(invocation_expression
                        function: (member_access_expression
                          expression: (invocation_expression
                            function: (member_access_expression name: (identifier) @s))
                          name: (identifier) @n)
                        (#eq? @s "Substring")
                        (#any-of? @n "IndexOf" "IndexOfAny" "LastIndexOf" "LastIndexOfAny")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int F(string s, int i) { return s.Substring(i).IndexOf('x'); } }",
            good: "class A { int F(string s, int i) { return s.IndexOf('x', i); } }",
        }),
    },
    Rule {
        id: "cs/empty-comment",
        name: "Comments should not be empty",
        description: "An empty comment is a leftover that adds noise.",
        message: "Remove this empty comment.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S4663")],
        check: Check::Query {
            langs: CSHARP,
            query: "(comment) @match",
            filter: Some(Keep(is_empty_comment)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F() { //\n G(); } }",
            good: "class A { void F() { // explain why\n G(); } }",
        }),
    },
    Rule {
        id: "cs/unix-epoch",
        name: "DateTime.UnixEpoch should be used for the Unix epoch",
        description: "`new DateTime(1970, 1, 1)` spells out a constant the framework already has, and easily \
                      gets the DateTimeKind wrong.",
        message: "Use DateTime.UnixEpoch (or DateTimeOffset.UnixEpoch).",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6588")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(object_creation_expression type: (_) @t arguments: (argument_list)
                        (#match? @t "^(System\\.)?DateTime(Offset)?$")) @match"#,
            filter: Some(Keep(is_unix_epoch)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { DateTime E() { return new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc); } }",
            good: "class A { DateTime E() { return DateTime.UnixEpoch; } }",
        }),
    },
    Rule {
        id: "cs/log-template-not-constant",
        name: "Logging templates should be constant",
        description: "An interpolated or concatenated message is built even when the level is off, and loses \
                      the structured values a template such as `\"User {UserId}\"` keeps.",
        message: "Use a constant message template with placeholders, and pass the values as arguments.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2629")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(invocation_expression
                        function: (member_access_expression name: (identifier) @n)
                        arguments: (argument_list)
                        (#match? @n "^Log(Trace|Debug|Information|Warning|Error|Critical)$")) @match"#,
            filter: Some(Find(dynamic_log_template)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(ILogger log, int id) { log.LogInformation($\"Saved {id}\"); } }",
            good: "class A { void F(ILogger log, int id) { log.LogInformation(\"Saved {Id}\", id); } }",
        }),
    },
    Rule {
        id: "cs/format-string-unused-argument",
        name: "Composite format strings should use all their arguments",
        description: "An argument no placeholder refers to is never printed; the placeholder for it was \
                      probably forgotten.",
        message: "Add a placeholder for every argument, or remove the extra arguments.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3457")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(invocation_expression
                        function: (member_access_expression name: (identifier) @n)
                        (#any-of? @n "Format" "AppendFormat")) @match"#,
            filter: Some(Find(unused_format_argument)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { string F(int a, int b) { return string.Format(\"{0}\", a, b); } }",
            good: "class A { string F(int a, int b) { return string.Format(\"{0} {1}\", a, b); } }",
        }),
    },
];

// ---------------------------------------------------- helpers

fn type_members(declaration: Node) -> Vec<Node> {
    declaration
        .child_by_field_name("body")
        .map(cs_statements)
        .unwrap_or_default()
}

fn name_text<'s>(node: Node, src: &'s [u8]) -> &'s [u8] {
    node.child_by_field_name("name")
        .map_or(&b""[..], |n| text(n, src))
}

fn base_types<'t>(class: Node<'t>) -> Vec<Node<'t>> {
    let mut cursor = class.walk();
    let Some(list) = class
        .named_children(&mut cursor)
        .find(|c| c.kind() == "base_list")
    else {
        return Vec::new();
    };
    let mut inner = list.walk();
    list.named_children(&mut inner)
        .filter(|c| c.kind() != "comment" && c.kind() != "argument_list")
        .collect()
}

fn first_base_name<'s>(class: Node, src: &'s [u8]) -> Option<&'s [u8]> {
    base_types(class).first().map(|b| simple_name(*b, src))
}

/// The variables a `for` loop's condition reads.
fn identifiers_in<'s>(node: Node, src: &'s [u8]) -> Vec<&'s [u8]> {
    let mut out = Vec::new();
    if node.kind() == "identifier" {
        out.push(text(node, src));
    }
    let mut cursor = node.walk();
    if !cursor.goto_first_child() {
        return out;
    }
    loop {
        let n = cursor.node();
        if n.kind() == "identifier" {
            out.push(text(n, src));
        }
        if cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() || cursor.node() == node {
                return out;
            }
        }
    }
}

/// The variable an update expression (`i++`, `i += 2`, `i = j`) changes.
fn updated_variable<'s>(update: Node, src: &'s [u8]) -> Option<&'s [u8]> {
    match update.kind() {
        "postfix_unary_expression" | "prefix_unary_expression" => {
            let op = {
                let mut cursor = update.walk();
                update
                    .children(&mut cursor)
                    .find(|c| !c.is_named())
                    .map(|c| text(c, src))
            };
            matches!(op, Some(b"++" | b"--"))
                .then(|| {
                    operand(update)
                        .filter(|o| o.kind() == "identifier")
                        .map(|o| text(o, src))
                })
                .flatten()
        }
        "assignment_expression" => update
            .child_by_field_name("left")
            .filter(|l| l.kind() == "identifier")
            .map(|l| text(l, src)),
        _ => None,
    }
}

fn loop_counters<'s>(node: Node, src: &'s [u8]) -> Vec<&'s [u8]> {
    let mut cursor = node.walk();
    node.children_by_field_name("update", &mut cursor)
        .filter_map(|u| updated_variable(u, src))
        .collect()
}

// ---------------------------------------------------- filters

fn counter_changed_in_body<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let counters = loop_counters(node, src);
    if counters.is_empty() {
        return None;
    }
    let body = node.child_by_field_name("body")?;
    find_in_scope(body, CS_SCOPE_STOPS, |n| {
        updated_variable(n, src).is_some_and(|v| counters.contains(&v))
    })
}

fn is_plain_goto(node: Node, src: &[u8]) -> bool {
    // `goto case` and `goto default` are how C# falls through a switch.
    let t = text(node, src);
    !t.starts_with(b"goto case") && !t.starts_with(b"goto default")
}

fn is_public_instance_field(field: Node, src: &[u8]) -> bool {
    // Static fields are cs/visible-mutable-static-field's concern.
    cs_has_modifier(field, "public", src)
        && !["const", "readonly", "static"]
            .iter()
            .any(|m| cs_has_modifier(field, m, src))
}

fn utility_class_name<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if ["static", "abstract", "partial"]
        .iter()
        .any(|m| cs_has_modifier(class, m, src))
        || !base_types(class).is_empty()
    {
        return None;
    }
    let mut cursor = class.walk();
    if class.named_children(&mut cursor).any(|c| {
        matches!(
            c.kind(),
            "attribute_list" | "parameter_list" | "type_parameter_list"
        )
    }) {
        return None;
    }
    let members = type_members(class);
    let has_method = members.iter().any(|m| m.kind() == "method_declaration");
    let all_static = members.iter().all(|m| {
        m.kind() == "constructor_declaration" && !cs_has_modifier(*m, "public", src)
            || cs_has_modifier(*m, "static", src)
            || cs_has_modifier(*m, "const", src)
    });
    // A private constructor already stops instances.
    let hides_constructor = members
        .iter()
        .any(|m| m.kind() == "constructor_declaration" && !cs_has_modifier(*m, "static", src));
    (has_method && all_static && !hides_constructor).then(|| class.child_by_field_name("name"))?
}

fn is_obsolete_attribute(node: Node, src: &[u8]) -> bool {
    node.child_by_field_name("name")
        .is_some_and(|n| matches!(simple_name(n, src), b"Obsolete" | b"ObsoleteAttribute"))
}

fn uncaught_throw<'t>(block: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    // A throw inside a nested try is caught there, and in a lambda runs later.
    let stops: Vec<&str> = CS_SCOPE_STOPS
        .iter()
        .copied()
        .chain(["try_statement"])
        .collect();
    find_in_scope(block, &stops, |n| {
        matches!(n.kind(), "throw_statement" | "throw_expression")
    })
}

const COLLECTION_TYPES: &[&[u8]] = &[
    b"IEnumerable",
    b"ICollection",
    b"IList",
    b"IReadOnlyCollection",
    b"IReadOnlyList",
    b"List",
    b"Collection",
    b"ISet",
    b"HashSet",
    b"IDictionary",
    b"IReadOnlyDictionary",
    b"Dictionary",
];

fn collection_null<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let returns = method.child_by_field_name("returns")?;
    let is_collection =
        returns.kind() == "array_type" || COLLECTION_TYPES.contains(&simple_name(returns, src));
    if !is_collection {
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

fn only_calls_base<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !cs_has_modifier(method, "override", src) || cs_has_modifier(method, "sealed", src) {
        return None;
    }
    // An attribute on the override is a reason for it to exist.
    let mut cursor = method.walk();
    if method
        .named_children(&mut cursor)
        .any(|c| c.kind() == "attribute_list")
    {
        return None;
    }
    let name = name_text(method, src);
    let body = method.child_by_field_name("body")?;
    let call = match body.kind() {
        "arrow_expression_clause" => operand(body)?,
        "block" => match cs_statements(body).as_slice() {
            [s] if matches!(s.kind(), "expression_statement" | "return_statement") => operand(*s)?,
            _ => return None,
        },
        _ => return None,
    };
    let call = if call.kind() == "await_expression" {
        operand(call)?
    } else {
        call
    };
    if call.kind() != "invocation_expression"
        || call
            .child_by_field_name("function")
            .is_none_or(|f| text(f, src).strip_prefix(b"base.") != Some(name))
    {
        return None;
    }
    let params = method.child_by_field_name("parameters")?;
    let mut c = params.walk();
    let names: Vec<&[u8]> = params
        .named_children(&mut c)
        .filter(|p| p.kind() == "parameter")
        .map(|p| name_text(p, src))
        .collect();
    let args: Vec<&[u8]> = cs_call_arguments(call)
        .iter()
        .map(|a| text(*a, src))
        .collect();
    (names == args).then(|| method.child_by_field_name("name"))?
}

fn only_condition(node: Node, _: &[u8]) -> bool {
    node.child_by_field_name("initializer").is_none()
        && node.child_by_field_name("update").is_none()
}

fn has_too_many_cases(node: Node, src: &[u8]) -> bool {
    node.child_by_field_name("body").is_some_and(|b| {
        let mut cursor = b.walk();
        b.named_children(&mut cursor)
            .filter(|s| s.kind() == "switch_section" && !text(*s, src).starts_with(b"default"))
            .count()
            > 30
    })
}

fn is_null_reference_type(node: Node, src: &[u8]) -> bool {
    simple_name(node, src) == b"NullReferenceException"
}

fn virtual_call_in_constructor<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    // A sealed class can't be subclassed, so nothing overrides its members.
    if cs_has_modifier(class, "sealed", src) {
        return None;
    }
    let members = type_members(class);
    let overridable: Vec<&[u8]> = members
        .iter()
        .filter(|m| {
            m.kind() == "method_declaration"
                && (cs_has_modifier(**m, "virtual", src) || cs_has_modifier(**m, "abstract", src))
        })
        .map(|m| name_text(*m, src))
        .collect();
    if overridable.is_empty() {
        return None;
    }
    members
        .iter()
        .filter(|m| m.kind() == "constructor_declaration" && !cs_has_modifier(**m, "static", src))
        .find_map(|ctor| {
            let body = ctor.child_by_field_name("body")?;
            find_in_scope(body, CS_SCOPE_STOPS, |n| {
                n.kind() == "invocation_expression"
                    && n.child_by_field_name("function").is_some_and(|f| {
                        let t = text(f, src);
                        let t = t.strip_prefix(b"this.").unwrap_or(t);
                        overridable.contains(&t)
                    })
            })
        })
}

fn chain_repeats_a_branch<'t>(statement: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
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
    // Only the head of a chain. parent() costs the node's depth: test it after
    // cheap checks.
    let candidates: Vec<Node> = bodies
        .into_iter()
        .filter(|b| b.kind() == "block" && cs_statements(*b).len() >= 2)
        .collect();
    if candidates.len() < 2
        || statement.parent().is_some_and(|p| {
            p.kind() == "if_statement" && p.child_by_field_name("alternative") == Some(statement)
        })
    {
        return None;
    }
    for (i, body) in candidates.iter().enumerate() {
        if candidates[..i]
            .iter()
            .any(|earlier| same_code(*earlier, *body, src))
        {
            return Some(*body);
        }
    }
    None
}

fn update_misses_condition<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let condition = node.child_by_field_name("condition")?;
    let read = identifiers_in(condition, src);
    let mut cursor = node.walk();
    let updates: Vec<Node<'t>> = node.children_by_field_name("update", &mut cursor).collect();
    let changed: Vec<(Node<'t>, &[u8])> = updates
        .iter()
        .filter_map(|u| updated_variable(*u, src).map(|v| (*u, v)))
        .collect();
    // Only when every update is a plain variable change we understand.
    if changed.len() != updates.len() || changed.iter().any(|(_, v)| read.contains(v)) {
        return None;
    }
    changed.first().map(|(u, _)| *u)
}

fn empty_class_name<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !type_members(class).is_empty()
        || class
            .child_by_field_name("body")
            .is_some_and(|b| b.named_child_count() != 0)
        || cs_has_modifier(class, "partial", src)
        // An empty static class is a marker, such as the IsExternalInit polyfill.
        || cs_has_modifier(class, "static", src)
        || !base_types(class).is_empty()
    {
        return None;
    }
    let mut cursor = class.walk();
    if class.named_children(&mut cursor).any(|c| {
        matches!(
            c.kind(),
            "attribute_list" | "parameter_list" | "type_parameter_list"
        )
    }) {
        return None;
    }
    class.child_by_field_name("name")
}

fn class_has_no_base(name: Node, src: &[u8]) -> bool {
    // A static class can't derive from anything: it's a helper, such as a
    // ThrowIfNull polyfill named after the exception it throws.
    name.parent()
        .is_some_and(|class| base_types(class).is_empty() && !cs_has_modifier(class, "static", src))
}

fn type_parameter_names<'t>(declaration: Node<'t>) -> Vec<Node<'t>> {
    let list = declaration
        .child_by_field_name("type_parameters")
        .or_else(|| {
            let mut cursor = declaration.walk();
            declaration
                .named_children(&mut cursor)
                .find(|c| c.kind() == "type_parameter_list")
        });
    let Some(list) = list else {
        return Vec::new();
    };
    let mut cursor = list.walk();
    list.named_children(&mut cursor)
        .filter(|p| p.kind() == "type_parameter")
        .filter_map(|p| p.child_by_field_name("name").or_else(|| p.named_child(0)))
        .collect()
}

fn unused_type_parameter<'t>(declaration: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    // An override or interface implementation keeps the signature it's given.
    // Overrides keep the signature they're given, and interface or abstract
    // methods have no body to use the parameter in (implementations do).
    if cs_has_modifier(declaration, "override", src)
        || (declaration.kind() == "method_declaration"
            && declaration.child_by_field_name("body").is_none())
    {
        return None;
    }
    let whole = text(declaration, src);
    type_parameter_names(declaration)
        .into_iter()
        .find(|p| count_word(whole, text(*p, src)) == 1)
}

fn zero_flag_not_none<'t>(declaration: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_attribute(declaration, "Flags", src)?;
    let body = declaration.child_by_field_name("body")?;
    let mut cursor = body.walk();
    let members: Vec<Node<'t>> = body
        .named_children(&mut cursor)
        .filter(|m| m.kind() == "enum_member_declaration")
        .collect();
    members.into_iter().find_map(|m| {
        let zero = m
            .child_by_field_name("value")
            .is_some_and(|v| cs_integer(v, src) == Some(0));
        let name = m.child_by_field_name("name")?;
        (zero && text(name, src) != b"None").then_some(name)
    })
}

fn is_public_multidimensional(array: Node, src: &[u8]) -> bool {
    let multi = array
        .child_by_field_name("rank")
        .is_some_and(|r| text(r, src).contains(&b','))
        || array
            .child_by_field_name("type")
            .is_some_and(|t| t.kind() == "array_type");
    let method = array
        .parent()
        .and_then(|p| p.parent())
        .and_then(|l| l.parent());
    multi
        && method.is_some_and(|m| {
            cs_has_modifier(m, "public", src) && !cs_has_modifier(m, "override", src)
        })
}

fn getter_throw<'t>(property: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let allowed = |t: Node| {
        let created = if t.kind() == "throw_statement" || t.kind() == "throw_expression" {
            operand(t)
        } else {
            None
        };
        // `throw;` rethrows; the getter didn't choose the exception.
        created.is_none_or(|c| {
            c.kind() != "object_creation_expression"
                || c.child_by_field_name("type").is_some_and(|ty| {
                    matches!(
                        simple_name(ty, src),
                        b"InvalidOperationException"
                            | b"NotSupportedException"
                            | b"ObjectDisposedException"
                            | b"NotImplementedException"
                            | b"PlatformNotSupportedException"
                            | b"KeyNotFoundException"
                    )
                })
        })
    };
    let throw_in = |body: Node<'t>| {
        let stops: Vec<&str> = CS_SCOPE_STOPS
            .iter()
            .copied()
            .chain(["try_statement"])
            .collect();
        find_in_scope(body, &stops, |n| {
            matches!(n.kind(), "throw_statement" | "throw_expression") && !allowed(n)
        })
        .or_else(|| (body.kind() == "throw_expression" && !allowed(body)).then_some(body))
    };
    if let Some(value) = property
        .child_by_field_name("value")
        .filter(|v| v.kind() == "arrow_expression_clause")
    {
        return throw_in(value);
    }
    let accessors = property.child_by_field_name("accessors")?;
    let mut cursor = accessors.walk();
    let list: Vec<Node<'t>> = accessors.named_children(&mut cursor).collect();
    list.into_iter()
        .filter(|a| a.kind() == "accessor_declaration")
        .filter(|a| a.child_by_field_name("name").map(|k| text(k, src)) == Some(b"get"))
        .find_map(|a| throw_in(a.child_by_field_name("body")?))
}

fn write_only_name<'t>(property: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let accessors = property.child_by_field_name("accessors")?;
    let mut cursor = accessors.walk();
    let keywords: Vec<&[u8]> = accessors
        .named_children(&mut cursor)
        .filter(|a| a.kind() == "accessor_declaration")
        .filter_map(|a| a.child_by_field_name("name").map(|k| text(k, src)))
        .collect();
    (keywords.contains(&&b"set"[..]) && !keywords.contains(&&b"get"[..]))
        .then(|| property.child_by_field_name("name"))?
}

fn too_many_type_parameters<'t>(declaration: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    let limit = if declaration.kind() == "method_declaration" {
        3
    } else {
        2
    };
    let params = type_parameter_names(declaration);
    (params.len() > limit).then(|| declaration.child_by_field_name("name"))?
}

fn is_useless_bitwise(node: Node, src: &[u8]) -> bool {
    let op = operator_text(node, src);
    let right = node.child_by_field_name("right");
    let is = |n: Option<Node>, v: &[u8]| n.is_some_and(|n| text(n, src) == v);
    match op {
        b"|" | b"^" | b"|=" | b"^=" => {
            is(right, b"0") || (op.len() == 1 && is(node.child_by_field_name("left"), b"0"))
        }
        b"&" | b"&=" => {
            is(right, b"-1") || (op.len() == 1 && is(node.child_by_field_name("left"), b"-1"))
        }
        _ => false,
    }
}

fn tests_index_of_positive(node: Node, src: &[u8]) -> bool {
    let is_index_of = |n: Option<Node>| {
        n.is_some_and(|n| {
            n.kind() == "invocation_expression"
                && n.child_by_field_name("function")
                    .and_then(|f| f.child_by_field_name("name"))
                    .is_some_and(|m| matches!(text(m, src), b"IndexOf" | b"IndexOfAny"))
        })
    };
    let is_zero = |n: Option<Node>| n.is_some_and(|n| text(n, src) == b"0");
    let left = node.child_by_field_name("left");
    let right = node.child_by_field_name("right");
    match operator_text(node, src) {
        b">" => is_index_of(left) && is_zero(right),
        b"<" => is_zero(left) && is_index_of(right),
        _ => false,
    }
}

/// `flags & ~BindingFlags.NonPublic` removes the flag.
fn not_negated(node: Node, src: &[u8]) -> bool {
    !node
        .parent()
        .is_some_and(|p| p.kind() == "prefix_unary_expression" && text(p, src).starts_with(b"~"))
}

fn tests_this(node: Node, src: &[u8]) -> bool {
    let t = text(node, src);
    t.starts_with(b"this is ") || t.starts_with(b"this\nis ")
}

fn cast_after_type_check<'t>(statement: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let check = statement.child_by_field_name("condition")?;
    // `x is string` is an is_expression; `x is Foo` a constant pattern. A
    // declaration pattern (`x is Foo f`) already binds the value.
    let (subject, ty) = if check.kind() == "is_expression" {
        (
            check.child_by_field_name("left")?,
            check.child_by_field_name("right")?,
        )
    } else {
        let pattern = check.child_by_field_name("pattern")?;
        if pattern.kind() != "constant_pattern" {
            return None;
        }
        (check.child_by_field_name("expression")?, pattern)
    };
    let ty = text(ty, src);
    let body = statement.child_by_field_name("consequence")?;
    find_in_scope(body, CS_SCOPE_STOPS, |n| {
        n.kind() == "cast_expression"
            && n.child_by_field_name("type")
                .is_some_and(|t| text(t, src) == ty)
            && n.child_by_field_name("value")
                .is_some_and(|v| same_code(v, subject, src))
    })
}

fn namespace_is_empty(name: Node, _: &[u8]) -> bool {
    name.parent()
        .and_then(|ns| ns.child_by_field_name("body"))
        .is_some_and(|b| b.named_child_count() == 0)
}

fn missing_conventional_suffix<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let base = first_base_name(class, src)?;
    let suffix: &[u8] = match base {
        b"Attribute" => b"Attribute",
        b"EventArgs" => b"EventArgs",
        b"Exception" | b"SystemException" | b"ApplicationException" => b"Exception",
        _ => return None,
    };
    let name = class.child_by_field_name("name")?;
    (!text(name, src).ends_with(suffix)).then_some(name)
}

fn checks_before_assigning(statement: Node, src: &[u8]) -> bool {
    if statement.child_by_field_name("alternative").is_some() {
        return false;
    }
    let Some(condition) = statement.child_by_field_name("condition") else {
        return false;
    };
    if operator_text(condition, src) != b"!=" {
        return false;
    }
    let Some(consequence) = statement.child_by_field_name("consequence") else {
        return false;
    };
    let assignment = match consequence.kind() {
        "block" => match cs_statements(consequence).as_slice() {
            [s] => operand(*s),
            _ => None,
        },
        "expression_statement" => operand(consequence),
        _ => None,
    };
    let Some(assignment) = assignment.filter(|a| a.kind() == "assignment_expression") else {
        return false;
    };
    if operator_text(assignment, src) != b"=" {
        return false;
    }
    let (Some(target), Some(value)) = (
        assignment.child_by_field_name("left"),
        assignment.child_by_field_name("right"),
    ) else {
        return false;
    };
    let (Some(l), Some(r)) = (
        condition.child_by_field_name("left"),
        condition.child_by_field_name("right"),
    ) else {
        return false;
    };
    (same_code(l, target, src) && same_code(r, value, src))
        || (same_code(r, target, src) && same_code(l, value, src))
}

fn switch_sections(body: Node) -> Vec<Node> {
    let mut cursor = body.walk();
    body.named_children(&mut cursor)
        .filter(|s| s.kind() == "switch_section")
        .collect()
}

fn is_default_section(section: Node, src: &[u8]) -> bool {
    text(section, src).starts_with(b"default")
}

/// The statements of a switch section, without its labels.
fn section_statements(section: Node) -> Vec<Node> {
    let mut cursor = section.walk();
    section
        .named_children(&mut cursor)
        .filter(|c| c.kind().ends_with("_statement") || c.kind() == "block")
        .collect()
}

fn empty_case_before_default<'t>(body: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let sections = switch_sections(body);
    sections.windows(2).find_map(|pair| {
        (section_statements(pair[0]).is_empty()
            && !is_default_section(pair[0], src)
            && is_default_section(pair[1], src))
        .then_some(pair[0])
    })
}

fn non_public_exception_name<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let base = first_base_name(class, src)?;
    if !matches!(
        base,
        b"Exception" | b"SystemException" | b"ApplicationException"
    ) || cs_has_modifier(class, "public", src)
    {
        return None;
    }
    // Nested types are as visible as their container allows; only flag
    // top-level and namespace-level classes.
    let container = class.parent()?.parent();
    let top_level = class.parent()?.kind() == "compilation_unit"
        || container.is_some_and(|c| c.kind() == "namespace_declaration");
    top_level.then(|| class.child_by_field_name("name"))?
}

fn overloads_equality(operator: Node, src: &[u8]) -> bool {
    let mut cursor = operator.walk();
    operator
        .children(&mut cursor)
        .any(|c| !c.is_named() && text(c, src) == b"==")
}

fn throw_in_safe_method<'t>(member: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let safe = match member.kind() {
        "conversion_operator_declaration" => text(member, src).windows(8).any(|w| w == b"implicit"),
        "constructor_declaration" => cs_has_modifier(member, "static", src),
        _ => {
            let params = member
                .child_by_field_name("parameters")
                .map_or(0, |p| p.named_child_count());
            match (name_text(member, src), params) {
                (b"ToString" | b"GetHashCode", 0) => cs_has_modifier(member, "override", src),
                (b"Equals", 1) => cs_has_modifier(member, "override", src),
                (b"Dispose", 0) => true,
                _ => false,
            }
        }
    };
    if !safe {
        return None;
    }
    let body = member.child_by_field_name("body")?;
    let not_implemented = |n: Node| {
        operand(n).is_some_and(|c| {
            c.child_by_field_name("type")
                .is_some_and(|t| simple_name(t, src) == b"NotImplementedException")
        })
    };
    let stops: Vec<&str> = CS_SCOPE_STOPS
        .iter()
        .copied()
        .chain(["try_statement"])
        .collect();
    let found = find_in_scope(body, &stops, |n| {
        matches!(n.kind(), "throw_statement" | "throw_expression") && !not_implemented(n)
    });
    found.or_else(|| {
        operand(body).filter(|e| e.kind() == "throw_expression" && !not_implemented(*e))
    })
}

fn unknown_parameter_name<'t>(creation: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    // An exception built as a value (a test fixture, say) isn't about this
    // method's parameters.
    if !creation
        .parent()
        .is_some_and(|p| matches!(p.kind(), "throw_statement" | "throw_expression"))
    {
        return None;
    }
    let ty = simple_name(creation.child_by_field_name("type")?, src);
    let args = cs_call_arguments(creation);
    // ArgumentException(message, paramName); the others take paramName first.
    let position = if ty == b"ArgumentException" { 1 } else { 0 };
    let arg = *args.get(position)?;
    let name = cs_string_value(arg, src)?;
    if name.contains(&b' ') || name.is_empty() {
        return None;
    }
    // The enclosing member's parameters, plus `value` in setters.
    let mut current = creation.parent();
    for _ in 0..64 {
        let n = current?;
        match n.kind() {
            "method_declaration"
            | "constructor_declaration"
            | "local_function_statement"
            | "operator_declaration"
            | "conversion_operator_declaration"
            | "indexer_declaration" => {
                let params = n
                    .child_by_field_name("parameters")
                    .map(|p| text(p, src))
                    .unwrap_or_default();
                return (count_word(params, name) == 0).then_some(arg);
            }
            "accessor_declaration"
            | "lambda_expression"
            | "anonymous_method_expression"
            | "property_declaration" => return None,
            _ => {}
        }
        current = n.parent();
    }
    None
}

fn suppress_finalize_call<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let body = method.child_by_field_name("body")?;
    find_in_scope(body, CS_SCOPE_STOPS, |n| {
        n.kind() == "invocation_expression"
            && n.child_by_field_name("function").is_some_and(|f| {
                matches!(
                    text(f, src),
                    b"GC.SuppressFinalize" | b"System.GC.SuppressFinalize"
                )
            })
    })
}

fn attribute_without_usage<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if first_base_name(class, src) != Some(b"Attribute") || cs_has_modifier(class, "abstract", src)
    {
        return None;
    }
    if attribute_names(class, src)
        .iter()
        .any(|(_, n)| *n == b"AttributeUsage")
    {
        return None;
    }
    class.child_by_field_name("name")
}

fn is_outdated_base(base: Node, src: &[u8]) -> bool {
    matches!(
        simple_name(base, src),
        b"ApplicationException"
            | b"CollectionBase"
            | b"DictionaryBase"
            | b"ReadOnlyCollectionBase"
            | b"SortedList"
            | b"Queue"
            | b"Stack"
            | b"ArrayList"
            | b"Hashtable"
    ) && base.kind() != "generic_name"
}

fn separated_overload<'t>(declaration: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let members = type_members(declaration);
    let mut seen: Vec<&[u8]> = Vec::new();
    let mut last: Option<&[u8]> = None;
    for member in members {
        if member.kind() != "method_declaration" {
            // Other members between overloads separate them too.
            last = None;
            continue;
        }
        // `void IFoo.F()` implements an interface member; it isn't an overload.
        let mut cursor = member.walk();
        if member
            .named_children(&mut cursor)
            .any(|c| c.kind() == "explicit_interface_specifier")
        {
            continue;
        }
        let name = name_text(member, src);
        if last != Some(name) && seen.contains(&name) {
            return member.child_by_field_name("name");
        }
        if !seen.contains(&name) {
            seen.push(name);
        }
        last = Some(name);
    }
    None
}

fn default_in_the_middle<'t>(body: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let sections = switch_sections(body);
    let n = sections.len();
    sections
        .iter()
        .enumerate()
        .find(|(i, s)| *i != 0 && *i + 1 != n && is_default_section(**s, src))
        .map(|(_, s)| *s)
}

fn no_arguments_or_initializer(creation: Node, _: &[u8]) -> bool {
    creation
        .child_by_field_name("arguments")
        .is_some_and(|a| a.named_child_count() == 0)
        && creation.child_by_field_name("initializer").is_none()
}

fn is_empty_comment(comment: Node, src: &[u8]) -> bool {
    if !comment_is_blank(comment, src) {
        return false;
    }
    // A blank `//` or `///` line inside a comment block separates paragraphs.
    let row = comment.start_position().row;
    let adjacent = |n: Option<Node>, delta: isize| {
        n.is_some_and(|n| {
            n.kind() == "comment"
                && (if delta < 0 {
                    n.end_position().row + 1 == row
                } else {
                    n.start_position().row == row + 1
                })
        })
    };
    !adjacent(comment.prev_sibling(), -1) && !adjacent(comment.next_sibling(), 1)
}

fn comment_is_blank(comment: Node, src: &[u8]) -> bool {
    let t = text(comment, src);
    let inner: &[u8] = if let Some(rest) = t.strip_prefix(b"/*") {
        rest.strip_suffix(b"*/").unwrap_or(rest)
    } else if let Some(rest) = t.strip_prefix(b"//") {
        // `///` doc comments with nothing in them are empty too.
        rest.strip_prefix(b"/").unwrap_or(rest)
    } else {
        return false;
    };
    inner.iter().all(|b| b.is_ascii_whitespace() || *b == b'*')
}

fn is_unix_epoch(creation: Node, src: &[u8]) -> bool {
    let args = cs_call_arguments(creation);
    let year_month_day = args.len() >= 3
        && [1970u64, 1, 1]
            .iter()
            .zip(&args)
            .all(|(want, a)| cs_integer(*a, src) == Some(*want));
    // The rest must be zeros or a DateTimeKind/offset.
    year_month_day
        && args[3..].iter().all(|a| {
            cs_integer(*a, src) == Some(0)
                || matches!(text(*a, src), b"DateTimeKind.Utc" | b"TimeSpan.Zero")
        })
}

fn dynamic_log_template<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    // The template follows an optional EventId and exception.
    cs_call_arguments(call)
        .into_iter()
        .take(3)
        .find(|a| match a.kind() {
            "interpolated_string_expression" => {
                let mut cursor = a.walk();
                a.named_children(&mut cursor)
                    .any(|c| c.kind() == "interpolation")
            }
            "binary_expression" => {
                operator_text(*a, src) == b"+"
                    && !is_constant_text(*a)
                    && find_in_scope(*a, &[], |n| {
                        matches!(n.kind(), "string_literal" | "verbatim_string_literal")
                    })
                    .is_some()
            }
            _ => false,
        })
}

/// Literals joined with `+`, which the compiler folds into one constant.
fn is_constant_text(expr: Node) -> bool {
    match expr.kind() {
        "string_literal" | "verbatim_string_literal" | "raw_string_literal" => true,
        "binary_expression" => {
            expr.child_by_field_name("left")
                .is_some_and(is_constant_text)
                && expr
                    .child_by_field_name("right")
                    .is_some_and(is_constant_text)
        }
        "parenthesized_expression" => expr.named_child(0).is_some_and(is_constant_text),
        _ => false,
    }
}

fn unused_format_argument<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let function = call.child_by_field_name("function")?;
    let method = text(function.child_by_field_name("name")?, src);
    if method == b"Format"
        && !matches!(
            function
                .child_by_field_name("expression")
                .map(|r| simple_name(r, src)),
            Some(b"string" | b"String")
        )
    {
        return None;
    }
    let args = cs_call_arguments(call);
    let position = args
        .iter()
        .take(2)
        .position(|a| cs_string_value(*a, src).is_some())?;
    let rest = &args[position + 1..];
    // One argument may be an object[] holding all the values.
    if rest.len() < 2 {
        return None;
    }
    let value = cs_string_value(args[position], src)?;
    let used = placeholder_indices(value)?;
    (0..rest.len()).find(|i| !used.contains(i)).map(|i| rest[i])
}

/// Every placeholder index in a composite format string; None when it's
/// malformed (cs/format-string-arguments reports that).
fn placeholder_indices(value: &[u8]) -> Option<Vec<usize>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < value.len() {
        match value[i] {
            b'{' if value.get(i + 1) == Some(&b'{') => i += 2,
            b'}' if value.get(i + 1) == Some(&b'}') => i += 2,
            b'{' => {
                let end = value[i..].iter().position(|&b| b == b'}')? + i;
                let index = value[i + 1..end]
                    .split(|&b| b == b',' || b == b':')
                    .next()?;
                out.push(std::str::from_utf8(index).ok()?.trim().parse().ok()?);
                i = end + 1;
            }
            _ => i += 1,
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::super::cs::tests::flagged;

    fn class(body: &str) -> String {
        format!("namespace N;\nclass A {{\n{body}\n}}\n")
    }

    fn method(body: &str) -> String {
        format!("namespace N;\nclass A {{\nvoid F() {{\n{body}\n}}\n}}\n")
    }

    #[test]
    fn loops() {
        let src = method(
            "for (int i = 0; i < n; i++) { i++; }\nfor (int i = 0; i < n; i++) { G(i); }\nfor (int i = 0; i < n; j++) { }\nfor (int i = 0, j = 0; i < n; i++, j++) { }\nfor (; More();) { }\nfor (;;) { break; }\nfor (int i = 0; i < n; i++) { Action a = () => i++; }",
        );
        assert_eq!(flagged("cs/for-counter-modified-in-body", &src), [4]);
        assert_eq!(flagged("cs/for-update-other-variable", &src), [6]);
        assert_eq!(flagged("cs/for-as-while", &src), [8]);
    }

    #[test]
    fn jumps_and_blocks() {
        let src = method(
            "a: G();\ngoto a;\nswitch (x) { case 1: goto case 2; case 2: goto default; default: break; }\n{ H(); }\nif (b) { { H(); } }\nb = ((c));\nb = (c);",
        );
        assert_eq!(flagged("cs/goto", &src), [5]);
        assert_eq!(flagged("cs/nested-block", &src), [7, 8]);
        assert_eq!(flagged("cs/redundant-parentheses", &src), [9]);
    }

    #[test]
    fn fields_and_utility_classes() {
        let src = "namespace N;\nclass A { public int X; public const int Y = 1; public readonly int Z; private int w; public static int S; }\nstruct P { public int X; }\nclass U { public static int F() => 1; }\nclass V { private V() { } public static int F() => 1; }\nstatic class W { public static int F() => 1; }\nclass X2 { public static int Y; }\nclass Y2 : Base { public static int F() => 1; }";
        assert_eq!(flagged("cs/public-field", src), [2]);
        assert_eq!(flagged("cs/instantiable-utility-class", src), [4]);
    }

    #[test]
    fn exceptions() {
        let src = method(
            "try { G(); } finally { throw new E(); }\ntry { G(); } finally { try { H(); } catch { throw; } }\ntry { G(); } catch (NullReferenceException) { }\ntry { G(); } catch (System.NullReferenceException e) { }",
        );
        assert_eq!(flagged("cs/throw-in-finally", &src), [4]);
        assert_eq!(flagged("cs/catch-null-reference", &src), [6, 7]);
    }

    #[test]
    fn returns_and_overrides() {
        let src = "namespace N;\nclass A : B {\nint[] F() { return null; }\nList<int> G() => null;\nstring H() { return null; }\nIEnumerable<int> I() { Func<object> f = () => null; return new int[0]; }\npublic override void J(int x) { base.J(x); }\npublic override int K(int x, int y) => base.K(y, x);\npublic override async Task L() { await base.L(); }\n[Obsolete(\"x\")] public override void M() { base.M(); }\npublic override string ToString() { return base.ToString(); }\n}";
        assert_eq!(flagged("cs/null-instead-of-empty-collection", src), [3, 4]);
        assert_eq!(flagged("cs/override-only-calls-base", src), [7, 9, 11]);
        assert_eq!(flagged("cs/obsolete-code", src), [10]);
    }

    #[test]
    fn switches() {
        let cases: String = (0..31).map(|i| format!("case {i}: ")).collect();
        let src = method(&format!(
            "switch (x) {{ {cases}return; default: return; }}\nswitch (x) {{ case 1: return; case 2: default: return; }}\nswitch (x) {{ case 1: return; default: return; case 2: return; }}\nswitch (x) {{ default: return; case 1: return; }}"
        ));
        assert_eq!(flagged("cs/too-many-switch-cases", &src), [4]);
        assert_eq!(flagged("cs/empty-case-before-default", &src), [5]);
        assert_eq!(flagged("cs/default-not-first-or-last", &src), [6]);
    }

    #[test]
    fn constructors_calling_virtuals() {
        let src = "namespace N;\nclass A { public A() { Init(); } protected virtual void Init() { } }\nsealed class B { public B() { Init(); } public virtual void Init() { } }\nclass C { public C() { Init(); } void Init() { } }\nclass D { public D() { Action a = () => Init(); } protected abstract void Init(); }";
        assert_eq!(flagged("cs/constructor-calls-virtual", src), [2]);
    }

    #[test]
    fn branches_in_chains() {
        let src = method(
            "if (a) { G(); H(); } else if (b) { G(); H(); }\nif (a) { G(); } else if (b) { G(); }\nif (a) { G(); H(); } else { H(); G(); }",
        );
        assert_eq!(flagged("cs/identical-branches-in-chain", &src), [4]);
    }

    #[test]
    fn class_shapes() {
        let src = "namespace N;\nclass Empty { }\nstatic class IsExternalInit { }\npartial class P { }\nclass Sub : Base { }\n[Serializable] class Tagged { }\nclass ParseException { int code; }\nclass GoodException : Exception { }\nclass Retry : Attribute { }\nclass Changed : EventArgs { }\nclass Fail : Exception { }\ninternal class QuotaException : Exception { }\nclass OldException : ApplicationException { }";
        assert_eq!(flagged("cs/empty-class", src), [2]);
        assert_eq!(flagged("cs/exception-name-without-base", src), [7]);
        assert_eq!(flagged("cs/type-suffix-from-base", src), [9, 10, 11]);
        assert_eq!(flagged("cs/non-public-exception", src), [8, 11, 12, 13]);
        assert_eq!(flagged("cs/attribute-usage-missing", src), [9]);
        assert_eq!(flagged("cs/outdated-base-type", src), [13]);
        let polyfill = "namespace N;\nstatic class ArgumentNullException { }";
        assert!(flagged("cs/exception-name-without-base", polyfill).is_empty());
    }

    #[test]
    fn members() {
        let src = class(
            "public virtual event EventHandler E;\npublic event EventHandler F;\nvoid G<T>(int x) { }\nvoid H<T>(T x) { }\nclass K<T> { }\npublic void L(int[,] a) { }\npublic void M(int[][] a) { }\nvoid N(int[,] a) { }\npublic void O(int[] a) { }\nint x;\npublic int P { set { x = value; } }\npublic int Q { get => x; set => x = value; }\nvoid R<A, B, C, D>() { }\nclass S<A, B, C> { }\nabstract void T<X>();",
        );
        assert_eq!(flagged("cs/virtual-field-event", &src), [3]);
        assert_eq!(flagged("cs/unused-type-parameter", &src), [5, 7, 15, 16]);
        assert_eq!(flagged("cs/multidimensional-array-parameter", &src), [8, 9]);
        assert_eq!(flagged("cs/write-only-property", &src), [13]);
        assert_eq!(flagged("cs/too-many-type-parameters", &src), [15, 16]);
    }

    #[test]
    fn getters() {
        let src = class(
            "int A { get { throw new ArgumentException(); } }\nint B { get { throw new InvalidOperationException(); } }\nint C => throw new FormatException();\nint D { get { try { return G(); } catch { throw new E(); } } set { throw new ArgumentException(); } }\nint E { get => x ?? throw new ObjectDisposedException(nameof(A)); }",
        );
        assert_eq!(flagged("cs/property-getter-throws", &src), [3, 5]);
    }

    #[test]
    fn flags_and_expressions() {
        let src = method(
            "x = y | 0;\nx = y & -1;\nx |= 0;\nx = y | 1;\nb = s.IndexOf(\"a\") > 0;\nb = s.IndexOf(\"a\") >= 0;\nb = 0 < s.IndexOf('a');\nvar f = t.GetField(\"x\", BindingFlags.NonPublic | BindingFlags.Instance & ~BindingFlags.NonPublic);\nb = this is B;\nb = other is B;\nq = ps.OrderBy(p => p.A).OrderByDescending(p => p.B);\nq = ps.OrderBy(p => p.A).ThenBy(p => p.B);",
        );
        assert_eq!(flagged("cs/useless-bitwise", &src), [4, 5, 6]);
        assert_eq!(flagged("cs/index-of-positive", &src), [8, 10]);
        assert_eq!(flagged("cs/reflection-non-public", &src), [11]);
        assert_eq!(flagged("cs/this-is-type", &src), [12]);
        assert_eq!(flagged("cs/repeated-order-by", &src), [14]);
        let flags = "namespace N;\n[Flags] enum A { Nothing = 0, X = 1 }\n[Flags] enum B { None = 0, X = 1 }";
        assert_eq!(flagged("cs/flags-zero-not-none", flags), [2]);
    }

    #[test]
    fn casts_and_checks() {
        let src = method(
            "if (o is string) { var s = (string)o; }\nif (o is string t) { G(t); }\nif (o is string) { var n = (int)p; }\nif (x != 1) { x = 1; }\nif (x != 1) { x = 2; }\nif (1 != x) x = 1;\nif (x != 1) { x = 1; } else { G(); }",
        );
        assert_eq!(flagged("cs/duplicate-cast", &src), [4]);
        assert_eq!(flagged("cs/check-before-assign", &src), [7, 9]);
    }

    #[test]
    fn namespaces_operators_safe_methods() {
        let src = "namespace Empty { }\nnamespace N {\nclass M { public static bool operator ==(M a, M b) => true; public static bool operator !=(M a, M b) => false; }\nstruct V { public static bool operator ==(V a, V b) => true; public static bool operator !=(V a, V b) => false; }\nclass S {\npublic override string ToString() { throw new InvalidOperationException(); }\npublic override int GetHashCode() => throw new NotImplementedException();\npublic void Dispose() { if (x) throw new ObjectDisposedException(\"S\"); }\nstatic S() { throw new E(); }\npublic static implicit operator int(S s) => throw new E();\npublic string ToString(string f) { throw new E(); }\n}\n}";
        assert_eq!(flagged("cs/empty-namespace", src), [1]);
        assert_eq!(flagged("cs/class-equality-operator", src), [3]);
        assert_eq!(flagged("cs/throw-in-unexpected-method", src), [6, 8, 9, 10]);
    }

    #[test]
    fn calls() {
        let src = "namespace N;\nclass A {\nvoid F(string name, int count) {\nAssembly.LoadFrom(p);\nAssembly.Load(n);\nthrow new ArgumentNullException(\"nmae\");\nthrow new ArgumentNullException(nameof(name));\nthrow new ArgumentException(\"bad\", \"count\");\nthrow new ArgumentException(\"bad\", \"cnt\");\nthrow new ArgumentOutOfRangeException(\"name\", \"too long\");\nGC.SuppressFinalize(this);\nvar g = new Guid();\nvar h = new Guid(bytes);\nvar i = s.Substring(1).IndexOf('x');\nvar e = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);\nvar d = new DateTime(1970, 1, 2);\nlog.LogInformation($\"Saved {name}\");\nlog.LogWarning(\"Saved \" + name);\nlog.LogInformation(\"Saved {Name}\", name);\nlog.LogError(ex, $\"Failed {name}\");\nlog.LogWarning(\"Long \" + \"text\");\nvar unthrown = new ArgumentNullException(\"other\");\nvar s1 = string.Format(\"{0}\", a, b);\nvar s2 = string.Format(\"{1} {0}\", a, b);\n}\npublic void Dispose() { GC.SuppressFinalize(this); }\n}";
        assert_eq!(flagged("cs/assembly-load-from", src), [4]);
        assert_eq!(flagged("cs/argument-exception-param-name", src), [6, 9]);
        assert_eq!(flagged("cs/suppress-finalize-outside-dispose", src), [11]);
        assert_eq!(flagged("cs/new-guid", src), [12]);
        assert_eq!(flagged("cs/substring-then-search", src), [14]);
        assert_eq!(flagged("cs/unix-epoch", src), [15]);
        assert_eq!(flagged("cs/log-template-not-constant", src), [17, 18, 20]);
        assert_eq!(flagged("cs/format-string-unused-argument", src), [23]);
    }

    #[test]
    fn overloads_and_comments() {
        let src = "namespace N;\nclass A {\nvoid F(int x) { }\n// the string one\nvoid F(string s) { }\nvoid G() { }\nvoid F(bool b) { }\nvoid I.F(char c) { }\n//\n\n// note\n//\n// more\n\n/* */\n\n///\n}";
        assert_eq!(flagged("cs/overloads-not-adjacent", src), [7]);
        assert_eq!(flagged("cs/empty-comment", src), [9, 15, 17]);
    }
}
