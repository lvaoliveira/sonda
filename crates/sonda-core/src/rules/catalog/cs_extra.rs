//! C# rules, batch 5 (ADR-0007, ADR-0015): ASP.NET Core and MEF
//! conventions, naming, class design, logging and time APIs. Queries stay
//! cheap on deep trees: see the notes in `js_modern.rs`.

use super::cs::{
    CS_SCOPE_STOPS, cs_has_modifier, cs_statements, cs_string_value, operand, same_code,
    simple_name, unparenthesized,
};
use super::cs_bugs::{attribute_arguments, attribute_names, cs_call_arguments, find_attribute};
use super::cs_more::{
    declarators, declared_type, enclosing_type, log_template, members, template_placeholders,
};
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
        id: "cs/sql-keyword-spacing",
        name: "SQL fragments should be separated by a space when concatenated",
        description: "`\"SELECT *\" + \"FROM t\"` is fine, but `\"SELECT id\" + \"FROM t\"` sends `idFROM`, \
                      which the database rejects or misreads.",
        message: "Add a space between these two SQL fragments.",
        category: Bug,
        severity: Blocker,
        effort_minutes: 2,
        sonar: &[exact("S2857")],
        check: Check::Query {
            langs: CSHARP,
            query: "(binary_expression) @match",
            filter: Some(Keep(joins_sql_without_space)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { const string Q = \"SELECT id, name\" + \"FROM users\"; }",
            good: "class A { const string Q = \"SELECT id, name \" + \"FROM users\"; }",
        }),
    },
    Rule {
        id: "cs/thread-suspend-resume",
        name: "Thread.Suspend and Thread.Resume should not be used",
        description: "Suspending a thread at an arbitrary point can leave it holding a lock, which deadlocks \
                      everything else that needs it. Both methods are obsolete.",
        message: "Coordinate the threads with a synchronization primitive instead.",
        category: Bug,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[exact("S3889")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(invocation_expression
                        function: (member_access_expression expression: (_) @r name: (identifier) @n)
                        arguments: (argument_list) @a
                        (#any-of? @n "Suspend" "Resume")) @match"#,
            filter: Some(Keep(suspends_thread)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(Thread worker) { worker.Suspend(); } }",
            good: "class A { void F(ManualResetEventSlim pause) { pause.Reset(); } }",
        }),
    },
    Rule {
        id: "cs/winforms-main-without-stathread",
        name: "Windows Forms entry points should be marked [STAThread]",
        description: "Windows Forms needs a single-threaded apartment; without [STAThread] on Main, the \
                      clipboard, drag and drop and common dialogs fail at run time.",
        message: "Add [STAThread] to this Main method.",
        category: Bug,
        severity: Major,
        effort_minutes: 1,
        sonar: &[exact("S4210")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(method_declaration name: (identifier) @n body: (_) (#eq? @n "Main")) @match"#,
            filter: Some(Find(winforms_main_without_sta)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "static class P { static void Main() { Application.Run(new MainForm()); } }",
            good: "static class P { [STAThread] static void Main() { Application.Run(new MainForm()); } }",
        }),
    },
    Rule {
        id: "cs/part-creation-policy-without-export",
        name: "[PartCreationPolicy] should be used with [Export]",
        description: "MEF only reads the creation policy of exported parts, so on its own the attribute does \
                      nothing.",
        message: "Add [Export] to this class, or remove [PartCreationPolicy].",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S4428")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration (attribute_list) name: (identifier)) @match",
            filter: Some(Find(policy_without_export)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "[PartCreationPolicy(CreationPolicy.Shared)] class Cache { }",
            good: "[Export, PartCreationPolicy(CreationPolicy.Shared)] class Cache { }",
        }),
    },
    Rule {
        id: "cs/constructor-argument-missing",
        name: "[ConstructorArgument] should name a constructor parameter",
        description: "XAML uses the name to match the property to a constructor parameter; a name no \
                      constructor has breaks deserialization.",
        message: "Name a parameter of one of this class's constructors.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S4260")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration name: (identifier) body: (declaration_list)) @match",
            filter: Some(Find(unknown_constructor_argument)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class Ext { public Ext(string path) { Path = path; } [ConstructorArgument(\"file\")] public string Path { get; set; } }",
            good: "class Ext { public Ext(string path) { Path = path; } [ConstructorArgument(\"path\")] public string Path { get; set; } }",
        }),
    },
    Rule {
        id: "cs/export-type-not-implemented",
        name: "Exported types should implement the contract they export",
        description: "MEF fails when composing a part exported as an interface or base class it doesn't \
                      actually implement.",
        message: "Implement the exported type, or export a type this class implements.",
        category: Bug,
        severity: Blocker,
        effort_minutes: 5,
        sonar: &[exact("S4159")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration (attribute_list) name: (identifier)) @match",
            filter: Some(Find(export_not_implemented)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "[Export(typeof(IStore))] class Cache { }",
            good: "[Export(typeof(IStore))] class Cache : IStore { }",
        }),
    },
    Rule {
        id: "cs/jsinvokable-not-public",
        name: "[JSInvokable] methods should be public",
        description: "Blazor only calls public methods from JavaScript; a non-public [JSInvokable] method \
                      fails when the script calls it.",
        message: "Make this [JSInvokable] method public.",
        category: Bug,
        severity: Major,
        effort_minutes: 1,
        sonar: &[exact("S6798")],
        check: Check::Query {
            langs: CSHARP,
            query: "(method_declaration (attribute_list) name: (identifier)) @match",
            filter: Some(Find(hidden_js_invokable)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class C { [JSInvokable] void Notify() { } }",
            good: "class C { [JSInvokable] public void Notify() { } }",
        }),
    },
    Rule {
        id: "cs/route-backslash",
        name: "Route templates should not contain backslashes",
        description: "URLs use `/`; a backslash in a route template never matches a request, or matches a \
                      literal backslash.",
        message: "Use '/' instead of '\\' in this route template.",
        category: Bug,
        severity: Major,
        effort_minutes: 1,
        sonar: &[exact("S6930")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(attribute name: (_)) (invocation_expression function: (member_access_expression))] @match",
            filter: Some(Find(route_with_backslash)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class C : Controller { [Route(\"orders\\\\{id}\")] public IActionResult Get(int id) => Ok(); }",
            good: "class C : Controller { [Route(\"orders/{id}\")] public IActionResult Get(int id) => Ok(); }",
        }),
    },
    // ---- Code smells ----
    Rule {
        id: "cs/type-name-pascal-case",
        name: "Type names should be PascalCase",
        description: "C# types are named in PascalCase, with acronyms of more than two letters written like \
                      words (`HtmlParser`, not `HTMLParser`), and interfaces start with I.",
        message: "Rename this type in PascalCase.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S101")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(class_declaration name: (identifier) @match) (struct_declaration name: (identifier) @match) \
                     (interface_declaration name: (identifier) @match) (enum_declaration name: (identifier) @match) \
                     (record_declaration name: (identifier) @match) (delegate_declaration name: (identifier) @match)]",
            filter: Some(Keep(is_badly_cased_type_name)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class HTMLParser { }",
            good: "class HtmlParser { } interface IDbStore { } class IOStream { }",
        }),
    },
    Rule {
        id: "cs/literal-suffix-case",
        name: "Long literal suffixes should be upper case",
        description: "A lowercase `l` suffix looks like the digit 1: `100l` reads as one thousand and one.",
        message: "Use an upper case 'L' suffix.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[related("S818")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"((integer_literal) @match (#match? @match "l[uU]?$|[uU]l$"))"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { long Max = 100l; }",
            good: "class A { long Max = 100L; }",
        }),
    },
    Rule {
        id: "cs/assignment-in-subexpression",
        name: "Assignments should not be made inside sub-expressions",
        description: "An assignment hidden in a condition or argument is easy to miss, or to mistake for a \
                      comparison.",
        message: "Move this assignment into its own statement.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1121")],
        check: Check::Query {
            langs: CSHARP,
            // Matched from the parent: calling parent() on each assignment of
            // an `a = b = c = ...` chain costs its depth, which is quadratic.
            query: "(_ (assignment_expression)) @match",
            filter: Some(Find(nested_assignment)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int x; bool F(int y) { return (x = y) > 0; } }",
            good: "class A { int x; bool F(int y) { x = y; return x > 0; } }",
        }),
    },
    Rule {
        id: "cs/icomparable-without-operators",
        name: "Types implementing IComparable should define the comparison operators",
        description: "Readers expect `a < b` to work on a type that can be compared; without the operators \
                      they must call CompareTo, and `==` may disagree with it.",
        message: "Define the comparison operators (<, >, <=, >=) and equality for this type.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 15,
        sonar: &[exact("S1210")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(class_declaration name: (identifier) (base_list)) (struct_declaration name: (identifier) (base_list))] @match",
            filter: Some(Find(comparable_without_operators)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "struct Money : IComparable<Money> { public int CompareTo(Money o) => 0; }",
            good: "struct Money : IComparable<Money> { public int CompareTo(Money o) => 0; public static bool operator <(Money a, Money b) => a.CompareTo(b) < 0; public static bool operator >(Money a, Money b) => a.CompareTo(b) > 0; }",
        }),
    },
    Rule {
        id: "cs/trivial-property",
        name: "Trivial properties should be auto-implemented",
        description: "A property that only reads and writes a private field nothing else uses is an \
                      auto-property written out by hand.",
        message: "Make this an auto-implemented property and remove its backing field.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S2292")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration body: (declaration_list)) @match",
            filter: Some(Find(trivial_property_name)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { private int count; public int Count { get { return count; } set { count = value; } } }",
            good: "class A { public int Count { get; set; } }",
        }),
    },
    Rule {
        id: "cs/contextual-keyword-name",
        name: "Contextual keywords should not be used as names",
        description: "`await`, `async`, `var`, `dynamic`, `nameof` and `yield` are keywords in some contexts; \
                      as names they confuse readers and break when the code moves into such a context.",
        message: "Rename this; it's a contextual keyword.",
        category: CodeSmell,
        severity: Blocker,
        effort_minutes: 2,
        sonar: &[exact("S2306")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(variable_declarator name: (identifier) @match) (parameter name: (identifier) @match) \
                     (method_declaration name: (identifier) @match) (property_declaration name: (identifier) @match) \
                     (local_function_statement name: (identifier) @match)]",
            filter: Some(Keep(is_contextual_keyword)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(int await) { G(await); } }",
            good: "class A { void F(int delay) { G(delay); } }",
        }),
    },
    Rule {
        id: "cs/flags-enum-name-plural",
        name: "[Flags] enum names should be plural",
        description: "A [Flags] value holds several options at once, so a plural name (`FileAccessRights`) \
                      says so; a singular one reads like a single choice.",
        message: "Give this [Flags] enum a plural name.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[related("S2342")],
        check: Check::Query {
            langs: CSHARP,
            query: "(enum_declaration (attribute_list) name: (identifier)) @match",
            filter: Some(Find(singular_flags_name)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "[Flags] enum Permission { None = 0, Read = 1, Write = 2 }",
            good: "[Flags] enum Permissions { None = 0, Read = 1, Write = 2 }",
        }),
    },
    Rule {
        id: "cs/property-copies-collection",
        name: "Properties should not return copies of collections",
        description: "A property that copies an array or list on every read looks cheap but isn't, and \
                      changes to what it returns are silently lost. Use a method, or return a read-only view.",
        message: "Turn this property into a method, or return a read-only view instead of a copy.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S2365")],
        check: Check::Query {
            langs: CSHARP,
            query: "(property_declaration name: (identifier)) @match",
            filter: Some(Find(getter_copies_collection)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { List<int> items = new(); public int[] Items => items.ToArray(); }",
            good: "class A { List<int> items = new(); public IReadOnlyList<int> Items => items; }",
        }),
    },
    Rule {
        id: "cs/multiline-without-braces",
        name: "Statements indented under an unbraced if or loop should be in braces",
        description: "Without braces only the first statement belongs to the if or loop; one indented under \
                      it as well runs every time, whatever the indentation suggests.",
        message: "Add braces: this statement isn't part of the if or loop above it.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2681")],
        check: Check::Query {
            langs: CSHARP,
            query: "(block) @match",
            filter: Some(Find(misleadingly_indented_statement)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(bool b) {\n    if (b)\n        G();\n        H();\n} }",
            good: "class A { void F(bool b) {\n    if (b)\n    {\n        G();\n        H();\n    }\n} }",
        }),
    },
    Rule {
        id: "cs/instance-writes-static",
        name: "Instance members should not write static fields",
        description: "Every instance shares a static field, so a write from one instance's method changes \
                      what all the others see, and races when they run on different threads.",
        message: "Make this field an instance field, or change it only from static members.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 15,
        sonar: &[exact("S2696")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(method_declaration body: (_)) (accessor_declaration body: (_))] @match",
            filter: Some(Find(instance_writes_static)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { static int count; void Hit() { count++; } }",
            good: "class A { static int count; static void Hit() { count++; } }",
        }),
    },
    Rule {
        id: "cs/static-field-set-in-constructor",
        name: "Instance constructors should not set static fields",
        description: "Each new instance overwrites the shared value, so it ends up describing whichever \
                      object was created last.",
        message: "Initialize this static field inline or in a static constructor.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S3010")],
        check: Check::Query {
            langs: CSHARP,
            query: "(constructor_declaration body: (_)) @match",
            filter: Some(Find(constructor_writes_static)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { static string Name; public A(string name) { Name = name; } }",
            good: "class A { string name; public A(string name) { this.name = name; } }",
        }),
    },
    Rule {
        id: "cs/private-class-not-sealed",
        name: "Private classes that nothing derives from should be sealed",
        description: "Sealing says the class isn't designed for inheritance and lets the runtime call its \
                      members directly.",
        message: "Seal this private class.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S3260")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration body: (declaration_list (class_declaration name: (identifier)) @match))",
            filter: Some(Find(unsealed_private_class)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { private class Node { } }",
            good: "class A { private sealed class Node { } }",
        }),
    },
    Rule {
        id: "cs/event-never-used",
        name: "Events should be raised",
        description: "An event that nothing in its class raises never fires; subscribers wait for nothing.",
        message: "Raise this event, or remove it.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[related("S3264")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration name: (identifier) body: (declaration_list)) @match",
            filter: Some(Find(unused_event)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { public event EventHandler Changed; public void Set() { } }",
            good: "class A { public event EventHandler Changed; public void Set() { Changed?.Invoke(this, EventArgs.Empty); } }",
        }),
    },
    Rule {
        id: "cs/static-constructor-only-initializes",
        name: "Static fields should be initialized inline",
        description: "A static constructor that only assigns static fields says the same as their \
                      initializers, and stops the runtime from initializing the type lazily.",
        message: "Initialize these static fields where they're declared and remove the static constructor.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S3963")],
        check: Check::Query {
            langs: CSHARP,
            query: "(constructor_declaration (modifier) body: (block)) @match",
            filter: Some(Keep(only_assigns_static_fields)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { static int max; static A() { max = 10; } }",
            good: "class A { static int max = 10; }",
        }),
    },
    Rule {
        id: "cs/identical-methods",
        name: "Methods should not have identical implementations",
        description: "Two methods with the same body are duplicated code; one should call the other.",
        message: "Make this method call the identical one above it, or merge them.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 15,
        sonar: &[exact("S4144")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(class_declaration body: (declaration_list)) (struct_declaration body: (declaration_list))] @match",
            filter: Some(Find(identical_method)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F() { G(); H(); } void K() { G(); H(); } }",
            good: "class A { void F() { G(); H(); } void K() { F(); } }",
        }),
    },
    Rule {
        id: "cs/public-extern",
        name: "Native methods should be wrapped",
        description: "Exposing a P/Invoke declaration directly lets callers pass anything to native code, \
                      without the checks a managed wrapper would add.",
        message: "Make this extern method private and expose a managed wrapper.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S4200")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(method_declaration (modifier) @m name: (identifier) (#eq? @m "extern")) @match"#,
            filter: Some(Find(visible_extern_name)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class N { [DllImport(\"lib\")] public static extern int Run(string s); }",
            good: "class N { [DllImport(\"lib\")] private static extern int Run(string s); public static int Start(string s) => Run(s ?? \"\"); }",
        }),
    },
    Rule {
        id: "cs/null-check-before-is",
        name: "Null checks should not come before a type check",
        description: "`x is T` is already false for null, so `x != null && x is T` checks null twice.",
        message: "Remove this null check; 'is' already handles null.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S4201")],
        check: Check::Query {
            langs: CSHARP,
            query: "(binary_expression) @match",
            filter: Some(Keep(null_check_before_is)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { bool F(object o) { return o != null && o is string; } }",
            good: "class A { bool F(object o) { return o is string; } }",
        }),
    },
    Rule {
        id: "cs/event-args-null",
        name: "Events should not be raised with null arguments",
        description: "Handlers expect `sender` to be the object and the event data to exist; passing null \
                      makes every handler check for it, and the ones that don't throw.",
        message: "Pass 'this' as the sender and EventArgs.Empty (or real data) as the arguments.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S4220")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration body: (declaration_list)) @match",
            filter: Some(Find(event_raised_with_null)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { public event EventHandler Changed; void F() { Changed?.Invoke(this, null); } }",
            good: "class A { public event EventHandler Changed; void F() { Changed?.Invoke(this, EventArgs.Empty); } }",
        }),
    },
    Rule {
        id: "cs/datetime-now-benchmark",
        name: "Stopwatch should be used to measure elapsed time",
        description: "DateTime.Now has a coarse resolution and jumps with clock changes; Stopwatch measures \
                      intervals accurately.",
        message: "Use Stopwatch to measure this duration.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6561")],
        check: Check::Query {
            langs: CSHARP,
            query: "(binary_expression left: (member_access_expression)) @match",
            filter: Some(Keep(subtracts_from_now)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { TimeSpan F(DateTime start) { return DateTime.Now - start; } }",
            good: "class A { TimeSpan F(Stopwatch watch) { return watch.Elapsed; } }",
        }),
    },
    Rule {
        id: "cs/trace-write",
        name: "Trace.Write and Trace.WriteLine should not be used for logging",
        description: "They carry no severity, so listeners can't filter them; TraceInformation, TraceWarning \
                      and TraceError do.",
        message: "Use Trace.TraceInformation, TraceWarning or TraceError instead.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6670")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(invocation_expression
                        function: (member_access_expression expression: (_) @t name: (identifier) @n)
                        (#match? @t "(^|\\.)Trace$") (#any-of? @n "Write" "WriteLine")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F() { Trace.WriteLine(\"started\"); } }",
            good: "class A { void F() { Trace.TraceInformation(\"started\"); } }",
        }),
    },
    Rule {
        id: "cs/logger-field-name",
        name: "Logger fields should be named logger",
        description: "One name for the logger field (`logger`, `_logger`, `Logger`, `log` and the like) makes \
                      logging code easy to find and read across a codebase.",
        message: "Rename this field to 'logger' (or '_logger', 'Log').",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6669")],
        check: Check::Query {
            langs: CSHARP,
            query: "(field_declaration (variable_declaration type: [(identifier) (generic_name) (qualified_name)])) @match",
            filter: Some(Find(oddly_named_logger)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { private readonly ILogger<A> output; }",
            good: "class A { private readonly ILogger<A> logger; }",
        }),
    },
    Rule {
        id: "cs/log-exception-not-passed",
        name: "Caught exceptions should be passed to the logger",
        description: "Logging only a message in a catch block drops the exception's type and stack trace, \
                      which is what the log is needed for.",
        message: "Pass the exception to this logging call.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6667")],
        check: Check::Query {
            langs: CSHARP,
            query: "(catch_clause (catch_declaration name: (identifier)) body: (block)) @match",
            filter: Some(Find(log_without_exception)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(ILogger log) { try { G(); } catch (IOException e) { log.LogError(\"Write failed\"); } } }",
            good: "class A { void F(ILogger log) { try { G(); } catch (IOException e) { log.LogError(e, \"Write failed\"); } } }",
        }),
    },
    Rule {
        id: "cs/log-template-argument-order",
        name: "Log arguments should be in the order of their placeholders",
        description: "Placeholders take the arguments by position, not by name; `\"{From} {To}\", to, from` \
                      logs them the wrong way round.",
        message: "Pass the arguments in the order of the template's placeholders.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6673")],
        check: Check::Query {
            langs: CSHARP,
            query: "(invocation_expression function: (member_access_expression name: (identifier)) arguments: (argument_list)) @match",
            filter: Some(Find(arguments_out_of_order)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(ILogger log, int from, int to) { log.LogInformation(\"Moved {From} to {To}\", to, from); } }",
            good: "class A { void F(ILogger log, int from, int to) { log.LogInformation(\"Moved {From} to {To}\", from, to); } }",
        }),
    },
    Rule {
        id: "cs/action-route-leading-slash",
        name: "Action route templates should not start with /",
        description: "A template starting with `/` ignores the controller's [Route], so the action ends up at \
                      a URL its controller doesn't suggest.",
        message: "Remove the leading '/' so the action's route builds on the controller's.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6931")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration (attribute_list) name: (identifier) body: (declaration_list)) @match",
            filter: Some(Find(absolute_action_route)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "[Route(\"api/orders\")] class C : ControllerBase { [HttpGet(\"/all\")] public IActionResult All() => Ok(); }",
            good: "[Route(\"api/orders\")] class C : ControllerBase { [HttpGet(\"all\")] public IActionResult All() => Ok(); }",
        }),
    },
    Rule {
        id: "cs/controller-route-missing",
        name: "Controllers whose actions have routes should have a [Route]",
        description: "Without a controller-level [Route], every action repeats the common prefix, and changing \
                      it means editing them all.",
        message: "Add a [Route] to this controller with the part its actions share.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6934")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration name: (identifier) (base_list) body: (declaration_list)) @match",
            filter: Some(Find(controller_without_route)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class OrdersController : Controller { [HttpGet(\"orders/{id}\")] public IActionResult Get(int id) => Ok(); }",
            good: "[Route(\"orders\")] class OrdersController : Controller { [HttpGet(\"{id}\")] public IActionResult Get(int id) => Ok(); }",
        }),
    },
    Rule {
        id: "cs/api-controller-derives-controller",
        name: "API controllers should derive from ControllerBase",
        description: "`Controller` adds view support an API never uses; ControllerBase is the base for \
                      [ApiController] classes.",
        message: "Derive this API controller from ControllerBase.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6961")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration (attribute_list) name: (identifier) (base_list)) @match",
            filter: Some(Find(api_controller_with_views)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "[ApiController] class OrdersController : Controller { }",
            good: "[ApiController] class OrdersController : ControllerBase { }",
        }),
    },
    Rule {
        id: "cs/new-httpclient",
        name: "HttpClient should not be created per call",
        description: "Each new HttpClient opens its own connections, which exhausts sockets under load and \
                      misses DNS changes. Use IHttpClientFactory or one shared instance.",
        message: "Get this HttpClient from IHttpClientFactory, or reuse a shared instance.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 15,
        sonar: &[exact("S6962")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(object_creation_expression type: (_) @t (#match? @t "^(System\\.Net\\.Http\\.)?HttpClient$")) @match"#,
            filter: Some(Keep(created_in_a_method)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { async Task<string> F() { using var http = new HttpClient(); return await http.GetStringAsync(\"https://a.example\"); } }",
            good: "class A { static readonly HttpClient Http = new HttpClient(); Task<string> F() => Http.GetStringAsync(\"https://a.example\"); }",
        }),
    },
    Rule {
        id: "cs/action-without-http-verb",
        name: "API actions should declare their HTTP method",
        description: "Without [HttpGet], [HttpPost] and the like, an API action answers every verb, and API \
                      descriptions can't document it.",
        message: "Add the HTTP method attribute to this action.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6965")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration (attribute_list) name: (identifier) body: (declaration_list)) @match",
            filter: Some(Find(action_without_verb)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "[ApiController] class OrdersController : ControllerBase { public IActionResult List() => Ok(); }",
            good: "[ApiController] class OrdersController : ControllerBase { [HttpGet] public IActionResult List() => Ok(); }",
        }),
    },
    Rule {
        id: "cs/produces-response-type-missing",
        name: "API actions returning IActionResult should declare their response types",
        description: "`IActionResult` hides what the action returns, so API descriptions show nothing for it. \
                      [ProducesResponseType], or ActionResult<T>, says it.",
        message: "Add [ProducesResponseType] for the responses this action returns, or return ActionResult<T>.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6968")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration (attribute_list) name: (identifier) body: (declaration_list)) @match",
            filter: Some(Find(undescribed_action)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "[ApiController] class OrdersController : ControllerBase { [HttpGet] public IActionResult List() => Ok(); }",
            good: "[ApiController] class OrdersController : ControllerBase { [HttpGet] public ActionResult<Order[]> List() => Ok(); }",
        }),
    },
];

// ---------------------------------------------------- helpers

fn has_attribute(declaration: Node, names: &[&[u8]], src: &[u8]) -> bool {
    attribute_names(declaration, src)
        .iter()
        .any(|(_, n)| names.contains(n))
}

fn base_names<'s>(declaration: Node, src: &'s [u8]) -> Vec<&'s [u8]> {
    let mut cursor = declaration.walk();
    let Some(list) = declaration
        .named_children(&mut cursor)
        .find(|c| c.kind() == "base_list")
    else {
        return Vec::new();
    };
    let mut inner = list.walk();
    list.named_children(&mut inner)
        .filter(|c| c.kind() != "comment" && c.kind() != "argument_list")
        .map(|c| simple_name(c, src))
        .collect()
}

fn is_api_controller(class: Node, src: &[u8]) -> bool {
    has_attribute(class, &[b"ApiController"], src)
}

const HTTP_VERBS: &[&[u8]] = &[
    b"HttpGet",
    b"HttpPost",
    b"HttpPut",
    b"HttpDelete",
    b"HttpPatch",
    b"HttpHead",
    b"HttpOptions",
    b"AcceptVerbs",
];

/// Public, non-static methods of a controller that ASP.NET Core treats as
/// actions.
fn actions<'t>(class: Node<'t>, src: &[u8]) -> Vec<Node<'t>> {
    members(class)
        .into_iter()
        .filter(|m| {
            m.kind() == "method_declaration"
                && cs_has_modifier(*m, "public", src)
                && !cs_has_modifier(*m, "static", src)
                && !cs_has_modifier(*m, "override", src)
                && !has_attribute(*m, &[b"NonAction"], src)
        })
        .collect()
}

/// The route template string of a [Route] or [HttpGet("...")] attribute.
fn route_template<'t>(attribute: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let name = simple_name(attribute.child_by_field_name("name")?, src);
    let name = name.strip_suffix(b"Attribute").unwrap_or(name);
    if name != b"Route" && !HTTP_VERBS.contains(&name) {
        return None;
    }
    attribute_arguments(attribute)
        .into_iter()
        .find(|(n, v)| {
            n.is_none_or(|n| text(n, src) == b"Template") && cs_string_value(*v, src).is_some()
        })
        .map(|(_, v)| v)
}

fn route_templates<'t>(declaration: Node<'t>, src: &[u8]) -> Vec<Node<'t>> {
    attribute_names(declaration, src)
        .into_iter()
        .filter_map(|(a, _)| route_template(a, src))
        .collect()
}

/// Is this PascalCase, with acronyms of at most two capitals?
pub(super) fn is_pascal_case(name: &[u8]) -> bool {
    if name.is_empty() || !name[0].is_ascii_uppercase() || name.contains(&b'_') {
        return false;
    }
    // A run of capitals followed by a lower case letter ends with that word's
    // first letter: "IOStream" is IO + Stream.
    let mut i = 0;
    while i < name.len() {
        if name[i].is_ascii_uppercase() {
            let start = i;
            while i < name.len() && name[i].is_ascii_uppercase() {
                i += 1;
            }
            let run = i - start;
            let acronym = if i < name.len() && name[i].is_ascii_lowercase() {
                run - 1
            } else {
                run
            };
            if acronym > 2 {
                return false;
            }
        } else {
            i += 1;
        }
    }
    true
}

// ---------------------------------------------------- filters

const SQL_KEYWORDS: &[&[u8]] = &[
    b"select", b"insert", b"update", b"delete", b"from", b"where", b"join", b"values", b"into",
    b"group", b"order", b"having", b"set",
];

fn string_piece(node: Node, src: &[u8]) -> Option<Vec<u8>> {
    match node.kind() {
        "string_literal" | "verbatim_string_literal" => {
            cs_string_value(node, src).map(<[u8]>::to_vec)
        }
        "interpolated_string_expression" => {
            let mut cursor = node.walk();
            let parts: Vec<u8> = node
                .named_children(&mut cursor)
                .flat_map(|c| match c.kind() {
                    "string_content" => text(c, src).to_vec(),
                    "interpolation" => b"x".to_vec(),
                    _ => Vec::new(),
                })
                .collect();
            Some(parts)
        }
        _ => None,
    }
}

fn joins_sql_without_space(node: Node, src: &[u8]) -> bool {
    if operator_text(node, src) != b"+" {
        return false;
    }
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return false;
    };
    // The left side's last piece: the rightmost operand of a `+` chain.
    let mut last = left;
    while last.kind() == "binary_expression" {
        match last.child_by_field_name("right") {
            Some(r) => last = r,
            None => break,
        }
    }
    // Checked here rather than in the query: constraining `right:` after
    // `left:` keeps a pending match per level of a long `a + b + ...` chain.
    let (Some(before), Some(after)) = (string_piece(last, src), string_piece(right, src)) else {
        return false;
    };
    let ends_word = before.last().is_some_and(|b| b.is_ascii_alphanumeric());
    let starts_word = after.first().is_some_and(|b| b.is_ascii_alphanumeric());
    if !(ends_word && starts_word) {
        return false;
    }
    // Read the keywords from each fragment: joined, "name" + "FROM" is one word.
    let (before, after) = (before.to_ascii_lowercase(), after.to_ascii_lowercase());
    let words: Vec<&[u8]> = before
        .split(|b| !b.is_ascii_alphanumeric() && *b != b'_')
        .chain(after.split(|b| !b.is_ascii_alphanumeric() && *b != b'_'))
        .collect();
    words.contains(&&b"select"[..]) && words.contains(&&b"from"[..])
        || words.contains(&&b"update"[..]) && words.contains(&&b"set"[..])
        || words.contains(&&b"insert"[..]) && words.contains(&&b"into"[..])
        || words.contains(&&b"delete"[..]) && words.contains(&&b"from"[..])
        || SQL_KEYWORDS.iter().filter(|k| words.contains(k)).count() >= 3
}

fn suspends_thread(call: Node, src: &[u8]) -> bool {
    let no_args = call
        .child_by_field_name("arguments")
        .is_some_and(|a| a.named_child_count() == 0);
    let receiver = call
        .child_by_field_name("function")
        .and_then(|f| f.child_by_field_name("expression"));
    let Some(receiver) = receiver else {
        return false;
    };
    if !no_args {
        return false;
    }
    let name = text(receiver, src);
    if contains_ignoring_case(name, b"thread") {
        return true;
    }
    // A parameter, local or field declared as a Thread.
    let Some(scope) = enclosing_type(call) else {
        return false;
    };
    let declared_as_thread = |n: Node| {
        n.child_by_field_name("type")
            .is_some_and(|t| simple_name(t, src) == b"Thread")
    };
    find_in_scope(scope, &[], |n| match n.kind() {
        "parameter" => {
            declared_as_thread(n)
                && n.child_by_field_name("name")
                    .is_some_and(|x| text(x, src) == name)
        }
        "variable_declaration" => {
            declared_as_thread(n) && {
                let mut cursor = n.walk();
                n.named_children(&mut cursor).any(|d| {
                    d.kind() == "variable_declarator"
                        && d.child_by_field_name("name")
                            .is_some_and(|x| text(x, src) == name)
                })
            }
        }
        _ => false,
    })
    .is_some()
}

fn winforms_main_without_sta<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !cs_has_modifier(method, "static", src) || has_attribute(method, &[b"STAThread"], src) {
        return None;
    }
    let body = method.child_by_field_name("body")?;
    let runs_forms = find_in_scope(body, &[], |n| {
        n.kind() == "invocation_expression"
            && n.child_by_field_name("function").is_some_and(|f| {
                matches!(
                    text(f, src),
                    b"Application.Run" | b"System.Windows.Forms.Application.Run"
                )
            })
    })
    .is_some();
    runs_forms.then(|| method.child_by_field_name("name"))?
}

fn policy_without_export<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    (has_attribute(class, &[b"PartCreationPolicy"], src)
        && !has_attribute(class, &[b"Export", b"InheritedExport"], src))
    .then(|| class.child_by_field_name("name"))?
}

fn unknown_constructor_argument<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let ms = members(class);
    let parameters: Vec<&[u8]> = ms
        .iter()
        .filter(|m| m.kind() == "constructor_declaration")
        .filter_map(|m| m.child_by_field_name("parameters"))
        .flat_map(|p| {
            let mut cursor = p.walk();
            p.named_children(&mut cursor)
                .filter_map(|x| x.child_by_field_name("name").map(|n| text(n, src)))
                .collect::<Vec<_>>()
        })
        .collect();
    ms.iter()
        .filter(|m| m.kind() == "property_declaration")
        .find_map(|p| {
            let attribute = find_attribute(*p, "ConstructorArgument", src)?;
            let (_, value) = attribute_arguments(attribute).into_iter().next()?;
            let name = cs_string_value(value, src)?;
            (!parameters.contains(&name)).then_some(value)
        })
}

fn export_not_implemented<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let own = text(class.child_by_field_name("name")?, src);
    let bases = base_names(class, src);
    attribute_names(class, src)
        .into_iter()
        .filter(|(_, n)| matches!(*n, b"Export" | b"InheritedExport"))
        .find_map(|(attribute, _)| {
            let (_, value) = attribute_arguments(attribute)
                .into_iter()
                .find(|(_, v)| v.kind() == "typeof_expression")?;
            let exported = simple_name(value.child_by_field_name("type")?, src);
            (exported != own && !bases.contains(&exported) && !exported.is_empty()).then_some(value)
        })
}

fn hidden_js_invokable<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    (has_attribute(method, &[b"JSInvokable"], src) && !cs_has_modifier(method, "public", src))
        .then(|| method.child_by_field_name("name"))?
}

fn route_with_backslash<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let template = if node.kind() == "attribute" {
        route_template(node, src)?
    } else {
        // app.MapGet("orders\\{id}", ...)
        let method = node
            .child_by_field_name("function")
            .and_then(|f| f.child_by_field_name("name"))
            .map(|n| text(n, src))?;
        if !matches!(
            method,
            b"MapGet"
                | b"MapPost"
                | b"MapPut"
                | b"MapDelete"
                | b"MapPatch"
                | b"MapMethods"
                | b"MapGroup"
        ) {
            return None;
        }
        *cs_call_arguments(node).first()?
    };
    cs_string_value(template, src)
        .is_some_and(|v| v.contains(&b'\\'))
        .then_some(template)
}

fn is_badly_cased_type_name(name: Node, src: &[u8]) -> bool {
    let n = text(name, src);
    let is_interface = name
        .parent()
        .is_some_and(|p| p.kind() == "interface_declaration");
    let checked = if is_interface {
        match n.strip_prefix(b"I") {
            Some(rest) if rest.first().is_some_and(u8::is_ascii_uppercase) => rest,
            _ => return true,
        }
    } else {
        n
    };
    // Test classes commonly use underscores (Given_When_Then); leave them be.
    if checked.contains(&b'_')
        && name.parent().is_some_and(|c| {
            contains_ignoring_case(text(c, src), b"[Test")
                || contains_ignoring_case(text(c, src), b"[Fact")
        })
    {
        return false;
    }
    !is_pascal_case(checked)
}

fn is_contextual_keyword(name: Node, src: &[u8]) -> bool {
    matches!(
        text(name, src),
        b"async" | b"await" | b"dynamic" | b"nameof" | b"var" | b"yield"
    )
}

fn nested_assignment<'t>(parent: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut cursor = parent.walk();
    // `return cache ??= new();` is the lazy-initialization idiom.
    let assignment = parent
        .named_children(&mut cursor)
        .find(|c| c.kind() == "assignment_expression" && operator_text(*c, src) != b"??=")?;
    let nested = match parent.kind() {
        "expression_statement"
        | "for_statement"
        | "assignment_expression"
        | "lambda_expression"
        | "arrow_expression_clause"
        | "initializer_expression"
        | "with_initializer"
        | "anonymous_object_creation_expression"
        | "argument"
        | "attribute_argument" => false,
        // `while ((line = reader.ReadLine()) != null)` is an accepted idiom.
        "parenthesized_expression" => !parent
            .parent()
            .and_then(|b| b.parent())
            .is_some_and(|w| matches!(w.kind(), "while_statement" | "do_statement")),
        _ => true,
    };
    nested.then_some(assignment)
}

fn comparable_without_operators<'t>(declaration: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !base_names(declaration, src)
        .iter()
        .any(|b| *b == b"IComparable")
    {
        return None;
    }
    let defines_less = members(declaration).iter().any(|m| {
        m.kind() == "operator_declaration" && {
            let mut cursor = m.walk();
            m.children(&mut cursor)
                .any(|c| !c.is_named() && text(c, src) == b"<")
        }
    });
    (!defines_less).then(|| declaration.child_by_field_name("name"))?
}

fn trivial_property_name<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if class.has_error() || cs_has_modifier(class, "partial", src) {
        return None;
    }
    let ms = members(class);
    // Private, non-static fields without attributes or initializers.
    let fields: Vec<&[u8]> = ms
        .iter()
        .filter(|m| {
            m.kind() == "field_declaration"
                && ![
                    "public",
                    "protected",
                    "internal",
                    "static",
                    "readonly",
                    "volatile",
                ]
                .iter()
                .any(|x| cs_has_modifier(**m, x, src))
                && attribute_names(**m, src).is_empty()
        })
        .flat_map(|m| declarators(*m))
        .filter(|d| d.named_child_count() == 1)
        .filter_map(|d| d.child_by_field_name("name").map(|n| text(n, src)))
        .collect();
    let whole = text(class, src);
    ms.iter()
        .filter(|m| m.kind() == "property_declaration")
        .find_map(|p| {
            if cs_has_modifier(*p, "virtual", src)
                || cs_has_modifier(*p, "override", src)
                || cs_has_modifier(*p, "abstract", src)
            {
                return None;
            }
            let accessors = p.child_by_field_name("accessors")?;
            let mut cursor = accessors.walk();
            let list: Vec<Node> = accessors
                .named_children(&mut cursor)
                .filter(|a| a.kind() == "accessor_declaration")
                .collect();
            let [get, set] = list.as_slice() else {
                return None;
            };
            let body_expr = |a: Node<'t>| -> Option<Node<'t>> {
                let body = a.child_by_field_name("body")?;
                match body.kind() {
                    "arrow_expression_clause" => operand(body),
                    "block" => match cs_statements(body).as_slice() {
                        [s] => operand(*s),
                        _ => None,
                    },
                    _ => None,
                }
            };
            let read = body_expr(*get)
                .filter(|e| e.kind() == "identifier")
                .map(|e| text(e, src))?;
            let write = body_expr(*set).filter(|e| e.kind() == "assignment_expression")?;
            let wrote_field = write
                .child_by_field_name("left")
                .is_some_and(|l| text(l, src) == read);
            let wrote_value = write
                .child_by_field_name("right")
                .is_some_and(|r| text(r, src) == b"value");
            // The field is only used by this property: its declaration, the
            // getter and the setter.
            (fields.contains(&read) && wrote_field && wrote_value && count_word(whole, read) == 3)
                .then(|| p.child_by_field_name("name"))?
        })
}

fn singular_flags_name<'t>(declaration: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_attribute(declaration, "Flags", src)?;
    let name = declaration.child_by_field_name("name")?;
    (!text(name, src).ends_with(b"s")).then_some(name)
}

fn getter_copies_collection<'t>(property: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let getter_expression = || -> Option<Node<'t>> {
        if let Some(value) = property
            .child_by_field_name("value")
            .filter(|v| v.kind() == "arrow_expression_clause")
        {
            return operand(value);
        }
        let accessors = property.child_by_field_name("accessors")?;
        let mut cursor = accessors.walk();
        let get = accessors
            .named_children(&mut cursor)
            .find(|a| a.child_by_field_name("name").map(|k| text(k, src)) == Some(b"get"))?;
        let body = get.child_by_field_name("body")?;
        match body.kind() {
            "arrow_expression_clause" => operand(body),
            "block" => match cs_statements(body).as_slice() {
                [s] if s.kind() == "return_statement" => operand(*s),
                _ => None,
            },
            _ => None,
        }
    };
    let e = unparenthesized(getter_expression()?);
    let copies = match e.kind() {
        "invocation_expression" => {
            e.child_by_field_name("function")
                .and_then(|f| f.child_by_field_name("name"))
                .is_some_and(|m| matches!(text(m, src), b"ToList" | b"ToArray" | b"Clone"))
                && e.child_by_field_name("arguments")
                    .is_some_and(|a| a.named_child_count() == 0)
        }
        "object_creation_expression" => {
            e.child_by_field_name("type").is_some_and(|t| {
                matches!(simple_name(t, src), b"List" | b"HashSet" | b"Dictionary")
            }) && cs_call_arguments(e).len() == 1
        }
        _ => false,
    };
    copies.then_some(e)
}

fn misleadingly_indented_statement<'t>(block: Node<'t>, _src: &[u8]) -> Option<Node<'t>> {
    let stmts = cs_statements(block);
    stmts.windows(2).find_map(|pair| {
        let (control, next) = (pair[0], pair[1]);
        let body_field = match control.kind() {
            "if_statement" if control.child_by_field_name("alternative").is_none() => "consequence",
            "for_statement" | "foreach_statement" | "while_statement" => "body",
            _ => return None,
        };
        let body = control.child_by_field_name(body_field)?;
        // An unbraced body on its own line, and the next statement indented
        // like it rather than like the if.
        (body.kind() != "block"
            && body.start_position().row > control.start_position().row
            && next.start_position().column == body.start_position().column
            && next.start_position().column > super::cs_final::line_indent(control, _src))
        .then_some(next)
    })
}

/// The static, non-readonly, non-const field names of a type.
fn static_fields<'s>(declaration: Node, src: &'s [u8]) -> Vec<&'s [u8]> {
    members(declaration)
        .into_iter()
        .filter(|m| {
            m.kind() == "field_declaration"
                && cs_has_modifier(*m, "static", src)
                && !cs_has_modifier(*m, "readonly", src)
                && !cs_has_modifier(*m, "const", src)
                // [ThreadStatic] fields belong to their thread.
                && find_attribute(*m, "ThreadStatic", src).is_none()
        })
        .flat_map(declarators)
        .filter_map(|d| d.child_by_field_name("name").map(|n| text(n, src)))
        .collect()
}

/// An assignment or increment that changes one of `fields` (by its bare
/// name, or `this.`-less `Type.name`) inside `body`.
fn write_to<'t>(body: Node<'t>, fields: &[&[u8]], src: &[u8]) -> Option<Node<'t>> {
    let target_is_field = |t: Node| {
        let name = match t.kind() {
            "identifier" => text(t, src),
            _ => return false,
        };
        fields.contains(&name)
    };
    find_in_scope(body, CS_SCOPE_STOPS, |n| match n.kind() {
        "assignment_expression" => n.child_by_field_name("left").is_some_and(target_is_field),
        "postfix_unary_expression" | "prefix_unary_expression" => {
            let t = text(n, src);
            (t.starts_with(b"++")
                || t.starts_with(b"--")
                || t.ends_with(b"++")
                || t.ends_with(b"--"))
                && operand(n).is_some_and(target_is_field)
        }
        _ => false,
    })
}

fn instance_writes_static<'t>(member: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let owner = if member.kind() == "accessor_declaration" {
        member.parent().and_then(|l| l.parent())?
    } else {
        member
    };
    if cs_has_modifier(owner, "static", src) {
        return None;
    }
    let declaration = enclosing_type(owner)?;
    let fields = static_fields(declaration, src);
    if fields.is_empty() {
        return None;
    }
    write_to(member.child_by_field_name("body")?, &fields, src)
}

fn constructor_writes_static<'t>(constructor: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if cs_has_modifier(constructor, "static", src) {
        return None;
    }
    let fields = static_fields(enclosing_type(constructor)?, src);
    if fields.is_empty() {
        return None;
    }
    write_to(constructor.child_by_field_name("body")?, &fields, src)
}

fn unsealed_private_class<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let private = cs_has_modifier(class, "private", src)
        || !["public", "protected", "internal"]
            .iter()
            .any(|m| cs_has_modifier(class, m, src));
    if !private
        || ["sealed", "static", "abstract", "partial"]
            .iter()
            .any(|m| cs_has_modifier(class, m, src))
    {
        return None;
    }
    let name = class.child_by_field_name("name")?;
    let n = text(name, src);
    // Another class in the outer type may derive from it.
    let outer = class.parent()?.parent()?;
    let derived = find_in_scope(outer, &[], |c| {
        c.kind() == "base_list" && count_word(text(c, src), n) > 0
    })
    .is_some();
    (!derived).then_some(name)
}

fn unused_event<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if class.has_error() || cs_has_modifier(class, "partial", src) {
        return None;
    }
    let whole = text(class, src);
    members(class)
        .into_iter()
        .filter(|m| {
            m.kind() == "event_field_declaration"
                && !["override", "abstract", "virtual"]
                    .iter()
                    .any(|x| cs_has_modifier(*m, x, src))
        })
        .flat_map(declarators)
        .filter_map(|d| d.child_by_field_name("name"))
        .find(|n| count_word(whole, text(*n, src)) == 1)
}

fn only_assigns_static_fields(constructor: Node, src: &[u8]) -> bool {
    if !cs_has_modifier(constructor, "static", src) {
        return false;
    }
    let Some(body) = constructor.child_by_field_name("body") else {
        return false;
    };
    let Some(declaration) = enclosing_type(constructor) else {
        return false;
    };
    let fields: Vec<&[u8]> = members(declaration)
        .into_iter()
        .filter(|m| m.kind() == "field_declaration" && cs_has_modifier(*m, "static", src))
        .flat_map(declarators)
        .filter_map(|d| d.child_by_field_name("name").map(|n| text(n, src)))
        .collect();
    let stmts = cs_statements(body);
    !stmts.is_empty()
        && stmts.iter().all(|s| {
            operand(*s)
                .filter(|a| a.kind() == "assignment_expression" && operator_text(*a, src) == b"=")
                .and_then(|a| a.child_by_field_name("left"))
                .is_some_and(|l| fields.contains(&text(l, src)))
        })
}

fn identical_method<'t>(declaration: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let methods: Vec<(Node<'t>, Node<'t>)> = members(declaration)
        .into_iter()
        .filter(|m| m.kind() == "method_declaration")
        .filter_map(|m| {
            let body = m
                .child_by_field_name("body")
                .filter(|b| b.kind() == "block")?;
            // Short bodies are often the same on purpose (`=> throw ...`).
            (cs_statements(body).len() >= 2).then_some((m, body))
        })
        .collect();
    for (i, (method, body)) in methods.iter().enumerate() {
        let params = |m: Node| m.child_by_field_name("parameters").map(|p| text(p, src));
        let same = methods[..i].iter().any(|(earlier, earlier_body)| {
            params(*earlier) == params(*method) && same_code(*earlier_body, *body, src)
        });
        if same {
            return method.child_by_field_name("name");
        }
    }
    None
}

fn visible_extern_name<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    ["public", "protected"]
        .iter()
        .any(|m| cs_has_modifier(method, m, src))
        .then(|| method.child_by_field_name("name"))?
}

fn null_check_before_is(node: Node, src: &[u8]) -> bool {
    if operator_text(node, src) != b"&&" {
        return false;
    }
    let (Some(check), Some(is)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return false;
    };
    if !matches!(is.kind(), "is_expression" | "is_pattern_expression") {
        return false;
    }
    if operator_text(check, src) != b"!=" {
        return false;
    }
    let subject = match is.kind() {
        "is_expression" => is.child_by_field_name("left"),
        _ => is.child_by_field_name("expression"),
    };
    let (Some(l), Some(r), Some(subject)) = (
        check.child_by_field_name("left"),
        check.child_by_field_name("right"),
        subject,
    ) else {
        return false;
    };
    (r.kind() == "null_literal" && same_code(l, subject, src))
        || (l.kind() == "null_literal" && same_code(r, subject, src))
}

fn event_raised_with_null<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let events: Vec<&[u8]> = members(class)
        .into_iter()
        .filter(|m| m.kind() == "event_field_declaration")
        .flat_map(declarators)
        .filter_map(|d| d.child_by_field_name("name").map(|n| text(n, src)))
        .collect();
    if events.is_empty() {
        return None;
    }
    let body = class.child_by_field_name("body")?;
    find_in_scope(body, &[], |n| {
        if n.kind() != "invocation_expression" {
            return false;
        }
        let Some(function) = n.child_by_field_name("function") else {
            return false;
        };
        // E?.Invoke(...), E.Invoke(...) or E(...)
        let t = text(function, src);
        let raised = events
            .iter()
            .any(|e| t == *e || t == [*e, b"?.Invoke"].concat() || t == [*e, b".Invoke"].concat());
        if !raised {
            return false;
        }
        let args = cs_call_arguments(n);
        let in_static = n.parent().is_some_and(|_| {
            let mut current = n.parent();
            for _ in 0..64 {
                match current {
                    Some(m)
                        if matches!(
                            m.kind(),
                            "method_declaration" | "accessor_declaration" | "property_declaration"
                        ) =>
                    {
                        return cs_has_modifier(m, "static", src);
                    }
                    Some(m) => current = m.parent(),
                    None => return false,
                }
            }
            false
        });
        match args.as_slice() {
            [sender, data] => {
                (sender.kind() == "null_literal" && !in_static) || data.kind() == "null_literal"
            }
            _ => false,
        }
    })
}

fn subtracts_from_now(node: Node, src: &[u8]) -> bool {
    operator_text(node, src) == b"-"
        && node.child_by_field_name("left").is_some_and(|l| {
            matches!(
                text(l, src),
                b"DateTime.Now"
                    | b"DateTime.UtcNow"
                    | b"System.DateTime.Now"
                    | b"System.DateTime.UtcNow"
            )
        })
}

fn oddly_named_logger<'t>(field: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let ty = declared_type(field)?;
    // Logging abstractions only: a class merely named Logger may be anything.
    if !matches!(simple_name(ty, src), b"ILogger" | b"ILog") {
        return None;
    }
    declarators(field).into_iter().find_map(|d| {
        let name = d.child_by_field_name("name")?;
        let n = text(name, src).to_ascii_lowercase();
        let n = n.strip_prefix(b"_").unwrap_or(&n);
        (!matches!(n, b"logger" | b"log")).then_some(name)
    })
}

fn log_without_exception<'t>(catch: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut cursor = catch.walk();
    let name = catch
        .named_children(&mut cursor)
        .find(|c| c.kind() == "catch_declaration")
        .and_then(|d| d.child_by_field_name("name"))
        .map(|n| text(n, src))?;
    let body = catch.child_by_field_name("body")?;
    // Only when no log call in the block passes the exception.
    let is_log = |n: Node| n.kind() == "invocation_expression" && log_template(n, src).is_some();
    let passes_it = |n: Node| {
        cs_call_arguments(n)
            .iter()
            .any(|a| count_word(text(*a, src), name) > 0)
    };
    if find_in_scope(body, CS_SCOPE_STOPS, |n| is_log(n) && passes_it(n)).is_some() {
        return None;
    }
    find_in_scope(body, CS_SCOPE_STOPS, is_log)
}

fn arguments_out_of_order<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let template = log_template(call, src)?;
    let names = template_placeholders(cs_string_value(template, src)?).ok()?;
    let args = cs_call_arguments(call);
    let position = args.iter().position(|a| *a == template)?;
    let values: Vec<Vec<u8>> = args[position + 1..]
        .iter()
        .map(|a| text(*a, src).to_ascii_lowercase())
        .collect();
    if values.len() != names.len() || values.len() < 2 {
        return None;
    }
    let lower: Vec<Vec<u8>> = names.iter().map(|n| n.to_ascii_lowercase()).collect();
    // Every argument is a plain name matching some placeholder, and at least
    // one sits at another placeholder's position.
    let all_named = values.iter().all(|v| lower.contains(v));
    let misplaced = values.iter().zip(&lower).any(|(v, n)| v != n);
    (all_named && misplaced).then_some(template)
}

fn absolute_action_route<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if route_templates(class, src).is_empty() {
        return None;
    }
    actions(class, src).into_iter().find_map(|a| {
        route_templates(a, src).into_iter().find(|t| {
            cs_string_value(*t, src).is_some_and(|v| v.starts_with(b"/") || v.starts_with(b"~/"))
        })
    })
}

fn is_controller(class: Node, src: &[u8]) -> bool {
    base_names(class, src)
        .iter()
        .any(|b| matches!(*b, b"Controller" | b"ControllerBase"))
}

fn controller_without_route<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !is_controller(class, src) || !route_templates(class, src).is_empty() {
        return None;
    }
    // Two or more actions with templates that share their first segment.
    let firsts: Vec<Vec<u8>> = actions(class, src)
        .into_iter()
        .flat_map(|a| route_templates(a, src))
        .filter_map(|t| {
            cs_string_value(t, src)
                .map(|v| v.split(|&b| b == b'/').next().unwrap_or_default().to_vec())
        })
        .filter(|s| !s.is_empty() && !s.starts_with(b"{"))
        .collect();
    let shared = firsts.len() >= 2 && firsts.iter().all(|f| *f == firsts[0]);
    let single = firsts.len() == 1 && actions(class, src).len() == 1;
    (shared || single).then(|| class.child_by_field_name("name"))?
}

fn api_controller_with_views<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    (is_api_controller(class, src)
        && base_names(class, src).contains(&&b"Controller"[..])
        // Views mean it really is an MVC controller.
        && !contains_ignoring_case(text(class, src), b"View("))
    .then(|| class.child_by_field_name("name"))?
}

fn created_in_a_method(creation: Node, src: &[u8]) -> bool {
    // A field initializer creates one shared client, and a factory lambda
    // registered with dependency injection (`services.AddScoped(sp => new
    // HttpClient { ... })`, the Blazor WebAssembly template) lets the container
    // decide its lifetime.
    let mut current = creation.parent();
    for _ in 0..64 {
        let Some(n) = current else {
            return false;
        };
        match n.kind() {
            "field_declaration" | "property_declaration" => return false,
            "lambda_expression"
                if n.parent()
                    .and_then(|a| a.parent())
                    .and_then(|l| l.parent())
                    .and_then(|c| c.child_by_field_name("function"))
                    .and_then(|f| f.child_by_field_name("name"))
                    .is_some_and(|m| text(m, src).starts_with(b"Add")) =>
            {
                return false;
            }
            "method_declaration"
            | "local_function_statement"
            | "lambda_expression"
            | "accessor_declaration"
            | "global_statement" => return true,
            _ => current = n.parent(),
        }
    }
    false
}

fn action_without_verb<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !is_api_controller(class, src) {
        return None;
    }
    actions(class, src)
        .into_iter()
        .find(|a| !has_attribute(*a, HTTP_VERBS, src) && !has_attribute(*a, &[b"Route"], src))
        .and_then(|a| a.child_by_field_name("name"))
}

fn undescribed_action<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !is_api_controller(class, src) || has_attribute(class, &[b"ProducesResponseType"], src) {
        return None;
    }
    actions(class, src).into_iter().find_map(|a| {
        let returns = text(a.child_by_field_name("returns")?, src);
        let untyped = matches!(
            returns,
            b"IActionResult"
                | b"ActionResult"
                | b"Task<IActionResult>"
                | b"Task<ActionResult>"
                | b"ValueTask<IActionResult>"
                | b"IResult"
                | b"Task<IResult>"
        );
        (untyped && !has_attribute(a, &[b"ProducesResponseType", b"Produces"], src))
            .then(|| a.child_by_field_name("name"))?
    })
}

#[cfg(test)]
mod tests {
    use super::super::cs::tests::flagged;
    use super::is_pascal_case;

    fn method(body: &str) -> String {
        format!("namespace N;\nclass A {{\nvoid F() {{\n{body}\n}}\n}}\n")
    }

    #[test]
    fn pascal_case() {
        for ok in [
            "HtmlParser",
            "IOStream",
            "DbContext",
            "Xml",
            "A",
            "OrderID",
            "UIElement",
        ] {
            assert!(is_pascal_case(ok.as_bytes()), "{ok}");
        }
        for bad in ["HTMLParser", "htmlParser", "Html_Parser", "XMLHttp", "SQL"] {
            assert!(!is_pascal_case(bad.as_bytes()), "{bad}");
        }
        let src = "namespace N;\nclass HTMLParser { }\ninterface Store { }\ninterface IStore { }\nenum color { }\nclass Ok { }\n[TestClass] class Given_a_cart { [TestMethod] public void T() { } }";
        assert_eq!(flagged("cs/type-name-pascal-case", src), [2, 3, 5]);
    }

    #[test]
    fn sql_and_threads() {
        let src = method(
            "q = \"SELECT id, name\" + \"FROM users\";\nq = \"SELECT * \" + \"FROM users\";\nq = \"SELECT *\" + \"FROM users\";\nq = \"Hello\" + \"World\";\nq = $\"UPDATE t SET a = {a}\" + \"WHERE id = 1\";\nworker.Suspend();\nmyThread.Resume();\ngame.Resume();",
        );
        let typed = "namespace N;\nclass A { void F(Thread worker, Game game) { worker.Suspend(); game.Resume(); } }";
        assert_eq!(flagged("cs/thread-suspend-resume", typed), [2]);
        assert_eq!(flagged("cs/sql-keyword-spacing", &src), [4, 8]);
        assert_eq!(flagged("cs/thread-suspend-resume", &src), [10]);
    }

    #[test]
    fn attributes() {
        let src = "namespace N;\nstatic class P { static void Main() { Application.Run(new F()); } }\nstatic class Q { [STAThread] static void Main() { Application.Run(new F()); } }\n[PartCreationPolicy(CreationPolicy.Shared)] class C1 { }\n[Export, PartCreationPolicy(CreationPolicy.Shared)] class C2 { }\nclass E { public E(string path) { } [ConstructorArgument(\"file\")] public string P1 { get; set; } [ConstructorArgument(\"path\")] public string P2 { get; set; } }\n[Export(typeof(IStore))] class X1 { }\n[Export(typeof(IStore))] class X2 : IStore { }\nclass J { [JSInvokable] void A() { } [JSInvokable] public void B() { } }\nclass R : Controller { [Route(\"a\\\\b\")] public IActionResult G() => Ok(); }";
        assert_eq!(flagged("cs/winforms-main-without-stathread", src), [2]);
        assert_eq!(flagged("cs/part-creation-policy-without-export", src), [4]);
        assert_eq!(flagged("cs/constructor-argument-missing", src), [6]);
        assert_eq!(flagged("cs/export-type-not-implemented", src), [7]);
        assert_eq!(flagged("cs/jsinvokable-not-public", src), [9]);
        assert_eq!(flagged("cs/route-backslash", src), [10]);
    }

    #[test]
    fn literals_assignments_keywords() {
        let src = "namespace N;\nclass A {\nlong a = 100l;\nlong b = 100L;\nulong c = 5ul;\nvoid F(int await) {\nif ((x = G()) > 0) { }\nx = y = 0;\nwhile ((line = r.ReadLine()) != null) { }\nvar o = new P { X = 1 };\nint var = 1;\n}\n}";
        assert_eq!(flagged("cs/literal-suffix-case", src), [3, 5]);
        assert_eq!(flagged("cs/assignment-in-subexpression", src), [7]);
        assert_eq!(flagged("cs/contextual-keyword-name", src), [6, 11]);
    }

    #[test]
    fn class_design() {
        let src = "namespace N;\nstruct M : IComparable<M> { public int CompareTo(M o) => 0; }\nstruct K : IComparable<K> { public int CompareTo(K o) => 0; public static bool operator <(K a, K b) => true; public static bool operator >(K a, K b) => true; }\nclass T { private int count; public int Count { get { return count; } set { count = value; } } private int n; public int N { get => n; set => n = value; } void Reset() { n = 0; } }\n[Flags] enum Permission { None = 0 }\n[Flags] enum Permissions { None = 0 }\nclass L { List<int> items = new(); public int[] Items => items.ToArray(); public List<int> Copy { get { return new List<int>(items); } } public IReadOnlyList<int> View => items; }";
        assert_eq!(flagged("cs/icomparable-without-operators", src), [2]);
        assert_eq!(flagged("cs/trivial-property", src), [4]);
        assert_eq!(flagged("cs/flags-enum-name-plural", src), [5]);
        assert_eq!(flagged("cs/property-copies-collection", src), [7, 7]);
    }

    #[test]
    fn indentation() {
        let src = "namespace N;\nclass A {\nvoid F(bool b) {\n    if (b)\n        G();\n        H();\n    if (b)\n        G();\n    H();\n    if (b) G();\n    H();\n}\n}";
        assert_eq!(flagged("cs/multiline-without-braces", src), [6]);
    }

    #[test]
    fn statics() {
        let src = "namespace N;\nclass A {\nstatic int count;\nstatic readonly int max = 1;\n[ThreadStatic] static int depth;\nint own;\nvoid Hit() { count++; own = 1; depth = 2; }\nstatic void S() { count = 0; }\npublic A(int c) { count = c; }\nint P { set { count = value; } }\n}\nclass B { static int x; static int y; static B() { x = 1; y = 2; } }\nclass C { static int x; static C() { x = Compute(); Log(); } }";
        assert_eq!(flagged("cs/instance-writes-static", src), [7, 10]);
        assert_eq!(flagged("cs/static-field-set-in-constructor", src), [9]);
        assert_eq!(flagged("cs/static-constructor-only-initializes", src), [12]);
    }

    #[test]
    fn nested_classes_events_methods() {
        let src = "namespace N;\nclass Outer {\nprivate class A { }\nprivate class B { }\nprivate class C : B { }\nprivate sealed class D { }\npublic class E { }\npublic event EventHandler Used;\npublic event EventHandler Unused;\nvoid R() { Used?.Invoke(this, EventArgs.Empty); Used?.Invoke(null, EventArgs.Empty); Used.Invoke(this, null); }\nvoid F() { G(); H(); }\nvoid K() { G(); H(); }\nvoid M(int a) { G(); H(); }\n[DllImport(\"x\")] public static extern int Run();\n[DllImport(\"x\")] static extern int Hidden();\n}";
        assert_eq!(flagged("cs/private-class-not-sealed", src), [3, 5]);
        assert_eq!(flagged("cs/event-never-used", src), [9]);
        assert_eq!(flagged("cs/event-args-null", src), [10]);
        assert_eq!(flagged("cs/identical-methods", src), [12]);
        assert_eq!(flagged("cs/public-extern", src), [14]);
    }

    #[test]
    fn expressions() {
        let src = method(
            "b = o != null && o is string;\nb = o != null && o is string s;\nb = p != null && o is string;\nt = DateTime.Now - start;\nt = DateTime.UtcNow - start;\nt = end - start;\nTrace.WriteLine(\"x\");\nTrace.TraceInformation(\"x\");",
        );
        assert_eq!(flagged("cs/null-check-before-is", &src), [4, 5]);
        assert_eq!(flagged("cs/datetime-now-benchmark", &src), [7, 8]);
        assert_eq!(flagged("cs/trace-write", &src), [10]);
    }

    #[test]
    fn logging() {
        let src = "namespace N;\nclass A {\nprivate readonly ILogger<A> output;\nprivate readonly ILogger<A> _logger;\nprivate static ILogger Log;\nprivate readonly Logger _output;\nvoid F(int from, int to) {\ntry { G(); } catch (IOException e) { _logger.LogError(\"failed\"); }\ntry { G(); } catch (IOException e) { _logger.LogError(e, \"failed\"); }\ntry { G(); } catch (IOException e) { _logger.LogWarning(\"failed {Message}\", e.Message); }\n_logger.LogInformation(\"Moved {From} to {To}\", to, from);\n_logger.LogInformation(\"Moved {From} to {To}\", from, to);\n_logger.LogInformation(\"Moved {From} to {To}\", a.X, from);\n}\n}";
        assert_eq!(flagged("cs/logger-field-name", src), [3]);
        assert_eq!(flagged("cs/log-exception-not-passed", src), [8]);
        assert_eq!(flagged("cs/log-template-argument-order", src), [11]);
    }

    #[test]
    fn idioms_left_alone() {
        let src = "namespace N;\nclass A {\nList<int> cache;\nList<int> Get() { return cache ??= new(); }\nvoid F(IServiceCollection s) {\nvar record = 1;\ns.AddScoped(sp => new HttpClient { BaseAddress = u });\n}\n}";
        assert!(flagged("cs/assignment-in-subexpression", src).is_empty());
        assert!(flagged("cs/contextual-keyword-name", src).is_empty());
        assert!(flagged("cs/new-httpclient", src).is_empty());
    }

    #[test]
    fn aspnet() {
        let src = "namespace N;\n[Route(\"api/orders\")] class C1 : ControllerBase { [HttpGet(\"/all\")] public IActionResult All() => Ok(); [HttpGet(\"{id}\")] public ActionResult<int> One(int id) => 1; }\nclass C2Controller : Controller { [HttpGet(\"orders/{id}\")] public IActionResult Get(int id) => Ok(); [HttpPost(\"orders\")] public IActionResult Post() => Ok(); }\n[ApiController] class C3 : Controller { [HttpGet] public IActionResult List() => Ok(); public IActionResult NoVerb() => Ok(); [NonAction] public void Helper() { } }\n[ApiController, ProducesResponseType(200)] class C4 : ControllerBase { [HttpGet] public IActionResult A() => Ok(); }\nclass H { static readonly HttpClient Shared = new HttpClient(); async Task F() { using var c = new HttpClient(); } }";
        assert_eq!(flagged("cs/action-route-leading-slash", src), [2]);
        assert_eq!(flagged("cs/controller-route-missing", src), [3]);
        assert_eq!(flagged("cs/api-controller-derives-controller", src), [4]);
        assert_eq!(flagged("cs/action-without-http-verb", src), [4]);
        assert_eq!(flagged("cs/produces-response-type-missing", src), [4]);
        assert_eq!(flagged("cs/new-httpclient", src), [6]);
    }
}
