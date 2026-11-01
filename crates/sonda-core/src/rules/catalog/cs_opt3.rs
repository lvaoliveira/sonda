//! C# rules outside SonarQube's default profile, batch 10 (ADR-0007,
//! ADR-0015): size and coupling, visibility, interop, disposal, Azure
//! Functions and collection methods. Every rule here is off unless
//! `rules.enabled` lists it. Queries stay cheap on deep trees: see the notes
//! in `js_modern.rs`.

use super::cs::{cs_has_modifier, cs_statements, cs_string_value, simple_name, squeezed};
use super::cs_bugs::{attribute_names, cs_call_arguments};
use super::cs_final::is_azure_function;
use super::cs_more::{declarators, declared_type, members};
use super::cs_opt2::{
    enclosing_method, has_parameter_modifier, is_type_parameter_name, may_implement_contract,
};
use super::cs_types::{is_generic, type_of_name, walk_tree};
use super::java_bugs::{find_in_scope, operator_text};
use super::java_last::count_nodes;
use super::java_security::{contains_ignoring_case, text};
use super::java_smells::count_word;
use super::*;
use crate::semantic::Model;

/// Rules that are off unless `rules.enabled` lists them (see
/// `catalog::OFF_BY_DEFAULT`): all of this module's.
pub(super) static OFF_BY_DEFAULT: &[&str] = &[
    "cs/unnecessary-using",
    "cs/class-coupling",
    "cs/method-complexity",
    "cs/mergeable-try",
    "cs/array-covariance",
    "cs/redundant-modifier",
    "cs/field-disposed-outside-dispose",
    "cs/member-more-visible-than-type",
    "cs/interface-downcast",
    "cs/event-handler-signature",
    "cs/string-uri-overload-not-delegating",
    "cs/visible-pointer-field",
    "cs/disposable-handle-without-finalizer",
    "cs/field-differs-from-base-by-case",
    "cs/explicit-implementation-hidden",
    "cs/culture-overload",
    "cs/data-table-locale",
    "cs/extension-in-same-namespace",
    "cs/azure-function-without-try",
    "cs/azure-function-catch-not-logged",
    "cs/use-list-find",
    "cs/use-list-true-for-all",
    "cs/use-list-exists",
];

pub(super) static RULES: &[Rule] = &[
    // ---- Bugs ----
    Rule {
        id: "cs/field-disposed-outside-dispose",
        name: "Fields should be disposed of in the class's own Dispose method",
        description: "Dispose is where callers expect a class to clean up; disposing of a field from another \
                      method leaks it whenever that method isn't called.",
        message: "Dispose of this field in the class's Dispose method.",
        category: Bug,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S2952")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration (base_list) body: (declaration_list)) @match",
            filter: Some(Find(field_disposed_elsewhere)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class Holder : IDisposable { FileStream fs; public void CleanUp() { fs.Dispose(); } public void Dispose() { } }",
            good: "class Holder : IDisposable { FileStream fs; public void Dispose() { fs.Dispose(); } }",
        }),
    },
    // ---- Code smells ----
    Rule {
        id: "cs/unnecessary-using",
        name: "Unnecessary using directives should be removed",
        description: "A repeated using directive, or one for the namespace the code is already in, imports \
                      nothing.",
        message: "Remove this unnecessary using directive.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[related("S1128")],
        check: Check::Query {
            langs: CSHARP,
            query: "(using_directive) @match",
            filter: Some(Keep(is_unnecessary_using)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "using System;\nusing System;\nclass A { }",
            good: "using System;\nclass A { }",
        }),
    },
    Rule {
        id: "cs/class-coupling",
        name: "Classes should not depend on too many other types",
        description: "A class that uses dozens of types likely has more than one responsibility.",
        message: "Split this class: it depends on more than 30 other types.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 60,
        sonar: &[exact("S1200")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration name: (identifier) @match body: (declaration_list))",
            filter: Some(Keep(depends_on_many_types)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { Dep1 a1; Dep2 a2; Dep3 a3; Dep4 a4; Dep5 a5; Dep6 a6; Dep7 a7; Dep8 a8; Dep9 a9; Dep10 a10; Dep11 a11; Dep12 a12; Dep13 a13; Dep14 a14; Dep15 a15; Dep16 a16; Dep17 a17; Dep18 a18; Dep19 a19; Dep20 a20; Dep21 a21; Dep22 a22; Dep23 a23; Dep24 a24; Dep25 a25; Dep26 a26; Dep27 a27; Dep28 a28; Dep29 a29; Dep30 a30; Dep31 a31; }",
            good: "class A { Dep1 a1; }",
        }),
    },
    Rule {
        id: "cs/method-complexity",
        name: "Methods and properties should not be too complex",
        description: "Every branch is another path to understand and test; past 10 the code is hard to \
                      follow.",
        message: "Split this: its cyclomatic complexity is over 10.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 20,
        sonar: &[exact("S1541")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(method_declaration body: (_)) (constructor_declaration body: (_)) (accessor_declaration body: (_)) \
                     (local_function_statement body: (_)) (operator_declaration body: (_))] @match",
            filter: Some(Find(too_complex)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(int a) { if (a == 1) {} if (a == 2) {} if (a == 3) {} if (a == 4) {} if (a == 5) {} if (a == 6) {} if (a == 7) {} if (a == 8) {} if (a == 9) {} if (a == 10) {} } }",
            good: "class A { void F(int a) { if (a == 1) {} } }",
        }),
    },
    Rule {
        id: "cs/mergeable-try",
        name: "Consecutive try statements with the same handlers should be merged",
        description: "Two try statements in a row that catch and clean up the same way are one try statement \
                      written twice.",
        message: "Merge this try statement with the previous one.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2327")],
        check: Check::Query {
            langs: CSHARP,
            query: "(try_statement) @match",
            filter: Some(Keep(same_handlers_as_previous)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F() { try { G(); } catch (IOException e) { Log(e); } try { H(); } catch (IOException e) { Log(e); } } }",
            good: "class A { void F() { try { G(); H(); } catch (IOException e) { Log(e); } } }",
        }),
    },
    Rule {
        id: "cs/array-covariance",
        name: "Array covariance should not be used",
        description: "An `object[]` that holds a `string[]` compiles, but storing anything but a string in it \
                      throws ArrayTypeMismatchException at run time.",
        message: "Create an array of the declared element type.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S2330")],
        check: Check::Query {
            langs: CSHARP,
            query: "(variable_declarator (array_creation_expression type: (array_type)) @match)",
            filter: Some(Keep(covariant_array)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { object[] items = new string[3]; }",
            good: "class A { object[] items = new object[3]; }",
        }),
    },
    Rule {
        id: "cs/redundant-modifier",
        name: "Redundant modifiers should not be used",
        description: "`sealed` on a member of a sealed class and `unsafe` inside an unsafe type change nothing.",
        message: "Remove this redundant modifier.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[related("S2333")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(class_declaration (modifier) body: (declaration_list)) (struct_declaration (modifier) body: (declaration_list))] @match",
            filter: Some(Find(redundant_member_modifier)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "sealed class B : A { public sealed override void F() { } }",
            good: "sealed class B : A { public override void F() { } }",
        }),
    },
    Rule {
        id: "cs/member-more-visible-than-type",
        name: "Members should not be more visible than their type",
        description: "A public member of an internal type is no more reachable than an internal one; the \
                      modifier only misleads.",
        message: "Lower this member's visibility to the type's.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S3059")],
        check: Check::Query {
            langs: CSHARP,
            query: "(declaration_list [(method_declaration) (field_declaration) (property_declaration) (event_field_declaration) \
                     (class_declaration) (struct_declaration) (record_declaration) (enum_declaration) (interface_declaration)] @match)",
            filter: Some(Find(public_in_hidden_type)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "internal class Counter { public int GetOne() => 1; }",
            good: "internal class Counter { internal int GetOne() => 1; }",
        }),
    },
    Rule {
        id: "cs/interface-downcast",
        name: "Interface references should not be cast to concrete types",
        description: "Casting an interface to a class means the interface is missing something, and the cast \
                      fails for every other implementation.",
        message: "Add what you need to the interface instead of casting.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 15,
        sonar: &[related("S3215")],
        check: Check::Semantic {
            langs: CSHARP,
            find: downcasts_interface,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int F(IShape s) { var c = (Circle)s; return c.Radius; } }",
            good: "class A { int F(IShape s) { return s.Size; } }",
        }),
    },
    Rule {
        id: "cs/event-handler-signature",
        name: "Events should use the (sender, args) handler signature",
        description: "Handlers that take (object sender, TEventArgs e) can be shared and extended; an \
                      Action or Func event can't add data later without breaking subscribers.",
        message: "Declare this event as EventHandler or EventHandler<TEventArgs>.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[related("S3906")],
        check: Check::Query {
            langs: CSHARP,
            query: "(event_field_declaration (variable_declaration type: (_) @match))",
            filter: Some(Keep(is_action_or_func)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { public event Action<int> Changed; }",
            good: "class A { public event EventHandler<ChangedEventArgs> Changed; }",
        }),
    },
    Rule {
        id: "cs/string-uri-overload-not-delegating",
        name: "String URI overloads should call the System.Uri overload",
        description: "When a method has string and Uri overloads, the string one should only convert and \
                      delegate, so the parsing and validation live in one place.",
        message: "Call the System.Uri overload from this one.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3997")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(class_declaration body: (declaration_list)) (struct_declaration body: (declaration_list))] @match",
            filter: Some(Find(string_overload_not_delegating)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { public void Fetch(string uri) { Download(uri); } public void Fetch(Uri uri) { } }",
            good: "class A { public void Fetch(string uri) { Fetch(new Uri(uri)); } public void Fetch(Uri uri) { } }",
        }),
    },
    Rule {
        id: "cs/visible-pointer-field",
        name: "Pointers to unmanaged memory should not be visible",
        description: "A public or protected writable IntPtr or pointer field lets any caller point the class \
                      at arbitrary memory.",
        message: "Make this field private, internal or readonly.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S4000")],
        check: Check::Query {
            langs: CSHARP,
            query: "(field_declaration (modifier) (variable_declaration type: (_) @match))",
            filter: Some(Keep(visible_pointer_field)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "public class Native { public IntPtr Handle; }",
            good: "public class Native { private IntPtr handle; }",
        }),
    },
    Rule {
        id: "cs/disposable-handle-without-finalizer",
        name: "Disposable types holding native handles should have finalizers",
        description: "If callers forget Dispose, only a finalizer releases the native resource behind an IntPtr \
                      field.",
        message: "Add a finalizer that releases the native handle, or wrap it in a SafeHandle.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 15,
        sonar: &[exact("S4002")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration name: (identifier) @match (base_list) body: (declaration_list))",
            filter: Some(Keep(handle_without_finalizer)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class Native : IDisposable { private IntPtr handle; public void Dispose() { Free(handle); } }",
            good: "class Native : IDisposable { private IntPtr handle; ~Native() { Free(handle); } public void Dispose() { Free(handle); GC.SuppressFinalize(this); } }",
        }),
    },
    Rule {
        id: "cs/field-differs-from-base-by-case",
        name: "Fields should not differ from base class fields only by case",
        description: "`plantingseason` next to an inherited `plantingSeason` is bound to be confused with it.",
        message: "Rename this field; it differs from a base class field only by case.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[related("S4025")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration (base_list) body: (declaration_list)) @match",
            filter: Some(Find(field_shadowed_by_case)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class Fruit { protected string plantingSeason; }\nclass Raspberry : Fruit { protected string plantingseason; }",
            good: "class Fruit { protected string plantingSeason; }\nclass Raspberry : Fruit { protected string whenToPlant; }",
        }),
    },
    Rule {
        id: "cs/explicit-implementation-hidden",
        name: "Explicit interface implementations should be reachable from derived types",
        description: "A derived class can only call an explicit interface member through the interface, and \
                      loses it entirely if it re-implements the member.",
        message: "Add a protected or public member with the same name, or seal the class.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S4039")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration (modifier) (base_list) body: (declaration_list)) @match",
            filter: Some(Find(hidden_explicit_implementation)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "public class Store : IStore { void IStore.Save() { } }",
            good: "public class Store : IStore { void IStore.Save() => Save(); protected void Save() { } }",
        }),
    },
    Rule {
        id: "cs/culture-overload",
        name: "Formatting should state its culture",
        description: "string.Format and ToString(format) without an IFormatProvider use the current culture, so \
                      the output changes from machine to machine.",
        message: "Pass a CultureInfo or IFormatProvider.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[related("S4056")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(invocation_expression function: (member_access_expression name: (identifier) @n)
                        (#any-of? @n "Format" "ToString")) @match"#,
            filter: Some(Keep(formats_without_culture)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { string F(decimal d) { return string.Format(\"{0:N2}\", d); } }",
            good: "class A { string F(decimal d) { return string.Format(CultureInfo.InvariantCulture, \"{0:N2}\", d); } }",
        }),
    },
    Rule {
        id: "cs/data-table-locale",
        name: "DataTable and DataSet locales should be set",
        description: "They default to the current culture, so sorting and comparing shared data changes from \
                      machine to machine.",
        message: "Set this DataTable's or DataSet's Locale.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S4057")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(object_creation_expression type: (identifier) @t (#any-of? @t "DataTable" "DataSet")) @match"#,
            filter: Some(Keep(locale_not_set)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { DataTable F() { var t = new DataTable(\"Customers\"); return t; } }",
            good: "class A { DataTable F() { var t = new DataTable(\"Customers\"); t.Locale = CultureInfo.InvariantCulture; return t; } }",
        }),
    },
    Rule {
        id: "cs/extension-in-same-namespace",
        name: "Extension methods should not be in the namespace of the type they extend",
        description: "An extension next to the type it extends could simply be a method of that type.",
        message: "Move this method into the type, or the extension into its own namespace.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[related("S4226")],
        check: Check::Query {
            langs: CSHARP,
            query: "(method_declaration (modifier) parameters: (parameter_list . (parameter (modifier) type: (_) @match)))",
            filter: Some(Keep(extends_neighbour_type)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "namespace Shop { class Order { } static class OrderExtensions { public static int Total(this Order o) => 0; } }",
            good: "namespace Shop { class Order { public int Total() => 0; } }",
        }),
    },
    Rule {
        id: "cs/azure-function-without-try",
        name: "Azure Functions should handle errors at the top level",
        description: "A function whose body isn't in a try/catch lets failures escape unlogged, which makes \
                      the app's health hard to monitor.",
        message: "Wrap this function's body in try/catch, log, and rethrow what should be retried.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S6421")],
        check: Check::Query {
            langs: CSHARP,
            query: "(method_declaration name: (identifier) @match body: (_))",
            filter: Some(Keep(function_without_try)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class F { [FunctionName(\"Run\")] public async Task Run(ILogger log) { await Work(); } }",
            good: "class F { [FunctionName(\"Run\")] public async Task Run(ILogger log) { try { await Work(); } catch (Exception e) { log.LogError(e, \"Run failed\"); throw; } } }",
        }),
    },
    Rule {
        id: "cs/azure-function-catch-not-logged",
        name: "Azure Functions should log the failures they catch",
        description: "A failure caught without being logged (at Information level or above) never shows up in \
                      monitoring.",
        message: "Log this failure.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6423")],
        check: Check::Query {
            langs: CSHARP,
            query: "(method_declaration body: (block)) @match",
            filter: Some(Find(function_catch_without_log)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class F { [FunctionName(\"Run\")] public async Task Run(ILogger log) { try { await Work(); } catch (Exception e) { throw; } } }",
            good: "class F { [FunctionName(\"Run\")] public async Task Run(ILogger log) { try { await Work(); } catch (Exception e) { log.LogError(e, \"Run failed\"); throw; } } }",
        }),
    },
    Rule {
        id: "cs/use-list-find",
        name: "List<T>.Find should be used instead of FirstOrDefault",
        description: "List<T>.Find does the same without LINQ's enumerator, and is faster.",
        message: "Use Find instead of FirstOrDefault.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[related("S6602")],
        check: Check::Semantic {
            langs: CSHARP,
            find: use_list_find,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int F(List<int> xs) { return xs.FirstOrDefault(x => x > 1); } }",
            good: "class A { int F(List<int> xs) { return xs.Find(x => x > 1); } }",
        }),
    },
    Rule {
        id: "cs/use-list-true-for-all",
        name: "List<T>.TrueForAll should be used instead of All",
        description: "List<T>.TrueForAll does the same without LINQ's enumerator, and is faster.",
        message: "Use TrueForAll instead of All.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[related("S6603")],
        check: Check::Semantic {
            langs: CSHARP,
            find: use_list_true_for_all,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { bool F(List<int> xs) { return xs.All(x => x > 1); } }",
            good: "class A { bool F(List<int> xs) { return xs.TrueForAll(x => x > 1); } }",
        }),
    },
    Rule {
        id: "cs/use-list-exists",
        name: "List<T>.Exists should be used instead of Any",
        description: "List<T>.Exists does the same without LINQ's enumerator, and is faster.",
        message: "Use Exists instead of Any.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[related("S6605")],
        check: Check::Semantic {
            langs: CSHARP,
            find: use_list_exists,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { bool F(List<int> xs) { return xs.Any(x => x > 1); } }",
            good: "class A { bool F(List<int> xs) { return xs.Exists(x => x > 1); } }",
        }),
    },
];

// ---------------------------------------------------- filters

fn has_base(declaration: Node, src: &[u8], name: &[u8]) -> bool {
    let mut cursor = declaration.walk();
    declaration
        .named_children(&mut cursor)
        .filter(|c| c.kind() == "base_list")
        .any(|b| count_word(text(b, src), name) > 0)
}

fn field_names<'s>(class: Node, src: &'s [u8]) -> Vec<&'s [u8]> {
    members(class)
        .into_iter()
        .filter(|m| m.kind() == "field_declaration")
        .flat_map(declarators)
        .filter_map(|d| d.child_by_field_name("name").map(|n| text(n, src)))
        .collect()
}

fn field_disposed_elsewhere<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !has_base(class, src, b"IDisposable") && !has_base(class, src, b"IAsyncDisposable") {
        return None;
    }
    let fields = field_names(class, src);
    if fields.is_empty() {
        return None;
    }
    members(class)
        .into_iter()
        .filter(|m| m.kind() == "method_declaration")
        .find_map(|m| {
            let name = text(m.child_by_field_name("name")?, src);
            if contains_ignoring_case(name, b"Dispose") || name == b"Close" {
                return None;
            }
            let body = m.child_by_field_name("body")?;
            find_in_scope(body, &[], |n| {
                let Some(field) = disposed_receiver(n, src).filter(|f| fields.contains(f)) else {
                    return false;
                };
                // `old?.Dispose(); old = new Timer();` replaces the resource.
                let replaced = find_in_scope(body, &[], |a| {
                    a.kind() == "assignment_expression"
                        && a.start_byte() > n.end_byte()
                        && a.child_by_field_name("left")
                            .is_some_and(|l| simple_name(l, src) == field)
                });
                replaced.is_none()
            })
        })
}

/// `f.Dispose()`, `this.f.Dispose()` or `f?.Dispose()`: the receiver's name.
fn disposed_receiver<'s>(call: Node, src: &'s [u8]) -> Option<&'s [u8]> {
    if call.kind() != "invocation_expression" || !cs_call_arguments(call).is_empty() {
        return None;
    }
    let function = call.child_by_field_name("function")?;
    match function.kind() {
        "member_access_expression" => (text(function.child_by_field_name("name")?, src)
            == b"Dispose")
            .then(|| function.child_by_field_name("expression"))
            .flatten()
            .map(|r| simple_name(r, src)),
        "conditional_access_expression" => {
            let mut cursor = function.walk();
            let binding = function
                .named_children(&mut cursor)
                .find(|c| c.kind() == "member_binding_expression")?;
            (text(binding.child_by_field_name("name")?, src) == b"Dispose")
                .then(|| function.child_by_field_name("condition"))
                .flatten()
                .map(|r| simple_name(r, src))
        }
        _ => None,
    }
}

fn file_namespaces<'s>(using: Node, src: &'s [u8]) -> Vec<&'s [u8]> {
    // Block namespaces around the directive, and a file-scoped one.
    let mut names = Vec::new();
    let mut current = using.parent();
    while let Some(n) = current {
        if n.kind() == "namespace_declaration"
            && let Some(name) = n.child_by_field_name("name")
        {
            names.push(text(name, src));
        }
        if n.kind() == "compilation_unit" {
            let mut cursor = n.walk();
            names.extend(
                n.named_children(&mut cursor)
                    .filter(|c| c.kind() == "file_scoped_namespace_declaration")
                    .filter_map(|c| c.child_by_field_name("name"))
                    .map(|c| text(c, src)),
            );
        }
        current = n.parent();
    }
    names
}

fn is_unnecessary_using(using: Node, src: &[u8]) -> bool {
    let t = text(using, src);
    // Aliases, static and global usings do more than import a namespace.
    if using.child_by_field_name("name").is_some()
        || t.starts_with(b"global")
        || count_word(t, b"static") > 0
    {
        return false;
    }
    let Some(imported) = using.named_child(0).map(|n| text(n, src)) else {
        return false;
    };
    let mut previous = using.prev_named_sibling();
    while let Some(p) = previous.filter(|p| p.kind() == "using_directive") {
        if squeezed(p, src) == squeezed(using, src) {
            return true;
        }
        previous = p.prev_named_sibling();
    }
    // The current namespace and its parents are already in scope.
    file_namespaces(using, src).iter().any(|ns| {
        *ns == imported || (ns.starts_with(imported) && ns.get(imported.len()) == Some(&b'.'))
    })
}

const TRIVIAL_TYPES: &[&[u8]] = &[
    b"String",
    b"Object",
    b"Task",
    b"ValueTask",
    b"Func",
    b"Action",
    b"Nullable",
    b"var",
    b"dynamic",
];

fn collect_types<'s>(ty: Node, src: &'s [u8], into: &mut Vec<&'s [u8]>) {
    match ty.kind() {
        "identifier" | "qualified_name" => {
            let name = simple_name(ty, src);
            if !TRIVIAL_TYPES.contains(&name)
                && !is_type_parameter_name(name)
                && !into.contains(&name)
            {
                into.push(name);
            }
        }
        "predefined_type" | "implicit_type" => {}
        _ => {
            let mut cursor = ty.walk();
            for child in ty.named_children(&mut cursor) {
                collect_types(child, src, into);
            }
        }
    }
}

fn depends_on_many_types(name: Node, src: &[u8]) -> bool {
    let Some(class) = name.parent() else {
        return false;
    };
    let own = text(name, src);
    let mut seen: Vec<&[u8]> = Vec::new();
    // Nested types' dependencies are theirs, not the outer class's.
    let stops = [
        "class_declaration",
        "struct_declaration",
        "record_declaration",
        "interface_declaration",
    ];
    let mut stack = vec![class];
    while let Some(n) = stack.pop() {
        for field in ["type", "returns"] {
            if let Some(t) = n.child_by_field_name(field) {
                collect_types(t, src, &mut seen);
            }
        }
        let mut cursor = n.walk();
        for child in n.named_children(&mut cursor) {
            if child.kind() == "base_list" {
                collect_types(child, src, &mut seen);
            } else if !stops.contains(&child.kind()) {
                stack.push(child);
            }
        }
    }
    seen.iter().filter(|t| **t != own).count() > 30
}

fn too_complex<'t>(declaration: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let body = declaration.child_by_field_name("body")?;
    let branches = count_nodes(body, &["local_function_statement"], |n| match n.kind() {
        "if_statement"
        | "for_statement"
        | "foreach_statement"
        | "while_statement"
        | "do_statement"
        | "conditional_expression"
        | "conditional_access_expression"
        | "and_pattern"
        | "or_pattern" => true,
        "switch_expression_arm" => n.named_child(0).is_some_and(|p| p.kind() != "discard"),
        "binary_expression" => matches!(operator_text(n, src), b"&&" | b"||" | b"??"),
        // A `case` label: a pattern directly in a switch section.
        k if k.ends_with("pattern") => n.parent().is_some_and(|p| p.kind() == "switch_section"),
        _ => false,
    });
    (branches + 1 > 10).then(|| {
        declaration
            .child_by_field_name("name")
            .unwrap_or(declaration)
    })
}

fn catches_and_finally(try_statement: Node, src: &[u8]) -> Vec<Vec<u8>> {
    let mut cursor = try_statement.walk();
    try_statement
        .named_children(&mut cursor)
        .filter(|c| matches!(c.kind(), "catch_clause" | "finally_clause"))
        .map(|c| squeezed(c, src))
        .collect()
}

fn same_handlers_as_previous(try_statement: Node, src: &[u8]) -> bool {
    let Some(previous) = try_statement
        .prev_named_sibling()
        .filter(|p| p.kind() == "try_statement")
    else {
        return false;
    };
    let handlers = catches_and_finally(try_statement, src);
    !handlers.is_empty() && handlers == catches_and_finally(previous, src)
}

fn element_type(array_type: Node, src: &[u8]) -> Vec<u8> {
    let t = array_type
        .child_by_field_name("type")
        .map_or(&b""[..], |t| text(t, src));
    t.iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace() && *b != b'?')
        .collect()
}

fn covariant_array(creation: Node, src: &[u8]) -> bool {
    let Some(created) = creation.child_by_field_name("type") else {
        return false;
    };
    // declarator -> variable_declaration with the declared type.
    let declared = creation
        .parent()
        .and_then(|d| d.parent())
        .and_then(|v| v.child_by_field_name("type"))
        .filter(|t| t.kind() == "array_type");
    // Any other element type that compiles is a covariant reference.
    declared.is_some_and(|d| element_type(d, src) != element_type(created, src))
}

fn redundant_member_modifier<'t>(declaration: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let sealed = cs_has_modifier(declaration, "sealed", src);
    let unsafe_type = cs_has_modifier(declaration, "unsafe", src);
    if !sealed && !unsafe_type {
        return None;
    }
    members(declaration).into_iter().find_map(|m| {
        let mut cursor = m.walk();
        let modifiers: Vec<Node<'t>> = m
            .named_children(&mut cursor)
            .filter(|c| c.kind() == "modifier")
            .collect();
        let nested_type = matches!(
            m.kind(),
            "class_declaration"
                | "struct_declaration"
                | "record_declaration"
                | "interface_declaration"
        );
        modifiers.into_iter().find(|md| {
            let word = text(*md, src);
            (sealed && word == b"sealed" && !nested_type) || (unsafe_type && word == b"unsafe")
        })
    })
}

/// Public types inside public (or protected) types are visible outside the
/// assembly; anything else isn't.
fn externally_visible(declaration: Node, src: &[u8]) -> bool {
    let mut current = Some(declaration);
    let mut nested = false;
    while let Some(n) = current {
        if matches!(
            n.kind(),
            "class_declaration"
                | "struct_declaration"
                | "record_declaration"
                | "interface_declaration"
                | "enum_declaration"
        ) {
            let visible = cs_has_modifier(n, "public", src)
                || (nested && cs_has_modifier(n, "protected", src));
            if !visible && !(nested && n.kind() == "interface_declaration") {
                return false;
            }
        }
        if matches!(
            n.kind(),
            "compilation_unit" | "namespace_declaration" | "file_scoped_namespace_declaration"
        ) {
            return true;
        }
        nested = true;
        current = n.parent();
    }
    true
}

fn public_in_hidden_type<'t>(member: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut cursor = member.walk();
    let public = member
        .named_children(&mut cursor)
        .find(|c| c.kind() == "modifier" && text(*c, src) == b"public")?;
    let owner = member.parent()?.parent()?;
    if !matches!(
        owner.kind(),
        "class_declaration" | "struct_declaration" | "record_declaration"
    ) || externally_visible(owner, src)
    {
        return None;
    }
    // Overrides and interface implementations must stay public.
    let contract = member.kind() == "method_declaration" && may_implement_contract(member, src)
        || cs_has_modifier(member, "override", src)
        || (matches!(
            member.kind(),
            "property_declaration" | "event_field_declaration"
        ) && has_base_list(owner));
    (!contract).then_some(public)
}

fn has_base_list(declaration: Node) -> bool {
    let mut cursor = declaration.walk();
    declaration
        .named_children(&mut cursor)
        .any(|c| c.kind() == "base_list")
}

fn looks_like_interface(name: &[u8]) -> bool {
    name.len() > 1 && name[0] == b'I' && name[1].is_ascii_uppercase()
}

fn downcasts_interface<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let mut found = Vec::new();
    walk_tree(m, |node, _| {
        let (target, value) = match node.kind() {
            "cast_expression" => (
                node.child_by_field_name("type"),
                node.child_by_field_name("value"),
            ),
            "as_expression" => (
                node.child_by_field_name("right"),
                node.child_by_field_name("left"),
            ),
            _ => return,
        };
        let (Some(target), Some(value)) = (target, value) else {
            return;
        };
        if target.kind() != "identifier" || value.kind() != "identifier" {
            return;
        }
        let target = text(target, src);
        if looks_like_interface(target) || is_type_parameter_name(target) || target == b"Object" {
            return;
        }
        if type_of_name(m, value)
            .is_some_and(|t| t.kind() == "identifier" && looks_like_interface(text(t, src)))
        {
            found.push(node);
        }
    });
    found
}

fn is_action_or_func(ty: Node, src: &[u8]) -> bool {
    matches!(simple_name(ty, src), b"Action" | b"Func")
}

fn string_overload_not_delegating<'t>(declaration: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let methods: Vec<Node<'t>> = members(declaration)
        .into_iter()
        .filter(|m| m.kind() == "method_declaration")
        .collect();
    let parameter_types = |m: Node<'t>| -> Vec<&[u8]> {
        m.child_by_field_name("parameters")
            .map(|p| {
                let mut c = p.walk();
                p.named_children(&mut c)
                    .filter_map(|x| x.child_by_field_name("type").map(|t| simple_name(t, src)))
                    .collect()
            })
            .unwrap_or_default()
    };
    methods.iter().find_map(|m| {
        let name = m.child_by_field_name("name")?;
        let types = parameter_types(*m);
        let at = types.iter().position(|t| *t == b"string")?;
        let has_uri_twin = methods.iter().any(|o| {
            o != m
                && o.child_by_field_name("name")
                    .is_some_and(|n| text(n, src) == text(name, src))
                && {
                    let other = parameter_types(*o);
                    other.len() == types.len()
                        && other
                            .iter()
                            .zip(&types)
                            .enumerate()
                            .all(|(i, (a, b))| if i == at { *a == b"Uri" } else { a == b })
                }
        });
        let body = text(m.child_by_field_name("body")?, src);
        let delegates = count_word(body, text(name, src)) > 0 && count_word(body, b"Uri") > 0;
        (has_uri_twin && !delegates).then_some(name)
    })
}

fn visible_pointer_field(ty: Node, src: &[u8]) -> bool {
    let pointer = matches!(ty.kind(), "pointer_type" | "function_pointer_type")
        || matches!(simple_name(ty, src), b"IntPtr" | b"UIntPtr");
    let Some(field) = ty.parent().and_then(|v| v.parent()) else {
        return false;
    };
    let visible = cs_has_modifier(field, "public", src) || cs_has_modifier(field, "protected", src);
    pointer
        && visible
        && !cs_has_modifier(field, "readonly", src)
        && !cs_has_modifier(field, "const", src)
}

fn handle_without_finalizer(name: Node, src: &[u8]) -> bool {
    let Some(class) = name.parent() else {
        return false;
    };
    let ms = members(class);
    let holds_handle = ms.iter().any(|m| {
        m.kind() == "field_declaration"
            && !cs_has_modifier(*m, "static", src)
            && declared_type(*m).is_some_and(|t| {
                matches!(simple_name(t, src), b"IntPtr" | b"UIntPtr" | b"HandleRef")
            })
    });
    holds_handle
        && has_base(class, src, b"IDisposable")
        && !ms.iter().any(|m| m.kind() == "destructor_declaration")
}

fn non_private_fields<'s>(class: Node, src: &'s [u8]) -> Vec<(&'s [u8], bool)> {
    members(class)
        .into_iter()
        .filter(|m| m.kind() == "field_declaration")
        .filter(|m| {
            ["public", "protected", "internal"]
                .iter()
                .any(|v| cs_has_modifier(*m, v, src))
        })
        .flat_map(|m| {
            let is_static = cs_has_modifier(m, "static", src);
            declarators(m).into_iter().filter_map(move |d| {
                d.child_by_field_name("name")
                    .map(|n| (text(n, src), is_static))
            })
        })
        .collect()
}

fn field_shadowed_by_case<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let base = {
        let mut cursor = class.walk();
        let list = class
            .named_children(&mut cursor)
            .find(|c| c.kind() == "base_list")?;
        simple_name(list.named_child(0)?, src)
    };
    // The base class must be declared in this file.
    let mut root = class;
    while let Some(p) = root.parent() {
        root = p;
    }
    let base_class = find_in_scope(root, &["block"], |n| {
        n.kind() == "class_declaration"
            && n.child_by_field_name("name")
                .is_some_and(|x| text(x, src) == base)
    })?;
    let inherited = non_private_fields(base_class, src);
    if inherited.is_empty() {
        return None;
    }
    members(class)
        .into_iter()
        .filter(|m| m.kind() == "field_declaration")
        .flat_map(|m| {
            let is_static = cs_has_modifier(m, "static", src);
            declarators(m).into_iter().map(move |d| (d, is_static))
        })
        .find_map(|(d, is_static)| {
            let name = d.child_by_field_name("name")?;
            let n = text(name, src);
            inherited
                .iter()
                .any(|(b, base_static)| {
                    *b != n && b.eq_ignore_ascii_case(n) && !(is_static && *base_static)
                })
                .then_some(name)
        })
}

fn hidden_explicit_implementation<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !cs_has_modifier(class, "public", src)
        || cs_has_modifier(class, "sealed", src)
        || cs_has_modifier(class, "static", src)
    {
        return None;
    }
    let ms = members(class);
    let visible_names: Vec<&[u8]> = ms
        .iter()
        .filter(|m| cs_has_modifier(**m, "public", src) || cs_has_modifier(**m, "protected", src))
        .filter_map(|m| m.child_by_field_name("name").map(|n| text(n, src)))
        .collect();
    ms.iter().find_map(|m| {
        let mut cursor = m.walk();
        let interface = m
            .named_children(&mut cursor)
            .find(|c| c.kind() == "explicit_interface_specifier")?;
        let name = m.child_by_field_name("name")?;
        let n = text(name, src);
        // IDisposable.Dispose is reachable through Close() or Dispose(bool).
        let dispose_alternative = text(interface, src).starts_with(b"IDisposable")
            && (visible_names.contains(&&b"Close"[..]) || visible_names.contains(&&b"Dispose"[..]));
        (!visible_names.contains(&n) && !dispose_alternative).then_some(name)
    })
}

fn formats_without_culture(call: Node, src: &[u8]) -> bool {
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    let method = function
        .child_by_field_name("name")
        .map_or(&b""[..], |n| text(n, src));
    let args = cs_call_arguments(call);
    let mentions_culture = |a: &Node| {
        let t = text(*a, src);
        contains_ignoring_case(t, b"Culture")
            || contains_ignoring_case(t, b"Provider")
            || contains_ignoring_case(t, b"FormatInfo")
    };
    if args.iter().any(mentions_culture) {
        return false;
    }
    let literal = |a: &Node| a.kind() == "string_literal" || a.kind() == "verbatim_string_literal";
    match method {
        // string.Format("{0:N2}", x): the template comes first, so no provider.
        b"Format" => {
            function
                .child_by_field_name("expression")
                .is_some_and(|r| matches!(text(r, src), b"string" | b"String"))
                && args.first().is_some_and(literal)
                && args
                    .first()
                    .and_then(|a| cs_string_value(*a, src))
                    .is_some_and(|t| t.contains(&b'{'))
        }
        // x.ToString("N2"): a culture-dependent format; "D", "X" and the
        // round-trip formats read the same everywhere.
        _ => {
            args.len() == 1
                && args.first().is_some_and(literal)
                && args
                    .first()
                    .and_then(|a| cs_string_value(*a, src))
                    .is_some_and(|f| {
                        !f.is_empty()
                            && !matches!(
                                f,
                                b"o" | b"O"
                                    | b"r"
                                    | b"R"
                                    | b"s"
                                    | b"u"
                                    | b"x"
                                    | b"X"
                                    | b"D"
                                    | b"d"
                                    | b"g"
                                    | b"G"
                            )
                            && !f.starts_with(b"X")
                            && !f.starts_with(b"x")
                    })
        }
    }
}

fn locale_not_set(creation: Node, src: &[u8]) -> bool {
    // `new DataTable { Locale = ... }`
    let mut cursor = creation.walk();
    if creation
        .named_children(&mut cursor)
        .any(|c| c.kind() == "initializer_expression" && count_word(text(c, src), b"Locale") > 0)
    {
        return false;
    }
    let Some(declarator) = creation
        .parent()
        .filter(|p| p.kind() == "variable_declarator")
    else {
        // Assigned to a field or passed on: whoever receives it may set it.
        return creation
            .parent()
            .is_some_and(|p| matches!(p.kind(), "return_statement" | "arrow_expression_clause"));
    };
    let Some(name) = declarator.child_by_field_name("name").map(|n| text(n, src)) else {
        return false;
    };
    let scope = enclosing_method(creation).and_then(|m| m.child_by_field_name("body"));
    scope.is_some_and(|body| {
        find_in_scope(body, &[], |n| {
            n.kind() == "member_access_expression"
                && n.child_by_field_name("name")
                    .is_some_and(|x| text(x, src) == b"Locale")
                && n.child_by_field_name("expression")
                    .is_some_and(|e| text(e, src) == name)
        })
        .is_none()
    })
}

fn extends_neighbour_type(ty: Node, src: &[u8]) -> bool {
    let Some(parameter) = ty.parent() else {
        return false;
    };
    if !has_parameter_modifier(parameter, &[b"this"], src) {
        return false;
    }
    let extended = simple_name(ty, src);
    // The namespace the extension is in: the nearest block namespace, or the
    // whole file for a file-scoped one.
    let mut scope = ty;
    while let Some(p) = scope.parent() {
        scope = p;
        if scope.kind() == "namespace_declaration" {
            break;
        }
    }
    let generated = |n: Node| {
        attribute_names(n, src)
            .iter()
            .any(|(_, a)| *a == b"GeneratedCode")
    };
    find_in_scope(scope, &["block", "method_declaration"], |n| {
        matches!(
            n.kind(),
            "class_declaration"
                | "struct_declaration"
                | "record_declaration"
                | "interface_declaration"
        ) && n
            .child_by_field_name("name")
            .is_some_and(|x| text(x, src) == extended)
            && !generated(n)
    })
    .is_some()
}

fn function_without_try(name: Node, src: &[u8]) -> bool {
    let Some(method) = name.parent() else {
        return false;
    };
    if !is_azure_function(method, src) {
        return false;
    }
    let Some(body) = method.child_by_field_name("body") else {
        return false;
    };
    let statements = if body.kind() == "block" {
        cs_statements(body)
    } else {
        vec![body]
    };
    !statements.iter().any(|s| {
        s.kind() == "try_statement" && {
            let mut c = s.walk();
            s.named_children(&mut c).any(|x| x.kind() == "catch_clause")
        }
    })
}

fn logs_failure(block: Node, src: &[u8]) -> bool {
    find_in_scope(block, &[], |n| {
        n.kind() == "invocation_expression"
            && n.child_by_field_name("function").is_some_and(|f| {
                let method = simple_name(f, src);
                matches!(
                    method,
                    b"LogInformation"
                        | b"LogWarning"
                        | b"LogError"
                        | b"LogCritical"
                        | b"Log"
                        | b"Information"
                        | b"Warning"
                        | b"Error"
                        | b"Fatal"
                        | b"TrackException"
                )
            })
    })
    .is_some()
}

fn function_catch_without_log<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !is_azure_function(method, src) {
        return None;
    }
    let body = method.child_by_field_name("body")?;
    let catches: Vec<Node<'t>> = {
        let mut found = Vec::new();
        let mut stack = vec![body];
        while let Some(n) = stack.pop() {
            if n.kind() == "catch_clause" {
                found.push(n);
            }
            if matches!(n.kind(), "lambda_expression" | "local_function_statement") {
                continue;
            }
            let mut c = n.walk();
            stack.extend(n.named_children(&mut c));
        }
        found
    };
    catches.into_iter().find(|c| {
        c.child_by_field_name("body")
            .is_some_and(|b| !logs_failure(b, src))
    })
}

/// Calls `xs.Method(predicate)` on a receiver declared as a `List<T>`.
fn predicate_calls_on_list<'t>(m: &Model<'t>, method: &[u8], src: &[u8]) -> Vec<Node<'t>> {
    let mut found = Vec::new();
    walk_tree(m, |call, _| {
        if call.kind() != "invocation_expression" {
            return;
        }
        let Some(function) = call
            .child_by_field_name("function")
            .filter(|f| f.kind() == "member_access_expression")
        else {
            return;
        };
        let named = function
            .child_by_field_name("name")
            .is_some_and(|n| text(n, src) == method);
        let args = cs_call_arguments(call);
        let predicate = matches!(args.as_slice(), [a] if a.kind() == "lambda_expression" || a.kind() == "identifier");
        let list = function
            .child_by_field_name("expression")
            .filter(|r| r.kind() == "identifier")
            .and_then(|r| type_of_name(m, r))
            .is_some_and(|t| is_generic(t, b"List", src));
        if named && predicate && list {
            found.push(call);
        }
    });
    found
}

fn use_list_find<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    predicate_calls_on_list(m, b"FirstOrDefault", src)
}

fn use_list_true_for_all<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    predicate_calls_on_list(m, b"All", src)
}

fn use_list_exists<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    predicate_calls_on_list(m, b"Any", src)
}

#[cfg(test)]
mod tests {
    use super::super::cs::tests::flagged;

    #[test]
    fn usings() {
        let src = "using System;\nusing System;\nusing static System.Math;\nusing N.M;\nusing N;\nusing Other;\nnamespace N.M;\nclass A { }";
        assert_eq!(flagged("cs/unnecessary-using", src), [2, 4, 5]);
        let block = "namespace N { using System; using N; class A { } }";
        assert_eq!(flagged("cs/unnecessary-using", block), [1]);
    }

    #[test]
    fn size() {
        let fields: String = (1..=31).map(|i| format!("Dep{i} a{i}; ")).collect();
        let few: String = (1..=30).map(|i| format!("Dep{i} a{i}; ")).collect();
        let src = format!(
            "class A {{ {fields}}}\nclass C {{ {few}}}\nclass D {{ List<Dep1> x; Dictionary<Dep2, Dep3> y; T z; }}"
        );
        assert_eq!(flagged("cs/class-coupling", &src), [1]);
        let ifs: String = (1..=10).map(|i| format!("if (a == {i}) {{}} ")).collect();
        let nine: String = (1..=9).map(|i| format!("if (a == {i}) {{}} ")).collect();
        let src = format!(
            "class A {{\nvoid F(int a) {{ {ifs}}}\nvoid G(int a) {{ {nine}}}\nint P {{ get {{ {ifs}return 0; }} }}\nvoid S(int a) {{ switch (a) {{ case 1: case 2: case 3: case 4: case 5: break; case 6: case 7: case 8: case 9: case 10: break; default: break; }} }}\n}}"
        );
        assert_eq!(flagged("cs/method-complexity", &src), [2, 4, 5]);
    }

    #[test]
    fn statements() {
        let src = "class A {\nvoid F() {\ntry { G(); } catch (IOException e) { Log(e); }\ntry { H(); } catch (IOException e) { Log(e); }\ntry { K(); } catch (Exception e) { Log(e); }\ntry { L(); } finally { Close(); }\ntry { M(); } finally { Close(); }\n}\nobject[] a = new string[3];\nobject[] b = new object[3];\nstring?[] c = new string[1];\nvoid G() { object[] d = new Foo[2]; var e = new string[1]; }\n}";
        assert_eq!(flagged("cs/mergeable-try", src), [4, 7]);
        assert_eq!(flagged("cs/array-covariance", src), [9, 12]);
    }

    #[test]
    fn modifiers_and_visibility() {
        let src = "sealed class B : A { public sealed override void F() { } sealed class Inner { } }\nunsafe class U { unsafe void P() { } }\ninternal class C : I { public int GetOne() => 1; public int X; public void Run() { } }\nclass D { public int Y; public static D operator +(D a, D b) => a; public override string ToString() => \"\"; public D() { } }\npublic class E { public int Z; private class Hidden { public int W; } }";
        assert_eq!(flagged("cs/redundant-modifier", src), [1, 2]);
        assert_eq!(flagged("cs/member-more-visible-than-type", src), [3, 4, 5]);
    }

    #[test]
    fn types_and_casts() {
        let src = "class A {\nIShape shape;\nint F(IShape s, Base b) {\nvar c = (Circle)s;\nvar d = s as Circle;\nvar e = (IRound)s;\nvar f = (Circle)b;\nvar g = (Circle)shape;\nreturn 0;\n}\npublic event Action<int> Changed;\npublic event EventHandler<ChangedEventArgs> Ok;\n}";
        assert_eq!(flagged("cs/interface-downcast", src), [4, 5, 8]);
        assert_eq!(flagged("cs/event-handler-signature", src), [11]);
    }

    #[test]
    fn interop_and_disposal() {
        let src = "public class Native : IDisposable {\npublic IntPtr Handle;\nprotected readonly IntPtr Safe;\nprivate IntPtr own;\nFileStream fs;\nTimer timer;\npublic void CleanUp() { fs.Dispose(); }\npublic void Reset() { timer?.Dispose(); timer = new Timer(); }\nprotected virtual void Dispose(bool d) { fs.Dispose(); }\npublic void Dispose() { Dispose(true); }\n}\nclass Finalized : IDisposable { IntPtr h; ~Finalized() { } public void Dispose() { } }";
        assert_eq!(flagged("cs/visible-pointer-field", src), [2]);
        assert_eq!(flagged("cs/disposable-handle-without-finalizer", src), [1]);
        assert_eq!(flagged("cs/field-disposed-outside-dispose", src), [7]);
    }

    #[test]
    fn inheritance_and_overloads() {
        let src = "class Fruit { protected string plantingSeason; private int count; protected static int Shared; }\nclass Raspberry : Fruit { protected string plantingseason; int Count; static int shared; }\npublic class Store : IStore, IDisposable { void IStore.Save() { } void IStore.Load() { } protected void Load() { } void IDisposable.Dispose() { } public void Close() { } }\nsealed public class Sealed : IStore { void IStore.Save() { } }\nclass U { public void Fetch(string uri) { Download(uri); } public void Fetch(Uri uri) { } public void Get(string uri) { Get(new Uri(uri)); } public void Get(Uri uri) { } public void Put(string s) { } }";
        assert_eq!(flagged("cs/field-differs-from-base-by-case", src), [2]);
        assert_eq!(flagged("cs/explicit-implementation-hidden", src), [3]);
        assert_eq!(flagged("cs/string-uri-overload-not-delegating", src), [5]);
    }

    #[test]
    fn culture_and_data() {
        let src = "class A {\nstring F(decimal d, int n) {\nvar a = string.Format(\"{0:N2}\", d);\nvar b = string.Format(CultureInfo.InvariantCulture, \"{0:N2}\", d);\nvar c = d.ToString(\"N2\");\nvar e = n.ToString(\"X4\");\nvar f = d.ToString(\"N2\", CultureInfo.InvariantCulture);\nreturn a;\n}\nDataTable T() { var t = new DataTable(\"x\"); return t; }\nDataTable U() { var t = new DataTable(\"x\"); t.Locale = CultureInfo.InvariantCulture; return t; }\nDataSet V() => new DataSet();\nDataSet W() => new DataSet { Locale = CultureInfo.InvariantCulture };\n}";
        assert_eq!(flagged("cs/culture-overload", src), [3, 5]);
        assert_eq!(flagged("cs/data-table-locale", src), [10, 12]);
    }

    #[test]
    fn extensions_and_functions() {
        let src = "namespace Shop {\nclass Order { }\nstatic class X { public static int Total(this Order o) => 0; public static int Len(this string s) => 0; public static int Count(this List<Order> l) => 0; }\n}\nclass F {\n[FunctionName(\"Run\")] public async Task Run(ILogger log) { await Work(); }\n[FunctionName(\"Safe\")] public async Task Safe(ILogger log) { try { await Work(); } catch (Exception e) { log.LogError(e, \"failed\"); throw; } }\n[FunctionName(\"Quiet\")] public async Task Quiet(ILogger log) { try { await Work(); } catch (Exception e) { throw; } }\npublic async Task NotAFunction() { await Work(); }\n}";
        assert_eq!(flagged("cs/extension-in-same-namespace", src), [3]);
        assert_eq!(flagged("cs/azure-function-without-try", src), [6]);
        assert_eq!(flagged("cs/azure-function-catch-not-logged", src), [8]);
    }

    #[test]
    fn list_methods() {
        let src = "class A {\nList<int> items;\nbool F(List<int> xs, IEnumerable<int> ys, int[] zs) {\nvar a = xs.FirstOrDefault(x => x > 1);\nvar b = xs.All(x => x > 1);\nvar c = xs.Any(x => x > 1);\nvar d = ys.Any(x => x > 1);\nvar e = xs.Any();\nvar f = items.Any(x => x > 1);\nvar local = new List<int>();\nvar g = local.Any(IsBig);\nreturn zs.Any(x => x > 1);\n}\n}";
        assert_eq!(flagged("cs/use-list-find", src), [4]);
        assert_eq!(flagged("cs/use-list-true-for-all", src), [5]);
        assert_eq!(flagged("cs/use-list-exists", src), [6, 9, 11]);
    }
}
