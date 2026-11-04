//! C# rules from SonarQube's default profile that need types, batch 11
//! (ADR-0007, ADR-0015): built on the declared types `cs_types` finds.
//! A rule reports only what the declarations prove; the ones that see less
//! than SonarQube's typed analysis are `related`. Queries stay cheap on deep
//! trees: see the notes in `js_modern.rs`.

use super::cs::{simple_name, unparenthesized};
use super::cs_bugs::{attribute_arguments, attribute_names, cs_call_arguments};
use super::cs_more::members;
use super::cs_types::{
    enumerable_calls, expression_type, initial_value, is_one_of, is_value_type, normalized_type,
    numeric_range, numeric_value, shift_width, walk_tree,
};
use super::java_bugs::operator_text;
use super::java_security::{contains_ignoring_case, text};
use super::prelude::*;
use crate::semantic::Model;
use crate::semantic::cs_infer::Infer;

/// Rules that are off unless `rules.enabled` lists them: none, every rule
/// here is in SonarQube's default profile.
pub(super) static OFF_BY_DEFAULT: &[&str] = &[];

pub(super) static RULES: &[Rule] = &[
    // ---- Bugs ----
    Rule {
        id: "cs/shift-out-of-range",
        name: "Integers should not be shifted by zero or by their width or more",
        description: "C# masks the shift count: shifting an int by 33 shifts it by 1, and shifting by 0 changes \
                      nothing.",
        message: "Shift by a count between 1 and the type's width minus 1.",
        category: Bug,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S2183")],
        check: Check::Semantic {
            langs: CSHARP,
            find: shifts_out_of_range,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int F(int i) { return i << 33; } }",
            good: "class A { int F(int i) { return i << 1; } }",
        }),
    },
    Rule {
        id: "cs/reference-equals-value-type",
        name: "ReferenceEquals should not be used on value types",
        description: "A value type is boxed into a new object for each argument, so ReferenceEquals on it is \
                      always false.",
        message: "Use Equals or == to compare these values.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2995")],
        check: Check::Semantic {
            langs: CSHARP,
            find: reference_equals_on_value,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { bool F(int a, int b) { return ReferenceEquals(a, b); } }",
            good: "class A { bool F(int a, int b) { return a == b; } }",
        }),
    },
    Rule {
        id: "cs/shift-dynamic-non-int",
        name: "Right operands of shifts on dynamic values should be integers",
        description: "With a dynamic left operand the compiler doesn't check the shift count, so a non-integer \
                      throws RuntimeBinderException at run time.",
        message: "Shift by an int.",
        category: Bug,
        severity: Critical,
        effort_minutes: 2,
        sonar: &[exact("S3449")],
        check: Check::Semantic {
            langs: CSHARP,
            find: dynamic_shift_by_non_int,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { object F(dynamic d) { return d >> 5.4; } }",
            good: "class A { object F(dynamic d) { return d >> 5; } }",
        }),
    },
    Rule {
        id: "cs/nullable-get-type-comparison",
        name: "GetType() should not be compared with a nullable type",
        description: "GetType() on a nullable value returns the underlying type, so comparing it with \
                      typeof(int?) is always false, or throws on null.",
        message: "Compare with the underlying type, or test the value with 'is'.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S3610")],
        check: Check::Query {
            langs: CSHARP,
            query: "(typeof_expression type: [(nullable_type) (generic_name)]) @match",
            filter: Some(Keep(compared_with_get_type)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { bool F(int? v) { return v.GetType() == typeof(int?); } }",
            good: "class A { bool F(int? v) { return v.GetType() == typeof(int); } }",
        }),
    },
    Rule {
        id: "cs/route-constraint-type",
        name: "Component parameters should match their route constraint's type",
        description: "Blazor converts a constrained route value to the constraint's type; a parameter of \
                      another type fails at run time.",
        message: "Give this parameter the type of its route constraint.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6800")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration (attribute_list) body: (declaration_list)) @match",
            filter: Some(Find(route_parameter_type_mismatch)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "[Route(\"/orders/{Id:int}\")] class Order : ComponentBase { [Parameter] public string Id { get; set; } }",
            good: "[Route(\"/orders/{Id:int}\")] class Order : ComponentBase { [Parameter] public int Id { get; set; } }",
        }),
    },
    Rule {
        id: "cs/delegate-chain-subtraction",
        name: "Delegate chains should not be subtracted",
        description: "Subtracting `a + b` only removes a and b when they appear in that order, next to each \
                      other; otherwise nothing is removed.",
        message: "Subtract each delegate on its own.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3172")],
        check: Check::Semantic {
            langs: CSHARP,
            find: super::cs_inferred::subtracted_delegate_chains,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { Action F(Action all, Action a, Action b) { return all - (a + b); } }",
            good: "class A { Action F(Action all, Action a, Action b) { return all - a - b; } }",
        }),
    },
    Rule {
        id: "cs/ignored-pure-result",
        name: "Methods without side effects should not have their return values ignored",
        description: "LINQ, [Pure] methods, the methods of C#'s built-in types and of immutable collections \
                      return a new value instead of changing anything, so a call whose result is ignored does \
                      nothing.",
        message: "Use this call's result, or remove the call.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2201")],
        check: Check::Semantic {
            langs: CSHARP,
            find: super::cs_inferred::ignored_results,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { string F(string s) { s.Trim(); return s; } }",
            good: "class A { string F(string s) { s = s.Trim(); return s; } }",
        }),
    },
    Rule {
        id: "cs/unchecked-stream-read",
        name: "The count returned by Stream.Read should be checked",
        description: "Read may return fewer bytes than asked for, even before the end of the stream; ignoring \
                      the count processes stale buffer contents.",
        message: "Use the number of bytes read, or call ReadExactly.",
        category: Bug,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S2674")],
        check: Check::Semantic {
            langs: CSHARP,
            find: ignores_read_count,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(Stream s, byte[] b) { s.Read(b, 0, b.Length); } }",
            good: "class A { void F(Stream s, byte[] b) { s.ReadExactly(b, 0, b.Length); } }",
        }),
    },
    // ---- Vulnerabilities ----
    Rule {
        id: "cs/conflicting-transparency",
        name: "Members should not have transparency attributes that conflict with their type's",
        description: "Security transparency set on a type and differently on its members is ambiguous, and \
                      the type-level one wins, which may expose critical code.",
        message: "Remove the type-level transparency attribute, and annotate the members only.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S4211")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(class_declaration (attribute_list) body: (declaration_list)) (struct_declaration (attribute_list) body: (declaration_list))] @match",
            filter: Some(Find(conflicting_transparency)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "[SecuritySafeCritical] public class Foo { [SecurityCritical] public void Bar() { } }",
            good: "public class Foo { [SecurityCritical] public void Bar() { } }",
        }),
    },
    // ---- Code smells ----
    Rule {
        id: "cs/impossible-comparison",
        name: "Comparisons with values outside a type's range should not be made",
        description: "A byte is never greater than 255 and a char never negative; such a comparison is \
                      always true or always false.",
        message: "Remove this comparison: its result never changes.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 2,
        sonar: &[exact("S2198")],
        check: Check::Semantic {
            langs: CSHARP,
            find: compares_out_of_range,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { bool F(byte b) { return b > 300; } }",
            good: "class A { bool F(byte b) { return b > 200; } }",
        }),
    },
    Rule {
        id: "cs/foreach-explicit-conversion",
        name: "foreach should not cast elements of generic collections",
        description: "foreach silently casts each element to the loop variable's type, so a narrower type \
                      throws InvalidCastException at run time.",
        message: "Filter with OfType<T>() or use the collection's element type.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S3217")],
        check: Check::Semantic {
            langs: CSHARP,
            find: super::cs_inferred::foreach_explicit_conversions,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class Fruit { }\nclass Orange : Fruit { }\nclass A { void F(List<Fruit> basket) { foreach (Orange o in basket) { G(o); } } }",
            good: "class Fruit { }\nclass Orange : Fruit { }\nclass A { void F(List<Fruit> basket) { foreach (Orange o in basket.OfType<Orange>()) { G(o); } } }",
        }),
    },
    Rule {
        id: "cs/timezone-converter",
        name: "Time zones should be looked up without converting their IDs",
        description: "TimeZoneInfo.FindSystemTimeZoneById accepts both IANA and Windows IDs on every OS, so \
                      converting with TimeZoneConverter first is unnecessary.",
        message: "Pass the time zone ID to FindSystemTimeZoneById directly.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6575")],
        check: Check::Semantic {
            langs: CSHARP,
            find: converts_time_zone_id,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { TimeZoneInfo F() { return TimeZoneInfo.FindSystemTimeZoneById(TZConvert.IanaToWindows(\"Asia/Tokyo\")); } }",
            good: "class A { TimeZoneInfo F() { return TimeZoneInfo.FindSystemTimeZoneById(\"Asia/Tokyo\"); } }",
        }),
    },
    Rule {
        id: "cs/use-string-create",
        name: "string.Create should be used instead of FormattableString",
        description: "Since .NET 6, string.Create formats with a culture using pooled buffers, allocating less \
                      than FormattableString.Invariant or CurrentCulture.",
        message: "Use string.Create with a culture.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[related("S6618")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(invocation_expression function: (member_access_expression expression: (identifier) @r name: (identifier) @n)
                        (#eq? @r "FormattableString") (#any-of? @n "Invariant" "CurrentCulture")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { string F(int n) { return FormattableString.Invariant($\"n = {n}\"); } }",
            good: "class A { string F(int n) { return string.Create(CultureInfo.InvariantCulture, $\"n = {n}\"); } }",
        }),
    },
    Rule {
        id: "cs/trace-if-switch-level",
        name: "Trace.WriteLineIf should not be used with TraceSwitch levels",
        description: "`WriteLineIf(sw.TraceError, ...)` evaluates the message whether or not it's written; \
                      TraceError and TraceSource categorize and filter properly.",
        message: "Use Trace.TraceError/TraceWarning/TraceInformation, or test the level with if.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6675")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(invocation_expression
                        function: (member_access_expression expression: (identifier) @r name: (identifier) @n)
                        arguments: (argument_list . (argument (member_access_expression name: (identifier) @l)))
                        (#any-of? @r "Trace" "Debug") (#any-of? @n "WriteIf" "WriteLineIf")
                        (#any-of? @l "TraceError" "TraceWarning" "TraceInfo" "TraceVerbose")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(TraceSwitch sw) { Trace.WriteLineIf(sw.TraceError, \"failed\"); } }",
            good: "class A { void F() { Trace.TraceError(\"failed\"); } }",
        }),
    },
    Rule {
        id: "cs/value-task-misuse",
        name: "ValueTasks should be consumed once",
        description: "A ValueTask may reuse its backing object once it completes, so awaiting it twice, or \
                      reading its result before it's known to be done, gives wrong results.",
        message: "Consume this ValueTask once, or call AsTask() to keep a Task.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S5034")],
        check: Check::Semantic {
            langs: CSHARP,
            find: super::cs_inferred::value_task_misuse,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { async Task F() { ValueTask<int> vt = GetAsync(); var a = await vt; var b = await vt; } }",
            good: "class A { async Task F() { ValueTask<int> vt = GetAsync(); var a = await vt; } }",
        }),
    },
    Rule {
        id: "cs/redundant-cast",
        name: "Redundant casts should not be used",
        description: "Casting a value to the type it already has does nothing but add noise.",
        message: "Remove this cast: the value already has this type.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S1905")],
        check: Check::Semantic {
            langs: CSHARP,
            find: super::cs_inferred::redundant_casts,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int F(int i) { return (int)i; } }",
            good: "class A { int F(int i) { return i; } }",
        }),
    },
    Rule {
        id: "cs/indexing-instead-of-linq",
        name: "Lists and arrays should be indexed instead of using First, Last or ElementAt",
        description: "On a list or an array, `xs[0]` reads the element directly, where First() goes through \
                      LINQ.",
        message: "Index the collection directly.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S6608")],
        check: Check::Semantic {
            langs: CSHARP,
            find: linq_on_indexable,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int F(List<int> xs) { return xs.First(); } }",
            good: "class A { int F(List<int> xs) { return xs[0]; } }",
        }),
    },
    Rule {
        id: "cs/set-min-max",
        name: "Sorted sets' Min and Max properties should be used",
        description: "SortedSet<T> keeps its smallest and largest elements at hand; the LINQ Min() and Max() \
                      walk the whole set.",
        message: "Use the Min or Max property.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S6609")],
        check: Check::Semantic {
            langs: CSHARP,
            find: linq_min_max_on_sorted_set,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int F(SortedSet<int> xs) { return xs.Min(); } }",
            good: "class A { int F(SortedSet<int> xs) { return xs.Min; } }",
        }),
    },
    Rule {
        id: "cs/linked-list-first-last",
        name: "LinkedList's First and Last properties should be used",
        description: "LinkedList<T> holds its first and last nodes; the LINQ First() and Last() enumerate.",
        message: "Use the First or Last property.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S6613")],
        check: Check::Semantic {
            langs: CSHARP,
            find: linq_first_last_on_linked_list,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int F(LinkedList<int> xs) { return xs.First(); } }",
            good: "class A { int F(LinkedList<int> xs) { return xs.First.Value; } }",
        }),
    },
];

// ---------------------------------------------------- filters

/// The nodes of `kinds` that `keep` accepts, from one walk of the file.
fn matching<'t>(
    m: &Model<'t>,
    kinds: &[&str],
    keep: impl Fn(Node<'t>, &[Node<'t>]) -> bool,
) -> Vec<Node<'t>> {
    let mut found = Vec::new();
    walk_tree(m, |node, ancestors| {
        if kinds.contains(&node.kind()) && keep(node, ancestors) {
            found.push(node);
        }
    });
    found
}

/// The method name of a call `x.Name(...)` or `x.Name<T>(...)`.
fn method_name<'s>(call: Node, src: &'s [u8]) -> &'s [u8] {
    call.child_by_field_name("function")
        .filter(|f| f.kind() == "member_access_expression")
        .and_then(|f| f.child_by_field_name("name"))
        .map_or(&b""[..], |n| simple_name(n, src))
}

/// The receiver of a call `x.Name(...)`.
fn receiver(call: Node) -> Option<Node> {
    call.child_by_field_name("function")
        .filter(|f| f.kind() == "member_access_expression")
        .and_then(|f| f.child_by_field_name("expression"))
}

const SHIFTS: &[&[u8]] = &[b"<<", b">>", b">>>", b"<<=", b">>=", b">>>="];

fn shifts_out_of_range<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    matching(
        m,
        &["binary_expression", "assignment_expression"],
        |node, ancestors| {
            if !SHIFTS.contains(&operator_text(node, src)) {
                return false;
            }
            let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) else {
                return false;
            };
            let Some(count) = numeric_value(right, src).filter(|v| v.fract() == 0.0) else {
                return false;
            };
            let width = expression_type(m, left, src)
                .and_then(|t| shift_width(&t))
                .map(f64::from);
            // `1 << 0` spells out the first flag of a set; a shift of a variable
            // by zero does nothing.
            let constant = numeric_value(left, src).is_some()
                || ancestors
                    .iter()
                    .any(|a| a.kind() == "enum_member_declaration");
            (count == 0.0 && !constant) || count < 0.0 || width.is_some_and(|w| count >= w)
        },
    )
}

fn reference_equals_on_value<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    matching(m, &["invocation_expression"], |call, _| {
        let calls_it = call.child_by_field_name("function").is_some_and(|f| {
            matches!(f.kind(), "identifier" | "member_access_expression")
                && simple_name(f, src) == b"ReferenceEquals"
        });
        let args = cs_call_arguments(call);
        calls_it
            && args.len() == 2
            && args.iter().any(|a| {
                numeric_value(*a, src).is_some()
                    || matches!(a.kind(), "boolean_literal" | "character_literal")
                    || expression_type(m, *a, src).is_some_and(|t| is_value_type(m, &t))
            })
    })
}

fn dynamic_shift_by_non_int<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    matching(
        m,
        &["binary_expression", "assignment_expression"],
        |node, _| {
            if !SHIFTS.contains(&operator_text(node, src)) {
                return false;
            }
            let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) else {
                return false;
            };
            if expression_type(m, left, src).as_deref() != Some(&b"dynamic"[..]) {
                return false;
            }
            let right = unparenthesized(right);
            matches!(
                right.kind(),
                "null_literal"
                    | "real_literal"
                    | "object_creation_expression"
                    | "string_literal"
                    | "boolean_literal"
            ) || expression_type(m, right, src).is_some_and(|t| {
                matches!(
                    t.as_slice(),
                    b"double" | b"float" | b"decimal" | b"string" | b"object" | b"bool"
                )
            })
        },
    )
}

fn compared_with_get_type(typeof_expression: Node, src: &[u8]) -> bool {
    let Some(ty) = typeof_expression.child_by_field_name("type") else {
        return false;
    };
    if ty.kind() == "generic_name" && simple_name(ty, src) != b"Nullable" {
        return false;
    }
    let Some(comparison) = typeof_expression.parent().filter(|p| {
        p.kind() == "binary_expression" && matches!(operator_text(*p, src), b"==" | b"!=")
    }) else {
        return false;
    };
    ["left", "right"]
        .iter()
        .filter_map(|f| comparison.child_by_field_name(f))
        .any(|side| {
            side.kind() == "invocation_expression"
                && cs_call_arguments(side).is_empty()
                && side
                    .child_by_field_name("function")
                    .and_then(|f| f.child_by_field_name("name"))
                    .is_some_and(|n| text(n, src) == b"GetType")
        })
}

/// The .NET type a Blazor route constraint converts its value to.
fn constraint_type(constraint: &[u8]) -> Option<&'static [u8]> {
    Some(match constraint.to_ascii_lowercase().as_slice() {
        b"bool" => b"bool",
        b"datetime" => b"DateTime",
        b"decimal" => b"decimal",
        b"double" => b"double",
        b"float" => b"float",
        b"guid" => b"Guid",
        b"int" => b"int",
        b"long" => b"long",
        _ => return None,
    })
}

fn route_parameter_type_mismatch<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    // {name:constraint} pairs from the class's [Route] templates.
    let mut constrained: Vec<(Vec<u8>, &'static [u8])> = Vec::new();
    for (attribute, name) in attribute_names(class, src) {
        if !matches!(name, b"Route" | b"RouteAttribute") {
            continue;
        }
        for (_, value) in attribute_arguments(attribute) {
            let template = text(value, src);
            for segment in template.split(|b| *b == b'{').skip(1) {
                let inside = segment.split(|b| *b == b'}').next().unwrap_or_default();
                let mut parts = inside.split(|b| *b == b':');
                // `{*rest}` is a catch-all parameter named rest.
                let param = parts.next().unwrap_or_default();
                let param = param
                    .strip_prefix(b"**")
                    .or_else(|| param.strip_prefix(b"*"))
                    .unwrap_or(param);
                if let Some(ty) = parts
                    .next()
                    .and_then(|c| constraint_type(c.strip_suffix(b"?").unwrap_or(c)))
                {
                    constrained.push((param.to_ascii_lowercase(), ty));
                }
            }
        }
    }
    if constrained.is_empty() {
        return None;
    }
    members(class)
        .into_iter()
        .filter(|m| m.kind() == "property_declaration")
        .find_map(|p| {
            if !attribute_names(p, src)
                .iter()
                .any(|(_, n)| matches!(*n, b"Parameter" | b"ParameterAttribute"))
            {
                return None;
            }
            let name = text(p.child_by_field_name("name")?, src).to_ascii_lowercase();
            let ty = p.child_by_field_name("type")?;
            let declared = normalized_type(text(ty, src));
            let declared = declared.strip_suffix(b"?").unwrap_or(&declared);
            let declared = declared
                .strip_prefix(b"Nullable<")
                .and_then(|d| d.strip_suffix(b">"))
                .unwrap_or(declared);
            constrained
                .iter()
                .any(|(param, expected)| *param == name && declared != *expected)
                .then_some(ty)
        })
}

fn ignores_read_count<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    matching(m, &["invocation_expression"], |call, ancestors| {
        // `s.Read(...);` or `await s.ReadAsync(...);`
        let statement = match ancestors {
            [.., s, a] if a.kind() == "await_expression" => *s,
            [.., s] => *s,
            [] => return false,
        };
        if statement.kind() != "expression_statement" {
            return false;
        }
        let args = cs_call_arguments(call).len();
        let reads = match method_name(call, src) {
            b"Read" => args == 3 || args == 1,
            b"ReadAsync" => (1..=4).contains(&args),
            _ => false,
        };
        reads
            && receiver(call).is_some_and(|r| {
                expression_type(m, r, src).is_some_and(|t| t.ends_with(b"Stream"))
                    || contains_ignoring_case(simple_name(r, src), b"stream")
            })
    })
}

const TRANSPARENCY: &[&[u8]] = &[
    b"SecurityCritical",
    b"SecuritySafeCritical",
    b"SecurityTransparent",
];

fn transparency(declaration: Node, src: &[u8]) -> Option<Vec<u8>> {
    attribute_names(declaration, src)
        .into_iter()
        .find_map(|(_, n)| {
            let n = n.strip_suffix(b"Attribute").unwrap_or(n);
            TRANSPARENCY.contains(&n).then(|| n.to_vec())
        })
}

fn conflicting_transparency<'t>(declaration: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let own = transparency(declaration, src)?;
    members(declaration).into_iter().find_map(|m| {
        let theirs = transparency(m, src)?;
        (theirs != own).then(|| m.child_by_field_name("name").unwrap_or(m))
    })
}

fn compares_out_of_range<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    matching(m, &["binary_expression"], |node, _| {
        if !matches!(
            operator_text(node, src),
            b"<" | b"<=" | b">" | b">=" | b"==" | b"!="
        ) {
            return false;
        }
        let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) else {
            return false;
        };
        let (value, other) = match (numeric_value(left, src), numeric_value(right, src)) {
            (Some(v), None) => (v, right),
            (None, Some(v)) => (v, left),
            _ => return false,
        };
        expression_type(m, other, src)
            .and_then(|t| numeric_range(&t))
            .is_some_and(|(min, max)| value < min || value > max)
    })
}

fn converts_time_zone_id<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let converted =
        |n: Node| n.kind() == "invocation_expression" && text(n, src).starts_with(b"TZConvert.");
    matching(m, &["invocation_expression"], |call, _| {
        method_name(call, src) == b"FindSystemTimeZoneById"
            && cs_call_arguments(call).first().is_some_and(|a| {
                converted(*a)
                    || (a.kind() == "identifier" && initial_value(m, *a).is_some_and(converted))
            })
    })
}

/// `First()`, `Last()` and `ElementAt(i)` on a type with an indexer:
/// one implementing IList, IList<T> or IReadOnlyList<T>.
fn linq_on_indexable<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let Some(infer) = Infer::new(m, src) else {
        return Vec::new();
    };
    enumerable_calls(m, src, &[("First", 0), ("Last", 0), ("ElementAt", 1)])
        .into_iter()
        .filter(|(_, receiver)| {
            infer.supertypes(receiver).iter().any(|t| {
                t.is("System.Collections.IList")
                    || t.is("System.Collections.Generic.IList`1")
                    || t.is("System.Collections.Generic.IReadOnlyList`1")
            })
        })
        .map(|(call, _)| call)
        .collect()
}

/// `Min()` and `Max()` on sorted sets, which keep both at hand.
fn linq_min_max_on_sorted_set<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    const SETS: &[&str] = &[
        "System.Collections.Generic.SortedSet`1",
        "System.Collections.Immutable.ImmutableSortedSet`1",
        "System.Collections.Immutable.ImmutableSortedSet.Builder",
    ];
    enumerable_calls(m, src, &[("Min", 0), ("Max", 0)])
        .into_iter()
        .filter(|(_, receiver)| is_one_of(receiver, SETS, false))
        .map(|(call, _)| call)
        .collect()
}

/// `First()` and `Last()` on a LinkedList, which holds both nodes.
fn linq_first_last_on_linked_list<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    enumerable_calls(m, src, &[("First", 0), ("Last", 0)])
        .into_iter()
        .filter(|(_, receiver)| receiver.is("System.Collections.Generic.LinkedList`1"))
        .map(|(call, _)| call)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::super::cs::tests::flagged;

    fn class(body: &str) -> String {
        format!("namespace N;\nclass A {{\n{body}\n}}\n")
    }

    #[test]
    fn shifts() {
        let src = class(
            "int F(int i, long l, short s, dynamic d, BigInteger big) {\nvar a = i << 33;\nvar b = i << 0;\nvar c = l << 33;\nvar e = l << 64;\nvar f = s << 32;\nvar g = 1 << 0;\nvar h = 1 << 32;\nvar k = big << 100;\ni <<= 40;\nvar m = d >> 5.4;\nvar n = d << null;\nvar o = d >> 5;\nreturn 0;\n}\nenum E { None = 0, A = 1 << 0 }",
        );
        assert_eq!(flagged("cs/shift-out-of-range", &src), [4, 5, 7, 8, 10, 12]);
        assert_eq!(flagged("cs/shift-dynamic-non-int", &src), [13, 14]);
    }

    #[test]
    fn comparisons_and_equality() {
        let src = class(
            "bool F(byte b, char c, int i, int? n, Point p, string s, object o) {\nvar a = b > 256;\nvar d = b >= 255;\nvar e = c < -1;\nvar f = i > 3000000000;\nvar g = i < 100;\nvar h = ReferenceEquals(i, 1);\nvar k = object.ReferenceEquals(p, p);\nvar m = ReferenceEquals(s, o);\nvar q = n.GetType() == typeof(int?);\nvar r = o.GetType() != typeof(Nullable<int>);\nvar t = o.GetType() == typeof(int);\nreturn a;\n}\nstruct Point { }",
        );
        assert_eq!(flagged("cs/impossible-comparison", &src), [4, 6, 7]);
        assert_eq!(flagged("cs/reference-equals-value-type", &src), [9, 10]);
        assert_eq!(flagged("cs/nullable-get-type-comparison", &src), [12, 13]);
    }

    #[test]
    fn routes_and_transparency() {
        let src = "namespace N;\n[Route(\"/orders/{Id:int}/{Day:datetime?}/{Name}\")]\nclass Order : ComponentBase {\n[Parameter] public string Id { get; set; }\n[Parameter] public DateTime? Day { get; set; }\n[Parameter] public string Name { get; set; }\n}\n[Route(\"/api/{id:int}\")]\nclass Api : Controller { public string Id { get; set; } }\n[SecuritySafeCritical] public class Foo { [SecurityCritical] public void Bar() { } [SecuritySafeCritical] public void Baz() { } }\npublic class Bar { [SecurityCritical] public void Qux() { } }";
        assert_eq!(flagged("cs/route-constraint-type", src), [4]);
        assert_eq!(flagged("cs/conflicting-transparency", src), [10]);
    }

    #[test]
    fn delegates_and_pure_calls() {
        let src = class(
            "void F(Action all, Action a, Action b, int x, int y, string s, DateTime d, ImmutableList<int> il, List<int> l) {\nall = all - (a + b);\nall -= a + b;\nvar z = x - (y + 1);\nall -= a;\ns.Trim();\ns = s.Trim();\nd.AddDays(1);\nil.Add(1);\nl.Add(1);\nl.Where(v => v > 0);\nl.Remove(1);\nAssert.All(l, v => { });\nl.Should().Contain(1);\nl.ToList();\n}",
        );
        assert_eq!(flagged("cs/delegate-chain-subtraction", &src), [4, 5]);
        // ImmutableList isn't imported here, so it doesn't resolve.
        assert_eq!(flagged("cs/ignored-pure-result", &src), [8, 10, 13, 17]);
    }

    #[test]
    fn streams_and_value_tasks() {
        let src = class(
            "async Task F(Stream stream, byte[] b, TextReader reader) {\nstream.Read(b, 0, b.Length);\nvar n = stream.Read(b, 0, b.Length);\nawait stream.ReadAsync(b, 0, 10);\nreader.Read(b, 0, 1);\nstream.ReadExactly(b, 0, 2);\nValueTask<int> vt = GetAsync();\nvar x = await vt;\nvar y = await vt;\nValueTask<int> once = GetAsync();\nvar z = await once;\nValueTask<int> blocked = GetAsync();\nvar w = blocked.Result;\nValueTask<int> checkedFirst = GetAsync();\nif (checkedFirst.IsCompletedSuccessfully) { var v = checkedFirst.Result; }\n}",
        );
        assert_eq!(flagged("cs/unchecked-stream-read", &src), [4, 6]);
        assert_eq!(flagged("cs/value-task-misuse", &src), [11, 15]);
    }

    #[test]
    fn foreach_and_casts() {
        let src = "namespace N;\nclass Fruit { }\nclass Orange : Fruit { }\nclass A {\nvoid F(List<object> objs, List<Fruit> fruits, IEnumerable<IShape> shapes, List<int> ints, int[] arr, int i, long l) {\nforeach (string s in objs) { }\nforeach (Orange o in fruits) { }\nforeach (Circle c in shapes) { }\nforeach (Fruit f in fruits) { }\nforeach (object x in fruits) { }\nforeach (var v in objs) { }\nforeach (long n in ints) { }\nvar a = (int)i;\nvar b = (long)i;\nvar c2 = (int)(i + 42);\nvar d = (int?)i;\nvar e = ints.OfType<int>();\nvar g = ints.Cast<long>();\n}\n}";
        // Collections of objects are left alone, as documented, and so are
        // types nothing declares.
        assert_eq!(flagged("cs/foreach-explicit-conversion", src), [7]);
        assert_eq!(flagged("cs/redundant-cast", src), [13, 15, 17]);
    }

    #[test]
    fn misc_apis() {
        let src = class(
            "void F(List<int> xs, int[] arr, IEnumerable<int> seq, SortedSet<int> set, LinkedList<int> linked, TraceSwitch sw) {\nvar a = xs.First();\nvar b = arr.Last();\nvar c = xs.ElementAt(2);\nvar d = seq.First();\nvar e = xs.First(x => x > 1);\nvar f = set.Min();\nvar g = set.Max(x => -x);\nvar h = linked.First();\nvar k = linked.Last();\nvar m = FormattableString.Invariant($\"{a}\");\nTrace.WriteLineIf(sw.TraceError, \"failed\");\nTrace.WriteLineIf(verbose, \"x\");\nvar z = TimeZoneInfo.FindSystemTimeZoneById(TZConvert.IanaToWindows(\"Asia/Tokyo\"));\nvar id = TZConvert.WindowsToIana(\"Tokyo Standard Time\");\nvar z2 = TimeZoneInfo.FindSystemTimeZoneById(id);\nvar z3 = TimeZoneInfo.FindSystemTimeZoneById(\"Asia/Tokyo\");\n}",
        );
        assert_eq!(flagged("cs/indexing-instead-of-linq", &src), [4, 5, 6]);
        assert_eq!(flagged("cs/set-min-max", &src), [9]);
        assert_eq!(flagged("cs/linked-list-first-last", &src), [11, 12]);
        assert_eq!(flagged("cs/use-string-create", &src), [13]);
        assert_eq!(flagged("cs/trace-if-switch-level", &src), [14]);
        assert_eq!(flagged("cs/timezone-converter", &src), [16, 18]);
    }

    /// Shapes found reviewing the rules on real code, none of them reported.
    #[test]
    fn corpus_false_positives() {
        // JsonReader.Skip() and a specification builder's Where() are no LINQ.
        let src = class(
            "void F(JsonReader reader, List<int> xs) {\nreader.Skip();\nQuery.Where(x => x.Id > 0);\nxs.OfType<int>().Any(x => x > 1);\n}",
        );
        assert_eq!(flagged("cs/ignored-pure-result", &src), [6]);
        // The file declares ParentDto as a struct in one place and a class in
        // another: which one a name means is unknown.
        let src = "namespace N;\nclass Structs { public struct ParentDto { } }\nclass Classes {\npublic class ParentDto { }\nParentDto a, b;\nbool F() => object.ReferenceEquals(a, b);\n}";
        assert_eq!(flagged("cs/reference-equals-value-type", src), [0usize; 0]);
    }
}
