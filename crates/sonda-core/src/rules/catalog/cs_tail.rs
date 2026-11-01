//! C# rules, batch 7 (ADR-0007, ADR-0015): the rest of SonarQube's default
//! profile that one file can answer, from regular expression syntax to the
//! identifiers C# 14 makes contextual keywords. Queries stay cheap on deep
//! trees: see the notes in `js_modern.rs`.

use super::cs::{CS_SCOPE_STOPS, cs_has_modifier, operand, simple_name};
use super::cs_bugs::{attribute_names, cs_call_arguments};
use super::cs_more::{enclosing_type, members};
use super::java_bugs::{find_in_scope, operator_text};
use super::java_security::{contains_ignoring_case, text};
use super::java_smells::count_word;
use super::*;
use crate::regex::{Flags, parse_java};

/// Rules that are off unless `rules.enabled` lists them (see
/// `catalog::OFF_BY_DEFAULT`).
pub(super) static OFF_BY_DEFAULT: &[&str] = &[];

pub(super) static RULES: &[Rule] = &[
    // ---- Bugs ----
    Rule {
        id: "cs/datetime-primary-key",
        name: "Dates should not be used as primary keys",
        description: "Two rows created in the same tick get the same key, and the value changes meaning with \
                      time zones and clock adjustments.",
        message: "Use a numeric or Guid key, and keep the date as an ordinary column.",
        category: Bug,
        severity: Minor,
        effort_minutes: 30,
        sonar: &[exact("S3363")],
        check: Check::Query {
            langs: CSHARP,
            query: "(property_declaration type: (_) name: (identifier)) @match",
            filter: Some(Find(date_key)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class Reading { [Key] public DateTime Taken { get; set; } }",
            good: "class Reading { public int Id { get; set; } public DateTime Taken { get; set; } }",
        }),
    },
    Rule {
        id: "cs/optional-not-passed-to-base",
        name: "Optional parameters should be passed on to base calls",
        description: "An override that calls `base.M(a)` without its own optional `b` makes the base use its \
                      default, whatever the caller passed.",
        message: "Pass this method's optional parameter on to the base call.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S3466")],
        check: Check::Query {
            langs: CSHARP,
            query: "(method_declaration (modifier) name: (identifier) parameters: (parameter_list) body: (_)) @match",
            filter: Some(Find(base_call_drops_optional)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class B : A { public override void Save(string path, bool force = false) { base.Save(path); } }",
            good: "class B : A { public override void Save(string path, bool force = false) { base.Save(path, force); } }",
        }),
    },
    Rule {
        id: "cs/invalid-regex",
        name: "Regular expressions should be syntactically valid",
        description: "An invalid pattern throws an ArgumentException when the Regex is created, often only on \
                      the code path that tests miss.",
        message: "Fix this regular expression.",
        category: Bug,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[related("S5856")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(object_creation_expression arguments: (argument_list)) \
                     (invocation_expression function: (member_access_expression))] @match",
            filter: Some(Find(invalid_regex)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { bool F(string s) { return Regex.IsMatch(s, \"(ab\"); } }",
            good: "class A { bool F(string s) { return Regex.IsMatch(s, \"(ab)\"); } }",
        }),
    },
    // ---- Vulnerabilities ----
    Rule {
        id: "cs/unsafe-csp",
        name: "Content Security Policies should be restrictive",
        description: "'unsafe-inline', 'unsafe-eval' and wildcard sources let injected scripts run, which is \
                      what the policy is there to stop.",
        message: "Remove 'unsafe-inline', 'unsafe-eval' and '*' from this policy.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 15,
        sonar: &[exact("S7039")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(invocation_expression function: (member_access_expression)) \
                     (assignment_expression left: (element_access_expression))] @match",
            filter: Some(Keep(permissive_csp)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(HttpResponse r) { r.Headers.Append(\"Content-Security-Policy\", \"script-src 'self' 'unsafe-inline'\"); } }",
            good: "class A { void F(HttpResponse r) { r.Headers.Append(\"Content-Security-Policy\", \"script-src 'self'\"); } }",
        }),
    },
    Rule {
        id: "cs/xml-signature-unverified-key",
        name: "XML signatures should be checked against a trusted key",
        description: "SignedXml.CheckSignature() without arguments trusts the key embedded in the document, so \
                      anyone can sign a forged document with their own key.",
        message: "Pass the trusted key or certificate to CheckSignature.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 15,
        sonar: &[related("S6377")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(invocation_expression
                        function: (member_access_expression name: (identifier) @n)
                        arguments: (argument_list) @a
                        (#eq? @n "CheckSignature")) @match"#,
            filter: Some(Keep(checks_with_embedded_key)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { bool F(SignedXml xml) { return xml.CheckSignature(); } }",
            good: "class A { bool F(SignedXml xml, AsymmetricAlgorithm key) { return xml.CheckSignature(key); } }",
        }),
    },
    // ---- Code smells ----
    Rule {
        id: "cs/unchecked-sum",
        name: "Overflow checking should not be disabled for Sum",
        description: "Enumerable.Sum throws on overflow on purpose; inside `unchecked` that protection still \
                      applies, so the block suggests a wrap-around that won't happen.",
        message: "Remove 'unchecked' around this Sum, or handle the overflow explicitly.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S2291")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(checked_expression) (checked_statement)] @match",
            filter: Some(Find(sum_in_unchecked)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int F(int[] xs) { return unchecked(xs.Sum()); } }",
            good: "class A { int F(int[] xs) { return xs.Sum(); } }",
        }),
    },
    Rule {
        id: "cs/caller-info-passed",
        name: "Caller information arguments should not be passed explicitly",
        description: "[CallerMemberName] and the like fill in the caller's details; passing a value replaces them \
                      with whatever was written, which drifts as code moves.",
        message: "Leave this argument out so the compiler supplies it.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S3236")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration body: (declaration_list)) @match",
            filter: Some(Find(explicit_caller_info)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void Log(string m, [CallerMemberName] string c = \"\") { } void F() { Log(\"x\", \"F\"); } }",
            good: "class A { void Log(string m, [CallerMemberName] string c = \"\") { } void F() { Log(\"x\"); } }",
        }),
    },
    Rule {
        id: "cs/bitwise-on-non-flags-enum",
        name: "Bitwise operations should only combine [Flags] enums",
        description: "Values of an enum without [Flags] aren't bits; `Color.Red | Color.Blue` is just another \
                      number, possibly another member.",
        message: "Mark this enum [Flags] with power-of-two values, or don't combine its members.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[related("S3265")],
        check: Check::Query {
            langs: CSHARP,
            query: "(compilation_unit) @match",
            filter: Some(Find(non_flags_bitwise)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "enum Color { Red, Green, Blue } class A { Color F() => Color.Red | Color.Blue; }",
            good: "[Flags] enum Colors { None = 0, Red = 1, Green = 2, Blue = 4 } class A { Colors F() => Colors.Red | Colors.Blue; }",
        }),
    },
    Rule {
        id: "cs/array-for-params",
        name: "Arrays should not be created for params parameters",
        description: "A `params` parameter takes the values themselves; wrapping them in `new[] { ... }` is \
                      noise.",
        message: "Pass the values directly instead of creating an array.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[related("S3878")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration body: (declaration_list)) @match",
            filter: Some(Find(array_passed_to_params)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void Log(params string[] parts) { } void F() { Log(new[] { \"a\", \"b\" }); } }",
            good: "class A { void Log(params string[] parts) { } void F() { Log(\"a\", \"b\"); } }",
        }),
    },
    Rule {
        id: "cs/arglist",
        name: "params should be used instead of __arglist",
        description: "`__arglist` is an undocumented, non-CLS feature; `params` arrays do the same in a way \
                      every .NET language and tool understands.",
        message: "Use a params array instead of __arglist.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 10,
        sonar: &[exact("S4061")],
        check: Check::Query {
            langs: CSHARP,
            query: "(parameter_list) @match",
            filter: Some(Keep(declares_arglist)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void Log(string f, __arglist) { } }",
            good: "class A { void Log(string f, params object[] args) { } }",
        }),
    },
    Rule {
        id: "cs/azure-function-static-state",
        name: "Azure Functions should be stateless",
        description: "Static state is shared by every invocation on an instance and lost when the host scales \
                      out or restarts, so results depend on which instance ran.",
        message: "Keep this state in a store, not in a static field.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 15,
        sonar: &[exact("S6419")],
        check: Check::Query {
            langs: CSHARP,
            query: "(method_declaration (attribute_list) body: (_)) @match",
            filter: Some(Find(function_writes_static)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class F { static int calls; [FunctionName(\"Run\")] public void Run() { calls++; } }",
            good: "class F { [FunctionName(\"Run\")] public void Run(ICounter counter) { counter.Increment(); } }",
        }),
    },
    Rule {
        id: "cs/order-before-where",
        name: "Collections should be filtered before they're sorted",
        description: "`OrderBy(...).Where(...)` sorts elements the filter then throws away; filtering first \
                      sorts fewer.",
        message: "Call Where before OrderBy.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6607")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(invocation_expression
                        function: (member_access_expression
                          expression: (invocation_expression
                            function: (member_access_expression name: (identifier) @o))
                          name: (identifier) @w)
                        (#match? @o "^(OrderBy|OrderByDescending|ThenBy|ThenByDescending)$")
                        (#eq? @w "Where")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { object F(int[] xs) { return xs.OrderBy(x => x).Where(x => x > 0); } }",
            good: "class A { object F(int[] xs) { return xs.Where(x => x > 0).OrderBy(x => x); } }",
        }),
    },
    Rule {
        id: "cs/concurrent-dictionary-capture",
        name: "ConcurrentDictionary factories should use their key parameter",
        description: "A factory lambda that ignores its key and uses a captured variable instead allocates a \
                      closure on every call; the key parameter is the same value.",
        message: "Use the lambda's key parameter instead of the captured variable.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6612")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(invocation_expression
                        function: (member_access_expression name: (identifier) @n)
                        (#any-of? @n "GetOrAdd" "AddOrUpdate")) @match"#,
            filter: Some(Find(factory_captures_key)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { object F(ConcurrentDictionary<string, int> d, string key) { return d.GetOrAdd(key, k => key.Length); } }",
            good: "class A { object F(ConcurrentDictionary<string, int> d, string key) { return d.GetOrAdd(key, k => k.Length); } }",
        }),
    },
    Rule {
        id: "cs/blocking-call-in-async",
        name: "Async methods should await, not block",
        description: "`.Result`, `.Wait()` and Thread.Sleep in an async method hold a thread while waiting and \
                      can deadlock; the awaitable form doesn't.",
        message: "Await the asynchronous version (await t, await Task.Delay) instead.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[related("S6966")],
        check: Check::Query {
            langs: CSHARP,
            query: "(method_declaration (modifier) body: (_)) @match",
            filter: Some(Find(blocks_in_async)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { async Task F() { Thread.Sleep(100); await G(); } }",
            good: "class A { async Task F() { await Task.Delay(100); await G(); } }",
        }),
    },
    Rule {
        id: "cs/modelstate-not-checked",
        name: "Controller actions that accept input should check ModelState.IsValid",
        description: "Model binding records validation errors instead of throwing; an action that doesn't check \
                      ModelState goes on with invalid input. [ApiController] does it automatically.",
        message: "Check ModelState.IsValid before using this action's input.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[related("S6967")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration name: (identifier) (base_list) body: (declaration_list)) @match",
            filter: Some(Find(unchecked_post_action)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class OrdersController : Controller { [HttpPost] public IActionResult Create(Order o) { Save(o); return Ok(); } }",
            good: "class OrdersController : Controller { [HttpPost] public IActionResult Create(Order o) { if (!ModelState.IsValid) { return BadRequest(); } Save(o); return Ok(); } }",
        }),
    },
    Rule {
        id: "cs/field-keyword-conflict",
        name: "Identifiers in property accessors should not be named field",
        description: "Since C# 14, `field` in an accessor means the property's backing field, so a local, \
                      parameter or member named `field` changes meaning there.",
        message: "Rename this, or write @field to keep the old meaning.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 2,
        sonar: &[exact("S8367")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"((identifier) @match (#eq? @match "field"))"#,
            filter: Some(Keep(field_inside_accessor)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int field; public int X { get { return field; } } }",
            good: "class A { int value_; public int X { get { return value_; } } }",
        }),
    },
    Rule {
        id: "cs/extension-keyword-conflict",
        name: "Types should not be named extension",
        description: "Since C# 14, `extension` starts an extension block, so a type with that name needs \
                      escaping as @extension.",
        message: "Rename this type, or write @extension.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 2,
        sonar: &[exact("S8368")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"[(class_declaration name: (identifier) @match) (struct_declaration name: (identifier) @match)
                       (interface_declaration name: (identifier) @match) (record_declaration name: (identifier) @match)
                       (enum_declaration name: (identifier) @match) (delegate_declaration name: (identifier) @match)]"#,
            filter: Some(Keep(is_named_extension)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class extension { }",
            good: "class Extension { }",
        }),
    },
    Rule {
        id: "cs/partial-return-type",
        name: "Return types named partial should be escaped",
        description: "Since C# 14, `partial` before a method name starts a partial member, so a return type \
                      named `partial` must be written @partial.",
        message: "Write @partial for this return type.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 1,
        sonar: &[exact("S8380")],
        check: Check::Query {
            langs: CSHARP,
            // The grammar reads `partial Make()` as a partial constructor named
            // Make: one whose name isn't the class's is such a method.
            query: "(constructor_declaration (modifier) name: (identifier) @match)",
            filter: Some(Keep(is_partial_returning_method)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { partial Make() => null; }",
            good: "class A { @partial Make() => null; }",
        }),
    },
    Rule {
        id: "cs/scoped-lambda-parameter",
        name: "Lambda parameters named scoped should be escaped",
        description: "Since C# 14, `scoped` in a parenthesized lambda parameter list is a modifier, so a \
                      parameter or type named `scoped` must be written @scoped.",
        message: "Rename this, or write @scoped.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 1,
        sonar: &[exact("S8381")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(lambda_expression parameters: (parameter_list (parameter) @match))"#,
            filter: Some(Keep(mentions_scoped)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F() { Func<int, int> f = (int scoped) => scoped; } }",
            good: "class A { void F() { Func<int, int> f = (int @scoped) => @scoped; } }",
        }),
    },
];

// ---------------------------------------------------- filters

fn date_key<'t>(property: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let ty = property.child_by_field_name("type")?;
    let t = text(ty, src);
    let t = t.strip_suffix(b"?").unwrap_or(t);
    if !matches!(
        t,
        b"DateTime" | b"DateTimeOffset" | b"System.DateTime" | b"System.DateTimeOffset"
    ) {
        return None;
    }
    let keyed = attribute_names(property, src)
        .iter()
        .any(|(_, n)| *n == b"Key");
    // EF Core's convention: a property named Id, or <Class>Id.
    let name = text(property.child_by_field_name("name")?, src);
    let class_name = enclosing_type(property)
        .and_then(|c| c.child_by_field_name("name"))
        .map(|n| text(n, src));
    let conventional = name == b"Id" || class_name.is_some_and(|c| name == [c, b"Id"].concat());
    (keyed || conventional).then_some(ty)
}

fn base_call_drops_optional<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !cs_has_modifier(method, "override", src) {
        return None;
    }
    let name = text(method.child_by_field_name("name")?, src);
    let params = method.child_by_field_name("parameters")?;
    let mut cursor = params.walk();
    let list: Vec<Node> = params
        .named_children(&mut cursor)
        .filter(|p| p.kind() == "parameter")
        .collect();
    let optional: Vec<&[u8]> = list
        .iter()
        .filter(|p| text(**p, src).contains(&b'='))
        .filter_map(|p| p.child_by_field_name("name").map(|n| text(n, src)))
        .collect();
    if optional.is_empty() {
        return None;
    }
    let body = method.child_by_field_name("body")?;
    find_in_scope(body, CS_SCOPE_STOPS, |n| {
        n.kind() == "invocation_expression"
            && n.child_by_field_name("function")
                .is_some_and(|f| text(f, src).strip_prefix(b"base.") == Some(name))
            && cs_call_arguments(n).len() < list.len()
            && {
                let args = text(n.child_by_field_name("arguments").unwrap_or(n), src);
                optional.iter().any(|o| count_word(args, o) == 0)
            }
    })
}

/// A C# string literal's value: escapes decoded for regular strings, `""`
/// for verbatim ones. None for interpolated strings and unknown escapes.
fn decoded_string(node: Node, src: &[u8]) -> Option<String> {
    let t = std::str::from_utf8(text(node, src)).ok()?;
    match node.kind() {
        "verbatim_string_literal" => {
            let inner = t.strip_prefix("@\"")?.strip_suffix('"')?;
            Some(inner.replace("\"\"", "\""))
        }
        "string_literal" => {
            let inner = t.strip_prefix('"')?.strip_suffix('"')?;
            let mut out = String::new();
            let mut chars = inner.chars();
            while let Some(c) = chars.next() {
                if c != '\\' {
                    out.push(c);
                    continue;
                }
                match chars.next()? {
                    '\\' => out.push('\\'),
                    '"' => out.push('"'),
                    '\'' => out.push('\''),
                    'n' => out.push('\n'),
                    't' => out.push('\t'),
                    'r' => out.push('\r'),
                    '0' => out.push('\0'),
                    'u' => {
                        let hex: String = (0..4).filter_map(|_| chars.next()).collect();
                        out.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
                    }
                    _ => return None,
                }
            }
            Some(out)
        }
        _ => None,
    }
}

/// .NET-only regex syntax the Java parser doesn't know: class subtraction,
/// balancing and quote-named groups, and the `n` (explicit capture) option.
fn uses_dotnet_only_syntax(pattern: &str) -> bool {
    pattern.contains("-[")
        || pattern.contains("(?'")
        || pattern.contains("\\k'")
        || pattern.contains("(?n")
        || pattern.contains("(?x")
        || pattern.match_indices("(?<").any(|(i, _)| {
            pattern[i + 3..]
                .chars()
                .take_while(|c| *c != '>')
                .any(|c| c == '-')
        })
}

fn invalid_regex<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let args = cs_call_arguments(node);
    let pattern = if node.kind() == "object_creation_expression" {
        let is_regex = node
            .child_by_field_name("type")
            .is_some_and(|t| simple_name(t, src) == b"Regex");
        if !is_regex {
            return None;
        }
        *args.first()?
    } else {
        let function = node.child_by_field_name("function")?;
        let receiver = function
            .child_by_field_name("expression")
            .map(|e| simple_name(e, src));
        let method = function.child_by_field_name("name").map(|n| text(n, src));
        if receiver != Some(b"Regex")
            || !matches!(
                method,
                Some(b"IsMatch" | b"Match" | b"Matches" | b"Replace" | b"Split" | b"Count")
            )
        {
            return None;
        }
        // Static calls take (input, pattern, ...).
        *args.get(1)?
    };
    let value = decoded_string(pattern, src)?;
    // RegexOptions.IgnorePatternWhitespace changes how the pattern reads.
    let ignores_whitespace = args
        .iter()
        .any(|a| contains_ignoring_case(text(*a, src), b"IgnorePatternWhitespace"));
    if uses_dotnet_only_syntax(&value) || ignores_whitespace {
        return None;
    }
    parse_java(&value, Flags::default())
        .is_err()
        .then_some(pattern)
}

fn permissive_csp(node: Node, src: &[u8]) -> bool {
    let is_csp_name = |n: Node| {
        super::cs::cs_string_value(n, src)
            .is_some_and(|v| v.eq_ignore_ascii_case(b"Content-Security-Policy"))
    };
    let unsafe_value = |n: Node| {
        super::cs::cs_string_value(n, src).is_some_and(|v| {
            contains_ignoring_case(v, b"'unsafe-inline'")
                || contains_ignoring_case(v, b"'unsafe-eval'")
                || v.split(|b| *b == b' ' || *b == b';').any(|w| w == b"*")
        })
    };
    if node.kind() == "assignment_expression" {
        let key = node
            .child_by_field_name("left")
            .and_then(|l| l.child_by_field_name("subscript"))
            .and_then(|s| s.named_child(0))
            .and_then(|a| a.named_child(0));
        return key.is_some_and(is_csp_name)
            && node.child_by_field_name("right").is_some_and(unsafe_value);
    }
    let method = node
        .child_by_field_name("function")
        .and_then(|f| f.child_by_field_name("name"))
        .map(|n| text(n, src));
    matches!(
        method,
        Some(b"Add" | b"Append" | b"TryAdd" | b"AddHeader" | b"AppendHeader")
    ) && matches!(cs_call_arguments(node).as_slice(), [k, v] if is_csp_name(*k) && unsafe_value(*v))
}

fn checks_with_embedded_key(call: Node, _: &[u8]) -> bool {
    call.child_by_field_name("arguments")
        .is_some_and(|a| a.named_child_count() == 0)
}

fn sum_in_unchecked<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !text(node, src).starts_with(b"unchecked") {
        return None;
    }
    find_in_scope(node, CS_SCOPE_STOPS, |n| {
        n.kind() == "invocation_expression"
            && n.child_by_field_name("function")
                .and_then(|f| f.child_by_field_name("name"))
                .is_some_and(|m| text(m, src) == b"Sum")
    })
}

const CALLER_INFO: &[&[u8]] = &[
    b"CallerMemberName",
    b"CallerFilePath",
    b"CallerLineNumber",
    b"CallerArgumentExpression",
];

fn explicit_caller_info<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    // Methods of this class with caller information parameters: name, and the
    // position of the first such parameter.
    let methods: Vec<(&[u8], usize)> = members(class)
        .into_iter()
        .filter(|m| m.kind() == "method_declaration")
        .filter_map(|m| {
            let params = m.child_by_field_name("parameters")?;
            let mut c = params.walk();
            let position = params
                .named_children(&mut c)
                .filter(|p| p.kind() == "parameter")
                .position(|p| {
                    attribute_names(p, src)
                        .iter()
                        .any(|(_, n)| CALLER_INFO.contains(n))
                })?;
            Some((text(m.child_by_field_name("name")?, src), position))
        })
        .collect();
    if methods.is_empty() {
        return None;
    }
    let body = class.child_by_field_name("body")?;
    find_in_scope(body, &[], |n| {
        if n.kind() != "invocation_expression" {
            return false;
        }
        let Some(name) = n.child_by_field_name("function").map(|f| {
            let t = text(f, src);
            t.strip_prefix(b"this.").unwrap_or(t)
        }) else {
            return false;
        };
        let args = cs_call_arguments(n);
        // Named arguments are deliberate; positional ones that reach the
        // caller information parameter replace it.
        let positional = args
            .iter()
            .filter(|a| {
                a.parent()
                    .is_none_or(|p| p.child_by_field_name("name").is_none())
            })
            .count();
        methods
            .iter()
            .any(|(m, position)| *m == name && positional > *position)
    })
}

fn non_flags_bitwise<'t>(unit: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    // Enums declared in this file without [Flags].
    let mut enums: Vec<&[u8]> = Vec::new();
    let mut stack = vec![unit];
    while let Some(n) = stack.pop() {
        if n.kind() == "enum_declaration" {
            let flags = attribute_names(n, src).iter().any(|(_, a)| *a == b"Flags");
            if !flags && let Some(name) = n.child_by_field_name("name") {
                enums.push(text(name, src));
            }
            continue;
        }
        if matches!(n.kind(), "method_declaration" | "block") {
            continue;
        }
        let mut c = n.walk();
        stack.extend(n.named_children(&mut c));
    }
    if enums.is_empty() {
        return None;
    }
    let is_member = |n: Option<Node>| {
        n.is_some_and(|n| {
            n.kind() == "member_access_expression"
                && n.child_by_field_name("expression")
                    .is_some_and(|e| enums.contains(&simple_name(e, src)))
        })
    };
    find_in_scope(unit, &[], |n| {
        n.kind() == "binary_expression"
            && matches!(operator_text(n, src), b"|" | b"&" | b"^")
            && is_member(n.child_by_field_name("left"))
            && is_member(n.child_by_field_name("right"))
    })
}

fn array_passed_to_params<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    // Methods of this class whose last parameter is `params`, by name and
    // the number of parameters before it.
    let methods: Vec<(&[u8], usize)> = members(class)
        .into_iter()
        .filter(|m| m.kind() == "method_declaration")
        .filter_map(|m| {
            // tree-sitter-c-sharp puts a `params T[] x` parameter's type and
            // name on the list itself, not in a `parameter` node.
            let params = m.child_by_field_name("parameters")?;
            if count_word(text(params, src), b"params") == 0 {
                return None;
            }
            let mut c = params.walk();
            let before = params
                .named_children(&mut c)
                .filter(|p| p.kind() == "parameter")
                .count();
            Some((text(m.child_by_field_name("name")?, src), before))
        })
        .collect();
    if methods.is_empty() {
        return None;
    }
    let body = class.child_by_field_name("body")?;
    find_in_scope(body, &[], |n| {
        if n.kind() != "invocation_expression" {
            return false;
        }
        let name = n.child_by_field_name("function").map(|f| text(f, src));
        let args = cs_call_arguments(n);
        methods.iter().any(|(m, before)| {
            Some(*m) == name
                && args.len() == before + 1
                && args.last().is_some_and(|a| {
                    matches!(a.kind(), "implicit_array_creation_expression")
                        || a.kind() == "array_creation_expression" && a.named_child_count() >= 2
                })
        })
    })
}

fn declares_arglist(list: Node, src: &[u8]) -> bool {
    count_word(text(list, src), b"__arglist") > 0
}

fn function_writes_static<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let function = attribute_names(method, src)
        .iter()
        .any(|(_, n)| matches!(*n, b"FunctionName" | b"Function"));
    if !function {
        return None;
    }
    let class = enclosing_type(method)?;
    let statics: Vec<&[u8]> = members(class)
        .into_iter()
        .filter(|m| {
            m.kind() == "field_declaration"
                && cs_has_modifier(*m, "static", src)
                && !cs_has_modifier(*m, "readonly", src)
                && !cs_has_modifier(*m, "const", src)
        })
        .flat_map(super::cs_more::declarators)
        .filter_map(|d| d.child_by_field_name("name").map(|n| text(n, src)))
        .collect();
    if statics.is_empty() {
        return None;
    }
    let body = method.child_by_field_name("body")?;
    let target = |t: Node| statics.contains(&text(t, src));
    find_in_scope(body, CS_SCOPE_STOPS, |n| match n.kind() {
        "assignment_expression" => n.child_by_field_name("left").is_some_and(target),
        "postfix_unary_expression" | "prefix_unary_expression" => {
            let t = text(n, src);
            (t.contains(&b'+') || t.contains(&b'-')) && operand(n).is_some_and(target)
        }
        _ => false,
    })
}

fn factory_captures_key<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let args = cs_call_arguments(call);
    let key = args.first().filter(|k| k.kind() == "identifier")?;
    let key_name = text(*key, src);
    args.iter().skip(1).find_map(|a| {
        if a.kind() != "lambda_expression" {
            return None;
        }
        let param_text = text(a.child_by_field_name("parameters")?, src);
        let body = text(a.child_by_field_name("body")?, src);
        (count_word(body, key_name) > 0 && count_word(param_text, key_name) == 0).then_some(*a)
    })
}

/// Without types, `.Result` and `.Wait()` are only known to block when the
/// receiver visibly is a task: an `...Async(...)` call, a `Task.` call, or a
/// variable named like one.
pub(super) fn looks_like_task(receiver: Node, src: &[u8]) -> bool {
    let t = text(receiver, src);
    if receiver.kind() == "invocation_expression" {
        let name = receiver
            .child_by_field_name("function")
            .map(|f| super::cs::simple_name(f, src))
            .unwrap_or_default();
        return name.ends_with(b"Async") || t.starts_with(b"Task.");
    }
    let lower = simple_name(receiver, src).to_ascii_lowercase();
    lower == b"t" || lower.ends_with(b"task") || lower.ends_with(b"tasks")
}

/// `await Task.WhenAll(a, b); var x = a.Result;` reads a finished task.
pub(super) fn awaited_by_when_all(body: Node, task: Node, read: Node, src: &[u8]) -> bool {
    let name = text(task, src);
    find_in_scope(body, CS_SCOPE_STOPS, |n| {
        n.kind() == "invocation_expression"
            && n.end_byte() <= read.start_byte()
            && n.child_by_field_name("function")
                .is_some_and(|f| text(f, src).ends_with(b"WhenAll"))
            && cs_call_arguments(n).iter().any(|a| text(*a, src) == name)
    })
    .is_some()
}

fn blocks_in_async<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !cs_has_modifier(method, "async", src) {
        return None;
    }
    let body = method.child_by_field_name("body")?;
    find_in_scope(body, CS_SCOPE_STOPS, |n| match n.kind() {
        "member_access_expression" => {
            n.child_by_field_name("name")
                .is_some_and(|m| text(m, src) == b"Result")
                && n.child_by_field_name("expression").is_some_and(|r| {
                    looks_like_task(r, src) && !awaited_by_when_all(body, r, n, src)
                })
        }
        "invocation_expression" => n.child_by_field_name("function").is_some_and(|f| {
            if text(f, src) == b"Thread.Sleep" {
                return true;
            }
            let method = f.child_by_field_name("name").map(|m| text(m, src));
            let receiver = f.child_by_field_name("expression");
            match method {
                Some(b"Wait") => {
                    receiver.is_some_and(|r| looks_like_task(r, src))
                        && cs_call_arguments(n).is_empty()
                }
                // t.GetAwaiter().GetResult()
                Some(b"GetResult") => {
                    receiver.is_some_and(|r| text(r, src).ends_with(b".GetAwaiter()"))
                }
                _ => false,
            }
        }),
        _ => false,
    })
}

fn unchecked_post_action<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut cursor = class.walk();
    let is_controller = class
        .named_children(&mut cursor)
        .filter(|c| c.kind() == "base_list")
        .any(|b| {
            count_word(text(b, src), b"Controller") > 0
                || count_word(text(b, src), b"ControllerBase") > 0
        });
    // [ApiController] returns 400 for invalid models by itself.
    if !is_controller
        || attribute_names(class, src)
            .iter()
            .any(|(_, n)| *n == b"ApiController")
    {
        return None;
    }
    members(class).into_iter().find_map(|m| {
        if m.kind() != "method_declaration" || !cs_has_modifier(m, "public", src) {
            return None;
        }
        let posts = attribute_names(m, src)
            .iter()
            .any(|(_, n)| matches!(*n, b"HttpPost" | b"HttpPut" | b"HttpPatch"));
        let takes_input = m
            .child_by_field_name("parameters")
            .is_some_and(|p| p.named_child_count() > 0);
        let checks = m
            .child_by_field_name("body")
            .is_some_and(|b| contains_ignoring_case(text(b, src), b"ModelState"));
        (posts && takes_input && !checks).then(|| m.child_by_field_name("name"))?
    })
}

fn field_inside_accessor(name: Node, src: &[u8]) -> bool {
    // Inside a property accessor?
    let mut current = name.parent();
    let mut accessor = None;
    for _ in 0..64 {
        match current {
            Some(n) if n.kind() == "accessor_declaration" => {
                accessor = Some(n);
                break;
            }
            Some(n)
                if matches!(
                    n.kind(),
                    "class_declaration" | "struct_declaration" | "method_declaration"
                ) =>
            {
                return false;
            }
            Some(n) => current = n.parent(),
            None => return false,
        }
    }
    let Some(accessor) = accessor else {
        return false;
    };
    // A local or parameter named field declared there, or a use of a member
    // named field, which C# 14 reads as the backing field instead.
    let declares = name.parent().is_some_and(|p| {
        matches!(p.kind(), "variable_declarator" | "parameter")
            && p.child_by_field_name("name") == Some(name)
    });
    if declares {
        return true;
    }
    let is_member_name = name.parent().is_some_and(|p| {
        p.kind() == "member_access_expression" && p.child_by_field_name("name") == Some(name)
    });
    !is_member_name
        && enclosing_type(accessor).is_some_and(|t| {
            members(t).iter().any(|m| match m.kind() {
                "field_declaration" => super::cs_more::declarators(*m).iter().any(|d| {
                    d.child_by_field_name("name")
                        .is_some_and(|n| text(n, src) == b"field")
                }),
                "property_declaration" => m
                    .child_by_field_name("name")
                    .is_some_and(|n| text(n, src) == b"field"),
                _ => false,
            })
        })
}

fn is_partial_returning_method(name: Node, src: &[u8]) -> bool {
    let Some(constructor) = name.parent() else {
        return false;
    };
    let class_name = constructor
        .parent()
        .and_then(|b| b.parent())
        .and_then(|c| c.child_by_field_name("name"))
        .map(|n| text(n, src));
    cs_has_modifier(constructor, "partial", src) && class_name != Some(text(name, src))
}

fn is_named_extension(name: Node, src: &[u8]) -> bool {
    text(name, src) == b"extension"
}

fn mentions_scoped(parameter: Node, src: &[u8]) -> bool {
    let t = text(parameter, src);
    // `scoped` as the name or the type, not as the modifier `scoped ref`.
    parameter
        .child_by_field_name("name")
        .is_some_and(|n| text(n, src) == b"scoped")
        || parameter
            .child_by_field_name("type")
            .is_some_and(|ty| text(ty, src) == b"scoped")
            && !t.starts_with(b"scoped ref")
}

#[cfg(test)]
mod tests {
    use super::super::cs::tests::flagged;
    use super::{decoded_string, uses_dotnet_only_syntax};

    fn method(body: &str) -> String {
        format!("namespace N;\nclass A {{\nvoid F() {{\n{body}\n}}\n}}\n")
    }

    #[test]
    fn divisions_keys_and_base_calls() {
        let src = "namespace N;\nclass A : B {\nvoid F() { double a = 1 / 3; double b = 1.0 / 3; int c = 1 / 3; float d = (2 / 4); }\n[Key] public DateTime Taken { get; set; }\npublic DateTime Id { get; set; }\npublic DateTime Created { get; set; }\npublic override void Save(string p, bool force = false) { base.Save(p); }\npublic override void Load(string p, bool force = false) { base.Load(p, force); }\n}";
        assert_eq!(flagged("cs/datetime-primary-key", src), [4, 5]);
        assert_eq!(flagged("cs/optional-not-passed-to-base", src), [7]);
    }

    #[test]
    fn regexes() {
        assert_eq!(decoded_string_of("\"a\\\\d\""), Some("a\\d".to_string()));
        assert!(uses_dotnet_only_syntax("[a-z-[aeiou]]"));
        assert!(uses_dotnet_only_syntax("(?<open-close>x)"));
        assert!(!uses_dotnet_only_syntax("(?<name>x)"));
        let src = method(
            "Regex.IsMatch(s, \"(ab\");\nRegex.IsMatch(s, \"(ab)\");\nnew Regex(@\"[a-z\");\nnew Regex(@\"[a-z-[aeiou]]\");\nnew Regex(\"\\\\d+\");\nRegex.Replace(s, \"*x\", \"y\");\nnew Regex(\"# comment (\", RegexOptions.IgnorePatternWhitespace);",
        );
        assert_eq!(flagged("cs/invalid-regex", &src), [4, 6, 9]);
    }

    fn decoded_string_of(literal: &str) -> Option<String> {
        let src = format!("class A {{ string s = {literal}; }}");
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&crate::lang::Lang::CSharp.grammar())
            .unwrap();
        let tree = parser.parse(&src, None).unwrap();
        let mut found = None;
        let mut stack = vec![tree.root_node()];
        while let Some(n) = stack.pop() {
            if n.kind() == "string_literal" {
                found = decoded_string(n, src.as_bytes());
            }
            let mut c = n.walk();
            stack.extend(n.named_children(&mut c));
        }
        found
    }

    #[test]
    fn security() {
        let src = method(
            "r.Headers.Append(\"Content-Security-Policy\", \"script-src 'self' 'unsafe-inline'\");\nr.Headers.Append(\"Content-Security-Policy\", \"script-src 'self'\");\nr.Headers[\"Content-Security-Policy\"] = \"default-src *\";\nvar ok = xml.CheckSignature();\nvar good = xml.CheckSignature(key);",
        );
        assert_eq!(flagged("cs/unsafe-csp", &src), [4, 6]);
        assert_eq!(flagged("cs/xml-signature-unverified-key", &src), [7]);
    }

    #[test]
    fn sums_caller_info_params() {
        let src = "namespace N;\nclass A {\nvoid Log(string m, [CallerMemberName] string c = \"\") { }\nvoid Many(int a, params string[] parts) { }\nvoid F() {\nvar x = unchecked(xs.Sum());\nunchecked { y = ys.Sum(); }\nvar z = unchecked(a + b);\nLog(\"x\", \"F\");\nLog(\"x\");\nLog(\"x\", c: \"F\");\nMany(1, new[] { \"a\", \"b\" });\nMany(1, \"a\", \"b\");\nMany(1, new string[0]);\n}\nvoid G(__arglist) { }\n}";
        assert_eq!(flagged("cs/unchecked-sum", src), [6, 7]);
        assert_eq!(flagged("cs/caller-info-passed", src), [9]);
        assert_eq!(flagged("cs/array-for-params", src), [12]);
        assert_eq!(flagged("cs/arglist", src), [16]);
    }

    #[test]
    fn enums_loops_constants() {
        let src = "namespace N;\nenum Color { Red, Blue }\n[Flags] enum Access { None = 0, Read = 1, Write = 2 }\nclass A {\nobject F() => Color.Red | Color.Blue;\nobject G() => Access.Read | Access.Write;\nvoid H(int[] xs) {\nforeach (var x in xs) { if (x > 0) { G(x); } }\nforeach (var x in xs) { if (x > 0) { return; } }\nforeach (var x in xs) { if (x > 0) { G(x); } else { H(x); } }\n}\nprivate int Limit() { return 10; }\nprivate int Twice(int x) => x * 2;\npublic string Name() => \"a\";\nprivate override int K() => 1;\n}";
        assert_eq!(flagged("cs/bitwise-on-non-flags-enum", src), [5]);
    }

    #[test]
    fn functions_linq_async() {
        let src = "namespace N;\nclass F {\nstatic int calls;\nstatic readonly int max = 1;\n[FunctionName(\"Run\")] public void Run() { calls++; }\n[FunctionName(\"Go\")] public int Go() => max;\nvoid L() {\nvar a = xs.OrderBy(x => x).Where(x => x > 0);\nvar b = xs.Where(x => x > 0).OrderBy(x => x);\nd.GetOrAdd(key, k => key.Length);\nd.GetOrAdd(key, k => k.Length);\n}\nasync Task A() { Thread.Sleep(10); var r = t.Result; t.Wait(); await Task.Delay(1); }\nTask B() { Thread.Sleep(10); return t; }\nasync Task C() { var r = outcome.Result; var s = GetAsync().Result; await Task.Delay(1); }\nasync Task D() { await Task.WhenAll(aTask, bTask); var a = aTask.Result; }\n}";
        assert_eq!(flagged("cs/azure-function-static-state", src), [5]);
        assert_eq!(flagged("cs/order-before-where", src), [8]);
        assert_eq!(flagged("cs/concurrent-dictionary-capture", src), [10]);
        assert_eq!(flagged("cs/blocking-call-in-async", src), [13, 15]);
    }

    #[test]
    fn controllers() {
        let src = "namespace N;\nclass OrdersController : Controller {\n[HttpPost] public IActionResult Create(Order o) { Save(o); return Ok(); }\n[HttpPost] public IActionResult Update(Order o) { if (!ModelState.IsValid) { return BadRequest(); } return Ok(); }\n[HttpGet] public IActionResult Get(int id) => Ok();\n}\n[ApiController] class ApiOrdersController : ControllerBase { [HttpPost] public IActionResult Create(Order o) => Ok(); }";
        assert_eq!(flagged("cs/modelstate-not-checked", src), [3]);
    }

    #[test]
    fn csharp_14_keywords() {
        let src = "namespace N;\nclass extension { }\nclass A {\nint field;\npublic int X { get { var field = 1; return field; } }\npublic int Y { get { return field; } }\nvoid M(int field) { }\nprivate partial Make() => null;\nvoid L() { Func<int, int> f = (int scoped) => scoped; Func<int, int> g = (int x) => x; }\n}";
        assert_eq!(flagged("cs/extension-keyword-conflict", src), [2]);
        assert_eq!(flagged("cs/field-keyword-conflict", src), [5, 5, 6]);
        assert_eq!(flagged("cs/partial-return-type", src), [8]);
        assert_eq!(flagged("cs/scoped-lambda-parameter", src), [9]);
    }
}
