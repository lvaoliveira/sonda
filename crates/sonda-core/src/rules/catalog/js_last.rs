//! JavaScript and TypeScript rules, part 9 (ADR-0007, batch 27): the last
//! checks that can be approximated from one file: local data flow (unused
//! assignments, null checks), tests, React props, ARIA roles and a few
//! TypeScript type checks. A rule only reports what the file itself shows.

use super::js::{
    attribute, attributes, has_token, opening_tag, static_value, string_content, tag_name, text,
};
use super::js_checks::literal_kind;
use super::js_extra::{named, operator_text};
use super::js_syntax::{ancestors_in_function, is_function_kind, root_node, strip_parens, walk};
use super::*;

/// This module's rules that are off unless `rules.enabled` lists them
/// (see `catalog::OFF_BY_DEFAULT`).
pub(super) static OFF_BY_DEFAULT: &[&str] = &[
    "js/arrow-function-style",
    "js/undeclared-variable",
    "js/props-without-prop-types",
    "js/default-type-argument-redundant",
    "js/redundant-cast",
];

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "js/find-for-existence",
        name: "Prefer .some() over .find() when only checking existence",
        description: "find() returns the element; if only its presence matters, some() says so.",
        message: "Use .some().",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S7754")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression property: (property_identifier) @p (#eq? @p "find"))) @match"#,
            filter: Some(Keep(find_result_only_tested)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function f(items) { const hit = items.find((i) => i.ok); if (hit) { return 1; } return 0; }",
            good: "function f(items) { if (items.some((i) => i.ok)) { return 1; } return 0; }",
        }),
    },
    Rule {
        id: "js/unused-assignment",
        name: "Unused assignments should be removed",
        description: "A value that is overwritten or never read was computed for nothing.",
        message: "Remove this assignment, or use its value.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S1854")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(function_declaration) (function_expression) (arrow_function) (method_definition) (generator_function) (generator_function_declaration)] @match"#,
            filter: Some(Find(unused_assignment)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function f() { let x = g(); x = 2; return x; }",
            good: "function f() { let x = g(); return x; }",
        }),
    },
    Rule {
        id: "js/deprecated-api",
        name: "Deprecated APIs should not be used",
        description: "Deprecated APIs are on their way out.",
        message: "Use the replacement.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S1874")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression) @match"#,
            filter: Some(Find(uses_deprecated_api)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const s = 'abc'.substr(1, 2);",
            good: "const s = 'abc'.slice(1, 3);",
        }),
    },
    Rule {
        id: "js/deprecated-buffer-constructor",
        name: "Deprecated APIs should not be used",
        description: "new Buffer() can expose uninitialized memory and is deprecated.",
        message: "Use Buffer.from or Buffer.alloc.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1874")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(new_expression) @match"#,
            filter: Some(Keep(buffer_constructor)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const b = new Buffer(10);",
            good: "const b = Buffer.alloc(10);",
        }),
    },
    Rule {
        id: "js/null-dereference",
        name: "Properties of variables with \"null\" or \"undefined\" values should not be accessed",
        description: "The branch that just checked for null reads a property of it.",
        message: "Handle the null case.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2259")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(if_statement) @match"#,
            filter: Some(Find(dereferences_a_null_value)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function f(x) { if (x === null) { return x.name; } return 1; }",
            good: "function f(x) { if (x !== null) { return x.name; } return 1; }",
        }),
    },
    Rule {
        id: "js/gratuitous-condition",
        name: "Boolean expressions should not be gratuitous",
        description: "A condition that is always true or false, or repeats one already known, never decides anything.",
        message: "Remove the condition.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S2589")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(if_statement) (ternary_expression) (binary_expression)] @match"#,
            filter: Some(Find(gratuitous_condition)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function f(a) { if (a) { if (a) { g(); } } }",
            good: "function f(a) { if (a) { g(); } }",
        }),
    },
    Rule {
        id: "js/arrow-function-style",
        name: "Braces and parentheses should be used consistently with arrow functions",
        description: "(x) => { return x; } says it the long way.",
        message: "Use x => x.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S3524")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(arrow_function) @match"#,
            filter: Some(Keep(arrow_style_is_inconsistent)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const f = (x) => x * 2;",
            good: "const f = x => x * 2;",
        }),
    },
    Rule {
        id: "js/array-index-not-a-count",
        name: "Array indexes should be numeric",
        description: "Writing arr['name'] adds a property that array methods ignore.",
        message: "Use an object, or a numeric index.",
        category: Bug,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S3579")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(subscript_expression) @match"#,
            filter: Some(Keep(array_index_is_not_a_count)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const a = []; a['name'] = 1;",
            good: "const a = []; a[0] = 1;",
        }),
    },
    Rule {
        id: "js/builtin-argument-type",
        name: "Arguments to built-in functions should match documented types",
        description: "Math.max('abc') is NaN.",
        message: "Pass a number.",
        category: Bug,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S3782")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression) @match"#,
            filter: Some(Find(builtin_gets_the_wrong_type)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const m = Math.max('abc', 1);",
            good: "const m = Math.max(2, 1);",
        }),
    },
    Rule {
        id: "js/undeclared-variable",
        name: "Variables should be defined before being used",
        description: "An identifier that nothing declares is a ReferenceError, or a global created by accident.",
        message: "Declare the variable.",
        category: Bug,
        severity: Blocker,
        effort_minutes: 5,
        sonar: &[exact("S3827")],
        check: Check::Query {
            langs: &[Lang::JavaScript],
            query: r#"(program) @match"#,
            filter: Some(Find(undeclared_variable)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function f() { return total + 1; }",
            good: "function f(total) { return total + 1; }",
        }),
    },
    Rule {
        id: "js/promise-rejection-in-try",
        name: "Promise rejections should not be caught by \"try\" blocks",
        description: "A catch block cannot see the rejection of a promise that is neither awaited nor returned.",
        message: "Await the promise, or add .catch.",
        category: Bug,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S4822")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(try_statement) @match"#,
            filter: Some(Find(promise_chain_in_try)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "async function f() { try { g().then(h); } catch (e) { log(e); } }",
            good: "async function f() { try { await g().then(h); } catch (e) { log(e); } }",
        }),
    },
    Rule {
        id: "js/test-with-sleep",
        name: "Tests should be stable",
        description: "A fixed delay makes a test slow and flaky.",
        message: "Wait for the condition instead.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5973")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (identifier) @f (#any-of? @f "it" "test" "specify")) @match"#,
            filter: Some(Find(sleeps_in_a_test)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "it('waits', () => { setTimeout(done, 500); });",
            good: "it('waits', async () => { await ready(); });",
        }),
    },
    Rule {
        id: "js/similar-tests",
        name: "Similar tests should be grouped in a single Parameterized test",
        description: "Three tests that differ only in literals are one test with three rows.",
        message: "Use it.each or test.each.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 15,
        sonar: &[exact("S5976")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(program) (statement_block)] @match"#,
            filter: Some(Find(similar_tests)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "it('a', () => { expect(f(1)).toBe(2); }); it('b', () => { expect(f(2)).toBe(3); }); it('c', () => { expect(f(3)).toBe(4); });",
            good: "it.each([[1, 2], [2, 3], [3, 4]])('f(%i)', (a, b) => { expect(f(a)).toBe(b); });",
        }),
    },
    Rule {
        id: "js/chai-two-reasons",
        name: "Chai assertions should have only one reason to succeed",
        description: "not.throw(Error) passes when anything else is thrown too.",
        message: "Assert one thing.",
        category: Bug,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S6092")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression)) @match"#,
            filter: Some(Keep(chai_assertion_has_two_reasons)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "expect(fn).to.not.throw(TypeError);",
            good: "expect(fn).to.not.throw();",
        }),
    },
    Rule {
        id: "js/missing-to-string",
        name: "Objects and classes converted or coerced to strings should define a \"toString()\" method",
        description: "`${obj}` prints [object Object].",
        message: "Define toString, or print a property.",
        category: Bug,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S6551")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(template_substitution) (binary_expression)] @match"#,
            filter: Some(Keep(to_string_is_missing)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const s = `value: ${{ a: 1 }}`;",
            good: "const s = `value: ${JSON.stringify({ a: 1 })}`;",
        }),
    },
    Rule {
        id: "js/wallet-phrase-hardcoded",
        name: "Wallet phrases should not be hard-coded",
        description: "A recovery phrase in source code hands over the wallet.",
        message: "Load the phrase from a secret store.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 15,
        sonar: &[exact("S7639")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(string) @match"#,
            filter: Some(Keep(wallet_phrase_is_hardcoded)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const mnemonic = 'abandon ability able about above absent absorb abstract absurd abuse access accident';",
            good: "const mnemonic = process.env.MNEMONIC;",
        }),
    },
    Rule {
        id: "js/function-can-move-up",
        name: "Functions should be moved to the highest possible scope",
        description: "A function that uses nothing from the function around it is recreated on every call.",
        message: "Move it out of the enclosing function.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7721")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(function_declaration) @match"#,
            filter: Some(Keep(function_captures_nothing)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function outer(a) { function helper(x) { return x * 2; } return helper(a); }",
            good: "function helper(x) { return x * 2; } function outer(a) { return helper(a); }",
        }),
    },
    Rule {
        id: "js/assertion-outside-test",
        name: "Assertions should be placed inside test cases or hooks",
        description: "An assertion in a describe body runs while the tests are being collected.",
        message: "Move it into a test.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S8784")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (identifier) @f (#eq? @f "expect")) @match"#,
            filter: Some(Keep(assertion_outside_a_test)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "describe('a', () => { expect(1).toBe(1); it('b', () => {}); });",
            good: "describe('a', () => { it('b', () => { expect(1).toBe(1); }); });",
        }),
    },
    Rule {
        id: "js/props-without-prop-types",
        name: "React components should validate prop types",
        description: "A prop nobody declared can be anything.",
        message: "Add propTypes, or use TypeScript.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6774")],
        check: Check::Query {
            langs: &[Lang::JavaScript],
            query: r#"[(function_declaration) (variable_declarator)] @match"#,
            filter: Some(Keep(props_without_prop_types)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function Hello(props) { return <p>{props.name}</p>; }",
            good: "function Hello(props) { return <p>{props.name}</p>; } Hello.propTypes = {};",
        }),
    },
    Rule {
        id: "js/default-prop-is-required",
        name: "All \"defaultProps\" should have non-required PropTypes",
        description: "A required prop never uses its default.",
        message: "Make the prop optional, or drop the default.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S6775")],
        check: Check::Query {
            langs: JSX,
            query: r#"(program) @match"#,
            filter: Some(Find(default_prop_is_required)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function A() { return <p />; } A.propTypes = { a: PropTypes.string.isRequired }; A.defaultProps = { a: 'x' };",
            good: "function A() { return <p />; } A.propTypes = { a: PropTypes.string }; A.defaultProps = { a: 'x' };",
        }),
    },
    Rule {
        id: "js/headers-reference-missing-cell",
        name: "Table cells should reference their headers",
        description: "headers must name ids that exist.",
        message: "Fix the id, or add the header.",
        category: Bug,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S5260")],
        check: Check::Query {
            langs: JSX,
            query: r#"[(jsx_element) (jsx_self_closing_element)] @match"#,
            filter: Some(Keep(cell_references_a_missing_header)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const a = <table><tr><th id=\"a\">A</th></tr><tr><td headers=\"b\">1</td></tr></table>;",
            good: "const a = <table><tr><th id=\"a\">A</th></tr><tr><td headers=\"a\">1</td></tr></table>;",
        }),
    },
    Rule {
        id: "js/aria-attribute-role-mismatch",
        name: "DOM elements with ARIA role should only have supported properties",
        description: "aria-checked on a button is ignored by assistive technology.",
        message: "Remove the attribute, or change the role.",
        category: Bug,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S6811")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_attribute (property_identifier) @a (#eq? @a "role")) @match"#,
            filter: Some(Keep(is_aria_role_misuse)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const a = <div role=\"button\" aria-checked=\"true\" />;",
            good: "const a = <div role=\"button\" aria-pressed=\"true\" />;",
        }),
    },
    Rule {
        id: "js/default-type-argument-redundant",
        name: "Default type parameters should be omitted",
        description: "Repeating the default adds nothing.",
        message: "Remove the type argument.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S4157")],
        check: Check::Query {
            langs: TS,
            query: r#"(generic_type) @match"#,
            filter: Some(Keep(default_type_argument_is_redundant)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "interface Box<T = string> { v: T } let b: Box<string>;",
            good: "interface Box<T = string> { v: T } let b: Box;",
        }),
    },
    Rule {
        id: "js/union-alias",
        name: "Type aliases should be used",
        description: "The same union written three times belongs in a type alias.",
        message: "Define a type alias.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S4323")],
        check: Check::Query {
            langs: TS,
            query: r#"(union_type) @match"#,
            filter: Some(Keep(union_alias_is_repeated)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "let a: 'x' | 'y' | 'z'; let b: 'x' | 'y' | 'z';",
            good: "type T = 'x' | 'y' | 'z'; let a: T; let b: T;",
        }),
    },
    Rule {
        id: "js/redundant-cast",
        name: "Redundant casts and non-null assertions should be avoided",
        description: "The compiler already knows the type.",
        message: "Remove the cast.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S4325")],
        check: Check::Query {
            langs: TS,
            query: r#"[(as_expression) (non_null_expression)] @match"#,
            filter: Some(Keep(cast_changes_nothing)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "const a = 'x' as string;",
            good: "const a = 'x';",
        }),
    },
    Rule {
        id: "js/props-not-readonly",
        name: "React props should be read-only",
        description: "Props are never written to; readonly says so.",
        message: "Mark the props readonly.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 3,
        sonar: &[exact("S6759")],
        check: Check::Query {
            langs: &[Lang::Tsx],
            query: r#"[(function_declaration) (variable_declarator)] @match"#,
            filter: Some(Find(props_are_writable)),
        },
        example: Some(Example {
            lang: Lang::Tsx,
            bad: "interface P { name: string } function Hello(props: P) { return <p>{props.name}</p>; }",
            good: "interface P { readonly name: string } function Hello(props: P) { return <p>{props.name}</p>; }",
        }),
    },
    Rule {
        id: "js/props-unused",
        name: "Unused React typed props should be removed",
        description: "A declared prop that the component never reads is dead weight.",
        message: "Remove the prop from the type.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S6767")],
        check: Check::Query {
            langs: &[Lang::Tsx],
            query: r#"[(function_declaration) (variable_declarator)] @match"#,
            filter: Some(Find(declares_unused_props)),
        },
        example: Some(Example {
            lang: Lang::Tsx,
            bad: "interface P { a: string; b: string } function Hello({ a }: P) { return <p>{a}</p>; }",
            good: "interface P { a: string } function Hello({ a }: P) { return <p>{a}</p>; }",
        }),
    },
];

// ------------------------------------------------------------- scope helpers

const GLOBALS: &[&str] = &[
    "undefined",
    "NaN",
    "Infinity",
    "globalThis",
    "window",
    "self",
    "global",
    "document",
    "navigator",
    "location",
    "history",
    "console",
    "process",
    "module",
    "exports",
    "require",
    "__dirname",
    "__filename",
    "Buffer",
    "setTimeout",
    "clearTimeout",
    "setInterval",
    "clearInterval",
    "setImmediate",
    "clearImmediate",
    "queueMicrotask",
    "structuredClone",
    "fetch",
    "Request",
    "Response",
    "Headers",
    "URL",
    "URLSearchParams",
    "FormData",
    "Blob",
    "File",
    "FileReader",
    "AbortController",
    "AbortSignal",
    "Event",
    "EventTarget",
    "CustomEvent",
    "MessageChannel",
    "TextEncoder",
    "TextDecoder",
    "WebSocket",
    "Worker",
    "XMLHttpRequest",
    "localStorage",
    "sessionStorage",
    "alert",
    "confirm",
    "prompt",
    "requestAnimationFrame",
    "cancelAnimationFrame",
    "performance",
    "crypto",
    "atob",
    "btoa",
    "Object",
    "Function",
    "Array",
    "String",
    "Number",
    "Boolean",
    "Symbol",
    "BigInt",
    "Math",
    "Date",
    "RegExp",
    "Error",
    "TypeError",
    "RangeError",
    "SyntaxError",
    "ReferenceError",
    "EvalError",
    "URIError",
    "AggregateError",
    "JSON",
    "Promise",
    "Map",
    "Set",
    "WeakMap",
    "WeakSet",
    "WeakRef",
    "FinalizationRegistry",
    "Proxy",
    "Reflect",
    "Intl",
    "ArrayBuffer",
    "SharedArrayBuffer",
    "DataView",
    "Atomics",
    "Int8Array",
    "Uint8Array",
    "Uint8ClampedArray",
    "Int16Array",
    "Uint16Array",
    "Int32Array",
    "Uint32Array",
    "Float32Array",
    "Float64Array",
    "BigInt64Array",
    "BigUint64Array",
    "parseInt",
    "parseFloat",
    "isNaN",
    "isFinite",
    "encodeURIComponent",
    "decodeURIComponent",
    "encodeURI",
    "decodeURI",
    "escape",
    "unescape",
    "eval",
    "arguments",
    "describe",
    "it",
    "test",
    "expect",
    "beforeEach",
    "afterEach",
    "beforeAll",
    "afterAll",
    "jest",
    "vi",
    "before",
    "after",
    "context",
    "suite",
    "specify",
    "xit",
    "xdescribe",
    "fit",
    "fdescribe",
    "cy",
    "Cypress",
    "$",
    "jQuery",
    "define",
    "Image",
    "Audio",
    "HTMLElement",
    "Element",
    "Node",
    "NodeList",
    "MutationObserver",
    "IntersectionObserver",
    "ResizeObserver",
    "getComputedStyle",
    "matchMedia",
    "screen",
    "innerWidth",
    "innerHeight",
    "scrollTo",
    "open",
    "close",
    "print",
    "postMessage",
    "SuppressedError",
    "DisposableStack",
    "AsyncDisposableStack",
    "ReadableStream",
    "WritableStream",
    "TransformStream",
    "BroadcastChannel",
    "indexedDB",
    "caches",
    "Notification",
    "DOMParser",
    "XMLSerializer",
    "WebAssembly",
    "Iterator",
];

/// The names a binding pattern declares, skipping default-value expressions.
fn pattern_names<'a>(pattern: Node<'_>, src: &'a [u8], out: &mut Vec<&'a [u8]>) {
    match pattern.kind() {
        "identifier" | "shorthand_property_identifier_pattern" | "type_identifier" => {
            out.push(text(pattern, src));
        }
        "pair_pattern" => {
            if let Some(v) = pattern.child_by_field_name("value") {
                pattern_names(v, src, out);
            }
        }
        "assignment_pattern" | "object_assignment_pattern" => {
            if let Some(l) = pattern.child_by_field_name("left") {
                pattern_names(l, src, out);
            }
        }
        "required_parameter" | "optional_parameter" => {
            if let Some(p) = pattern.child_by_field_name("pattern") {
                pattern_names(p, src, out);
            }
        }
        "object_pattern" | "array_pattern" | "rest_pattern" => {
            for c in named(pattern) {
                pattern_names(c, src, out);
            }
        }
        _ => {}
    }
}

/// Every name declared anywhere under `root`.
fn declared_names<'a>(root: Node<'_>, src: &'a [u8]) -> Vec<&'a [u8]> {
    let mut out: Vec<&[u8]> = Vec::new();
    let mut visit = |n: Node<'_>| {
        match n.kind() {
            "variable_declarator" => {
                if let Some(p) = n.child_by_field_name("name") {
                    pattern_names(p, src, &mut out);
                }
            }
            "function_declaration"
            | "generator_function_declaration"
            | "class_declaration"
            | "function_expression"
            | "function"
            | "generator_function"
            | "class"
            | "abstract_class_declaration"
            | "enum_declaration"
            | "internal_module"
            | "module"
            | "function_signature" => {
                if let Some(p) = n.child_by_field_name("name") {
                    out.push(text(p, src));
                }
            }
            "formal_parameters" => {
                for c in named(n) {
                    pattern_names(c, src, &mut out);
                }
            }
            "arrow_function" => {
                if let Some(p) = n.child_by_field_name("parameter") {
                    pattern_names(p, src, &mut out);
                }
            }
            "catch_clause" => {
                if let Some(p) = n.child_by_field_name("parameter") {
                    pattern_names(p, src, &mut out);
                }
            }
            "import_specifier" => {
                if let Some(p) = n
                    .child_by_field_name("alias")
                    .or_else(|| n.child_by_field_name("name"))
                {
                    out.push(text(p, src));
                }
            }
            "namespace_import" | "import_clause" | "import_require_clause" => {
                for c in named(n) {
                    if c.kind() == "identifier" {
                        out.push(text(c, src));
                    }
                }
            }
            "for_in_statement" => {
                if n.child_by_field_name("kind").is_some()
                    && let Some(l) = n.child_by_field_name("left")
                {
                    pattern_names(l, src, &mut out);
                }
            }
            "index_signature" => {
                if let Some(p) = n.child_by_field_name("name") {
                    out.push(text(p, src));
                }
            }
            _ => {}
        }
        true
    };
    visit(root);
    walk(root, &mut visit);
    out
}

/// The identifiers under `node` that read or write a variable, with the
/// ones that only name something excluded.
fn references<'t>(node: Node<'t>) -> Vec<Node<'t>> {
    let mut out = Vec::new();
    let mut visit = |n: Node<'t>| {
        if matches!(n.kind(), "identifier" | "shorthand_property_identifier") {
            let skip = n.parent().is_some_and(|p| match p.kind() {
                "export_specifier" => p.child_by_field_name("alias") == Some(n),
                "import_specifier" => true,
                "labeled_statement" => true,
                "jsx_opening_element" | "jsx_self_closing_element" | "jsx_closing_element" => false,
                _ => false,
            });
            if !skip {
                out.push(n);
            }
        }
        true
    };
    visit(node);
    walk(node, &mut visit);
    out
}

fn is_declaration_name(id: Node) -> bool {
    let Some(p) = id.parent() else {
        return false;
    };
    match p.kind() {
        "variable_declarator" => p.child_by_field_name("name") == Some(id),
        "function_declaration"
        | "class_declaration"
        | "function_expression"
        | "function"
        | "generator_function_declaration"
        | "generator_function"
        | "class" => p.child_by_field_name("name") == Some(id),
        "formal_parameters"
        | "catch_clause"
        | "import_clause"
        | "namespace_import"
        | "required_parameter"
        | "optional_parameter"
        | "rest_pattern"
        | "array_pattern"
        | "object_pattern"
        | "pair_pattern"
        | "assignment_pattern"
        | "object_assignment_pattern" => true,
        "arrow_function" => p.child_by_field_name("parameter") == Some(id),
        _ => false,
    }
}

fn is_assignment_target(id: Node) -> bool {
    id.parent().is_some_and(|p| {
        (matches!(
            p.kind(),
            "assignment_expression" | "augmented_assignment_expression"
        ) && p.child_by_field_name("left") == Some(id))
            || (p.kind() == "update_expression")
    })
}

// ------------------------------------------------------------- S1854

fn unused_assignment<'t>(function: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let body = function.child_by_field_name("body")?;
    if body.kind() != "statement_block" {
        return None;
    }
    // (a) A value overwritten by the next statement before anyone reads it.
    let mut found = None;
    let mut blocks = vec![body];
    walk(body, &mut |n| {
        if is_function_kind(n.kind()) {
            return false;
        }
        if n.kind() == "statement_block" {
            blocks.push(n);
        }
        true
    });
    for block in blocks {
        for w in named(block).windows(2) {
            let (first, second) = (w[0], w[1]);
            let (name, value_end) = match first.kind() {
                "expression_statement" => {
                    let Some(a) = first
                        .named_child(0)
                        .filter(|a| a.kind() == "assignment_expression")
                    else {
                        continue;
                    };
                    match a.child_by_field_name("left") {
                        Some(l) if l.kind() == "identifier" => (text(l, src), a),
                        _ => continue,
                    }
                }
                "lexical_declaration" | "variable_declaration" => {
                    let decls = named(first);
                    let [d] = decls.as_slice() else { continue };
                    match (
                        d.child_by_field_name("name"),
                        d.child_by_field_name("value"),
                    ) {
                        (Some(n), Some(_)) if n.kind() == "identifier" => (text(n, src), *d),
                        _ => continue,
                    }
                }
                _ => continue,
            };
            if second.kind() != "expression_statement" {
                continue;
            }
            let Some(next) = second
                .named_child(0)
                .filter(|a| a.kind() == "assignment_expression")
            else {
                continue;
            };
            let overwrites = next
                .child_by_field_name("left")
                .is_some_and(|l| l.kind() == "identifier" && text(l, src) == name);
            let reads = next
                .child_by_field_name("right")
                .is_some_and(|r| references(r).iter().any(|i| text(*i, src) == name));
            let _ = value_end;
            if overwrites && !reads {
                found = Some(first);
                break;
            }
        }
        if found.is_some() {
            return found;
        }
    }
    // (b) A local that is written and never read.
    let mut locals: Vec<(&[u8], Node)> = Vec::new();
    walk(body, &mut |n| {
        if is_function_kind(n.kind()) {
            return false;
        }
        if n.kind() == "variable_declarator"
            && let Some(pattern) = n.child_by_field_name("name")
            && n.child_by_field_name("value").is_some()
            && n.parent()
                .is_some_and(|d| matches!(d.kind(), "lexical_declaration" | "variable_declaration"))
            && !n.parent().and_then(|d| d.parent()).is_some_and(|g| {
                matches!(
                    g.kind(),
                    "for_statement" | "for_in_statement" | "export_statement"
                )
            })
        {
            // `const { a, ...rest } = x` keeps its siblings of a rest on purpose.
            let mut names = Vec::new();
            let has_rest = {
                let mut found = false;
                walk(pattern, &mut |c| {
                    found |= c.kind() == "rest_pattern";
                    true
                });
                found
            };
            if !has_rest {
                pattern_names(pattern, src, &mut names);
                for name in names {
                    locals.push((name, n));
                }
            }
        }
        true
    });
    let refs = references(body);
    locals.into_iter().find_map(|(name, declarator)| {
        if name.starts_with(b"_") {
            return None;
        }
        let mut read = false;
        for r in refs.iter().filter(|r| text(**r, src) == name) {
            if is_declaration_name(*r)
                || is_assignment_target(*r)
                    && r.parent().is_some_and(|p| p.kind() != "update_expression")
            {
                continue;
            }
            read = true;
            break;
        }
        // A closure may read it later.
        let captured = refs.iter().any(|r| {
            text(*r, src) == name
                && ancestors_in_function(*r)
                    .last()
                    .is_none_or(|top| top.byte_range() != body.byte_range() && false)
                && r.start_byte() > body.start_byte()
                && enclosing_function_of(*r).is_some_and(|f| f.id() != function.id())
        });
        (!read && !captured).then_some(declarator)
    })
}

fn enclosing_function_of(node: Node) -> Option<Node> {
    let mut cur = node.parent();
    while let Some(p) = cur {
        if is_function_kind(p.kind()) {
            return Some(p);
        }
        cur = p.parent();
    }
    None
}

// ------------------------------------------------------------- S1874

fn uses_deprecated_api<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let function = call.child_by_field_name("function")?;
    let t = text(function, src);
    let member = function
        .child_by_field_name("property")
        .map(|p| text(p, src))
        .unwrap_or_default();
    let object = function
        .child_by_field_name("object")
        .map(|o| text(o, src))
        .unwrap_or_default();
    let deprecated = match (object, member) {
        (b"util", m) if m.starts_with(b"is") && m != b"isDeepStrictEqual" => true,
        (b"fs", b"exists") => true,
        (b"crypto", b"createCipher" | b"createDecipher") => true,
        (b"url", b"parse") => true,
        (b"process", b"binding") => true,
        (b"ReactDOM", b"render" | b"hydrate" | b"findDOMNode" | b"unmountComponentAtNode") => true,
        (b"React", b"createClass") => true,
        (b"document", b"execCommand") => true,
        (b"Object" | b"Reflect", _) => false,
        (_, b"substr") => true,
        (_, b"getYear" | b"setYear" | b"toGMTString") => true,
        (
            _,
            b"__defineGetter__" | b"__defineSetter__" | b"__lookupGetter__" | b"__lookupSetter__",
        ) => true,
        _ => false,
    };
    if deprecated || matches!(t, b"escape" | b"unescape") {
        return Some(call);
    }
    // Same-file functions marked @deprecated.
    if function.kind() == "identifier"
        && deprecated_functions(call, src)
            .iter()
            .any(|n| n.as_slice() == t)
    {
        return Some(call);
    }
    None
}

/// The names of this file's functions whose preceding comment says
/// @deprecated, found once per file.
fn deprecated_functions(node: Node, src: &[u8]) -> std::rc::Rc<Vec<Vec<u8>>> {
    use std::cell::RefCell;
    type Key = (usize, usize, Vec<u8>);
    type Names = std::rc::Rc<Vec<Vec<u8>>>;
    thread_local! {
        static CACHE: RefCell<Option<(Key, Names)>> = const { RefCell::new(None) };
    }
    let key: Key = (
        src.as_ptr() as usize,
        src.len(),
        [
            src.get(..32).unwrap_or(src),
            src.get(src.len().saturating_sub(32)..).unwrap_or(src),
        ]
        .concat(),
    );
    if let Some(hit) = CACHE.with(|c| {
        c.borrow()
            .as_ref()
            .filter(|(k, _)| *k == key)
            .map(|(_, v)| v.clone())
    }) {
        return hit;
    }
    let mut names: Vec<Vec<u8>> = Vec::new();
    if src.windows(11).any(|w| w == b"@deprecated") {
        walk(root_node(node), &mut |n| {
            if n.kind() == "function_declaration"
                && let Some(name) = n.child_by_field_name("name")
                && let Some(prev) = n.prev_sibling().or_else(|| {
                    n.parent()
                        .filter(|p| p.kind() == "export_statement")
                        .and_then(|p| p.prev_sibling())
                })
                && prev.kind() == "comment"
                && text(prev, src).windows(11).any(|w| w == b"@deprecated")
            {
                names.push(text(name, src).to_vec());
            }
            true
        });
    }
    let value = std::rc::Rc::new(names);
    CACHE.with(|c| *c.borrow_mut() = Some((key, value.clone())));
    value
}

fn buffer_constructor(new_expr: Node, src: &[u8]) -> bool {
    new_expr
        .child_by_field_name("constructor")
        .is_some_and(|c| text(c, src) == b"Buffer")
}

// ------------------------------------------------------------- S2259

fn tests_for_null(condition: Node, src: &[u8]) -> Option<Vec<u8>> {
    let expr = strip_parens(condition);
    if expr.kind() != "binary_expression" {
        return None;
    }
    if !matches!(operator_text(expr, src), b"===" | b"==") {
        return None;
    }
    let (l, r) = (
        expr.child_by_field_name("left")?,
        expr.child_by_field_name("right")?,
    );
    let nullish = |n: Node| matches!(n.kind(), "null" | "undefined") || text(n, src) == b"void 0";
    match (l.kind(), r.kind()) {
        ("identifier", _) if nullish(r) => Some(text(l, src).to_vec()),
        (_, "identifier") if nullish(l) => Some(text(r, src).to_vec()),
        _ => None,
    }
}

fn dereferences_a_null_value<'t>(if_: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let name = tests_for_null(if_.child_by_field_name("condition")?, src)?;
    let body = if_.child_by_field_name("consequence")?;
    let mut assigned = false;
    let mut access = None;
    walk(body, &mut |n| {
        if is_function_kind(n.kind()) {
            return false;
        }
        if matches!(
            n.kind(),
            "assignment_expression" | "augmented_assignment_expression" | "update_expression"
        ) {
            let target = n
                .child_by_field_name("left")
                .or_else(|| n.child_by_field_name("argument"));
            if target.is_some_and(|t| text(t, src) == name) {
                assigned = true;
            }
        }
        if access.is_none()
            && !assigned
            && matches!(n.kind(), "member_expression" | "subscript_expression")
            && n.child_by_field_name("object")
                .is_some_and(|o| o.kind() == "identifier" && text(o, src) == name)
            && !has_token(n, "?.")
            && n.child_by_field_name("optional_chain").is_none()
        {
            access = Some(n);
        }
        true
    });
    if assigned { None } else { access }
}

// ------------------------------------------------------------- S2589

fn gratuitous_condition<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    match node.kind() {
        "if_statement" | "ternary_expression" => {
            let cond = strip_parens(node.child_by_field_name("condition")?);
            if matches!(cond.kind(), "true" | "false" | "null" | "undefined")
                || (cond.kind() == "number" && matches!(text(cond, src), b"0" | b"1"))
            {
                return Some(cond);
            }
            if node.kind() != "if_statement" {
                return None;
            }
            let simple = |c: Node| {
                matches!(c.kind(), "identifier" | "member_expression")
                    && !text(c, src).contains(&b'(')
            };
            if !simple(cond) {
                return None;
            }
            let body = node.child_by_field_name("consequence")?;
            let root_name: Vec<u8> = text(cond, src)
                .split(|b| *b == b'.')
                .next()
                .unwrap_or_default()
                .to_vec();
            // Only the statements of the block itself: a walk of everything
            // below would be quadratic on deeply nested code.
            let statements = if body.kind() == "statement_block" {
                named(body)
            } else {
                vec![body]
            };
            for statement in statements {
                if statement.kind() == "if_statement"
                    && statement
                        .child_by_field_name("condition")
                        .is_some_and(|c| text(strip_parens(c), src) == text(cond, src))
                {
                    return statement.child_by_field_name("condition");
                }
                let writes_it = |n: Node| {
                    matches!(
                        n.kind(),
                        "assignment_expression"
                            | "augmented_assignment_expression"
                            | "update_expression"
                    ) && n
                        .child_by_field_name("left")
                        .or_else(|| n.child_by_field_name("argument"))
                        .is_some_and(|t| {
                            text(t, src)
                                .split(|b| *b == b'.')
                                .next()
                                .unwrap_or_default()
                                == root_name.as_slice()
                        })
                };
                let mut written = writes_it(statement);
                if statement.kind() != "if_statement" {
                    walk(statement, &mut |n| {
                        written |= writes_it(n);
                        !written
                    });
                }
                if written {
                    return None;
                }
            }
            None
        }
        "binary_expression" => {
            if !matches!(operator_text(node, src), b"&&" | b"||") {
                return None;
            }
            let (l, r) = (
                node.child_by_field_name("left")?,
                node.child_by_field_name("right")?,
            );
            (l.kind() == "identifier" && text(l, src) == text(r, src)).then_some(r)
        }
        _ => None,
    }
}

// ------------------------------------------------------------- S3524

fn arrow_style_is_inconsistent(arrow: Node, src: &[u8]) -> bool {
    // (x) => ... with one plain parameter: the parentheses add nothing.
    if let Some(params) = arrow.child_by_field_name("parameters") {
        let kids = named(params);
        if let [only] = kids.as_slice()
            && only.kind() == "identifier"
            && text(params, src).starts_with(b"(")
        {
            return true;
        }
    }
    // { return x; } with nothing else: the braces add nothing.
    arrow
        .child_by_field_name("body")
        .filter(|b| b.kind() == "statement_block")
        .is_some_and(|b| {
            matches!(named(b).as_slice(), [only] if only.kind() == "return_statement" && only.named_child(0).is_some())
        })
}

// ------------------------------------------------------------- S3579, S3782

fn declared_array<'t>(root: Node<'t>, name: &[u8], src: &[u8]) -> bool {
    let mut found = false;
    walk(root, &mut |n| {
        if !found
            && n.kind() == "variable_declarator"
            && n.child_by_field_name("name")
                .is_some_and(|x| text(x, src) == name)
            && n.child_by_field_name("value")
                .is_some_and(|v| v.kind() == "array")
        {
            found = true;
        }
        !found
    });
    found
}

fn array_index_is_not_a_count(subscript: Node, src: &[u8]) -> bool {
    let (Some(object), Some(index)) = (
        subscript.child_by_field_name("object"),
        subscript.child_by_field_name("index"),
    ) else {
        return false;
    };
    if object.kind() != "identifier"
        || !declared_array(root_node(subscript), text(object, src), src)
    {
        return false;
    }
    let bad_index = match index.kind() {
        "string" => {
            let c = string_content(index, src);
            !c.is_empty() && !c.iter().all(u8::is_ascii_digit) && c != b"length"
        }
        "unary_expression" => literal_kind(index) == Some("number"),
        "number" => text(index, src).contains(&b'.'),
        _ => false,
    };
    // Methods and properties of arrays are read with a string key on purpose.
    bad_index
        && subscript.parent().is_some_and(|p| {
            p.kind() == "assignment_expression" && p.child_by_field_name("left") == Some(subscript)
        })
}

fn builtin_gets_the_wrong_type<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let function = call.child_by_field_name("function")?;
    let object = function.child_by_field_name("object")?;
    if text(object, src) != b"Math" {
        return None;
    }
    named(call.child_by_field_name("arguments")?)
        .into_iter()
        .find(|a| match literal_kind(*a) {
            Some("string") => {
                let t = text(*a, src);
                let inner = &t[1..t.len().saturating_sub(1)];
                std::str::from_utf8(inner)
                    .ok()
                    .and_then(|s| s.trim().parse::<f64>().ok())
                    .is_none()
            }
            Some("object" | "array" | "function" | "regex" | "undefined") => true,
            _ => false,
        })
}

// ------------------------------------------------------------- S3827

fn undeclared_variable<'t>(program: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let declared: std::collections::HashSet<&[u8]> =
        declared_names(program, src).into_iter().collect();
    let globals: std::collections::HashSet<&[u8]> = GLOBALS.iter().map(|g| g.as_bytes()).collect();
    let mut found = None;
    walk(program, &mut |n| {
        if found.is_some() {
            return false;
        }
        if !matches!(n.kind(), "identifier" | "shorthand_property_identifier") {
            return true;
        }
        let name = text(n, src);
        if declared.contains(name) || globals.contains(name) {
            return true;
        }
        let Some(parent) = n.parent() else {
            return true;
        };
        let skip = match parent.kind() {
            "export_specifier" => parent.child_by_field_name("alias") == Some(n),
            "import_specifier" | "labeled_statement" => true,
            "jsx_opening_element" | "jsx_self_closing_element" | "jsx_closing_element" => {
                name.first().is_some_and(u8::is_ascii_lowercase)
            }
            "unary_expression" => text(parent, src).starts_with(b"typeof"),
            _ => false,
        };
        if !skip {
            found = Some(n);
        }
        true
    });
    found
}

// ------------------------------------------------------------- S4822

fn promise_chain_in_try<'t>(try_: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let body = try_.child_by_field_name("body")?;
    try_.child_by_field_name("handler")?;
    let mut found = None;
    walk(body, &mut |n| {
        if found.is_some() || is_function_kind(n.kind()) {
            return false;
        }
        if n.kind() == "call_expression"
            && let Some(f) = n.child_by_field_name("function")
            && f.kind() == "member_expression"
            && f.child_by_field_name("property")
                .is_some_and(|p| text(p, src) == b"then")
            && !n.parent().is_some_and(|p| {
                let mut up = Some(p);
                while let Some(a) = up {
                    if matches!(a.kind(), "return_statement" | "await_expression") {
                        return true;
                    }
                    if matches!(a.kind(), "expression_statement" | "statement_block") {
                        break;
                    }
                    up = a.parent();
                }
                false
                    || (p.kind() == "member_expression"
                        && p.child_by_field_name("property").is_some_and(|x| {
                            matches!(text(x, src), b"catch" | b"then" | b"finally")
                        }))
            })
            && n.child_by_field_name("arguments")
                .is_some_and(|a| named(a).len() < 2)
        {
            found = Some(n);
        }
        true
    });
    found
}

// ------------------------------------------------------------- tests

fn is_test_call(call: Node, src: &[u8]) -> bool {
    call.child_by_field_name("function")
        .is_some_and(|f| matches!(text(f, src), b"it" | b"test" | b"specify"))
        && call.child_by_field_name("arguments").is_some_and(|a| {
            named(a)
                .iter()
                .any(|x| matches!(x.kind(), "arrow_function" | "function_expression"))
        })
}

fn test_callback<'t>(call: Node<'t>) -> Option<Node<'t>> {
    named(call.child_by_field_name("arguments")?)
        .into_iter()
        .find(|x| matches!(x.kind(), "arrow_function" | "function_expression"))
}

fn sleeps_in_a_test<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !is_test_call(call, src) {
        return None;
    }
    let body = test_callback(call)?.child_by_field_name("body")?;
    let mut found = None;
    walk(body, &mut |n| {
        if found.is_some() {
            return false;
        }
        if n.kind() == "call_expression"
            && n.child_by_field_name("function").is_some_and(|f| {
                matches!(text(f, src), b"setTimeout" | b"sleep" | b"delay" | b"wait")
            })
        {
            found = Some(n);
        }
        true
    });
    found
}

/// The text of `node` with every string and number replaced by a placeholder.
fn normalized(node: Node, src: &[u8]) -> Vec<u8> {
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    walk(node, &mut |n| {
        if matches!(n.kind(), "string" | "number" | "template_string") {
            ranges.push((n.start_byte(), n.end_byte()));
            return false;
        }
        true
    });
    let mut out = Vec::new();
    let mut at = node.start_byte();
    for (s, e) in ranges {
        out.extend_from_slice(&src[at..s]);
        out.push(b'#');
        at = e;
    }
    out.extend_from_slice(&src[at..node.end_byte()]);
    out.retain(|b| !b.is_ascii_whitespace());
    out
}

fn similar_tests<'t>(container: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let tests: Vec<Node> = named(container)
        .into_iter()
        .filter_map(|s| {
            s.named_child(0)
                .filter(|c| c.kind() == "call_expression" && is_test_call(*c, src))
        })
        .collect();
    let keys: Vec<Vec<u8>> = tests
        .iter()
        .map(|t| {
            test_callback(*t)
                .and_then(|c| c.child_by_field_name("body"))
                .map(|b| normalized(b, src))
                .unwrap_or_default()
        })
        .collect();
    (0..tests.len()).find_map(|i| {
        let same = keys.iter().filter(|k| **k == keys[i]).count();
        (keys[i].len() >= 20 && same >= 3 && !keys[..i].contains(&keys[i])).then_some(tests[i])
    })
}

fn chai_assertion_has_two_reasons(call: Node, src: &[u8]) -> bool {
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    let method = function
        .child_by_field_name("property")
        .map(|p| text(p, src))
        .unwrap_or_default();
    let arg_count = call
        .child_by_field_name("arguments")
        .map_or(0, |a| named(a).len());
    let two_reasons =
        (method == b"throw" && arg_count >= 1) || (method == b"property" && arg_count >= 2);
    if !two_reasons {
        return false;
    }
    let (mut negated, mut rooted_in_expect) = (false, false);
    let mut cur = function.child_by_field_name("object");
    while let Some(n) = cur {
        match n.kind() {
            "member_expression" => {
                if n.child_by_field_name("property")
                    .is_some_and(|p| text(p, src) == b"not")
                {
                    negated = true;
                }
                cur = n.child_by_field_name("object");
            }
            "call_expression" => {
                rooted_in_expect = n
                    .child_by_field_name("function")
                    .is_some_and(|f| text(f, src) == b"expect");
                break;
            }
            _ => break,
        }
    }
    negated && rooted_in_expect
}

fn assertion_outside_a_test(call: Node, src: &[u8]) -> bool {
    let root = root_node(call);
    let root_text = text(root, src);
    let looks_like_test_file = [&b"describe("[..], b"it(", b"test("]
        .iter()
        .any(|w| root_text.windows(w.len()).any(|x| x == *w));
    if !looks_like_test_file {
        return false;
    }
    // `expect` itself, at the start of `expect(x).toBe(y)`.
    if !call
        .parent()
        .is_some_and(|p| p.kind() == "member_expression")
    {
        return false;
    }
    let mut cur = call.parent();
    while let Some(p) = cur {
        if is_function_kind(p.kind()) {
            let describe_callback = p
                .parent()
                .filter(|a| a.kind() == "arguments")
                .and_then(|a| a.parent())
                .and_then(|c| c.child_by_field_name("function"))
                .is_some_and(|f| matches!(text(f, src), b"describe" | b"context" | b"suite"));
            if !describe_callback {
                return false;
            }
        }
        cur = p.parent();
    }
    true
}

// ------------------------------------------------------------- misc

fn to_string_is_missing(node: Node, src: &[u8]) -> bool {
    // `${obj}` and 'text' + obj with an object literal, or an instance of a
    // class in this file that defines no toString.
    let target = match node.kind() {
        "template_substitution" => node.named_child(0),
        "binary_expression" if operator_text(node, src) == b"+" => {
            let (l, r) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            );
            match (l, r) {
                (Some(l), Some(r)) if literal_kind(l) == Some("string") => Some(r),
                (Some(l), Some(r)) if literal_kind(r) == Some("string") => Some(l),
                _ => None,
            }
        }
        _ => None,
    };
    let Some(target) = target else {
        return false;
    };
    if literal_kind(target) == Some("object") {
        return true;
    }
    if target.kind() != "identifier" {
        return false;
    }
    let root = root_node(node);
    let mut class_name = None;
    walk(root, &mut |n| {
        if class_name.is_none()
            && n.kind() == "variable_declarator"
            && n.child_by_field_name("name")
                .is_some_and(|x| text(x, src) == text(target, src))
            && let Some(v) = n.child_by_field_name("value")
            && v.kind() == "new_expression"
        {
            class_name = v.child_by_field_name("constructor").map(|c| text(c, src));
        }
        class_name.is_none()
    });
    let Some(class_name) = class_name else {
        return false;
    };
    let mut defined = false;
    let mut has_to_string = false;
    walk(root, &mut |n| {
        if n.kind() == "class_declaration"
            && n.child_by_field_name("name")
                .is_some_and(|x| text(x, src) == class_name)
        {
            defined = true;
            has_to_string = n.child_by_field_name("body").is_some_and(|b| {
                named(b).iter().any(|m| {
                    m.child_by_field_name("name")
                        .is_some_and(|x| text(x, src) == b"toString")
                })
            }) || n.child_by_field_name("heritage").is_some()
                || has_token(n, "class_heritage");
        }
        true
    });
    defined && !has_to_string
}

fn wallet_phrase_is_hardcoded(string: Node, src: &[u8]) -> bool {
    let Some(parent) = string.parent() else {
        return false;
    };
    let name = match parent.kind() {
        "variable_declarator" => parent.child_by_field_name("name"),
        "pair" => parent.child_by_field_name("key"),
        _ => None,
    };
    let Some(name) = name else {
        return false;
    };
    let name = String::from_utf8_lossy(text(name, src)).to_ascii_lowercase();
    let named_like_a_phrase = [
        "mnemonic",
        "seedphrase",
        "seed_phrase",
        "recoveryphrase",
        "recovery_phrase",
        "walletphrase",
        "secretphrase",
        "secret_phrase",
    ]
    .iter()
    .any(|w| name.contains(w));
    if !named_like_a_phrase {
        return false;
    }
    let value = string_content(string, src);
    let words: Vec<&[u8]> = value
        .split(|b| *b == b' ')
        .filter(|w| !w.is_empty())
        .collect();
    [12, 15, 18, 21, 24].contains(&words.len())
        && words
            .iter()
            .all(|w| (3..=8).contains(&w.len()) && w.iter().all(u8::is_ascii_lowercase))
}

fn function_captures_nothing(function: Node, src: &[u8]) -> bool {
    // A named function or a const-bound arrow, declared inside another function.
    let (name_owner, func) = match function.kind() {
        "function_declaration" => (function, function),
        "variable_declarator" => {
            let Some(v) = function
                .child_by_field_name("value")
                .filter(|v| matches!(v.kind(), "arrow_function" | "function_expression"))
            else {
                return false;
            };
            (function, v)
        }
        _ => return false,
    };
    let Some(enclosing) = enclosing_function_of(name_owner) else {
        return false;
    };
    if enclosing.kind() == "method_definition" && false {
        return false;
    }
    let uses_this = {
        let mut found = false;
        walk(func, &mut |n| {
            if matches!(n.kind(), "this" | "super")
                || (n.kind() == "identifier" && text(n, src) == b"arguments")
            {
                found = true;
            }
            !found && !(is_function_kind(n.kind()) && n.kind() != "arrow_function")
        });
        found
    };
    if uses_this {
        return false;
    }
    let own = declared_names(func, src);
    let outer_scope: Vec<&[u8]> = {
        let all = declared_names(enclosing, src);
        let inner = declared_names(func, src);
        all.into_iter().filter(|n| !inner.contains(n)).collect()
    };
    let mut free = references(func)
        .into_iter()
        .filter(|r| !own.contains(&text(*r, src)));
    let name = name_owner
        .child_by_field_name("name")
        .map(|n| text(n, src))
        .unwrap_or_default();
    !free.any(|r| {
        outer_scope.contains(&text(r, src))
            || (text(r, src) != name
                && is_declared_in_enclosing_params(enclosing, text(r, src), src))
    }) && !name.is_empty()
}

fn is_declared_in_enclosing_params(enclosing: Node, name: &[u8], src: &[u8]) -> bool {
    let mut names = Vec::new();
    if let Some(params) = enclosing.child_by_field_name("parameters") {
        for c in named(params) {
            pattern_names(c, src, &mut names);
        }
    }
    if let Some(p) = enclosing.child_by_field_name("parameter") {
        pattern_names(p, src, &mut names);
    }
    names.contains(&name)
}

// ------------------------------------------------------------- React and TypeScript

fn jsx_below(node: Node) -> bool {
    let mut found = false;
    walk(node, &mut |n| {
        if matches!(
            n.kind(),
            "jsx_element" | "jsx_self_closing_element" | "jsx_fragment"
        ) {
            found = true;
        }
        !found
    });
    found
}

fn component_name<'t, 's>(node: Node<'t>, src: &'s [u8]) -> Option<(&'s [u8], Node<'t>)> {
    let (name, func) = match node.kind() {
        "function_declaration" => (node.child_by_field_name("name")?, node),
        "variable_declarator" => (
            node.child_by_field_name("name")?,
            node.child_by_field_name("value")
                .filter(|v| matches!(v.kind(), "arrow_function" | "function_expression"))?,
        ),
        _ => return None,
    };
    let text_ = text(name, src);
    if !text_.first().is_some_and(u8::is_ascii_uppercase) || !jsx_below(func) {
        return None;
    }
    Some((text_, func))
}

fn first_parameter(func: Node) -> Option<Node> {
    func.child_by_field_name("parameters")
        .and_then(|p| named(p).into_iter().next())
        .or_else(|| func.child_by_field_name("parameter"))
}

fn props_without_prop_types(node: Node, src: &[u8]) -> bool {
    let Some((name, func)) = component_name(node, src) else {
        return false;
    };
    if first_parameter(func).is_none() {
        return false;
    }
    let root = text(root_node(node), src);
    let needle = [name, b".propTypes"].concat();
    !(root.windows(needle.len()).any(|w| w == needle.as_slice()))
        && !root.windows(11).any(|w| w == b"propTypes =")
}

fn type_members<'t>(type_node: Node<'t>) -> Vec<Node<'t>> {
    match type_node.kind() {
        "interface_declaration" => type_node
            .child_by_field_name("body")
            .map(named)
            .unwrap_or_default(),
        "type_alias_declaration" => type_node
            .child_by_field_name("value")
            .filter(|v| v.kind() == "object_type")
            .map(named)
            .unwrap_or_default(),
        "object_type" => named(type_node),
        _ => Vec::new(),
    }
}

fn props_type_in_file<'t>(root: Node<'t>, name: &[u8], src: &[u8]) -> Option<Node<'t>> {
    let mut found = None;
    walk(root, &mut |n| {
        if found.is_none()
            && matches!(n.kind(), "interface_declaration" | "type_alias_declaration")
            && n.child_by_field_name("name")
                .is_some_and(|x| text(x, src) == name)
        {
            found = Some(n);
        }
        found.is_none()
    });
    found
}

fn props_are_writable<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let (_, func) = component_name(node, src)?;
    let param = first_parameter(func)?;
    let annotation = param.child_by_field_name("type")?;
    let ty = annotation.named_child(0)?;
    let members = match ty.kind() {
        "object_type" => type_members(ty),
        "type_identifier" => type_members(props_type_in_file(root_node(node), text(ty, src), src)?),
        _ => return None,
    };
    members
        .into_iter()
        .find(|m| m.kind() == "property_signature" && !has_token(*m, "readonly"))
        .map(|_| param)
}

fn declares_unused_props<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let (_, func) = component_name(node, src)?;
    let param = first_parameter(func)?;
    let pattern = param
        .child_by_field_name("pattern")
        .filter(|p| p.kind() == "object_pattern")?;
    if named(pattern).iter().any(|c| c.kind() == "rest_pattern") {
        return None;
    }
    let ty = param.child_by_field_name("type")?.named_child(0)?;
    if ty.kind() != "type_identifier" {
        return None;
    }
    let declaration = props_type_in_file(root_node(node), text(ty, src), src)?;
    let mut used = Vec::new();
    pattern_names(pattern, src, &mut used);
    // `{ a: renamed }` keeps the key a used.
    let mut keys: Vec<&[u8]> = Vec::new();
    for c in named(pattern) {
        match c.kind() {
            "pair_pattern" => {
                if let Some(k) = c.child_by_field_name("key") {
                    keys.push(text(k, src));
                }
            }
            "shorthand_property_identifier_pattern" | "object_assignment_pattern" => {
                keys.push(text(c.child_by_field_name("left").unwrap_or(c), src));
            }
            _ => {}
        }
    }
    type_members(declaration).into_iter().find(|m| {
        m.kind() == "property_signature"
            && m.child_by_field_name("name")
                .is_some_and(|n| !keys.contains(&text(n, src)))
    })
}

fn default_prop_is_required<'t>(program: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    // Component.propTypes = { a: PropTypes.string.isRequired } and
    // Component.defaultProps = { a: 'x' } name the same key.
    let mut prop_types: Vec<(Vec<u8>, Vec<Node>)> = Vec::new();
    let mut defaults: Vec<(Vec<u8>, Vec<&[u8]>)> = Vec::new();
    walk(program, &mut |n| {
        if n.kind() == "assignment_expression"
            && let (Some(left), Some(right)) = (
                n.child_by_field_name("left"),
                n.child_by_field_name("right"),
            )
            && left.kind() == "member_expression"
            && right.kind() == "object"
            && let (Some(obj), Some(prop)) = (
                left.child_by_field_name("object"),
                left.child_by_field_name("property"),
            )
        {
            let pairs: Vec<Node> = named(right)
                .into_iter()
                .filter(|p| p.kind() == "pair")
                .collect();
            match text(prop, src) {
                b"propTypes" => prop_types.push((text(obj, src).to_vec(), pairs)),
                b"defaultProps" => defaults.push((
                    text(obj, src).to_vec(),
                    pairs
                        .iter()
                        .filter_map(|p| p.child_by_field_name("key"))
                        .map(|k| text(k, src))
                        .collect(),
                )),
                _ => {}
            }
        }
        true
    });
    prop_types.iter().find_map(|(component, pairs)| {
        let (_, keys) = defaults.iter().find(|(c, _)| c == component)?;
        pairs.iter().copied().find(|p| {
            p.child_by_field_name("key")
                .is_some_and(|k| keys.contains(&text(k, src)))
                && p.child_by_field_name("value")
                    .is_some_and(|v| text(v, src).ends_with(b".isRequired"))
        })
    })
}

fn jsx_attribute_text<'t>(opening: Node<'t>, name: &str, src: &'t [u8]) -> Option<&'t [u8]> {
    let attr = attribute(opening, name, src)?;
    static_value(attr, src)
}

fn cell_references_a_missing_header(element: Node, src: &[u8]) -> bool {
    let Some(opening) = opening_tag(element) else {
        return false;
    };
    if !matches!(tag_name(opening, src), Some(b"td" | b"th")) {
        return false;
    }
    let Some(headers) = jsx_attribute_text(opening, "headers", src) else {
        return false;
    };
    let ids: Vec<&[u8]> = headers
        .split(|b| b.is_ascii_whitespace())
        .filter(|w| !w.is_empty())
        .collect();
    let root = root_node(element);
    ids.iter().any(|id| {
        let mut found = false;
        walk(root, &mut |n| {
            if !found && n.kind() == "jsx_attribute" {
                let is_id = n.named_child(0).is_some_and(|k| text(k, src) == b"id");
                if is_id && static_value(n, src) == Some(*id) {
                    found = true;
                }
            }
            !found
        });
        !found
    })
}

const GLOBAL_ARIA: &[&str] = &[
    "atomic",
    "busy",
    "controls",
    "current",
    "describedby",
    "details",
    "disabled",
    "dropeffect",
    "errormessage",
    "flowto",
    "grabbed",
    "haspopup",
    "hidden",
    "invalid",
    "keyshortcuts",
    "label",
    "labelledby",
    "live",
    "owns",
    "relevant",
    "roledescription",
];

/// Role-specific attributes: (attribute, roles that support it).
const ARIA_SPECIFIC: &[(&str, &[&str])] = &[
    (
        "checked",
        &[
            "checkbox",
            "menuitemcheckbox",
            "menuitemradio",
            "option",
            "radio",
            "switch",
            "treeitem",
        ],
    ),
    ("pressed", &["button"]),
    (
        "selected",
        &[
            "gridcell",
            "option",
            "row",
            "tab",
            "columnheader",
            "rowheader",
            "treeitem",
            "cell",
        ],
    ),
    ("level", &["heading", "listitem", "row", "treeitem"]),
    ("modal", &["dialog", "alertdialog"]),
    ("multiline", &["textbox"]),
    (
        "multiselectable",
        &["grid", "listbox", "tablist", "tree", "treegrid"],
    ),
    ("placeholder", &["textbox", "searchbox"]),
    ("sort", &["columnheader", "rowheader"]),
    (
        "valuenow",
        &[
            "meter",
            "progressbar",
            "scrollbar",
            "separator",
            "slider",
            "spinbutton",
        ],
    ),
    (
        "valuemin",
        &[
            "meter",
            "progressbar",
            "scrollbar",
            "separator",
            "slider",
            "spinbutton",
        ],
    ),
    (
        "valuemax",
        &[
            "meter",
            "progressbar",
            "scrollbar",
            "separator",
            "slider",
            "spinbutton",
        ],
    ),
    (
        "valuetext",
        &[
            "meter",
            "progressbar",
            "scrollbar",
            "separator",
            "slider",
            "spinbutton",
        ],
    ),
];

fn aria_attribute_is_unsupported_by_role(opening: Node, src: &[u8]) -> bool {
    let Some(role) = jsx_attribute_text(opening, "role", src) else {
        return false;
    };
    let role = String::from_utf8_lossy(role).into_owned();
    if !ARIA_SPECIFIC
        .iter()
        .any(|(_, roles)| roles.contains(&role.as_str()))
        && ![
            "presentation",
            "none",
            "link",
            "img",
            "navigation",
            "main",
            "banner",
            "article",
            "region",
            "form",
            "search",
            "contentinfo",
            "complementary",
            "list",
            "listitem",
            "status",
            "alert",
            "tooltip",
            "menu",
            "menubar",
            "toolbar",
            "tabpanel",
            "group",
        ]
        .contains(&role.as_str())
    {
        return false;
    }
    attributes(opening).into_iter().any(|a| {
        let Some(name) = a
            .named_child(0)
            .filter(|n| n.kind() == "property_identifier")
        else {
            return false;
        };
        let name = String::from_utf8_lossy(text(name, src)).into_owned();
        let Some(short) = name.strip_prefix("aria-") else {
            return false;
        };
        if GLOBAL_ARIA.contains(&short) {
            return false;
        }
        ARIA_SPECIFIC
            .iter()
            .find(|(attr, _)| *attr == short)
            .is_some_and(|(_, roles)| !roles.contains(&role.as_str()))
    })
}

fn is_aria_role_misuse(attr: Node, src: &[u8]) -> bool {
    // Reported on the opening tag, found from its role attribute.
    attr.parent()
        .is_some_and(|opening| aria_attribute_is_unsupported_by_role(opening, src))
        && attr.named_child(0).is_some_and(|n| text(n, src) == b"role")
}

fn default_type_argument_is_redundant(generic: Node, src: &[u8]) -> bool {
    let (Some(name), Some(args)) = (
        generic.child_by_field_name("name"),
        generic.child_by_field_name("type_arguments"),
    ) else {
        return false;
    };
    let declaration = {
        let mut found = None;
        walk(root_node(generic), &mut |n| {
            if found.is_none()
                && matches!(
                    n.kind(),
                    "interface_declaration" | "type_alias_declaration" | "class_declaration"
                )
                && n.child_by_field_name("name")
                    .is_some_and(|x| text(x, src) == text(name, src))
            {
                found = Some(n);
            }
            found.is_none()
        });
        found
    };
    let Some(params) = declaration.and_then(|d| d.child_by_field_name("type_parameters")) else {
        return false;
    };
    let defaults: Vec<Option<Vec<u8>>> = named(params)
        .into_iter()
        .map(|p| {
            p.child_by_field_name("value").map(|v| {
                let t = text(v, src);
                String::from_utf8_lossy(t)
                    .trim_start_matches('=')
                    .trim()
                    .as_bytes()
                    .to_vec()
            })
        })
        .collect();
    let given = named(args);
    given.last().is_some_and(|last| {
        let i = given.len() - 1;
        defaults
            .get(i)
            .and_then(|d| d.as_ref())
            .is_some_and(|d| d.as_slice() == text(*last, src))
    })
}

fn union_alias_is_repeated(union: Node, src: &[u8]) -> bool {
    if union
        .parent()
        .is_some_and(|p| matches!(p.kind(), "union_type" | "type_alias_declaration"))
    {
        return false;
    }
    fn count(n: Node) -> usize {
        if n.kind() == "union_type" {
            named(n).into_iter().map(count).sum()
        } else {
            1
        }
    }
    if count(union) < 3 {
        return false;
    }
    let key: Vec<u8> = text(union, src)
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    let mut seen = 0;
    let mut first = None;
    walk(root_node(union), &mut |n| {
        if n.kind() == "union_type"
            && !n
                .parent()
                .is_some_and(|p| matches!(p.kind(), "union_type" | "type_alias_declaration"))
            && text(n, src)
                .iter()
                .copied()
                .filter(|b| !b.is_ascii_whitespace())
                .eq(key.iter().copied())
        {
            seen += 1;
            first.get_or_insert(n.start_byte());
        }
        true
    });
    seen >= 2 && first == Some(union.start_byte())
}

fn cast_changes_nothing(node: Node, src: &[u8]) -> bool {
    match node.kind() {
        "as_expression" => {
            let (Some(value), Some(ty)) = (node.named_child(0), node.named_child(1)) else {
                return false;
            };
            matches!(
                (literal_kind(value), text(ty, src)),
                (Some("string"), b"string")
                    | (Some("number"), b"number")
                    | (Some("boolean"), b"boolean")
            )
        }
        "non_null_expression" => node.named_child(0).is_some_and(|e| {
            matches!(
                e.kind(),
                "this"
                    | "string"
                    | "number"
                    | "template_string"
                    | "array"
                    | "object"
                    | "new_expression"
                    | "true"
                    | "false"
            )
        }),
        _ => false,
    }
}

fn is_truthiness_test(id: Node) -> bool {
    let Some(p) = id.parent() else {
        return false;
    };
    match p.kind() {
        "unary_expression" => text_starts_with_not(p),
        "parenthesized_expression" => p.parent().is_some_and(|g| {
            matches!(
                g.kind(),
                "if_statement" | "while_statement" | "do_statement"
            )
        }),
        "ternary_expression" => p.child_by_field_name("condition") == Some(id),
        "binary_expression" => p
            .child_by_field_name("operator")
            .is_some_and(|o| matches!(o.kind(), "&&" | "||")),
        _ => false,
    }
}

fn text_starts_with_not(unary: Node) -> bool {
    unary
        .child_by_field_name("operator")
        .is_some_and(|o| o.kind() == "!")
}

fn find_result_only_tested(call: Node, src: &[u8]) -> bool {
    let Some(parent) = call.parent() else {
        return false;
    };
    // `if (items.find(...))` and `!items.find(...)`.
    if is_truthiness_test(call) {
        return true;
    }
    // `const hit = items.find(...)` where every later use asks only if it exists.
    if parent.kind() != "variable_declarator" || parent.child_by_field_name("value") != Some(call) {
        return false;
    }
    let Some(name) = parent
        .child_by_field_name("name")
        .filter(|n| n.kind() == "identifier")
    else {
        return false;
    };
    let Some(scope) = enclosing_function_of(parent) else {
        return false;
    };
    let uses: Vec<Node> = references(scope)
        .into_iter()
        .filter(|r| text(*r, src) == text(name, src) && *r != name)
        .collect();
    !uses.is_empty() && uses.iter().all(|u| is_truthiness_test(*u))
}
