//! JavaScript, JSX and TypeScript rules, part 4 (ADR-0007, batch 12): promise
//! and callback misuse, array-method pitfalls, SQL and DOMPurify, a few
//! React checks and more TypeScript type checks. Queries stay cheap on deep
//! trees: see `js_modern.rs`.

use super::js::{
    attribute, find_below, has_spread, has_token, on_dom_element, opening_tag, static_value,
    string_content, tag_name, text,
};
use super::js_extra::{count_pattern, count_word, named, operator_text};
use super::*;

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "js/await-non-promise",
        name: "await should only be used with promises",
        description: "Awaiting a literal or an object waits for nothing and hides a missing call.",
        message: "Remove this await, or await the real promise.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S4123")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(await_expression) @match"#,
            filter: Some(Keep(awaits_a_plain_value)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "async function f() { await 5; }",
            good: "async function f() { await load(); }",
        }),
    },
    Rule {
        id: "js/getter-reads-another-field",
        name: "Getters and setters should access the expected fields",
        description: "A getter that returns a different field than its name suggests is usually a typo.",
        message: "Return the field this getter is named for.",
        category: Bug,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S4275")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(method_definition name: (property_identifier)) @match"#,
            filter: Some(Keep(getter_reads_another_field)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "class A { constructor() { this._size = 1; this._count = 2; } get size() { return this._count; } }",
            good: "class A { constructor() { this._size = 1; } get size() { return this._size; } }",
        }),
    },
    Rule {
        id: "js/bitwise-in-condition",
        name: "Bitwise operators should not be used in boolean contexts",
        description: "`a > 1 & b > 1` evaluates both sides even when the first is false.",
        message: "Use && or ||.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S1529")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(binary_expression) @match"#,
            filter: Some(Keep(bitwise_between_conditions)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (a > 1 & b > 1) {}",
            good: "if (a > 1 && b > 1) {}",
        }),
    },
    Rule {
        id: "js/in-with-primitive",
        name: "in should not be used with primitive types",
        description: "The right operand of `in` must be an object; a string or number throws.",
        message: "Check the value another way.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S3785")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(binary_expression) @match"#,
            filter: Some(Keep(in_on_a_primitive)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const r = 'a' in 'abc';",
            good: "const r = 'abc'.includes('a');",
        }),
    },
    Rule {
        id: "js/callback-without-return",
        name: "Callbacks of array methods should have return statements",
        description: "A map or filter callback with a block body and no return produces undefined for every element.",
        message: "Return a value from this callback.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3796")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression property: (property_identifier) @p (#any-of? @p "map" "filter" "flatMap" "some" "every" "find" "findIndex" "reduce" "sort")) arguments: (arguments . [(arrow_function) (function_expression)] @cb)) @match"#,
            filter: Some(Keep(callback_never_returns)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const r = list.map(x => { x * 2; });",
            good: "const r = list.map(x => { return x * 2; });",
        }),
    },
    Rule {
        id: "js/size-comparison",
        name: "Collection size and array length comparisons should make sense",
        description: "A length is never negative, so `length < 0` is always false and `length >= 0` always true.",
        message: "Fix this comparison.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S3981")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(binary_expression) @match"#,
            filter: Some(Keep(compares_size_with_zero_nonsensically)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (items.length < 0) {}",
            good: "if (items.length === 0) {}",
        }),
    },
    Rule {
        id: "js/in-on-array",
        name: "in should not be used on arrays",
        description: "`x in [1, 2]` tests property names (0 and 1), not values.",
        message: "Use includes().",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S4619")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(binary_expression) @match"#,
            filter: Some(Keep(in_on_an_array_literal)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const r = 2 in [1, 2, 3];",
            good: "const r = [1, 2, 3].includes(2);",
        }),
    },
    Rule {
        id: "js/async-foreach",
        name: "Promises should not be misused",
        description: "forEach ignores the promises an async callback returns, so nothing waits for them.",
        message: "Use a for...of loop or Promise.all.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6544")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression property: (property_identifier) @p (#eq? @p "forEach"))) @match"#,
            filter: Some(Keep(callback_is_async)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "list.forEach(async (x) => { await save(x); });",
            good: "await Promise.all(list.map((x) => save(x)));",
        }),
    },
    Rule {
        id: "js/reject-with-literal",
        name: "Literals should not be used for promise rejection",
        description: "A rejection with a string has no stack trace.",
        message: "Reject with an Error.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6671")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression object: (identifier) @o property: (property_identifier) @p (#eq? @o "Promise") (#eq? @p "reject"))) @match"#,
            filter: Some(Keep(rejects_with_a_literal)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const p = Promise.reject('failed');",
            good: "const p = Promise.reject(new Error('failed'));",
        }),
    },
    Rule {
        id: "js/reduce-without-initial",
        name: "Array.reduce() calls should include an initial value",
        description: "Without one, reduce throws on an empty array.",
        message: "Pass an initial value.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6959")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression property: (property_identifier) @p (#any-of? @p "reduce" "reduceRight"))) @match"#,
            filter: Some(Keep(reduces_without_initial_value)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const s = [1, 2, 3].reduce((a, b) => a + b);",
            good: "const s = [1, 2, 3].reduce((a, b) => a + b, 0);",
        }),
    },
    Rule {
        id: "js/parseint-as-callback",
        name: "Function references should not be passed directly to iterator methods",
        description: "`['1','2','3'].map(parseInt)` passes the index as the radix.",
        message: "Wrap the call: x => parseInt(x, 10).",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S7727")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression property: (property_identifier) @p (#any-of? @p "map" "flatMap")) arguments: (arguments . (identifier) @a (#eq? @a "parseInt"))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const r = list.map(parseInt);",
            good: "const r = list.map((x) => parseInt(x, 10));",
        }),
    },
    Rule {
        id: "js/sort-assigned",
        name: "Array-mutating methods should not be used misleadingly",
        description: "sort() and reverse() change the array in place, so assigning the result suggests a copy that does not exist.",
        message: "Copy the array first, or use toSorted().",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S4043")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(variable_declarator value: (call_expression function: (member_expression object: (identifier) property: (property_identifier) @p (#any-of? @p "sort" "reverse")))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const sorted = items.sort();",
            good: "const sorted = [...items].sort();",
        }),
    },
    Rule {
        id: "js/dissimilar-strict-equality",
        name: "Strict equality operators should not be used with dissimilar types",
        description: "`1 === '1'` is always false.",
        message: "Compare values of the same type.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S3403")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(binary_expression) @match"#,
            filter: Some(Keep(compares_dissimilar_literals)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (1 === '1') {}",
            good: "if (1 === 1) {}",
        }),
    },
    Rule {
        id: "js/ignored-pure-call",
        name: "Return values from functions without side effects should not be ignored",
        description: "Calling toLowerCase() or map() and dropping the result does nothing.",
        message: "Use the returned value.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2201")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(expression_statement (call_expression function: (member_expression property: (property_identifier) @p (#any-of? @p "toLowerCase" "toUpperCase" "trim" "trimStart" "trimEnd" "substring" "substr" "slice" "concat" "map" "filter" "padStart" "padEnd" "repeat" "includes" "startsWith" "endsWith")))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "name.toLowerCase();",
            good: "name = name.toLowerCase();",
        }),
    },
    Rule {
        id: "js/sql-built-dynamically",
        name: "SQL queries should not be dynamically formatted",
        description: "Building a query from strings lets an attacker change what it does.",
        message: "Use a parameterized query.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 15,
        sonar: &[related("S2077")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression property: (property_identifier) @p (#any-of? @p "query" "execute" "raw" "prepare"))) @match"#,
            filter: Some(Keep(query_is_built_from_strings)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "db.query(`SELECT * FROM t WHERE id = ${id}`);",
            good: "db.query('SELECT * FROM t WHERE id = ?', [id]);",
        }),
    },
    Rule {
        id: "js/postmessage-origin",
        name: "Origins should be verified during cross-origin communications",
        description: "A message handler that never looks at event.origin accepts messages from any site.",
        message: "Check event.origin.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S2819")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression property: (property_identifier) @p (#eq? @p "addEventListener"))) @match"#,
            filter: Some(Keep(message_handler_ignores_origin)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "window.addEventListener('message', (e) => { run(e.data); });",
            good: "window.addEventListener('message', (e) => { if (e.origin === TRUSTED) run(e.data); });",
        }),
    },
    Rule {
        id: "js/dompurify-unsafe-config",
        name: "DOMPurify configuration should not be bypassable",
        description: "Allowing script tags or unknown protocols defeats what the sanitizer is for.",
        message: "Remove the unsafe option.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S8479")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression object: (identifier) @o property: (property_identifier) @p (#eq? @o "DOMPurify") (#eq? @p "sanitize"))) @match"#,
            filter: Some(Keep(dompurify_config_is_unsafe)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "DOMPurify.sanitize(html, { ADD_TAGS: ['script'] });",
            good: "DOMPurify.sanitize(html);",
        }),
    },
    Rule {
        id: "js/script-without-integrity",
        name: "Remote artifacts should not be used without integrity checks",
        description: "A script from another origin can be replaced without anyone noticing.",
        message: "Add an integrity attribute.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S5725")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_self_closing_element name: (identifier) @n (#any-of? @n "script" "link")) @match
(jsx_element open_tag: (jsx_opening_element name: (identifier) @n2 (#any-of? @n2 "script" "link"))) @match"#,
            filter: Some(Keep(remote_asset_lacks_integrity)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const s = <script src=\"https://cdn.example.net/lib.js\" />;",
            good: "const s = <script src=\"https://cdn.example.net/lib.js\" integrity=\"sha384-abc\" crossOrigin=\"anonymous\" />;",
        }),
    },
    Rule {
        id: "js/internal-api",
        name: "Users should not use internal APIs",
        description: "Underscore-prefixed internals change without notice.",
        message: "Use the public API.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S6627")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"((property_identifier) @match (#match? @match "^(__SECRET|_reactInternal|__reactFiber|__reactProps)"))"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const f = node._reactInternals;",
            good: "const r = useRef(null);",
        }),
    },
    Rule {
        id: "js/optional-chaining-preferred",
        name: "Optional chaining should be preferred",
        description: "`a && a.b` is `a?.b`.",
        message: "Use optional chaining.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6582")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(binary_expression) @match"#,
            filter: Some(Keep(guards_then_reads_the_same_value)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const v = user && user.name;",
            good: "const v = user?.name;",
        }),
    },
    Rule {
        id: "js/nullish-coalescing-preferred",
        name: "Nullish coalescing should be preferred",
        description: "`x != null ? x : y` is `x ?? y`.",
        message: "Use ??.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6606")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(ternary_expression) @match"#,
            filter: Some(Keep(ternary_is_a_nullish_default)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const v = x != null ? x : 'd';",
            good: "const v = x ?? 'd';",
        }),
    },
    Rule {
        id: "js/consecutive-push",
        name: "Multiple consecutive calls to methods that accept multiple arguments should be merged",
        description: "push(a, b) does what two push calls do.",
        message: "Merge these calls.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7778")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(statement_block) @match
(program) @match"#,
            filter: Some(Find(repeated_push)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "list.push(1);\nlist.push(2);",
            good: "list.push(1, 2);",
        }),
    },
    Rule {
        id: "js/this-arg",
        name: "Array method callbacks should not use the thisArg parameter",
        description: "An arrow function or bind() says which this is meant.",
        message: "Use an arrow function.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7729")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression property: (property_identifier) @p (#any-of? @p "map" "filter" "forEach" "some" "every" "find" "findIndex" "flatMap"))) @match"#,
            filter: Some(Keep(passes_a_this_argument)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "list.map(function (x) { return this.f(x); }, this);",
            good: "list.map((x) => this.f(x));",
        }),
    },
    Rule {
        id: "js/void-operator",
        name: "void should not be used",
        description: "`void` is cryptic; its common uses have clearer forms.",
        message: "Remove void.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S3735")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(unary_expression operator: "void") @match"#,
            filter: Some(Keep(void_is_not_void_zero)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "void fetchData();",
            good: "fetchData().catch(report);",
        }),
    },
    Rule {
        id: "js/index-of-positive",
        name: "indexOf checks should not be for positive numbers",
        description: "`indexOf(x) > 0` misses a match at index 0.",
        message: "Compare with -1 or use includes().",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2692")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(binary_expression) @match"#,
            filter: Some(Keep(checks_index_of_for_positive)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (list.indexOf(x) > 0) {}",
            good: "if (list.includes(x)) {}",
        }),
    },
    Rule {
        id: "js/polyfill-import",
        name: "Polyfills should not be used when native support is available",
        description: "Modern runtimes already provide these features.",
        message: "Remove the polyfill.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S7742")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(import_statement source: (string) @match)
(call_expression function: (identifier) @f (#eq? @f "require") arguments: (arguments . (string) @match))"#,
            filter: Some(Keep(names_a_polyfill)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "import 'core-js/stable';",
            good: "import { run } from './run';",
        }),
    },
    Rule {
        id: "js/numeric-separator-grouping",
        name: "Numeric literals should use consistent digit grouping with separators",
        description: "1_00_000 mixes group sizes.",
        message: "Group digits in threes.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S7749")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(number) @match"#,
            filter: Some(Keep(separator_groups_are_uneven)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const n = 1_00_000;",
            good: "const n = 100_000;",
        }),
    },
    Rule {
        id: "js/autocomplete-value",
        name: "DOM elements should use the autocomplete attribute correctly",
        description: "A value that is not in the HTML list is ignored by browsers.",
        message: "Use a valid autocomplete token.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6840")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_attribute (property_identifier) @a (#eq? @a "autoComplete")) @match"#,
            filter: Some(Keep(autocomplete_is_not_a_known_token)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const i = <input autoComplete=\"mail\" />;",
            good: "const i = <input autoComplete=\"email\" />;",
        }),
    },
    Rule {
        id: "js/render-zero",
        name: "React components should not render non-boolean condition values",
        description: "`{items.length && <List />}` renders 0 when the list is empty.",
        message: "Compare explicitly: items.length > 0 &&.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6439")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_expression (binary_expression)) @match"#,
            filter: Some(Keep(renders_a_count_when_empty)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const v = <div>{items.length && <List />}</div>;",
            good: "const v = <div>{items.length > 0 && <List />}</div>;",
        }),
    },
    Rule {
        id: "ts/type-predicate",
        name: "Type predicates should be used",
        description: "A boolean-returning check does not narrow the type for the caller.",
        message: "Return a type predicate (x is T).",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S4322")],
        check: Check::Query {
            langs: TS,
            query: r#"(function_declaration) @match"#,
            filter: Some(Keep(boolean_check_could_be_a_predicate)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "function isText(x: unknown): boolean { return typeof x === 'string'; }",
            good: "function isText(x: unknown): x is string { return typeof x === 'string'; }",
        }),
    },
    Rule {
        id: "ts/readonly-private-field",
        name: "Fields that are only assigned in the constructor should be readonly",
        description: "readonly states the intent and stops later accidental writes.",
        message: "Make this field readonly.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S2933")],
        check: Check::Query {
            langs: TS,
            query: r#"(class_body) @match"#,
            filter: Some(Find(private_field_only_set_in_constructor)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "class A { private name: string; constructor(n: string) { this.name = n; } }",
            good: "class A { private readonly name: string; constructor(n: string) { this.name = n; } }",
        }),
    },
    Rule {
        id: "ts/optional-and-undefined",
        name: "Optional property declarations should not use both ? and undefined",
        description: "`a?: string | undefined` says undefined twice.",
        message: "Remove one of them.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S4782")],
        check: Check::Query {
            langs: TS,
            query: r#"(property_signature) @match
(public_field_definition) @match"#,
            filter: Some(Keep(optional_with_undefined)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "interface I { a?: string | undefined; }",
            good: "interface I { a?: string; }",
        }),
    },
    Rule {
        id: "ts/redundant-union-constituent",
        name: "Type constituents of unions and intersections should not be redundant",
        description: "`string | any` is `any`, and `'a' | string` is `string`.",
        message: "Remove the redundant constituent.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6571")],
        check: Check::Query {
            langs: TS,
            query: r#"(union_type) @match"#,
            filter: Some(Keep(union_has_a_redundant_member)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "type A = string | any;",
            good: "type A = string | number;",
        }),
    },
    Rule {
        id: "ts/enum-mixed-values",
        name: "Enum members should not mix value types",
        description: "An enum with both numbers and strings has no consistent meaning.",
        message: "Use one value type.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6583")],
        check: Check::Query {
            langs: TS,
            query: r#"(enum_body) @match"#,
            filter: Some(Keep(mixes_number_and_string_values)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "enum E { A = 1, B = 'b' }",
            good: "enum E { A = 1, B = 2 }",
        }),
    },
];

// ---------------------------------------------------- filters

fn awaits_a_plain_value(await_: Node, _: &[u8]) -> bool {
    await_.named_child(0).is_some_and(|v| {
        matches!(
            v.kind(),
            "number"
                | "string"
                | "array"
                | "object"
                | "arrow_function"
                | "function_expression"
                | "template_string"
                | "true"
                | "false"
                | "null"
                | "regex"
        )
    })
}

fn getter_reads_another_field(method: Node, src: &[u8]) -> bool {
    if !has_token(method, "get") {
        return false;
    }
    let (Some(name), Some(body), Some(class)) = (
        method.child_by_field_name("name"),
        method.child_by_field_name("body"),
        method.parent().filter(|b| b.kind() == "class_body"),
    ) else {
        return false;
    };
    let items = named(body);
    let [only] = items.as_slice() else {
        return false;
    };
    let Some(read) = only
        .named_child(0)
        .filter(|v| only.kind() == "return_statement" && v.kind() == "member_expression")
    else {
        return false;
    };
    if !read
        .child_by_field_name("object")
        .is_some_and(|o| o.kind() == "this")
    {
        return false;
    }
    let Some(property) = read.child_by_field_name("property") else {
        return false;
    };
    let n = text(name, src);
    let expected: [Vec<u8>; 3] = [n.to_vec(), [b"_", n].concat(), [b"#", n].concat()];
    let returned = text(property, src);
    if expected.iter().any(|e| e.as_slice() == returned) {
        return false;
    }
    // The field the name suggests has to exist, or the getter may be fine.
    let class_text = text(class, src);
    expected
        .iter()
        .any(|e| count_pattern(class_text, &[b"this.", e.as_slice()].concat()) > 0)
}

fn bitwise_between_conditions(binary: Node, src: &[u8]) -> bool {
    if !matches!(operator_text(binary, src), b"&" | b"|") {
        return false;
    }
    let conditional = |n: Option<Node>| {
        n.is_some_and(|n| match n.kind() {
            "binary_expression" => matches!(
                operator_text(n, src),
                b"==" | b"!=" | b"===" | b"!==" | b"<" | b">" | b"<=" | b">=" | b"&&" | b"||"
            ),
            "unary_expression" => operator_text(n, src) == b"!",
            "true" | "false" => true,
            _ => false,
        })
    };
    conditional(binary.child_by_field_name("left"))
        && conditional(binary.child_by_field_name("right"))
}

fn in_on_a_primitive(binary: Node, src: &[u8]) -> bool {
    operator_text(binary, src) == b"in"
        && binary.child_by_field_name("right").is_some_and(|r| {
            matches!(
                r.kind(),
                "string" | "number" | "true" | "false" | "template_string"
            )
        })
}

fn callback_never_returns(call: Node, _: &[u8]) -> bool {
    let Some(callback) = call
        .child_by_field_name("arguments")
        .and_then(|a| a.named_child(0))
    else {
        return false;
    };
    let Some(body) = callback
        .child_by_field_name("body")
        .filter(|b| b.kind() == "statement_block")
    else {
        return false;
    };
    !named(body).is_empty()
        && find_below(body, false, |n| {
            n.kind() == "return_statement" && n.named_child_count() > 0
        })
        .is_none()
        && !has_token(callback, "async")
}

fn compares_size_with_zero_nonsensically(binary: Node, src: &[u8]) -> bool {
    let (Some(l), Some(r)) = (
        binary.child_by_field_name("left"),
        binary.child_by_field_name("right"),
    ) else {
        return false;
    };
    let is_size = l.kind() == "member_expression"
        && l.child_by_field_name("property")
            .is_some_and(|p| matches!(text(p, src), b"length" | b"size"));
    is_size && text(r, src) == b"0" && matches!(operator_text(binary, src), b"<" | b">=")
}

fn in_on_an_array_literal(binary: Node, src: &[u8]) -> bool {
    operator_text(binary, src) == b"in"
        && binary
            .child_by_field_name("right")
            .is_some_and(|r| r.kind() == "array")
}

fn callback_is_async(call: Node, _: &[u8]) -> bool {
    call.child_by_field_name("arguments")
        .and_then(|a| a.named_child(0))
        .is_some_and(|cb| {
            matches!(cb.kind(), "arrow_function" | "function_expression") && has_token(cb, "async")
        })
}

fn rejects_with_a_literal(call: Node, _: &[u8]) -> bool {
    call.child_by_field_name("arguments")
        .and_then(|a| a.named_child(0))
        .is_some_and(|v| {
            matches!(
                v.kind(),
                "string" | "number" | "true" | "false" | "null" | "template_string"
            )
        })
}

fn reduces_without_initial_value(call: Node, src: &[u8]) -> bool {
    let Some(args) = call.child_by_field_name("arguments") else {
        return false;
    };
    // SonarQube reports it where the receiver is known to be an array: an
    // `.reduce` on a parameter or any other unknown value may not be one.
    matches!(named(args).as_slice(), [only] if matches!(only.kind(), "arrow_function" | "function_expression"))
        && call
            .child_by_field_name("function")
            .and_then(|f| f.child_by_field_name("object"))
            .is_some_and(|o| is_provably_array(o, src, 0))
}

/// Whether the file itself shows `expr` to be an array: a literal, a
/// well-known array producer, a method chain on one, a local declared as
/// one, or a call to a function in this file that returns one.
pub(super) fn is_provably_array(expr: Node, src: &[u8], depth: usize) -> bool {
    is_provably(expr, src, depth, false)
}

/// The same for strings: a literal, a string method, `await res.text()`.
pub(super) fn is_provably_string(expr: Node, src: &[u8], depth: usize) -> bool {
    is_provably(expr, src, depth, true)
}

fn is_provably(expr: Node, src: &[u8], depth: usize, strings: bool) -> bool {
    if depth > 6 {
        return false;
    }
    let again = |e: Node| is_provably(e, src, depth + 1, strings);
    if strings {
        return match expr.kind() {
            "string" | "template_string" => true,
            "parenthesized_expression" => expr.named_child(0).is_some_and(again),
            "await_expression" => expr.named_child(0).is_some_and(|c| {
                c.child_by_field_name("function")
                    .and_then(|f| f.child_by_field_name("property"))
                    .is_some_and(|p| text(p, src) == b"text")
            }),
            "binary_expression" => {
                operator_text(expr, src) == b"+"
                    && ["left", "right"].iter().any(|f| {
                        expr.child_by_field_name(f)
                            .is_some_and(|c| matches!(c.kind(), "string" | "template_string"))
                    })
            }
            "call_expression" => {
                let Some(f) = expr.child_by_field_name("function") else {
                    return false;
                };
                let t = text(f, src);
                if matches!(t, b"String" | b"JSON.stringify") {
                    return true;
                }
                f.child_by_field_name("property").is_some_and(|m| {
                    matches!(
                        text(m, src),
                        b"toString"
                            | b"trim"
                            | b"toLowerCase"
                            | b"toUpperCase"
                            | b"padStart"
                            | b"padEnd"
                            | b"join"
                            | b"toFixed"
                    )
                })
            }
            "identifier" => lookup_declared(expr, src, |v| is_provably(v, src, depth + 1, true)),
            _ => false,
        };
    }
    match expr.kind() {
        "array" => true,
        "parenthesized_expression" => expr
            .named_child(0)
            .is_some_and(|e| is_provably_array(e, src, depth + 1)),
        "new_expression" => expr
            .child_by_field_name("constructor")
            .is_some_and(|c| text(c, src) == b"Array"),
        "call_expression" => {
            let Some(function) = expr.child_by_field_name("function") else {
                return false;
            };
            let t = text(function, src);
            if matches!(
                t,
                b"Array.from" | b"Array.of" | b"Object.keys" | b"Object.values" | b"Object.entries"
            ) {
                return true;
            }
            match function.kind() {
                "member_expression" => {
                    let method = function
                        .child_by_field_name("property")
                        .map(|p| text(p, src))
                        .unwrap_or_default();
                    match method {
                        b"split" => true,
                        b"map" | b"filter" | b"slice" | b"concat" | b"flat" | b"flatMap"
                        | b"sort" | b"toSorted" | b"reverse" => function
                            .child_by_field_name("object")
                            .is_some_and(|o| is_provably_array(o, src, depth + 1)),
                        _ => false,
                    }
                }
                "identifier" => returns_an_array(expr, t, src, depth),
                _ => false,
            }
        }
        "identifier" => lookup_declared(expr, src, |v| is_provably(v, src, depth + 1, false)),
        _ => false,
    }
}

/// Whether the nearest scope declaring the identifier initializes it with a
/// value `accept` approves: a parameter of a function is a value nobody has
/// shown anything about.
fn lookup_declared(id: Node, src: &[u8], accept: impl Fn(Node) -> bool) -> bool {
    let name = text(id, src);
    let mut scope = id.parent();
    while let Some(s) = scope {
        let is_function = matches!(
            s.kind(),
            "function_declaration"
                | "function_expression"
                | "arrow_function"
                | "method_definition"
                | "generator_function"
                | "generator_function_declaration"
                | "program"
        );
        if is_function {
            if declares_parameter(s, name, src) {
                return false;
            }
            let mut declared: Option<Node> = None;
            crate::rules::catalog::js_syntax::walk(s, &mut |n| {
                if declared.is_some() {
                    return false;
                }
                if matches!(
                    n.kind(),
                    "function_declaration"
                        | "function_expression"
                        | "arrow_function"
                        | "method_definition"
                ) {
                    return false;
                }
                if n.kind() == "variable_declarator"
                    && n.child_by_field_name("name")
                        .is_some_and(|x| text(x, src) == name)
                {
                    declared = Some(n);
                }
                true
            });
            if let Some(d) = declared {
                return d.child_by_field_name("value").is_some_and(&accept);
            }
        }
        scope = s.parent();
    }
    false
}

fn declares_parameter(function: Node, name: &[u8], src: &[u8]) -> bool {
    let mut names: Vec<&[u8]> = Vec::new();
    let mut add = |n: Node| {
        let mut stack = vec![n];
        while let Some(p) = stack.pop() {
            match p.kind() {
                "identifier" | "shorthand_property_identifier_pattern" => names.push(text(p, src)),
                _ => stack.extend(named(p)),
            }
        }
    };
    if let Some(params) = function.child_by_field_name("parameters") {
        add(params);
    }
    if let Some(p) = function.child_by_field_name("parameter") {
        add(p);
    }
    names.contains(&name)
}

fn root_of(node: Node) -> Node {
    let mut cur = node;
    while let Some(p) = cur.parent() {
        cur = p;
    }
    cur
}

/// A call to a function declared in this file whose every return is an array.
fn returns_an_array(call: Node, name: &[u8], src: &[u8], depth: usize) -> bool {
    let mut declared = None;
    crate::rules::catalog::js_syntax::walk(root_of(call), &mut |n| {
        if declared.is_none()
            && n.kind() == "function_declaration"
            && n.child_by_field_name("name")
                .is_some_and(|x| text(x, src) == name)
        {
            declared = Some(n);
        }
        declared.is_none()
    });
    let Some(function) = declared.and_then(|f| f.child_by_field_name("body")) else {
        return false;
    };
    let mut returns = Vec::new();
    crate::rules::catalog::js_syntax::walk(function, &mut |n| {
        if matches!(
            n.kind(),
            "function_declaration" | "function_expression" | "arrow_function"
        ) {
            return false;
        }
        if n.kind() == "return_statement" {
            returns.push(n.named_child(0));
        }
        true
    });
    !returns.is_empty()
        && returns
            .iter()
            .all(|r| r.is_some_and(|v| is_provably_array(v, src, depth + 1)))
}

fn compares_dissimilar_literals(binary: Node, src: &[u8]) -> bool {
    if !matches!(operator_text(binary, src), b"===" | b"!==") {
        return false;
    }
    let kind = |n: Option<Node>| -> Option<&'static str> {
        match n?.kind() {
            "number" => Some("number"),
            "string" => Some("string"),
            "true" | "false" => Some("boolean"),
            "null" => Some("null"),
            _ => None,
        }
    };
    match (
        kind(binary.child_by_field_name("left")),
        kind(binary.child_by_field_name("right")),
    ) {
        (Some(a), Some(b)) => a != b,
        _ => false,
    }
}

fn query_is_built_from_strings(call: Node, src: &[u8]) -> bool {
    let Some(first) = call
        .child_by_field_name("arguments")
        .and_then(|a| a.named_child(0))
    else {
        return false;
    };
    match first.kind() {
        "template_string" => find_below(first, true, |n| {
            n.kind() == "template_substitution"
                && n.named_child(0)
                    .is_none_or(|e| !is_numeric_expression(e, src))
        })
        .is_some(),
        "binary_expression" => {
            operator_text(first, src) == b"+"
                && find_below(first, true, |n| n.kind() == "string").is_some()
                && !all_literals(first)
        }
        _ => false,
    }
}

/// Whether the value is plainly a number, which cannot carry an injection.
fn is_numeric_expression(expr: Node, src: &[u8]) -> bool {
    match expr.kind() {
        "number" => true,
        "parenthesized_expression" => expr
            .named_child(0)
            .is_some_and(|e| is_numeric_expression(e, src)),
        "call_expression" => expr.child_by_field_name("function").is_some_and(|f| {
            let t = text(f, src);
            t.starts_with(b"Math.") || matches!(t, b"Number" | b"parseInt" | b"parseFloat")
        }),
        "member_expression" => expr
            .child_by_field_name("property")
            .is_some_and(|p| text(p, src) == b"length"),
        _ => false,
    }
}

fn all_literals(expr: Node) -> bool {
    match expr.kind() {
        "string" | "number" => true,
        "binary_expression" => {
            expr.child_by_field_name("left").is_some_and(all_literals)
                && expr.child_by_field_name("right").is_some_and(all_literals)
        }
        _ => false,
    }
}

fn message_handler_ignores_origin(call: Node, src: &[u8]) -> bool {
    let Some(args) = call.child_by_field_name("arguments") else {
        return false;
    };
    let items = named(args);
    let [event, handler, ..] = items.as_slice() else {
        return false;
    };
    event.kind() == "string"
        && string_content(*event, src) == b"message"
        && matches!(handler.kind(), "arrow_function" | "function_expression")
        && count_word(text(*handler, src), b"origin") == 0
}

fn dompurify_config_is_unsafe(call: Node, src: &[u8]) -> bool {
    let Some(config) = call
        .child_by_field_name("arguments")
        .map(named)
        .and_then(|a| a.get(1).copied())
        .filter(|c| c.kind() == "object")
    else {
        return false;
    };
    named(config).iter().any(|pair| {
        let key = pair
            .child_by_field_name("key")
            .map_or(&b""[..], |k| text(k, src));
        let value = pair
            .child_by_field_name("value")
            .map_or(&b""[..], |v| text(v, src));
        (key == b"ALLOW_UNKNOWN_PROTOCOLS" && value == b"true")
            || (key == b"ADD_TAGS"
                && [&b"script"[..], b"iframe", b"object", b"embed"]
                    .iter()
                    .any(|t| value.windows(t.len()).any(|w| w == *t)))
    })
}

fn remote_asset_lacks_integrity(element: Node, src: &[u8]) -> bool {
    let Some(opening) = opening_tag(element) else {
        return false;
    };
    if has_spread(opening) || attribute(opening, "integrity", src).is_some() {
        return false;
    }
    let remote = |name: &str| {
        attribute(opening, name, src)
            .and_then(|a| static_value(a, src))
            .is_some_and(|v| {
                v.starts_with(b"http://") || v.starts_with(b"https://") || v.starts_with(b"//")
            })
    };
    match tag_name(opening, src) {
        Some(b"script") => remote("src"),
        Some(b"link") => {
            attribute(opening, "rel", src).and_then(|a| static_value(a, src)) == Some(b"stylesheet")
                && remote("href")
        }
        _ => false,
    }
}

fn guards_then_reads_the_same_value(binary: Node, src: &[u8]) -> bool {
    let and = operator_text(binary, src) == b"&&";
    let or = operator_text(binary, src) == b"||";
    if !and && !or {
        return false;
    }
    let (Some(l), Some(r)) = (
        binary.child_by_field_name("left"),
        binary.child_by_field_name("right"),
    ) else {
        return false;
    };
    // The value the left side guards: `a && ...`, `a != null && ...`,
    // `!a || ...`, `a == null || ...`.
    let is_value = |n: Node| matches!(n.kind(), "identifier" | "member_expression" | "this");
    let subject = match l.kind() {
        "identifier" | "member_expression" | "this" if and => Some(l),
        "unary_expression" if or => l
            .child_by_field_name("argument")
            .filter(|a| is_value(*a) && text(l, src).starts_with(b"!")),
        "binary_expression" => {
            let op = operator_text(l, src);
            let wanted: &[&[u8]] = if and {
                &[b"!=", b"!=="]
            } else {
                &[b"==", b"==="]
            };
            let (a, b) = (
                l.child_by_field_name("left"),
                l.child_by_field_name("right"),
            );
            let nullish = |n: Node| matches!(n.kind(), "null" | "undefined");
            match (a, b) {
                (Some(a), Some(b)) if wanted.contains(&op) && is_value(a) && nullish(b) => Some(a),
                _ => None,
            }
        }
        _ => None,
    };
    let Some(subject) = subject else {
        return false;
    };
    // `!a || a.b` is `!a?.b` only when the right side is itself a negation
    // or a null test; a plain read there would flip the result.
    if or {
        let mut right = r;
        while right.kind() == "parenthesized_expression" {
            match right.named_child(0) {
                Some(inner) => right = inner,
                None => return false,
            }
        }
        let negated = right.kind() == "unary_expression" && text(right, src).starts_with(b"!");
        let null_test = right.kind() == "binary_expression"
            && right
                .child_by_field_name("right")
                .is_some_and(|n| matches!(n.kind(), "null" | "undefined"));
        if !negated && !null_test {
            return false;
        }
    }
    // `a && a.x === 1 && a.y === 2`: SonarQube leaves a chain whose later
    // operands are comparisons of the same value, which cannot join one
    // optional chain.
    if and
        && let Some(outer) = binary.parent().filter(|p| {
            p.kind() == "binary_expression"
                && operator_text(*p, src) == b"&&"
                && p.child_by_field_name("left") == Some(binary)
        })
        && let Some(next) = outer.child_by_field_name("right")
        && next.kind() == "binary_expression"
        && reads_property_of(next, text(subject, src), src, true)
    {
        return false;
    }
    reads_property_of(r, text(subject, src), src, and)
}

/// Whether `expr` reads a property or calls a method of `subject`, in a way
/// an optional chain can replace: the chain itself, an equality test of it
/// (after `&&`), or its negation or null test (after `||`). A relational
/// comparison is left alone, as SonarQube does: `undefined > 0` is not the
/// same answer as short-circuiting.
fn reads_property_of(expr: Node, subject: &[u8], src: &[u8], and: bool) -> bool {
    let mut node = expr;
    loop {
        match node.kind() {
            "member_expression" | "subscript_expression" => {
                let Some(object) = node.child_by_field_name("object") else {
                    return false;
                };
                if text(object, src) == subject {
                    return true;
                }
                node = object;
            }
            "call_expression" => match node.child_by_field_name("function") {
                Some(f) => node = f,
                None => return false,
            },
            "binary_expression" => {
                let op = operator_text(node, src);
                let equality = matches!(op, b"==" | b"===" | b"!=" | b"!==");
                if !equality {
                    return false;
                }
                let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) else {
                    return false;
                };
                let nullish = |n: Node| matches!(n.kind(), "null" | "undefined");
                if !and && !nullish(right) {
                    return false;
                }
                node = left;
            }
            "unary_expression" if !and && text(node, src).starts_with(b"!") => {
                match node.child_by_field_name("argument") {
                    Some(a) => node = a,
                    None => return false,
                }
            }
            "parenthesized_expression" | "non_null_expression" => match node.named_child(0) {
                Some(inner) => node = inner,
                None => return false,
            },
            _ => return false,
        }
    }
}

fn ternary_is_a_nullish_default(ternary: Node, src: &[u8]) -> bool {
    let (Some(cond), Some(cons), Some(alt)) = (
        ternary.child_by_field_name("condition"),
        ternary.child_by_field_name("consequence"),
        ternary.child_by_field_name("alternative"),
    ) else {
        return false;
    };
    if cond.kind() != "binary_expression" {
        return false;
    }
    let (Some(l), Some(r)) = (
        cond.child_by_field_name("left"),
        cond.child_by_field_name("right"),
    ) else {
        return false;
    };
    let is_null = |n: Node| n.kind() == "null" || (n.kind() == "undefined");
    let tested = if is_null(r) {
        l
    } else if is_null(l) {
        r
    } else {
        return false;
    };
    match operator_text(cond, src) {
        b"!=" => text(cons, src) == text(tested, src),
        b"==" => text(alt, src) == text(tested, src),
        _ => false,
    }
}

fn repeated_push<'t>(block: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let receiver = |s: Node<'t>| -> Option<&[u8]> {
        if s.kind() != "expression_statement" {
            return None;
        }
        let call = s.named_child(0).filter(|c| c.kind() == "call_expression")?;
        let function = call
            .child_by_field_name("function")
            .filter(|f| f.kind() == "member_expression")?;
        let property = function.child_by_field_name("property")?;
        if text(property, src) != b"push" {
            return None;
        }
        function.child_by_field_name("object").map(|o| text(o, src))
    };
    named(block).windows(2).find_map(|pair| {
        let (a, b) = (receiver(pair[0])?, receiver(pair[1])?);
        (a == b).then_some(pair[1])
    })
}

fn passes_a_this_argument(call: Node, src: &[u8]) -> bool {
    let Some(args) = call.child_by_field_name("arguments") else {
        return false;
    };
    let items = named(args);
    let [callback, _] = items.as_slice() else {
        return false;
    };
    let lodash = call
        .child_by_field_name("function")
        .and_then(|f| f.child_by_field_name("object"))
        .is_some_and(|o| matches!(text(o, src), b"_" | b"lodash"));
    !lodash && matches!(callback.kind(), "arrow_function" | "function_expression")
}

fn void_is_not_void_zero(unary: Node, src: &[u8]) -> bool {
    unary
        .child_by_field_name("argument")
        .is_some_and(|a| text(a, src) != b"0")
}

fn checks_index_of_for_positive(binary: Node, src: &[u8]) -> bool {
    let (Some(l), Some(r)) = (
        binary.child_by_field_name("left"),
        binary.child_by_field_name("right"),
    ) else {
        return false;
    };
    l.kind() == "call_expression"
        && l.child_by_field_name("function")
            .and_then(|f| f.child_by_field_name("property"))
            .is_some_and(|p| matches!(text(p, src), b"indexOf" | b"lastIndexOf"))
        && operator_text(binary, src) == b">"
        && text(r, src) == b"0"
}

fn names_a_polyfill(string: Node, src: &[u8]) -> bool {
    let name = string_content(string, src);
    name.starts_with(b"core-js")
        || name.starts_with(b"babel-polyfill")
        || name.starts_with(b"@babel/polyfill")
        || name.starts_with(b"es6-promise")
        || name.starts_with(b"es6-symbol")
        || name.starts_with(b"es5-shim")
        || name.starts_with(b"es6-shim")
        || name.starts_with(b"es7-shim")
        || name.starts_with(b"object-assign")
        || name.starts_with(b"array.prototype.")
        || name.starts_with(b"string.prototype.")
        || name.starts_with(b"object.assign")
        || name.ends_with(b"-polyfill")
        || name.ends_with(b"-polyfills")
}

fn separator_groups_are_uneven(number: Node, src: &[u8]) -> bool {
    let t = text(number, src);
    if !t.contains(&b'_')
        || t.starts_with(b"0x")
        || t.starts_with(b"0X")
        || t.starts_with(b"0b")
        || t.starts_with(b"0B")
        || t.starts_with(b"0o")
    {
        return false;
    }
    let whole = t
        .split(|&b| b == b'.' || b == b'e' || b == b'E')
        .next()
        .unwrap_or(t);
    let groups: Vec<&[u8]> = whole.split(|&b| b == b'_').collect();
    groups.len() > 1
        && (groups[0].is_empty() || groups[0].len() > 3 || groups[1..].iter().any(|g| g.len() != 3))
}

const AUTOCOMPLETE_TOKENS: &[&str] = &[
    "on",
    "off",
    "name",
    "honorific-prefix",
    "given-name",
    "additional-name",
    "family-name",
    "honorific-suffix",
    "nickname",
    "email",
    "username",
    "new-password",
    "current-password",
    "one-time-code",
    "organization-title",
    "organization",
    "street-address",
    "address-line1",
    "address-line2",
    "address-line3",
    "address-level4",
    "address-level3",
    "address-level2",
    "address-level1",
    "country",
    "country-name",
    "postal-code",
    "cc-name",
    "cc-given-name",
    "cc-additional-name",
    "cc-family-name",
    "cc-number",
    "cc-exp",
    "cc-exp-month",
    "cc-exp-year",
    "cc-csc",
    "cc-type",
    "transaction-currency",
    "transaction-amount",
    "language",
    "bday",
    "bday-day",
    "bday-month",
    "bday-year",
    "sex",
    "url",
    "photo",
    "tel",
    "tel-country-code",
    "tel-national",
    "tel-area-code",
    "tel-local",
    "tel-extension",
    "impp",
    "shipping",
    "billing",
    "home",
    "work",
    "mobile",
    "fax",
    "pager",
    "webauthn",
];

fn autocomplete_is_not_a_known_token(attr: Node, src: &[u8]) -> bool {
    if !on_dom_element(attr, src) {
        return false;
    }
    let Some(value) = static_value(attr, src) else {
        return false;
    };
    let value = String::from_utf8_lossy(value);
    let mut tokens = value.split_whitespace().peekable();
    tokens.peek().is_some()
        && tokens.any(|t| !(AUTOCOMPLETE_TOKENS.contains(&t) || t.starts_with("section-")))
}

fn renders_a_count_when_empty(expression: Node, src: &[u8]) -> bool {
    let Some(binary) = expression
        .named_child(0)
        .filter(|b| b.kind() == "binary_expression")
    else {
        return false;
    };
    if operator_text(binary, src) != b"&&" {
        return false;
    }
    let (Some(l), Some(r)) = (
        binary.child_by_field_name("left"),
        binary.child_by_field_name("right"),
    ) else {
        return false;
    };
    l.kind() == "member_expression"
        && l.child_by_field_name("property")
            .is_some_and(|p| matches!(text(p, src), b"length" | b"size"))
        && matches!(
            r.kind(),
            "jsx_element" | "jsx_self_closing_element" | "jsx_fragment"
        )
}

// ---- TypeScript

fn boolean_check_could_be_a_predicate(function: Node, src: &[u8]) -> bool {
    let (Some(ret), Some(params), Some(body), Some(name)) = (
        function.child_by_field_name("return_type"),
        function.child_by_field_name("parameters"),
        function.child_by_field_name("body"),
        function.child_by_field_name("name"),
    ) else {
        return false;
    };
    if text(ret, src) != b": boolean" || !text(name, src).starts_with(b"is") {
        return false;
    }
    let declared = named(params);
    let [param] = declared.as_slice() else {
        return false;
    };
    let Some(pname) = param.child_by_field_name("pattern").map(|p| text(p, src)) else {
        return false;
    };
    let items = named(body);
    let [only] = items.as_slice() else {
        return false;
    };
    let Some(check) = only
        .named_child(0)
        .filter(|c| only.kind() == "return_statement" && c.kind() == "binary_expression")
    else {
        return false;
    };
    let (Some(l), Some(_)) = (
        check.child_by_field_name("left"),
        check.child_by_field_name("right"),
    ) else {
        return false;
    };
    match operator_text(check, src) {
        b"instanceof" => text(l, src) == pname,
        b"===" | b"==" => {
            l.kind() == "unary_expression"
                && operator_text(l, src) == b"typeof"
                && l.child_by_field_name("argument")
                    .is_some_and(|a| text(a, src) == pname)
        }
        _ => false,
    }
}

fn private_field_only_set_in_constructor<'t>(body: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let members = named(body);
    let outside_constructor: Vec<&[u8]> = members
        .iter()
        .filter(|m| {
            !(m.kind() == "method_definition"
                && m.child_by_field_name("name")
                    .is_some_and(|n| text(n, src) == b"constructor"))
        })
        .map(|m| text(*m, src))
        .collect();
    members.into_iter().find(|f| {
        if f.kind() != "public_field_definition"
            || has_token(*f, "readonly")
            || has_token(*f, "static")
        {
            return false;
        }
        let mut cursor = f.walk();
        let is_private = f
            .children(&mut cursor)
            .any(|c| c.kind() == "accessibility_modifier" && text(c, src) == b"private");
        let Some(name) = f.child_by_field_name("name").map(|n| text(n, src)) else {
            return false;
        };
        let target = [b"this.", name].concat();
        let written_elsewhere = outside_constructor.iter().any(|t| {
            [
                &b" ="[..],
                b" +=",
                b" -=",
                b"++",
                b"--",
                b" ||=",
                b" ??=",
                b" &&=",
            ]
            .iter()
            .any(|op| {
                let needle = [target.as_slice(), op].concat();
                t.windows(needle.len()).any(|w| w == needle.as_slice())
            })
        });
        // A field with an initializer and no constructor write is already effectively constant.
        is_private && !written_elsewhere && f.child_by_field_name("value").is_none()
    })
}

fn optional_with_undefined(property: Node, src: &[u8]) -> bool {
    if !has_token(property, "?") {
        return false;
    }
    let Some(annotation) = named(property)
        .into_iter()
        .find(|c| c.kind() == "type_annotation")
    else {
        return false;
    };
    let t = text(annotation, src);
    let t = t.strip_prefix(b":").unwrap_or(t);
    t.split(|&b| b == b'|')
        .any(|part| part.trim_ascii() == b"undefined")
}

fn union_has_a_redundant_member(union: Node, src: &[u8]) -> bool {
    if union.parent().is_some_and(|p| p.kind() == union.kind()) {
        return false;
    }
    let mut members: Vec<Node> = Vec::new();
    let mut stack = vec![union];
    while let Some(n) = stack.pop() {
        for m in named(n) {
            if m.kind() == union.kind() {
                stack.push(m);
            } else {
                members.push(m);
            }
        }
    }
    if members.len() < 2 {
        return false;
    }
    let absorbs = members.iter().any(|m| {
        m.kind() == "predefined_type" && matches!(text(*m, src), b"any" | b"unknown" | b"never")
    });
    let primitive_and_literal = members
        .iter()
        .any(|m| m.kind() == "predefined_type" && text(*m, src) == b"string")
        && members
            .iter()
            .any(|m| m.kind() == "literal_type" && text(*m, src).first() == Some(&b'\''))
        || members
            .iter()
            .any(|m| m.kind() == "predefined_type" && text(*m, src) == b"number")
            && members.iter().any(|m| {
                m.kind() == "literal_type" && text(*m, src).first().is_some_and(u8::is_ascii_digit)
            });
    absorbs || primitive_and_literal
}

fn mixes_number_and_string_values(body: Node, _: &[u8]) -> bool {
    let kinds: Vec<&str> = named(body)
        .iter()
        .filter(|m| m.kind() == "enum_assignment")
        .filter_map(|m| m.child_by_field_name("value").map(|v| v.kind()))
        .collect();
    kinds.contains(&"number") && kinds.contains(&"string")
}

#[cfg(test)]
mod tests {
    use crate::analysis::analyze;
    use crate::analysis::tests::far_deadline;
    use crate::config::Config;
    use crate::lang::Lang;
    use crate::rules::RuleSet;

    fn flagged(rule: &str, lang: Lang, src: &str) -> Vec<usize> {
        let cfg = Config::default();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let file = analyze("t", lang, src, &rules, &cfg, far_deadline()).unwrap();
        file.issues
            .iter()
            .filter(|i| i.rule == rule)
            .map(|i| i.line)
            .collect()
    }

    const JS: Lang = Lang::JavaScript;
    const TS: Lang = Lang::TypeScript;

    #[test]
    fn promises_and_callbacks() {
        let src = "async function f() {\nawait 5;\nawait load();\nawait [1];\n}\nconst a = list.map(x => { x * 2; });\nconst b = list.map(x => { return x * 2; });\nconst c = list.map(x => x * 2);\nconst d = list.forEach(x => { x; });\nlist.forEach(async (x) => { await save(x); });\nlist.forEach((x) => { save(x); });\nconst e = Promise.reject('failed');\nconst g = Promise.reject(new Error('failed'));\nconst h = [1, 2].reduce((a, b) => a + b);\nconst i = [1, 2].reduce((a, b) => a + b, 0);\nconst unknown = list.reduce((a, b) => a + b);\nconst j = list.map(parseInt);\nconst k = list.map((x) => parseInt(x, 10));";
        assert_eq!(flagged("js/await-non-promise", JS, src), [2, 4]);
        assert_eq!(flagged("js/callback-without-return", JS, src), [6]);
        assert_eq!(flagged("js/async-foreach", JS, src), [10]);
        assert_eq!(flagged("js/reject-with-literal", JS, src), [12]);
        assert_eq!(flagged("js/reduce-without-initial", JS, src), [14]);
        assert_eq!(flagged("js/parseint-as-callback", JS, src), [17]);
    }

    #[test]
    fn comparisons() {
        let src = "if (a > 1 & b > 1) {}\nif (a > 1 && b > 1) {}\nif (a & 1) {}\nconst r = 'a' in 'abc';\nconst s = 'a' in obj;\nconst t = 2 in [1, 2];\nif (items.length < 0) {}\nif (items.length >= 0) {}\nif (items.length > 0) {}\nif (list.indexOf(x) > 0) {}\nif (list.indexOf(x) > -1) {}\nif (1 === '1') {}\nif (1 === 1) {}\nif (1 === true) {}\nif (a === null) {}\nif (a === b) {}";
        assert_eq!(flagged("js/bitwise-in-condition", JS, src), [1]);
        assert_eq!(flagged("js/in-with-primitive", JS, src), [4]);
        assert_eq!(flagged("js/in-on-array", JS, src), [6]);
        assert_eq!(flagged("js/size-comparison", JS, src), [7, 8]);
        assert_eq!(flagged("js/index-of-positive", JS, src), [10]);
        assert_eq!(flagged("js/dissimilar-strict-equality", JS, src), [12, 14]);
    }

    #[test]
    fn expressions() {
        let src = "const a = user && user.name;\nconst b = user.profile && user.profile.name;\nconst c = user && other.name;\nconst d = x != null ? x : 'd';\nconst e = x == null ? 'd' : x;\nconst f = x != null ? y : 'd';\nconst g = items.sort();\nconst h = [...items].sort();\nlist.push(1);\nlist.push(2);\nother.push(3);\nlist.map(function (x) { return this.f(x); }, this);\nlist.map((x) => x);\n_.map(list, fn, this);\nvoid fetchData();\nvoid 0;\nconst n = 1_00_000;\nconst o = 100_000;\nconst p = 0xFF_FF;\nconst q = node._reactInternals;";
        assert_eq!(flagged("js/optional-chaining-preferred", JS, src), [1, 2]);
        let more = "const a = !meta || !meta.enabled;\nconst b = last && last.end === h;\nconst c = !prices || !prices[hour];\nconst d = p != null && p.usePrice != null;\nconst e = a && other.name;\nconst f = !a || b.c;";
        assert_eq!(
            flagged("js/optional-chaining-preferred", JS, more),
            [1, 2, 3, 4]
        );
        assert_eq!(flagged("js/nullish-coalescing-preferred", JS, src), [4, 5]);
        assert_eq!(flagged("js/sort-assigned", JS, src), [7]);
        assert_eq!(flagged("js/consecutive-push", JS, src), [10]);
        assert_eq!(flagged("js/this-arg", JS, src), [12]);
        assert_eq!(flagged("js/void-operator", JS, src), [15]);
        assert_eq!(flagged("js/numeric-separator-grouping", JS, src), [17]);
        assert_eq!(flagged("js/internal-api", JS, src), [20]);
    }

    #[test]
    fn statements_and_security() {
        let src = "name.toLowerCase();\nname = name.toLowerCase();\nconst q = name.trim();\nitems.map(f);\ndb.query(`SELECT * FROM t WHERE id = ${id}`);\ndb.query('SELECT * FROM t WHERE id = ?', [id]);\ndb.query('SELECT ' + col + ' FROM t');\ndb.query('SELECT 1' + ' FROM t');\nwindow.addEventListener('message', (e) => { run(e.data); });\nwindow.addEventListener('message', (e) => { if (e.origin === T) run(e.data); });\nwindow.addEventListener('click', (e) => { run(e); });\nDOMPurify.sanitize(html, { ADD_TAGS: ['script'] });\nDOMPurify.sanitize(html, { ADD_TAGS: ['b'] });\nDOMPurify.sanitize(html);\nimport 'core-js/stable';\nimport x from 'left-pad';\nconst r = require('es6-promise');";
        assert_eq!(flagged("js/ignored-pure-call", JS, src), [1, 4]);
        assert_eq!(flagged("js/sql-built-dynamically", JS, src), [5, 7]);
        assert_eq!(flagged("js/postmessage-origin", JS, src), [9]);
        assert_eq!(flagged("js/dompurify-unsafe-config", JS, src), [12]);
        assert_eq!(flagged("js/polyfill-import", JS, src), [15, 17]);
    }

    #[test]
    fn getters() {
        let src = "class A {\nconstructor() { this._size = 1; this._count = 2; }\nget size() { return this._count; }\nget count() { return this._count; }\nget other() { return this._x; }\n}";
        assert_eq!(flagged("js/getter-reads-another-field", JS, src), [3]);
    }

    #[test]
    fn jsx() {
        let src = "const a = <input autoComplete=\"mail\" />;\nconst b = <input autoComplete=\"email\" />;\nconst c = <input autoComplete=\"section-a shipping given-name\" />;\nconst d = <div>{items.length && <List />}</div>;\nconst e = <div>{items.length > 0 && <List />}</div>;\nconst f = <script src=\"https://cdn.example.net/x.js\" />;\nconst g = <script src=\"https://cdn.example.net/x.js\" integrity=\"sha384-a\" />;\nconst h = <script src=\"/local.js\" />;\nconst i = <link rel=\"stylesheet\" href=\"https://cdn.example.net/x.css\" />;";
        assert_eq!(flagged("js/autocomplete-value", Lang::Tsx, src), [1]);
        assert_eq!(flagged("js/render-zero", Lang::Tsx, src), [4]);
        assert_eq!(
            flagged("js/script-without-integrity", Lang::Tsx, src),
            [6, 9]
        );
    }

    #[test]
    fn typescript() {
        let src = "function isText(x: unknown): boolean { return typeof x === 'string'; }\nfunction isText2(x: unknown): x is string { return typeof x === 'string'; }\nfunction other(x: unknown): boolean { return typeof x === 'string'; }\nclass A { private name: string; private count: number; constructor(n: string) { this.name = n; this.count = 0; } inc() { this.count++; } }\nclass B { private readonly name: string; constructor(n: string) { this.name = n; } }\ninterface I { a?: string | undefined; b?: string; c: string | undefined; }\ntype U = string | any;\ntype V = string | number;\ntype W = string | 'a';\nenum E1 { A = 1, B = 'b' }\nenum E2 { A = 1, B = 2 }";
        assert_eq!(flagged("ts/type-predicate", TS, src), [1]);
        assert_eq!(flagged("ts/readonly-private-field", TS, src), [4]);
        assert_eq!(flagged("ts/optional-and-undefined", TS, src), [6]);
        assert_eq!(flagged("ts/redundant-union-constituent", TS, src), [7, 9]);
        assert_eq!(flagged("ts/enum-mixed-values", TS, src), [10]);
    }
}
