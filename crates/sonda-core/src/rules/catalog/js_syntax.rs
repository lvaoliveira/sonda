//! JavaScript and TypeScript rules, part 6 (ADR-0007, batch 21): structure and
//! complexity limits, naming, style rules SonarQube's default profile leaves
//! out, and a handful of newer-syntax and TypeScript checks. Most are off by
//! default.

use super::js::{has_token, string_content, text};
use super::js_extra::{named, operator_text};
use super::*;

/// This module's rules that are off unless `rules.enabled` lists them
/// (see `catalog::OFF_BY_DEFAULT`).
pub(super) static OFF_BY_DEFAULT: &[&str] = &[
    "js/braces-required",
    "js/else-if-without-else",
    "js/nesting-too-deep",
    "js/multiple-jumps-in-loop",
    "js/continue-statement",
    "js/mergeable-if",
    "js/expression-too-complex",
    "js/duplicated-string-literal",
    "js/array-constructor",
    "js/function-declared-in-block",
    "js/for-in-unfiltered",
    "js/nested-switch",
    "js/assign-undefined",
    "js/wildcard-import",
    "js/setter-without-getter",
    "js/builtin-overridden",
    "js/parseint-radix",
    "js/new-object",
    "js/object-shorthand-property",
    "js/shorthand-grouping",
    "js/string-concat-template",
    "js/arguments-object",
    "js/destructuring-assignment",
    "js/template-literal-in-string",
    "js/redundant-await-return",
    "js/bind-or-arrow-in-jsx-prop",
    "js/await-member-access",
    "js/for-loop-to-for-of",
    "js/negated-condition-with-else",
    "js/number-literal-format",
    "js/use-globalthis",
    "js/regex-test-for-existence",
    "js/cyclomatic-complexity",
    "js/use-strict-in-function",
    "js/console-logging",
    "js/global-scope-declaration",
    "js/function-name-convention",
    "js/variable-name-convention",
    "js/magic-number",
    "js/ternary-operator",
    "js/iam-kms-resource-wildcard",
    "js/non-null-assertion",
    "js/primitive-type-annotation",
    "js/empty-interface",
    "js/type-assertion-angle",
    "js/union-too-long",
    "js/optional-boolean-parameter",
];

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "js/braces-required",
        name: "Control structures should use curly braces",
        description: "Without braces, a second statement added later looks guarded but is not.",
        message: "Add curly braces.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 1,
        sonar: &[exact("S121")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(if_statement consequence: (_) @match) (for_statement body: (_) @match) (for_in_statement body: (_) @match) (while_statement body: (_) @match) (do_statement body: (_) @match) (else_clause (_) @match)]"#,
            filter: Some(Keep(lacks_braces)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (a) f();",
            good: "if (a) { f(); }",
        }),
    },
    Rule {
        id: "js/else-if-without-else",
        name: "\"if ... else if\" constructs should end with \"else\" clauses",
        description: "The last else documents that the remaining case was considered.",
        message: "Add a final else clause.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 2,
        sonar: &[exact("S126")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(if_statement alternative: (else_clause (if_statement))) @match"#,
            filter: Some(Keep(else_if_chain_lacks_else)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (a) { f(); } else if (b) { g(); }",
            good: "if (a) { f(); } else if (b) { g(); } else { h(); }",
        }),
    },
    Rule {
        id: "js/nesting-too-deep",
        name: "Control flow statements should not be nested too deeply",
        description: "Four levels of if, loops and try make a function hard to follow.",
        message: "Extract the inner levels into a function.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S134")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(if_statement) (for_statement) (for_in_statement) (while_statement) (do_statement) (switch_statement) (try_statement)] @match"#,
            filter: Some(Keep(nested_four_deep)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function f() { if (a) { if (b) { if (c) { if (d) { g(); } } } } }",
            good: "function f() { if (a && b) { if (c) { g(); } } }",
        }),
    },
    Rule {
        id: "js/multiple-jumps-in-loop",
        name: "Loops should not contain more than a single \"break\" or \"continue\" statement",
        description: "Several jumps make the loop's exit conditions hard to see.",
        message: "Restructure the loop to have one jump.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S135")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(for_statement) (for_in_statement) (while_statement) (do_statement)] @match"#,
            filter: Some(Keep(has_several_jumps)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "for (const a of b) { if (a) { continue; } if (c) { break; } }",
            good: "for (const a of b) { if (a) { break; } }",
        }),
    },
    Rule {
        id: "js/continue-statement",
        name: "\"continue\" should not be used",
        description: "continue hides the loop's real condition.",
        message: "Restructure the loop without continue.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S909")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(continue_statement) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "for (const a of b) { if (a) { continue; } f(a); }",
            good: "for (const a of b) { if (!a) { f(a); } }",
        }),
    },
    Rule {
        id: "js/mergeable-if",
        name: "Mergeable \"if\" statements should be combined",
        description: "Nested ifs with no else read better as one condition.",
        message: "Merge this if with the one around it.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1066")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(if_statement) @match"#,
            filter: Some(Find(inner_mergeable_if)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (a) { if (b) { f(); } }",
            good: "if (a && b) { f(); }",
        }),
    },
    Rule {
        id: "js/expression-too-complex",
        name: "Expressions should not be too complex",
        description: "More than three boolean operators in one expression is hard to read.",
        message: "Split this expression.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S1067")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(binary_expression) @match"#,
            filter: Some(Keep(expression_has_many_operators)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const x = a && b || c && d || e;",
            good: "const x = a && b || c;",
        }),
    },
    Rule {
        id: "js/duplicated-string-literal",
        name: "String literals should not be duplicated",
        description: "A literal repeated three times belongs in a constant.",
        message: "Define a constant for this literal.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S1192")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(string) @match"#,
            filter: Some(Keep(is_first_of_a_duplicated_literal)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "f('some long text'); g('some long text'); h('some long text');",
            good: "const T = 'some long text'; f(T); g(T); h(T);",
        }),
    },
    Rule {
        id: "js/array-constructor",
        name: "Array constructors should not be used",
        description: "new Array(a, b) means different things depending on its arguments.",
        message: "Use an array literal.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S1528")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(new_expression constructor: (identifier) @c (#eq? @c "Array")) (call_expression function: (identifier) @c (#eq? @c "Array"))] @match"#,
            filter: Some(Keep(array_constructor_misused)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const a = new Array(1, 2, 3);",
            good: "const a = [1, 2, 3];",
        }),
    },
    Rule {
        id: "js/function-declared-in-block",
        name: "Function declarations should not be made within blocks",
        description: "Where a function declared in a block is visible differs between engines.",
        message: "Declare it at the top of the function, or assign a function expression.",
        category: Bug,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S1530")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(function_declaration) @match"#,
            filter: Some(Keep(declared_inside_a_nested_block)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function f() { if (a) { function g() {} } }",
            good: "function f() { const g = () => {}; if (a) { g(); } }",
        }),
    },
    Rule {
        id: "js/for-in-unfiltered",
        name: "\"for...in\" loops should filter properties before acting on them",
        description: "for...in also visits inherited properties.",
        message: "Filter the properties with an if statement.",
        category: Bug,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S1535")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(for_in_statement) @match"#,
            filter: Some(Keep(for_in_without_filter)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "for (const k in o) { f(k); }",
            good: "for (const k in o) { if (Object.hasOwn(o, k)) { f(k); } }",
        }),
    },
    Rule {
        id: "js/nested-switch",
        name: "\"switch\" statements should not be nested",
        description: "A switch inside a switch is hard to follow.",
        message: "Extract the inner switch into a function.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S1821")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(switch_statement) @match"#,
            filter: Some(Keep(switch_inside_switch)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "switch (a) { case 1: switch (b) { case 2: f(); } }",
            good: "switch (a) { case 1: g(b); }",
        }),
    },
    Rule {
        id: "js/assign-undefined",
        name: "\"undefined\" should not be assigned",
        description: "Assigning undefined is a roundabout way of saying nothing.",
        message: "Declare the variable without a value, or use delete or null.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S2138")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(assignment_expression right: (undefined) @match) (variable_declarator value: (undefined) @match)]"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "let x = undefined;",
            good: "let x;",
        }),
    },
    Rule {
        id: "js/wildcard-import",
        name: "Wildcard imports should not be used",
        description: "import * pulls in names nobody listed.",
        message: "Import the names you use.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 2,
        sonar: &[exact("S2208")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(import_statement (import_clause (namespace_import))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "import * as m from 'lib';",
            good: "import { a } from 'lib';",
        }),
    },
    Rule {
        id: "js/setter-without-getter",
        name: "Property getters and setters should come in pairs",
        description: "A property that can be set but not read is surprising.",
        message: "Add the matching getter.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2376")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(class_body) (object)] @match"#,
            filter: Some(Find(setter_lacks_getter)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "class A { set v(x) { this._v = x; } }",
            good: "class A { get v() { return this._v; } set v(x) { this._v = x; } }",
        }),
    },
    Rule {
        id: "js/builtin-overridden",
        name: "Built-in objects should not be overridden",
        description: "Redefining Object, Array and friends breaks every library that relies on them.",
        message: "Pick another name.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2424")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(function_declaration name: (identifier) @match) (variable_declarator name: (identifier) @match) (class_declaration name: (_) @match)]"#,
            filter: Some(Keep(is_builtin_name)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function Object() {}",
            good: "function Thing() {}",
        }),
    },
    Rule {
        id: "js/parseint-radix",
        name: "The base should be provided to \"parseInt\"",
        description: "Without a radix, a leading 0 is read differently across engines.",
        message: "Pass the radix as the second argument.",
        category: Bug,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S2427")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: [(identifier) (member_expression)] @f (#match? @f "^(Number\\.)?parseInt$")) @match"#,
            filter: Some(Keep(has_exactly_one_argument)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const n = parseInt(s);",
            good: "const n = parseInt(s, 10);",
        }),
    },
    Rule {
        id: "js/new-object",
        name: "Object literal syntax should be used",
        description: "new Object() is a longer way to write {}.",
        message: "Use {}.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S2428")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(new_expression constructor: (identifier) @c (#eq? @c "Object")) @match"#,
            filter: Some(Keep(has_no_arguments)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const o = new Object();",
            good: "const o = {};",
        }),
    },
    Rule {
        id: "js/object-shorthand-property",
        name: "Object literal shorthand syntax should be used",
        description: "{ a: a } is {a}.",
        message: "Use the shorthand.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S3498")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(pair key: (property_identifier) @k value: (identifier) @v) @match"#,
            filter: Some(Keep(key_and_value_match)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const o = { a: a };",
            good: "const o = { a };",
        }),
    },
    Rule {
        id: "js/shorthand-grouping",
        name: "Shorthand object properties should be grouped at the beginning or end of an object declaration",
        description: "Mixed shorthand and long properties are harder to scan.",
        message: "Group the shorthand properties.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S3499")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(object) @match"#,
            filter: Some(Keep(shorthands_are_scattered)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const o = { a, b: 1, c };",
            good: "const o = { a, c, b: 1 };",
        }),
    },
    Rule {
        id: "js/string-concat-template",
        name: "Template strings should be used instead of concatenation",
        description: "`a${b}c` reads better than 'a' + b + 'c'.",
        message: "Use a template string.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S3512")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(binary_expression) @match"#,
            filter: Some(Keep(concatenates_with_a_string_literal)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const s = 'hello ' + name;",
            good: "const s = `hello ${name}`;",
        }),
    },
    Rule {
        id: "js/arguments-object",
        name: "\"arguments\" should not be accessed directly",
        description: "Rest parameters say what the function takes.",
        message: "Use a rest parameter.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S3513")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(identifier) @match"#,
            filter: Some(Keep(is_arguments_object)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function f() { return arguments[0]; }",
            good: "function f(...args) { return args[0]; }",
        }),
    },
    Rule {
        id: "js/destructuring-assignment",
        name: "Destructuring syntax should be used for assignments",
        description: "const a = o.a is const { a } = o.",
        message: "Use destructuring.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S3514")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(variable_declarator name: (identifier) @n value: (member_expression property: (property_identifier) @p)) @match"#,
            filter: Some(Keep(name_equals_property)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const a = o.a;",
            good: "const { a } = o;",
        }),
    },
    Rule {
        id: "js/template-literal-in-string",
        name: "Template literal placeholder syntax should not be used in regular strings",
        description: "'${x}' in quotes is printed as is.",
        message: "Use backticks.",
        category: Bug,
        severity: Major,
        effort_minutes: 1,
        sonar: &[exact("S3786")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(string) @match"#,
            filter: Some(Keep(has_placeholder)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const s = 'hi ${name}';",
            good: "const s = `hi ${name}`;",
        }),
    },
    Rule {
        id: "js/redundant-await-return",
        name: "\"await\" should not be used redundantly",
        description: "return await adds nothing outside of a try block.",
        message: "Return the promise directly.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S4326")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(return_statement (await_expression) @match)"#,
            filter: Some(Keep(await_not_in_try)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "async function f() { return await g(); }",
            good: "async function f() { return g(); }",
        }),
    },
    Rule {
        id: "js/global-regex-state",
        name: "Regular expressions with the global flag should be used with caution",
        description: "test and exec on a /g regex keep lastIndex between calls.",
        message: "Drop the g flag, or create the regex where it is used.",
        category: Bug,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S6351")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression object: (identifier) @o property: (property_identifier) @p (#eq? @p "test"))) @match"#,
            filter: Some(Keep(regex_variable_is_global)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const re = /a/g; function f(s) { return re.test(s); }",
            good: "const re = /a/; function f(s) { return re.test(s); }",
        }),
    },
    Rule {
        id: "js/bind-or-arrow-in-jsx-prop",
        name: "Disallow .bind() and arrow functions in JSX props",
        description: "A new function per render defeats memoization.",
        message: "Define the handler once.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S6480")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_attribute (jsx_expression [(arrow_function) (call_expression function: (member_expression property: (property_identifier) @p (#eq? @p "bind")))])) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const a = <button onClick={() => f()} />;",
            good: "const a = <button onClick={f} />;",
        }),
    },
    Rule {
        id: "js/jsx-component-case",
        name: "User-defined JSX components should use Pascal case",
        description: "Names such as My_Component are read as DOM elements or constants.",
        message: "Rename the component in PascalCase.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6770")],
        check: Check::Query {
            langs: JSX,
            query: r#"[(jsx_opening_element name: (identifier) @match) (jsx_self_closing_element name: (identifier) @match)]"#,
            filter: Some(Keep(is_not_pascal_case)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const a = <My_Component />;",
            good: "const a = <MyComponent />;",
        }),
    },
    Rule {
        id: "js/await-member-access",
        name: "Member access from await expressions should use destructuring or intermediate variables",
        description: "(await f()).x nests two ideas in one expression.",
        message: "Store the awaited value first.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S7730")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(member_expression object: (parenthesized_expression (await_expression))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "async function f() { const x = (await g()).value; }",
            good: "async function f() { const { value } = await g(); }",
        }),
    },
    Rule {
        id: "js/for-loop-to-for-of",
        name: "Traditional for loops should be replaced with for-of loops",
        description: "If the index is only used to read the array, for-of says so.",
        message: "Use for...of.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 3,
        sonar: &[exact("S7731")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(for_statement) @match"#,
            filter: Some(Keep(index_only_reads_the_array)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "for (let i = 0; i < a.length; i++) { f(a[i]); }",
            good: "for (const x of a) { f(x); }",
        }),
    },
    Rule {
        id: "js/negated-condition-with-else",
        name: "Negated conditions should be avoided when an else clause is present",
        description: "Swap the branches and drop the negation.",
        message: "Swap the branches.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S7735")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(if_statement) (ternary_expression)] @match"#,
            filter: Some(Keep(negated_with_else)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (!a) { f(); } else { g(); }",
            good: "if (a) { g(); } else { f(); }",
        }),
    },
    Rule {
        id: "js/object-default-parameter",
        name: "Objects should not be used as default parameters",
        description: "The default object is replaced whole by any argument.",
        message: "Destructure the options with a default for each.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 3,
        sonar: &[exact("S7737")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(object) @match"#,
            filter: Some(Keep(is_object_default_parameter)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function f(o = { a: 1 }) {}",
            good: "function f({ a = 1 } = {}) {}",
        }),
    },
    Rule {
        id: "js/iife-arrow-parentheses",
        name: "Immediately invoked arrow functions with parenthesized expressions should be avoided",
        description: "(() => (x))() is a noisy way to write x.",
        message: "Remove the wrapper.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S7743")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (parenthesized_expression (arrow_function body: (parenthesized_expression)))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const a = (() => (b))();",
            good: "const a = b;",
        }),
    },
    Rule {
        id: "js/number-literal-format",
        name: "Number literals should not have unnecessary decimal points or trailing zeros",
        description: "1.0 and 1.50 say nothing 1 and 1.5 do not.",
        message: "Write the number without the extra zeros.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S7748")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(number) @match"#,
            filter: Some(Keep(has_trailing_zero)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const a = 1.0;",
            good: "const a = 1;",
        }),
    },
    Rule {
        id: "js/use-globalthis",
        name: "Use \"globalThis\" instead of \"window\", \"self\", or \"global\"",
        description: "globalThis works in every environment.",
        message: "Use globalThis.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S7764")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(member_expression object: (identifier) @match (#any-of? @match "window" "self" "global"))"#,
            filter: Some(Keep(is_unshadowed_global)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const a = window.location;",
            good: "const a = globalThis.location;",
        }),
    },
    Rule {
        id: "js/regex-test-for-existence",
        name: "Use \"RegExp.test()\" instead of \"String.match()\" or \"RegExp.exec()\" when only checking for pattern existence",
        description: "test returns the boolean the condition wants.",
        message: "Use test().",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 1,
        sonar: &[exact("S7775")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression property: (property_identifier) @p (#any-of? @p "match" "exec"))) @match"#,
            filter: Some(Keep(used_as_a_condition)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (s.match(/a/)) { f(); }",
            good: "if (/a/.test(s)) { f(); }",
        }),
    },
    Rule {
        id: "js/set-size-via-array",
        name: "Set size should be accessed directly instead of converting to array first",
        description: "[...new Set(x)].length builds an array to count.",
        message: "Use .size.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S7777")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(member_expression property: (property_identifier) @p (#eq? @p "length")) @match"#,
            filter: Some(Keep(counts_a_spread_set)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const n = [...new Set(a)].length;",
            good: "const n = new Set(a).size;",
        }),
    },
    Rule {
        id: "js/function-in-loop",
        name: "Functions should not be defined inside loops",
        description: "A function created per iteration that uses loop variables sees their final values.",
        message: "Move the function out of the loop.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1515")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(function_expression) (arrow_function)] @match"#,
            filter: Some(Keep(captures_loop_state)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "var fs = []; for (var i = 0; i < 3; i++) { fs.push(function () { return i; }); }",
            good: "var fs = []; for (let i = 0; i < 3; i++) { fs.push(function () { return i; }); }",
        }),
    },
    Rule {
        id: "js/cyclomatic-complexity",
        name: "Cyclomatic Complexity of functions should not be too high",
        description: "Many paths through a function make it hard to test and change.",
        message: "Split this function: its cyclomatic complexity is above 10.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 20,
        sonar: &[exact("S1541")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(function_declaration) (function_expression) (arrow_function) (method_definition) (generator_function) (generator_function_declaration)] @match"#,
            filter: Some(Keep(is_cyclomatically_complex)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function f(a) { if (a == 1) {} if (a == 2) {} if (a == 3) {} if (a == 4) {} if (a == 5) {} if (a == 6) {} if (a == 7) {} if (a == 8) {} if (a == 9) {} if (a == 10) {} }",
            good: "function f(a) { if (a == 1) {} }",
        }),
    },
    Rule {
        id: "js/use-strict-in-function",
        name: "\"strict\" mode should be used with caution",
        description: "A function-level \"use strict\" changes the rules for part of a file.",
        message: "Move \"use strict\" to the top of the file, or use modules.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 2,
        sonar: &[exact("S1539")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(expression_statement (string)) @match"#,
            filter: Some(Keep(is_function_level_use_strict)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function f() { 'use strict'; return 1; }",
            good: "function f() { return 1; }",
        }),
    },
    Rule {
        id: "js/console-logging",
        name: "Standard outputs should not be used directly to log anything",
        description: "console output cannot be filtered, routed or silenced.",
        message: "Use a logger.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S106")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression object: (identifier) @o (#eq? @o "console"))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "console.log('x');",
            good: "logger.info('x');",
        }),
    },
    Rule {
        id: "js/global-scope-declaration",
        name: "Variables and functions should not be declared in the global scope",
        description: "In a script, they become properties of the global object.",
        message: "Wrap them in a module or a function.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3798")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(program (variable_declaration) @match) (program (function_declaration) @match)]"#,
            filter: Some(Keep(file_is_a_script)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "var x = 1;",
            good: "export const x = 1;",
        }),
    },
    Rule {
        id: "js/function-name-convention",
        name: "Function and method names should comply with a naming convention",
        description: "Names that follow one convention are easier to read.",
        message: "Rename this function in camelCase.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S100")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(function_declaration name: (identifier) @match) (method_definition name: (property_identifier) @match)]"#,
            filter: Some(Keep(is_not_camel_case)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function Do_it() {}",
            good: "function doIt() {}",
        }),
    },
    Rule {
        id: "js/variable-name-convention",
        name: "Variable names should comply with a naming convention",
        description: "Names that follow one convention are easier to read.",
        message: "Rename this variable in camelCase.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S117")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(variable_declarator name: (identifier) @match)"#,
            filter: Some(Keep(is_snake_case_variable)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "let my_value = 1;",
            good: "let myValue = 1;",
        }),
    },
    Rule {
        id: "js/magic-number",
        name: "Magic numbers should not be used",
        description: "A bare number hides what it means.",
        message: "Give this number a name.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S109")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(number) @match"#,
            filter: Some(Keep(is_magic_number)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const x = y * 37 + z;",
            good: "const RATE = 37; const x = y * RATE + z;",
        }),
    },
    Rule {
        id: "js/ternary-operator",
        name: "The ternary operator should not be used",
        description: "Nested or long ternaries are harder to read than if statements.",
        message: "Use an if statement.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S1774")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(ternary_expression) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const a = b ? 1 : 2;",
            good: "let a; if (b) { a = 1; } else { a = 2; }",
        }),
    },
    Rule {
        id: "js/void-return-used",
        name: "The return value of void functions should not be used",
        description: "A function that returns nothing yields undefined.",
        message: "Do not use the result of this call.",
        category: Bug,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S3699")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (identifier)) @match"#,
            filter: Some(Keep(uses_result_of_void_function)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function log(m) { console.error(m); } const r = log('x');",
            good: "function log(m) { console.error(m); } log('x');",
        }),
    },
    Rule {
        id: "js/iam-action-wildcard",
        name: "AWS IAM policies should limit the scope of permissions given",
        description: "An Allow statement for every action grants far more than any role needs.",
        message: "Grant only the actions that are needed.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 15,
        sonar: &[exact("S6317")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(object) @match"#,
            filter: Some(Keep(allows_every_action)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const p = { Effect: 'Allow', Action: '*', Resource: 'arn:aws:s3:::b/*' };",
            good: "const p = { Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::b/*' };",
        }),
    },
    Rule {
        id: "js/iam-kms-resource-wildcard",
        name: "IAM policies should not grant access to all account resources",
        description: "kms:Decrypt on * lets the role decrypt anything in the account.",
        message: "Name the key in Resource.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 15,
        sonar: &[exact("S6304")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(object) @match"#,
            filter: Some(Keep(allows_kms_on_every_resource)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const p = { Effect: 'Allow', Action: 'kms:Decrypt', Resource: '*' };",
            good: "const p = { Effect: 'Allow', Action: 'kms:Decrypt', Resource: 'arn:aws:kms:eu-west-1:1:key/k' };",
        }),
    },
    Rule {
        id: "js/non-null-assertion",
        name: "Non-null assertions should not be used",
        description: "x! silences the compiler instead of handling the null.",
        message: "Check for null.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S2966")],
        check: Check::Query {
            langs: TS,
            query: r#"(non_null_expression) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "const n = a!.length;",
            good: "const n = a?.length;",
        }),
    },
    Rule {
        id: "js/primitive-type-annotation",
        name: "Primitive types should be omitted from initialized or defaulted declarations",
        description: "The type is inferred from the value.",
        message: "Remove the annotation.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S3257")],
        check: Check::Query {
            langs: TS,
            query: r#"(variable_declarator name: (identifier) type: (type_annotation (predefined_type)) value: (_)) @match"#,
            filter: Some(Keep(annotation_repeats_the_value)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "let n: number = 5;",
            good: "let n = 5;",
        }),
    },
    Rule {
        id: "js/empty-interface",
        name: "Interfaces should not be empty",
        description: "An empty interface accepts anything but null.",
        message: "Remove it, or add members.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 3,
        sonar: &[exact("S4023")],
        check: Check::Query {
            langs: TS,
            query: r#"(interface_declaration) @match"#,
            filter: Some(Keep(interface_is_empty)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "interface A {}",
            good: "interface A { id: number }",
        }),
    },
    Rule {
        id: "js/type-assertion-angle",
        name: "Type assertions should use \"as\"",
        description: "<T>x cannot be used in TSX and reads like a generic.",
        message: "Use as.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S4137")],
        check: Check::Query {
            langs: &[Lang::TypeScript],
            query: r#"(type_assertion) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "const a = <string>b;",
            good: "const a = b as string;",
        }),
    },
    Rule {
        id: "js/union-too-long",
        name: "Union types should not have too many elements",
        description: "A union of many members belongs in a named alias.",
        message: "Define a type alias.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 3,
        sonar: &[exact("S4622")],
        check: Check::Query {
            langs: TS,
            query: r#"(union_type) @match"#,
            filter: Some(Keep(union_has_many_members)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "let x: 'a' | 'b' | 'c' | 'd';",
            good: "type Letter = 'a' | 'b' | 'c' | 'd'; let x: Letter;",
        }),
    },
    Rule {
        id: "js/optional-boolean-parameter",
        name: "Optional boolean parameters should have default value",
        description: "An absent boolean is a third state nobody asked for.",
        message: "Give it a default value.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S4798")],
        check: Check::Query {
            langs: TS,
            query: r#"(optional_parameter) @match"#,
            filter: Some(Keep(optional_param_is_boolean)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "function f(flag?: boolean) {}",
            good: "function f(flag = false) {}",
        }),
    },
];

// ------------------------------------------------------------- helpers

pub(super) fn is_function_kind(kind: &str) -> bool {
    matches!(
        kind,
        "function_declaration"
            | "function_expression"
            | "function"
            | "arrow_function"
            | "method_definition"
            | "generator_function"
            | "generator_function_declaration"
            | "class_static_block"
    )
}

fn is_loop_kind(kind: &str) -> bool {
    matches!(
        kind,
        "for_statement" | "for_in_statement" | "while_statement" | "do_statement"
    )
}

/// The ancestors of `node` up to, not including, the enclosing function.
pub(super) fn ancestors_in_function(node: Node) -> Vec<Node> {
    let mut out = Vec::new();
    let mut cur = node.parent();
    while let Some(p) = cur {
        if is_function_kind(p.kind()) {
            break;
        }
        out.push(p);
        cur = p.parent();
    }
    out
}

pub(super) fn root_node(node: Node) -> Node {
    let mut cur = node;
    while let Some(p) = cur.parent() {
        cur = p;
    }
    cur
}

/// Visits every descendant of `node`; `visit` returns false to skip a
/// node's children.
pub(super) fn walk<'t>(node: Node<'t>, visit: &mut impl FnMut(Node<'t>) -> bool) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if visit(child) {
            walk(child, visit);
        }
    }
}

fn strip_parens(mut node: Node) -> Node {
    while node.kind() == "parenthesized_expression" {
        match node.named_child(0) {
            Some(inner) => node = inner,
            None => break,
        }
    }
    node
}

fn is_logical(op: &[u8]) -> bool {
    matches!(op, b"&&" | b"||" | b"??")
}

// ------------------------------------------------------------- structure

fn lacks_braces(node: Node, _: &[u8]) -> bool {
    if node.kind() == "statement_block" || node.kind() == "comment" {
        return false;
    }
    // `else if` is the chain continuing.
    !(node.kind() == "if_statement" && node.parent().is_some_and(|p| p.kind() == "else_clause"))
}

fn else_if_chain_lacks_else(node: Node, _: &[u8]) -> bool {
    if node.parent().is_some_and(|p| p.kind() == "else_clause") {
        return false;
    }
    let mut cur = node;
    loop {
        let Some(alt) = cur.child_by_field_name("alternative") else {
            return true;
        };
        match alt.named_child(0) {
            Some(inner) if inner.kind() == "if_statement" => cur = inner,
            _ => return false,
        }
    }
}

fn nested_four_deep(node: Node, _: &[u8]) -> bool {
    let is_else_if = |n: Node| {
        n.kind() == "if_statement" && n.parent().is_some_and(|p| p.kind() == "else_clause")
    };
    if is_else_if(node) {
        return false;
    }
    let depth = ancestors_in_function(node)
        .into_iter()
        .filter(|a| {
            matches!(
                a.kind(),
                "if_statement"
                    | "for_statement"
                    | "for_in_statement"
                    | "while_statement"
                    | "do_statement"
                    | "switch_statement"
                    | "try_statement"
            ) && !is_else_if(*a)
        })
        .count();
    depth == 3
}

fn has_several_jumps(loop_: Node, _: &[u8]) -> bool {
    fn count(node: Node, in_loop: bool, in_switch: bool) -> usize {
        let mut cursor = node.walk();
        let mut n = 0;
        for child in node.children(&mut cursor) {
            let kind = child.kind();
            if is_function_kind(kind) {
                continue;
            }
            if kind == "break_statement" {
                if child.child_by_field_name("label").is_none() && !in_loop && !in_switch {
                    n += 1;
                }
            } else if kind == "continue_statement" {
                if child.child_by_field_name("label").is_none() && !in_loop {
                    n += 1;
                }
            } else {
                n += count(
                    child,
                    in_loop || is_loop_kind(kind),
                    in_switch || kind == "switch_statement",
                );
            }
        }
        n
    }
    count(loop_, false, false) > 1
}

fn inner_mergeable_if<'t>(outer: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    if outer.child_by_field_name("alternative").is_some() {
        return None;
    }
    let body = outer.child_by_field_name("consequence")?;
    let inner = if body.kind() == "statement_block" {
        let kids = named(body);
        if kids.len() != 1 {
            return None;
        }
        kids[0]
    } else {
        body
    };
    (inner.kind() == "if_statement" && inner.child_by_field_name("alternative").is_none())
        .then_some(inner)
}

fn expression_has_many_operators(bin: Node, src: &[u8]) -> bool {
    if !is_logical(operator_text(bin, src)) {
        return false;
    }
    let mut parent = bin.parent();
    while let Some(p) = parent {
        match p.kind() {
            "parenthesized_expression" => parent = p.parent(),
            "binary_expression" if is_logical(operator_text(p, src)) => return false,
            _ => break,
        }
    }
    fn count(node: Node, src: &[u8]) -> usize {
        match node.kind() {
            "binary_expression" => {
                let own = usize::from(is_logical(operator_text(node, src)));
                own + named(node)
                    .into_iter()
                    .map(|c| count(c, src))
                    .sum::<usize>()
            }
            "parenthesized_expression" | "unary_expression" => {
                named(node).into_iter().map(|c| count(c, src)).sum()
            }
            _ => 0,
        }
    }
    count(bin, src) > 3
}

fn is_first_of_a_duplicated_literal(string: Node, src: &[u8]) -> bool {
    if string_content(string, src).len() < 10 {
        return false;
    }
    if string.parent().is_some_and(|p| {
        matches!(
            p.kind(),
            "import_statement" | "export_statement" | "jsx_attribute"
        )
    }) {
        return false;
    }
    let want = text(string, src);
    let mut count = 0;
    let mut first = None;
    walk(root_node(string), &mut |n| {
        if n.kind() == "string" && text(n, src) == want {
            count += 1;
            first.get_or_insert(n.start_byte());
        }
        true
    });
    count >= 3 && first == Some(string.start_byte())
}

fn array_constructor_misused(node: Node, _: &[u8]) -> bool {
    let count = node
        .child_by_field_name("arguments")
        .map_or(0, |a| named(a).len());
    count != 1
}

fn declared_inside_a_nested_block(function: Node, _: &[u8]) -> bool {
    let Some(block) = function.parent().filter(|p| p.kind() == "statement_block") else {
        return false;
    };
    block
        .parent()
        .is_some_and(|gp| !is_function_kind(gp.kind()))
}

fn for_in_without_filter(node: Node, src: &[u8]) -> bool {
    if node.child_by_field_name("operator").map(|o| text(o, src)) != Some(b"in") {
        return false;
    }
    let Some(body) = node.child_by_field_name("body") else {
        return false;
    };
    match body.kind() {
        "if_statement" | "empty_statement" => false,
        "statement_block" => named(body)
            .first()
            .is_some_and(|first| first.kind() != "if_statement"),
        _ => true,
    }
}

fn switch_inside_switch(node: Node, _: &[u8]) -> bool {
    ancestors_in_function(node)
        .iter()
        .any(|a| a.kind() == "switch_statement")
}

fn setter_lacks_getter<'t>(container: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let members = named(container);
    let key = |m: Node| {
        m.child_by_field_name("name").map(|n| {
            (
                text(n, src).to_vec(),
                has_token(m, "static"),
                n.kind() == "computed_property_name",
            )
        })
    };
    let getters: Vec<_> = members
        .iter()
        .filter(|m| m.kind() == "method_definition" && has_token(**m, "get"))
        .filter_map(|m| key(*m))
        .collect();
    members
        .iter()
        .filter(|m| m.kind() == "method_definition" && has_token(**m, "set"))
        .find(|m| key(**m).is_some_and(|k| !k.2 && !getters.contains(&k)))
        .copied()
}

fn is_builtin_name(node: Node, src: &[u8]) -> bool {
    const BUILTINS: &[&[u8]] = &[
        b"Object",
        b"Function",
        b"Array",
        b"String",
        b"Number",
        b"Boolean",
        b"Date",
        b"RegExp",
        b"Error",
        b"Math",
        b"JSON",
        b"Promise",
        b"Map",
        b"Set",
        b"WeakMap",
        b"WeakSet",
        b"Symbol",
        b"BigInt",
        b"Proxy",
        b"Reflect",
        b"undefined",
        b"NaN",
        b"Infinity",
        b"eval",
    ];
    if !BUILTINS.contains(&text(node, src)) {
        return false;
    }
    let mut cur = node.parent();
    while let Some(p) = cur {
        if p.kind() == "ambient_declaration" {
            return false;
        }
        cur = p.parent();
    }
    true
}

fn has_exactly_one_argument(call: Node, _: &[u8]) -> bool {
    call.child_by_field_name("arguments")
        .is_some_and(|a| matches!(named(a).as_slice(), [only] if only.kind() != "spread_element"))
}

fn has_no_arguments(new_expr: Node, _: &[u8]) -> bool {
    new_expr
        .child_by_field_name("arguments")
        .is_none_or(|a| named(a).is_empty())
}

// ------------------------------------------------------------- style

fn key_and_value_match(pair: Node, src: &[u8]) -> bool {
    match (
        pair.child_by_field_name("key"),
        pair.child_by_field_name("value"),
    ) {
        (Some(k), Some(v)) => text(k, src) == text(v, src),
        _ => false,
    }
}

fn shorthands_are_scattered(object: Node, _: &[u8]) -> bool {
    let members = named(object);
    let flags: Vec<bool> = members
        .iter()
        .map(|m| m.kind() == "shorthand_property_identifier")
        .collect();
    let shorthand = flags.iter().filter(|f| **f).count();
    if shorthand == 0 || shorthand == flags.len() {
        return false;
    }
    let prefix = flags[..shorthand].iter().all(|f| *f);
    let suffix = flags[flags.len() - shorthand..].iter().all(|f| *f);
    !(prefix || suffix)
}

fn concatenates_with_a_string_literal(bin: Node, src: &[u8]) -> bool {
    if operator_text(bin, src) != b"+" {
        return false;
    }
    if bin
        .parent()
        .is_some_and(|p| p.kind() == "binary_expression" && operator_text(p, src) == b"+")
    {
        return false;
    }
    fn leaves<'t>(node: Node<'t>, src: &[u8], out: &mut Vec<Node<'t>>) {
        if node.kind() == "binary_expression" && operator_text(node, src) == b"+" {
            for c in named(node) {
                leaves(c, src, out);
            }
        } else {
            out.push(node);
        }
    }
    let mut all = Vec::new();
    leaves(bin, src, &mut all);
    let literal = |n: &Node| matches!(n.kind(), "string" | "template_string" | "number");
    all.iter()
        .any(|n| matches!(n.kind(), "string" | "template_string"))
        && all.iter().any(|n| !literal(n))
}

fn is_arguments_object(id: Node, src: &[u8]) -> bool {
    text(id, src) == b"arguments"
        && ancestors_in_function(id).len() < 10_000
        && id.parent().is_some_and(|p| {
            !matches!(p.kind(), "formal_parameters" | "variable_declarator")
                || p.child_by_field_name("name") != Some(id)
        })
}

fn name_equals_property(declarator: Node, src: &[u8]) -> bool {
    match (
        declarator.child_by_field_name("name"),
        declarator
            .child_by_field_name("value")
            .and_then(|v| v.child_by_field_name("property")),
    ) {
        (Some(n), Some(p)) => text(n, src) == text(p, src),
        _ => false,
    }
}

fn has_placeholder(string: Node, src: &[u8]) -> bool {
    let t = string_content(string, src);
    t.windows(2)
        .position(|w| w == b"${")
        .is_some_and(|i| t[i..].contains(&b'}'))
}

fn await_not_in_try(await_: Node, _: &[u8]) -> bool {
    !ancestors_in_function(await_)
        .iter()
        .any(|a| a.kind() == "try_statement")
}

fn regex_is_global(value: Node, src: &[u8]) -> bool {
    match value.kind() {
        "regex" => {
            let t = text(value, src);
            t.iter()
                .rposition(|b| *b == b'/')
                .is_some_and(|i| t[i + 1..].iter().any(|b| matches!(b, b'g' | b'y')))
        }
        "new_expression" => {
            value
                .child_by_field_name("constructor")
                .is_some_and(|c| text(c, src) == b"RegExp")
                && value.child_by_field_name("arguments").is_some_and(|a| {
                    named(a).get(1).is_some_and(|f| {
                        f.kind() == "string"
                            && string_content(*f, src)
                                .iter()
                                .any(|b| matches!(b, b'g' | b'y'))
                    })
                })
        }
        _ => false,
    }
}

fn regex_variable_is_global(call: Node, src: &[u8]) -> bool {
    let Some(object) = call
        .child_by_field_name("function")
        .and_then(|f| f.child_by_field_name("object"))
    else {
        return false;
    };
    let name = text(object, src);
    let mut found = false;
    walk(root_node(call), &mut |n| {
        if !found
            && n.kind() == "variable_declarator"
            && n.child_by_field_name("name")
                .is_some_and(|x| text(x, src) == name)
            && n.child_by_field_name("value")
                .is_some_and(|v| regex_is_global(v, src))
        {
            found = true;
        }
        !found
    });
    found
}

fn is_not_pascal_case(name: Node, src: &[u8]) -> bool {
    let t = text(name, src);
    t.first().is_some_and(u8::is_ascii_uppercase) && t.contains(&b'_')
}

fn is_negated(expr: Node, src: &[u8]) -> bool {
    let expr = strip_parens(expr);
    match expr.kind() {
        "unary_expression" => {
            expr.child_by_field_name("operator").map(|o| text(o, src)) == Some(b"!")
                && expr.child_by_field_name("argument").is_some_and(|a| {
                    !(a.kind() == "unary_expression" && text(a, src).starts_with(b"!"))
                })
        }
        "binary_expression" => matches!(operator_text(expr, src), b"!=" | b"!=="),
        _ => false,
    }
}

fn negated_with_else(node: Node, src: &[u8]) -> bool {
    let Some(condition) = node.child_by_field_name("condition") else {
        return false;
    };
    if node.kind() == "if_statement" {
        let Some(alt) = node.child_by_field_name("alternative") else {
            return false;
        };
        if alt
            .named_child(0)
            .is_none_or(|s| s.kind() == "if_statement")
        {
            return false;
        }
    }
    is_negated(condition, src)
}

fn is_object_default_parameter(object: Node, _: &[u8]) -> bool {
    if named(object).is_empty() {
        return false;
    }
    let Some(parent) = object.parent() else {
        return false;
    };
    matches!(
        parent.kind(),
        "assignment_pattern" | "required_parameter" | "optional_parameter"
    ) && parent
        .child_by_field_name("right")
        .or_else(|| parent.child_by_field_name("value"))
        == Some(object)
        && parent
            .parent()
            .is_some_and(|gp| gp.kind() == "formal_parameters")
}

fn has_trailing_zero(number: Node, src: &[u8]) -> bool {
    let lower = text(number, src).to_ascii_lowercase();
    if lower.starts_with(b"0x")
        || lower.starts_with(b"0b")
        || lower.starts_with(b"0o")
        || lower.contains(&b'_')
        || lower.contains(&b'e')
        || lower.ends_with(b"n")
    {
        return false;
    }
    match lower.iter().position(|b| *b == b'.') {
        Some(dot) => {
            let frac = &lower[dot + 1..];
            frac.is_empty() || frac.ends_with(b"0")
        }
        None => false,
    }
}

fn used_as_a_condition(call: Node, src: &[u8]) -> bool {
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    let is_regex = |n: Option<Node>| n.is_some_and(|n| n.kind() == "regex");
    let property = function
        .child_by_field_name("property")
        .map(|p| text(p, src));
    let ok = match property {
        Some(b"match") => is_regex(
            call.child_by_field_name("arguments")
                .and_then(|a| a.named_child(0)),
        ),
        Some(b"exec") => is_regex(function.child_by_field_name("object")),
        _ => false,
    };
    if !ok {
        return false;
    }
    let Some(parent) = call.parent() else {
        return false;
    };
    match parent.kind() {
        "unary_expression" => {
            parent.child_by_field_name("operator").map(|o| text(o, src)) == Some(b"!")
        }
        "parenthesized_expression" => parent.parent().is_some_and(|gp| {
            matches!(
                gp.kind(),
                "if_statement" | "while_statement" | "do_statement"
            )
        }),
        "ternary_expression" => parent.child_by_field_name("condition") == Some(call),
        _ => false,
    }
}

fn counts_a_spread_set(member: Node, src: &[u8]) -> bool {
    let Some(object) = member.child_by_field_name("object") else {
        return false;
    };
    let is_set = |n: Node| {
        n.kind() == "new_expression"
            && n.child_by_field_name("constructor")
                .is_some_and(|c| matches!(text(c, src), b"Set" | b"Map"))
    };
    match object.kind() {
        "array" => match named(object).as_slice() {
            [spread] if spread.kind() == "spread_element" => {
                spread.named_child(0).is_some_and(is_set)
            }
            _ => false,
        },
        "call_expression" => {
            object
                .child_by_field_name("function")
                .is_some_and(|f| text(f, src) == b"Array.from")
                && object
                    .child_by_field_name("arguments")
                    .and_then(|a| a.named_child(0))
                    .is_some_and(is_set)
        }
        _ => false,
    }
}

fn captures_loop_state(function: Node, src: &[u8]) -> bool {
    if function.parent().is_some_and(|p| {
        p.kind() == "parenthesized_expression"
            && p.parent().is_some_and(|g| g.kind() == "call_expression")
    }) {
        return false;
    }
    let Some(loop_) = ancestors_in_function(function)
        .into_iter()
        .find(|a| is_loop_kind(a.kind()))
    else {
        return false;
    };
    let mut mutable: Vec<&[u8]> = Vec::new();
    walk(loop_, &mut |n| {
        match n.kind() {
            "variable_declaration" => {
                for d in named(n) {
                    if let Some(name) = d
                        .child_by_field_name("name")
                        .filter(|x| x.kind() == "identifier")
                    {
                        mutable.push(text(name, src));
                    }
                }
            }
            "assignment_expression" | "augmented_assignment_expression" => {
                if let Some(l) = n
                    .child_by_field_name("left")
                    .filter(|l| l.kind() == "identifier")
                {
                    mutable.push(text(l, src));
                }
            }
            "update_expression" => {
                if let Some(a) = n
                    .child_by_field_name("argument")
                    .filter(|a| a.kind() == "identifier")
                {
                    mutable.push(text(a, src));
                }
            }
            _ => {}
        }
        true
    });
    // `for (let i ...)` gives each iteration its own binding.
    if let Some(init) = loop_
        .child_by_field_name("initializer")
        .filter(|i| i.kind() == "lexical_declaration")
    {
        for d in named(init) {
            if let Some(name) = d.child_by_field_name("name") {
                mutable.retain(|m| *m != text(name, src));
            }
        }
    }
    let mut captured = false;
    walk(function, &mut |n| {
        if n.kind() == "identifier" && mutable.contains(&text(n, src)) {
            captured = true;
        }
        !captured
    });
    captured
}

fn index_only_reads_the_array(for_: Node, src: &[u8]) -> bool {
    let (Some(init), Some(cond), Some(step), Some(body)) = (
        for_.child_by_field_name("initializer"),
        for_.child_by_field_name("condition"),
        for_.child_by_field_name("increment"),
        for_.child_by_field_name("body"),
    ) else {
        return false;
    };
    let declarators = named(init);
    let [declarator] = declarators.as_slice() else {
        return false;
    };
    let (Some(var), Some(zero)) = (
        declarator.child_by_field_name("name"),
        declarator.child_by_field_name("value"),
    ) else {
        return false;
    };
    if text(zero, src) != b"0" {
        return false;
    }
    let var_name = text(var, src);
    let cond = if cond.kind() == "expression_statement" {
        match cond.named_child(0) {
            Some(c) => c,
            None => return false,
        }
    } else {
        cond
    };
    if cond.kind() != "binary_expression" || operator_text(cond, src) != b"<" {
        return false;
    }
    let (Some(left), Some(right)) = (
        cond.child_by_field_name("left"),
        cond.child_by_field_name("right"),
    ) else {
        return false;
    };
    if text(left, src) != var_name || right.kind() != "member_expression" {
        return false;
    }
    let (Some(array), Some(prop)) = (
        right.child_by_field_name("object"),
        right.child_by_field_name("property"),
    ) else {
        return false;
    };
    if text(prop, src) != b"length" || array.kind() != "identifier" {
        return false;
    }
    let step_text = text(step, src);
    if step_text != [var_name, b"++"].concat() && step_text != [b"++", var_name].concat() {
        return false;
    }
    let array_name = text(array, src);
    let mut uses = 0;
    let mut other = false;
    walk(body, &mut |n| {
        if n.kind() == "identifier" && text(n, src) == var_name {
            let read_only = n.parent().is_some_and(|p| {
                p.kind() == "subscript_expression"
                    && p.child_by_field_name("index") == Some(n)
                    && p.child_by_field_name("object")
                        .is_some_and(|o| text(o, src) == array_name)
                    && !p.parent().is_some_and(|g| {
                        matches!(
                            g.kind(),
                            "assignment_expression" | "augmented_assignment_expression"
                        ) && g.child_by_field_name("left") == Some(p)
                            || g.kind() == "update_expression"
                    })
            });
            if read_only {
                uses += 1;
            } else {
                other = true;
            }
        }
        true
    });
    uses > 0 && !other
}

fn is_unshadowed_global(id: Node, src: &[u8]) -> bool {
    let name = text(id, src);
    let mut declared = false;
    walk(root_node(id), &mut |n| {
        if matches!(
            n.kind(),
            "variable_declarator"
                | "required_parameter"
                | "optional_parameter"
                | "function_declaration"
        ) && n
            .child_by_field_name("name")
            .or_else(|| n.child_by_field_name("pattern"))
            .is_some_and(|x| text(x, src) == name)
        {
            declared = true;
        }
        if n.kind() == "formal_parameters" {
            declared |= named(n).iter().any(|p| text(*p, src) == name);
        }
        !declared
    });
    !declared
}

// ------------------------------------------------------------- more

fn is_cyclomatically_complex(function: Node, src: &[u8]) -> bool {
    fn count(node: Node, src: &[u8]) -> usize {
        let mut cursor = node.walk();
        let mut n = 0;
        for child in node.children(&mut cursor) {
            if is_function_kind(child.kind()) {
                continue;
            }
            n += match child.kind() {
                "if_statement" | "for_statement" | "for_in_statement" | "while_statement"
                | "do_statement" | "switch_case" | "catch_clause" | "ternary_expression" => 1,
                "binary_expression" => usize::from(is_logical(operator_text(child, src))),
                _ => 0,
            };
            n += count(child, src);
        }
        n
    }
    count(function, src) + 1 > 10
}

fn is_function_level_use_strict(statement: Node, src: &[u8]) -> bool {
    let Some(string) = statement.named_child(0) else {
        return false;
    };
    string_content(string, src) == b"use strict"
        && statement.parent().is_some_and(|block| {
            block.kind() == "statement_block"
                && block.parent().is_some_and(|f| is_function_kind(f.kind()))
        })
}

fn file_is_a_script(declaration: Node, _: &[u8]) -> bool {
    let root = root_node(declaration);
    let mut cursor = root.walk();
    !root
        .children(&mut cursor)
        .any(|c| matches!(c.kind(), "import_statement" | "export_statement"))
}

fn is_not_camel_case(name: Node, src: &[u8]) -> bool {
    let t = text(name, src);
    if t == b"constructor" {
        return false;
    }
    let ok_start = t
        .first()
        .is_some_and(|b| *b == b'_' || b.is_ascii_lowercase());
    !(ok_start && t.iter().skip(1).all(u8::is_ascii_alphanumeric))
}

fn is_snake_case_variable(name: Node, src: &[u8]) -> bool {
    let t = text(name, src);
    let inner_underscore = t.iter().skip(1).any(|b| *b == b'_');
    if !inner_underscore {
        return false;
    }
    let constant = t
        .iter()
        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_');
    !(constant
        && name
            .parent()
            .and_then(|d| d.parent())
            .is_some_and(|decl| text(decl, src).starts_with(b"const")))
}

fn is_magic_number(number: Node, src: &[u8]) -> bool {
    let t = text(number, src);
    if matches!(t, b"0" | b"1" | b"2") {
        return false;
    }
    let mut node = number;
    if let Some(p) = node.parent().filter(|p| p.kind() == "unary_expression") {
        node = p;
    }
    let Some(parent) = node.parent() else {
        return false;
    };
    // A named constant, a lookup table or an argument is not a bare operand.
    matches!(
        parent.kind(),
        "binary_expression"
            | "augmented_assignment_expression"
            | "assignment_expression"
            | "return_statement"
            | "ternary_expression"
    )
}

fn uses_result_of_void_function(call: Node, src: &[u8]) -> bool {
    let Some(parent) = call.parent() else {
        return false;
    };
    let used = match parent.kind() {
        "variable_declarator" => parent.child_by_field_name("value") == Some(call),
        "assignment_expression" => parent.child_by_field_name("right") == Some(call),
        "return_statement" => true,
        _ => false,
    };
    if !used {
        return false;
    }
    let Some(callee) = call.child_by_field_name("function") else {
        return false;
    };
    let name = text(callee, src);
    let mut declared = Vec::new();
    walk(root_node(call), &mut |n| {
        if n.kind() == "function_declaration"
            && n.child_by_field_name("name")
                .is_some_and(|x| text(x, src) == name)
        {
            declared.push(n);
        }
        true
    });
    let [function] = declared.as_slice() else {
        return false;
    };
    if has_token(*function, "async") || has_token(*function, "*") {
        return false;
    }
    let Some(body) = function.child_by_field_name("body") else {
        return false;
    };
    let mut returns_value = false;
    walk(body, &mut |n| {
        if is_function_kind(n.kind()) {
            return false;
        }
        if n.kind() == "return_statement" && n.named_child(0).is_some() {
            returns_value = true;
        }
        true
    });
    !returns_value
}

/// The value of the pair whose key is `key` (case-insensitive), in an object.
fn pair_value<'t>(object: Node<'t>, keys: &[&str], src: &[u8]) -> Option<Node<'t>> {
    named(object).into_iter().find_map(|p| {
        if p.kind() != "pair" {
            return None;
        }
        let k = p.child_by_field_name("key")?;
        let k = if k.kind() == "string" {
            string_content(k, src)
        } else {
            text(k, src)
        };
        let k = String::from_utf8_lossy(k).to_ascii_lowercase();
        keys.contains(&k.as_str())
            .then(|| p.child_by_field_name("value"))
            .flatten()
    })
}

fn string_values<'t>(value: Node<'t>, src: &'t [u8]) -> Vec<&'t [u8]> {
    match value.kind() {
        "string" => vec![string_content(value, src)],
        "array" => named(value)
            .into_iter()
            .filter(|n| n.kind() == "string")
            .map(|n| string_content(n, src))
            .collect(),
        _ => Vec::new(),
    }
}

fn is_allow(object: Node, src: &[u8]) -> bool {
    pair_value(object, &["effect"], src).is_some_and(|e| {
        let t = text(e, src);
        t.eq_ignore_ascii_case(b"'allow'")
            || t.eq_ignore_ascii_case(b"\"allow\"")
            || t.ends_with(b"ALLOW")
    })
}

fn allows_every_action(object: Node, src: &[u8]) -> bool {
    is_allow(object, src)
        && pair_value(object, &["action", "actions"], src)
            .is_some_and(|a| string_values(a, src).contains(&&b"*"[..]))
}

fn allows_kms_on_every_resource(object: Node, src: &[u8]) -> bool {
    is_allow(object, src)
        && pair_value(object, &["resource", "resources"], src)
            .is_some_and(|r| string_values(r, src).contains(&&b"*"[..]))
        && pair_value(object, &["action", "actions"], src)
            .is_some_and(|a| string_values(a, src).iter().any(|s| s.starts_with(b"kms:")))
}

fn annotation_repeats_the_value(declarator: Node, src: &[u8]) -> bool {
    let (Some(annotation), Some(value)) = (
        declarator.child_by_field_name("type"),
        declarator.child_by_field_name("value"),
    ) else {
        return false;
    };
    let value = if value.kind() == "unary_expression" {
        value.child_by_field_name("argument").unwrap_or(value)
    } else {
        value
    };
    match text(annotation, src) {
        b": number" => value.kind() == "number",
        b": string" => matches!(value.kind(), "string" | "template_string"),
        b": boolean" => matches!(value.kind(), "true" | "false"),
        _ => false,
    }
}

fn interface_is_empty(interface: Node, _: &[u8]) -> bool {
    let Some(body) = interface.child_by_field_name("body") else {
        return false;
    };
    if !named(body).is_empty() {
        return false;
    }
    let mut cursor = interface.walk();
    let extends = interface
        .children(&mut cursor)
        .find(|c| c.kind() == "extends_type_clause")
        .map_or(0, |c| named(c).len());
    extends <= 1
}

fn union_has_many_members(union: Node, _: &[u8]) -> bool {
    if union
        .parent()
        .is_some_and(|p| matches!(p.kind(), "union_type" | "type_alias_declaration"))
    {
        return false;
    }
    fn members(node: Node) -> usize {
        if node.kind() == "union_type" {
            named(node).into_iter().map(members).sum()
        } else {
            1
        }
    }
    members(union) > 3
}

fn optional_param_is_boolean(param: Node, src: &[u8]) -> bool {
    param
        .child_by_field_name("type")
        .is_some_and(|t| text(t, src) == b": boolean")
}
