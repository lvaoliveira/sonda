//! JavaScript, JSX and TypeScript rules, part 3 (ADR-0007, batch 11): a11y
//! role checks, modern idioms, TypeScript type and enum checks, and a few
//! Angular checks. Queries stay cheap on deep trees: see `js_modern.rs`.

use super::js::{
    attribute, find_below, has_spread, has_token, opening_tag, static_value, string_content,
    tag_name, text,
};
use super::js_modern::collect_below;
use super::*;

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "js/extra-arguments",
        name: "Function calls should not pass extra arguments",
        description: "Arguments beyond the parameter list are ignored, which usually means the wrong function was called.",
        message: "Remove the extra arguments, or fix the call.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S930")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(program) @match"#,
            filter: Some(Find(first_call_with_extra_arguments)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function f(a) { return a; }\nf(1, 2);",
            good: "function f(a) { return a; }\nf(1);",
        }),
    },
    Rule {
        id: "js/label-on-non-loop",
        name: "Only while, do, for and switch statements should be labelled",
        description: "A label on anything else cannot be jumped to.",
        message: "Remove this label.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S1439")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(labeled_statement) @match"#,
            filter: Some(Keep(labels_a_non_loop)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "a: { f(); }",
            good: "a: for (;;) { break a; }",
        }),
    },
    Rule {
        id: "js/identical-branch-bodies",
        name: "Two branches in a conditional structure should not have exactly the same implementation",
        description: "Repeating a block in two branches suggests they should be merged.",
        message: "Merge these branches.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1871")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(statement_block) @match
(program) @match"#,
            filter: Some(Find(block_has_chain_repeating_a_body)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (a) { f(); g(); } else if (b) { f(); g(); }",
            good: "if (a || b) { f(); g(); }",
        }),
    },
    Rule {
        id: "js/inconsistent-new",
        name: "Functions should be called consistently with or without new",
        description: "A function used both as a constructor and as a plain call behaves differently each way.",
        message: "Use it one way throughout.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S3686")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(program) @match"#,
            filter: Some(Find(called_both_ways)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function Foo() {}\nconst a = new Foo();\nconst b = Foo();",
            good: "function Foo() {}\nconst a = new Foo();\nconst b = new Foo();",
        }),
    },
    Rule {
        id: "js/for-to-for-of",
        name: "for of should be used with Iterables",
        description: "An index loop whose index is only used to read the array is a for-of.",
        message: "Use for...of.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S4138")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(for_statement) @match"#,
            filter: Some(Keep(index_only_reads_the_array)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "for (let i = 0; i < items.length; i++) { use(items[i]); }",
            good: "for (const item of items) { use(item); }",
        }),
    },
    Rule {
        id: "js/empty-collection-read",
        name: "Empty collections should not be accessed or iterated",
        description: "Reading a collection that nothing ever fills gives nothing.",
        message: "Fill the collection, or remove the code.",
        category: Bug,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S4158")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(variable_declarator name: (identifier) value: (array)) @match"#,
            filter: Some(Keep(empty_array_only_read)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function f() { const items = []; items.forEach(use); }",
            good: "function f() { const items = []; items.push(1); items.forEach(use); }",
        }),
    },
    Rule {
        id: "js/default-as-named-import",
        name: "Default imports and exports should use the dedicated syntax",
        description: "`import { default as x }` is `import x`.",
        message: "Use the default import/export syntax.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S7734")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(import_specifier) @match
(export_specifier) @match"#,
            filter: Some(Keep(uses_default_as_a_name)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "import { default as x } from 'm';",
            good: "import x from 'm';",
        }),
    },
    Rule {
        id: "js/typeof-undefined",
        name: "typeof should not be used to check for undefined",
        description: "`x === undefined` says the same for a declared value.",
        message: "Compare with undefined directly.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S7741")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(binary_expression) @match"#,
            filter: Some(Keep(typeof_compared_with_undefined)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (typeof obj.value === 'undefined') {}",
            good: "if (obj.value === undefined) {}",
        }),
    },
    Rule {
        id: "js/unnecessary-spread",
        name: "Spread syntax should not be used unnecessarily",
        description: "Spreading an array or object literal into another one just copies it.",
        message: "Remove the spread.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S7747")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(spread_element) @match"#,
            filter: Some(Keep(spreads_a_literal)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const a = [...[1, 2]];",
            good: "const a = [1, 2];",
        }),
    },
    Rule {
        id: "js/ternary-in-array-spread",
        name: "Ternary expressions in array spreads should use consistent types",
        description: "Spreading undefined or null into an array throws.",
        message: "Use [] instead of undefined.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7720")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(spread_element) @match"#,
            filter: Some(Keep(spread_ternary_mixes_types)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const a = [...(x ? [1] : undefined)];",
            good: "const a = [...(x ? [1] : [])];",
        }),
    },
    Rule {
        id: "js/manual-flatten",
        name: "Array flattening should use the native flat() method",
        description: "`[].concat(...arrays)` and reduce+concat are what flat() is for.",
        message: "Use flat().",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7751")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression) @match"#,
            filter: Some(Keep(flattens_by_hand)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const flat = [].concat(...lists);",
            good: "const flat = lists.flat();",
        }),
    },
    Rule {
        id: "js/find-index-to-index-of",
        name: "indexOf() should be used instead of findIndex() for simple equality",
        description: "findIndex with `x => x === v` is indexOf(v).",
        message: "Use indexOf().",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7753")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression property: (property_identifier) @p (#eq? @p "findIndex"))) @match"#,
            filter: Some(Keep(find_index_tests_equality)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const i = list.findIndex(x => x === v);",
            good: "const i = list.indexOf(v);",
        }),
    },
    Rule {
        id: "js/file-reader",
        name: "Modern Blob methods should be used instead of FileReader",
        description: "blob.text() and blob.arrayBuffer() return promises.",
        message: "Use Blob methods.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7756")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(new_expression constructor: (identifier) @c (#eq? @c "FileReader")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const r = new FileReader();",
            good: "const t = await blob.text();",
        }),
    },
    Rule {
        id: "js/constructor-field-assignment",
        name: "Class properties should be declared as fields rather than assigned in constructors",
        description: "A field declaration shows the shape of the class at a glance.",
        message: "Declare this as a class field.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7757")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(method_definition name: (property_identifier) @n (#eq? @n "constructor")) @match"#,
            filter: Some(Find(constant_assigned_in_constructor)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "class A { constructor() { this.count = 0; } }",
            good: "class A { count = 0; }",
        }),
    },
    Rule {
        id: "js/reexport-by-hand",
        name: "Re-exports should use export...from syntax",
        description: "Importing a name only to export it again is `export { x } from`.",
        message: "Use export ... from.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7763")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(program) @match"#,
            filter: Some(Find(import_exported_again)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "import { a } from 'm';\nexport { a };",
            good: "export { a } from 'm';",
        }),
    },
    Rule {
        id: "js/array-for-existence",
        name: "Arrays used only for existence checks should be Sets",
        description: "includes() on an array is a linear scan on every call.",
        message: "Use a Set.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S7776")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(variable_declarator name: (identifier) value: [(array) (call_expression)]) @match"#,
            filter: Some(Keep(array_only_asks_includes)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const allowed = ['a', 'b', 'c', 'd'];\nfunction ok(x) { return allowed.includes(x); }",
            good: "const allowed = new Set(['a', 'b', 'c', 'd']);\nfunction ok(x) { return allowed.has(x); }",
        }),
    },
    Rule {
        id: "js/escaped-backslashes",
        name: "String literals with escaped backslashes should use String.raw",
        description: "`'\\\\\\\\d+'` is easier to read as String.raw`\\\\d+`.",
        message: "Use String.raw.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7780")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(string) @match"#,
            filter: Some(Keep(has_escaped_backslashes)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const p = 'C:\\\\\\\\Users\\\\\\\\me';",
            good: "const p = String.raw`C:\\\\Users\\\\me`;",
        }),
    },
    Rule {
        id: "js/lodash-native",
        name: "Native APIs should be preferred over Lodash and Underscore.js methods",
        description: "Array and string natives cover what these helpers do.",
        message: "Use the native method.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S8907")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression object: (identifier) @o property: (property_identifier) @p (#any-of? @o "_" "lodash") (#any-of? @p "isArray" "map" "forEach" "filter" "reduce" "find" "some" "every" "includes" "keys" "values" "entries" "assign" "concat" "join" "slice" "trim" "startsWith" "endsWith" "toUpper" "toLower" "fill"))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const a = _.map(list, fn);",
            good: "const a = list.map(fn);",
        }),
    },
    Rule {
        id: "js/memoize-without-resolver",
        name: "memoize calls on functions with multiple parameters should use an explicit resolver",
        description: "The default cache key is the first argument only.",
        message: "Pass a resolver.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S8932")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression object: (identifier) @o property: (property_identifier) @p (#any-of? @o "_" "lodash") (#eq? @p "memoize"))) @match"#,
            filter: Some(Keep(memoizes_many_parameters_without_resolver)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const f = _.memoize((a, b) => a + b);",
            good: "const f = _.memoize((a, b) => a + b, (a, b) => `${a}:${b}`);",
        }),
    },
    Rule {
        id: "js/code-after-done",
        name: "Tests should not execute any code after done() is called",
        description: "The test may already be over when later code runs.",
        message: "Call done() last.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6079")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(statement_block) @match"#,
            filter: Some(Find(statement_after_done)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "it('a', (done) => { done(); cleanup(); });",
            good: "it('a', (done) => { cleanup(); done(); });",
        }),
    },
    Rule {
        id: "js/handler-on-plain-element",
        name: "Non-interactive elements should not have event handlers",
        description: "A div with onClick can't be reached or activated from the keyboard.",
        message: "Use a button, or add a role and tabIndex.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6847"), related("S6848")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_attribute (property_identifier) @a (#match? @a "^on(Click|DoubleClick|MouseDown|MouseUp|KeyDown|KeyUp|KeyPress)$")) @match"#,
            filter: Some(Keep(handler_on_plain_element)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const d = <div onClick={go}>x</div>;",
            good: "const d = <button onClick={go}>x</button>;",
        }),
    },
    Rule {
        id: "js/interactive-role-on-static-element",
        name: "Non-interactive DOM elements should not have interactive ARIA roles",
        description: "A heading or paragraph that acts as a button confuses assistive technology.",
        message: "Use a native interactive element.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6842")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_attribute (property_identifier) @a (#eq? @a "role")) @match"#,
            filter: Some(Keep(interactive_role_on_semantic_element)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const h = <h1 role=\"button\">x</h1>;",
            good: "const h = <button>x</button>;",
        }),
    },
    Rule {
        id: "js/static-role-on-interactive-element",
        name: "Interactive DOM elements should not have non-interactive ARIA roles",
        description: "A button announced as a heading can't be activated by assistive technology users.",
        message: "Remove the role.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6843")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_attribute (property_identifier) @a (#eq? @a "role")) @match"#,
            filter: Some(Keep(static_role_on_interactive_element)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const b = <button role=\"heading\">x</button>;",
            good: "const b = <button>x</button>;",
        }),
    },
    Rule {
        id: "js/role-missing-required-props",
        name: "DOM elements with ARIA roles should have the required properties",
        description: "A checkbox role without aria-checked tells assistive technology nothing about its state.",
        message: "Add the required ARIA properties.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6807")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_attribute (property_identifier) @a (#eq? @a "role")) @match"#,
            filter: Some(Keep(role_lacks_required_properties)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const c = <div role=\"checkbox\" tabIndex={0} />;",
            good: "const c = <div role=\"checkbox\" aria-checked={on} tabIndex={0} />;",
        }),
    },
    Rule {
        id: "js/label-without-control",
        name: "Label elements should have a text label and an associated control",
        description: "A label that points at nothing does nothing.",
        message: "Add htmlFor, or nest the control.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6853")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_element open_tag: (jsx_opening_element name: (identifier) @n (#eq? @n "label"))) @match"#,
            filter: Some(Keep(label_has_no_control)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const l = <label>Name</label>;",
            good: "const l = <label htmlFor=\"n\">Name</label>;",
        }),
    },
    Rule {
        id: "ts/readonly-public-static",
        name: "Public static fields should be read-only",
        description: "A mutable public static is global state anyone can change.",
        message: "Make it readonly.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 2,
        sonar: &[exact("S1444")],
        check: Check::Query {
            langs: TS,
            query: r#"(public_field_definition) @match"#,
            filter: Some(Keep(public_static_is_mutable)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "class A { public static count = 0; }",
            good: "class A { public static readonly count = 0; }",
        }),
    },
    Rule {
        id: "ts/constructor-in-interface",
        name: "Constructors should not be declared inside interfaces",
        description: "An interface method named constructor is an ordinary method, not a constructor.",
        message: "Use a construct signature.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S4124")],
        check: Check::Query {
            langs: TS,
            query: r#"(interface_declaration body: (interface_body (method_signature name: (property_identifier) @n (#eq? @n "constructor")) @match))"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "interface I { constructor(x: number): void; }",
            good: "interface I { new (x: number): I; }",
        }),
    },
    Rule {
        id: "ts/module-keyword",
        name: "module should not be used",
        description: "`module Foo {}` is the old spelling of `namespace Foo {}`.",
        message: "Use namespace.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S4156")],
        check: Check::Query {
            langs: TS,
            query: r#"(module name: (identifier)) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "module Foo { export const a = 1; }",
            good: "namespace Foo { export const a = 1; }",
        }),
    },
    Rule {
        id: "ts/duplicate-union-member",
        name: "Union and intersection types should not include duplicated constituents",
        description: "A repeated member does nothing.",
        message: "Remove the duplicate.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S4621")],
        check: Check::Query {
            langs: TS,
            query: r#"(union_type) @match
(intersection_type) @match"#,
            filter: Some(Keep(has_repeated_member)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "type A = string | number | string;",
            good: "type A = string | number;",
        }),
    },
    Rule {
        id: "ts/enum-member-literal",
        name: "All enum members should be literals",
        description: "A computed member makes the enum's values depend on evaluation order.",
        message: "Use a literal value.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6550")],
        check: Check::Query {
            langs: TS,
            query: r#"(enum_assignment) @match"#,
            filter: Some(Keep(initializer_is_not_a_literal)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "enum E { A = foo(), B = 2 }",
            good: "enum E { A = 1, B = 2 }",
        }),
    },
    Rule {
        id: "ts/redundant-type-alias",
        name: "Redundant type aliases should not be used",
        description: "An alias that just renames a primitive adds a name without meaning.",
        message: "Use the type directly.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6564")],
        check: Check::Query {
            langs: TS,
            query: r#"(type_alias_declaration value: (predefined_type)) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "type Name = string;",
            good: "type Name = string & { brand: 'name' };",
        }),
    },
    Rule {
        id: "ts/misleading-non-null",
        name: "Non-null assertions should not be used misleadingly",
        description: "`a! ?? b` asserts a is not null and then guards against it being null.",
        message: "Remove the assertion.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6568")],
        check: Check::Query {
            langs: TS,
            query: r#"(non_null_expression) @match"#,
            filter: Some(Keep(non_null_before_nullish_check)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "const v = a! ?? b;",
            good: "const v = a ?? b;",
        }),
    },
    Rule {
        id: "ts/unnecessary-type-constraint",
        name: "Unnecessary type constraints should be removed",
        description: "`T extends any` constrains nothing.",
        message: "Remove the constraint.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S6569")],
        check: Check::Query {
            langs: TS,
            query: r#"(type_parameter) @match"#,
            filter: Some(Keep(constraint_is_any_or_unknown)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "function f<T extends unknown>(x: T) {}",
            good: "function f<T>(x: T) {}",
        }),
    },
    Rule {
        id: "ts/enum-partial-initialization",
        name: "Enum member values should be either all initialized or none",
        description: "Mixing initialized and implicit members makes the values easy to misread.",
        message: "Initialize all members or none.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6572")],
        check: Check::Query {
            langs: TS,
            query: r#"(enum_body) @match"#,
            filter: Some(Keep(some_members_initialized)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "enum E { A = 1, B, C = 3 }",
            good: "enum E { A = 1, B = 2, C = 3 }",
        }),
    },
    Rule {
        id: "ts/enum-duplicate-value",
        name: "Enum values should be unique",
        description: "Two members with one value are indistinguishable at runtime.",
        message: "Give each member its own value.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6578")],
        check: Check::Query {
            langs: TS,
            query: r#"(enum_body) @match"#,
            filter: Some(Find(repeated_enum_value)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "enum E { A = 1, B = 1 }",
            good: "enum E { A = 1, B = 2 }",
        }),
    },
    Rule {
        id: "ts/call-signature-interface",
        name: "Function types should be preferred",
        description: "An interface with only a call signature is a function type.",
        message: "Use a function type.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6598")],
        check: Check::Query {
            langs: TS,
            query: r#"(interface_declaration) @match"#,
            filter: Some(Keep(interface_is_only_a_call_signature)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "interface F { (x: number): string; }",
            good: "type F = (x: number) => string;",
        }),
    },
    Rule {
        id: "ts/empty-lifecycle-method",
        name: "Empty Angular lifecycle methods should be removed",
        description: "An empty ngOnInit does nothing and still costs a call.",
        message: "Remove the method.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S7647")],
        check: Check::Query {
            langs: TS,
            query: r#"(method_definition name: (property_identifier) @n (#match? @n "^ng(OnInit|OnDestroy|OnChanges|DoCheck|AfterViewInit|AfterViewChecked|AfterContentInit|AfterContentChecked)$")) @match"#,
            filter: Some(Keep(method_body_is_empty)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "@Component({}) class C { ngOnInit() {} }",
            good: "@Component({}) class C { ngOnInit() { this.load(); } }",
        }),
    },
    Rule {
        id: "ts/lifecycle-interface",
        name: "Angular classes should implement lifecycle interfaces for their lifecycle methods",
        description: "The interface turns a misspelled hook into a compile error.",
        message: "Implement the interface.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7655")],
        check: Check::Query {
            langs: TS,
            query: r#"(method_definition name: (property_identifier) @n (#match? @n "^ng(OnInit|OnDestroy|OnChanges|AfterViewInit)$")) @match"#,
            filter: Some(Keep(hook_without_interface)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "@Component({}) class C { ngOnInit() { this.load(); } }",
            good: "@Component({}) class C implements OnInit { ngOnInit() { this.load(); } }",
        }),
    },
    Rule {
        id: "ts/pipe-transform",
        name: "Angular Pipes should implement the PipeTransform interface",
        description: "Without it a wrong transform signature goes unnoticed.",
        message: "Implement PipeTransform.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7656")],
        check: Check::Query {
            langs: TS,
            query: r#"(class_declaration) @match"#,
            filter: Some(Keep(pipe_lacks_pipe_transform)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "@Pipe({ name: 'x' }) class P { transform(v: string) { return v; } }",
            good: "@Pipe({ name: 'x' }) class P implements PipeTransform { transform(v: string) { return v; } }",
        }),
    },
    Rule {
        id: "ts/aliased-binding",
        name: "Input and output bindings should not be aliased",
        description: "An alias gives one property two names.",
        message: "Remove the alias.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7649"), related("S7653")],
        check: Check::Query {
            langs: TS,
            query: r#"(decorator (call_expression function: (identifier) @d (#any-of? @d "Input" "Output") arguments: (arguments (string)))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "class C { @Input('other') name = ''; }",
            good: "class C { @Input() name = ''; }",
        }),
    },
    Rule {
        id: "ts/metadata-bindings",
        name: "The inputs and outputs metadata properties should not be used",
        description: "Decorators on the properties keep the binding next to the field.",
        message: "Use @Input() and @Output().",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7650")],
        check: Check::Query {
            langs: TS,
            query: r#"(decorator (call_expression function: (identifier) @d (#any-of? @d "Component" "Directive") arguments: (arguments (object (pair key: (property_identifier) @k (#any-of? @k "inputs" "outputs")))))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "@Component({ inputs: ['a'] }) class C {}",
            good: "@Component({}) class C { @Input() a = ''; }",
        }),
    },
    Rule {
        id: "ts/output-named-like-dom-event",
        name: "Output bindings should not be named like standard DOM events or prefixed with on",
        description: "A native event of the same name would bubble through the output.",
        message: "Rename the output.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7651"), related("S7652")],
        check: Check::Query {
            langs: TS,
            query: r#"(public_field_definition (decorator (call_expression function: (identifier) @d (#eq? @d "Output"))) name: (property_identifier) @n) @match"#,
            filter: Some(Keep(output_has_a_dom_event_name)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "class C { @Output() click = new EventEmitter(); }",
            good: "class C { @Output() selected = new EventEmitter(); }",
        }),
    },
];

// ---------------------------------------------------- filters

pub(super) fn named(node: Node) -> Vec<Node> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|n| n.kind() != "comment")
        .collect()
}

pub(super) fn count_word(haystack: &[u8], word: &[u8]) -> usize {
    if word.is_empty() {
        return 0;
    }
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'$';
    let mut count = 0;
    let mut i = 0;
    while i + word.len() <= haystack.len() {
        if &haystack[i..i + word.len()] == word
            && (i == 0 || !is_ident(haystack[i - 1]))
            && haystack.get(i + word.len()).is_none_or(|&b| !is_ident(b))
        {
            count += 1;
            i += word.len();
        } else {
            i += 1;
        }
    }
    count
}

pub(super) fn count_pattern(haystack: &[u8], pattern: &[u8]) -> usize {
    if pattern.is_empty() {
        return 0;
    }
    haystack
        .windows(pattern.len())
        .filter(|w| *w == pattern)
        .count()
}

pub(super) fn operator_text<'a>(node: Node, src: &'a [u8]) -> &'a [u8] {
    node.child_by_field_name("operator")
        .map_or(&b""[..], |o| text(o, src))
}

fn first_call_with_extra_arguments<'t>(program: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    // Top-level function declarations, by name; a name declared twice is ambiguous.
    let mut functions: Vec<(&[u8], Node<'t>)> = Vec::new();
    for n in named(program) {
        let d = if n.kind() == "export_statement" {
            match n.child_by_field_name("declaration") {
                Some(d) => d,
                None => continue,
            }
        } else {
            n
        };
        if d.kind() == "function_declaration"
            && let Some(name) = d.child_by_field_name("name")
        {
            functions.push((text(name, src), d));
        }
    }
    if functions.is_empty() {
        return None;
    }
    let mut cursor = program.walk();
    if !cursor.goto_first_child() {
        return None;
    }
    loop {
        let call = cursor.node();
        if call.kind() == "call_expression"
            && let (Some(callee), Some(args)) = (
                call.child_by_field_name("function")
                    .filter(|c| c.kind() == "identifier"),
                call.child_by_field_name("arguments"),
            )
        {
            let name = text(callee, src);
            let matches: Vec<&Node> = functions
                .iter()
                .filter(|(n, _)| *n == name)
                .map(|(_, d)| d)
                .collect();
            if let [function] = matches.as_slice() {
                let given = named(args);
                let spread = given.iter().any(|a| a.kind() == "spread_element");
                let declared = function.child_by_field_name("parameters").map(named);
                let rest = declared.as_ref().is_some_and(|d| {
                    d.iter()
                        .any(|p| matches!(p.kind(), "rest_pattern" | "rest_parameter"))
                });
                let uses_arguments = function
                    .child_by_field_name("body")
                    .is_some_and(|b| count_word(text(b, src), b"arguments") > 0);
                if !spread
                    && !rest
                    && !uses_arguments
                    && declared.is_some_and(|d| given.len() > d.len())
                {
                    return Some(call);
                }
            }
        }
        if cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return None;
            }
        }
    }
}

fn labels_a_non_loop(labeled: Node, _: &[u8]) -> bool {
    labeled.child_by_field_name("body").is_some_and(|b| {
        !matches!(
            b.kind(),
            "for_statement"
                | "for_in_statement"
                | "while_statement"
                | "do_statement"
                | "switch_statement"
        )
    })
}

fn chain_repeats_a_body<'t>(statement: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut bodies: Vec<Node> = Vec::new();
    let mut current = Some(statement);
    while let Some(branch) = current {
        bodies.extend(branch.child_by_field_name("consequence"));
        current = match branch.child_by_field_name("alternative") {
            Some(a) => match a.named_child(0) {
                Some(i) if i.kind() == "if_statement" => Some(i),
                Some(i) => {
                    bodies.push(i);
                    None
                }
                None => None,
            },
            None => None,
        };
    }
    let mut seen: Vec<&[u8]> = Vec::new();
    for body in bodies {
        if body.kind() != "statement_block" || named(body).len() < 2 {
            continue;
        }
        let t = text(body, src);
        if seen.contains(&t) {
            return Some(body);
        }
        seen.push(t);
    }
    None
}

/// Only the head of an else-if chain walks the chain, and heads are the `if`
/// statements that sit directly in a block: no `parent()` lookups needed.
fn block_has_chain_repeating_a_body<'t>(block: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    named(block)
        .into_iter()
        .filter(|s| s.kind() == "if_statement")
        .find_map(|s| chain_repeats_a_body(s, src))
}

fn called_both_ways<'t>(program: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    const COERCIONS: &[&[u8]] = &[
        b"String",
        b"Number",
        b"Boolean",
        b"BigInt",
        b"Symbol",
        b"Array",
        b"Object",
        b"Date",
        b"Error",
        b"RegExp",
        b"Function",
        b"TypeError",
        b"RangeError",
    ];
    let mut constructed: Vec<&[u8]> = Vec::new();
    let mut called: Vec<(Node<'t>, &[u8])> = Vec::new();
    let mut cursor = program.walk();
    if !cursor.goto_first_child() {
        return None;
    }
    loop {
        let n = cursor.node();
        let name_of = |x: Option<Node<'t>>| {
            x.filter(|c| c.kind() == "identifier")
                .map(|c| text(c, src))
                .filter(|t| t.first().is_some_and(u8::is_ascii_uppercase) && !COERCIONS.contains(t))
        };
        match n.kind() {
            "new_expression" => {
                if let Some(t) = name_of(n.child_by_field_name("constructor")) {
                    constructed.push(t);
                }
            }
            "call_expression" => {
                if let Some(t) = name_of(n.child_by_field_name("function")) {
                    called.push((n, t));
                }
            }
            _ => {}
        }
        if cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return called
                    .into_iter()
                    .find(|(_, t)| constructed.contains(t))
                    .map(|(n, _)| n);
            }
        }
    }
}

fn index_only_reads_the_array(for_loop: Node, src: &[u8]) -> bool {
    let (Some(init), Some(condition), Some(update), Some(body)) = (
        for_loop.child_by_field_name("initializer"),
        for_loop.child_by_field_name("condition"),
        for_loop.child_by_field_name("increment"),
        for_loop.child_by_field_name("body"),
    ) else {
        return false;
    };
    let declarators = named(init);
    let Some(declarator) = declarators
        .iter()
        .find(|d| d.kind() == "variable_declarator")
    else {
        return false;
    };
    let Some(index) = declarator.child_by_field_name("name").map(|n| text(n, src)) else {
        return false;
    };
    let starts_at_zero = declarator
        .child_by_field_name("value")
        .is_some_and(|v| text(v, src) == b"0");
    // condition: i < items.length
    let condition = if condition.kind() == "expression_statement" {
        condition.named_child(0)
    } else {
        Some(condition)
    };
    let Some(condition) = condition.filter(|c| c.kind() == "binary_expression") else {
        return false;
    };
    let (Some(l), Some(r)) = (
        condition.child_by_field_name("left"),
        condition.child_by_field_name("right"),
    ) else {
        return false;
    };
    if text(l, src) != index
        || operator_text(condition, src) != b"<"
        || r.kind() != "member_expression"
    {
        return false;
    }
    let (Some(array), Some(prop)) = (
        r.child_by_field_name("object"),
        r.child_by_field_name("property"),
    ) else {
        return false;
    };
    if text(prop, src) != b"length" || array.kind() != "identifier" {
        return false;
    }
    let ut = text(update, src);
    let steps_by_one = ut == [index, b"++"].concat() || ut == [b"++", index].concat();
    let access = [text(array, src), b"[", index, b"]"].concat();
    let body_text = text(body, src);
    let reads = count_pattern(body_text, &access);
    let assigned = count_pattern(body_text, &[access.as_slice(), b" ="].concat())
        - count_pattern(body_text, &[access.as_slice(), b" =="].concat());
    starts_at_zero
        && steps_by_one
        && reads > 0
        && assigned == 0
        && count_word(body_text, index) == reads
}

pub(super) fn scope_text<'a>(node: Node, src: &'a [u8]) -> &'a [u8] {
    let mut p = node.parent();
    let mut hops = 0;
    while let Some(n) = p {
        if matches!(
            n.kind(),
            "function_declaration"
                | "function_expression"
                | "arrow_function"
                | "method_definition"
                | "program"
                | "generator_function_declaration"
        ) {
            return text(n, src);
        }
        hops += 1;
        if hops > 64 {
            break;
        }
        p = n.parent();
    }
    b""
}

fn is_const_declaration(declarator: Node) -> bool {
    declarator.parent().is_some_and(|d| {
        d.kind() == "lexical_declaration" && {
            let mut c = d.walk();
            d.children(&mut c).any(|k| k.kind() == "const")
        }
    })
}

fn empty_array_only_read(declarator: Node, src: &[u8]) -> bool {
    let (Some(name), Some(value)) = (
        declarator.child_by_field_name("name"),
        declarator.child_by_field_name("value"),
    ) else {
        return false;
    };
    if !is_const_declaration(declarator) || value.named_child_count() != 0 {
        return false;
    }
    let n = text(name, src);
    let scope = scope_text(declarator, src);
    let total = count_word(scope, n);
    let reads: usize = [
        &b".forEach("[..],
        b".map(",
        b".filter(",
        b".reduce(",
        b".some(",
        b".every(",
        b".find(",
        b".length",
    ]
    .iter()
    .map(|suffix| count_pattern(scope, &[n, suffix].concat()))
    .sum();
    reads >= 1 && total == reads + 1
}

fn uses_default_as_a_name(specifier: Node, src: &[u8]) -> bool {
    let t = text(specifier, src);
    if specifier.kind() == "import_specifier" {
        t.starts_with(b"default ") && t.windows(4).any(|w| w == b" as ")
    } else {
        t.ends_with(b" as default")
    }
}

fn typeof_compared_with_undefined(binary: Node, src: &[u8]) -> bool {
    if !matches!(operator_text(binary, src), b"===" | b"!==" | b"==" | b"!=") {
        return false;
    }
    let (Some(l), Some(r)) = (
        binary.child_by_field_name("left"),
        binary.child_by_field_name("right"),
    ) else {
        return false;
    };
    let typeof_of_member = |n: Node| {
        n.kind() == "unary_expression"
            && operator_text(n, src) == b"typeof"
            && n.child_by_field_name("argument")
                .is_some_and(|a| matches!(a.kind(), "member_expression" | "subscript_expression"))
    };
    let undefined_string = |n: Node| n.kind() == "string" && string_content(n, src) == b"undefined";
    (typeof_of_member(l) && undefined_string(r)) || (typeof_of_member(r) && undefined_string(l))
}

fn spreads_a_literal(spread: Node, _: &[u8]) -> bool {
    let Some(arg) = spread.named_child(0) else {
        return false;
    };
    let Some(parent) = spread.parent() else {
        return false;
    };
    // `for (const x of [...set])`: the loop can iterate the set itself.
    let copied_for_of = parent.kind() == "array"
        && parent.named_child_count() == 1
        && parent.parent().is_some_and(|g| {
            g.kind() == "for_in_statement" && g.child_by_field_name("right") == Some(parent)
        });
    copied_for_of
        || (arg.kind() == "array" && matches!(parent.kind(), "array" | "arguments"))
        || (arg.kind() == "object" && parent.kind() == "object")
}

fn spread_ternary_mixes_types(spread: Node, src: &[u8]) -> bool {
    let Some(mut arg) = spread.named_child(0) else {
        return false;
    };
    while arg.kind() == "parenthesized_expression" {
        let Some(inner) = arg.named_child(0) else {
            return false;
        };
        arg = inner;
    }
    if arg.kind() != "ternary_expression" || spread.parent().is_none_or(|p| p.kind() != "array") {
        return false;
    }
    let (Some(a), Some(b)) = (
        arg.child_by_field_name("consequence"),
        arg.child_by_field_name("alternative"),
    ) else {
        return false;
    };
    let hollow = |n: Node| {
        matches!(n.kind(), "null" | "undefined" | "number" | "true" | "false")
            || (n.kind() == "identifier" && text(n, src) == b"undefined")
    };
    (a.kind() == "array" && hollow(b)) || (b.kind() == "array" && hollow(a))
}

fn flattens_by_hand(call: Node, src: &[u8]) -> bool {
    let Some(function) = call
        .child_by_field_name("function")
        .filter(|f| f.kind() == "member_expression")
    else {
        return false;
    };
    let Some(args) = call.child_by_field_name("arguments") else {
        return false;
    };
    let given = named(args);
    let method = function
        .child_by_field_name("property")
        .map_or(&b""[..], |p| text(p, src));
    match method {
        b"concat" => {
            function
                .child_by_field_name("object")
                .is_some_and(|o| o.kind() == "array" && o.named_child_count() == 0)
                && matches!(given.as_slice(), [only] if only.kind() == "spread_element")
        }
        b"reduce" => {
            let [reducer, init] = given.as_slice() else {
                return false;
            };
            init.kind() == "array"
                && init.named_child_count() == 0
                && reducer.kind() == "arrow_function"
                && reducer.child_by_field_name("body").is_some_and(|b| {
                    b.kind() == "call_expression"
                        && b.child_by_field_name("function")
                            .and_then(|f| f.child_by_field_name("property"))
                            .is_some_and(|p| text(p, src) == b"concat")
                })
        }
        _ => false,
    }
}

fn arrow_parameter<'a>(arrow: Node, src: &'a [u8]) -> Option<&'a [u8]> {
    if let Some(p) = arrow.child_by_field_name("parameter") {
        return Some(text(p, src));
    }
    let params = arrow.child_by_field_name("parameters")?;
    let items = named(params);
    match items.as_slice() {
        [only] if only.kind() == "identifier" => Some(text(*only, src)),
        _ => None,
    }
}

fn find_index_tests_equality(call: Node, src: &[u8]) -> bool {
    let Some(args) = call.child_by_field_name("arguments") else {
        return false;
    };
    let given = named(args);
    let [callback] = given.as_slice() else {
        return false;
    };
    if callback.kind() != "arrow_function" {
        return false;
    }
    let (Some(p), Some(body)) = (
        arrow_parameter(*callback, src),
        callback.child_by_field_name("body"),
    ) else {
        return false;
    };
    if body.kind() != "binary_expression" || operator_text(body, src) != b"===" {
        return false;
    }
    let (Some(l), Some(r)) = (
        body.child_by_field_name("left"),
        body.child_by_field_name("right"),
    ) else {
        return false;
    };
    (text(l, src) == p && count_word(text(r, src), p) == 0)
        || (text(r, src) == p && count_word(text(l, src), p) == 0)
}

fn constant_assigned_in_constructor<'t>(method: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    let body = method.child_by_field_name("body")?;
    // Only the statements at the very top count, as SonarQube does: once
    // something else has run, a field initializer is no longer equivalent.
    for s in named(body) {
        let literal_to_this = s.kind() == "expression_statement"
            && s.named_child(0).is_some_and(|a| {
                a.kind() == "assignment_expression"
                    && a.child_by_field_name("left").is_some_and(|l| {
                        l.kind() == "member_expression"
                            && l.child_by_field_name("object")
                                .is_some_and(|o| o.kind() == "this")
                    })
                    && a.child_by_field_name("right").is_some_and(|r| {
                        matches!(r.kind(), "number" | "string" | "true" | "false" | "null")
                    })
            });
        return literal_to_this.then_some(s);
    }
    None
}

fn import_exported_again<'t>(program: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut imported: Vec<&[u8]> = Vec::new();
    for statement in named(program) {
        if statement.kind() != "import_statement" {
            continue;
        }
        let mut stack = vec![statement];
        while let Some(n) = stack.pop() {
            match n.kind() {
                "import_specifier" => {
                    let local = n
                        .child_by_field_name("alias")
                        .or_else(|| n.child_by_field_name("name"));
                    imported.extend(local.map(|l| text(l, src)));
                }
                "namespace_import" => {}
                "import_statement" | "import_clause" => {
                    stack.extend(named(n));
                }
                "named_imports" => stack.extend(named(n)),
                "identifier" if n.parent().is_some_and(|p| p.kind() == "import_clause") => {
                    imported.push(text(n, src));
                }
                _ => {}
            }
        }
    }
    named(program).into_iter().find(|s| {
        s.kind() == "export_statement"
            && s.child_by_field_name("source").is_none()
            && named(*s).into_iter().any(|clause| {
                clause.kind() == "export_clause"
                    && named(clause).into_iter().any(|spec| {
                        spec.child_by_field_name("name")
                            .is_some_and(|n| imported.contains(&text(n, src)))
                    })
            })
    })
}

fn array_only_asks_includes(declarator: Node, src: &[u8]) -> bool {
    let (Some(name), Some(value)) = (
        declarator.child_by_field_name("name"),
        declarator.child_by_field_name("value"),
    ) else {
        return false;
    };
    if !is_const_declaration(declarator) {
        return false;
    }
    if value.kind() == "call_expression" {
        // An array built by a call: only the methods that return one.
        let builds_an_array = value
            .child_by_field_name("function")
            .and_then(|f| f.child_by_field_name("property"))
            .is_some_and(|p| matches!(text(p, src), b"map" | b"filter" | b"flatMap" | b"slice"));
        if !builds_an_array {
            return false;
        }
    } else {
        let items = named(value);
        if items.len() < 4
            || !items
                .iter()
                .all(|i| matches!(i.kind(), "string" | "number"))
        {
            return false;
        }
    }
    let n = text(name, src);
    let scope = scope_text(declarator, src);
    let asks = count_pattern(scope, &[n, b".includes("].concat());
    asks >= 1 && count_word(scope, n) == asks + 1
}

fn has_escaped_backslashes(string: Node, src: &[u8]) -> bool {
    if string.parent().is_some_and(|p| p.kind() == "jsx_attribute") {
        return false;
    }
    let body = string_content(string, src);
    let mut pairs = 0;
    let mut i = 0;
    while i < body.len() {
        if body[i] == b'\\' {
            if body.get(i + 1) == Some(&b'\\') {
                pairs += 1;
                i += 2;
                continue;
            }
            return false;
        }
        i += 1;
    }
    pairs >= 2
}

fn memoizes_many_parameters_without_resolver(call: Node, src: &[u8]) -> bool {
    let Some(args) = call.child_by_field_name("arguments") else {
        return false;
    };
    let given = named(args);
    let [function] = given.as_slice() else {
        return false;
    };
    let params = match function.kind() {
        "arrow_function" => function.child_by_field_name("parameters").map(named),
        "function_expression" | "function" => function.child_by_field_name("parameters").map(named),
        _ => None,
    };
    let _ = src;
    params.is_some_and(|p| p.len() >= 2)
}

fn statement_after_done<'t>(block: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let items = named(block);
    items.windows(2).find_map(|pair| {
        let is_done = pair[0].kind() == "expression_statement"
            && pair[0].named_child(0).is_some_and(|c| {
                c.kind() == "call_expression"
                    && c.child_by_field_name("function")
                        .is_some_and(|f| text(f, src) == b"done")
            });
        is_done.then_some(pair[1])
    })
}

const PLAIN_TAGS: &[&[u8]] = &[
    b"div", b"span", b"p", b"section", b"article", b"h1", b"h2", b"h3", b"h4", b"h5", b"h6", b"li",
    b"ul", b"ol", b"table", b"tr", b"td", b"th", b"header", b"footer", b"main", b"aside",
];

const INTERACTIVE_ROLES: &[&[u8]] = &[
    b"button",
    b"checkbox",
    b"link",
    b"menuitem",
    b"menuitemcheckbox",
    b"menuitemradio",
    b"option",
    b"radio",
    b"slider",
    b"spinbutton",
    b"switch",
    b"tab",
    b"textbox",
    b"combobox",
    b"searchbox",
    b"treeitem",
];

fn element_tag<'a>(attr: Node<'a>, src: &'a [u8]) -> Option<(Node<'a>, &'a [u8])> {
    let opening = attr.parent()?;
    tag_name(opening, src).map(|t| (opening, t))
}

fn handler_on_plain_element(attr: Node, src: &[u8]) -> bool {
    let Some((opening, tag)) = element_tag(attr, src) else {
        return false;
    };
    PLAIN_TAGS.contains(&tag)
        && !has_spread(opening)
        && attribute(opening, "role", src).is_none()
        && attribute(opening, "tabIndex", src).is_none()
}

fn interactive_role_on_semantic_element(attr: Node, src: &[u8]) -> bool {
    let Some((_, tag)) = element_tag(attr, src) else {
        return false;
    };
    let semantic = matches!(
        tag,
        b"h1"
            | b"h2"
            | b"h3"
            | b"h4"
            | b"h5"
            | b"h6"
            | b"p"
            | b"ul"
            | b"ol"
            | b"li"
            | b"table"
            | b"tr"
            | b"td"
            | b"th"
            | b"img"
            | b"article"
            | b"section"
            | b"main"
            | b"aside"
            | b"blockquote"
            | b"figure"
    );
    semantic && static_value(attr, src).is_some_and(|r| INTERACTIVE_ROLES.contains(&r))
}

fn static_role_on_interactive_element(attr: Node, src: &[u8]) -> bool {
    let Some((opening, tag)) = element_tag(attr, src) else {
        return false;
    };
    let interactive = matches!(tag, b"button" | b"select" | b"textarea" | b"input")
        || (tag == b"a" && attribute(opening, "href", src).is_some());
    interactive
        && static_value(attr, src).is_some_and(|r| {
            matches!(
                r,
                b"article"
                    | b"banner"
                    | b"complementary"
                    | b"contentinfo"
                    | b"definition"
                    | b"directory"
                    | b"document"
                    | b"feed"
                    | b"figure"
                    | b"heading"
                    | b"img"
                    | b"list"
                    | b"listitem"
                    | b"main"
                    | b"math"
                    | b"navigation"
                    | b"note"
                    | b"region"
                    | b"status"
                    | b"table"
                    | b"term"
            )
        })
}

fn role_lacks_required_properties(attr: Node, src: &[u8]) -> bool {
    let Some((opening, tag)) = element_tag(attr, src) else {
        return false;
    };
    if !PLAIN_TAGS.contains(&tag) || has_spread(opening) {
        return false;
    }
    let required: &[&str] = match static_value(attr, src) {
        Some(b"checkbox" | b"radio" | b"switch" | b"menuitemcheckbox" | b"menuitemradio") => {
            &["aria-checked"]
        }
        Some(b"slider" | b"spinbutton") => &["aria-valuenow"],
        Some(b"scrollbar") => &["aria-controls", "aria-valuenow"],
        Some(b"combobox") => &["aria-expanded", "aria-controls"],
        Some(b"heading") => &["aria-level"],
        Some(b"option") => &["aria-selected"],
        _ => return false,
    };
    required
        .iter()
        .any(|a| attribute(opening, a, src).is_none())
}

fn label_has_no_control(element: Node, src: &[u8]) -> bool {
    let Some(opening) = opening_tag(element) else {
        return false;
    };
    if has_spread(opening)
        || attribute(opening, "htmlFor", src).is_some()
        || attribute(opening, "for", src).is_some()
    {
        return false;
    }
    // Anything that could render a control counts as having one.
    !collect_below(element, |n| {
        n.kind() == "jsx_expression" && n.parent().is_some_and(|p| p.kind() == "jsx_element")
            || matches!(n.kind(), "jsx_self_closing_element" | "jsx_opening_element")
                && tag_name(n, src).is_some_and(|t| {
                    matches!(t, b"input" | b"select" | b"textarea")
                        || t.first().is_some_and(u8::is_ascii_uppercase)
                })
    })
    .iter()
    .any(|_| true)
}

// ---- TypeScript

fn public_static_is_mutable(field: Node, src: &[u8]) -> bool {
    if !has_token(field, "static") || has_token(field, "readonly") {
        return false;
    }
    let mut cursor = field.walk();
    let private = field.children(&mut cursor).any(|c| {
        c.kind() == "accessibility_modifier" && matches!(text(c, src), b"private" | b"protected")
    });
    !private
        && field
            .child_by_field_name("name")
            .is_some_and(|n| n.kind() == "property_identifier")
}

fn has_repeated_member(union: Node, src: &[u8]) -> bool {
    // `a | b | c` nests as `(a | b) | c`; look across the whole chain.
    if union.parent().is_some_and(|p| p.kind() == union.kind()) {
        return false;
    }
    let mut seen: Vec<&[u8]> = Vec::new();
    let mut stack = vec![union];
    while let Some(n) = stack.pop() {
        for member in named(n).into_iter().rev() {
            if member.kind() == union.kind() {
                stack.push(member);
                continue;
            }
            let t = text(member, src);
            if seen.contains(&t) {
                return true;
            }
            seen.push(t);
        }
    }
    false
}

fn initializer_is_not_a_literal(assignment: Node, src: &[u8]) -> bool {
    assignment
        .child_by_field_name("value")
        .is_some_and(|v| match v.kind() {
            "number" | "string" => false,
            "unary_expression" => !v.named_child(0).is_some_and(|n| n.kind() == "number"),
            "template_string" => {
                find_below(v, true, |n| n.kind() == "template_substitution").is_some()
            }
            _ => {
                let _ = src;
                true
            }
        })
}

fn non_null_before_nullish_check(non_null: Node, src: &[u8]) -> bool {
    let Some(parent) = non_null.parent() else {
        return false;
    };
    match parent.kind() {
        "binary_expression" => {
            operator_text(parent, src) == b"??"
                && parent.child_by_field_name("left") == Some(non_null)
        }
        "member_expression" => {
            parent.child_by_field_name("object") == Some(non_null) && has_token(parent, "?.")
        }
        _ => false,
    }
}

fn constraint_is_any_or_unknown(param: Node, src: &[u8]) -> bool {
    named(param).into_iter().any(|c| {
        c.kind() == "constraint"
            && matches!(
                text(c, src)
                    .strip_prefix(b"extends")
                    .map(<[u8]>::trim_ascii),
                Some(b"any" | b"unknown")
            )
    })
}

fn some_members_initialized(body: Node, _: &[u8]) -> bool {
    let members = named(body);
    let initialized = members
        .iter()
        .filter(|m| m.kind() == "enum_assignment")
        .count();
    initialized > 0 && initialized < members.len()
}

fn repeated_enum_value<'t>(body: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut seen: Vec<&[u8]> = Vec::new();
    for member in named(body) {
        if member.kind() != "enum_assignment" {
            continue;
        }
        let Some(value) = member
            .child_by_field_name("value")
            .filter(|v| matches!(v.kind(), "number" | "string"))
        else {
            continue;
        };
        let t = text(value, src);
        if seen.contains(&t) {
            return Some(member);
        }
        seen.push(t);
    }
    None
}

fn interface_is_only_a_call_signature(interface: Node, _: &[u8]) -> bool {
    let has_heritage = {
        let mut c = interface.walk();
        interface
            .children(&mut c)
            .any(|k| k.kind() == "extends_type_clause")
    };
    !has_heritage
        && interface.child_by_field_name("body").is_some_and(
            |b| matches!(named(b).as_slice(), [only] if only.kind() == "call_signature"),
        )
}

fn method_body_is_empty(method: Node, _: &[u8]) -> bool {
    method
        .child_by_field_name("body")
        .is_some_and(|b| b.named_child_count() == 0)
}

fn angular_class(method: Node) -> Option<Node> {
    method
        .parent()
        .and_then(|b| b.parent())
        .filter(|c| c.kind() == "class_declaration")
}

fn decorators_of<'a>(class: Node, src: &'a [u8]) -> Vec<&'a [u8]> {
    let mut cursor = class.walk();
    class
        .children(&mut cursor)
        .filter(|c| c.kind() == "decorator")
        .map(|d| text(d, src))
        .collect()
}

fn heritage_text<'a>(class: Node, src: &'a [u8]) -> &'a [u8] {
    let mut cursor = class.walk();
    class
        .children(&mut cursor)
        .find(|c| c.kind() == "class_heritage")
        .map_or(&b""[..], |h| text(h, src))
}

fn hook_without_interface(method: Node, src: &[u8]) -> bool {
    let Some(class) = angular_class(method) else {
        return false;
    };
    let is_angular = decorators_of(class, src).iter().any(|d| {
        [
            &b"@Component"[..],
            b"@Directive",
            b"@Injectable",
            b"@Pipe",
            b"@NgModule",
        ]
        .iter()
        .any(|n| d.starts_with(n))
    });
    let Some(name) = method.child_by_field_name("name") else {
        return false;
    };
    let interface = &text(name, src)[2..];
    is_angular && count_word(heritage_text(class, src), interface) == 0
}

fn pipe_lacks_pipe_transform(class: Node, src: &[u8]) -> bool {
    decorators_of(class, src)
        .iter()
        .any(|d| d.starts_with(b"@Pipe"))
        && count_word(heritage_text(class, src), b"PipeTransform") == 0
}

fn output_has_a_dom_event_name(field: Node, src: &[u8]) -> bool {
    let Some(name) = field.child_by_field_name("name").map(|n| text(n, src)) else {
        return false;
    };
    matches!(
        name,
        b"click"
            | b"dblclick"
            | b"change"
            | b"input"
            | b"blur"
            | b"focus"
            | b"submit"
            | b"keydown"
            | b"keyup"
            | b"keypress"
            | b"mouseover"
            | b"mouseout"
            | b"mousedown"
            | b"mouseup"
            | b"scroll"
            | b"resize"
            | b"load"
            | b"error"
            | b"select"
            | b"reset"
            | b"drop"
            | b"drag"
    ) || name == b"on"
        || (name.len() > 2 && name.starts_with(b"on") && name[2].is_ascii_uppercase())
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
    fn calls_and_constructors() {
        let src = "function f(a, b) { return a; }\nfunction g(...r) { return r; }\nfunction h() { return arguments; }\nf(1, 2);\nf(1, 2, 3);\ng(1, 2, 3);\nh(1, 2);\nfoo(1, 2);\nfunction Foo() {}\nconst a = new Foo();\nconst b = Foo();\nconst c = String(1);\nconst d = new Date();";
        assert_eq!(flagged("js/extra-arguments", JS, src), [5]);
        assert_eq!(flagged("js/inconsistent-new", JS, src), [11]);
    }

    #[test]
    fn loops_and_collections() {
        let src = "for (let i = 0; i < items.length; i++) { use(items[i]); }\nfor (let i = 0; i < items.length; i++) { use(items[i], i); }\nfor (let i = 0; i < items.length; i++) { items[i] = 1; }\nfunction f() { const a = []; a.forEach(use); }\nfunction g() { const a = []; a.push(1); a.forEach(use); }\nconst allowed = ['a', 'b', 'c', 'd'];\nfunction ok(x) { return allowed.includes(x); }\nconst other = ['a', 'b', 'c', 'd'];\nfunction no(x) { return other.includes(x) || other.length; }";
        assert_eq!(flagged("js/for-to-for-of", JS, src), [1]);
        assert_eq!(flagged("js/empty-collection-read", JS, src), [4]);
        assert_eq!(flagged("js/array-for-existence", JS, src), [6]);
    }

    #[test]
    fn expressions() {
        let src = "const a = typeof obj.value === 'undefined';\nconst b = typeof value === 'undefined';\nconst c = [...[1, 2]];\nconst d = { ...{ a: 1 } };\nconst e = [...list];\nconst f = [...(x ? [1] : undefined)];\nconst g = [...(x ? [1] : [])];\nconst h = [].concat(...lists);\nconst i = lists.reduce((a, b) => a.concat(b), []);\nconst j = list.findIndex(x => x === v);\nconst k = list.findIndex(x => x.id === v);\nconst l = new FileReader();\nconst m = 'a\\\\b\\\\c';\nconst n = 'a\\nb';\nconst o = _.map(list, fn);\nconst p = _.memoize((a, b) => a);\nconst q = _.memoize((a) => a);";
        assert_eq!(flagged("js/typeof-undefined", JS, src), [1]);
        assert_eq!(flagged("js/unnecessary-spread", JS, src), [3, 4]);
        assert_eq!(flagged("js/ternary-in-array-spread", JS, src), [6]);
        assert_eq!(flagged("js/manual-flatten", JS, src), [8, 9]);
        assert_eq!(flagged("js/find-index-to-index-of", JS, src), [10]);
        assert_eq!(flagged("js/file-reader", JS, src), [12]);
        assert_eq!(flagged("js/escaped-backslashes", JS, src), [13]);
        assert_eq!(flagged("js/lodash-native", JS, src), [15]);
        assert_eq!(flagged("js/memoize-without-resolver", JS, src), [16]);
    }

    #[test]
    fn statements() {
        let src = "a: { f(); }\nb: for (;;) { break b; }\nif (x) { f(); g(); } else if (y) { f(); g(); }\nif (x) { f(); } else if (y) { f(); }\nit('a', (done) => { done(); cleanup(); });\nit('b', (done) => { cleanup(); done(); });\nclass A { constructor() { this.count = 0; this.name = make(); } }\nclass B { count = 0; }";
        assert_eq!(flagged("js/label-on-non-loop", JS, src), [1]);
        assert_eq!(flagged("js/identical-branch-bodies", JS, src), [3]);
        assert_eq!(flagged("js/code-after-done", JS, src), [5]);
        assert_eq!(flagged("js/constructor-field-assignment", JS, src), [7]);
    }

    #[test]
    fn imports() {
        let src = "import { a } from 'm';\nimport { default as x } from 'n';\nimport y from 'o';\nexport { a };\nexport { z };\nexport { w as default };";
        assert_eq!(flagged("js/default-as-named-import", JS, src), [2, 6]);
        assert_eq!(flagged("js/reexport-by-hand", JS, src), [4]);
    }

    #[test]
    fn jsx_roles_and_handlers() {
        let src = "const a = <div onClick={go}>x</div>;\nconst b = <div onClick={go} role=\"button\" tabIndex={0}>x</div>;\nconst c = <button onClick={go}>x</button>;\nconst d = <h1 role=\"button\">x</h1>;\nconst e = <button role=\"heading\">x</button>;\nconst f = <div role=\"checkbox\" tabIndex={0} />;\nconst g = <div role=\"checkbox\" aria-checked={on} tabIndex={0} />;\nconst h = <label>Name</label>;\nconst i = <label htmlFor=\"n\">Name</label>;\nconst j = <label>Name <input /></label>;";
        assert_eq!(flagged("js/handler-on-plain-element", Lang::Tsx, src), [1]);
        assert_eq!(
            flagged("js/interactive-role-on-static-element", Lang::Tsx, src),
            [4]
        );
        assert_eq!(
            flagged("js/static-role-on-interactive-element", Lang::Tsx, src),
            [5]
        );
        assert_eq!(
            flagged("js/role-missing-required-props", Lang::Tsx, src),
            [6]
        );
        assert_eq!(flagged("js/label-without-control", Lang::Tsx, src), [8]);
    }

    #[test]
    fn typescript_types() {
        let src = "class A { public static count = 0; public static readonly ok = 1; private static hidden = 2; }\nmodule Foo { export const a = 1; }\nnamespace Bar { export const a = 1; }\ntype U = string | number | string;\ntype V = string | number;\nenum E1 { A = foo(), B = 2 }\nenum E2 { A = 1, B, C = 3 }\nenum E3 { A = 1, B = 1 }\nenum E4 { A = 1, B = 2 }\ntype Name = string;\ntype Tagged = string & { brand: 1 };\nconst v = a! ?? b;\nconst w = a ?? b;\nfunction f<T extends unknown>(x: T) {}\nfunction g<T extends object>(x: T) {}\ninterface F { (x: number): string; }\ninterface G { (x: number): string; name: string; }\ninterface I { constructor(x: number): void; }";
        assert_eq!(flagged("ts/readonly-public-static", TS, src), [1]);
        assert_eq!(flagged("ts/module-keyword", TS, src), [2]);
        assert_eq!(flagged("ts/duplicate-union-member", TS, src), [4]);
        assert_eq!(flagged("ts/enum-member-literal", TS, src), [6]);
        assert_eq!(flagged("ts/enum-partial-initialization", TS, src), [7]);
        assert_eq!(flagged("ts/enum-duplicate-value", TS, src), [8]);
        assert_eq!(flagged("ts/redundant-type-alias", TS, src), [10]);
        assert_eq!(flagged("ts/misleading-non-null", TS, src), [12]);
        assert_eq!(flagged("ts/unnecessary-type-constraint", TS, src), [14]);
        assert_eq!(flagged("ts/call-signature-interface", TS, src), [16]);
        assert_eq!(flagged("ts/constructor-in-interface", TS, src), [18]);
    }

    #[test]
    fn angular() {
        let src = "@Component({ inputs: ['a'] }) class C { ngOnInit() {} ngOnDestroy() { this.stop(); } }\n@Component({}) class D implements OnInit { ngOnInit() { this.x(); } }\n@Component({}) class E { ngOnInit() { this.x(); } }\nclass NotAngular { ngOnInit() { this.x(); } }\n@Pipe({ name: 'p' }) class P { transform(v: string) { return v; } }\n@Pipe({ name: 'q' }) class Q implements PipeTransform { transform(v: string) { return v; } }\nclass F { @Input('alias') name = ''; @Input() ok = ''; @Output() click = new EventEmitter(); @Output() onSave = new EventEmitter(); @Output() saved = new EventEmitter(); }";
        assert_eq!(flagged("ts/empty-lifecycle-method", TS, src), [1]);
        assert_eq!(flagged("ts/lifecycle-interface", TS, src), [1, 1, 3]);
        assert_eq!(flagged("ts/pipe-transform", TS, src), [5]);
        assert_eq!(flagged("ts/aliased-binding", TS, src), [7]);
        assert_eq!(flagged("ts/metadata-bindings", TS, src), [1]);
        assert_eq!(flagged("ts/output-named-like-dom-event", TS, src), [7, 7]);
    }
}
