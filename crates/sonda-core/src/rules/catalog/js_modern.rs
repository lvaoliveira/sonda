//! JavaScript and TypeScript rules for modern idioms, deprecated or
//! error-prone constructs and style (ADR-0007, batch 2).
//!
//! Keep queries cheap on deep trees (`large_and_deep_code_stays_fast` guards
//! this). Two things made rules quadratic here:
//! - a pattern that constrains a field after `left` on `binary_expression`
//!   (such as `operator:`) keeps a pending match at every level of a chain like
//!   `1 + 1 + ...`; match the node and test the operator in the filter;
//! - a sibling anchor (`(a) . (b)`) keeps one pending match per open parent;
//!   scan the parent's children in a `Find` filter instead.
//!
//! `Node::parent()` and sibling lookups cost the node's depth, so filters on
//! frequent nodes should not call them in a loop.

use super::js::{find_below, has_token, string_content, text};
use super::*;

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "js/comma-operator",
        name: "The comma operator should not be used",
        description: "A comma expression hides that several things happen in one statement; separate statements say it plainly.",
        message: "Split this into separate statements.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[related("S878")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(sequence_expression) @match"#,
            filter: Some(Keep(comma_outside_for_clause)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const x = (f(), g());",
            good: "f();\nconst x = g();\nfor (let i = 0, j = 9; i < j; i++, j--) {}",
        }),
    },
    Rule {
        id: "js/lowercase-constructor",
        name: "Constructor names should start with an upper case letter",
        description: "Capitalized names tell readers a function is meant to be called with `new`.",
        message: "Rename this constructor so it starts with an upper case letter.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S2430")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(new_expression constructor: (identifier) @c (#match? @c "^[a-z]")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const a = new widget();",
            good: "const a = new Widget();",
        }),
    },
    Rule {
        id: "js/global-this",
        name: "The global \"this\" object should not be used",
        description: "Outside a function or class, `this` is the global object or `module.exports` depending on the module system, which is rarely what the code means.",
        message: "Use globalThis, or move this into a function.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S2990")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(this) @match"#,
            filter: Some(Keep(this_at_top_level)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "this.config = {};",
            good: "function f() { return this.config; }",
        }),
    },
    Rule {
        id: "js/nested-template",
        name: "Template literals should not be nested",
        description: "A template inside a template's placeholder is hard to read; name the inner one first.",
        message: "Extract this nested template literal into a variable.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S4624")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(template_string) @match"#,
            filter: Some(Keep(directly_in_template_substitution)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const s = `a ${`b ${c}`}`;",
            good: "const inner = `b ${c}`;\nconst s = `a ${inner}`;",
        }),
    },
    Rule {
        id: "js/promise-shorthand",
        name: "Shorthand promises should be used",
        description: "Wrapping one resolve or reject call in `new Promise` is what Promise.resolve and Promise.reject are for.",
        message: "Use Promise.resolve() or Promise.reject() instead.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S4634")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(new_expression constructor: (identifier) @c (#eq? @c "Promise")) @match"#,
            filter: Some(Keep(promise_wraps_one_call)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const p = new Promise(resolve => resolve(1));",
            good: "const p = Promise.resolve(1);",
        }),
    },
    Rule {
        id: "js/redundant-boolean-cast",
        name: "Extra boolean casts should be removed",
        description: "In a condition the value is already treated as a boolean, so `!!x` and `Boolean(x)` add nothing.",
        message: "Remove this redundant boolean cast.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6509")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(unary_expression operator: "!" argument: (unary_expression operator: "!")) @match
(call_expression function: (identifier) @f (#eq? @f "Boolean")) @match"#,
            filter: Some(Keep(cast_in_boolean_context)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (!!ready) { run(); }",
            good: "if (ready) { run(); }\nconst flag = !!ready;",
        }),
    },
    Rule {
        id: "js/constructor-return",
        name: "Constructors should not return values",
        description: "A value returned from a constructor replaces the new object, which surprises callers.",
        message: "Remove this return value from the constructor.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S6635")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(method_definition name: (property_identifier) @n (#eq? @n "constructor")) @match"#,
            filter: Some(Find(constructor_return_value)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "class A { constructor() { return {}; } }",
            good: "class A { constructor() { this.x = 1; } }",
        }),
    },
    Rule {
        id: "js/unneeded-bind",
        name: "Unnecessary calls to .bind() should not be used",
        description: "Arrow functions ignore bind, and a function that never uses `this` doesn't need it.",
        message: "Remove this .bind() call.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6637")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression object: (_) @o property: (property_identifier) @p (#eq? @p "bind"))) @match"#,
            filter: Some(Keep(bind_changes_nothing)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const f = (() => 1).bind(this);",
            good: "const f = (function () { return this.x; }).bind(obj);",
        }),
    },
    Rule {
        id: "js/builtin-prototype-modified",
        name: "Prototypes of builtin objects should not be modified",
        description: "Adding to Array.prototype and friends changes every script that shares the runtime, and can clash with future language features.",
        message: "Use a standalone function instead of extending this builtin.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 15,
        sonar: &[exact("S6643")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(assignment_expression left: (member_expression object: (member_expression object: (identifier) @o property: (property_identifier) @p (#eq? @p "prototype") (#any-of? @o "Object" "Array" "String" "Number" "Boolean" "Function" "Date" "RegExp" "Error" "Promise" "Map" "Set" "Symbol")))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "Array.prototype.last = function () { return this[this.length - 1]; };",
            good: "const last = (a) => a[a.length - 1];",
        }),
    },
    Rule {
        id: "js/ternary-simplifiable",
        name: "Ternary operators should not be used instead of simpler alternatives",
        description: "`a ? a : b` is `a || b`, and `c ? true : false` is the condition itself.",
        message: "Replace this ternary with a simpler expression.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6644")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(ternary_expression) @match"#,
            filter: Some(Keep(ternary_has_simpler_form)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const v = a ? a : b;",
            good: "const v = a || b;",
        }),
    },
    Rule {
        id: "js/useless-constructor",
        name: "Unnecessary constructors should be removed",
        description: "An empty constructor, or one that only forwards its arguments to super, is what the language does anyway.",
        message: "Remove this constructor.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6647")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(method_definition name: (property_identifier) @n (#eq? @n "constructor")) @match"#,
            filter: Some(Keep(constructor_does_nothing)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "class A { constructor() {} }",
            good: "class A { constructor() { this.x = 1; } }",
        }),
    },
    Rule {
        id: "js/has-own-property",
        name: "Object.hasOwn should be used instead of hasOwnProperty",
        description: "hasOwnProperty can be shadowed or missing on objects without a prototype; Object.hasOwn cannot.",
        message: "Use Object.hasOwn(obj, key).",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6653")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression property: (property_identifier) @p (#eq? @p "hasOwnProperty"))) @match
(call_expression function: (member_expression object: (member_expression property: (property_identifier) @q (#eq? @q "hasOwnProperty")) property: (property_identifier) @c (#eq? @c "call"))) @match"#,
            filter: Some(Keep(has_own_property_call)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (obj.hasOwnProperty(key)) {}",
            good: "if (Object.hasOwn(obj, key)) {}",
        }),
    },
    Rule {
        id: "js/object-assign-spread",
        name: "Object spread should be used instead of Object.assign",
        description: "`{ ...a, ...b }` says the same as `Object.assign({}, a, b)` and reads better.",
        message: "Use object spread instead of Object.assign.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6661")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression object: (identifier) @o property: (property_identifier) @p (#eq? @o "Object") (#eq? @p "assign")) arguments: (arguments . (object))) @match"#,
            filter: Some(Keep(assign_into_new_object)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const c = Object.assign({}, a, b);",
            good: "const c = { ...a, ...b };",
        }),
    },
    Rule {
        id: "js/apply-spread",
        name: "Spread syntax should be used instead of apply()",
        description: "`fn(...args)` replaces `fn.apply(null, args)`.",
        message: "Use spread syntax instead of apply().",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6666")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression property: (property_identifier) @p (#eq? @p "apply"))) @match"#,
            filter: Some(Keep(apply_could_spread)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "Math.max.apply(Math, nums);",
            good: "Math.max(...nums);",
        }),
    },
    Rule {
        id: "js/redundant-call-apply",
        name: "Calls to .call() and .apply() should not be redundant",
        description: "Calling a plain function with `undefined` or `null` as `this` is the same as calling it directly.",
        message: "Call the function directly.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6676")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression object: (identifier) property: (property_identifier) @p (#any-of? @p "call" "apply"))) @match"#,
            filter: Some(Keep(call_with_nothing_as_this)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "greet.call(undefined, 'a');",
            good: "greet('a');",
        }),
    },
    Rule {
        id: "js/date-clone",
        name: "Date objects should be cloned directly",
        description: "`new Date(date)` copies a date without the round trip through getTime().",
        message: "Pass the date itself to the Date constructor.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7719")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(new_expression constructor: (identifier) @c (#eq? @c "Date") arguments: (arguments (call_expression function: (member_expression property: (property_identifier) @p (#eq? @p "getTime"))))) @match"#,
            filter: Some(Keep(clones_through_get_time)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const d2 = new Date(d.getTime());",
            good: "const d2 = new Date(d);",
        }),
    },
    Rule {
        id: "js/error-without-message",
        name: "Built-in error objects should have meaningful messages",
        description: "An error with no message gives whoever reads the log nothing to go on.",
        message: "Give this error a message that says what went wrong.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S7722")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(new_expression constructor: (identifier) @c (#match? @c "^(Error|TypeError|RangeError|SyntaxError|ReferenceError|EvalError|URIError)$")) @match
(call_expression function: (identifier) @c (#match? @c "^(Error|TypeError|RangeError|SyntaxError|ReferenceError|EvalError|URIError)$")) @match"#,
            filter: Some(Keep(error_has_no_message)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "throw new Error();",
            good: "throw new Error('Cannot parse input');",
        }),
    },
    Rule {
        id: "js/builtin-new-consistency",
        name: "Built-in constructors should be called with new",
        description: "Collections, errors and typed arrays are constructors; calling them without `new` is inconsistent and fails for some.",
        message: "Add 'new' before this constructor call.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7723")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (identifier) @f (#any-of? @f "Array" "ArrayBuffer" "Map" "Set" "WeakMap" "WeakSet" "WeakRef" "Promise" "Proxy" "DataView" "Error" "TypeError" "RangeError" "SyntaxError" "ReferenceError" "EvalError" "URIError" "RegExp" "Int8Array" "Uint8Array" "Uint8ClampedArray" "Int16Array" "Uint16Array" "Int32Array" "Uint32Array" "Float32Array" "Float64Array" "BigInt64Array" "BigUint64Array")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const s = Set([1]);",
            good: "const s = new Set([1]);",
        }),
    },
    Rule {
        id: "js/anonymous-default-export",
        name: "Default exports should be named",
        description: "An anonymous default export has no name in stack traces, search results or auto-imports.",
        message: "Give this default export a name.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7726")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(export_statement) @match"#,
            filter: Some(Keep(anonymous_default_export)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "export default function () {}",
            good: "export default function render() {}",
        }),
    },
    Rule {
        id: "js/instanceof-builtin",
        name: "instanceof should not be used with built-in objects",
        description: "`instanceof` fails across frames and for primitives; dedicated checks such as Array.isArray don't.",
        message: "Use a dedicated check instead of instanceof here.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7732")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(binary_expression) @match"#,
            filter: Some(Keep(instanceof_builtin)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (x instanceof Array) {}",
            good: "if (Array.isArray(x)) {}",
        }),
    },
    Rule {
        id: "js/promise-single-element",
        name: "Single-element arrays should not be passed to Promise methods",
        description: "Promise.all([p]) is just `p` with extra steps.",
        message: "Use the promise directly.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7738")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression object: (identifier) @o property: (property_identifier) @p (#eq? @o "Promise") (#any-of? @p "all" "allSettled" "any" "race")) arguments: (arguments . (array) @a)) @match"#,
            filter: Some(Keep(array_has_one_element)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "async function f() { await Promise.all([load()]); }",
            good: "async function f() { await load(); }",
        }),
    },
    Rule {
        id: "js/this-alias",
        name: "Variables should not be assigned the value of \"this\"",
        description: "Aliases like `self` and `that` exist for callbacks; arrow functions keep `this` already.",
        message: "Use an arrow function instead of aliasing this.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7740"), exact("S4327")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(variable_declarator name: (identifier) value: (this)) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const self = this;",
            good: "const run = () => this.go();",
        }),
    },
    Rule {
        id: "js/spread-fallback",
        name: "Unnecessary fallback objects should not be used when spreading",
        description: "Spreading `undefined` or `null` into an object adds nothing, so `a || {}` is not needed.",
        message: "Spread the value directly.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7744")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(spread_element) @match"#,
            filter: Some(Keep(spreads_fallback_object)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const o = { ...(a || {}) };",
            good: "const o = { ...a };",
        }),
    },
    Rule {
        id: "js/length-check-before-some",
        name: "Array length checks should not be used before some() and every()",
        description: "`some` is false and `every` is true for an empty array, so the length check is redundant.",
        message: "Remove the length check.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7745")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(binary_expression left: (binary_expression left: (member_expression property: (property_identifier) @l (#eq? @l "length"))) right: (call_expression function: (member_expression property: (property_identifier) @m (#any-of? @m "some" "every")))) @match"#,
            filter: Some(Keep(length_check_is_redundant)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (items.length > 0 && items.some(isOk)) {}",
            good: "if (items.some(isOk)) {}",
        }),
    },
    Rule {
        id: "js/promise-resolve-in-async",
        name: "Promise.resolve() and Promise.reject() should not be used in async functions",
        description: "An async function already wraps its return value in a promise, and throwing rejects it.",
        message: "Return the value, or throw, instead.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S7746")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(return_statement (call_expression function: (member_expression object: (identifier) @o property: (property_identifier) @p (#eq? @o "Promise") (#any-of? @p "resolve" "reject")))) @match"#,
            filter: Some(Keep(in_async_function)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "async function f() { return Promise.resolve(1); }",
            good: "async function f() { return 1; }",
        }),
    },
    Rule {
        id: "js/filter-then-first",
        name: "find() should be preferred over filter()[0]",
        description: "filter walks the whole array and builds a new one just to take its first element.",
        message: "Use find() instead.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7750")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(subscript_expression object: (call_expression function: (member_expression property: (property_identifier) @p (#eq? @p "filter"))) index: (number) @n (#eq? @n "0")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const first = items.filter(isOk)[0];",
            good: "const first = items.find(isOk);",
        }),
    },
    Rule {
        id: "js/map-then-flat",
        name: "flatMap() should be used instead of map().flat()",
        description: "flatMap does both in one pass.",
        message: "Use flatMap() instead of map().flat().",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7752")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression object: (call_expression function: (member_expression property: (property_identifier) @m (#eq? @m "map"))) property: (property_identifier) @f (#eq? @f "flat"))) @match"#,
            filter: Some(Keep(flat_one_level)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const all = lists.map(toItems).flat();",
            good: "const all = lists.flatMap(toItems);",
        }),
    },
    Rule {
        id: "js/filter-length-check",
        name: "some() should be used instead of filter().length checks",
        description: "some stops at the first match; filter builds a whole array to count it.",
        message: "Use some() to test for existence.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7754")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(binary_expression left: (member_expression object: (call_expression function: (member_expression property: (property_identifier) @m (#eq? @m "filter"))) property: (property_identifier) @l (#eq? @l "length"))) @match"#,
            filter: Some(Keep(checks_filter_for_any)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (items.filter(isOk).length > 0) {}",
            good: "if (items.some(isOk)) {}",
        }),
    },
    Rule {
        id: "js/code-unit-methods",
        name: "Unicode-aware string methods should be used",
        description: "charCodeAt and fromCharCode work on UTF-16 halves, so characters outside the basic plane break.",
        message: "Use codePointAt() or fromCodePoint().",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7758")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression property: (property_identifier) @p (#eq? @p "charCodeAt"))) @match
(call_expression function: (member_expression object: (identifier) @o property: (property_identifier) @q (#eq? @o "String") (#eq? @q "fromCharCode"))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const c = s.charCodeAt(0);",
            good: "const c = s.codePointAt(0);",
        }),
    },
    Rule {
        id: "js/date-now",
        name: "Date.now() should be used to get the current timestamp",
        description: "`new Date().getTime()` builds a throwaway object.",
        message: "Use Date.now().",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7759")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression object: (new_expression constructor: (identifier) @c (#eq? @c "Date")) property: (property_identifier) @p (#any-of? @p "getTime" "valueOf"))) @match
(unary_expression operator: "+" argument: (new_expression constructor: (identifier) @c (#eq? @c "Date"))) @match"#,
            filter: Some(Keep(date_without_arguments)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const t = new Date().getTime();",
            good: "const t = Date.now();",
        }),
    },
    Rule {
        id: "js/data-attribute-dataset",
        name: "Data attributes should be accessed with .dataset",
        description: "`el.dataset.id` is shorter than `getAttribute('data-id')` and keeps the naming in one place.",
        message: "Use the dataset property.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S7761")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression property: (property_identifier) @p (#any-of? @p "getAttribute" "setAttribute" "hasAttribute" "removeAttribute")) arguments: (arguments . (string) @a (#match? @a "^['\"]data-"))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "el.getAttribute('data-id');",
            good: "el.dataset.id;",
        }),
    },
    Rule {
        id: "js/remove-child",
        name: "DOM nodes should be removed with remove()",
        description: "`node.remove()` needs no reference to the parent.",
        message: "Use remove() instead of removeChild().",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S7762")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression property: (property_identifier) @p (#eq? @p "removeChild"))) @match"#,
            filter: Some(Keep(one_argument)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "parent.removeChild(child);",
            good: "child.remove();",
        }),
    },
    Rule {
        id: "js/index-of-existence",
        name: "includes() should be used for existence checks",
        description: "`includes` states the question directly, where `indexOf(x) !== -1` states how it is answered.",
        message: "Use includes() instead of indexOf().",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7765")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(binary_expression left: (call_expression function: (member_expression property: (property_identifier) @p (#any-of? @p "indexOf" "lastIndexOf")))) @match"#,
            filter: Some(Keep(compares_index_for_existence)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (list.indexOf(x) !== -1) {}",
            good: "if (list.includes(x)) {}",
        }),
    },
    Rule {
        id: "js/math-min-max-ternary",
        name: "Math.min() and Math.max() should replace simple comparisons",
        description: "`a > b ? a : b` is `Math.max(a, b)`.",
        message: "Use Math.min() or Math.max().",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7766")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(ternary_expression) @match"#,
            filter: Some(Keep(ternary_picks_min_or_max)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const m = a > b ? a : b;",
            good: "const m = Math.max(a, b);",
        }),
    },
    Rule {
        id: "js/bitwise-truncation",
        name: "Bitwise operators should not be used to truncate numbers",
        description: "`x | 0` and `~~x` rely on a side effect of 32-bit conversion and wrap around for large numbers.",
        message: "Use Math.trunc().",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S7767")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(binary_expression) @match
(unary_expression operator: "~" argument: (unary_expression operator: "~")) @match"#,
            filter: Some(Keep(truncates_to_integer)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const i = x | 0;",
            good: "const i = Math.trunc(x);",
        }),
    },
    Rule {
        id: "js/legacy-dom-insert",
        name: "Modern DOM manipulation methods should be used",
        description: "append, before and replaceWith accept several nodes and strings, and need no reference node.",
        message: "Use append(), before() or replaceWith().",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S7768")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression property: (property_identifier) @p (#any-of? @p "appendChild" "insertBefore" "replaceChild" "insertAdjacentElement" "insertAdjacentText"))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "parent.appendChild(child);",
            good: "parent.append(child);",
        }),
    },
    Rule {
        id: "js/legacy-math",
        name: "Modern Math APIs should be used",
        description: "Math.log10, Math.log2 and Math.hypot are exact where the manual formula loses precision.",
        message: "Use the dedicated Math function.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7769")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(binary_expression left: (call_expression function: (member_expression object: (identifier) @o property: (property_identifier) @p (#eq? @o "Math") (#eq? @p "log"))) operator: "/" right: (member_expression object: (identifier) @o2 property: (property_identifier) @c (#eq? @o2 "Math") (#any-of? @c "LN10" "LN2"))) @match
(call_expression function: (member_expression object: (identifier) @o3 property: (property_identifier) @s (#eq? @o3 "Math") (#eq? @s "sqrt"))) @match"#,
            filter: Some(Keep(manual_math_formula)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const d = Math.log(x) / Math.LN10;",
            good: "const d = Math.log10(x);",
        }),
    },
    Rule {
        id: "js/needless-conversion-wrapper",
        name: "Wrapper functions around built-in conversions should be avoided",
        description: "`x => String(x)` is `String`.",
        message: "Pass the built-in function directly.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7770")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(arrow_function body: (call_expression function: (identifier) @f (#any-of? @f "String" "Number" "Boolean" "BigInt"))) @match"#,
            filter: Some(Keep(arrow_only_converts_its_argument)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "ids.map(x => String(x));",
            good: "ids.map(String);",
        }),
    },
    Rule {
        id: "js/negative-index",
        name: "Negative indices should be used instead of length calculations",
        description: "`arr.at(-1)` says what `arr[arr.length - 1]` computes.",
        message: "Use at() with a negative index.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7771"), related("S7755")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(subscript_expression object: (_) @o index: (binary_expression left: (member_expression object: (_) @lo property: (property_identifier) @l (#eq? @l "length")) operator: "-" right: (number))) @match"#,
            filter: Some(Keep(reads_from_the_end)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const last = arr[arr.length - 1];",
            good: "const last = arr.at(-1);",
        }),
    },
    Rule {
        id: "js/node-protocol",
        name: "Node.js built-in modules should be imported with the node: protocol",
        description: "The prefix tells readers and tools the module is built in, not a package of the same name.",
        message: "Add the node: prefix.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7772")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(import_statement source: (string) @match)
(call_expression function: (identifier) @f (#eq? @f "require") arguments: (arguments . (string) @match))"#,
            filter: Some(Keep(is_bare_node_builtin)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const fs = require('fs');",
            good: "const fs = require('node:fs');",
        }),
    },
    Rule {
        id: "js/number-static",
        name: "Number static methods should be preferred over global ones",
        description: "Number.parseInt and Number.parseFloat are the same functions, grouped with the rest of Number.",
        message: "Use the Number.* version.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7773")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (identifier) @f (#any-of? @f "parseInt" "parseFloat" "isFinite")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const n = parseInt(s, 10);",
            good: "const n = Number.parseInt(s, 10);",
        }),
    },
    Rule {
        id: "js/prototype-via-instance",
        name: "Methods should be accessed from prototypes, not instances",
        description: "`[].slice.call(x)` allocates an array just to reach a method.",
        message: "Use Array.prototype or Object.prototype directly.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S7774")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression object: (member_expression object: [(array) (object)] property: (property_identifier)) property: (property_identifier) @c (#any-of? @c "call" "apply"))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "[].slice.call(args);",
            good: "Array.prototype.slice.call(args);",
        }),
    },
    Rule {
        id: "js/replace-all",
        name: "replaceAll() should be used instead of replace() with a global regex",
        description: "replaceAll says the intent and doesn't need a regex for a fixed string.",
        message: "Use replaceAll().",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7781")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression property: (property_identifier) @p (#eq? @p "replace")) arguments: (arguments . (regex flags: (regex_flags) @f (#match? @f "g")))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "s.replace(/a/g, 'b');",
            good: "s.replaceAll('a', 'b');",
        }),
    },
    Rule {
        id: "js/structured-clone",
        name: "structuredClone() should be used for deep copies",
        description: "A JSON round trip drops undefined, dates and maps; structuredClone keeps them.",
        message: "Use structuredClone().",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7784")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression object: (identifier) @o property: (property_identifier) @p (#eq? @o "JSON") (#eq? @p "parse")) arguments: (arguments . (call_expression function: (member_expression object: (identifier) @o2 property: (property_identifier) @q (#eq? @o2 "JSON") (#eq? @q "stringify"))))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const copy = JSON.parse(JSON.stringify(obj));",
            good: "const copy = structuredClone(obj);",
        }),
    },
    Rule {
        id: "js/type-error-after-check",
        name: "TypeError should be thrown after a type check",
        description: "When the check is about a value's type, TypeError tells callers what kind of mistake it was.",
        message: "Throw a TypeError.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7786")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(throw_statement (new_expression constructor: (identifier) @c (#eq? @c "Error"))) @match"#,
            filter: Some(Keep(throw_follows_type_check)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function f(x) { if (typeof x !== 'string') { throw new Error('x must be a string'); } }",
            good: "function f(x) { if (typeof x !== 'string') { throw new TypeError('x must be a string'); } }",
        }),
    },
    Rule {
        id: "js/empty-import-specifiers",
        name: "Import statements should not have empty specifier lists",
        description: "`import {} from 'x'` imports nothing but looks like it does; a side-effect import is written without braces.",
        message: "Remove the braces, or import something.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7787")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(import_statement (import_clause (named_imports) @n)) @match"#,
            filter: Some(Keep(import_list_is_empty)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "import {} from 'x';",
            good: "import 'x';",
        }),
    },
    Rule {
        id: "js/regexp-constructor-literal",
        name: "Regular expression literals should be used when possible",
        description: "A literal is checked when the file loads and needs no string escaping.",
        message: "Use a regular expression literal.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6325")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(new_expression constructor: (identifier) @c (#eq? @c "RegExp") arguments: (arguments . (string) @s)) @match"#,
            filter: Some(Keep(regexp_from_plain_string)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const re = new RegExp('ab+c');",
            good: "const re = /ab+c/;",
        }),
    },
    Rule {
        id: "js/class-name-convention",
        name: "Class names should comply with a naming convention",
        description: "PascalCase marks a name as a class, which is how readers tell classes from functions.",
        message: "Rename this class to PascalCase.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S101")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(class_declaration name: (_) @n) @match"#,
            filter: Some(Keep(class_name_not_pascal)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "class my_widget {}",
            good: "class MyWidget {}",
        }),
    },
    Rule {
        id: "js/absolute-import-path",
        name: "Imports should not use absolute paths",
        description: "An absolute path ties the code to one machine's file layout.",
        message: "Use a relative path or a package name.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S6859")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(import_statement source: (string) @match (#match? @match "^['\"]/"))"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "import x from '/src/x';",
            good: "import x from './x';",
        }),
    },
    Rule {
        id: "js/exported-mutable",
        name: "Mutable variables should not be exported",
        description: "Importers see the value change under them, and can't assign to it.",
        message: "Export a const, or a getter function.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S6861")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(export_statement declaration: [(lexical_declaration) (variable_declaration)] @match)"#,
            filter: Some(Keep(declares_mutable_variable)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "export let count = 0;",
            good: "export const count = 0;",
        }),
    },
    Rule {
        id: "js/deprecated-react-api",
        name: "Deprecated React APIs should not be used",
        description: "ReactDOM.render and friends are removed in React 19.",
        message: "Use the createRoot API.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 15,
        sonar: &[exact("S6957")],
        check: Check::Query {
            langs: JSX,
            query: r#"(call_expression function: (member_expression object: (identifier) @o property: (property_identifier) @p (#eq? @o "ReactDOM") (#any-of? @p "render" "hydrate" "unmountComponentAtNode"))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "ReactDOM.render(<App />, root);",
            good: "createRoot(root).render(<App />);",
        }),
    },
    Rule {
        id: "js/reserved-word-identifier",
        name: "Future reserved words should not be used as identifiers",
        description: "Words such as `package` and `public` are reserved in strict mode and in later editions.",
        message: "Rename this identifier.",
        category: CodeSmell,
        severity: Blocker,
        effort_minutes: 2,
        sonar: &[exact("S1527")],
        check: Check::Query {
            langs: &[Lang::JavaScript],
            query: r#"(variable_declarator name: (identifier) @match (#any-of? @match "implements" "interface" "package" "private" "protected" "public" "static" "enum"))"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "var public = 1;",
            good: "var visibility = 1;",
        }),
    },
    Rule {
        id: "js/hardcoded-ip",
        name: "IP addresses should not be hard-coded",
        description: "A literal address breaks when the network changes and can't be overridden per environment.",
        message: "Move this address to configuration.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S1313")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"((string) @match (#match? @match "^['\"][0-9]+[.][0-9]+[.][0-9]+[.][0-9]+['\"]$"))"#,
            filter: Some(Keep(is_routable_ipv4)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const host = '203.0.113.7';",
            good: "const host = process.env.HOST;\nconst local = '127.0.0.1';",
        }),
    },
    Rule {
        id: "js/for-update-unrelated",
        name: "\"for\" loop increments should modify the loop counters",
        description: "An update clause that touches other variables than the ones the condition tests usually never ends the loop.",
        message: "Update the variable the loop tests.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S1994")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(for_statement) @match"#,
            filter: Some(Keep(update_ignores_tested_variables)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "for (let i = 0; i < 10; j++) {}",
            good: "for (let i = 0; i < 10; i++) {}",
        }),
    },
    Rule {
        id: "js/function-nesting",
        name: "Functions should not be nested too deeply",
        description: "Each level of nesting adds context the reader has to hold.",
        message: "Move this function out of its enclosing functions.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 20,
        sonar: &[exact("S2004")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(function_declaration) @match
(function_expression) @match
(arrow_function) @match
(method_definition) @match"#,
            filter: Some(Keep(nested_four_levels_deep)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function a() { function b() { function c() { function d() { function e() {} } } } }",
            good: "function a() { function b() { function c() { function d() {} } } }",
        }),
    },
    Rule {
        id: "js/loop-counter-assigned",
        name: "Loop counters should not be assigned within the loop body",
        description: "Changing the counter in the body makes the number of iterations hard to read.",
        message: "Don't change the loop counter inside the loop.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2310")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(for_statement) @match"#,
            filter: Some(Find(counter_assigned_in_body)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "for (let i = 0; i < 10; i++) { i += 2; }",
            good: "for (let i = 0; i < 10; i += 2) {}",
        }),
    },
    Rule {
        id: "js/invariant-return",
        name: "Function returns should not be invariant",
        description: "A function whose every return gives the same value can be replaced by that value.",
        message: "Return something that depends on the input, or remove the return values.",
        category: CodeSmell,
        severity: Blocker,
        effort_minutes: 10,
        sonar: &[exact("S3516")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(function_declaration) @match
(function_expression) @match
(arrow_function) @match
(method_definition) @match"#,
            filter: Some(Keep(all_returns_identical)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function f(a) { if (a) { return 1; } return 1; }",
            good: "function f(a) { if (a) { return 1; } return 2; }",
        }),
    },
    Rule {
        id: "js/conditional-on-new-line",
        name: "Conditionals should start on new lines",
        description: "`if (a) {} if (b) {}` on one line reads like an else-if that is missing its else.",
        message: "Move this 'if' to its own line.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 2,
        sonar: &[exact("S3972")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(statement_block) @match
(program) @match"#,
            filter: Some(Find(if_on_line_where_previous_ended)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (a) { f(); } if (b) { g(); }",
            good: "if (a) { f(); }\nif (b) { g(); }",
        }),
    },
    Rule {
        id: "js/redundant-assignment",
        name: "Assignments should not be redundant",
        description: "Assigning the same value twice in a row does nothing the second time.",
        message: "Remove this repeated assignment.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S4165")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(statement_block) @match
(program) @match"#,
            filter: Some(Find(repeated_assignment)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "x = y;\nx = y;",
            good: "x = y;\nx = z;",
        }),
    },
    Rule {
        id: "js/unnecessary-escape",
        name: "Unnecessary character escapes should be removed",
        description: "A backslash before a character that needs none is noise, and hides which escapes matter.",
        message: "Remove this unnecessary escape.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6535")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(string) @match"#,
            filter: Some(Keep(has_needless_escape)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const s = 'a\\.b';",
            good: "const s = 'a.b';\nconst t = 'a\\nb';",
        }),
    },
    Rule {
        id: "js/catch-parameter-name",
        name: "Error parameters in catch clauses should follow a naming convention",
        description: "One name for the caught value, `error`, makes handlers look alike.",
        message: "Rename this catch parameter to 'error'.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[related("S7718")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(catch_clause parameter: (identifier) @p) @match"#,
            filter: Some(Keep(catch_name_not_error)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "try { f(); } catch (e) { g(e); }",
            good: "try { f(); } catch (error) { g(error); }",
        }),
    },
    Rule {
        id: "js/default-param-fallback",
        name: "Default parameters should be used instead of reassigning parameters",
        description: "`a = a || 5` at the top of a function is what `a = 5` in the parameter list is for.",
        message: "Use a default parameter value.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S7760")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(expression_statement (assignment_expression left: (identifier) @l right: (binary_expression left: (identifier) @r))) @match"#,
            filter: Some(Keep(reassigns_parameter_with_literal)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function f(a) { a = a || 5; return a; }",
            good: "function f(a = 5) { return a; }",
        }),
    },
    Rule {
        id: "js/multiline-without-braces",
        name: "Multiline blocks should be enclosed in curly braces",
        description: "A second statement indented like the first looks guarded by the condition, but isn't.",
        message: "Add curly braces around the body.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2681")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(if_statement consequence: (expression_statement)) @match
(for_statement body: (expression_statement)) @match
(while_statement body: (expression_statement)) @match"#,
            filter: Some(Keep(next_line_looks_guarded)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (ok)\n  a();\n  b();",
            good: "if (ok) {\n  a();\n  b();\n}",
        }),
    },
    Rule {
        id: "js/duplicate-imports",
        name: "Imports from the same module should be merged",
        description: "Two import statements for one module split what belongs together.",
        message: "Merge these imports.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S3863")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(program) @match"#,
            filter: Some(Find(second_import_of_module)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "import { a } from 'm';\nimport { b } from 'm';",
            good: "import { a, b } from 'm';",
        }),
    },
    Rule {
        id: "js/identical-functions",
        name: "Functions should not have identical implementations",
        description: "Two functions with the same body are one function written twice.",
        message: "Reuse the other function instead of repeating its body.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 15,
        sonar: &[exact("S4144")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(program) @match
(class_body) @match"#,
            filter: Some(Find(duplicate_function_body)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function a() {\n  const x = 1;\n  return x + 1;\n}\nfunction b() {\n  const x = 1;\n  return x + 1;\n}",
            good: "function a() {\n  const x = 1;\n  return x + 1;\n}\nfunction b() {\n  return 2;\n}",
        }),
    },
    Rule {
        id: "js/playwright-force",
        name: "Forced browser interactions should not bypass actionability checks",
        description: "force: true skips Playwright's waits for the element to be visible and enabled, hiding real UI problems.",
        message: "Remove 'force: true' and fix what blocks the element.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S8783")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(pair key: (property_identifier) @k (#eq? @k "force") value: (true)) @match"#,
            filter: Some(Keep(in_playwright_action)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "await page.click('#go', { force: true });",
            good: "await page.click('#go');",
        }),
    },
    Rule {
        id: "js/lodash-default-import",
        name: "Default imports from modular utility libraries should not be used",
        description: "Importing the whole library pulls in every function.",
        message: "Import only the functions you use.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S8927")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(import_statement (import_clause (identifier)) source: (string) @s (#match? @s "^['\"](lodash|underscore)['\"]$")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "import _ from 'lodash';",
            good: "import debounce from 'lodash/debounce';",
        }),
    },
];

// ---------------------------------------------------- filters

fn kind_in(node: Node, kinds: &[&str]) -> bool {
    kinds.contains(&node.kind())
}

const FUNCTION_KINDS: &[&str] = &[
    "function_declaration",
    "function_expression",
    "function",
    "arrow_function",
    "method_definition",
    "generator_function",
    "generator_function_declaration",
];

fn operator_text<'a>(node: Node, src: &'a [u8]) -> &'a [u8] {
    node.child_by_field_name("operator")
        .map_or(&b""[..], |o| text(o, src))
}

fn arguments_of(call: Node) -> Option<Node> {
    call.child_by_field_name("arguments")
}

fn argument_count(call: Node) -> usize {
    arguments_of(call).map_or(0, |a| a.named_child_count())
}

fn nearest_function(node: Node) -> Option<Node> {
    let mut p = node.parent();
    while let Some(n) = p {
        if kind_in(n, FUNCTION_KINDS) {
            return Some(n);
        }
        p = n.parent();
    }
    None
}

fn comma_outside_for_clause(sequence: Node, _: &[u8]) -> bool {
    !sequence
        .parent()
        .is_some_and(|p| matches!(p.kind(), "for_statement" | "sequence_expression"))
}

fn this_at_top_level(this: Node, _: &[u8]) -> bool {
    let mut p = this.parent();
    while let Some(n) = p {
        if kind_in(
            n,
            &[
                "function_declaration",
                "function_expression",
                "function",
                "generator_function",
                "generator_function_declaration",
                "method_definition",
                "class_declaration",
                "class",
                "class_static_block",
                "public_field_definition",
                "field_definition",
            ],
        ) {
            return false;
        }
        p = n.parent();
    }
    true
}

fn directly_in_template_substitution(template: Node, _: &[u8]) -> bool {
    let mut p = template.parent();
    while let Some(n) = p {
        if n.kind() == "template_substitution" {
            return true;
        }
        if kind_in(n, FUNCTION_KINDS) {
            return false;
        }
        p = n.parent();
    }
    false
}

/// The names of a function's plain parameters; None when any is a pattern.
fn simple_parameter_names<'s>(function: Node, src: &'s [u8]) -> Option<Vec<&'s [u8]>> {
    if let Some(single) = function.child_by_field_name("parameter") {
        return Some(vec![text(single, src)]);
    }
    let params = function.child_by_field_name("parameters")?;
    let mut cursor = params.walk();
    params
        .named_children(&mut cursor)
        .filter(|p| p.kind() != "comment")
        .map(|p| match p.kind() {
            "identifier" => Some(text(p, src)),
            "required_parameter" | "optional_parameter"
                if p.child_by_field_name("value").is_none() =>
            {
                p.child_by_field_name("pattern")
                    .filter(|n| n.kind() == "identifier")
                    .map(|n| text(n, src))
            }
            _ => None,
        })
        .collect()
}

/// The single expression an arrow or function body consists of.
fn sole_expression(function: Node) -> Option<Node> {
    let body = function.child_by_field_name("body")?;
    if body.kind() != "statement_block" {
        return Some(body);
    }
    let mut cursor = body.walk();
    let mut statements = body
        .named_children(&mut cursor)
        .filter(|n| n.kind() != "comment");
    let first = statements.next()?;
    if statements.next().is_some() || first.kind() != "expression_statement" {
        return None;
    }
    first.named_child(0)
}

fn promise_wraps_one_call(new: Node, src: &[u8]) -> bool {
    let Some(args) = arguments_of(new) else {
        return false;
    };
    if args.named_child_count() != 1 {
        return false;
    }
    let Some(executor) = args.named_child(0).filter(|e| {
        matches!(
            e.kind(),
            "arrow_function" | "function_expression" | "function"
        )
    }) else {
        return false;
    };
    let (Some(params), Some(call)) = (
        simple_parameter_names(executor, src),
        sole_expression(executor),
    ) else {
        return false;
    };
    call.kind() == "call_expression"
        && argument_count(call) <= 1
        && call
            .child_by_field_name("function")
            .is_some_and(|f| f.kind() == "identifier" && params.contains(&text(f, src)))
}

fn cast_in_boolean_context(cast: Node, src: &[u8]) -> bool {
    if cast.kind() == "call_expression" && argument_count(cast) != 1 {
        return false;
    }
    let Some(p) = cast.parent() else {
        return false;
    };
    match p.kind() {
        "parenthesized_expression" => p.parent().is_some_and(|g| {
            (matches!(
                g.kind(),
                "if_statement" | "while_statement" | "do_statement"
            ) && g.child_by_field_name("condition") == Some(p))
                || (g.kind() == "unary_expression" && operator_text(g, src) == b"!")
        }),
        "ternary_expression" => p.child_by_field_name("condition") == Some(cast),
        "for_statement" => p.child_by_field_name("condition") == Some(cast),
        "unary_expression" => operator_text(p, src) == b"!",
        _ => false,
    }
}

fn constructor_return_value<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let body = method.child_by_field_name("body")?;
    find_below(body, false, |n| {
        n.kind() == "return_statement" && n.named_child(0).is_some_and(|v| text(v, src) != b"this")
    })
}

fn bind_changes_nothing(call: Node, _: &[u8]) -> bool {
    let Some(mut target) = call
        .child_by_field_name("function")
        .and_then(|f| f.child_by_field_name("object"))
    else {
        return false;
    };
    while target.kind() == "parenthesized_expression" {
        let Some(inner) = target.named_child(0) else {
            return false;
        };
        target = inner;
    }
    match target.kind() {
        "arrow_function" => true,
        "function_expression" | "function" => target
            .child_by_field_name("body")
            .is_some_and(|b| find_below(b, false, |n| n.kind() == "this").is_none()),
        _ => false,
    }
}

fn ternary_has_simpler_form(ternary: Node, src: &[u8]) -> bool {
    let (Some(cond), Some(cons), Some(alt)) = (
        ternary.child_by_field_name("condition"),
        ternary.child_by_field_name("consequence"),
        ternary.child_by_field_name("alternative"),
    ) else {
        return false;
    };
    let plain = matches!(cond.kind(), "identifier" | "member_expression");
    (plain && (text(cond, src) == text(cons, src) || text(cond, src) == text(alt, src)))
        || (matches!(cons.kind(), "true" | "false")
            && matches!(alt.kind(), "true" | "false")
            && cons.kind() != alt.kind())
}

fn constructor_does_nothing(method: Node, src: &[u8]) -> bool {
    let mut cursor = method.walk();
    if method
        .children(&mut cursor)
        .any(|c| matches!(c.kind(), "accessibility_modifier" | "override_modifier"))
    {
        return false;
    }
    let (Some(params), Some(body)) = (
        method.child_by_field_name("parameters"),
        method.child_by_field_name("body"),
    ) else {
        return false;
    };
    // TypeScript parameter properties (`constructor(private x: T)`) declare fields.
    let mut pc = params.walk();
    if params.named_children(&mut pc).any(|p| {
        let mut c = p.walk();
        p.children(&mut c).any(|k| {
            matches!(
                k.kind(),
                "accessibility_modifier" | "override_modifier" | "readonly"
            )
        })
    }) {
        return false;
    }
    let class = method.parent().and_then(|b| b.parent());
    let has_heritage = class.is_some_and(|c| {
        let mut k = c.walk();
        c.children(&mut k).any(|n| n.kind() == "class_heritage")
    });
    let mut bc = body.walk();
    let statements: Vec<Node> = body
        .named_children(&mut bc)
        .filter(|n| n.kind() != "comment")
        .collect();
    if !has_heritage {
        return statements.is_empty();
    }
    let [only] = statements.as_slice() else {
        return false;
    };
    let Some(call) = only
        .named_child(0)
        .filter(|c| only.kind() == "expression_statement" && c.kind() == "call_expression")
    else {
        return false;
    };
    if call.child_by_field_name("function").map(|f| f.kind()) != Some("super") {
        return false;
    }
    let Some(args) = arguments_of(call) else {
        return false;
    };
    let mut ac = args.walk();
    let given: Vec<Node> = args.named_children(&mut ac).collect();
    if let [spread] = given.as_slice()
        && spread.kind() == "spread_element"
        && spread
            .named_child(0)
            .is_some_and(|n| text(n, src) == b"arguments")
    {
        return params.named_child_count() == 0;
    }
    let Some(names) = simple_parameter_names(method, src) else {
        // A rest parameter: `constructor(...args) { super(...args); }`.
        let mut pcur = params.walk();
        let rest: Vec<Node> = params.named_children(&mut pcur).collect();
        return matches!(
            (rest.as_slice(), given.as_slice()),
            ([r], [s]) if r.kind() == "rest_pattern"
                && s.kind() == "spread_element"
                && r.named_child(0).zip(s.named_child(0)).is_some_and(|(a, b)| text(a, src) == text(b, src))
        );
    };
    names.len() == given.len()
        && names
            .iter()
            .zip(&given)
            .all(|(n, g)| g.kind() == "identifier" && text(*g, src) == *n)
}

fn has_own_property_call(call: Node, src: &[u8]) -> bool {
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    let Some(property) = function.child_by_field_name("property") else {
        return false;
    };
    if text(property, src) == b"hasOwnProperty" {
        return argument_count(call) == 1
            && function
                .child_by_field_name("object")
                .is_some_and(|o| text(o, src) != b"Object.prototype");
    }
    true
}

fn assign_into_new_object(call: Node, _: &[u8]) -> bool {
    let Some(args) = arguments_of(call) else {
        return false;
    };
    let mut cursor = args.walk();
    args.named_child_count() >= 2
        && !args
            .named_children(&mut cursor)
            .any(|a| a.kind() == "spread_element")
}

fn apply_could_spread(call: Node, src: &[u8]) -> bool {
    let Some(args) = arguments_of(call) else {
        return false;
    };
    let (Some(first), Some(_), None) = (
        args.named_child(0),
        args.named_child(1),
        args.named_child(2),
    ) else {
        return false;
    };
    if matches!(text(first, src), b"null" | b"undefined") {
        return true;
    }
    call.child_by_field_name("function")
        .and_then(|f| f.child_by_field_name("object"))
        .and_then(|callee| callee.child_by_field_name("object"))
        .is_some_and(|receiver| text(receiver, src) == text(first, src))
}

fn call_with_nothing_as_this(call: Node, src: &[u8]) -> bool {
    arguments_of(call)
        .and_then(|a| a.named_child(0))
        .is_some_and(|first| first.kind() == "null" || text(first, src) == b"undefined")
}

fn clones_through_get_time(new: Node, _: &[u8]) -> bool {
    arguments_of(new).is_some_and(|a| {
        a.named_child_count() == 1 && a.named_child(0).is_some_and(|c| argument_count(c) == 0)
    })
}

fn error_has_no_message(error: Node, src: &[u8]) -> bool {
    match arguments_of(error) {
        None => true,
        Some(a) if a.named_child_count() == 0 => true,
        Some(a) => a
            .named_child(0)
            .is_some_and(|m| m.kind() == "string" && string_content(m, src).is_empty()),
    }
}

fn anonymous_default_export(export: Node, _: &[u8]) -> bool {
    if !has_token(export, "default") {
        return false;
    }
    export
        .child_by_field_name("value")
        .or_else(|| export.child_by_field_name("declaration"))
        .is_some_and(|d| {
            kind_in(
                d,
                &[
                    "arrow_function",
                    "function_expression",
                    "function",
                    "function_declaration",
                    "generator_function",
                    "generator_function_declaration",
                    "class",
                    "class_declaration",
                ],
            ) && d.child_by_field_name("name").is_none()
        })
}

fn array_has_one_element(call: Node, _: &[u8]) -> bool {
    argument_count(call) == 1
        && arguments_of(call)
            .and_then(|a| a.named_child(0))
            .is_some_and(|arr| {
                arr.named_child_count() == 1
                    && arr
                        .named_child(0)
                        .is_some_and(|e| e.kind() != "spread_element")
            })
}

fn spreads_fallback_object(spread: Node, src: &[u8]) -> bool {
    let Some(mut value) = spread.named_child(0) else {
        return false;
    };
    while value.kind() == "parenthesized_expression" {
        let Some(inner) = value.named_child(0) else {
            return false;
        };
        value = inner;
    }
    value.kind() == "binary_expression"
        && matches!(operator_text(value, src), b"||" | b"??")
        && value
            .child_by_field_name("right")
            .is_some_and(|r| r.kind() == "object" && r.named_child_count() == 0)
}

fn length_check_is_redundant(logical: Node, src: &[u8]) -> bool {
    let (Some(check), Some(call)) = (
        logical.child_by_field_name("left"),
        logical.child_by_field_name("right"),
    ) else {
        return false;
    };
    let method = call
        .child_by_field_name("function")
        .and_then(|f| f.child_by_field_name("property"))
        .map_or(&b""[..], |p| text(p, src));
    let receiver = call
        .child_by_field_name("function")
        .and_then(|f| f.child_by_field_name("object"));
    let measured = check
        .child_by_field_name("left")
        .and_then(|l| l.child_by_field_name("object"));
    if receiver
        .zip(measured)
        .is_none_or(|(a, b)| text(a, src) != text(b, src))
    {
        return false;
    }
    let number = check
        .child_by_field_name("right")
        .map_or(&b""[..], |n| text(n, src));
    match (operator_text(logical, src), method) {
        (b"&&", b"some") => matches!(
            (operator_text(check, src), number),
            (b">", b"0") | (b"!==", b"0") | (b"!=", b"0") | (b">=", b"1")
        ),
        (b"||", b"every") => matches!(
            (operator_text(check, src), number),
            (b"===", b"0") | (b"==", b"0") | (b"<", b"1")
        ),
        _ => false,
    }
}

fn in_async_function(node: Node, _: &[u8]) -> bool {
    nearest_function(node).is_some_and(|f| has_token(f, "async"))
}

fn flat_one_level(call: Node, src: &[u8]) -> bool {
    match argument_count(call) {
        0 => true,
        1 => arguments_of(call)
            .and_then(|a| a.named_child(0))
            .is_some_and(|d| text(d, src) == b"1"),
        _ => false,
    }
}

fn checks_filter_for_any(binary: Node, src: &[u8]) -> bool {
    let number = binary
        .child_by_field_name("right")
        .map_or(&b""[..], |n| text(n, src));
    matches!(
        (operator_text(binary, src), number),
        (b">", b"0")
            | (b"!==", b"0")
            | (b"!=", b"0")
            | (b">=", b"1")
            | (b"===", b"0")
            | (b"==", b"0")
            | (b"<", b"1")
    )
}

fn date_without_arguments(node: Node, _: &[u8]) -> bool {
    let new = if node.kind() == "unary_expression" {
        node.child_by_field_name("argument")
    } else {
        node.child_by_field_name("function")
            .and_then(|f| f.child_by_field_name("object"))
    };
    new.is_some_and(|n| n.kind() == "new_expression" && argument_count(n) == 0)
}

fn one_argument(call: Node, _: &[u8]) -> bool {
    argument_count(call) == 1
}

fn compares_index_for_existence(binary: Node, src: &[u8]) -> bool {
    let number = binary
        .child_by_field_name("right")
        .map_or(&b""[..], |n| text(n, src));
    matches!(
        (operator_text(binary, src), number),
        (b"!==", b"-1")
            | (b"!=", b"-1")
            | (b"===", b"-1")
            | (b"==", b"-1")
            | (b">", b"-1")
            | (b">=", b"0")
            | (b"<", b"0")
    )
}

fn truncates_to_integer(node: Node, src: &[u8]) -> bool {
    if node.kind() == "unary_expression" {
        return true;
    }
    matches!(operator_text(node, src), b"|" | b"^" | b"<<" | b">>")
        && node
            .child_by_field_name("right")
            .is_some_and(|r| r.kind() == "number" && text(r, src) == b"0")
}

fn instanceof_builtin(binary: Node, src: &[u8]) -> bool {
    operator_text(binary, src) == b"instanceof"
        && binary.child_by_field_name("right").is_some_and(|r| {
            r.kind() == "identifier"
                && matches!(
                    text(r, src),
                    b"Array" | b"String" | b"Number" | b"Boolean" | b"Symbol" | b"BigInt"
                )
        })
}

fn ternary_picks_min_or_max(ternary: Node, src: &[u8]) -> bool {
    let (Some(cond), Some(cons), Some(alt)) = (
        ternary.child_by_field_name("condition"),
        ternary.child_by_field_name("consequence"),
        ternary.child_by_field_name("alternative"),
    ) else {
        return false;
    };
    if cond.kind() != "binary_expression"
        || !matches!(operator_text(cond, src), b"<" | b">" | b"<=" | b">=")
    {
        return false;
    }
    let (Some(l), Some(r)) = (
        cond.child_by_field_name("left"),
        cond.child_by_field_name("right"),
    ) else {
        return false;
    };
    let (l, r, c, a) = (text(l, src), text(r, src), text(cons, src), text(alt, src));
    (c == l && a == r) || (c == r && a == l)
}

fn manual_math_formula(node: Node, src: &[u8]) -> bool {
    if node.kind() == "binary_expression" {
        return true;
    }
    // Math.sqrt(a * a + b * b)
    let Some(sum) = arguments_of(node)
        .and_then(|a| a.named_child(0))
        .filter(|s| s.kind() == "binary_expression" && operator_text(*s, src) == b"+")
    else {
        return false;
    };
    let square = |side: Option<Node>| {
        side.is_some_and(|s| {
            s.kind() == "binary_expression"
                && operator_text(s, src) == b"*"
                && s.child_by_field_name("left")
                    .zip(s.child_by_field_name("right"))
                    .is_some_and(|(a, b)| text(a, src) == text(b, src))
        })
    };
    square(sum.child_by_field_name("left")) && square(sum.child_by_field_name("right"))
}

fn arrow_only_converts_its_argument(arrow: Node, src: &[u8]) -> bool {
    let Some(names) = simple_parameter_names(arrow, src) else {
        return false;
    };
    let (Some(call), [param]) = (sole_expression(arrow), names.as_slice()) else {
        return false;
    };
    call.kind() == "call_expression"
        && argument_count(call) == 1
        && arguments_of(call)
            .and_then(|a| a.named_child(0))
            .is_some_and(|arg| arg.kind() == "identifier" && text(arg, src) == *param)
}

fn reads_from_the_end(subscript: Node, src: &[u8]) -> bool {
    let (Some(object), Some(index)) = (
        subscript.child_by_field_name("object"),
        subscript.child_by_field_name("index"),
    ) else {
        return false;
    };
    let measured = index
        .child_by_field_name("left")
        .and_then(|l| l.child_by_field_name("object"));
    if measured.is_none_or(|m| text(m, src) != text(object, src)) {
        return false;
    }
    // Writing to an element has no at() form.
    !subscript.parent().is_some_and(|p| {
        (matches!(
            p.kind(),
            "assignment_expression" | "augmented_assignment_expression"
        ) && p.child_by_field_name("left") == Some(subscript))
            || p.kind() == "update_expression"
            || (p.kind() == "unary_expression" && operator_text(p, src) == b"delete")
    })
}

const NODE_BUILTINS: &[&[u8]] = &[
    b"assert",
    b"assert/strict",
    b"async_hooks",
    b"buffer",
    b"child_process",
    b"cluster",
    b"console",
    b"crypto",
    b"dgram",
    b"diagnostics_channel",
    b"dns",
    b"dns/promises",
    b"domain",
    b"events",
    b"fs",
    b"fs/promises",
    b"http",
    b"http2",
    b"https",
    b"inspector",
    b"module",
    b"net",
    b"os",
    b"path",
    b"path/posix",
    b"path/win32",
    b"perf_hooks",
    b"process",
    b"querystring",
    b"readline",
    b"readline/promises",
    b"repl",
    b"stream",
    b"stream/promises",
    b"string_decoder",
    b"timers",
    b"timers/promises",
    b"tls",
    b"trace_events",
    b"tty",
    b"url",
    b"util",
    b"v8",
    b"vm",
    b"worker_threads",
    b"zlib",
];

fn is_bare_node_builtin(string: Node, src: &[u8]) -> bool {
    NODE_BUILTINS.contains(&string_content(string, src))
}

fn throw_follows_type_check(throw: Node, src: &[u8]) -> bool {
    let mut p = throw.parent();
    while let Some(n) = p {
        if kind_in(n, FUNCTION_KINDS) {
            return false;
        }
        if n.kind() == "if_statement" {
            return n.child_by_field_name("condition").is_some_and(|c| {
                let t = text(c, src);
                [&b"typeof "[..], b"instanceof", b"Array.isArray"]
                    .iter()
                    .any(|needle| t.windows(needle.len()).any(|w| w == *needle))
            });
        }
        p = n.parent();
    }
    false
}

fn import_list_is_empty(import: Node, _: &[u8]) -> bool {
    let mut cursor = import.walk();
    import
        .children(&mut cursor)
        .find(|c| c.kind() == "import_clause")
        .is_some_and(|clause| {
            clause.named_child_count() == 1
                && clause
                    .named_child(0)
                    .is_some_and(|n| n.kind() == "named_imports" && n.named_child_count() == 0)
        })
}

fn regexp_from_plain_string(new: Node, src: &[u8]) -> bool {
    let Some(args) = arguments_of(new) else {
        return false;
    };
    let (Some(pattern), flags) = (args.named_child(0), args.named_child(1)) else {
        return false;
    };
    let body = string_content(pattern, src);
    args.named_child_count() <= 2
        && flags.is_none_or(|f| f.kind() == "string")
        && !body.is_empty()
        && !body.contains(&b'/')
        && !body.contains(&b'\n')
}

fn class_name_not_pascal(class: Node, src: &[u8]) -> bool {
    let Some(name) = class.child_by_field_name("name") else {
        return false;
    };
    let t = text(name, src);
    !(t.first().is_some_and(u8::is_ascii_uppercase) && t.iter().all(u8::is_ascii_alphanumeric))
}

fn declares_mutable_variable(declaration: Node, _: &[u8]) -> bool {
    declaration.kind() == "variable_declaration" || has_token(declaration, "let")
}

fn is_routable_ipv4(string: Node, src: &[u8]) -> bool {
    let body = string_content(string, src);
    let octets: Vec<u16> = String::from_utf8_lossy(body)
        .split('.')
        .filter_map(|o| o.parse().ok())
        .collect();
    octets.len() == 4
        && octets.iter().all(|&o| o <= 255)
        && octets[0] != 127
        && octets != [0, 0, 0, 0]
        && octets != [255, 255, 255, 255]
}

/// Every node below `node` (inside nested functions too) that satisfies `pred`.
pub(super) fn collect_below<'t>(node: Node<'t>, pred: impl Fn(Node<'t>) -> bool) -> Vec<Node<'t>> {
    let mut found = Vec::new();
    let mut cursor = node.walk();
    if !cursor.goto_first_child() {
        return found;
    }
    loop {
        if pred(cursor.node()) {
            found.push(cursor.node());
        }
        if cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return found;
            }
        }
    }
}

/// The variable an update or assignment node writes to.
fn written_identifier<'a>(node: Node, src: &'a [u8]) -> Option<&'a [u8]> {
    let target = match node.kind() {
        "update_expression" => node.child_by_field_name("argument"),
        "assignment_expression" | "augmented_assignment_expression" => {
            node.child_by_field_name("left")
        }
        _ => None,
    };
    target
        .filter(|t| t.kind() == "identifier")
        .map(|t| text(t, src))
}

fn is_write(node: Node) -> bool {
    matches!(
        node.kind(),
        "update_expression" | "assignment_expression" | "augmented_assignment_expression"
    )
}

fn update_ignores_tested_variables(for_loop: Node, src: &[u8]) -> bool {
    let (Some(condition), Some(increment)) = (
        for_loop.child_by_field_name("condition"),
        for_loop.child_by_field_name("increment"),
    ) else {
        return false;
    };
    let mut writes = collect_below(increment, is_write);
    if is_write(increment) {
        writes.push(increment);
    }
    let changed: Vec<&[u8]> = writes
        .into_iter()
        .filter_map(|w| written_identifier(w, src))
        .collect();
    if changed.is_empty() {
        return false;
    }
    let mut tested: Vec<&[u8]> = collect_below(condition, |n| n.kind() == "identifier")
        .into_iter()
        .map(|n| text(n, src))
        .collect();
    if condition.kind() == "identifier" {
        tested.push(text(condition, src));
    }
    !changed.iter().any(|c| tested.contains(c))
}

fn nested_four_levels_deep(function: Node, _: &[u8]) -> bool {
    // `parent()` costs the node's depth, so give up on absurdly deep trees.
    let mut depth = 0;
    let mut hops = 0;
    let mut p = function.parent();
    while let Some(n) = p {
        if kind_in(n, FUNCTION_KINDS) {
            depth += 1;
            if depth > 4 {
                return false;
            }
        }
        hops += 1;
        if hops > 256 {
            return false;
        }
        p = n.parent();
    }
    depth == 4
}

fn loop_counter_names<'a>(for_loop: Node, src: &'a [u8]) -> Vec<&'a [u8]> {
    let Some(init) = for_loop.child_by_field_name("initializer") else {
        return Vec::new();
    };
    match init.kind() {
        "lexical_declaration" | "variable_declaration" => {
            collect_below(init, |n| n.kind() == "variable_declarator")
                .into_iter()
                .filter_map(|d| d.child_by_field_name("name"))
                .filter(|n| n.kind() == "identifier")
                .map(|n| text(n, src))
                .collect()
        }
        _ => {
            let mut names: Vec<&[u8]> = collect_below(init, is_write)
                .into_iter()
                .filter_map(|w| written_identifier(w, src))
                .collect();
            names.extend(written_identifier(init, src));
            names
        }
    }
}

fn counter_assigned_in_body<'t>(for_loop: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let counters = loop_counter_names(for_loop, src);
    if counters.is_empty() {
        return None;
    }
    let body = for_loop.child_by_field_name("body")?;
    collect_below(body, is_write)
        .into_iter()
        .find(|n| written_identifier(*n, src).is_some_and(|name| counters.contains(&name)))
}

/// The return statements of a function body, not looking into nested functions.
fn returns_of(body: Node) -> Vec<Node> {
    let mut found = Vec::new();
    let mut cursor = body.walk();
    if !cursor.goto_first_child() {
        return found;
    }
    loop {
        let n = cursor.node();
        if n.kind() == "return_statement" {
            found.push(n);
        }
        if !kind_in(n, FUNCTION_KINDS) && cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return found;
            }
        }
    }
}

fn all_returns_identical(function: Node, src: &[u8]) -> bool {
    let Some(body) = function
        .child_by_field_name("body")
        .filter(|b| b.kind() == "statement_block")
    else {
        return false;
    };
    let returns = returns_of(body);
    if returns.len() < 2 {
        return false;
    }
    let mut values = returns.iter().map(|r| r.named_child(0));
    let Some(Some(first)) = values.next() else {
        return false;
    };
    matches!(
        first.kind(),
        "number" | "string" | "true" | "false" | "null"
    ) && values
        .all(|v| v.is_some_and(|v| v.kind() == first.kind() && text(v, src) == text(first, src)))
}

fn if_on_line_where_previous_ended<'t>(block: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    let mut cursor = block.walk();
    let statements: Vec<Node> = block.named_children(&mut cursor).collect();
    statements.windows(2).find_map(|pair| {
        (pair[0].kind() == "if_statement"
            && pair[1].kind() == "if_statement"
            && pair[0].end_position().row == pair[1].start_position().row)
            .then_some(pair[1])
    })
}

fn repeated_assignment<'t>(block: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut cursor = block.walk();
    let statements: Vec<Node> = block.named_children(&mut cursor).collect();
    statements.windows(2).find_map(|pair| {
        let assignment = |s: Node<'t>| {
            (s.kind() == "expression_statement")
                .then(|| s.named_child(0))
                .flatten()
                .filter(|a| a.kind() == "assignment_expression")
        };
        let (a, b) = (assignment(pair[0])?, assignment(pair[1])?);
        let pure = a.child_by_field_name("right").is_some_and(|r| {
            matches!(
                r.kind(),
                "identifier"
                    | "number"
                    | "string"
                    | "true"
                    | "false"
                    | "null"
                    | "member_expression"
            )
        });
        (pure && text(a, src) == text(b, src)).then_some(pair[1])
    })
}

fn has_needless_escape(string: Node, src: &[u8]) -> bool {
    if string.parent().is_some_and(|p| p.kind() == "jsx_attribute") {
        return false;
    }
    let raw = text(string, src);
    let Some(&quote) = raw.first() else {
        return false;
    };
    let body = string_content(string, src);
    let mut i = 0;
    while i < body.len() {
        if body[i] == b'\\' {
            let Some(&next) = body.get(i + 1) else {
                return false;
            };
            let needed = b"nrtbfv0123456789xu\\\n\r/".contains(&next) || next == quote;
            if !needed {
                return true;
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    false
}

fn catch_name_not_error(catch: Node, src: &[u8]) -> bool {
    let Some(name) = catch.child_by_field_name("parameter") else {
        return false;
    };
    let t = text(name, src);
    !(t == b"error" || t.starts_with(b"_") || t.ends_with(b"Error"))
}

fn reassigns_parameter_with_literal(statement: Node, src: &[u8]) -> bool {
    let Some(assignment) = statement.named_child(0) else {
        return false;
    };
    let (Some(left), Some(right)) = (
        assignment.child_by_field_name("left"),
        assignment.child_by_field_name("right"),
    ) else {
        return false;
    };
    let Some((same, literal)) = right
        .child_by_field_name("left")
        .zip(right.child_by_field_name("right"))
    else {
        return false;
    };
    if !matches!(operator_text(right, src), b"||" | b"??") {
        return false;
    }
    if text(same, src) != text(left, src)
        || !matches!(
            literal.kind(),
            "number" | "string" | "true" | "false" | "null" | "object" | "array" | "regex"
        )
    {
        return false;
    }
    nearest_function(statement)
        .and_then(|f| simple_parameter_names(f, src))
        .is_some_and(|names| names.contains(&text(left, src)))
}

fn next_line_looks_guarded(parent: Node, _: &[u8]) -> bool {
    let Some(body) = parent
        .child_by_field_name("consequence")
        .or_else(|| parent.child_by_field_name("body"))
    else {
        return false;
    };
    // An else branch ends the statement the first line belongs to.
    if parent.kind() == "if_statement" && parent.child_by_field_name("alternative").is_some() {
        return false;
    }
    let Some(next) = parent.next_named_sibling() else {
        return false;
    };
    body.start_position().row > parent.start_position().row
        && next.start_position().row > body.end_position().row
        && next.start_position().column == body.start_position().column
        && body.start_position().column > parent.start_position().column
}

fn second_import_of_module<'t>(program: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut seen: Vec<(&[u8], bool)> = Vec::new();
    let mut cursor = program.walk();
    for import in program.named_children(&mut cursor) {
        if import.kind() != "import_statement" {
            continue;
        }
        let mut c = import.walk();
        if !import.children(&mut c).any(|k| k.kind() == "import_clause") {
            continue;
        }
        let Some(source) = import.child_by_field_name("source") else {
            continue;
        };
        let key = (
            string_content(source, src),
            text(import, src).starts_with(b"import type"),
        );
        if seen.contains(&key) {
            return Some(import);
        }
        seen.push(key);
    }
    None
}

fn duplicate_function_body<'t>(container: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut seen: Vec<&[u8]> = Vec::new();
    let mut cursor = container.walk();
    for member in container.named_children(&mut cursor) {
        if !matches!(member.kind(), "function_declaration" | "method_definition") {
            continue;
        }
        let name = member
            .child_by_field_name("name")
            .map_or(&b""[..], |n| text(n, src));
        let Some(body) = member.child_by_field_name("body").filter(|b| {
            b.named_child_count() >= 2 && b.end_position().row - b.start_position().row >= 2
        }) else {
            continue;
        };
        if name == b"constructor" || has_token(member, "get") || has_token(member, "set") {
            continue;
        }
        let body_text = text(body, src);
        if seen.contains(&body_text) {
            return Some(member);
        }
        seen.push(body_text);
    }
    None
}

fn in_playwright_action(pair: Node, src: &[u8]) -> bool {
    let call = pair
        .parent()
        .and_then(|o| o.parent())
        .and_then(|a| a.parent())
        .filter(|c| c.kind() == "call_expression");
    call.and_then(|c| c.child_by_field_name("function"))
        .and_then(|f| f.child_by_field_name("property"))
        .is_some_and(|p| {
            matches!(
                text(p, src),
                b"click"
                    | b"dblclick"
                    | b"check"
                    | b"uncheck"
                    | b"fill"
                    | b"hover"
                    | b"tap"
                    | b"selectOption"
                    | b"setInputFiles"
                    | b"dragTo"
                    | b"press"
                    | b"focus"
            )
        })
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
    fn comma_expressions_outside_for_clauses() {
        let src =
            "for (let i = 0, j = 1; i < j; i++, j--) {}\nconst x = (a(), b());\nf((a, b, c));";
        assert_eq!(flagged("js/comma-operator", JS, src), [2, 3]);
    }

    #[test]
    fn this_outside_functions() {
        let src = "this.a = 1;\nconst f = () => this.b;\nfunction g() { return this.c; }\nclass K { m() { return this.d; } x = this.e; }";
        assert_eq!(flagged("js/global-this", JS, src), [1, 2]);
    }

    #[test]
    fn boolean_casts_only_in_conditions() {
        let src = "if (!!a) {}\nconst b = !!a;\nwhile (Boolean(a)) {}\nconst c = x ? 1 : 2;\nconst d = !!a ? 1 : 2;\nif (!(!!a)) {}\nconst e = Boolean(a, b);";
        assert_eq!(flagged("js/redundant-boolean-cast", JS, src), [1, 3, 5, 6]);
    }

    #[test]
    fn useless_constructors() {
        let src = "class A { constructor() {} }
class B extends A { constructor(x, y) { super(x, y); } }
class C extends A { constructor(...args) { super(...args); } }
class D extends A { constructor(x) { super(x, 1); } }
class E extends A { constructor() { super(); this.v = 1; } }
class F { constructor(a) { this.a = a; } }
class G extends A { constructor() { super(...arguments); } }";
        assert_eq!(flagged("js/useless-constructor", JS, src), [1, 2, 3, 7]);
        let ts =
            "class P { constructor(private x: number) {} }\nclass Q { private constructor() {} }";
        assert!(flagged("js/useless-constructor", TS, ts).is_empty());
    }

    #[test]
    fn index_of_comparisons() {
        let src = "a.indexOf(x) !== -1;\na.indexOf(x) > -1;\na.indexOf(x) >= 0;\na.indexOf(x) === -1;\na.indexOf(x) > 0;\na.indexOf(x) === 2;";
        assert_eq!(flagged("js/index-of-existence", JS, src), [1, 2, 3, 4]);
    }

    #[test]
    fn for_loop_counters() {
        let src = "for (let i = 0; i < n; j++) {}\nfor (let i = 0; i < n; i++) {}\nfor (let i = 0, j = 5; i < j; i++, j--) {}\nfor (;;) {}\nfor (let i = 0; i < 10; i++) { i += 2; }\nfor (let i = 0; i < 10; i++) { const k = i; }";
        assert_eq!(flagged("js/for-update-unrelated", JS, src), [1]);
        assert_eq!(flagged("js/loop-counter-assigned", JS, src), [5]);
    }

    #[test]
    fn invariant_returns() {
        let src = "function a(x) { if (x) { return 1; } return 1; }\nfunction b(x) { if (x) { return 1; } return 2; }\nfunction c(x) { if (x) { return 1; } }\nfunction d(x) { const f = () => { return 2; }; if (x) { return 1; } return 1; }";
        assert_eq!(flagged("js/invariant-return", JS, src), [1, 4]);
    }

    #[test]
    fn conditionals_on_one_line() {
        let src = "if (a) { f(); } if (b) { g(); }\nif (a) { f(); }\nif (b) { g(); }\nif (a) { f(); } else if (b) { g(); }";
        assert_eq!(flagged("js/conditional-on-new-line", JS, src), [1]);
    }

    #[test]
    fn repeated_and_distinct_assignments() {
        let src = "x = y;\nx = y;\nz = f();\nz = f();\nq = 1;\nq = 2;";
        assert_eq!(flagged("js/redundant-assignment", JS, src), [2]);
    }

    #[test]
    fn needless_escapes_in_strings() {
        let src = "const a = 'a\\.b';\nconst b = 'a\\nb';\nconst c = \"it\\'s\";\nconst d = 'it\\'s';\nconst e = 'a\\u0041\\/';\nconst f = <p title=\"a\\.b\" />;";
        assert_eq!(flagged("js/unnecessary-escape", Lang::Tsx, src), [1, 3]);
    }

    #[test]
    fn catch_parameter_names() {
        let src = "try {} catch (e) {}\ntry {} catch (error) {}\ntry {} catch (_) {}\ntry {} catch (fetchError) {}\ntry {} catch (err) {}";
        assert_eq!(flagged("js/catch-parameter-name", JS, src), [1, 5]);
    }

    #[test]
    fn parameter_fallbacks() {
        let src = "function f(a, b) { a = a || 5; b = c || 5; return a; }\nfunction g(a = 1) { a = a || 2; }\nconst h = (x) => { x = x ?? 'd'; };";
        assert_eq!(flagged("js/default-param-fallback", JS, src), [1, 3]);
    }

    #[test]
    fn statements_that_look_guarded() {
        let src = "if (ok)\n  a();\n  b();\nif (ok)\n  a();\nb();\nif (ok) a();\nb();\nfor (;;)\n  a();\n  b();\nif (x)\n  a();\nelse\n  c();\n  d();";
        assert_eq!(flagged("js/multiline-without-braces", JS, src), [1, 9]);
    }

    #[test]
    fn imports_and_duplicates() {
        let src = "import { a } from 'm';\nimport { b } from 'm';\nimport 'm';\nimport c from 'n';";
        assert_eq!(flagged("js/duplicate-imports", JS, src), [2]);
        let types = "import type { A } from 'm';\nimport { b } from 'm';";
        assert!(flagged("js/duplicate-imports", TS, types).is_empty());
    }

    #[test]
    fn identical_function_bodies() {
        let src = "function a() {\n  const x = 1;\n  return x;\n}\nfunction b() {\n  const x = 1;\n  return x;\n}\nfunction c() { return 1; }\nfunction d() { return 1; }";
        assert_eq!(flagged("js/identical-functions", JS, src), [5]);
    }

    #[test]
    fn nesting_depth_reports_the_first_level_over() {
        let src = "function a() { function b() { function c() { function d() { function e() { function f() {} } } } } }";
        assert_eq!(flagged("js/function-nesting", JS, src), [1]);
    }

    #[test]
    fn at_negative_index_only_for_reads() {
        let src = "const a = arr[arr.length - 1];\narr[arr.length - 1] = 2;\nconst b = other[arr.length - 1];";
        assert_eq!(flagged("js/negative-index", JS, src), [1]);
    }

    #[test]
    fn ips_and_node_modules() {
        let src = "a('203.0.113.7');\nb('127.0.0.1');\nc('0.0.0.0');\nd('1.2.3');\nconst fs = require('fs');\nconst p = require('node:path');\nimport os from 'os';\nimport x from 'left-pad';";
        assert_eq!(flagged("js/hardcoded-ip", JS, src), [1]);
        assert_eq!(flagged("js/node-protocol", JS, src), [5, 7]);
    }

    #[test]
    fn promises_and_async() {
        let src = "new Promise(r => r(1));\nnew Promise((_, rej) => { rej(e); });\nnew Promise(r => { setTimeout(r, 1); });\nnew Promise((r) => r(1, 2));";
        assert_eq!(flagged("js/promise-shorthand", JS, src), [1, 2]);
        let asyncs = "async function f() { return Promise.resolve(1); }\nfunction g() { return Promise.resolve(1); }";
        assert_eq!(flagged("js/promise-resolve-in-async", JS, asyncs), [1]);
    }

    #[test]
    fn array_length_checks_before_some() {
        let src = "a.length > 0 && a.some(f);\na.length === 0 || a.every(f);\nb.length > 0 && a.some(f);\na.length > 1 && a.some(f);";
        assert_eq!(flagged("js/length-check-before-some", JS, src), [1, 2]);
    }

    #[test]
    fn small_idioms() {
        let src = "const a = new Date(d.getTime());\nconst b = new Date().getTime();\nconst c = +new Date();\nconst d2 = new Date(5).getTime();\nthrow new Error();\nthrow new Error('');\nthrow new Error('x');\nconst m = a > b ? a : b;\nconst n = a > b ? c : b;\nconst t = x ? x : y;\nconst u = ok ? true : false;\nconst v = f() ? f() : y;";
        assert_eq!(flagged("js/date-clone", JS, src), [1]);
        assert_eq!(flagged("js/date-now", JS, src), [2, 3]);
        assert_eq!(flagged("js/error-without-message", JS, src), [5, 6]);
        assert_eq!(flagged("js/math-min-max-ternary", JS, src), [8]);
        assert_eq!(flagged("js/ternary-simplifiable", JS, src), [10, 11]);
    }

    #[test]
    fn mutable_exports_and_default_exports() {
        let src = "export let a = 1;\nexport var b = 2;\nexport const c = 3;\nexport default function () {}";
        assert_eq!(flagged("js/exported-mutable", JS, src), [1, 2]);
        assert_eq!(flagged("js/anonymous-default-export", JS, src), [4]);
        let named = "export default function main() {}\nexport default class Foo {}";
        assert!(flagged("js/anonymous-default-export", JS, named).is_empty());
    }

    #[test]
    fn classes_and_regexps() {
        let src = "class my_widget {}\nclass Widget {}\nclass HTTPClient {}\nconst a = new RegExp('ab+c');\nconst b = new RegExp('a/b');\nconst c = new RegExp(pattern);";
        assert_eq!(flagged("js/class-name-convention", JS, src), [1]);
        assert_eq!(flagged("js/regexp-constructor-literal", JS, src), [4]);
    }

    #[test]
    fn throw_after_a_type_check() {
        let src = "function f(x) {\n  if (typeof x !== 'string') {\n    throw new Error('bad');\n  }\n  if (!x) {\n    throw new Error('empty');\n  }\n}";
        assert_eq!(flagged("js/type-error-after-check", JS, src), [3]);
    }
}
