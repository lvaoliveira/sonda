//! JavaScript and TypeScript rules, part 8 (ADR-0007, batch 26): the checks
//! SonarQube runs with a type checker, approximated from what one file shows:
//! literals, declarations in the same file and the shape of the code. A
//! value whose type is not visible is never reported.

use super::js::{has_token, text};
use super::js_extra::{named, operator_text};
use super::js_syntax::{ancestors_in_function, is_function_kind, root_node, walk};
use super::*;

/// This module's rules that are off unless `rules.enabled` lists them
/// (see `catalog::OFF_BY_DEFAULT`).
pub(super) static OFF_BY_DEFAULT: &[&str] = &[
    "js/switch-without-default",
    "js/immediately-returned-variable",
    "js/string-comparison",
    "js/string-plus-non-string",
    "js/prototype-assignment",
    "js/require-instead-of-import",
    "js/arithmetic-on-non-numbers",
    "js/arithmetic-on-strings-or-booleans",
    "js/comparison-of-non-numbers",
    "js/inconsistent-return",
    "js/for-in-over-array",
    "js/foreach-to-for-of",
    "js/boxed-return-type",
];

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "js/switch-without-default",
        name: "\"switch\" statements should have \"default\" clauses",
        description: "Without a default, an unexpected value is silently ignored.",
        message: "Add a default clause.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 2,
        sonar: &[exact("S131")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(switch_statement) @match"#,
            filter: Some(Keep(lacks_default)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "switch (a) { case 1: f(); break; case 2: g(); break; }",
            good: "switch (a) { case 1: f(); break; case 2: g(); break; default: h(); }",
        }),
    },
    Rule {
        id: "js/switch-instead-of-if",
        name: "\"if\" statements should be preferred over \"switch\" when simpler",
        description: "A switch with one or two cases is an if in disguise.",
        message: "Use an if statement.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S1301")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(switch_statement) @match"#,
            filter: Some(Keep(has_fewer_than_three_clauses)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "switch (a) { case 1: f(); break; default: g(); }",
            good: "if (a === 1) { f(); } else { g(); }",
        }),
    },
    Rule {
        id: "js/immediately-returned-variable",
        name: "Local variables should not be declared and then immediately returned or thrown",
        description: "The variable adds a name for a value that is used once, on the next line.",
        message: "Return the expression directly.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S1488")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(statement_block) @match"#,
            filter: Some(Find(declared_then_returned)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function f() { const r = g(); return r; }",
            good: "function f() { return g(); }",
        }),
    },
    Rule {
        id: "js/sort-without-compare",
        name: "\"Array.prototype.sort()\" and \"Array.prototype.toSorted()\" should use a compare function",
        description: "The default order compares elements as strings: 10 sorts before 9.",
        message: "Pass a compare function.",
        category: Bug,
        severity: Critical,
        effort_minutes: 2,
        sonar: &[exact("S2871")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression property: (property_identifier) @p (#any-of? @p "sort" "toSorted")) arguments: (arguments) @a) @match"#,
            filter: Some(Keep(sorts_numbers_by_default)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const s = [10, 9, 1].sort();",
            good: "const s = [10, 9, 1].sort((a, b) => a - b);",
        }),
    },
    Rule {
        id: "js/delete-on-array",
        name: "\"delete\" should not be used on arrays",
        description: "delete leaves a hole and keeps the length.",
        message: "Use splice.",
        category: Bug,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S2870")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(unary_expression argument: (subscript_expression index: (_) @i)) @match"#,
            filter: Some(Keep(deletes_by_index)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "delete items[2];",
            good: "items.splice(2, 1);",
        }),
    },
    Rule {
        id: "js/new-on-non-constructor",
        name: "\"new\" should only be used with functions and classes",
        description: "An arrow function cannot be a constructor.",
        message: "Use a function or a class.",
        category: Bug,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S2999")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(new_expression constructor: (identifier) @c) @match"#,
            filter: Some(Keep(constructor_is_an_arrow)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const make = () => ({}); const o = new make();",
            good: "function Make() {} const o = new Make();",
        }),
    },
    Rule {
        id: "js/string-comparison",
        name: "Comparison operators should not be used with strings",
        description: "< and > compare strings by code unit, not alphabetically.",
        message: "Use localeCompare.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S3003")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(binary_expression) @match"#,
            filter: Some(Keep(compares_a_string_literal)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (a < 'm') { f(); }",
            good: "if (a.localeCompare('m') < 0) { f(); }",
        }),
    },
    Rule {
        id: "js/string-plus-non-string",
        name: "Strings and non-strings should not be added",
        description: "'1' + 2 is '12', which is rarely what was meant.",
        message: "Convert one side explicitly.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S3402")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(binary_expression) @match"#,
            filter: Some(Keep(adds_string_to_literal)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const x = '1' + 2;",
            good: "const x = `1${2}`;",
        }),
    },
    Rule {
        id: "js/prototype-assignment",
        name: "Class methods should be used instead of \"prototype\" assignments",
        description: "The class syntax says the same with less.",
        message: "Use a class.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 10,
        sonar: &[exact("S3525")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(assignment_expression left: (member_expression object: (member_expression property: (property_identifier) @p)) (#eq? @p "prototype")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function A() {} A.prototype.f = function () {};",
            good: "class A { f() {} }",
        }),
    },
    Rule {
        id: "js/require-instead-of-import",
        name: "\"import\" should be used to include external code",
        description: "require is the module system of an older Node.",
        message: "Use import.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S3533")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (identifier) @f arguments: (arguments (string)) (#eq? @f "require")) @match"#,
            filter: Some(Keep(is_top_level_require)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const fs = require('fs');",
            good: "import fs from 'fs';",
        }),
    },
    Rule {
        id: "js/arithmetic-on-non-numbers",
        name: "Arithmetic operations should not result in \"NaN\"",
        description: "Arithmetic on an object, array, function or undefined is NaN.",
        message: "Use numbers.",
        category: Bug,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S3757")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(binary_expression) @match"#,
            filter: Some(Keep(arithmetic_on_nan_operand)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const x = {} * 2;",
            good: "const x = 3 * 2;",
        }),
    },
    Rule {
        id: "js/arithmetic-on-strings-or-booleans",
        name: "Arithmetic operators should only have numbers as operands",
        description: "'a' - 1 is NaN, true * 2 is 2.",
        message: "Convert the operand to a number first.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S3760")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(binary_expression) @match"#,
            filter: Some(Keep(arithmetic_on_non_number_operand)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const x = 'a' - 1;",
            good: "const x = Number(a) - 1;",
        }),
    },
    Rule {
        id: "js/comparison-of-non-numbers",
        name: "Values not convertible to numbers should not be used in numeric comparisons",
        description: "{} > 1 is false whatever the object holds.",
        message: "Compare numbers.",
        category: Bug,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S3758")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(binary_expression) @match"#,
            filter: Some(Keep(compares_a_non_number)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if ({} > 1) { f(); }",
            good: "if (n > 1) { f(); }",
        }),
    },
    Rule {
        id: "js/inconsistent-return",
        name: "Functions should use \"return\" consistently",
        description: "Some paths return a value, others return nothing.",
        message: "Return a value on every path.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3801")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(function_declaration) (function_expression) (arrow_function) (method_definition) (generator_function) (generator_function_declaration)] @match"#,
            filter: Some(Keep(returns_inconsistently)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function f(a) { if (a) { return 1; } return; }",
            good: "function f(a) { if (a) { return 1; } return 0; }",
        }),
    },
    Rule {
        id: "js/inconsistent-return-types",
        name: "Functions should always return the same type",
        description: "A function returning a string on one path and a number on another is hard to use.",
        message: "Return one type.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3800")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(function_declaration) (function_expression) (arrow_function) (method_definition) (generator_function) (generator_function_declaration)] @match"#,
            filter: Some(Keep(returns_different_literal_types)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function f(a) { if (a) { return 'x'; } return 1; }",
            good: "function f(a) { if (a) { return 'x'; } return 'y'; }",
        }),
    },
    Rule {
        id: "js/for-in-over-array",
        name: "\"for in\" should not be used with iterables",
        description: "for...in visits indexes as strings, and inherited keys.",
        message: "Use for...of.",
        category: Bug,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S4139")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(for_in_statement) @match"#,
            filter: Some(Keep(for_in_over_an_array)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "for (const i in [1, 2, 3]) { f(i); }",
            good: "for (const i of [1, 2, 3]) { f(i); }",
        }),
    },
    Rule {
        id: "js/constructor-async",
        name: "Constructors should not contain asynchronous operations",
        description: "A constructor cannot wait, so the object is used before it is ready.",
        message: "Move the work to an async factory or init method.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S7059")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(method_definition name: (property_identifier) @n (#eq? @n "constructor")) @match"#,
            filter: Some(Find(async_work_in_constructor)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "class A { constructor() { fetch('/x'); } }",
            good: "class A { static async create() { await fetch('/x'); return new A(); } }",
        }),
    },
    Rule {
        id: "js/foreach-to-for-of",
        name: "Use \"for...of\" loops instead of \"forEach\" method calls",
        description: "for...of allows break, await and return.",
        message: "Use for...of.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 3,
        sonar: &[exact("S7728")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression property: (property_identifier) @p (#eq? @p "forEach"))) @match"#,
            filter: Some(Keep(foreach_with_a_callback)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "items.forEach((i) => f(i));",
            good: "for (const i of items) { f(i); }",
        }),
    },
    Rule {
        id: "js/top-level-await",
        name: "Top-level await should be preferred over promise chains and async wrappers",
        description: "In a module, an async IIFE is what await at the top level replaces.",
        message: "Use top-level await.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7785")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(program (expression_statement (call_expression)) @match)"#,
            filter: Some(Keep(is_async_iife_in_a_module)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "import x from 'x'; (async () => { await x(); })();",
            good: "import x from 'x'; await x();",
        }),
    },
    Rule {
        id: "js/prefer-starts-ends-with",
        name: "Ends of strings should be checked with \"startsWith()\" and \"endsWith()\"",
        description: "indexOf and slice comparisons say it the long way.",
        message: "Use startsWith or endsWith.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6557")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(binary_expression) @match"#,
            filter: Some(Keep(checks_a_string_end_by_hand)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (s.indexOf('a') === 0) { f(); }",
            good: "if (s.startsWith('a')) { f(); }",
        }),
    },
    Rule {
        id: "js/fluent-return-this",
        name: "Prefer the return type \"this\" in fluent interfaces",
        description: "A method returning its own class type loses the subclass.",
        message: "Declare the return type as this.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6565")],
        check: Check::Query {
            langs: TS,
            query: r#"(method_definition) @match"#,
            filter: Some(Keep(returns_this_typed_as_the_class)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "class A { set(): A { return this; } }",
            good: "class A { set(): this { return this; } }",
        }),
    },
    Rule {
        id: "js/boxed-return-type",
        name: "Primitive return types should be used",
        description: "Number, String and Boolean are the wrapper objects.",
        message: "Use number, string or boolean.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S4324")],
        check: Check::Query {
            langs: TS,
            query: r#"[(function_declaration return_type: (type_annotation (type_identifier) @match)) (method_definition return_type: (type_annotation (type_identifier) @match)) (arrow_function return_type: (type_annotation (type_identifier) @match))]"#,
            filter: Some(Keep(is_boxed_primitive)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "function f(): Number { return 1; }",
            good: "function f(): number { return 1; }",
        }),
    },
    Rule {
        id: "js/meaningless-intersection",
        name: "Type intersections should use meaningful types",
        description: "string & number has no values.",
        message: "Remove the impossible member.",
        category: Bug,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S4335")],
        check: Check::Query {
            langs: TS,
            query: r#"(intersection_type) @match"#,
            filter: Some(Keep(intersection_is_meaningless)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "type T = string & number;",
            good: "type T = string & { brand: 'a' };",
        }),
    },
    Rule {
        id: "js/undefined-for-optional-parameter",
        name: "\"undefined\" should not be passed as the value of optional parameters",
        description: "An omitted argument already means undefined.",
        message: "Omit the argument.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S4623")],
        check: Check::Query {
            langs: TS,
            query: r#"(call_expression function: (identifier) @f arguments: (arguments)) @match"#,
            filter: Some(Keep(passes_undefined_to_optional)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "function f(a: number, b?: number) {} f(1, undefined);",
            good: "function f(a: number, b?: number) {} f(1);",
        }),
    },
    Rule {
        id: "js/arguments-in-wrong-order",
        name: "Parameters should be passed in the correct order",
        description: "Passing the arguments swapped is a typo that compiles.",
        message: "Swap the arguments.",
        category: Bug,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S2234")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (identifier)) @match"#,
            filter: Some(Keep(arguments_are_swapped)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function area(width, height) {} const width = 1; const height = 2; area(height, width);",
            good: "function area(width, height) {} const width = 1; const height = 2; area(width, height);",
        }),
    },
    Rule {
        id: "js/selector-parameter",
        name: "Methods should not contain selector parameters",
        description: "A boolean flag that picks between two behaviours is two methods.",
        message: "Split the method.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S2301")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(function_declaration) (function_expression) (arrow_function) (method_definition) (generator_function) (generator_function_declaration)] @match"#,
            filter: Some(Keep(branches_on_a_boolean_parameter)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function f(flag = false) { if (flag) { g(); } else { h(); } }",
            good: "function f() { g(); }",
        }),
    },
    Rule {
        id: "js/test-without-assertion",
        name: "Tests should include assertions",
        description: "A test that asserts nothing passes whatever the code does.",
        message: "Add an assertion.",
        category: Bug,
        severity: Blocker,
        effort_minutes: 5,
        sonar: &[exact("S2699")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (identifier) @f (#any-of? @f "it" "test")) @match"#,
            filter: Some(Keep(test_has_no_assertion)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "it('works', () => { run(); });",
            good: "it('works', () => { expect(run()).toBe(1); });",
        }),
    },
    Rule {
        id: "js/assertion-incompatible-types",
        name: "Assertions comparing incompatible types should not be made",
        description: "expect(1).toBe('1') can never pass.",
        message: "Compare values of the same type.",
        category: Bug,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S5845")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression) @match"#,
            filter: Some(Keep(asserts_literals_of_different_types)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "expect(1).toBe('1');",
            good: "expect(1).toBe(1);",
        }),
    },
    Rule {
        id: "js/template-autoescape-disabled",
        name: "Auto-escaping in HTML template engines should not be disabled",
        description: "Without escaping, any value can inject markup.",
        message: "Leave auto-escaping on.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S5247")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(pair key: (property_identifier) @k value: (_) @v) @match"#,
            filter: Some(Keep(disables_escaping)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const html = Handlebars.compile(t, { noEscape: true });",
            good: "const html = Handlebars.compile(t);",
        }),
    },
];

// ------------------------------------------------------------- helpers

/// The kind of value a literal expression is, when it is one.
pub(super) fn literal_kind(node: Node) -> Option<&'static str> {
    let mut node = node;
    while node.kind() == "parenthesized_expression" {
        node = node.named_child(0)?;
    }
    Some(match node.kind() {
        "string" | "template_string" => "string",
        "number" => "number",
        "unary_expression" => {
            let arg = node.child_by_field_name("argument")?;
            match arg.kind() {
                "number" => "number",
                _ => return None,
            }
        }
        "true" | "false" => "boolean",
        "null" => "null",
        "undefined" => "undefined",
        "object" => "object",
        "array" => "array",
        "function_expression" | "arrow_function" | "function" => "function",
        "regex" => "regex",
        _ => return None,
    })
}

fn operands(binary: Node) -> Option<(Node, Node)> {
    Some((
        binary.child_by_field_name("left")?,
        binary.child_by_field_name("right")?,
    ))
}

fn is_module(node: Node) -> bool {
    let root = root_node(node);
    let mut cursor = root.walk();
    root.children(&mut cursor)
        .any(|c| matches!(c.kind(), "import_statement" | "export_statement"))
}

/// The function declaration named `name` in the file, when exactly one is.
fn declared_function<'t>(root: Node<'t>, name: &[u8], src: &[u8]) -> Option<Node<'t>> {
    let mut found: Vec<Node> = Vec::new();
    walk(root, &mut |n| {
        if n.kind() == "function_declaration"
            && n.child_by_field_name("name")
                .is_some_and(|x| text(x, src) == name)
        {
            found.push(n);
        }
        true
    });
    match found.as_slice() {
        [only] => Some(*only),
        _ => None,
    }
}

/// Every return statement of `function`, not looking into nested functions.
fn returns_of<'t>(function: Node<'t>) -> Vec<Node<'t>> {
    let mut out = Vec::new();
    if let Some(body) = function.child_by_field_name("body") {
        walk(body, &mut |n| {
            if is_function_kind(n.kind()) {
                return false;
            }
            if n.kind() == "return_statement" {
                out.push(n);
            }
            true
        });
    }
    out
}

// ------------------------------------------------------------- switch and blocks

fn lacks_default(switch: Node, _: &[u8]) -> bool {
    let Some(body) = switch.child_by_field_name("body") else {
        return false;
    };
    !named(body).iter().any(|c| c.kind() == "switch_default")
}

fn has_fewer_than_three_clauses(switch: Node, _: &[u8]) -> bool {
    let Some(body) = switch.child_by_field_name("body") else {
        return false;
    };
    named(body)
        .iter()
        .filter(|c| matches!(c.kind(), "switch_case" | "switch_default"))
        .count()
        < 3
}

fn declared_then_returned<'t>(block: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let statements = named(block);
    statements.windows(2).find_map(|w| {
        let (decl, next) = (w[0], w[1]);
        if !matches!(decl.kind(), "lexical_declaration" | "variable_declaration") {
            return None;
        }
        let declarators = named(decl);
        let [declarator] = declarators.as_slice() else {
            return None;
        };
        let name = declarator.child_by_field_name("name")?;
        declarator.child_by_field_name("value")?;
        if name.kind() != "identifier"
            || !matches!(next.kind(), "return_statement" | "throw_statement")
        {
            return None;
        }
        let returned = next.named_child(0)?;
        (returned.kind() == "identifier" && text(returned, src) == text(name, src)).then_some(decl)
    })
}

// ------------------------------------------------------------- bugs

fn array_declaration<'t>(root: Node<'t>, name: &[u8], src: &[u8]) -> Option<Node<'t>> {
    let mut found = None;
    walk(root, &mut |n| {
        if found.is_none()
            && n.kind() == "variable_declarator"
            && n.child_by_field_name("name")
                .is_some_and(|x| text(x, src) == name)
            && let Some(v) = n.child_by_field_name("value")
            && v.kind() == "array"
        {
            found = Some(v);
        }
        found.is_none()
    });
    found
}

fn deletes_by_index(unary: Node, src: &[u8]) -> bool {
    if !text(unary, src).starts_with(b"delete") {
        return false;
    }
    let Some(target) = unary.child_by_field_name("argument") else {
        return false;
    };
    let Some(index) = target.child_by_field_name("index") else {
        return false;
    };
    if index.kind() == "number" {
        return true;
    }
    target
        .child_by_field_name("object")
        .filter(|o| o.kind() == "identifier")
        .is_some_and(|o| array_declaration(root_node(unary), text(o, src), src).is_some())
}

fn sorts_numbers_by_default(call: Node, src: &[u8]) -> bool {
    if call
        .child_by_field_name("arguments")
        .is_some_and(|a| !named(a).is_empty())
    {
        return false;
    }
    let Some(receiver) = call
        .child_by_field_name("function")
        .and_then(|f| f.child_by_field_name("object"))
    else {
        return false;
    };
    let array = match receiver.kind() {
        "array" => Some(receiver),
        "identifier" => array_declaration(root_node(call), text(receiver, src), src),
        _ => None,
    };
    // `[...set].sort()`: what the spread yields is not known to be strings.
    array.is_some_and(|a| {
        named(a)
            .iter()
            .any(|e| literal_kind(*e) == Some("number") || e.kind() == "spread_element")
    })
}

fn constructor_is_an_arrow(new_expr: Node, src: &[u8]) -> bool {
    let Some(name) = new_expr.child_by_field_name("constructor") else {
        return false;
    };
    let mut arrow = false;
    walk(root_node(new_expr), &mut |n| {
        if n.kind() == "variable_declarator"
            && n.child_by_field_name("name")
                .is_some_and(|x| text(x, src) == text(name, src))
            && n.child_by_field_name("value")
                .is_some_and(|v| v.kind() == "arrow_function")
        {
            arrow = true;
        }
        !arrow
    });
    arrow
}

fn compares_a_string_literal(binary: Node, src: &[u8]) -> bool {
    if !matches!(operator_text(binary, src), b"<" | b">" | b"<=" | b">=") {
        return false;
    }
    operands(binary).is_some_and(|(l, r)| {
        literal_kind(l) == Some("string") || literal_kind(r) == Some("string")
    })
}

fn adds_string_to_literal(binary: Node, src: &[u8]) -> bool {
    if operator_text(binary, src) != b"+" {
        return false;
    }
    let Some((l, r)) = operands(binary) else {
        return false;
    };
    let (kl, kr) = (literal_kind(l), literal_kind(r));
    let plain = |k: Option<&str>| matches!(k, Some("number" | "boolean" | "null" | "undefined"));
    (kl == Some("string") && plain(kr)) || (kr == Some("string") && plain(kl))
}

fn is_top_level_require(call: Node, _: &[u8]) -> bool {
    ancestors_in_function(call).len() < 4
        && call.parent().is_some_and(|p| {
            matches!(
                p.kind(),
                "variable_declarator" | "expression_statement" | "member_expression"
            )
        })
}

const ARITHMETIC: &[&[u8]] = &[b"-", b"*", b"/", b"%", b"**"];

fn arithmetic_on_nan_operand(binary: Node, src: &[u8]) -> bool {
    if !ARITHMETIC.contains(&operator_text(binary, src)) {
        return false;
    }
    operands(binary).is_some_and(|(l, r)| {
        [l, r].iter().any(|o| {
            matches!(
                literal_kind(*o),
                Some("object" | "array" | "function" | "undefined" | "regex")
            )
        })
    })
}

fn arithmetic_on_non_number_operand(binary: Node, src: &[u8]) -> bool {
    if !ARITHMETIC.contains(&operator_text(binary, src)) {
        return false;
    }
    operands(binary).is_some_and(|(l, r)| {
        [l, r]
            .iter()
            .any(|o| matches!(literal_kind(*o), Some("string" | "boolean" | "null")))
    })
}

fn compares_a_non_number(binary: Node, src: &[u8]) -> bool {
    if !matches!(operator_text(binary, src), b"<" | b">" | b"<=" | b">=") {
        return false;
    }
    operands(binary).is_some_and(|(l, r)| {
        [l, r].iter().any(|o| {
            matches!(
                literal_kind(*o),
                Some("object" | "array" | "function" | "undefined" | "regex")
            )
        })
    })
}

fn returns_inconsistently(function: Node, _: &[u8]) -> bool {
    if has_token(function, "async") && function.child_by_field_name("body").is_none() {
        return false;
    }
    let returns = returns_of(function);
    let with_value = returns
        .iter()
        .filter(|r| r.named_child(0).is_some())
        .count();
    let bare = returns.len() - with_value;
    if with_value == 0 {
        return false;
    }
    if bare > 0 {
        return true;
    }
    // Falling off the end after a plain statement.
    let Some(body) = function
        .child_by_field_name("body")
        .filter(|b| b.kind() == "statement_block")
    else {
        return false;
    };
    named(body).last().is_some_and(|last| {
        matches!(
            last.kind(),
            "expression_statement" | "lexical_declaration" | "variable_declaration"
        )
    })
}

fn returns_different_literal_types(function: Node, _: &[u8]) -> bool {
    let mut kinds: Vec<&str> = Vec::new();
    for r in returns_of(function) {
        if let Some(kind) = r.named_child(0).and_then(literal_kind)
            && !matches!(kind, "null" | "undefined")
            && !kinds.contains(&kind)
        {
            kinds.push(kind);
        }
    }
    kinds.len() > 1
}

fn for_in_over_an_array(node: Node, src: &[u8]) -> bool {
    if node.child_by_field_name("operator").map(|o| text(o, src)) != Some(b"in") {
        return false;
    }
    let Some(right) = node.child_by_field_name("right") else {
        return false;
    };
    if right.kind() == "array" {
        return true;
    }
    if right.kind() != "identifier" {
        return false;
    }
    let mut array = false;
    walk(root_node(node), &mut |n| {
        if n.kind() == "variable_declarator"
            && n.child_by_field_name("name")
                .is_some_and(|x| text(x, src) == text(right, src))
            && n.child_by_field_name("value")
                .is_some_and(|v| v.kind() == "array")
        {
            array = true;
        }
        !array
    });
    array
}

fn async_work_in_constructor<'t>(constructor: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let body = constructor.child_by_field_name("body")?;
    let mut found = None;
    walk(body, &mut |n| {
        if found.is_some() || is_function_kind(n.kind()) {
            return false;
        }
        match n.kind() {
            "await_expression" => found = Some(n),
            "call_expression" => {
                let function = n.child_by_field_name("function");
                let promise_call = function.is_some_and(|f| {
                    text(f, src) == b"fetch"
                        || (f.kind() == "member_expression"
                            && f.child_by_field_name("property").is_some_and(|p| {
                                matches!(text(p, src), b"then" | b"catch" | b"finally")
                            }))
                });
                if promise_call {
                    found = Some(n);
                }
            }
            _ => {}
        }
        true
    });
    found
}

// ------------------------------------------------------------- style

fn foreach_with_a_callback(call: Node, _: &[u8]) -> bool {
    call.child_by_field_name("arguments").is_some_and(|a| {
        matches!(named(a).as_slice(), [only] if matches!(only.kind(), "arrow_function" | "function_expression"))
    })
}

fn is_async_iife_in_a_module(statement: Node, src: &[u8]) -> bool {
    // `main().catch(...)`: a promise chain on a call, in a module.
    if let Some(call) = statement
        .named_child(0)
        .filter(|c| c.kind() == "call_expression")
        && let Some(f) = call.child_by_field_name("function")
        && f.kind() == "member_expression"
        && f.child_by_field_name("property")
            .is_some_and(|p| matches!(text(p, src), b"catch" | b"then" | b"finally"))
        && f.child_by_field_name("object")
            .is_some_and(|o| o.kind() == "call_expression")
    {
        return is_module(statement);
    }
    let Some(function) = statement
        .named_child(0)
        .and_then(|c| c.child_by_field_name("function"))
        .and_then(|p| p.named_child(0))
    else {
        return false;
    };
    matches!(function.kind(), "arrow_function" | "function_expression")
        && has_token(function, "async")
        && is_module(statement)
}

fn checks_a_string_end_by_hand(binary: Node, src: &[u8]) -> bool {
    if !matches!(operator_text(binary, src), b"===" | b"==" | b"!==" | b"!=") {
        return false;
    }
    let Some((l, r)) = operands(binary) else {
        return false;
    };
    fn call_of<'t>(n: Node<'t>, src: &[u8]) -> Option<(Vec<u8>, Vec<Node<'t>>)> {
        if n.kind() != "call_expression" {
            return None;
        }
        let f = n.child_by_field_name("function")?;
        let name = text(f.child_by_field_name("property")?, src).to_vec();
        Some((name, named(n.child_by_field_name("arguments")?)))
    }
    let is_zero = |n: Option<&Node>| n.is_some_and(|n| text(*n, src) == b"0");
    for (call, other) in [(l, r), (r, l)] {
        let Some((name, args)) = call_of(call, src) else {
            continue;
        };
        match name.as_slice() {
            b"indexOf" | b"lastIndexOf" if args.len() == 1 && text(other, src) == b"0" => {
                return name == b"indexOf";
            }
            b"charAt" if is_zero(args.first()) && other.kind() == "string" => return true,
            b"slice" | b"substring" | b"substr"
                if args.len() == 2
                    && is_zero(args.first())
                    && literal_kind(other) == Some("string") =>
            {
                return true;
            }
            b"slice" if args.len() == 1 && args[0].kind() == "unary_expression" => {
                return literal_kind(other) == Some("string");
            }
            _ => {}
        }
    }
    false
}

// ------------------------------------------------------------- TypeScript

fn returns_this_typed_as_the_class(method: Node, src: &[u8]) -> bool {
    let Some(annotation) = method.child_by_field_name("return_type") else {
        return false;
    };
    let mut class = None;
    let mut cur = method.parent();
    while let Some(p) = cur {
        if p.kind() == "class_declaration" {
            class = p.child_by_field_name("name");
            break;
        }
        cur = p.parent();
    }
    let Some(class) = class else {
        return false;
    };
    let ty = text(annotation, src);
    if ty.strip_prefix(b": ") != Some(text(class, src)) {
        return false;
    }
    let returns = returns_of(method);
    !returns.is_empty()
        && returns
            .iter()
            .all(|r| r.named_child(0).is_some_and(|v| v.kind() == "this"))
}

fn is_boxed_primitive(name: Node, src: &[u8]) -> bool {
    matches!(
        text(name, src),
        b"Number" | b"String" | b"Boolean" | b"Symbol" | b"BigInt"
    )
}

fn intersection_is_meaningless(intersection: Node, src: &[u8]) -> bool {
    fn members<'t>(n: Node<'t>, out: &mut Vec<Node<'t>>) {
        if n.kind() == "intersection_type" {
            for c in named(n) {
                members(c, out);
            }
        } else {
            out.push(n);
        }
    }
    if intersection
        .parent()
        .is_some_and(|p| p.kind() == "intersection_type")
    {
        return false;
    }
    let mut all = Vec::new();
    members(intersection, &mut all);
    let primitive = |t: &[u8]| {
        matches!(
            t,
            b"string" | b"number" | b"boolean" | b"symbol" | b"bigint"
        )
    };
    let texts: Vec<&[u8]> = all.iter().map(|m| text(*m, src)).collect();
    if texts
        .iter()
        .any(|t| matches!(*t, b"null" | b"undefined" | b"never"))
    {
        return true;
    }
    let mut primitives: Vec<&[u8]> = texts.iter().copied().filter(|t| primitive(t)).collect();
    primitives.sort();
    primitives.dedup();
    primitives.len() > 1
}

/// The declared parameters of a function: name, and whether it is optional.
fn declared_parameters(function: Node, src: &[u8]) -> Vec<(Vec<u8>, bool)> {
    let Some(params) = function.child_by_field_name("parameters") else {
        return Vec::new();
    };
    named(params)
        .into_iter()
        .map(|p| {
            let name = p
                .child_by_field_name("pattern")
                .or_else(|| p.child_by_field_name("left"))
                .unwrap_or(p);
            let optional = p.kind() == "optional_parameter"
                || p.child_by_field_name("value").is_some()
                || p.kind() == "assignment_pattern";
            (text(name, src).to_vec(), optional)
        })
        .collect()
}

fn passes_undefined_to_optional(call: Node, src: &[u8]) -> bool {
    let (Some(callee), Some(arguments)) = (
        call.child_by_field_name("function"),
        call.child_by_field_name("arguments"),
    ) else {
        return false;
    };
    let args = named(arguments);
    let Some(last) = args.last() else {
        return false;
    };
    if text(*last, src) != b"undefined" {
        return false;
    }
    let Some(function) = declared_function(root_node(call), text(callee, src), src) else {
        return false;
    };
    declared_parameters(function, src)
        .get(args.len() - 1)
        .is_some_and(|(_, optional)| *optional)
}

fn arguments_are_swapped(call: Node, src: &[u8]) -> bool {
    let (Some(callee), Some(arguments)) = (
        call.child_by_field_name("function"),
        call.child_by_field_name("arguments"),
    ) else {
        return false;
    };
    let args = named(arguments);
    if args.len() < 2 || args.iter().any(|a| a.kind() != "identifier") {
        return false;
    }
    let Some(function) = declared_function(root_node(call), text(callee, src), src) else {
        return false;
    };
    let params = declared_parameters(function, src);
    if params.len() != args.len() {
        return false;
    }
    let names: Vec<&[u8]> = args.iter().map(|a| text(*a, src)).collect();
    let in_order = names
        .iter()
        .zip(&params)
        .all(|(a, (p, _))| *a == p.as_slice());
    let same_set = names
        .iter()
        .all(|a| params.iter().any(|(p, _)| p.as_slice() == *a))
        && params.iter().all(|(p, _)| names.contains(&p.as_slice()));
    same_set && !in_order
}

fn branches_on_a_boolean_parameter(function: Node, src: &[u8]) -> bool {
    let Some(params) = function.child_by_field_name("parameters") else {
        return false;
    };
    let flags: Vec<&[u8]> = named(params)
        .into_iter()
        .filter_map(|p| match p.kind() {
            "required_parameter" => {
                let typed = p
                    .child_by_field_name("type")
                    .is_some_and(|t| text(t, src) == b": boolean");
                let defaulted = p
                    .child_by_field_name("value")
                    .is_some_and(|v| matches!(v.kind(), "true" | "false"));
                (typed || defaulted)
                    .then(|| p.child_by_field_name("pattern").map(|n| text(n, src)))
                    .flatten()
            }
            "assignment_pattern" => {
                let v = p.child_by_field_name("right")?;
                matches!(v.kind(), "true" | "false")
                    .then(|| p.child_by_field_name("left").map(|n| text(n, src)))
                    .flatten()
            }
            _ => None,
        })
        .collect();
    if flags.is_empty() {
        return false;
    }
    let Some(body) = function.child_by_field_name("body") else {
        return false;
    };
    named(body).iter().any(|s| {
        s.kind() == "if_statement"
            && s.child_by_field_name("alternative").is_some()
            && s.child_by_field_name("condition")
                .and_then(|c| c.named_child(0))
                .is_some_and(|c| flags.contains(&text(c, src)))
    })
}

// ------------------------------------------------------------- tests

fn test_has_no_assertion(call: Node, src: &[u8]) -> bool {
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return false;
    };
    let args = named(arguments);
    let Some(callback) = args
        .get(1)
        .filter(|a| matches!(a.kind(), "arrow_function" | "function_expression"))
    else {
        return false;
    };
    // A `done` callback or a returned promise is checked by the framework.
    if callback
        .child_by_field_name("parameters")
        .is_some_and(|p| !named(p).is_empty())
        || callback.child_by_field_name("parameter").is_some()
    {
        return false;
    }
    let Some(body) = callback.child_by_field_name("body") else {
        return false;
    };
    if body.kind() != "statement_block" {
        return false;
    }
    let t = text(body, src);
    let lower = t.to_ascii_lowercase();
    ![
        &b"expect"[..],
        b"assert",
        b"should",
        b"fail",
        b"verify",
        b"check",
        b"throw",
        b"return",
        b"await",
    ]
    .iter()
    .any(|w| lower.windows(w.len()).any(|x| x == *w))
        && !named(body).is_empty()
}

fn asserts_literals_of_different_types(call: Node, src: &[u8]) -> bool {
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return false;
    };
    let args = named(arguments);
    let matcher = function
        .child_by_field_name("property")
        .map(|p| text(p, src))
        .unwrap_or_default();
    // expect(a).toBe(b) / expect(a).to.equal(b)
    if matches!(
        matcher,
        b"toBe" | b"toEqual" | b"toStrictEqual" | b"equal" | b"equals" | b"eql" | b"strictEqual"
    ) {
        let object = function.child_by_field_name("object");
        if let Some(expect) = object.and_then(find_expect_call)
            && let (Some(actual), [expected]) = (
                expect
                    .child_by_field_name("arguments")
                    .and_then(|a| a.named_child(0)),
                args.as_slice(),
            )
            && let (Some(a), Some(b)) = (literal_kind(actual), literal_kind(*expected))
        {
            return a != b && !matches!((a, b), ("null", "undefined") | ("undefined", "null"));
        }
        // assert.strictEqual(a, b)
        if matches!(matcher, b"strictEqual" | b"equal")
            && object.is_some_and(|o| text(o, src) == b"assert")
            && let [a, b] = args.as_slice()
            && let (Some(ka), Some(kb)) = (literal_kind(*a), literal_kind(*b))
        {
            return ka != kb && matcher == b"strictEqual";
        }
    }
    false
}

/// `expect(x)` at the root of a chain such as `expect(x).not.to`.
fn find_expect_call(node: Node) -> Option<Node> {
    let mut cur = node;
    loop {
        match cur.kind() {
            "call_expression" => {
                return cur
                    .child_by_field_name("function")
                    .filter(|f| f.kind() == "identifier")
                    .map(|_| cur);
            }
            "member_expression" => cur = cur.child_by_field_name("object")?,
            _ => return None,
        }
    }
}

fn disables_escaping(pair: Node, src: &[u8]) -> bool {
    let (Some(key), Some(value)) = (
        pair.child_by_field_name("key"),
        pair.child_by_field_name("value"),
    ) else {
        return false;
    };
    matches!(
        (text(key, src), text(value, src)),
        (b"noEscape", b"true") | (b"autoescape", b"false") | (b"autoEscape", b"false")
    )
}
