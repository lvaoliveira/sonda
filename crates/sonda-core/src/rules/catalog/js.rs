//! JavaScript and TypeScript rules.

use super::*;

pub(super) static RULES: &[Rule] = &[
    // ---- JavaScript / TypeScript ----
    Rule {
        id: "js/no-eval",
        name: "eval() should not be used",
        description: "eval() executes arbitrary strings as code and is a common injection vector.",
        message: "Remove this use of eval().",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 30,
        sonar: &[related("S1523")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (identifier) @f (#eq? @f "eval")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "eval(userInput);",
            good: "JSON.parse(userInput);",
        }),
    },
    Rule {
        id: "js/no-new-function",
        name: "The Function constructor should not be used",
        description: "new Function(...) compiles strings into code, just like eval().",
        message: "Remove this use of the Function constructor.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 30,
        sonar: &[related("S1523")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(new_expression constructor: (identifier) @c (#eq? @c "Function")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const f = new Function('a', 'return a');",
            good: "const f = (a) => a;",
        }),
    },
    Rule {
        id: "js/inner-html",
        name: "HTML should not be assigned through innerHTML/outerHTML",
        description: "Assigning strings to innerHTML or outerHTML can lead to cross-site scripting.",
        message: "Avoid assigning to innerHTML/outerHTML; use textContent or DOM APIs.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 15,
        sonar: &[],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(assignment_expression
                        left: (member_expression property: (property_identifier) @p)
                        (#any-of? @p "innerHTML" "outerHTML")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "el.innerHTML = html;",
            good: "el.textContent = text;",
        }),
    },
    Rule {
        id: "js/eqeqeq",
        name: "Strict equality operators should be used",
        description: "`==` and `!=` perform type coercion with surprising results. \
                      Comparisons against `null`/`undefined` are allowed.",
        message: "Use '===' or '!==' instead.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1440")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(binary_expression operator: ["==" "!="] @match)"#,
            filter: Some(not_nullish_comparison),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (a == b) { f(); }",
            good: "if (a === b) { f(); }\nif (x == null) { g(); }",
        }),
    },
    Rule {
        id: "js/assignment-in-condition",
        name: "Assignments should not be used as conditions",
        description: "`if (x = y)` is almost always a typo for `===`. Wrap in extra parentheses if intended.",
        message: "Did you mean '==='? Move this assignment out of the condition.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[related("S1121")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(if_statement condition: (parenthesized_expression (assignment_expression) @match))"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (x = 5) { f(); }",
            good: "if (x === 5) { f(); }\nif ((m = re.exec(s))) { g(); }",
        }),
    },
    Rule {
        id: "js/no-debugger",
        name: "debugger statements should not be committed",
        description: "debugger statements pause execution in any open devtools.",
        message: "Remove this debugger statement.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 1,
        sonar: &[exact("S1525")],
        check: Check::Query {
            langs: JS_TS,
            query: "(debugger_statement) @match",
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function f() { debugger; }",
            good: "function f() { return 1; }",
        }),
    },
    Rule {
        id: "js/no-var",
        name: "let or const should be used instead of var",
        description: "var is function-scoped and hoisted, which causes subtle bugs.",
        message: "Use 'let' or 'const' instead of 'var'.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S3504")],
        check: Check::Query {
            langs: JS_TS,
            query: "(variable_declaration) @match",
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "var x = 1;",
            good: "let x = 1;\nconst y = 2;",
        }),
    },
    Rule {
        id: "js/empty-catch",
        name: "Exceptions should not be silently swallowed",
        description: "An empty catch block hides failures. Handle the error or explain with a comment.",
        message: "Handle this exception or add a comment explaining why it is ignored.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[related("S2486")],
        check: Check::Query {
            langs: JS_TS,
            query: "(catch_clause body: (statement_block) @match)",
            filter: Some(empty_block),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "try { f(); } catch (e) {}",
            good: "try { f(); } catch (e) { /* best effort */ }",
        }),
    },
    Rule {
        id: "js/no-console",
        name: "console calls should not be left in production code",
        description: "Use a proper logger instead of console.* calls.",
        message: "Replace this console call with a logger.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression
                        function: (member_expression object: (identifier) @o)
                        (#eq? @o "console")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "console.log('hi');",
            good: "logger.info('hi');",
        }),
    },
    Rule {
        id: "ts/no-explicit-any",
        name: "The 'any' type should not be used",
        description: "`any` disables type checking; prefer `unknown` or a precise type.",
        message: "Replace 'any' with a more specific type or 'unknown'.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S4204")],
        check: Check::Query {
            langs: TS,
            query: r#"((predefined_type) @match (#eq? @match "any"))"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "let x: any = 1;",
            good: "let x: unknown = 1;",
        }),
    },
];
