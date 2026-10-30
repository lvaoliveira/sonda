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
            query: r#"["==" "!="] @match"#,
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
        id: "js/jump-in-finally",
        name: "finally blocks should not return, throw, break or continue",
        description: "A jump out of a finally block discards whatever the try or catch block \
                      was doing: its return value or its exception is silently lost.",
        message: "This finally block returns, throws, breaks or continues, which discards the try block's result or exception. Move the jump out of it.",
        category: Bug,
        severity: Critical,
        effort_minutes: 15,
        sonar: &[exact("S1143")],
        check: Check::Query {
            langs: JS_TS,
            query: "(finally_clause body: (statement_block) @match)",
            filter: Some(jumps_out_of_finally),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function f() { try { return g(); } finally { return 0; } }",
            good: "function f() { try { return g(); } finally { for (;;) { break; } cleanup(); } }",
        }),
    },
    Rule {
        id: "js/no-with",
        name: "with statements should not be used",
        description: "Inside `with`, a bare name may refer to a property of the object or to a \
                      variable, depending on the object at run time. Strict mode forbids it.",
        message: "Replace this 'with' statement with a variable holding the object.",
        category: Bug,
        severity: Minor,
        effort_minutes: 10,
        sonar: &[exact("S1321")],
        check: Check::Query {
            langs: JS_TS,
            query: "(with_statement) @match",
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "with (config) { f(port); }",
            good: "const c = config; f(c.port);",
        }),
    },
    Rule {
        id: "js/duplicate-parameter",
        name: "Parameter names should be unique",
        description: "When two parameters share a name, the later one hides the earlier, \
                      whose argument becomes unreachable.",
        message: "Rename the duplicated parameter.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1536")],
        check: Check::Query {
            langs: JS_TS,
            query: "(formal_parameters) @match",
            filter: Some(has_duplicate_parameter),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function move(x, y, x) { return x + y; }",
            good: "function move(x, y, z) { return x + y + z; }",
        }),
    },
    Rule {
        id: "js/self-assignment",
        name: "Variables should not be assigned to themselves",
        description: "`x = x` has no effect. It usually means another variable or property was meant.",
        message: "Remove this self-assignment, or assign the value that was intended.",
        category: Bug,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S1656")],
        check: Check::Query {
            langs: JS_TS,
            query: "(assignment_expression) @match",
            filter: Some(assigns_itself),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "this.name = this.name;",
            good: "this.name = name;\nitems[i++] = items[i++];",
        }),
    },
    Rule {
        id: "js/identical-operands",
        name: "Both sides of an operator should not be identical",
        description: "`a === a`, `a - a` or `a && a` always give the same result, so one side \
                      is almost always a copy-paste mistake. `x !== x` (a NaN test) and \
                      `h & h` (a 32-bit integer conversion) are idioms and allowed.",
        message: "Both sides of this operator are the same; one of them is probably a typo.",
        category: Bug,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S1764")],
        check: Check::Query {
            langs: JS_TS,
            query: "(binary_expression) @match",
            filter: Some(operands_are_pure),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (a.length === a.length) { f(); }",
            good: "if (a.length === b.length) { f(); }\nconst r = next() - next();\nconst m = 1 << 1;",
        }),
    },
    Rule {
        id: "js/duplicate-condition",
        name: "Conditions in an if/else-if chain or switch should be unique",
        description: "A condition repeated further down an if/else-if chain, or a repeated \
                      switch case, can never be reached: the first one always wins.",
        message: "A condition here is repeated later in the same chain, so the later branch never runs. Fix or remove it.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1862")],
        check: Check::Query {
            langs: JS_TS,
            query: "[(if_statement) (switch_body)] @match",
            filter: Some(has_repeated_condition),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (x === 1) { a(); } else if (x === 2) { b(); } else if (x === 1) { c(); }",
            good: "if (x === 1) { a(); } else if (x === 2) { b(); }\nswitch (y) { case 1: a(); break; case 2: b(); }",
        }),
    },
    Rule {
        id: "js/nan-comparison",
        name: "NaN should not be compared with operators",
        description: "NaN is not equal to anything, itself included, so `x === NaN` is always false.",
        message: "Use Number.isNaN() instead of comparing with NaN.",
        category: Bug,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S2688")],
        check: Check::Query {
            langs: JS_TS,
            query: "(binary_expression) @match",
            filter: Some(compares_with_nan),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (value === NaN) { reset(); }",
            good: "if (Number.isNaN(value)) { reset(); }",
        }),
    },
    Rule {
        id: "js/reversed-compound-assignment",
        name: "'=+', '=-' and '=!' should not be used",
        description: "`x =+ 1` assigns `+1` to `x`; it was almost certainly meant as `x += 1`.",
        message: "Did you mean '+=', '-=' or '!='? Otherwise, put a space after '='.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2757")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(assignment_expression right: (unary_expression operator: ["+" "-" "!"]) @match)
                      (variable_declarator value: (unary_expression operator: ["+" "-" "!"]) @match)"#,
            filter: Some(glued_to_equals_sign),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "total =+ price;",
            good: "total += price;\nsign = -1;\nlet ready = !busy;",
        }),
    },
    Rule {
        id: "js/delete-variable",
        name: "delete should only be used on object properties",
        description: "`delete` removes properties. On a variable it does nothing (and is a \
                      syntax error in strict mode).",
        message: "Remove this 'delete'; set the variable to undefined, or delete a property instead.",
        category: Bug,
        severity: Minor,
        effort_minutes: 3,
        sonar: &[exact("S3001")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(unary_expression operator: "delete" argument: (identifier)) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "delete cache;",
            good: "delete cache[key];\ncache = undefined;",
        }),
    },
    Rule {
        id: "js/case-with-comma-or-or",
        name: "switch cases should not combine values with ',' or '||'",
        description: "`case 1, 2:` matches only 2, and `case a || b:` matches only the value of \
                      `a || b`. Neither matches any of the listed values.",
        message: "Write one 'case' per value, stacked on top of each other.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3616")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(switch_case value: [(sequence_expression) (binary_expression operator: "||")] @match)"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "switch (day) { case 'sat', 'sun': rest(); }",
            good: "switch (day) { case 'sat':\ncase 'sun': rest(); }",
        }),
    },
    Rule {
        id: "js/empty-destructuring",
        name: "Destructuring patterns should not be empty",
        description: "`const {} = obj` binds nothing. A default value was usually meant: \
                      `const { a = {} } = obj`.",
        message: "This pattern destructures nothing; name the properties to extract.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3799")],
        check: Check::Query {
            langs: JS_TS,
            query: "[(object_pattern) (array_pattern)] @match",
            filter: Some(empty_block),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const { options: {} } = settings;",
            good: "const { options = {} } = settings;\nconst [, second] = pair;",
        }),
    },
    Rule {
        id: "js/negated-in-instanceof",
        name: "Negated 'in' and 'instanceof' operands should be parenthesized",
        description: "`!key in obj` negates `key` first and then tests `false in obj`; \
                      `!a instanceof B` is always false.",
        message: "Wrap the whole test in parentheses: !(a instanceof B), !(key in obj).",
        category: Bug,
        severity: Critical,
        effort_minutes: 2,
        sonar: &[exact("S3812")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(binary_expression
                        left: (unary_expression operator: "!")
                        operator: ["in" "instanceof"]) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (!err instanceof TypeError) { retry(); }",
            good: "if (!(err instanceof TypeError)) { retry(); }",
        }),
    },
    Rule {
        id: "js/negated-equality-operand",
        name: "A negated operand should not be compared for equality",
        description: "`!a === b` compares the boolean `!a` with `b`, not `a` with `b`.",
        message: "Use 'a !== b', or parenthesize: !(a === b).",
        category: Bug,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S7736")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(binary_expression
                        left: (unary_expression operator: "!")
                        operator: ["==" "!=" "===" "!=="]) @match"#,
            filter: Some(negates_a_value),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (!status === 'ok') { warn(); }",
            good: "if (status !== 'ok') { warn(); }\nconst same = !a === !b;\nif (!0 === x || !!y === z) {}",
        }),
    },
    Rule {
        id: "js/new-symbol-bigint",
        name: "Symbol and BigInt should not be called with new",
        description: "Symbol() and BigInt() are functions, not constructors: `new` throws a TypeError.",
        message: "Remove 'new' and call the function directly.",
        category: Bug,
        severity: Critical,
        effort_minutes: 1,
        sonar: &[exact("S3834")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(new_expression constructor: (identifier) @c (#any-of? @c "Symbol" "BigInt")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const id = new Symbol('id');",
            good: "const id = Symbol('id');",
        }),
    },
    Rule {
        id: "js/invalid-typeof",
        name: "typeof should be compared with a type it can return",
        description: "typeof only returns \"undefined\", \"object\", \"boolean\", \"number\", \
                      \"bigint\", \"string\", \"symbol\" or \"function\"; a comparison with \
                      anything else is always false.",
        message: "Fix this type name: typeof can't return it, so the comparison is always false.",
        category: Bug,
        severity: Critical,
        effort_minutes: 2,
        sonar: &[exact("S4125")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(binary_expression
                        left: (unary_expression operator: "typeof")
                        operator: ["==" "!=" "===" "!=="]
                        right: (string) @match)
                      (binary_expression
                        left: (string) @match
                        operator: ["==" "!=" "===" "!=="]
                        right: (unary_expression operator: "typeof"))"#,
            filter: Some(not_a_typeof_result),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (typeof x === 'array') { f(); }",
            good: "if (typeof x === 'object') { f(); }\nif ('string' === typeof y) { g(); }",
        }),
    },
    Rule {
        id: "js/setter-return",
        name: "Setters should not return a value",
        description: "The value returned by a setter is discarded: `o.x = v` always evaluates to `v`.",
        message: "Remove the value from this setter's return statement.",
        category: Bug,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S2432")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(method_definition "set" body: (statement_block) @body) @match"#,
            filter: Some(setter_returns_a_value),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "class A { set x(v) { this._x = v; return this; } }",
            good: "class A { set x(v) { if (v == null) { return; } this._x = v; this.on(() => { return 1; }); } }",
        }),
    },
    Rule {
        id: "js/generator-without-yield",
        name: "Generators should yield",
        description: "A generator that never yields produces an empty sequence; it was \
                      probably meant to be a plain function, or a yield is missing.",
        message: "Add the missing 'yield', or make this a regular function.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3531")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(generator_function_declaration) (generator_function) (method_definition "*")] @match"#,
            filter: Some(generator_never_yields),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function* ids() { return [1, 2, 3]; }",
            good: "function* ids() { yield* [1, 2, 3]; }\nfunction* none() {}",
        }),
    },
    Rule {
        id: "js/duplicate-member",
        name: "Object literals and classes should not define a member twice",
        description: "When a key or member name repeats, the last definition silently replaces \
                      the earlier ones.",
        message: "This object or class defines the same member twice, and the later one silently replaces the earlier. Remove or rename one.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1534")],
        check: Check::Query {
            langs: JS_TS,
            query: "[(object) (class_body)] @match",
            filter: Some(has_duplicate_member),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const o = { port: 80, host: 'a', 'port': 8080 };",
            good: "const o = { port: 80, host: 'a', get v() { return 1; }, set v(x) {} };\n\
                   class A { static of() {} of() {} }",
        }),
    },
    Rule {
        id: "js/useless-increment",
        name: "A variable should not be assigned its own post-increment",
        description: "`i = i++` stores the old value back into `i`, so the increment is lost.",
        message: "Use 'i++' (or 'i += 1') on its own.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2123")],
        check: Check::Query {
            langs: JS_TS,
            query: "(assignment_expression
                        left: (identifier) @l
                        right: (update_expression argument: (identifier) @r) @match
                        (#eq? @l @r))",
            filter: Some(is_postfix),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "count = count++;",
            good: "count++;\nprev = count++;",
        }),
    },
    Rule {
        id: "js/for-wrong-direction",
        name: "A for loop should move its counter toward the end condition",
        description: "`for (i = 0; i < n; i--)` moves away from its bound, so the loop never \
                      ends or ends only on overflow.",
        message: "This update moves the counter away from the loop's bound; did you mean the opposite operator?",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2251")],
        check: Check::Query {
            langs: JS_TS,
            query: "(for_statement) @match",
            filter: Some(counter_moves_away_from_bound),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "for (let i = 0; i < n; i--) { f(i); }",
            good: "for (let i = 0; i < n; i++) { f(i); }\nfor (let i = n; i > 0; i -= 2) { f(i); }",
        }),
    },
    Rule {
        id: "js/identical-branches",
        name: "Every branch of a conditional should not do the same thing",
        description: "When all branches of an if/else chain or a ternary are identical, the \
                      condition is pointless, or one branch was meant to differ.",
        message: "All branches here are identical: remove the condition, or fix the branch that should differ.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S3923")],
        check: Check::Query {
            langs: JS_TS,
            query: "[(if_statement) (ternary_expression)] @match",
            filter: Some(all_branches_identical),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (fast) { run(); } else { run(); }",
            good: "if (fast) { run(); } else { walk(); }\nif (a) { run(); } else if (b) { run(); }",
        }),
    },
    Rule {
        id: "js/error-not-thrown",
        name: "Errors should be thrown, not just created",
        description: "`new Error(...)` on its own line creates an error and drops it. \
                      `throw` was almost certainly forgotten.",
        message: "Add 'throw' before this error, or remove it.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S3984")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(expression_statement
                        (new_expression constructor: (identifier) @c (#match? @c "Error$")) @match)"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (!ok) { new TypeError('bad input'); }",
            good: "if (!ok) { throw new TypeError('bad input'); }",
        }),
    },
    Rule {
        id: "js/literal-called",
        name: "Literals should not be called as functions",
        description: "Calling a string, number or other literal always throws a TypeError. It \
                      usually comes from a missing semicolon before a parenthesized line.",
        message: "This literal is called like a function: add the missing semicolon or operator before the parenthesis.",
        category: Bug,
        severity: Critical,
        effort_minutes: 2,
        sonar: &[exact("S6958")],
        check: Check::Query {
            langs: JS_TS,
            query: "(call_expression
                        function: [(string) (number) (true) (false) (null) (regex) (template_string)] @match)",
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const s = 'a'\n(items || []).forEach(f);",
            good: "const s = 'a';\n(items || []).forEach(f);\nconst q = sql`select 1`;",
        }),
    },
    Rule {
        id: "js/exclusive-test",
        name: "Exclusive tests should not be committed",
        description: "`it.only` and `describe.only` silently skip every other test in the run, \
                      so CI stays green while tests are ignored.",
        message: "Remove '.only' so the rest of the suite runs.",
        category: Bug,
        severity: Major,
        effort_minutes: 1,
        sonar: &[exact("S6426")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression
                        function: (member_expression
                          object: (identifier) @o
                          property: (property_identifier) @p) @match
                        (#any-of? @o "describe" "it" "test" "context" "suite")
                        (#eq? @p "only"))"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "it.only('adds', () => { add(1, 2); });",
            good: "it('adds', () => { add(1, 2); });\ntest.skip('later', () => {});",
        }),
    },
    Rule {
        id: "js/shadowed-builtin-name",
        name: "undefined, NaN, Infinity, eval and arguments should not be redefined",
        description: "Binding or assigning these names makes code that relies on their \
                      standard meaning misbehave. Strict mode rejects most such uses.",
        message: "Choose another name; this one hides a built-in that other code relies on.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2137")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"([(identifier) (undefined)] @match
                        (#any-of? @match "undefined" "NaN" "Infinity" "eval" "arguments"))"#,
            filter: Some(is_bound_or_assigned),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function f(arguments) { let undefined = 1; return arguments; }",
            good: "function f(...args) { const n = arguments.length; return undefined === n || isNaN(n); }",
        }),
    },
    Rule {
        id: "js/tls-unverified",
        name: "TLS certificate checks should not be turned off",
        description: "`rejectUnauthorized: false` accepts any certificate, so anyone on the \
                      network path can impersonate the server.",
        message: "Remove 'rejectUnauthorized: false'; trust a private CA with the 'ca' option instead.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 15,
        sonar: &[exact("S4830")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(pair
                        key: (_) @k
                        value: (false)
                        (#match? @k "^[\"']?rejectUnauthorized[\"']?$")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "https.request({ host, rejectUnauthorized: false });",
            good: "https.request({ host, ca: fs.readFileSync('ca.pem') });",
        }),
    },
    Rule {
        id: "js/weak-hash",
        name: "Weak hashing algorithms should not be used",
        description: "MD2, MD4, MD5, SHA-1 and RIPEMD-160 are broken for security purposes.",
        message: "Use a stronger algorithm such as SHA-256.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 15,
        sonar: &[exact("S4790")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"((string) @match
                        (#match? @match "(?i)^[\"'](md2|md4|md5|sha-?1|ripemd-?160)[\"']$"))"#,
            filter: Some(is_create_hash_algorithm),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "crypto.createHash('md5').update(password);",
            good: "crypto.createHash('sha256').update(data);",
        }),
    },
    Rule {
        id: "js/number-precision-loss",
        name: "Number literals should not lose precision",
        description: "Numbers are 64-bit floats: a literal with more precision than that, like \
                      9007199254740993, silently becomes a different number.",
        message: "This literal can't be represented exactly; use a BigInt (123n) or a string.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6534")],
        check: Check::Query {
            langs: JS_TS,
            query: "(number) @match",
            filter: Some(loses_precision),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const id = 9007199254740993;",
            good: "const id = 9007199254740993n;\nconst max = 9007199254740991;\nconst x = 0.1 + 1e21 + 0xFF;",
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

// ---------------------------------------------------- filters

/// Node kinds that start a new function body: walks stop at them, since a
/// `return` or `yield` inside belongs to the inner function.
const FUNCTIONS: &[&str] = &[
    "function_declaration",
    "function_expression",
    "function",
    "arrow_function",
    "method_definition",
    "generator_function_declaration",
    "generator_function",
    "class_static_block",
];

const EQUALITY: &[&str] = &["==", "!=", "===", "!=="];
const COMPARISONS: &[&str] = &["==", "!=", "===", "!==", "<", "<=", ">", ">="];

const LOOPS: &[&str] = &[
    "for_statement",
    "for_in_statement",
    "while_statement",
    "do_statement",
];

fn text<'a>(node: Node, src: &'a [u8]) -> &'a [u8] {
    &src[node.byte_range()]
}

/// Whether any node below `node`, not looking inside nested functions,
/// satisfies `pred`. Iterative, like every tree walk in sonda.
fn contains(node: Node, pred: impl Fn(Node) -> bool) -> bool {
    let mut cursor = node.walk();
    if !cursor.goto_first_child() {
        return false;
    }
    loop {
        let n = cursor.node();
        if pred(n) {
            return true;
        }
        if !FUNCTIONS.contains(&n.kind()) && cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return false;
            }
        }
    }
}

/// Whether `node` has an anonymous child token `token`, such as `set` or `*`.
fn has_token(node: Node, token: &str) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor).any(|c| c.kind() == token)
}

fn has_side_effects(node: Node) -> bool {
    let effect = |n: Node| {
        matches!(
            n.kind(),
            "call_expression"
                | "new_expression"
                | "update_expression"
                | "assignment_expression"
                | "augmented_assignment_expression"
                | "await_expression"
                | "yield_expression"
        )
    };
    effect(node) || contains(node, effect)
}

/// Whether a return, throw, break or continue leaves `block`. Walks down,
/// keeping the loops, switches and labels around the current node, since
/// looking up a node's parent costs a walk from the root.
fn jumps_out_of_finally(block: Node, src: &[u8]) -> bool {
    let mut around: Vec<(usize, Node)> = Vec::new();
    let mut cursor = block.walk();
    if !cursor.goto_first_child() {
        return false;
    }
    let mut depth = 1;
    loop {
        let n = cursor.node();
        while around.last().is_some_and(|(d, _)| *d >= depth) {
            around.pop();
        }
        match n.kind() {
            "return_statement" | "throw_statement" => return true,
            kind @ ("break_statement" | "continue_statement") => {
                let label = n
                    .named_child(0)
                    .filter(|l| l.kind() == "statement_identifier")
                    .map(|l| text(l, src));
                let stays = around.iter().any(|(_, a)| match label {
                    Some(l) => {
                        a.kind() == "labeled_statement"
                            && a.child_by_field_name("label").map(|x| text(x, src)) == Some(l)
                    }
                    None => {
                        LOOPS.contains(&a.kind())
                            || (kind == "break_statement" && a.kind() == "switch_statement")
                    }
                });
                if !stays {
                    return true;
                }
            }
            _ => {}
        }
        if !FUNCTIONS.contains(&n.kind()) && cursor.goto_first_child() {
            around.push((depth, n));
            depth += 1;
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return false;
            }
            depth -= 1;
        }
    }
}

fn has_duplicate_parameter(params: Node, src: &[u8]) -> bool {
    let mut names: Vec<&[u8]> = Vec::new();
    let mut cursor = params.walk();
    for p in params.named_children(&mut cursor) {
        // TypeScript wraps each parameter; a default or rest wraps the name.
        let p = match p.kind() {
            "required_parameter" | "optional_parameter" => match p.child_by_field_name("pattern") {
                Some(pattern) => pattern,
                None => continue,
            },
            _ => p,
        };
        let name = match p.kind() {
            "identifier" => Some(p),
            "assignment_pattern" => p.child_by_field_name("left"),
            "rest_pattern" => p.named_child(0),
            _ => None,
        };
        if let Some(name) = name.filter(|n| n.kind() == "identifier") {
            let name = text(name, src);
            if names.contains(&name) {
                return true;
            }
            names.push(name);
        }
    }
    false
}

/// Byte-equal source text, rejecting different lengths first: comparing
/// whole operands of a long `a + b + ...` chain would be quadratic.
fn same_text(a: Node, b: Node, src: &[u8]) -> bool {
    a.byte_range().len() == b.byte_range().len() && text(a, src) == text(b, src)
}

fn assigns_itself(assignment: Node, src: &[u8]) -> bool {
    match (
        assignment.child_by_field_name("left"),
        assignment.child_by_field_name("right"),
    ) {
        (Some(l), Some(r)) => same_text(l, r, src) && !has_side_effects(l),
        _ => false,
    }
}

fn operands_are_pure(expr: Node, src: &[u8]) -> bool {
    let (Some(left), Some(right)) = (
        expr.child_by_field_name("left"),
        expr.child_by_field_name("right"),
    ) else {
        return false;
    };
    let Some(op) = expr.child_by_field_name("operator").map(|o| o.kind()) else {
        return false;
    };
    // `x !== x` (or `x === x`) is the classic NaN test; `h & h` and `h | h`
    // convert to a 32-bit integer; `x + x` and `x * x` are fine.
    let nan_test = left.kind() == "identifier" && EQUALITY.contains(&op);
    (COMPARISONS.contains(&op)
        || matches!(
            op,
            "&&" | "||" | "??" | "-" | "/" | "%" | "^" | "instanceof" | "in"
        ))
        && same_text(left, right, src)
        && left.kind() != "number"
        && !nan_test
        && !has_side_effects(left)
}

/// For an if statement, whether its condition comes back further down its
/// else-if chain; for a switch, whether two cases test the same value.
fn has_repeated_condition(node: Node, src: &[u8]) -> bool {
    if node.kind() == "switch_body" {
        let mut seen = std::collections::HashSet::new();
        let mut cursor = node.walk();
        return node
            .named_children(&mut cursor)
            .filter_map(|case| case.child_by_field_name("value"))
            .any(|value| !seen.insert(text(value, src)));
    }
    let Some(cond) = node.child_by_field_name("condition") else {
        return false;
    };
    let mut current = node;
    for _ in 0..MAX_CHAIN {
        let Some(next) = else_if(current) else {
            break;
        };
        if next
            .child_by_field_name("condition")
            .is_some_and(|c| same_text(c, cond, src))
        {
            return true;
        }
        current = next;
    }
    false
}

/// How far down an else-if chain the checks look, so a generated chain of
/// thousands of branches costs n * MAX_CHAIN, not n squared.
const MAX_CHAIN: usize = 256;

/// The if statement in `if_statement`'s `else if`, if any.
fn else_if(if_statement: Node) -> Option<Node> {
    let else_clause = if_statement.child_by_field_name("alternative")?;
    let mut cursor = else_clause.walk();
    let body = else_clause
        .named_children(&mut cursor)
        .find(|c| c.kind() != "comment")?;
    (body.kind() == "if_statement").then_some(body)
}

fn compares_with_nan(expr: Node, src: &[u8]) -> bool {
    let is_nan = |field: &str| {
        expr.child_by_field_name(field).is_some_and(|n| {
            let t = text(n, src);
            t.len() <= 10 && (t == b"NaN" || t == b"Number.NaN")
        })
    };
    expr.child_by_field_name("operator")
        .is_some_and(|op| COMPARISONS.contains(&op.kind()))
        && (is_nan("left") || is_nan("right"))
}

/// The algorithm string is the first argument of a `.createHash(...)` call.
fn is_create_hash_algorithm(string: Node, src: &[u8]) -> bool {
    let Some(args) = string.parent().filter(|a| a.kind() == "arguments") else {
        return false;
    };
    args.named_child(0) == Some(string)
        && args
            .parent()
            .and_then(|call| call.child_by_field_name("function"))
            .and_then(|f| f.child_by_field_name("property"))
            .is_some_and(|p| text(p, src) == b"createHash")
}

fn glued_to_equals_sign(unary: Node, src: &[u8]) -> bool {
    let start = unary.start_byte();
    start >= 2 && src[start - 1] == b'=' && src[start - 2].is_ascii_whitespace()
}

fn is_negation(node: Node) -> bool {
    node.kind() == "unary_expression"
        && node
            .child_by_field_name("operator")
            .is_some_and(|op| op.kind() == "!")
}

/// `!a === b`, but not `!a === !b` (comparing two booleans), nor `!0`/`!1`
/// (minified true/false) or `!!a` (a conversion to boolean).
fn negates_a_value(expr: Node, _: &[u8]) -> bool {
    let operand = expr
        .child_by_field_name("left")
        .and_then(|l| l.child_by_field_name("argument"));
    operand.is_some_and(|o| o.kind() != "number" && !is_negation(o))
        && expr
            .child_by_field_name("right")
            .is_some_and(|r| !is_negation(r))
}

fn not_a_typeof_result(string: Node, src: &[u8]) -> bool {
    let quoted = text(string, src);
    let inner = &quoted[1..quoted.len().saturating_sub(1).max(1)];
    ![
        "undefined",
        "object",
        "boolean",
        "number",
        "bigint",
        "string",
        "symbol",
        "function",
        // Old Internet Explorer returned it for some host objects.
        "unknown",
    ]
    .iter()
    .any(|t| t.as_bytes() == inner)
}

fn setter_returns_a_value(setter: Node, _: &[u8]) -> bool {
    has_token(setter, "set")
        && setter.child_by_field_name("body").is_some_and(|body| {
            contains(body, |n| {
                n.kind() == "return_statement"
                    && n.named_child(0).is_some_and(|v| v.kind() != "comment")
            })
        })
}

fn generator_never_yields(function: Node, _: &[u8]) -> bool {
    if function.kind() == "method_definition" && !has_token(function, "*") {
        return false;
    }
    function.child_by_field_name("body").is_some_and(|body| {
        body.named_child_count() > 0 && !contains(body, |n| n.kind() == "yield_expression")
    })
}

/// The name a member of an object literal or class body defines, with
/// whether it's static. None for members that don't simply define a name:
/// accessors (a getter and a setter pair up), spreads, computed keys,
/// TypeScript overload signatures.
fn member_key(member: Node, src: &[u8]) -> Option<(bool, Vec<u8>)> {
    let key = match member.kind() {
        "pair" => member.child_by_field_name("key"),
        "shorthand_property_identifier" => Some(member),
        "method_definition" if !has_token(member, "get") && !has_token(member, "set") => {
            member.child_by_field_name("name")
        }
        "field_definition" => member.child_by_field_name("property"),
        "public_field_definition" => member.child_by_field_name("name"),
        _ => None,
    }?;
    let name = match key.kind() {
        "string" => {
            let quoted = text(key, src);
            quoted.get(1..quoted.len().checked_sub(1)?)?.to_vec()
        }
        "property_identifier"
        | "private_property_identifier"
        | "shorthand_property_identifier"
        | "number" => text(key, src).to_vec(),
        _ => return None,
    };
    Some((has_token(member, "static"), name))
}

fn has_duplicate_member(container: Node, src: &[u8]) -> bool {
    let mut seen = std::collections::HashSet::new();
    let mut cursor = container.walk();
    container
        .named_children(&mut cursor)
        .filter_map(|m| member_key(m, src))
        .any(|key| !seen.insert(key))
}

fn is_postfix(update: Node, _: &[u8]) -> bool {
    update
        .child(0)
        .is_some_and(|c| c.kind() != "++" && c.kind() != "--")
}

fn counter_moves_away_from_bound(for_statement: Node, src: &[u8]) -> bool {
    let (Some(cond), Some(update)) = (
        for_statement.child_by_field_name("condition"),
        for_statement.child_by_field_name("increment"),
    ) else {
        return false;
    };
    let cond = match cond.kind() {
        "expression_statement" => match cond.named_child(0) {
            Some(c) => c,
            None => return false,
        },
        _ => cond,
    };
    // The counter and the direction the update moves it.
    let (counter, increases) = match update.kind() {
        "update_expression" => {
            let Some(arg) = update.child_by_field_name("argument") else {
                return false;
            };
            (arg, has_token(update, "++"))
        }
        "augmented_assignment_expression" => {
            let (Some(left), Some(op), Some(right)) = (
                update.child_by_field_name("left"),
                update.child_by_field_name("operator"),
                update.child_by_field_name("right"),
            ) else {
                return false;
            };
            // Only constant steps: `i += step` may be negative.
            if right.kind() != "number" || !matches!(op.kind(), "+=" | "-=") {
                return false;
            }
            (left, op.kind() == "+=")
        }
        _ => return false,
    };
    if counter.kind() != "identifier" || cond.kind() != "binary_expression" {
        return false;
    }
    let (Some(left), Some(op), Some(right)) = (
        cond.child_by_field_name("left"),
        cond.child_by_field_name("operator"),
        cond.child_by_field_name("right"),
    ) else {
        return false;
    };
    let name = text(counter, src);
    // Whether the condition holds while the counter is below its bound.
    let below = match (op.kind(), text(left, src) == name, text(right, src) == name) {
        ("<" | "<=", true, false) | (">" | ">=", false, true) => true,
        (">" | ">=", true, false) | ("<" | "<=", false, true) => false,
        _ => return false,
    };
    below != increases
}

fn all_branches_identical(node: Node, src: &[u8]) -> bool {
    let Some(first) = node.child_by_field_name("consequence") else {
        return false;
    };
    if node.kind() == "ternary_expression" {
        return node
            .child_by_field_name("alternative")
            .is_some_and(|a| same_text(a, first, src));
    }
    let mut current = node;
    for _ in 0..MAX_CHAIN {
        if let Some(next) = else_if(current) {
            if next
                .child_by_field_name("consequence")
                .is_none_or(|c| !same_text(c, first, src))
            {
                return false;
            }
            current = next;
            continue;
        }
        let Some(else_clause) = current.child_by_field_name("alternative") else {
            return false; // no final else
        };
        let mut cursor = else_clause.walk();
        let same = else_clause
            .named_children(&mut cursor)
            .find(|c| c.kind() != "comment")
            .is_some_and(|body| same_text(body, first, src));
        // Only the head of an else-if chain reports. Looking up the parent
        // is costly, so it's checked last, on the rare identical chain.
        return same && node.parent().is_none_or(|p| p.kind() != "else_clause");
    }
    false
}

/// Kinds that only declare types: nothing in them runs.
const DECLARATIONS_ONLY: &[&str] = &[
    "ambient_declaration",
    "function_signature",
    "method_signature",
    "call_signature",
    "construct_signature",
    "abstract_method_signature",
];

fn is_bound_or_assigned(name: Node, _: &[u8]) -> bool {
    let Some(parent) = name.parent() else {
        return false;
    };
    let is_field = |field: &str| parent.child_by_field_name(field) == Some(name);
    let binds = match parent.kind() {
        "assignment_expression" | "augmented_assignment_expression" | "assignment_pattern" => {
            is_field("left")
        }
        "variable_declarator"
        | "function_declaration"
        | "function_expression"
        | "generator_function_declaration"
        | "generator_function"
        | "class_declaration" => is_field("name"),
        "required_parameter" | "optional_parameter" => is_field("pattern"),
        "catch_clause" => is_field("parameter"),
        "update_expression" | "formal_parameters" | "rest_pattern" | "array_pattern" => true,
        _ => false,
    };
    // Rare, so the walk up (each step costly) happens only here.
    let mut ancestor = Some(parent);
    while binds && let Some(a) = ancestor {
        if DECLARATIONS_ONLY.contains(&a.kind()) {
            return false;
        }
        ancestor = a.parent();
    }
    binds
}

fn loses_precision(number: Node, src: &[u8]) -> bool {
    let Ok(literal) = std::str::from_utf8(text(number, src)) else {
        return false;
    };
    let literal = literal.replace('_', "");
    let lower = literal.to_ascii_lowercase();
    if lower.ends_with('n') {
        return false; // BigInt
    }
    for (prefix, radix) in [("0x", 16), ("0o", 8), ("0b", 2)] {
        if let Some(digits) = lower.strip_prefix(prefix) {
            return u128::from_str_radix(digits, radix).is_ok_and(|v| (v as f64) as u128 != v);
        }
    }
    if lower.len() > 1 && lower.starts_with('0') && lower.as_bytes()[1].is_ascii_digit() {
        return false; // legacy octal
    }
    let Ok(value) = lower.parse::<f64>() else {
        return false;
    };
    // Compare significant digits: the literal's against the shortest
    // representation of the float it becomes.
    let significant = |s: &str| -> String {
        let mantissa = s.split('e').next().unwrap_or("");
        let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
        digits
            .trim_start_matches('0')
            .trim_end_matches('0')
            .to_string()
    };
    !value.is_finite() || significant(&lower) != significant(&format!("{value:e}"))
}

#[cfg(test)]
mod tests {
    use crate::analysis::analyze;
    use crate::analysis::tests::far_deadline;
    use crate::config::Config;
    use crate::lang::Lang;
    use crate::rules::RuleSet;

    /// The lines `rule` flags in `src`.
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
    fn jumps_out_of_finally() {
        let src = "outer: for (;;) {
  try { f(); } finally {
    throw e;
    break outer;
    inner: for (;;) { continue inner; }
    switch (x) { case 1: break; }
    g(() => { return 1; });
  }
}";
        assert_eq!(flagged("js/jump-in-finally", JS, src), [2]);
        let inner = "try { f(); } finally {\n  for (;;) { if (a) { break; } continue; }\n  l: { break l; }\n  switch (x) { case 1: break; }\n}";
        assert!(flagged("js/jump-in-finally", JS, inner).is_empty());
    }

    #[test]
    fn typescript_parameters_and_members() {
        let params = "function f(a: number, b?: string, ...a: number[]) {}";
        assert_eq!(flagged("js/duplicate-parameter", TS, params), [1]);
        // Overload signatures and accessor pairs are not duplicates.
        let class = "class A {\n  m(x: number): void;\n  m(x: any) {}\n  get v() { return 1; }\n  set v(x) {}\n  v2 = 1;\n  v2 = 2;\n}";
        assert_eq!(flagged("js/duplicate-member", TS, class), [1]);
        assert_eq!(
            flagged("js/empty-destructuring", TS, "function C({}: Props) {}"),
            [1]
        );
    }

    #[test]
    fn built_in_names() {
        let src = "undefined = 1;\ntry {} catch (eval) {}\nfunction f(NaN: number) {}\nconst x = undefined;\nobj.eval = f;";
        assert_eq!(flagged("js/shadowed-builtin-name", TS, src), [1, 2, 3]);
    }

    #[test]
    fn for_loop_direction() {
        let src = "for (i = 0; n > i; i--) {}\nfor (i = n; i >= 0; i += 1) {}\nfor (i = 0; i < n; i += step) {}\nfor (i = 0; i < n; j--) {}";
        assert_eq!(flagged("js/for-wrong-direction", JS, src), [1, 2]);
    }

    #[test]
    fn precision() {
        let src = "a = 0x20000000000001;\nb = 1.00000000000000001;\nc = 123456789012345678;\nd = 1e400;\ne = 9007199254740992;\nf = 0.30000000000000004;\ng = 1_000_000;\nh = 0777;";
        assert_eq!(flagged("js/number-precision-loss", JS, src), [1, 2, 3, 4]);
    }

    #[test]
    fn spacing_decides_reversed_operators() {
        let src = "x =- 1;\nx = -1;\nx=-1;\nlet y =! z;";
        assert_eq!(flagged("js/reversed-compound-assignment", JS, src), [1, 4]);
    }

    #[test]
    fn duplicate_conditions_need_the_same_chain() {
        let src = "if (a) {} else if (b) {} else if (a) {}\nif (a) { if (a) {} }\nswitch (x) { case 1: case 2: case 1: }";
        assert_eq!(flagged("js/duplicate-condition", JS, src), [1, 3]);
    }

    /// Shapes where a filter that looks up parents or siblings, or compares
    /// whole operands, goes quadratic.
    #[test]
    fn large_and_deep_code_stays_fast() {
        let n = 20_000;
        let keys: String = (0..n).map(|i| format!("k{i}: {i}, ")).collect();
        let sum: String = (0..n).map(|i| format!("a{i} + ")).collect();
        let cases: String = (0..5_000).map(|i| format!("case {i}: f(); ")).collect();
        let chain: String = (0..2_000)
            .map(|i| format!("if (x === {i}) {{ f(); }} else "))
            .collect();
        let nested = format!(
            "try {{}} finally {{ {}return; {} }}",
            "if (a) { ".repeat(2_000),
            "}".repeat(2_000)
        );
        let src = format!(
            "const o = {{ {keys} }};\nconst s = {sum}0;\nswitch (x) {{ {cases} }}\n{chain}{{ g(); }}\n{nested}\n"
        );
        let cfg = Config::default();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let file = analyze("t", JS, &src, &rules, &cfg, deadline).expect("finishes in time");
        assert!(file.issues.iter().any(|i| i.rule == "js/jump-in-finally"));
    }

    #[test]
    fn idioms_are_not_flagged() {
        let src = "a = x !== x;\nb = h & h;\nc = x.y !== x.y;\nd = !0 === e;\nf = !!g === h;\nif (typeof w === 'unknown') {}";
        assert_eq!(flagged("js/identical-operands", JS, src), [3]);
        assert!(flagged("js/negated-equality-operand", JS, src).is_empty());
        assert!(flagged("js/invalid-typeof", JS, src).is_empty());
        let dts = "declare var NaN: number;\ndeclare function f(...arguments: any[]): void;\ninterface I { m(eval: string): void; }";
        assert!(flagged("js/shadowed-builtin-name", TS, dts).is_empty());
    }

    #[test]
    fn identical_branches_need_an_else() {
        let src = "if (a) { f(); } else if (b) { f(); } else { f(); }\nif (a) { f(); } else if (b) { f(); }\nx = c ? 1 : 1;";
        assert_eq!(flagged("js/identical-branches", JS, src), [1, 3]);
    }
}
