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
            filter: Some(Keep(not_nullish_comparison)),
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
            filter: Some(Keep(empty_block)),
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
        message: "Move this jump out of the finally block, so it can't discard the try block's result or exception.",
        category: Bug,
        severity: Critical,
        effort_minutes: 15,
        sonar: &[exact("S1143")],
        check: Check::Query {
            langs: JS_TS,
            query: "(finally_clause body: (statement_block) @match)",
            filter: Some(Find(jump_out_of_finally)),
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
            filter: Some(Keep(has_duplicate_parameter)),
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
            filter: Some(Keep(assigns_itself)),
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
            filter: Some(Keep(operands_are_pure)),
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
        message: "This condition repeats an earlier one in the same chain, so this branch never runs. Fix or remove it.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1862")],
        check: Check::Query {
            langs: JS_TS,
            query: "[(if_statement) (switch_body)] @match",
            filter: Some(Find(repeated_condition)),
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
            filter: Some(Keep(compares_with_nan)),
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
            filter: Some(Keep(glued_to_equals_sign)),
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
            filter: Some(Keep(empty_block)),
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
            filter: Some(Keep(negates_a_value)),
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
            filter: Some(Keep(not_a_typeof_result)),
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
            filter: Some(Keep(setter_returns_a_value)),
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
            filter: Some(Keep(generator_never_yields)),
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
        message: "Remove or rename this member: an earlier one has the same name and is overwritten.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1534")],
        check: Check::Query {
            langs: JS_TS,
            query: "[(object) (class_body)] @match",
            filter: Some(Find(duplicate_member)),
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
            filter: Some(Keep(is_postfix)),
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
            filter: Some(Keep(counter_moves_away_from_bound)),
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
            filter: Some(Keep(all_branches_identical)),
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
            filter: Some(Keep(is_bound_or_assigned)),
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
            filter: Some(Keep(is_create_hash_algorithm)),
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
            filter: Some(Keep(loses_precision)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const id = 9007199254740993;",
            good: "const id = 9007199254740993n;\nconst max = 9007199254740991;\nconst x = 0.1 + 1e21 + 0xFF;",
        }),
    },
    Rule {
        id: "js/empty-block",
        name: "Blocks should not be left empty",
        description: "An empty if, else, loop, try or finally block is usually unfinished \
                      code. If it's intended, a comment saying why makes that clear.",
        message: "Fill in this empty block, remove it, or add a comment explaining why it's empty.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S108")],
        check: Check::Query {
            langs: JS_TS,
            query: "(if_statement consequence: (statement_block) @match)
                    (else_clause (statement_block) @match)
                    (for_statement body: (statement_block) @match)
                    (for_in_statement body: (statement_block) @match)
                    (while_statement body: (statement_block) @match)
                    (do_statement body: (statement_block) @match)
                    (try_statement body: (statement_block) @match)
                    (finally_clause body: (statement_block) @match)
                    (switch_statement body: (switch_body) @match)",
            filter: Some(Keep(empty_block)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (ready) {} else { start(); }",
            good: "if (ready) { /* already started */ } else { start(); }\nfunction noop() {}",
        }),
    },
    Rule {
        id: "js/switch-fallthrough",
        name: "switch cases should not fall through",
        description: "A case without a break, return or throw at its end also runs the next \
                      case's code, which is rarely intended. Empty cases that share a body \
                      are fine, and so is a case followed by a comment that mentions falling \
                      through.",
        message: "End this case with 'break', 'return' or 'throw', or add a '// falls through' comment if that's intended.",
        category: CodeSmell,
        severity: Blocker,
        effort_minutes: 10,
        sonar: &[exact("S128")],
        check: Check::Query {
            langs: JS_TS,
            query: "(switch_body) @match",
            filter: Some(Find(falling_case)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "switch (x) { case 1: a(); case 2: b(); break; }",
            good: "switch (x) {\ncase 1:\ncase 2: b(); break;\ncase 3: c();\n// falls through\ncase 4: if (y) { return; } else { throw e; }\ndefault: d();\n}",
        }),
    },
    Rule {
        id: "js/equality-in-for-condition",
        name: "A for loop should not end on an equality test of its counter",
        description: "`for (i = 0; i !== 10; i += 3)` steps over 10 and never stops. A \
                      range test (`<`, `>`) ends the loop even when the counter skips the \
                      exact value.",
        message: "Use '<', '<=', '>' or '>=' to end this loop, so it stops even if the counter skips the value.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S888")],
        check: Check::Query {
            langs: JS_TS,
            query: "(for_statement) @match",
            filter: Some(Keep(counter_tested_for_equality)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "for (let i = 0; i !== 10; i += 3) { f(i); }",
            good: "for (let i = 0; i < 10; i += 3) { f(i); }\nfor (let n = head; n !== null; n = n.next) { f(n); }",
        }),
    },
    Rule {
        id: "js/no-label",
        name: "Labels should not be used",
        description: "Labeled breaks and continues jump across nested code and make control \
                      flow hard to follow. Extracting a function with an early return is \
                      usually clearer.",
        message: "Remove this label: restructure the loops, for example by extracting a function that returns early.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 20,
        sonar: &[exact("S1119")],
        check: Check::Query {
            langs: JS_TS,
            query: "(labeled_statement) @match",
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "outer: for (const a of rows) { for (const b of a) { if (b) { break outer; } } }",
            good: "for (const a of rows) { if (a.some(Boolean)) { break; } }",
        }),
    },
    Rule {
        id: "js/boolean-literal-comparison",
        name: "Booleans should not be compared with true or false",
        description: "`x == true` is a roundabout `x`, and with loose equality it can also \
                      match values that aren't booleans.",
        message: "Use the value directly ('x' or '!x') instead of comparing it with true or false.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[related("S1125")],
        check: Check::Query {
            langs: JS_TS,
            query: "(binary_expression) @match",
            filter: Some(Keep(loosely_compares_boolean_literal)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (done == true) { stop(); }",
            good: "if (done) { stop(); }\nif (flag === false) { start(); }",
        }),
    },
    Rule {
        id: "js/return-boolean-if",
        name: "A condition should be returned directly, not through if/else",
        description: "`if (c) { return true; } else { return false; }` is a long way to \
                      write `return c;`.",
        message: "Return the condition itself (or its negation) instead of true/false from each branch.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[related("S1126")],
        check: Check::Query {
            langs: JS_TS,
            query: "(if_statement) @match",
            filter: Some(Keep(returns_boolean_from_both_branches)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function big(a) { if (a > 10) { return true; } else { return false; } }",
            good: "function big(a) { return a > 10; }\nfunction g(a) { if (a) { return true; } else { return a === 0; } }",
        }),
    },
    Rule {
        id: "js/empty-function",
        name: "Functions should not be empty",
        description: "An empty function may be unfinished. If it's an intentional no-op, a \
                      comment inside says so. Arrow functions (common as callbacks) and \
                      constructors are not checked.",
        message: "Implement this function, or add a comment explaining why it's empty.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S1186")],
        check: Check::Query {
            langs: JS_TS,
            query: "[(function_declaration) (function_expression) (generator_function_declaration)
                     (generator_function) (method_definition)] @match",
            filter: Some(Keep(has_empty_body)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "class Cache { clear() {} }",
            good: "class Cache { clear() { /* nothing cached yet */ } constructor() {} }\nconst noop = () => {};",
        }),
    },
    Rule {
        id: "js/nested-block",
        name: "Code blocks should not be nested for no reason",
        description: "A bare `{ ... }` inside other code adds indentation and suggests a \
                      missing if or loop. Blocks inside switch cases, which scope `let` and \
                      `const`, are fine.",
        message: "Remove these braces, or extract the block into a function.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S1199")],
        check: Check::Query {
            langs: JS_TS,
            query: "[(statement_block) (program)] @match",
            filter: Some(Find(nested_block)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function f() { a(); { b(); } }",
            good: "function f() { a(); b(); }\nswitch (x) { case 1: { const y = 1; f(y); } }",
        }),
    },
    Rule {
        id: "js/label-in-switch",
        name: "switch statements should not contain labels",
        description: "A label inside a switch is usually a misspelled `default:` or a \
                      missing `case`, and it silently matches nothing. Labeled blocks and \
                      loops, which a `break label` can target, are fine.",
        message: "This is a label, not a case: did you mean 'case' or 'default'?",
        category: CodeSmell,
        severity: Blocker,
        effort_minutes: 5,
        sonar: &[exact("S1219")],
        check: Check::Query {
            langs: JS_TS,
            query: "(switch_case (labeled_statement) @match)
                    (switch_default (labeled_statement) @match)",
            filter: Some(Keep(labels_a_plain_statement)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "switch (x) { case 1: f(); break; defualt: g(); }",
            good: "switch (x) { case 1: f(); break; default: g(); }\nswitch (y) { case 2: done: if (z) { break done; } }",
        }),
    },
    Rule {
        id: "js/for-as-while",
        name: "A for loop with only a condition should be a while loop",
        description: "`for (; cond;)` has no initializer or update, which is exactly what \
                      `while (cond)` expresses more plainly.",
        message: "Replace this 'for' with 'while', since it has no initializer or update.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S1264")],
        check: Check::Query {
            langs: JS_TS,
            query: "(for_statement) @match",
            filter: Some(Keep(only_has_condition)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "for (; i < n;) { i = next(i); }",
            good: "while (i < n) { i = next(i); }\nfor (;;) { if (done()) { break; } }",
        }),
    },
    Rule {
        id: "js/octal-literal",
        name: "Legacy octal literals should not be used",
        description: "`0755` is octal, not 755, which surprises readers. Strict mode forbids \
                      it; `0o755` says it explicitly.",
        message: "Write this octal number with the '0o' prefix (0o755), or drop the leading zero if it's decimal.",
        category: CodeSmell,
        severity: Blocker,
        effort_minutes: 2,
        sonar: &[exact("S1314")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"((number) @match (#match? @match "^0[0-7]+$"))"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const mode = 0755;",
            good: "const mode = 0o755;\nconst zero = 0;\nconst half = 0.5;",
        }),
    },
    Rule {
        id: "js/octal-escape",
        name: "Octal escape sequences should not be used",
        description: "`\"\\251\"` is an octal escape, deprecated and forbidden in strict mode \
                      and template literals.",
        message: "Use a hexadecimal or Unicode escape instead, such as \\xA9 or \\u00A9.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6657")],
        check: Check::Query {
            langs: JS_TS,
            query: "(escape_sequence) @match",
            filter: Some(Keep(is_octal_escape)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const c = '\\251 2026';",
            good: "const c = '\\u00a9 2026';\nconst nul = '\\0';",
        }),
    },
    Rule {
        id: "js/call-arguments-new-line",
        name: "Call arguments should start on the same line as the function",
        description: "`a\\n(b)` is parsed as the call `a(b)`, which is rarely what was meant \
                      when a line starts with a parenthesis.",
        message: "Move this '(' to the line of the function it calls, or add a semicolon if the lines are separate statements.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S1472")],
        check: Check::Query {
            langs: JS_TS,
            query: "(call_expression) @match",
            filter: Some(Find(arguments_on_a_later_line)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const x = load\n(config);",
            good: "const x = load(\n  config,\n);\nconst y = tag\n`text`;",
        }),
    },
    Rule {
        id: "js/too-many-cases",
        name: "switch statements should not have too many cases",
        description: "A switch with more than 30 cases is hard to read and maintain; a \
                      lookup table (an object or a Map) is usually clearer.",
        message: "This switch has more than 30 cases; replace it with a lookup table.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 30,
        sonar: &[exact("S1479")],
        check: Check::Query {
            langs: JS_TS,
            query: "(switch_body) @match",
            filter: Some(Keep(has_too_many_cases)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "switch (x) { case 0: case 1: case 2: case 3: case 4: case 5: case 6: case 7: \
                  case 8: case 9: case 10: case 11: case 12: case 13: case 14: case 15: \
                  case 16: case 17: case 18: case 19: case 20: case 21: case 22: case 23: \
                  case 24: case 25: case 26: case 27: case 28: case 29: case 30: f(); }",
            good: "switch (x) { case 0: case 1: f(); break; default: g(); }",
        }),
    },
    Rule {
        id: "js/multiline-string",
        name: "Strings should not continue on the next line with a backslash",
        description: "A backslash at the end of a line continues the string, but any space \
                      after it breaks the code, and the indentation of the next line ends up \
                      in the string.",
        message: "Join the parts with '+' or use a template literal instead of a backslash line continuation.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S1516")],
        check: Check::Query {
            langs: JS_TS,
            query: "(string) @match",
            filter: Some(Keep(continues_on_next_line)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const s = 'one \\\ntwo';",
            good: "const s = 'one ' +\n  'two';\nconst t = `one\ntwo`;",
        }),
    },
    Rule {
        id: "js/primitive-wrapper",
        name: "Primitive wrapper objects should not be created",
        description: "`new String('a')` is an object, not a string: `typeof` says \"object\", \
                      it's always truthy (even `new Boolean(false)`), and `===` compares \
                      identity.",
        message: "Remove 'new': call String(), Number() or Boolean() to convert, or use a literal.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S1533")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(new_expression
                        constructor: (identifier) @c
                        (#any-of? @c "String" "Number" "Boolean")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const ok = new Boolean(false);",
            good: "const ok = Boolean(value);\nconst s = String(n);",
        }),
    },
    Rule {
        id: "js/default-param-not-last",
        name: "Parameters with defaults should come last",
        description: "A default followed by a required parameter can only be used by \
                      passing `undefined` explicitly.",
        message: "Move the parameters with default values after the required ones.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S1788")],
        check: Check::Query {
            langs: JS_TS,
            query: "(formal_parameters) @match",
            filter: Some(Find(default_before_required)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function connect(port = 80, host) {}",
            good: "function connect(host, port = 80) {}\nfunction g(a = 1, ...rest) {}",
        }),
    },
    Rule {
        id: "js/inverted-equality",
        name: "Equality checks should not be inverted",
        description: "`!(a === b)` is `a !== b` with an extra step.",
        message: "Use the opposite operator instead of negating the comparison: 'a !== b', not '!(a === b)'.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[related("S1940")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(unary_expression
                        operator: "!"
                        argument: (parenthesized_expression (binary_expression) @b)) @match"#,
            filter: Some(Keep(negates_an_equality)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (!(a === b)) { f(); }",
            good: "if (a !== b) { f(); }\nif (!(a < b)) { f(); }\nif (!(e instanceof E)) { f(); }",
        }),
    },
    Rule {
        id: "js/empty-class",
        name: "Classes should not be empty",
        description: "A class with no members does nothing a plain object couldn't. Classes \
                      that extend or implement something, or carry decorators, are fine.",
        message: "Add members to this class, or remove it.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S2094")],
        check: Check::Query {
            langs: JS_TS,
            query: "[(class_declaration) (class)] @match",
            filter: Some(Keep(is_empty_class)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "class Marker {}",
            good: "class Marker { id = 1; }\nclass NotFound extends Error {}",
        }),
    },
    Rule {
        id: "js/arguments-callee",
        name: "arguments.callee and arguments.caller should not be used",
        description: "Both are forbidden in strict mode and prevent engine optimizations.",
        message: "Refer to the function by name instead of arguments.callee or arguments.caller.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2685")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"((property_identifier) @match (#any-of? @match "callee" "caller"))"#,
            filter: Some(Keep(is_property_of_arguments)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function fact(n) { return n ? n * arguments.callee(n - 1) : 1; }",
            good: "function fact(n) { return n ? n * fact(n - 1) : 1; }\nconst c = opts.callee;",
        }),
    },
    Rule {
        id: "js/useless-catch",
        name: "catch clauses should do more than rethrow",
        description: "`catch (e) { throw e; }` changes nothing: the error would propagate \
                      the same way without it.",
        message: "Remove this catch clause, or handle the error before rethrowing it.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S2737")],
        check: Check::Query {
            langs: JS_TS,
            query: "(catch_clause
                        parameter: (identifier) @p
                        body: (statement_block . (throw_statement (identifier) @t) .)
                        (#eq? @p @t)) @match",
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "try { f(); } catch (e) { throw e; }",
            good: "try { f(); } catch (e) { log(e); throw e; }\ntry { f(); } catch (e) { throw new Wrapped(e); }",
        }),
    },
    Rule {
        id: "js/nested-ternary",
        name: "Ternary operators should not be nested",
        description: "`a ? x : b ? y : z` packs several decisions into one expression; an \
                      if/else chain or a lookup is easier to read.",
        message: "Extract the nested ternary into an if/else chain, a separate variable or a lookup.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3358")],
        check: Check::Query {
            langs: JS_TS,
            query: "(ternary_expression) @match",
            filter: Some(Keep(has_nested_ternary)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const size = n > 100 ? 'big' : n > 10 ? 'medium' : 'small';",
            good: "const size = n > 100 ? 'big' : 'small';\nconst f = a ? g(() => (b ? 1 : 2)) : 3;",
        }),
    },
    Rule {
        id: "js/redundant-jump",
        name: "Jumps should not be redundant",
        description: "A bare `return;` at the end of a function, or `continue;` at the end \
                      of a loop body, does nothing.",
        message: "Remove this redundant jump.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S3626")],
        check: Check::Query {
            langs: JS_TS,
            query: "(function_declaration body: (statement_block (return_statement) @match .))
                    (function_expression body: (statement_block (return_statement) @match .))
                    (arrow_function body: (statement_block (return_statement) @match .))
                    (method_definition body: (statement_block (return_statement) @match .))
                    (generator_function_declaration body: (statement_block (return_statement) @match .))
                    (generator_function body: (statement_block (return_statement) @match .))
                    (for_statement body: (statement_block (continue_statement) @match .))
                    (for_in_statement body: (statement_block (continue_statement) @match .))
                    (while_statement body: (statement_block (continue_statement) @match .))
                    (do_statement body: (statement_block (continue_statement) @match .))",
            filter: Some(Keep(is_bare_jump)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function f() { g(); return; }",
            good: "function f() { if (a) { return; } g(); }\nfor (const x of xs) { if (x) { continue; } g(x); }",
        }),
    },
    Rule {
        id: "js/throw-literal",
        name: "Literals should not be thrown",
        description: "A thrown string or number has no stack trace, and code that catches it \
                      can't rely on `error.message` or `instanceof Error`.",
        message: "Throw an Error object instead: throw new Error('...').",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3696")],
        check: Check::Query {
            langs: JS_TS,
            query: "(throw_statement
                        [(string) (template_string) (number) (true) (false) (null) (undefined)] @match)",
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "throw 'not found';",
            good: "throw new Error('not found');\nthrow err;",
        }),
    },
    Rule {
        id: "js/sparse-array",
        name: "Array literals should not have holes",
        description: "`[1, , 3]` creates an empty slot that iteration methods skip, and the \
                      extra comma is easy to miss or mistake for a typo.",
        message: "Remove the extra comma, or write 'undefined' explicitly.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S4140")],
        check: Check::Query {
            langs: JS_TS,
            query: "(array) @match",
            filter: Some(Keep(has_hole)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const a = [1, , 3];",
            good: "const a = [1, undefined, 3];\nconst b = [1, 2,];",
        }),
    },
    Rule {
        id: "js/default-not-last",
        name: "The default clause should be last",
        description: "A `default` in the middle of a switch reads like the end of it; \
                      readers expect it last.",
        message: "Move this 'default' clause to the end of the switch.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S4524")],
        check: Check::Query {
            langs: JS_TS,
            query: "(switch_body) @match",
            filter: Some(Find(default_before_a_case)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "switch (x) { default: f(); break; case 1: g(); }",
            good: "switch (x) { case 1: g(); break; default: f(); }",
        }),
    },
    Rule {
        id: "js/lonely-if",
        name: "An if should not be the only statement in an else block",
        description: "`else { if (b) { ... } }` is `else if (b) { ... }` with an extra level \
                      of nesting.",
        message: "Merge this 'if' into the 'else' as 'else if'.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6660")],
        check: Check::Query {
            langs: JS_TS,
            query: "(else_clause (statement_block . (if_statement) @match .))",
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (a) { f(); } else { if (b) { g(); } }",
            good: "if (a) { f(); } else if (b) { g(); }\nif (a) { f(); } else { if (b) { g(); } h(); }",
        }),
    },
    Rule {
        id: "js/declaration-in-case",
        name: "case clauses should not declare let, const, class or function directly",
        description: "Declarations in one case are visible in the whole switch, but only \
                      initialized when that case runs, so using them from another case \
                      throws.",
        message: "Wrap this case's body in braces, so the declaration stays local to it.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6836")],
        check: Check::Query {
            langs: JS_TS,
            query: "(switch_case [(lexical_declaration) (class_declaration) (function_declaration)] @match)
                    (switch_default [(lexical_declaration) (class_declaration) (function_declaration)] @match)",
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "switch (x) { case 1: const y = 2; f(y); }",
            good: "switch (x) { case 1: { const y = 2; f(y); } }",
        }),
    },
    Rule {
        id: "js/rename-to-same-name",
        name: "Imports, exports and destructuring should not rename to the same name",
        description: "`import { a as a }` or `const { k: k } = o` renames nothing.",
        message: "Remove the redundant rename.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S6650")],
        check: Check::Query {
            langs: JS_TS,
            query: "(import_specifier name: (_) @a alias: (_) @b (#eq? @a @b)) @match
                    (export_specifier name: (_) @a alias: (_) @b (#eq? @a @b)) @match
                    (pair_pattern key: (property_identifier) @a value: (identifier) @b (#eq? @a @b)) @match",
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "import { load as load } from './io';",
            good: "import { load as read } from './io';\nconst { k } = o;\nconst { k: key } = o;",
        }),
    },
    Rule {
        id: "js/proto-property",
        name: "__proto__ should not be used",
        description: "`__proto__` is a legacy accessor. Object.getPrototypeOf, \
                      Object.setPrototypeOf and Object.create say the same thing in standard \
                      terms.",
        message: "Use Object.getPrototypeOf(), Object.setPrototypeOf() or Object.create() instead of __proto__.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S6654")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"((property_identifier) @match (#eq? @match "__proto__"))"#,
            filter: Some(Keep(is_member_property)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const p = obj.__proto__;",
            good: "const p = Object.getPrototypeOf(obj);",
        }),
    },
    Rule {
        id: "js/global-isnan",
        name: "Number.isNaN() should be used instead of isNaN()",
        description: "The global isNaN() converts its argument first, so `isNaN('abc')` is \
                      true. Number.isNaN() only says whether the value is NaN.",
        message: "Use Number.isNaN(), which doesn't convert its argument to a number first.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6679")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (identifier) @f (#eq? @f "isNaN")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (isNaN(value)) { reset(); }",
            good: "if (Number.isNaN(value)) { reset(); }",
        }),
    },
    Rule {
        id: "js/eslint-disable-all",
        name: "eslint-disable comments should name the rules they disable",
        description: "A bare `eslint-disable` turns off every rule, hiding problems nobody \
                      meant to accept.",
        message: "Name the rules this comment disables, e.g. 'eslint-disable-next-line no-console'.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S7724")],
        check: Check::Query {
            langs: JS_TS,
            query: "(comment) @match",
            filter: Some(Keep(disables_every_eslint_rule)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "/* eslint-disable */\nf();",
            good: "/* eslint-disable no-console */\n// eslint-disable-next-line no-alert -- legacy prompt\nf(); // see the eslint-disable docs",
        }),
    },
    Rule {
        id: "js/init-to-undefined",
        name: "Variables should not be initialized to undefined",
        description: "`let x = undefined;` is what `let x;` already does.",
        message: "Remove '= undefined': the variable is already undefined.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S6645")],
        check: Check::Query {
            langs: JS_TS,
            query: "(variable_declarator value: (undefined) @match)",
            filter: Some(Keep(declared_without_const)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "let current = undefined;",
            good: "let current;\nconst none = undefined;",
        }),
    },
    Rule {
        id: "js/trim-left-right",
        name: "trimStart() and trimEnd() should be used instead of trimLeft() and trimRight()",
        description: "trimLeft() and trimRight() are legacy aliases kept for compatibility.",
        message: "Use trimStart() or trimEnd(), the standard names.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 1,
        sonar: &[exact("S7783")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"((property_identifier) @match (#any-of? @match "trimLeft" "trimRight"))"#,
            filter: Some(Keep(is_member_property)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const s = input.trimLeft();",
            good: "const s = input.trimStart();",
        }),
    },
    // ---- React ----
    Rule {
        id: "js/jsx-comment-as-text",
        name: "Comments in JSX should be inside braces",
        description: "In JSX, `// note` between tags is text, not a comment: it's rendered \
                      on the page.",
        message: "Wrap this comment in braces, {/* like this */}, or it is rendered as text.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6438")],
        check: Check::Query {
            langs: JSX,
            query: "(jsx_text) @match",
            filter: Some(Keep(text_looks_like_comment)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const v = <div>\n  // the user's name\n  {name}\n</div>;",
            good: "const v = <div>\n  {/* the user's name */}\n  {name}\n</div>;\nconst u = <a href=\"x\">see http://example.com</a>;",
        }),
    },
    Rule {
        id: "js/jsx-missing-key",
        name: "Elements rendered from a list should have a key",
        description: "React uses `key` to match list items between renders. Without it, \
                      items can lose their state or be re-rendered needlessly when the list \
                      changes.",
        message: "Add a 'key' prop that identifies this item, such as its id.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6477")],
        check: Check::Query {
            langs: JSX,
            query: r#"((property_identifier) @match (#eq? @match "map"))"#,
            filter: Some(Find(mapped_element_without_key)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const v = <ul>{rows.map((r) => <li>{r.name}</li>)}</ul>;",
            good: "const v = <ul>{rows.map((r) => <li key={r.id}>{r.name}</li>)}</ul>;\nconst w = rows.map((r) => { return <Row key={r.id} {...r} />; });",
        }),
    },
    Rule {
        id: "js/jsx-index-key",
        name: "Array indexes should not be used as keys",
        description: "An index identifies a position, not an item: when the list is \
                      reordered, filtered or prepended, React matches the wrong items and \
                      their state moves with the position.",
        message: "Use a stable id from the item as its key, not the array index.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6479")],
        check: Check::Query {
            langs: JSX,
            query: r#"((property_identifier) @match (#eq? @match "map"))"#,
            filter: Some(Find(mapped_element_keyed_by_index)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const v = rows.map((r, i) => <li key={i}>{r.name}</li>);",
            good: "const v = rows.map((r, i) => <li key={r.id}>{i + 1}. {r.name}</li>);",
        }),
    },
    Rule {
        id: "js/children-with-inner-html",
        name: "children and dangerouslySetInnerHTML should not be used together",
        description: "React throws when an element has both children and \
                      dangerouslySetInnerHTML.",
        message: "Use either children or dangerouslySetInnerHTML on this element, not both.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6761")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_attribute (property_identifier) @a (#eq? @a "dangerouslySetInnerHTML")) @match"#,
            filter: Some(Keep(element_also_has_children)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const v = <div dangerouslySetInnerHTML={{ __html: html }}>fallback</div>;",
            good: "const v = <div dangerouslySetInnerHTML={{ __html: html }} />;",
        }),
    },
    Rule {
        id: "js/children-prop",
        name: "children should be nested, not passed as a prop",
        description: "`<Box children={x} />` hides the content in an attribute; nesting it \
                      is the idiom readers expect, and both together conflict.",
        message: "Nest the content between the tags instead of passing a 'children' prop.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6748")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_attribute (property_identifier) @a (#eq? @a "children")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const v = <Box children={<Title />} />;",
            good: "const v = <Box><Title /></Box>;",
        }),
    },
    Rule {
        id: "js/redundant-fragment",
        name: "Fragments around a single element should be removed",
        description: "A fragment exists to group several children; around one element it \
                      only adds nesting. Fragments with a key are needed and fine.",
        message: "Remove this fragment: it wraps a single element.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S6749")],
        check: Check::Query {
            langs: JSX,
            query: "(jsx_element) @match",
            filter: Some(Keep(is_redundant_fragment)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const v = <><Header /></>;",
            good: "const v = <><Header /><Body /></>;\nconst w = <Fragment key={id}><Row /></Fragment>;\nconst t = <>{label}</>;",
        }),
    },
    Rule {
        id: "js/find-dom-node",
        name: "findDOMNode should not be used",
        description: "findDOMNode breaks component abstraction, is deprecated, and is \
                      removed in React 19. A ref on the element gives the DOM node.",
        message: "Attach a ref to the element instead of calling findDOMNode().",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 15,
        sonar: &[exact("S6788")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"([(identifier) (property_identifier)] @match (#eq? @match "findDOMNode"))"#,
            filter: Some(Keep(is_called)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const node = ReactDOM.findDOMNode(this);",
            good: "const node = this.ref.current;",
        }),
    },
    Rule {
        id: "js/is-mounted",
        name: "isMounted should not be used",
        description: "`this.isMounted()` is deprecated and hides leaks: cancel subscriptions \
                      and requests in componentWillUnmount instead.",
        message: "Remove isMounted(): cancel pending work when the component unmounts instead.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 15,
        sonar: &[exact("S6789")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"((property_identifier) @match (#eq? @match "isMounted"))"#,
            filter: Some(Keep(is_called_on_this)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (this.isMounted()) { this.setState({ data }); }",
            good: "componentWillUnmount() { this.request.abort(); }",
        }),
    },
    Rule {
        id: "js/string-ref",
        name: "String refs should not be used",
        description: "`ref=\"name\"` is a legacy API, removed in React 19. Use useRef or \
                      createRef, or a callback ref.",
        message: "Replace this string ref with useRef(), createRef() or a callback ref.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S6790")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_attribute (property_identifier) @a (string) (#eq? @a "ref")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const v = <input ref=\"name\" />;",
            good: "const v = <input ref={nameRef} />;",
        }),
    },
    Rule {
        id: "js/legacy-lifecycle",
        name: "Legacy React lifecycle methods should not be used",
        description: "componentWillMount, componentWillReceiveProps and componentWillUpdate \
                      are unsafe with async rendering and removed in React 19.",
        message: "Move this logic to componentDidMount, componentDidUpdate or getDerivedStateFromProps.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 30,
        sonar: &[exact("S6791")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(method_definition
                        name: (property_identifier) @n
                        (#any-of? @n "componentWillMount" "componentWillReceiveProps" "componentWillUpdate")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "class A extends Component { componentWillMount() { this.load(); } }",
            good: "class A extends Component { componentDidMount() { this.load(); } }",
        }),
    },
    Rule {
        id: "js/state-mutation",
        name: "this.state should not be changed directly",
        description: "Assigning to `this.state` outside the constructor doesn't re-render \
                      and is overwritten by the next setState.",
        message: "Call this.setState() instead of assigning to this.state.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6746")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(member_expression object: (this) property: (property_identifier) @p (#eq? @p "state")) @match"#,
            filter: Some(Find(state_assignment_outside_constructor)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "class A extends Component { onClick() { this.state.count = 1; } }",
            good: "class A extends Component { constructor(p) { super(p); this.state = { count: 0 }; } onClick() { this.setState({ count: 1 }); } }",
        }),
    },
    Rule {
        id: "js/set-state-from-state",
        name: "setState should use a callback when it reads this.state",
        description: "State updates are batched, so `this.state` may already be stale when \
                      the update applies. The callback form receives the current state.",
        message: "Pass a function to setState, (prev) => ({ ... }), instead of reading this.state.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6756")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"((property_identifier) @match (#eq? @match "setState"))"#,
            filter: Some(Find(set_state_reading_state)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "this.setState({ count: this.state.count + 1 });",
            good: "this.setState((prev) => ({ count: prev.count + 1 }));\nthis.setState({ open: true });",
        }),
    },
    Rule {
        id: "js/state-setter-same-value",
        name: "A state setter should not be called with its own state",
        description: "`setCount(count)` sets the state to the value it already has: nothing \
                      happens. Another value was probably meant.",
        message: "This sets the state to its current value; pass the new value instead.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6443")],
        check: Check::Query {
            langs: JS_TS,
            query: "(variable_declarator name: (array_pattern) value: (call_expression)) @match",
            filter: Some(Find(setter_called_with_own_state)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function C() { const [open, setOpen] = useState(false); return <b onClick={() => setOpen(open)} />; }",
            good: "function C() { const [open, setOpen] = useState(false); return <b onClick={() => setOpen(!open)} />; }",
        }),
    },
    Rule {
        id: "js/set-state-in-render",
        name: "State setters should not be called while rendering",
        description: "Calling a useState setter in the component body triggers another \
                      render, which calls it again: an infinite loop. Call it from an event \
                      handler or an effect.",
        message: "Move this state update into an event handler or a useEffect.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S6442")],
        check: Check::Query {
            langs: JS_TS,
            query: "(variable_declarator name: (array_pattern) value: (call_expression)) @match",
            filter: Some(Find(setter_called_in_render)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function C({ v }) { const [x, setX] = useState(0); setX(v); return x; }",
            good: "function C({ v }) { const [x, setX] = useState(0); useEffect(() => { setX(v); }, [v]); return x; }",
        }),
    },
    Rule {
        id: "js/use-state-naming",
        name: "useState results should be destructured as [value, setValue]",
        description: "The `[thing, setThing]` convention tells readers which setter belongs \
                      to which state at a glance.",
        message: "Name the pair [value, setValue], matching the setter to the state.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6754")],
        check: Check::Query {
            langs: JS_TS,
            query: "(variable_declarator value: (call_expression)) @match",
            filter: Some(Keep(use_state_badly_named)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const [count, update] = useState(0);",
            good: "const [count, setCount] = useState(0);\nconst [, setTick] = useState(0);",
        }),
    },
    Rule {
        id: "js/hook-in-condition",
        name: "Hooks should not be called conditionally or in loops",
        description: "React matches hooks by call order, so a hook inside an if, a loop, a \
                      ternary or after `&&` gets another hook's state when the condition \
                      changes.",
        message: "Call this hook unconditionally at the top level of the component, and put the condition inside it.",
        category: Bug,
        severity: Major,
        effort_minutes: 15,
        sonar: &[related("S6440")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (identifier) @f (#match? @f "^use[A-Z]")) @match"#,
            filter: Some(Keep(is_called_conditionally)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function C({ id }) { if (id) { useEffect(() => load(id)); } }",
            good: "function C({ id }) { useEffect(() => { if (id) { load(id); } }); const f = () => (ok ? 1 : 2); }",
        }),
    },
    Rule {
        id: "js/render-without-return",
        name: "React render methods should return a value",
        description: "A class component's render() that never returns anything renders \
                      nothing; usually a `return` was forgotten. Return null to render \
                      nothing on purpose.",
        message: "Return the rendered elements from render() (or null on purpose).",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6435")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(method_definition name: (property_identifier) @n (#eq? @n "render")) @match"#,
            filter: Some(Keep(component_render_returns_nothing)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "class A extends React.Component { render() { <div />; } }",
            good: "class A extends React.Component { render() { return <div />; } }\nclass Chart { render() { this.draw(); } }",
        }),
    },
    Rule {
        id: "js/react-dom-render-result",
        name: "The return value of ReactDOM.render should not be used",
        description: "ReactDOM.render's return value is a legacy, unreliable reference. Use \
                      a callback ref on the root element instead.",
        message: "Don't use what ReactDOM.render() returns; attach a ref to the root element.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S6750")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(member_expression
                        object: (identifier) @o
                        property: (property_identifier) @p
                        (#eq? @o "ReactDOM")
                        (#eq? @p "render")) @match"#,
            filter: Some(Find(used_call_result)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const app = ReactDOM.render(<App />, root);",
            good: "ReactDOM.render(<App />, root);",
        }),
    },
    Rule {
        id: "js/pure-component-scu",
        name: "PureComponent should not define shouldComponentUpdate",
        description: "PureComponent exists to implement shouldComponentUpdate with a \
                      shallow comparison; defining it again overrides that.",
        message: "Extend Component instead of PureComponent, or remove shouldComponentUpdate.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6763")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(method_definition name: (property_identifier) @n (#eq? @n "shouldComponentUpdate")) @match"#,
            filter: Some(Keep(in_pure_component)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "class A extends React.PureComponent { shouldComponentUpdate() { return true; } }",
            good: "class A extends React.Component { shouldComponentUpdate() { return true; } }",
        }),
    },
    // ---- Accessibility (JSX) ----
    Rule {
        id: "js/img-alt",
        name: "Images should have alternative text",
        description: "Screen readers read `alt` in place of an image. Without it they read \
                      the file name. Use alt=\"\" for decorative images.",
        message: "Add an 'alt' attribute describing the image, or alt=\"\" if it's decorative.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S1077")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_self_closing_element name: (identifier) @n (#any-of? @n "img" "area" "input")) @match
                      (jsx_element open_tag: (jsx_opening_element name: (identifier) @n (#any-of? @n "img" "area" "input"))) @match"#,
            filter: Some(Keep(image_without_alt)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const v = <img src={logo} />;",
            good: "const v = <img src={logo} alt=\"Company logo\" />;\nconst d = <img src={line} alt=\"\" />;\nconst p = <img {...props} />;\nconst i = <input type=\"text\" />;",
        }),
    },
    Rule {
        id: "js/iframe-title",
        name: "iframes should have a title",
        description: "Screen readers announce an iframe by its title; without one, users \
                      can't tell what it contains.",
        message: "Add a 'title' attribute describing this iframe's content.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S1090")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_self_closing_element name: (identifier) @n (#eq? @n "iframe")) @match
                      (jsx_element open_tag: (jsx_opening_element name: (identifier) @n (#eq? @n "iframe"))) @match"#,
            filter: Some(Keep(lacks_title)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const v = <iframe src={url} />;",
            good: "const v = <iframe src={url} title=\"Payment form\" />;",
        }),
    },
    Rule {
        id: "js/accesskey",
        name: "accessKey should not be used",
        description: "Access keys conflict with shortcuts of browsers and assistive \
                      technologies, and aren't announced to users.",
        message: "Remove 'accessKey'; provide visible, documented shortcuts if they're needed.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6846")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_attribute (property_identifier) @a (#eq? @a "accessKey")) @match"#,
            filter: Some(Keep(on_dom_element)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const v = <button accessKey=\"s\">Save</button>;",
            good: "const v = <button>Save</button>;\nconst w = <Shortcut accessKey=\"s\" />;",
        }),
    },
    Rule {
        id: "js/tabindex-positive",
        name: "tabIndex should be 0 or -1",
        description: "A positive tabIndex moves the element ahead of the page's natural \
                      order, which confuses keyboard users.",
        message: "Use tabIndex 0 (natural order) or -1 (focusable by script only).",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6841")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_attribute (property_identifier) @a (#eq? @a "tabIndex")) @match"#,
            filter: Some(Keep(positive_value)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const v = <div tabIndex={2} />;",
            good: "const v = <div tabIndex={0} />;\nconst w = <div tabIndex=\"-1\" />;",
        }),
    },
    Rule {
        id: "js/aria-hidden-focusable",
        name: "Focusable elements should not be aria-hidden",
        description: "A focusable element hidden from screen readers can still receive \
                      focus, leaving users on something that isn't announced.",
        message: "Remove aria-hidden, or make the element unfocusable (tabIndex={-1}).",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6825")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_attribute (property_identifier) @a (#eq? @a "aria-hidden")) @match"#,
            filter: Some(Keep(hides_focusable_element)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const v = <button aria-hidden=\"true\">x</button>;",
            good: "const v = <span aria-hidden=\"true\">x</span>;\nconst w = <button aria-hidden=\"true\" tabIndex={-1}>x</button>;",
        }),
    },
    Rule {
        id: "js/anchor-as-button",
        name: "Links should not be used as buttons",
        description: "An `<a>` with an onClick and no real href doesn't behave like a button \
                      for keyboard and screen-reader users, and breaks opening in a new tab.",
        message: "Use a <button> for this action, or give the link a real href.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6844")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_self_closing_element name: (identifier) @n (#eq? @n "a")) @match
                      (jsx_element open_tag: (jsx_opening_element name: (identifier) @n (#eq? @n "a"))) @match"#,
            filter: Some(Keep(link_used_as_button)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const v = <a href=\"#\" onClick={save}>Save</a>;",
            good: "const v = <button onClick={save}>Save</button>;\nconst w = <a href=\"/docs\" onClick={track}>Docs</a>;",
        }),
    },
    Rule {
        id: "js/anchor-content",
        name: "Links should have content",
        description: "A link with no text and no aria-label is announced as just \"link\"; \
                      users can't tell where it goes.",
        message: "Give this link text content, or an aria-label.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6827")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_self_closing_element name: (identifier) @n (#eq? @n "a")) @match
                      (jsx_element open_tag: (jsx_opening_element name: (identifier) @n (#eq? @n "a"))) @match"#,
            filter: Some(Keep(has_no_accessible_content)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const v = <a href=\"/home\"></a>;",
            good: "const v = <a href=\"/home\">Home</a>;\nconst w = <a href=\"/home\" aria-label=\"Home\" />;",
        }),
    },
    Rule {
        id: "js/heading-content",
        name: "Headings should have content",
        description: "Screen-reader users navigate by headings; an empty heading is a stop \
                      that says nothing.",
        message: "Give this heading text content, or remove it.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6850")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_self_closing_element name: (identifier) @n (#match? @n "^h[1-6]$")) @match
                      (jsx_element open_tag: (jsx_opening_element name: (identifier) @n (#match? @n "^h[1-6]$"))) @match"#,
            filter: Some(Keep(has_no_accessible_content)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const v = <h2 className=\"title\"></h2>;",
            good: "const v = <h2 className=\"title\">{title}</h2>;",
        }),
    },
    Rule {
        id: "js/redundant-alt",
        name: "Alternative text should not say it's an image",
        description: "Screen readers already announce an image as one; \"image of\" or \
                      \"photo\" in alt text repeats that.",
        message: "Describe what the image shows, without words like 'image', 'photo' or 'picture'.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6851")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_attribute (property_identifier) @a (string) (#eq? @a "alt")) @match"#,
            filter: Some(Keep(alt_says_image)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const v = <img src={p} alt=\"Photo of the team\" />;",
            good: "const v = <img src={p} alt=\"The team at the 2026 offsite\" />;\nconst w = <img src={p} alt=\"Photographer at work\" />;",
        }),
    },
    Rule {
        id: "js/mouse-without-keyboard",
        name: "Mouse events should have keyboard equivalents",
        description: "onMouseOver and onMouseOut only fire for mouse users; keyboard users \
                      need the same behavior on onFocus and onBlur.",
        message: "Add onFocus next to onMouseOver, and onBlur next to onMouseOut.",
        category: Bug,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S1082")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_attribute (property_identifier) @a (#any-of? @a "onMouseOver" "onMouseOut")) @match"#,
            filter: Some(Keep(mouse_handler_without_keyboard)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const v = <div onMouseOver={show}>i</div>;",
            good: "const v = <div onMouseOver={show} onFocus={show}>i</div>;\nconst w = <Tip onMouseOver={show} />;",
        }),
    },
    // ---- Test frameworks ----
    Rule {
        id: "js/test-empty-title",
        name: "Tests and suites should have a title",
        description: "An empty title makes failures impossible to locate in the report.",
        message: "Give this test or suite a title that says what it checks.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S8781")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression
                        function: (identifier) @f
                        arguments: (arguments . (string) @match)
                        (#any-of? @f "describe" "it" "test" "context" "suite"))"#,
            filter: Some(Keep(is_blank_string)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "it('', () => { expect(sum(1, 2)).toBe(3); });",
            good: "it('adds two numbers', () => { expect(sum(1, 2)).toBe(3); });",
        }),
    },
    Rule {
        id: "js/async-describe",
        name: "Suite callbacks should be synchronous",
        description: "describe() collects tests synchronously and doesn't wait for a \
                      returned promise: tests registered after an await are lost.",
        message: "Make this describe callback synchronous; do asynchronous setup in beforeAll or beforeEach.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S8785")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"((identifier) @match (#any-of? @match "describe" "context" "suite"))"#,
            filter: Some(Find(async_suite_callback)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "describe('db', async () => { const db = await open(); it('reads', () => {}); });",
            good: "describe('db', () => { let db; beforeAll(async () => { db = await open(); }); it('reads', async () => { await db.read(); }); });",
        }),
    },
    Rule {
        id: "js/assertion-same-argument",
        name: "Assertions should not compare a value with itself",
        description: "`expect(x).toBe(x)` always passes; one side was meant to be the \
                      expected value.",
        message: "Compare with the expected value: both sides of this assertion are the same.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5863")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"((identifier) @match (#any-of? @match "expect" "assert"))"#,
            filter: Some(Find(same_argument_assertion)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "expect(total).toBe(total);\nassert.equal(a.length, a.length);",
            good: "expect(total).toBe(10);\nassert.equal(a.length, b.length);",
        }),
    },
    Rule {
        id: "js/assertion-constant",
        name: "Assertions should not compare constants",
        description: "`expect(true).toBe(true)` or `assert(true)` can't fail, so they test \
                      nothing.",
        message: "Assert on the value under test, not on a constant.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5914")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"((identifier) @match (#any-of? @match "expect" "assert"))"#,
            filter: Some(Find(constant_assertion)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "expect(true).toBe(true);",
            good: "expect(isReady()).toBe(true);\nassert.fail('unreachable');",
        }),
    },
    Rule {
        id: "js/assertion-order",
        name: "Assertions should put the actual value first",
        description: "expect(actual).toBe(expected) and assert.equal(actual, expected): \
                      swapping them gives failure messages that say the opposite of what \
                      happened.",
        message: "Swap the arguments: the value under test goes first, the expected value second.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S3415")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"((identifier) @match (#any-of? @match "expect" "assert"))"#,
            filter: Some(Find(reversed_assertion)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "expect(3).toBe(sum(1, 2));\nassert.equal(3, sum(1, 2));",
            good: "expect(sum(1, 2)).toBe(3);\nassert.equal(sum(1, 2), 3);",
        }),
    },
    Rule {
        id: "js/assertion-specific",
        name: "The most specific assertion should be used",
        description: "`expect(a.length).toBe(3)` reports \"expected 3, got 2\"; \
                      `toHaveLength(3)` also shows the array. Likewise `expect(a === b)` \
                      and `assert(a === b)` lose the values being compared.",
        message: "Use the specific assertion (toHaveLength, toBe/toEqual on the values, assert.strictEqual) so failures show the values.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S5906")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"((identifier) @match (#any-of? @match "expect" "assert"))"#,
            filter: Some(Find(unspecific_assertion)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "expect(items.length).toBe(3);\nassert(a === b);",
            good: "expect(items).toHaveLength(3);\nassert.strictEqual(a, b);",
        }),
    },
    Rule {
        id: "js/incomplete-assertion",
        name: "Assertions should be complete",
        description: "`expect(x);` or `expect(x).not;` asserts nothing: the matcher call is \
                      missing, so the test can't fail.",
        message: "Complete this assertion with a matcher call, such as .toBe(...).",
        category: CodeSmell,
        severity: Blocker,
        effort_minutes: 2,
        sonar: &[exact("S2970")],
        check: Check::Query {
            langs: JS_TS,
            query: "(expression_statement [(call_expression) (member_expression)] @match)",
            filter: Some(Keep(is_incomplete_expect)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "expect(result).not;",
            good: "expect(result).not.toBeNull();\nexpect(flag).to.be.true;",
        }),
    },
    Rule {
        id: "js/unspecified-throw",
        name: "Tests should check which error is thrown",
        description: "`toThrow()` with no argument passes for any error, including a \
                      TypeError from a typo in the test itself.",
        message: "Say which error is expected: pass its class, message or a pattern.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5958")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"((identifier) @match (#any-of? @match "expect" "assert"))"#,
            filter: Some(Find(any_error_assertion)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "expect(() => parse('')).toThrow();",
            good: "expect(() => parse('')).toThrow(SyntaxError);\nassert.throws(() => parse(''), /empty/);",
        }),
    },
    Rule {
        id: "js/async-assertion-not-awaited",
        name: "Assertions on promises should be awaited",
        description: "`expect(p).resolves...` returns a promise. If it isn't awaited or \
                      returned, the test ends before it settles and passes regardless.",
        message: "Await (or return) this assertion, so the test waits for it.",
        category: Bug,
        severity: Critical,
        effort_minutes: 2,
        sonar: &[exact("S8780")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"((property_identifier) @match (#any-of? @match "resolves" "rejects"))"#,
            filter: Some(Find(unawaited_promise_assertion)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "it('loads', () => { expect(load()).resolves.toBe(1); });",
            good: "it('loads', async () => { await expect(load()).resolves.toBe(1); });\nit('fails', () => expect(load()).rejects.toThrow(E));",
        }),
    },
    Rule {
        id: "js/skipped-test-without-reason",
        name: "Skipped tests should say why",
        description: "A skipped test with no explanation tends to stay skipped forever; a \
                      comment saying why (and when to re-enable it) keeps it honest.",
        message: "Add a comment on the line above explaining why this test is skipped.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S1607")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression
                        function: (member_expression object: (identifier) @o property: (property_identifier) @p)
                        (#any-of? @o "describe" "it" "test" "context" "suite")
                        (#eq? @p "skip")) @match
                      (call_expression function: (identifier) @f (#any-of? @f "xit" "xdescribe" "xtest")) @match"#,
            filter: Some(Keep(no_comment_above)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "it.skip('syncs', () => {});",
            good: "// Flaky on CI until the mock server is fixed (#123).\nit.skip('syncs', () => {});",
        }),
    },
    Rule {
        id: "js/duplicate-test-title",
        name: "Test titles should be unique within a suite",
        description: "Two tests with the same title in one suite can't be told apart in \
                      reports, and one is often a copy that was never renamed.",
        message: "Rename this test: another test in the same suite has the same title.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S8754")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"((identifier) @match (#any-of? @match "describe" "context" "suite"))
                      (program) @match"#,
            filter: Some(Find(duplicate_test_title_in_suite)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "describe('sum', () => {\n  it('adds', () => {});\n  it('adds', () => {});\n});",
            good: "describe('sum', () => {\n  it('adds', () => {});\n  it('adds negatives', () => {});\n});\ndescribe('other', () => { it('adds', () => {}); });",
        }),
    },
    Rule {
        id: "js/hook-after-test",
        name: "Setup and teardown hooks should come before the tests",
        description: "beforeEach and friends apply to every test in the suite regardless of \
                      position; placed after tests, they read as if they only applied to \
                      what follows.",
        message: "Move this hook above the tests and suites in this block.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S8782")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"((identifier) @match (#any-of? @match "describe" "context" "suite"))
                      (program) @match"#,
            filter: Some(Find(hook_after_test_in_suite)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "describe('db', () => {\n  it('reads', () => {});\n  beforeEach(() => reset());\n});",
            good: "describe('db', () => {\n  beforeEach(() => reset());\n  it('reads', () => {});\n});",
        }),
    },
    Rule {
        id: "js/fixed-wait",
        name: "Tests should not use fixed waits or debug pauses",
        description: "`cy.wait(1000)` or `page.waitForTimeout(500)` makes tests slow and \
                      flaky; `cy.pause()` and `page.pause()` stop a CI run.",
        message: "Wait for a condition (an element, a request) instead of a fixed time, and remove debug pauses.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S2925")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression
                        function: (member_expression object: (identifier) @o)
                        (#any-of? @o "cy" "page" "browser")) @match"#,
            filter: Some(Keep(is_fixed_wait)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "cy.wait(2000);",
            good: "cy.wait('@save');\ncy.get('[data-test=done]').should('be.visible');",
        }),
    },
    // ---- Bugs (batch 4) ----
    Rule {
        id: "js/float-equality",
        name: "Floating-point numbers should not be tested for equality",
        description: "Decimal fractions like 0.1 aren't exact in binary, so `0.1 + 0.2 === \
                      0.3` is false. Compare within a tolerance instead.",
        message: "Compare with a tolerance, e.g. Math.abs(a - b) < Number.EPSILON, instead of testing a fraction for equality.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1244")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"((number) @match (#match? @match "\\.[0-9]*[1-9]"))"#,
            filter: Some(Find(fraction_compared_for_equality)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (total === 0.3) { done(); }",
            good: "if (Math.abs(total - 0.3) < 1e-9) { done(); }\nif (n === 3) { done(); }\nconst half = 0.5;",
        }),
    },
    Rule {
        id: "js/new-result-dropped",
        name: "Objects should not be created only to be dropped",
        description: "`new Thing();` on its own line throws the object away. If the \
                      constructor is called for its side effects, a function would say so; \
                      otherwise the result was meant to be stored. Errors are the \
                      error-not-thrown rule's case, and `new URL(s)` inside a try block \
                      (to validate) is fine.",
        message: "Store the new object, or call a function instead if only the side effect is wanted.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1848")],
        check: Check::Query {
            langs: JS_TS,
            query: "(expression_statement (new_expression) @match)",
            filter: Some(Keep(is_not_an_error)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "new Logger(config);",
            good: "const logger = new Logger(config);\nnew Error('x');",
        }),
    },
    Rule {
        id: "js/single-iteration-loop",
        name: "Loops should not always exit on their first iteration",
        description: "A loop whose body always ends in return, throw or break runs at most \
                      once: either the exit is misplaced or it should be an if.",
        message: "This loop always exits during its first iteration; use an if, or fix the misplaced exit.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S1751")],
        check: Check::Query {
            langs: JS_TS,
            query: "[(for_statement) (for_in_statement) (while_statement) (do_statement)] @match",
            filter: Some(Keep(always_exits_first_iteration)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "for (const user of users) { notify(user); return; }",
            good: "for (const user of users) { if (user.admin) { return user; } }\nwhile (q.length) { const x = q.pop(); if (!x) { continue; } return x; }",
        }),
    },
    Rule {
        id: "js/unreachable-code",
        name: "Code after return, throw, break or continue should be removed",
        description: "Statements after an unconditional jump never run. Function \
                      declarations are hoisted and fine.",
        message: "Remove this unreachable code, or move it before the jump.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[related("S1763")],
        check: Check::Query {
            langs: JS_TS,
            query: "[(statement_block) (switch_case) (switch_default)] @match",
            filter: Some(Find(statement_after_jump)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function f() { return 1; cleanup(); }",
            good: "function f() { cleanup(); return 1; function helper() {} }",
        }),
    },
    Rule {
        id: "js/useless-expression",
        name: "Statements should have an effect",
        description: "`a === b;` or `x;` computes a value and drops it: usually an \
                      assignment, call or return was meant.",
        message: "This statement has no effect; did you mean an assignment, a call or a return?",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S905")],
        check: Check::Query {
            langs: JS_TS,
            query: "(expression_statement
                        [(identifier) (number) (binary_expression) (unary_expression)
                         (true) (false) (null) (this)] @match)",
            filter: Some(Keep(has_no_effect)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function reset(state) { state.count === 0; }",
            good: "function reset(state) { state.count = 0; }\nready && start();\nvoid run();",
        }),
    },
    Rule {
        id: "js/super-call",
        name: "super() should be called in derived constructors, and only there",
        description: "A derived class's constructor must call super() before using `this`; \
                      a class that extends nothing can't call it at all.",
        message: "Call super() in this derived class's constructor, or remove super() from a class that extends nothing.",
        category: Bug,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[related("S3854")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(method_definition name: (property_identifier) @n (#eq? @n "constructor")) @match"#,
            filter: Some(Find(misplaced_super)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "class Admin extends User { constructor(name) { this.role = 'admin'; } }",
            good: "class Admin extends User { constructor(name) { super(name); this.role = 'admin'; } }\nclass Box { constructor() { this.items = []; } }",
        }),
    },
    Rule {
        id: "js/overwritten-element",
        name: "Elements should not be overwritten right after being set",
        description: "`a[k] = x; a[k] = y;` or two `map.set(k, ...)` in a row discard the \
                      first value: one key is probably wrong.",
        message: "This overwrites the value set on the previous line; is the key right?",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S4143")],
        check: Check::Query {
            langs: JS_TS,
            query: "[(statement_block) (program) (switch_case)] @match",
            filter: Some(Find(overwritten_element)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "names[0] = 'a';\nnames[0] = 'b';",
            good: "names[0] = 'a';\nnames[1] = 'b';\ncount[k] = 1;\ncount[k] = count[k] + 1;",
        }),
    },
    Rule {
        id: "js/constant-comparison",
        name: "Comparisons should not have a constant result",
        description: "`x === {}` compares with a brand-new object, so it's always false, and \
                      `'a' ?? b` never uses `b`.",
        message: "This expression always gives the same result; compare with an existing value, or remove it.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[related("S6638")],
        check: Check::Query {
            langs: JS_TS,
            query: "(binary_expression) @match",
            filter: Some(Keep(has_constant_result)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "if (options === {}) { useDefaults(); }",
            good: "if (Object.keys(options).length === 0) { useDefaults(); }\nconst n = value ?? 0;",
        }),
    },
    Rule {
        id: "js/accessor-recursion",
        name: "Getters and setters should not access their own property",
        description: "`get name() { return this.name; }` calls itself until the stack \
                      overflows; the value belongs in another field, like `this._name`.",
        message: "This accessor calls itself; store the value in a separate field, such as this._name.",
        category: Bug,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S7725")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(method_definition "get") @match
                      (method_definition "set") @match"#,
            filter: Some(Find(accessor_self_access)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "class U { get name() { return this.name; } }",
            good: "class U { get name() { return this._name; } set name(v) { this._name = v; } }",
        }),
    },
    Rule {
        id: "js/get-with-body",
        name: "GET and HEAD requests should not have a body",
        description: "Browsers reject a body on GET and HEAD (fetch throws), and servers may \
                      ignore it.",
        message: "Remove the body, or use POST/PUT if the request needs one.",
        category: Bug,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S7733")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(pair key: (property_identifier) @k (#eq? @k "body")) @match"#,
            filter: Some(Keep(in_get_request)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "fetch(url, { method: 'GET', body: JSON.stringify(q) });",
            good: "fetch(url, { method: 'POST', body: JSON.stringify(q) });",
        }),
    },
    Rule {
        id: "js/then-property",
        name: "Objects should not have a then property",
        description: "An object with a `then` method is treated as a promise: `await obj` \
                      or returning it from an async function calls it.",
        message: "Rename 'then': objects with it are taken for promises by await and async functions.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7739")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(pair key: (property_identifier) @k (#eq? @k "then")) @match
                      (method_definition name: (property_identifier) @k (#eq? @k "then")) @match"#,
            filter: Some(Keep(in_object_literal)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const step = { then: () => next() };",
            good: "const step = { andThen: () => next() };\np.then(f);",
        }),
    },
    Rule {
        id: "js/infinite-loop",
        name: "Loops should be able to end",
        description: "`while (true)` or `for (;;)` without a break, return or throw never \
                      ends. Loops that await or yield are left alone: they wait between \
                      iterations on purpose.",
        message: "Add an exit to this loop (break, return or throw), or a condition that can become false.",
        category: Bug,
        severity: Blocker,
        effort_minutes: 10,
        sonar: &[related("S2189")],
        check: Check::Query {
            langs: JS_TS,
            query: "[(for_statement) (while_statement) (do_statement)] @match",
            filter: Some(Keep(never_ends)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "while (true) { tick(); }",
            good: "while (true) { if (tick()) { break; } }\nwhile (true) { await next(); }\nfor (;;) { for (;;) { break; } return; }",
        }),
    },
    Rule {
        id: "js/unsafe-optional-chaining",
        name: "Optional chaining should not be used where undefined throws",
        description: "`(a?.b).c`, `(a?.f)()`, `[...a?.list]` and `for (x of a?.list)` throw \
                      a TypeError when the chain short-circuits, which defeats the `?.`.",
        message: "Continue the chain with ?. (or provide a default with ??) so a short-circuit doesn't throw.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6523")],
        check: Check::Query {
            langs: JS_TS,
            query: "(optional_chain) @match",
            filter: Some(Find(unsafe_chain_use)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const n = (user?.address).street;",
            good: "const n = user?.address?.street;\nconst all = [...(user?.tags ?? [])];",
        }),
    },
    // ---- Vulnerabilities (batch 4) ----
    Rule {
        id: "js/weak-tls",
        name: "Weak TLS versions should not be allowed",
        description: "SSL 3, TLS 1.0 and TLS 1.1 have known attacks. Require TLS 1.2 or \
                      later.",
        message: "Require TLS 1.2 or later (minVersion: 'TLSv1.2').",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S4423")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(pair
                        key: (property_identifier) @k
                        value: (string) @v
                        (#any-of? @k "secureProtocol" "minVersion")
                        (#match? @v "^['\"](SSLv2_method|SSLv3_method|SSLv23_method|TLSv1_method|TLSv1_1_method|TLSv1|TLSv1\\.1)['\"]$")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "tls.connect({ host, minVersion: 'TLSv1' });",
            good: "tls.connect({ host, minVersion: 'TLSv1.2' });",
        }),
    },
    Rule {
        id: "js/weak-key",
        name: "Cryptographic keys should be long enough",
        description: "RSA and DSA keys shorter than 2048 bits, and elliptic curves under 224 \
                      bits, can be broken.",
        message: "Use at least 2048-bit RSA/DSA keys, or a curve of 224 bits or more (e.g. P-256).",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S4426")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(pair key: (property_identifier) @k (#any-of? @k "modulusLength" "namedCurve")) @match"#,
            filter: Some(Keep(is_weak_key_size)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });",
            good: "crypto.generateKeyPairSync('rsa', { modulusLength: 4096 });\ncrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });",
        }),
    },
    Rule {
        id: "js/tls-hostname-unverified",
        name: "TLS server hostnames should be verified",
        description: "A checkServerIdentity that accepts everything lets any certificate \
                      for any host through, so anyone on the path can impersonate the server.",
        message: "Remove this checkServerIdentity override, or make it reject hostnames that don't match.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 15,
        sonar: &[exact("S5527")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(pair key: (property_identifier) @k (#eq? @k "checkServerIdentity")) @match"#,
            filter: Some(Keep(accepts_any_identity)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "https.request({ host, checkServerIdentity: () => {} });",
            good: "https.request({ host, checkServerIdentity: (h, cert) => pinned(cert) ? undefined : new Error('pin') });",
        }),
    },
    Rule {
        id: "js/weak-cipher",
        name: "Weak ciphers should not be used",
        description: "DES, 3DES, RC2, RC4 and Blowfish have small keys or blocks and \
                      practical attacks. AES is the standard choice.",
        message: "Use AES (for example aes-256-gcm) instead of this cipher.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 15,
        sonar: &[exact("S5547")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"((string) @match
                        (#match? @match "(?i)^['\"](des|des-[a-z0-9-]*|des3|rc2[a-z0-9-]*|rc4[a-z0-9-]*|bf|bf-[a-z0-9-]*|blowfish|cast[a-z0-9-]*)['\"]$"))"#,
            filter: Some(Keep(is_cipher_algorithm)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "crypto.createCipheriv('des-ede3-cbc', key, iv);",
            good: "crypto.createCipheriv('aes-256-gcm', key, iv);",
        }),
    },
    Rule {
        id: "js/insecure-cipher-mode",
        name: "Encryption should use a secure mode and padding",
        description: "ECB leaks patterns in the data, and CBC (and RSA's PKCS#1 v1.5 \
                      padding) allows padding-oracle attacks. Use GCM, or OAEP for RSA.",
        message: "Use an authenticated mode such as GCM (or OAEP padding for RSA).",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 15,
        sonar: &[exact("S5542")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"((string) @match (#match? @match "(?i)^['\"][a-z0-9-]*-(ecb|cbc)['\"]$"))
                      ((property_identifier) @match (#eq? @match "RSA_PKCS1_PADDING"))"#,
            filter: Some(Keep(is_cipher_algorithm_or_padding)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "crypto.createCipheriv('aes-128-ecb', key, null);",
            good: "crypto.createCipheriv('aes-128-gcm', key, iv);",
        }),
    },
    Rule {
        id: "js/jwt-none",
        name: "JWTs should be signed and verified with a real algorithm",
        description: "The 'none' algorithm means unsigned tokens: anyone can forge one, and \
                      a verifier that accepts it trusts them.",
        message: "Use a signing algorithm such as RS256 or HS256, never 'none'.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S5659")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(pair key: (property_identifier) @k (#any-of? @k "algorithm" "algorithms")) @match"#,
            filter: Some(Keep(allows_none_algorithm)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "jwt.verify(token, key, { algorithms: ['RS256', 'none'] });",
            good: "jwt.verify(token, key, { algorithms: ['RS256'] });",
        }),
    },
    Rule {
        id: "js/world-permissions",
        name: "Files should not be made writable by everyone",
        description: "A mode that lets \"others\" write (like 0o777 or 0o666) lets every user \
                      on the machine change the file. Read and execute for others (0o755) \
                      are left alone: executables and public files need them.",
        message: "Remove write permission for others from this mode (e.g. 0o755 or 0o644).",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 5,
        sonar: &[related("S2612")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"((property_identifier) @match
                        (#any-of? @match "chmod" "chmodSync" "fchmod" "fchmodSync" "lchmod" "lchmodSync"))"#,
            filter: Some(Find(world_accessible_mode)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "fs.chmodSync(file, 0o777);",
            good: "fs.chmodSync(file, 0o750);\nfs.chmodSync(bin, 0o755);",
        }),
    },
    Rule {
        id: "js/public-tmp",
        name: "Files should not be created in shared temporary directories by name",
        description: "Paths like /tmp/app.log can be guessed: another user can create or \
                      link the file first. Use fs.mkdtemp() under os.tmpdir().",
        message: "Create a private directory with fs.mkdtemp(path.join(os.tmpdir(), ...)) instead of a fixed /tmp path.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S5443")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"((string) @match (#match? @match "^['\"]/(tmp|var/tmp|usr/tmp|dev/shm)(/|['\"])"))"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "fs.writeFileSync('/tmp/report.csv', data);",
            good: "const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'report-'));",
        }),
    },
    Rule {
        id: "js/window-open-opener",
        name: "Windows opened by window.open should not get access to the opener",
        description: "Without 'noopener', the opened page can navigate this one through \
                      window.opener (reverse tabnabbing).",
        message: "Pass 'noopener,noreferrer' as window.open's third argument.",
        category: Vulnerability,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S5148")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(member_expression
                        object: (identifier) @o
                        property: (property_identifier) @p
                        (#eq? @o "window")
                        (#eq? @p "open")) @match"#,
            filter: Some(Find(open_without_noopener)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "window.open(link, '_blank');",
            good: "window.open(link, '_blank', 'noopener,noreferrer');",
        }),
    },
    Rule {
        id: "js/jsx-target-blank",
        name: "Links opening a new tab should not give it access to this page",
        description: "`target=\"_blank\"` to another site without `rel=\"noopener\"` lets \
                      that page navigate this one through window.opener in older browsers.",
        message: "Add rel=\"noopener noreferrer\" to this link.",
        category: Vulnerability,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S5148")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_attribute (property_identifier) @a (#eq? @a "target")) @match"#,
            filter: Some(Keep(blank_target_without_noopener)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const v = <a href=\"https://example.com\" target=\"_blank\">Docs</a>;",
            good: "const v = <a href=\"https://example.com\" target=\"_blank\" rel=\"noopener noreferrer\">Docs</a>;\nconst w = <a href=\"/help\" target=\"_blank\">Help</a>;",
        }),
    },
    Rule {
        id: "js/command-path",
        name: "OS commands should be run by absolute path",
        description: "A bare command name is looked up in PATH, which whoever controls the \
                      environment can point at another program.",
        message: "Run the command by its absolute path (e.g. /usr/bin/git).",
        category: Vulnerability,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S4036")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"([(identifier) (property_identifier)] @match
                        (#any-of? @match "exec" "execSync" "execFile" "execFileSync" "spawn" "spawnSync"))"#,
            filter: Some(Find(command_by_name)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "child_process.execSync('git status');",
            good: "child_process.execFileSync('/usr/bin/git', ['status']);\nconst m = re.exec(line);",
        }),
    },
    Rule {
        id: "js/hardcoded-password",
        name: "Passwords should not be hard-coded",
        description: "A password in the source is visible to everyone with access to the \
                      repository, and stays in its history. Read it from the environment \
                      or a secret store.",
        message: "Read this password from the environment or a secret store instead of the source code.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[exact("S2068"), related("S6437")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(variable_declarator name: (identifier) @n value: (string) @match
                        (#match? @n "(?i)(password|passwd|pwd|passphrase)$"))
                      (pair key: [(property_identifier) (string)] @n value: (string) @match
                        (#match? @n "(?i)(password|passwd|pwd|passphrase)['\"]?$"))
                      (assignment_expression
                        left: (member_expression property: (property_identifier) @n)
                        right: (string) @match
                        (#match? @n "(?i)(password|passwd|pwd|passphrase)$"))"#,
            filter: Some(Keep(looks_like_a_secret_value)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const db = connect({ user: 'app', password: 'hunter2' });",
            good: "const db = connect({ user: 'app', password: process.env.DB_PASSWORD });\nconst labels = { password: 'Your password' };\nconst field = { password: '' };",
        }),
    },
    Rule {
        id: "js/hardcoded-secret",
        name: "Secrets should not be hard-coded",
        description: "Tokens and API keys in the source leak with every copy of the \
                      repository. Only random-looking values are flagged: at least 16 \
                      characters, mixing letters and digits.",
        message: "Revoke this secret and read it from the environment or a secret store.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[exact("S6418")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(variable_declarator name: (identifier) @n value: (string) @match
                        (#match? @n "(?i)(secret|token|api_?key|access_?key|private_?key|auth_?key|client_?secret)$"))
                      (pair key: [(property_identifier) (string)] @n value: (string) @match
                        (#match? @n "(?i)(secret|token|api_?key|access_?key|private_?key|auth_?key|client_?secret)['\"]?$"))"#,
            filter: Some(Keep(looks_random)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const apiKey = 'x9Fq2LmZ7vR4tK8wB1nC6pD3';",
            good: "const apiKey = process.env.API_KEY;\nconst tokenHeader = 'Authorization';",
        }),
    },
    Rule {
        id: "js/xxe",
        name: "XML parsers should not expand external entities",
        description: "With `noent: true`, libxmljs resolves external entities, so a crafted \
                      document can read local files or reach internal hosts (XXE).",
        message: "Remove 'noent: true' so external entities aren't expanded.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 10,
        sonar: &[exact("S2755")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(pair key: (property_identifier) @k value: (true) (#eq? @k "noent")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "libxmljs.parseXml(xml, { noent: true });",
            good: "libxmljs.parseXml(xml, { noblanks: true });",
        }),
    },
    Rule {
        id: "js/cookie-not-secure",
        name: "Cookies should have the secure flag",
        description: "Without `secure`, the cookie is also sent over plain HTTP, where \
                      anyone on the network can read it.",
        message: "Set 'secure: true' so the cookie is only sent over HTTPS.",
        category: Vulnerability,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S2092")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(pair key: (property_identifier) @k value: (false) (#eq? @k "secure")) @match"#,
            filter: Some(Keep(in_cookie_options)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "res.cookie('sid', id, { secure: false });",
            good: "res.cookie('sid', id, { secure: true, httpOnly: true });\nnodemailer.createTransport({ host, secure: false });",
        }),
    },
    Rule {
        id: "js/cookie-not-httponly",
        name: "Cookies should have the HttpOnly flag",
        description: "Without `httpOnly`, scripts on the page can read the cookie, so any \
                      XSS can steal the session.",
        message: "Set 'httpOnly: true' so scripts can't read this cookie.",
        category: Vulnerability,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S3330")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(pair key: (property_identifier) @k value: (false) (#eq? @k "httpOnly")) @match"#,
            filter: Some(Keep(in_cookie_options)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "app.use(session({ secret, cookie: { httpOnly: false } }));",
            good: "app.use(session({ secret, cookie: { httpOnly: true, secure: true } }));",
        }),
    },
    Rule {
        id: "js/cors-any-origin",
        name: "CORS should not allow every origin",
        description: "`Access-Control-Allow-Origin: *` (also cors() with no options) lets any \
                      website read this server's responses from a visitor's browser.",
        message: "List the trusted origins instead of allowing every origin.",
        category: Vulnerability,
        severity: Minor,
        effort_minutes: 10,
        sonar: &[exact("S5122")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(pair key: (property_identifier) @k value: (string) (#eq? @k "origin")) @match
                      ((string) @match (#match? @match "(?i)^['\"]access-control-allow-origin['\"]$"))
                      ((identifier) @match (#eq? @match "cors"))"#,
            filter: Some(Find(allows_any_origin)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "res.setHeader('Access-Control-Allow-Origin', '*');",
            good: "res.setHeader('Access-Control-Allow-Origin', 'https://app.example.com');\napp.use(cors({ origin: ['https://app.example.com'] }));",
        }),
    },
    Rule {
        id: "js/csp-disabled",
        name: "The Content-Security-Policy should not be disabled",
        description: "helmet's CSP limits where scripts and other content can load from; \
                      turning it off removes a key defense against XSS.",
        message: "Configure the CSP directives instead of disabling contentSecurityPolicy.",
        category: Vulnerability,
        severity: Minor,
        effort_minutes: 15,
        sonar: &[exact("S5728")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(pair key: (property_identifier) @k value: (false) (#eq? @k "contentSecurityPolicy")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "app.use(helmet({ contentSecurityPolicy: false }));",
            good: "app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: [\"'self'\"] } } }));",
        }),
    },
    Rule {
        id: "js/nosniff-disabled",
        name: "MIME type sniffing should stay disabled",
        description: "Without `X-Content-Type-Options: nosniff`, browsers may run an upload \
                      or response as a script despite its declared type.",
        message: "Keep helmet's noSniff (X-Content-Type-Options) enabled.",
        category: Vulnerability,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S5734")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(pair key: (property_identifier) @k value: (false) (#any-of? @k "noSniff" "xContentTypeOptions")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "app.use(helmet({ noSniff: false }));",
            good: "app.use(helmet());",
        }),
    },
    Rule {
        id: "js/unsafe-referrer-policy",
        name: "The Referrer-Policy should not leak full URLs",
        description: "'unsafe-url' and 'no-referrer-when-downgrade' send the full URL, \
                      including paths and query strings, to other sites.",
        message: "Use a stricter policy such as 'strict-origin-when-cross-origin' or 'no-referrer'.",
        category: Vulnerability,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S5736")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"((string) @match (#match? @match "^['\"](unsafe-url|no-referrer-when-downgrade)['\"]$"))"#,
            filter: Some(Keep(is_referrer_policy)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "app.use(helmet.referrerPolicy({ policy: 'unsafe-url' }));",
            good: "app.use(helmet.referrerPolicy({ policy: 'no-referrer' }));",
        }),
    },
    Rule {
        id: "js/hsts-disabled",
        name: "HTTP Strict-Transport-Security should not be disabled",
        description: "HSTS tells browsers to use HTTPS only; without it, a first plain-HTTP \
                      request can be intercepted and downgraded.",
        message: "Keep helmet's HSTS enabled.",
        category: Vulnerability,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S5739")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(pair key: (property_identifier) @k value: (false) (#any-of? @k "hsts" "strictTransportSecurity")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "app.use(helmet({ hsts: false }));",
            good: "app.use(helmet({ hsts: { maxAge: 31536000 } }));",
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

pub(super) fn text<'a>(node: Node, src: &'a [u8]) -> &'a [u8] {
    &src[node.byte_range()]
}

/// Whether any node below `node`, not looking inside nested functions,
/// satisfies `pred`.
pub(super) fn contains(node: Node, pred: impl Fn(Node) -> bool) -> bool {
    find_below(node, false, pred).is_some()
}

/// The first node below `node` that satisfies `pred`, looking inside
/// nested functions only when `into_functions` is set. Iterative, like
/// every tree walk in sonda.
pub(super) fn find_below<'t>(
    node: Node<'t>,
    into_functions: bool,
    pred: impl Fn(Node) -> bool,
) -> Option<Node<'t>> {
    let mut cursor = node.walk();
    if !cursor.goto_first_child() {
        return None;
    }
    loop {
        let n = cursor.node();
        if pred(n) {
            return Some(n);
        }
        if (into_functions || !FUNCTIONS.contains(&n.kind())) && cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return None;
            }
        }
    }
}

/// Whether `node` has an anonymous child token `token`, such as `set` or `*`.
pub(super) fn has_token(node: Node, token: &str) -> bool {
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

/// The first return, throw, break or continue that leaves a finally block.
fn jump_out_of_finally<'t>(block: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    first_escape(block, src, false)
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

/// For an if statement, its condition where it comes back further down its
/// else-if chain; for a switch, a case testing the same value as an earlier
/// one.
fn repeated_condition<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if node.kind() == "switch_body" {
        let mut seen = std::collections::HashSet::new();
        let mut cursor = node.walk();
        return node
            .named_children(&mut cursor)
            .filter_map(|case| case.child_by_field_name("value"))
            .find(|&value| !seen.insert(text(value, src)));
    }
    let cond = node.child_by_field_name("condition")?;
    let mut current = node;
    for _ in 0..MAX_CHAIN {
        let next = else_if(current)?;
        let later = next.child_by_field_name("condition")?;
        if same_text(later, cond, src) {
            return Some(later);
        }
        current = next;
    }
    None
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
    is_first_argument_of(string, &[b"createHash"], src)
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

fn duplicate_member<'t>(container: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut seen = std::collections::HashSet::new();
    let mut cursor = container.walk();
    container
        .named_children(&mut cursor)
        .find(|&m| member_key(m, src).is_some_and(|key| !seen.insert(key)))
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
    binds && !DECLARATIONS_ONLY.contains(&parent.kind()) && !declares_only(parent)
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

/// A bare block directly inside `container`. Captured from the outside: a
/// `(statement_block (statement_block))` pattern stays open over the
/// block's whole subtree, which is quadratic on deep nesting.
fn nested_block<'t>(container: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    let mut cursor = container.walk();
    container
        .named_children(&mut cursor)
        .find(|c| c.kind() == "statement_block")
}

/// The last named child that isn't a comment.
fn last_statement(node: Node) -> Option<Node> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|c| c.kind() != "comment")
        .last()
}

/// Whether control can't continue past `statement`: it ends with a break,
/// return, throw or continue, also through blocks and if/else with both
/// branches ending that way. Iterative, with a work list.
fn ends_with_jump(statement: Node) -> bool {
    let mut pending = vec![statement];
    while let Some(s) = pending.pop() {
        match s.kind() {
            "break_statement" | "return_statement" | "throw_statement" | "continue_statement" => {}
            "statement_block" => match last_statement(s) {
                Some(last) => pending.push(last),
                None => return false,
            },
            "if_statement" => {
                let consequence = s.child_by_field_name("consequence");
                let otherwise = s
                    .child_by_field_name("alternative")
                    .and_then(last_statement);
                match (consequence, otherwise) {
                    (Some(c), Some(o)) => pending.extend([c, o]),
                    _ => return false,
                }
            }
            _ => return false,
        }
    }
    true
}

/// A case that runs into the next one: it has statements, the last can
/// fall through, and no comment after it mentions falling through.
fn falling_case<'t>(body: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut falling: Option<Node> = None;
    let mut cursor = body.walk();
    for child in body.named_children(&mut cursor) {
        match child.kind() {
            "switch_case" | "switch_default" => {
                if falling.is_some() {
                    return falling;
                }
                let value = child.child_by_field_name("value");
                let mut inner = child.walk();
                let body: Vec<Node> = child
                    .named_children(&mut inner)
                    .filter(|&c| Some(c) != value)
                    .collect();
                let commented = body
                    .last()
                    .is_some_and(|&c| c.kind() == "comment" && mentions_fall_through(c, src));
                let last = body.iter().rev().find(|c| c.kind() != "comment");
                falling = last
                    .filter(|&&l| !commented && !ends_with_jump(l))
                    .map(|_| child);
            }
            "comment" if mentions_fall_through(child, src) => falling = None,
            _ => {}
        }
    }
    None
}

fn mentions_fall_through(comment: Node, src: &[u8]) -> bool {
    let t = text(comment, src).to_ascii_lowercase();
    t.windows(4).any(|w| w == b"fall")
}

fn counter_tested_for_equality(for_statement: Node, src: &[u8]) -> bool {
    let (Some(cond), Some(update)) = (
        for_statement.child_by_field_name("condition"),
        for_statement.child_by_field_name("increment"),
    ) else {
        return false;
    };
    let counter = match update.kind() {
        "update_expression" => update.child_by_field_name("argument"),
        "augmented_assignment_expression"
            if update
                .child_by_field_name("operator")
                .is_some_and(|op| matches!(op.kind(), "+=" | "-=")) =>
        {
            update.child_by_field_name("left")
        }
        _ => None,
    };
    let Some(counter) = counter.filter(|c| c.kind() == "identifier") else {
        return false;
    };
    cond.kind() == "binary_expression"
        && cond
            .child_by_field_name("operator")
            .is_some_and(|op| EQUALITY.contains(&op.kind()))
        && ["left", "right"].iter().any(|f| {
            cond.child_by_field_name(f)
                .is_some_and(|side| same_text(side, counter, src))
        })
}

fn loosely_compares_boolean_literal(expr: Node, _: &[u8]) -> bool {
    expr.child_by_field_name("operator")
        .is_some_and(|op| matches!(op.kind(), "==" | "!="))
        && ["left", "right"].iter().any(|f| {
            expr.child_by_field_name(f)
                .is_some_and(|side| matches!(side.kind(), "true" | "false"))
        })
}

/// `true` or `false` when `branch` is just `return true;`/`return false;`,
/// alone or in a block.
fn returned_boolean(branch: Node) -> Option<bool> {
    let statement = if branch.kind() == "statement_block" {
        if branch.named_child_count() != 1 {
            return None;
        }
        branch.named_child(0)?
    } else {
        branch
    };
    if statement.kind() != "return_statement" {
        return None;
    }
    match statement.named_child(0)?.kind() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn returns_boolean_from_both_branches(if_statement: Node, _: &[u8]) -> bool {
    let then = if_statement
        .child_by_field_name("consequence")
        .and_then(returned_boolean);
    let otherwise = if_statement
        .child_by_field_name("alternative")
        .and_then(|e| {
            let mut cursor = e.walk();
            e.named_children(&mut cursor)
                .find(|c| c.kind() != "comment")
        })
        .and_then(returned_boolean);
    matches!((then, otherwise), (Some(a), Some(b)) if a != b)
}

fn has_empty_body(function: Node, src: &[u8]) -> bool {
    let is_constructor = function.kind() == "method_definition"
        && function
            .child_by_field_name("name")
            .is_some_and(|n| text(n, src) == b"constructor");
    !is_constructor
        && function
            .child_by_field_name("body")
            .is_some_and(|b| b.kind() == "statement_block" && b.named_child_count() == 0)
}

fn only_has_condition(for_statement: Node, _: &[u8]) -> bool {
    for_statement
        .child_by_field_name("initializer")
        .is_some_and(|i| i.kind() == "empty_statement")
        && for_statement.child_by_field_name("increment").is_none()
        && for_statement
            .child_by_field_name("condition")
            .is_some_and(|c| c.kind() != "empty_statement")
}

fn is_octal_escape(escape: Node, src: &[u8]) -> bool {
    matches!(
        text(escape, src),
        [b'\\', b'1'..=b'7', ..] | [b'\\', b'0', b'0'..=b'9', ..]
    )
}

/// The arguments of a call when they start on a later line than the
/// function.
fn arguments_on_a_later_line<'t>(call: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    // In `f<T>(x)`, the arguments follow the type arguments.
    let before = call
        .child_by_field_name("type_arguments")
        .or_else(|| call.child_by_field_name("function"))?;
    call.child_by_field_name("arguments").filter(|args| {
        args.kind() == "arguments" && args.start_position().row > before.end_position().row
    })
}

fn has_too_many_cases(body: Node, _: &[u8]) -> bool {
    let mut cursor = body.walk();
    body.named_children(&mut cursor)
        .filter(|c| c.kind() == "switch_case")
        .count()
        > 30
}

fn continues_on_next_line(string: Node, src: &[u8]) -> bool {
    text(string, src)
        .windows(2)
        .any(|w| w == b"\\\n" || w == b"\\\r")
}

/// The first parameter with a default value that a required parameter
/// follows.
fn default_before_required<'t>(params: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    let mut first_default = None;
    let mut cursor = params.walk();
    for p in params.named_children(&mut cursor) {
        let (has_default, required) = match p.kind() {
            "assignment_pattern" => (true, false),
            "required_parameter" => {
                let rest = p
                    .child_by_field_name("pattern")
                    .is_some_and(|x| x.kind() == "rest_pattern");
                if rest {
                    return None;
                }
                let has_default = p.child_by_field_name("value").is_some();
                (has_default, !has_default)
            }
            "identifier" | "object_pattern" | "array_pattern" => (false, true),
            "rest_pattern" => return None,
            _ => (false, false),
        };
        if has_default && first_default.is_none() {
            first_default = Some(p);
        } else if required && first_default.is_some() {
            return first_default;
        }
    }
    None
}

fn negates_an_equality(negation: Node, _: &[u8]) -> bool {
    negation
        .child_by_field_name("argument")
        .and_then(|p| p.named_child(0))
        .and_then(|b| b.child_by_field_name("operator"))
        .is_some_and(|op| EQUALITY.contains(&op.kind()))
}

fn is_empty_class(class: Node, _: &[u8]) -> bool {
    let mut cursor = class.walk();
    let extends_or_decorated = class
        .children(&mut cursor)
        .any(|c| matches!(c.kind(), "class_heritage" | "decorator"));
    !extends_or_decorated
        && class
            .child_by_field_name("body")
            .is_some_and(|b| b.named_child_count() == 0)
        && !declares_only(class)
}

/// Whether `node` is inside a type-only declaration (`declare ...`, a
/// signature), where nothing runs. Walks up, so call it only on rare nodes.
fn declares_only(node: Node) -> bool {
    let mut ancestor = node.parent();
    while let Some(a) = ancestor {
        if DECLARATIONS_ONLY.contains(&a.kind()) {
            return true;
        }
        ancestor = a.parent();
    }
    false
}

/// A label on a simple statement, like the misspelled `defualt: f();`. A
/// label on a block, if, try, loop or switch is a `break` target.
fn labels_a_plain_statement(label: Node, _: &[u8]) -> bool {
    label.child_by_field_name("body").is_some_and(|b| {
        matches!(
            b.kind(),
            "expression_statement"
                | "return_statement"
                | "throw_statement"
                | "break_statement"
                | "continue_statement"
                | "lexical_declaration"
                | "variable_declaration"
                | "empty_statement"
        )
    })
}

/// `name` is the property of a member expression (`x.name`), not an object
/// key or a method name. Checked only on rare names, so the parent lookup
/// is cheap overall.
fn is_member_property(name: Node, _: &[u8]) -> bool {
    name.parent().is_some_and(|m| {
        m.kind() == "member_expression" && m.child_by_field_name("property") == Some(name)
    })
}

fn is_property_of_arguments(name: Node, src: &[u8]) -> bool {
    name.parent().is_some_and(|m| {
        m.kind() == "member_expression"
            && m.child_by_field_name("object")
                .is_some_and(|o| text(o, src) == b"arguments")
    })
}

fn has_nested_ternary(ternary: Node, _: &[u8]) -> bool {
    // Reported on the inner conditional, as SonarQube does: that is the one
    // that makes the outer hard to read.
    let mut parent = ternary.parent();
    while let Some(p) = parent.filter(|p| p.kind() == "parenthesized_expression") {
        parent = p.parent();
    }
    parent.is_some_and(|p| p.kind() == "ternary_expression") && !chain_is_a_jsx_state(ternary)
}

/// Whether the chain `ternary` belongs to sits directly in a JSX `{...}`,
/// the usual way to render loading/empty/list states. Walks up only from
/// ternaries already found nested, so the parent lookups stay rare.
fn chain_is_a_jsx_state(ternary: Node) -> bool {
    let mut node = ternary;
    loop {
        let mut parent = node.parent();
        while let Some(p) = parent.filter(|p| p.kind() == "parenthesized_expression") {
            parent = p.parent();
        }
        match parent {
            Some(p) if p.kind() == "ternary_expression" => node = p,
            Some(p) => return p.kind() == "jsx_expression",
            None => return false,
        }
    }
}

/// `return;` or `continue;`, with no value or label.
fn is_bare_jump(jump: Node, _: &[u8]) -> bool {
    jump.named_child_count() == 0
}

fn has_hole(array: Node, _: &[u8]) -> bool {
    let mut cursor = array.walk();
    let mut previous = "";
    for c in array.children(&mut cursor) {
        if c.kind() == "comment" {
            continue;
        }
        if c.kind() == "," && matches!(previous, "," | "[") {
            return true;
        }
        previous = c.kind();
    }
    false
}

/// A `default` clause followed by a `case`.
fn default_before_a_case<'t>(body: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    let mut default = None;
    let mut cursor = body.walk();
    for c in body.named_children(&mut cursor) {
        match c.kind() {
            "switch_default" => default = Some(c),
            "switch_case" if default.is_some() => return default,
            _ => {}
        }
    }
    None
}

fn disables_every_eslint_rule(comment: Node, src: &[u8]) -> bool {
    let Ok(t) = std::str::from_utf8(text(comment, src)) else {
        return false;
    };
    let body = t
        .trim_start_matches("//")
        .trim_start_matches("/*")
        .trim_end_matches("*/")
        .trim();
    [
        "eslint-disable-next-line",
        "eslint-disable-line",
        "eslint-disable",
    ]
    .iter()
    .find_map(|d| body.strip_prefix(d))
    // The directive word must end here: "eslint-disable-foo" is not one.
    .filter(|rest| rest.is_empty() || rest.starts_with(char::is_whitespace))
    .is_some_and(|rest| rest.split("--").next().unwrap_or("").trim().is_empty())
}

/// `let x = undefined` or `var x = undefined`: removing the initializer
/// from a `const` would not compile.
fn declared_without_const(undefined: Node, _: &[u8]) -> bool {
    undefined
        .parent()
        .and_then(|declarator| declarator.parent())
        .is_some_and(|d| d.kind() == "variable_declaration" || has_token(d, "let"))
}

// ---------------------------------------------------- JSX helpers

/// The node holding an element's name and attributes.
pub(super) fn opening_tag(element: Node) -> Option<Node> {
    match element.kind() {
        "jsx_element" => element.child_by_field_name("open_tag"),
        "jsx_self_closing_element" => Some(element),
        _ => None,
    }
}

/// A plain tag name (`div`, `Button`); None for `Foo.Bar` and fragments.
pub(super) fn tag_name<'s>(opening: Node, src: &'s [u8]) -> Option<&'s [u8]> {
    opening
        .child_by_field_name("name")
        .filter(|n| n.kind() == "identifier")
        .map(|n| text(n, src))
}

/// HTML elements are lowercase; components start with a capital.
pub(super) fn is_dom_tag(name: &[u8]) -> bool {
    name.first().is_some_and(u8::is_ascii_lowercase)
}

pub(super) fn attributes<'t>(opening: Node<'t>) -> Vec<Node<'t>> {
    let mut cursor = opening.walk();
    opening
        .children_by_field_name("attribute", &mut cursor)
        .collect()
}

/// `{...props}` may set any attribute, so checks for a missing one stop.
pub(super) fn has_spread(opening: Node) -> bool {
    attributes(opening)
        .iter()
        .any(|a| a.kind() == "jsx_expression")
}

pub(super) fn attribute<'t>(opening: Node<'t>, name: &str, src: &[u8]) -> Option<Node<'t>> {
    attributes(opening).into_iter().find(|a| {
        a.kind() == "jsx_attribute"
            && a.named_child(0)
                .is_some_and(|n| text(n, src) == name.as_bytes())
    })
}

/// A value known without running the code: the text of `"x"`, `{1}`,
/// `{true}` or `{'x'}`, and `true` for a bare attribute (`disabled`).
pub(super) fn static_value<'s>(attr: Node, src: &'s [u8]) -> Option<&'s [u8]> {
    let Some(value) = attr.named_child(1) else {
        return Some(b"true");
    };
    let value = if value.kind() == "jsx_expression" {
        value.named_child(0)?
    } else {
        value
    };
    match value.kind() {
        "string" => {
            let t = text(value, src);
            t.get(1..t.len().checked_sub(1)?)
        }
        "number" | "true" | "false" => Some(text(value, src)),
        "unary_expression" => Some(text(value, src)), // -1
        _ => None,
    }
}

/// Whether an element has children worth announcing: text, expressions or
/// elements, not just whitespace or a comment.
fn has_content(element: Node, src: &[u8]) -> bool {
    if element.kind() != "jsx_element" {
        return false;
    }
    let open = element.child_by_field_name("open_tag");
    let close = element.child_by_field_name("close_tag");
    let mut cursor = element.walk();
    element.named_children(&mut cursor).any(|c| {
        if Some(c) == open || Some(c) == close {
            return false;
        }
        match c.kind() {
            "jsx_text" => !text(c, src).iter().all(u8::is_ascii_whitespace),
            "jsx_expression" => c.named_child(0).is_some_and(|e| e.kind() != "comment"),
            _ => true,
        }
    })
}

// ---------------------------------------------------- React filters

fn text_looks_like_comment(jsx_text: Node, src: &[u8]) -> bool {
    text(jsx_text, src).split(|&b| b == b'\n').any(|line| {
        let line = line.trim_ascii_start();
        line.starts_with(b"//") || line.starts_with(b"/*")
    })
}

/// For the `map` in `xs.map(cb)`: the callback and the JSX elements it
/// returns (its expression body, or its top-level `return`s).
fn mapped_elements<'t>(map: Node<'t>) -> Option<(Node<'t>, Vec<Node<'t>>)> {
    let member = map.parent().filter(|m| m.kind() == "member_expression")?;
    let call = member
        .parent()
        .filter(|c| c.child_by_field_name("function") == Some(member))?;
    let callback = call
        .child_by_field_name("arguments")?
        .named_child(0)
        .filter(|c| matches!(c.kind(), "arrow_function" | "function_expression"))?;
    let body = callback.child_by_field_name("body")?;
    let returned: Vec<Node> = if body.kind() == "statement_block" {
        let mut cursor = body.walk();
        body.named_children(&mut cursor)
            .filter(|s| s.kind() == "return_statement")
            .filter_map(|r| r.named_child(0))
            .collect()
    } else {
        vec![body]
    };
    let elements = returned
        .into_iter()
        .map(|mut e| {
            while e.kind() == "parenthesized_expression" {
                match e.named_child(0) {
                    Some(inner) => e = inner,
                    None => break,
                }
            }
            e
        })
        .filter(|e| matches!(e.kind(), "jsx_element" | "jsx_self_closing_element"))
        .collect();
    Some((callback, elements))
}

fn mapped_element_without_key<'t>(map: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let (_, elements) = mapped_elements(map)?;
    elements.into_iter().find(|&e| {
        opening_tag(e).is_some_and(|o| !has_spread(o) && attribute(o, "key", src).is_none())
    })
}

fn mapped_element_keyed_by_index<'t>(map: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let (callback, elements) = mapped_elements(map)?;
    let index = callback
        .child_by_field_name("parameters")?
        .named_child(1)
        .map(|p| p.child_by_field_name("pattern").unwrap_or(p))
        .filter(|p| p.kind() == "identifier")?;
    elements.into_iter().find_map(|e| {
        let key = attribute(opening_tag(e)?, "key", src)?;
        let value = key
            .named_child(1)
            .filter(|v| v.kind() == "jsx_expression")?;
        value
            .named_child(0)
            .is_some_and(|v| same_text(v, index, src))
            .then_some(key)
    })
}

fn element_also_has_children(attr: Node, src: &[u8]) -> bool {
    let Some(opening) = attr.parent() else {
        return false;
    };
    attribute(opening, "children", src).is_some()
        || (opening.kind() == "jsx_opening_element"
            && opening.parent().is_some_and(|e| has_content(e, src)))
}

fn is_redundant_fragment(element: Node, src: &[u8]) -> bool {
    let Some(open) = element.child_by_field_name("open_tag") else {
        return false;
    };
    let is_fragment = open
        .child_by_field_name("name")
        .is_none_or(|n| matches!(text(n, src), b"Fragment" | b"React.Fragment"));
    if !is_fragment || !attributes(open).is_empty() {
        return false;
    }
    let close = element.child_by_field_name("close_tag");
    let mut cursor = element.walk();
    let children: Vec<Node> = element
        .named_children(&mut cursor)
        .filter(|&c| Some(c) != Some(open) && Some(c) != close)
        // JSX drops whitespace that contains a newline; a plain space renders.
        .filter(|c| {
            c.kind() != "jsx_text" || {
                let t = text(*c, src);
                !t.iter().all(u8::is_ascii_whitespace) || !t.contains(&b'\n')
            }
        })
        .collect();
    matches!(children.as_slice(), [only] if matches!(only.kind(), "jsx_element" | "jsx_self_closing_element"))
}

/// `name(...)` or `x.name(...)`. Checked only on rare names.
fn is_called(name: Node, _: &[u8]) -> bool {
    let Some(parent) = name.parent() else {
        return false;
    };
    let callee = match parent.kind() {
        "member_expression" if parent.child_by_field_name("property") == Some(name) => parent,
        _ => name,
    };
    callee.parent().is_some_and(|c| {
        c.kind() == "call_expression" && c.child_by_field_name("function") == Some(callee)
    })
}

fn is_called_on_this(name: Node, src: &[u8]) -> bool {
    is_called(name, src)
        && name
            .parent()
            .and_then(|m| m.child_by_field_name("object"))
            .is_some_and(|o| o.kind() == "this")
}

/// The assignment to `this.state` (or a property of it), unless it's in a
/// constructor, where initializing state is the norm.
fn state_assignment_outside_constructor<'t>(state: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut target = state;
    while let Some(p) = target.parent().filter(|p| {
        p.kind() == "member_expression" && p.child_by_field_name("object") == Some(target)
    }) {
        target = p;
    }
    let write = target.parent().filter(|p| match p.kind() {
        "assignment_expression" | "augmented_assignment_expression" => {
            p.child_by_field_name("left") == Some(target)
        }
        "update_expression" => true,
        _ => false,
    })?;
    let mut ancestor = write.parent();
    while let Some(a) = ancestor {
        if FUNCTIONS.contains(&a.kind()) {
            // Only React components: other classes may have a `state` field.
            let component = a.kind() == "method_definition"
                && superclass(a, src).is_some_and(|h| h.ends_with(b"Component"));
            let constructor = a
                .child_by_field_name("name")
                .is_some_and(|n| text(n, src) == b"constructor");
            return (component && !constructor).then_some(write);
        }
        ancestor = a.parent();
    }
    None
}

fn set_state_reading_state<'t>(name: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let member = name.parent().filter(|m| m.kind() == "member_expression")?;
    let call = member
        .parent()
        .filter(|c| c.child_by_field_name("function") == Some(member))?;
    let update = call.child_by_field_name("arguments")?.named_child(0)?;
    if update.kind() != "object" {
        return None;
    }
    find_below(update, false, |n| {
        n.kind() == "member_expression"
            && n.child_by_field_name("object")
                .is_some_and(|o| o.kind() == "this")
            && n.child_by_field_name("property")
                .is_some_and(|p| text(p, src) == b"state")
    })
    .map(|_| call)
}

/// For `const [value, setValue] = useState(...)`: both names.
fn use_state_pair<'t>(declarator: Node<'t>, src: &[u8]) -> Option<(Node<'t>, Node<'t>)> {
    if !is_use_state_call(declarator.child_by_field_name("value")?, src) {
        return None;
    }
    let [value, setter] = array_pattern_slots(declarator.child_by_field_name("name")?)[..] else {
        return None;
    };
    Some((value?, setter?))
}

fn is_use_state_call(call: Node, src: &[u8]) -> bool {
    call.kind() == "call_expression"
        && call.child_by_field_name("function").is_some_and(|f| {
            let name = match f.kind() {
                "member_expression" => f.child_by_field_name("property"),
                _ => Some(f),
            };
            name.is_some_and(|n| text(n, src) == b"useState")
        })
}

/// The elements of `[a, , b]` by position, None for holes.
fn array_pattern_slots(pattern: Node) -> Vec<Option<Node>> {
    let mut slots = Vec::new();
    let mut current = None;
    let mut cursor = pattern.walk();
    for c in pattern.children(&mut cursor) {
        match c.kind() {
            "[" | "comment" => {}
            "," => slots.push(current.take()),
            // A trailing comma leaves nothing to push.
            "]" => slots.extend(current.take().map(Some)),
            _ => current = Some(c),
        }
    }
    slots
}

/// The body of the function `node` is in. Walks up: call it on rare nodes.
fn enclosing_body(node: Node) -> Option<Node> {
    let mut ancestor = node.parent();
    while let Some(a) = ancestor {
        if FUNCTIONS.contains(&a.kind()) {
            return a.child_by_field_name("body");
        }
        ancestor = a.parent();
    }
    None
}

fn calls_named<'t>(call: Node<'t>, name: Node, src: &[u8]) -> bool {
    call.kind() == "call_expression"
        && call
            .child_by_field_name("function")
            .is_some_and(|f| f.kind() == "identifier" && same_text(f, name, src))
}

fn setter_called_with_own_state<'t>(declarator: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let (value, setter) = use_state_pair(declarator, src)?;
    let body = enclosing_body(declarator)?;
    find_below(body, true, |n| {
        calls_named(n, setter, src)
            && n.child_by_field_name("arguments").is_some_and(|a| {
                a.named_child_count() == 1
                    && a.named_child(0)
                        .is_some_and(|v| v.kind() == "identifier" && same_text(v, value, src))
            })
    })
}

fn setter_called_in_render<'t>(declarator: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let (_, setter) = use_state_pair(declarator, src)?;
    let body = enclosing_body(declarator)?;
    let mut cursor = body.walk();
    body.named_children(&mut cursor)
        .filter(|s| s.kind() == "expression_statement")
        .filter_map(|s| s.named_child(0))
        .find(|&e| calls_named(e, setter, src))
}

fn use_state_badly_named(declarator: Node, src: &[u8]) -> bool {
    let (Some(value), Some(name)) = (
        declarator.child_by_field_name("value"),
        declarator.child_by_field_name("name"),
    ) else {
        return false;
    };
    if !is_use_state_call(value, src) {
        return false;
    }
    if name.kind() != "array_pattern" {
        return name.kind() == "identifier";
    }
    let [Some(state), Some(setter)] = array_pattern_slots(name)[..] else {
        return false;
    };
    if state.kind() != "identifier" || setter.kind() != "identifier" {
        return false;
    }
    let state = text(state, src);
    let mut expected = b"set".to_vec();
    expected.extend(state.first().map(u8::to_ascii_uppercase));
    expected.extend(state.iter().skip(1));
    text(setter, src) != expected.as_slice()
}

/// Whether a hook call depends on a condition or runs in a loop, within a
/// component (capitalized) or a custom hook (`useX`): elsewhere `useX` is
/// just a name. Walks up to the function: hook calls are few.
fn is_called_conditionally(call: Node, src: &[u8]) -> bool {
    let mut conditional = false;
    let mut child = call;
    while let Some(parent) = child.parent() {
        let kind = parent.kind();
        if FUNCTIONS.contains(&kind) {
            return conditional && is_component_or_hook(parent, src);
        }
        if kind == "program" {
            return false;
        }
        let branch = |f: &str| parent.child_by_field_name(f) == Some(child);
        conditional |= match kind {
            "if_statement" | "ternary_expression" => branch("consequence") || branch("alternative"),
            "binary_expression" => {
                branch("right")
                    && parent
                        .child_by_field_name("operator")
                        .is_some_and(|o| matches!(o.kind(), "&&" | "||" | "??"))
            }
            "switch_case" | "switch_default" | "catch_clause" => true,
            _ => LOOPS.contains(&kind),
        };
        child = parent;
    }
    false
}

/// A function named like a component (`Panel`) or a hook (`usePanel`),
/// by its own name or the variable it's assigned to.
fn is_component_or_hook(function: Node, src: &[u8]) -> bool {
    let name = function.child_by_field_name("name").or_else(|| {
        function
            .parent()
            .filter(|p| p.kind() == "variable_declarator")
            .and_then(|p| p.child_by_field_name("name"))
    });
    name.is_some_and(|n| {
        let t = text(n, src);
        t.first().is_some_and(u8::is_ascii_uppercase)
            || (t.starts_with(b"use") && t.get(3).is_some_and(u8::is_ascii_uppercase))
    })
}

/// The `extends ...` text of the class a method belongs to.
fn superclass<'s>(method: Node, src: &'s [u8]) -> Option<&'s [u8]> {
    let class = method.parent()?.parent()?;
    let mut cursor = class.walk();
    let heritage = class
        .children(&mut cursor)
        .find(|c| c.kind() == "class_heritage")?;
    Some(text(heritage, src))
}

fn component_render_returns_nothing(method: Node, src: &[u8]) -> bool {
    method.child_by_field_name("body").is_some_and(|body| {
        !contains(body, |n| {
            n.kind() == "return_statement"
                && n.named_child(0).is_some_and(|v| v.kind() != "comment")
        })
    }) && superclass(method, src).is_some_and(|h| h.ends_with(b"Component"))
}

fn used_call_result<'t>(callee: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    let call = callee.parent().filter(|c| {
        c.kind() == "call_expression" && c.child_by_field_name("function") == Some(callee)
    })?;
    call.parent()
        .is_some_and(|p| p.kind() != "expression_statement")
        .then_some(call)
}

fn in_pure_component(method: Node, src: &[u8]) -> bool {
    superclass(method, src).is_some_and(|h| h.ends_with(b"PureComponent"))
}

// ---------------------------------------------------- accessibility filters

fn image_without_alt(element: Node, src: &[u8]) -> bool {
    let Some(open) = opening_tag(element) else {
        return false;
    };
    if has_spread(open) || attribute(open, "alt", src).is_some() {
        return false;
    }
    match tag_name(open, src) {
        Some(b"input") => attribute(open, "type", src)
            .and_then(|t| static_value(t, src))
            .is_some_and(|t| t == b"image"),
        Some(_) => true,
        None => false,
    }
}

fn lacks_title(element: Node, src: &[u8]) -> bool {
    opening_tag(element).is_some_and(|o| !has_spread(o) && attribute(o, "title", src).is_none())
}

/// The attribute is on an HTML element, not a component, whose props may
/// mean anything.
pub(super) fn on_dom_element(attr: Node, src: &[u8]) -> bool {
    attr.parent()
        .and_then(|o| tag_name(o, src))
        .is_some_and(is_dom_tag)
}

fn as_number(value: &[u8]) -> Option<i64> {
    std::str::from_utf8(value).ok()?.trim().parse().ok()
}

fn positive_value(attr: Node, src: &[u8]) -> bool {
    on_dom_element(attr, src)
        && static_value(attr, src)
            .and_then(as_number)
            .is_some_and(|n| n > 0)
}

fn hides_focusable_element(attr: Node, src: &[u8]) -> bool {
    if static_value(attr, src) != Some(b"true") {
        return false;
    }
    let Some(open) = attr.parent() else {
        return false;
    };
    let Some(tag) = tag_name(open, src).filter(|t| is_dom_tag(t)) else {
        return false;
    };
    let tab_index =
        attribute(open, "tabIndex", src).map(|t| static_value(t, src).and_then(as_number));
    match tab_index {
        Some(Some(n)) => n >= 0,
        Some(None) => false, // dynamic: unknown
        None => {
            matches!(tag, b"button" | b"input" | b"select" | b"textarea")
                || (tag == b"a" && attribute(open, "href", src).is_some())
        }
    }
}

fn link_used_as_button(element: Node, src: &[u8]) -> bool {
    let Some(open) = opening_tag(element) else {
        return false;
    };
    if has_spread(open) || attribute(open, "onClick", src).is_none() {
        return false;
    }
    match attribute(open, "href", src) {
        None => true,
        Some(href) => static_value(href, src)
            .is_some_and(|h| h == b"#" || h.trim_ascii_start().starts_with(b"javascript:")),
    }
}

fn has_no_accessible_content(element: Node, src: &[u8]) -> bool {
    let Some(open) = opening_tag(element) else {
        return false;
    };
    !has_spread(open)
        && [
            "aria-label",
            "aria-labelledby",
            "title",
            "dangerouslySetInnerHTML",
            "children",
        ]
        .iter()
        .all(|a| attribute(open, a, src).is_none())
        && !has_content(element, src)
}

fn alt_says_image(attr: Node, src: &[u8]) -> bool {
    static_value(attr, src).is_some_and(|alt| {
        alt.split(|b| !b.is_ascii_alphanumeric()).any(|w| {
            w.eq_ignore_ascii_case(b"image")
                || w.eq_ignore_ascii_case(b"photo")
                || w.eq_ignore_ascii_case(b"picture")
        })
    })
}

fn mouse_handler_without_keyboard(attr: Node, src: &[u8]) -> bool {
    let Some(open) = attr.parent() else {
        return false;
    };
    if !on_dom_element(attr, src) || has_spread(open) {
        return false;
    }
    let needed = match attr.named_child(0).map(|n| text(n, src)) {
        Some(b"onMouseOver") => "onFocus",
        Some(b"onMouseOut") => "onBlur",
        _ => return false,
    };
    attribute(open, needed, src).is_none()
}

// ---------------------------------------------------- test-framework filters

const EQUALITY_MATCHERS: &[&[u8]] = &[b"toBe", b"toEqual", b"toStrictEqual"];
const EQUALITY_ASSERTS: &[&[u8]] = &[
    b"equal",
    b"strictEqual",
    b"deepEqual",
    b"deepStrictEqual",
    b"notEqual",
    b"notStrictEqual",
    b"notDeepEqual",
    b"notDeepStrictEqual",
];

fn arguments_of(call: Node) -> Vec<Node> {
    call.child_by_field_name("arguments")
        .filter(|a| a.kind() == "arguments")
        .map(|a| {
            let mut cursor = a.walk();
            a.named_children(&mut cursor)
                .filter(|c| c.kind() != "comment")
                .collect()
        })
        .unwrap_or_default()
}

/// For `expect(subject)` itself.
fn is_expect_call(node: Node, src: &[u8]) -> bool {
    node.kind() == "call_expression"
        && node
            .child_by_field_name("function")
            .is_some_and(|f| f.kind() == "identifier" && text(f, src) == b"expect")
}

/// `expect(subject).<matcher>(args)`, through `.not`, `.resolves` and
/// `.rejects`: the subject, the matcher's name and its arguments.
fn expect_matcher<'t, 's>(
    call: Node<'t>,
    src: &'s [u8],
) -> Option<(Node<'t>, &'s [u8], Vec<Node<'t>>)> {
    let function = call
        .child_by_field_name("function")
        .filter(|f| f.kind() == "member_expression")?;
    let matcher = text(function.child_by_field_name("property")?, src);
    let mut object = function.child_by_field_name("object")?;
    while object.kind() == "member_expression"
        && object
            .child_by_field_name("property")
            .is_some_and(|p| matches!(text(p, src), b"not" | b"resolves" | b"rejects"))
    {
        object = object.child_by_field_name("object")?;
    }
    if !is_expect_call(object, src) {
        return None;
    }
    let subject = *arguments_of(object).first()?;
    Some((subject, matcher, arguments_of(call)))
}

/// `assert(args)` or `assert.<method>(args)`; the method is empty for the
/// former.
fn assert_call<'t, 's>(call: Node<'t>, src: &'s [u8]) -> Option<(&'s [u8], Vec<Node<'t>>)> {
    let function = call.child_by_field_name("function")?;
    let method: &[u8] = match function.kind() {
        "identifier" if text(function, src) == b"assert" => b"",
        "member_expression"
            if function
                .child_by_field_name("object")
                .is_some_and(|o| o.kind() == "identifier" && text(o, src) == b"assert") =>
        {
            text(function.child_by_field_name("property")?, src)
        }
        _ => return None,
    };
    Some((method, arguments_of(call)))
}

fn is_literal(node: Node) -> bool {
    match node.kind() {
        "string" | "number" | "true" | "false" | "null" | "undefined" => true,
        "unary_expression" => node.named_child(0).is_some_and(|n| n.kind() == "number"),
        _ => false,
    }
}

/// The assertion an `expect` or `assert` identifier starts:
/// `expect(x).matcher(...)` (through `.not`, `.resolves`, `.rejects`),
/// `assert(...)` or `assert.method(...)`. Anchoring on these rare names
/// keeps the assertion rules off the hot path of every call.
fn assertion_call<'t>(name: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let parent = name.parent()?;
    let is_call_of = |c: Node, callee: Node| {
        c.kind() == "call_expression" && c.child_by_field_name("function") == Some(callee)
    };
    if text(name, src) == b"assert" {
        let callee = if parent.kind() == "member_expression"
            && parent.child_by_field_name("object") == Some(name)
        {
            parent
        } else {
            name
        };
        return callee.parent().filter(|&c| is_call_of(c, callee));
    }
    let mut node = Some(parent).filter(|&c| is_call_of(c, name))?;
    loop {
        let member = node.parent().filter(|m| {
            m.kind() == "member_expression" && m.child_by_field_name("object") == Some(node)
        })?;
        let up = member.parent()?;
        if is_call_of(up, member) {
            return Some(up);
        }
        node = member;
    }
}

fn same_argument_assertion<'t>(name: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    assertion_call(name, src).filter(|&c| asserts_value_against_itself(c, src))
}

fn constant_assertion<'t>(name: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    assertion_call(name, src).filter(|&c| asserts_constants(c, src))
}

fn reversed_assertion<'t>(name: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    assertion_call(name, src).filter(|&c| expected_value_first(c, src))
}

fn unspecific_assertion<'t>(name: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    assertion_call(name, src).filter(|&c| has_more_specific_assertion(c, src))
}

fn any_error_assertion<'t>(name: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    assertion_call(name, src).filter(|&c| checks_any_error(c, src))
}

fn asserts_value_against_itself(call: Node, src: &[u8]) -> bool {
    if let Some((subject, matcher, args)) = expect_matcher(call, src) {
        // Two equal literals are the constant-assertion rule's case.
        return EQUALITY_MATCHERS.contains(&matcher)
            && !is_literal(subject)
            && matches!(args.as_slice(), [expected] if same_text(*expected, subject, src));
    }
    matches!(assert_call(call, src), Some((method, args))
        if EQUALITY_ASSERTS.contains(&method) && args.len() >= 2 && !is_literal(args[0]) && same_text(args[0], args[1], src))
}

fn asserts_constants(call: Node, src: &[u8]) -> bool {
    if let Some((subject, matcher, args)) = expect_matcher(call, src) {
        return is_literal(subject)
            && match args.as_slice() {
                [] => true,
                [expected] => EQUALITY_MATCHERS.contains(&matcher) && is_literal(*expected),
                _ => false,
            };
    }
    match assert_call(call, src) {
        Some((b"" | b"ok" | b"isTrue" | b"isOk", args)) => args
            .first()
            .is_some_and(|a| matches!(a.kind(), "true" | "number" | "string")),
        Some((method, args)) => {
            EQUALITY_ASSERTS.contains(&method)
                && args.len() >= 2
                && is_literal(args[0])
                && is_literal(args[1])
        }
        None => false,
    }
}

fn expected_value_first(call: Node, src: &[u8]) -> bool {
    if let Some((subject, matcher, args)) = expect_matcher(call, src) {
        return EQUALITY_MATCHERS.contains(&matcher)
            && is_literal(subject)
            && matches!(args.as_slice(), [actual] if !is_literal(*actual));
    }
    matches!(assert_call(call, src), Some((method, args))
        if EQUALITY_ASSERTS.contains(&method) && args.len() >= 2 && is_literal(args[0]) && !is_literal(args[1]))
}

fn is_equality(node: Node) -> bool {
    node.kind() == "binary_expression"
        && node
            .child_by_field_name("operator")
            .is_some_and(|o| EQUALITY.contains(&o.kind()))
}

fn has_more_specific_assertion(call: Node, src: &[u8]) -> bool {
    if let Some((subject, matcher, args)) = expect_matcher(call, src) {
        if !EQUALITY_MATCHERS.contains(&matcher) {
            return false;
        }
        let length = subject.kind() == "member_expression"
            && subject
                .child_by_field_name("property")
                .is_some_and(|p| text(p, src) == b"length");
        let boolean_of_comparison = is_equality(subject)
            && matches!(args.as_slice(), [b] if matches!(b.kind(), "true" | "false"));
        return length || boolean_of_comparison;
    }
    matches!(assert_call(call, src), Some((b"" | b"ok", args)) if args.first().is_some_and(|a| is_equality(*a)))
}

/// Words that only continue an assertion chain (Jest's modifiers and
/// Chai's language chains): one of them last means no check was made.
const CHAIN_WORDS: &[&[u8]] = &[
    b"not",
    b"resolves",
    b"rejects",
    b"to",
    b"be",
    b"been",
    b"is",
    b"that",
    b"which",
    b"and",
    b"has",
    b"have",
    b"with",
    b"at",
    b"of",
    b"same",
    b"but",
    b"does",
    b"deep",
];

fn is_incomplete_expect(node: Node, src: &[u8]) -> bool {
    if node.kind() == "call_expression" {
        return is_expect_call(node, src);
    }
    let mut n = node;
    while n.kind() == "member_expression" {
        if !n
            .child_by_field_name("property")
            .is_some_and(|p| CHAIN_WORDS.contains(&text(p, src)))
        {
            return false;
        }
        match n.child_by_field_name("object") {
            Some(o) => n = o,
            None => return false,
        }
    }
    is_expect_call(n, src)
}

fn checks_any_error(call: Node, src: &[u8]) -> bool {
    if let Some((_, matcher, args)) = expect_matcher(call, src) {
        // `.not.toThrow()` rightly takes no argument.
        let negated = call
            .child_by_field_name("function")
            .and_then(|f| f.child_by_field_name("object"))
            .and_then(|o| o.child_by_field_name("property"))
            .is_some_and(|p| text(p, src) == b"not");
        return matches!(matcher, b"toThrow" | b"toThrowError") && args.is_empty() && !negated;
    }
    matches!(assert_call(call, src), Some((b"throws" | b"rejects", args)) if args.len() == 1)
}

/// The whole `expect(p).resolves.toBe(x)` expression when it's a statement
/// of its own: neither awaited nor returned.
fn unawaited_promise_assertion<'t>(word: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let member = word.parent().filter(|m| {
        m.kind() == "member_expression" && m.child_by_field_name("property") == Some(word)
    })?;
    let mut root = member.child_by_field_name("object")?;
    while root.kind() == "member_expression" {
        root = root.child_by_field_name("object")?;
    }
    if !is_expect_call(root, src) {
        return None;
    }
    let mut top = member;
    while let Some(p) = top.parent().filter(|p| {
        (p.kind() == "member_expression" && p.child_by_field_name("object") == Some(top))
            || (p.kind() == "call_expression" && p.child_by_field_name("function") == Some(top))
    }) {
        top = p;
    }
    top.parent()
        .is_some_and(|p| p.kind() == "expression_statement")
        .then_some(top)
}

fn is_blank_string(string: Node, src: &[u8]) -> bool {
    let t = text(string, src);
    t.get(1..t.len().saturating_sub(1))
        .is_some_and(|inner| inner.iter().all(u8::is_ascii_whitespace))
}

fn is_async(function: Node, _: &[u8]) -> bool {
    has_token(function, "async")
}

/// Whether the line above `node` (skipping blank lines) is or ends a comment.
fn no_comment_above(node: Node, src: &[u8]) -> bool {
    let line_start = src[..node.start_byte()]
        .iter()
        .rposition(|&b| b == b'\n')
        .map_or(0, |i| i + 1);
    let above = src[..line_start]
        .split(|&b| b == b'\n')
        .rev()
        .map(<[u8]>::trim_ascii)
        .find(|l| !l.is_empty());
    !above.is_some_and(|l| l.starts_with(b"//") || l.starts_with(b"*") || l.ends_with(b"*/"))
}

/// The name a test-framework call starts with: `it` for `it(...)` and
/// `it.only(...)`.
fn test_callee<'t, 's>(statement: Node<'t>, src: &'s [u8]) -> Option<(&'s [u8], Node<'t>)> {
    let call = statement
        .named_child(0)
        .filter(|c| statement.kind() == "expression_statement" && c.kind() == "call_expression")?;
    let mut function = call.child_by_field_name("function")?;
    if function.kind() == "member_expression" {
        function = function.child_by_field_name("object")?;
    }
    (function.kind() == "identifier").then(|| (text(function, src), call))
}

/// The callback of the `describe(title, () => {...})` call that `name`
/// starts. Anchored on the name rather than matched as a call pattern: a
/// pattern with a child step inside the arguments stays open over every
/// callback body in the file.
fn suite_callback<'t>(name: Node<'t>) -> Option<Node<'t>> {
    let call = name.parent().filter(|c| {
        c.kind() == "call_expression" && c.child_by_field_name("function") == Some(name)
    })?;
    let mut cursor = call.child_by_field_name("arguments")?.walk();
    let args = call.child_by_field_name("arguments")?;
    args.named_children(&mut cursor)
        .find(|a| matches!(a.kind(), "arrow_function" | "function_expression"))
}

/// The statements a suite's tests are listed in: a describe callback's
/// body, or the file itself.
fn suite_block<'t>(node: Node<'t>) -> Option<Node<'t>> {
    match node.kind() {
        "program" => Some(node),
        _ => suite_callback(node)?
            .child_by_field_name("body")
            .filter(|b| b.kind() == "statement_block"),
    }
}

fn async_suite_callback<'t>(name: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    suite_callback(name).filter(|&f| is_async(f, src))
}

fn duplicate_test_title_in_suite<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    duplicate_test_title(suite_block(node)?, src)
}

fn hook_after_test_in_suite<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    hook_after_test(suite_block(node)?, src)
}

fn duplicate_test_title<'t>(block: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut seen = std::collections::HashSet::new();
    let mut cursor = block.walk();
    block.named_children(&mut cursor).find_map(|s| {
        let (name, call) = test_callee(s, src)?;
        if !matches!(name, b"it" | b"test") {
            return None;
        }
        let title = arguments_of(call)
            .into_iter()
            .next()
            .filter(|t| t.kind() == "string")?;
        (!seen.insert(text(title, src))).then_some(title)
    })
}

fn hook_after_test<'t>(block: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut seen_test = false;
    let mut cursor = block.walk();
    for s in block.named_children(&mut cursor) {
        let Some((name, call)) = test_callee(s, src) else {
            continue;
        };
        match name {
            b"it" | b"test" | b"describe" | b"context" | b"suite" => seen_test = true,
            b"beforeEach" | b"afterEach" | b"beforeAll" | b"afterAll" | b"before" | b"after"
                if seen_test =>
            {
                return Some(call);
            }
            _ => {}
        }
    }
    None
}

fn is_fixed_wait(call: Node, src: &[u8]) -> bool {
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    let (Some(object), Some(method)) = (
        function.child_by_field_name("object"),
        function.child_by_field_name("property"),
    ) else {
        return false;
    };
    match (text(object, src), text(method, src)) {
        (b"cy", b"wait") => arguments_of(call)
            .first()
            .is_some_and(|a| a.kind() == "number"),
        (b"cy", b"pause" | b"debug")
        | (b"page", b"waitForTimeout" | b"pause")
        | (b"browser", b"pause") => true,
        _ => false,
    }
}

// ---------------------------------------------------- batch 4 filters

fn fraction_compared_for_equality<'t>(number: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    number.parent().filter(|p| {
        p.kind() == "binary_expression"
            && p.child_by_field_name("operator")
                .is_some_and(|o| EQUALITY.contains(&o.kind()))
    })
}

fn is_not_an_error(new: Node, src: &[u8]) -> bool {
    // `try { new URL(s); } catch { ... }` constructs to validate.
    let validates = new
        .parent()
        .and_then(|statement| statement.parent())
        .and_then(|block| block.parent())
        .is_some_and(|t| t.kind() == "try_statement");
    !validates
        && new
            .child_by_field_name("constructor")
            .is_some_and(|c| !text(c, src).ends_with(b"Error"))
}

fn always_exits_first_iteration(lp: Node, _: &[u8]) -> bool {
    let Some(body) = lp
        .child_by_field_name("body")
        .filter(|b| b.kind() == "statement_block")
    else {
        return false;
    };
    last_statement(body).is_some_and(|last| {
        matches!(
            last.kind(),
            "return_statement" | "throw_statement" | "break_statement"
        )
    }) && !contains(body, |n| n.kind() == "continue_statement")
}

/// The first statement after an unconditional jump in a block. Hoisted
/// declarations (functions, TypeScript types) are fine there.
fn statement_after_jump<'t>(block: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    let mut jumped = false;
    let mut cursor = block.walk();
    for c in block.named_children(&mut cursor) {
        match c.kind() {
            "comment"
            | "function_declaration"
            | "generator_function_declaration"
            | "type_alias_declaration"
            | "interface_declaration"
            | "empty_statement" => {}
            "return_statement" | "throw_statement" | "break_statement" | "continue_statement" => {
                if jumped {
                    return Some(c);
                }
                jumped = true;
            }
            _ if jumped => return Some(c),
            _ => {}
        }
    }
    None
}

fn has_no_effect(expr: Node, src: &[u8]) -> bool {
    // `let // note` before a declaration's name parses as a bare `let`, and
    // statements next to a syntax error are the parser's guesses.
    if text(expr, src) == b"let"
        || expr
            .parent()
            .and_then(|statement| statement.parent())
            .is_some_and(|block| block.has_error())
    {
        return false;
    }
    match expr.kind() {
        "binary_expression" => {
            expr.child_by_field_name("operator")
                .is_some_and(|o| !matches!(o.kind(), "&&" | "||" | "??"))
                && !has_side_effects(expr)
        }
        "unary_expression" => {
            expr.child_by_field_name("operator")
                .is_some_and(|o| matches!(o.kind(), "!" | "-" | "+" | "~" | "typeof"))
                && !has_side_effects(expr)
        }
        _ => true,
    }
}

fn misplaced_super<'t>(constructor: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let body = constructor.child_by_field_name("body")?;
    let derived = superclass(constructor, src).is_some_and(|h| h.starts_with(b"extends"));
    let is_super_call = |n: Node| {
        n.kind() == "call_expression"
            && n.child_by_field_name("function")
                .is_some_and(|f| f.kind() == "super")
    };
    if derived {
        (!contains(body, is_super_call)).then_some(constructor)
    } else {
        find_below(body, false, is_super_call)
    }
}

/// What a statement sets, and the value it sets: `a[k] = v` and
/// `m.set(k, v)`.
fn element_write<'t>(statement: Node<'t>, src: &[u8]) -> Option<(Vec<u8>, Vec<u8>, Node<'t>)> {
    let expr = statement
        .named_child(0)
        .filter(|_| statement.kind() == "expression_statement")?;
    match expr.kind() {
        "assignment_expression" => {
            // `a[++i] = x` writes a different element each time.
            let left = expr
                .child_by_field_name("left")
                .filter(|l| l.kind() == "subscript_expression" && !has_side_effects(*l))?;
            let target = text(left, src).to_vec();
            Some((target.clone(), target, expr.child_by_field_name("right")?))
        }
        "call_expression" => {
            let function = expr
                .child_by_field_name("function")
                .filter(|f| f.kind() == "member_expression")?;
            if text(function.child_by_field_name("property")?, src) != b"set" {
                return None;
            }
            let args = arguments_of(expr);
            let [key, value] = args[..] else {
                return None;
            };
            let object = text(function.child_by_field_name("object")?, src).to_vec();
            let mut target = object.clone();
            target.extend_from_slice(b"|");
            target.extend_from_slice(text(key, src));
            Some((target, object, value))
        }
        _ => None,
    }
}

fn overwritten_element<'t>(block: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut cursor = block.walk();
    let statements: Vec<Node> = block
        .named_children(&mut cursor)
        .filter(|c| c.kind() != "comment")
        .collect();
    statements.windows(2).find_map(|pair| {
        let (first, _, _) = element_write(pair[0], src)?;
        let (second, read, value) = element_write(pair[1], src)?;
        // `a[k] = a[k] + 1` reads the first value, so it isn't lost.
        let reads_it = text(value, src)
            .windows(read.len())
            .any(|w| w == read.as_slice());
        (first == second && !reads_it).then_some(pair[1])
    })
}

fn has_constant_result(expr: Node, _: &[u8]) -> bool {
    let (Some(op), Some(left), Some(right)) = (
        expr.child_by_field_name("operator"),
        expr.child_by_field_name("left"),
        expr.child_by_field_name("right"),
    ) else {
        return false;
    };
    let fresh = |n: Node| {
        matches!(
            n.kind(),
            "object"
                | "array"
                | "arrow_function"
                | "function_expression"
                | "class"
                | "regex"
                | "new_expression"
        )
    };
    match op.kind() {
        "==" | "!=" | "===" | "!==" => fresh(left) || fresh(right),
        "??" => {
            fresh(left)
                || matches!(
                    left.kind(),
                    "string" | "number" | "template_string" | "true" | "false"
                )
        }
        _ => false,
    }
}

fn accessor_self_access<'t>(accessor: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let name = accessor.child_by_field_name("name")?;
    let body = accessor.child_by_field_name("body")?;
    let is_own_property = |m: Node| {
        m.kind() == "member_expression"
            && m.child_by_field_name("object")
                .is_some_and(|o| o.kind() == "this")
            && m.child_by_field_name("property")
                .is_some_and(|p| same_text(p, name, src))
    };
    if has_token(accessor, "get") {
        // A lazy getter replaces itself first (`defineLazy(this, "shape")`,
        // Object.defineProperty), so reading the property afterwards is fine.
        let redefines_itself = contains(body, |n| {
            n.kind() == "string" && string_content(n, src) == text(name, src)
        });
        if redefines_itself {
            return None;
        }
        find_below(body, false, is_own_property)
    } else {
        find_below(body, false, |n| {
            n.kind() == "assignment_expression"
                && n.child_by_field_name("left").is_some_and(is_own_property)
        })
    }
}

fn in_get_request(body: Node, src: &[u8]) -> bool {
    let Some(object) = body.parent() else {
        return false;
    };
    let mut cursor = object.walk();
    object.named_children(&mut cursor).any(|p| {
        p.kind() == "pair"
            && p.child_by_field_name("key")
                .is_some_and(|k| text(k, src) == b"method")
            && p.child_by_field_name("value")
                .filter(|v| v.kind() == "string")
                .is_some_and(|v| {
                    let t = text(v, src);
                    let inner = t.get(1..t.len().saturating_sub(1)).unwrap_or(b"");
                    inner.eq_ignore_ascii_case(b"get") || inner.eq_ignore_ascii_case(b"head")
                })
    })
}

fn in_object_literal(node: Node, _: &[u8]) -> bool {
    node.kind() == "pair" || node.parent().is_some_and(|p| p.kind() == "object")
}

/// The first jump that leaves `block`, walking down with the loops,
/// switches and labels around the current node. For a loop's body, an
/// unlabeled `continue` stays in the loop, and `yield` and `await` count
/// as exits: such loops wait between iterations on purpose.
fn first_escape<'t>(block: Node<'t>, src: &[u8], loop_body: bool) -> Option<Node<'t>> {
    let mut around: Vec<(usize, Node)> = Vec::new();
    let mut cursor = block.walk();
    if !cursor.goto_first_child() {
        return None;
    }
    let mut depth = 1;
    loop {
        let n = cursor.node();
        while around.last().is_some_and(|(d, _)| *d >= depth) {
            around.pop();
        }
        match n.kind() {
            "return_statement" | "throw_statement" => return Some(n),
            "yield_expression" | "await_expression" if loop_body => return Some(n),
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
                let continues_this_loop =
                    loop_body && kind == "continue_statement" && label.is_none();
                if !stays && !continues_this_loop {
                    return Some(n);
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
                return None;
            }
            depth -= 1;
        }
    }
}

fn never_ends(lp: Node, src: &[u8]) -> bool {
    let always = match lp.child_by_field_name("condition") {
        None => lp.kind() == "for_statement",
        Some(c) => {
            let mut c = c;
            while matches!(
                c.kind(),
                "parenthesized_expression" | "expression_statement"
            ) {
                match c.named_child(0) {
                    Some(inner) => c = inner,
                    None => break,
                }
            }
            matches!(c.kind(), "true" | "empty_statement")
        }
    };
    always
        && lp
            .child_by_field_name("body")
            .is_some_and(|b| first_escape(b, src, true).is_none())
}

/// Where a short-circuited optional chain is used in a way that throws.
fn unsafe_chain_use<'t>(token: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    let mut chain = token.parent()?;
    while let Some(p) = chain.parent().filter(|p| {
        let continues = |f: &str| p.child_by_field_name(f) == Some(chain);
        match p.kind() {
            "member_expression" | "subscript_expression" => continues("object"),
            "call_expression" => continues("function"),
            _ => false,
        }
    }) {
        chain = p;
    }
    let parent = chain.parent()?;
    match parent.kind() {
        "parenthesized_expression" => {
            let user = parent.parent()?;
            let uses = |f: &str| user.child_by_field_name(f) == Some(parent);
            let throws = match user.kind() {
                "member_expression" | "subscript_expression" => uses("object"),
                "call_expression" => uses("function"),
                "new_expression" => uses("constructor"),
                _ => false,
            };
            throws.then_some(user)
        }
        "spread_element" => parent
            .parent()
            .filter(|g| matches!(g.kind(), "array" | "arguments"))
            .map(|_| parent),
        "for_in_statement" => (parent.child_by_field_name("right") == Some(chain)
            && has_token(parent, "of"))
        .then_some(chain),
        "variable_declarator" => (parent.child_by_field_name("value") == Some(chain)
            && parent
                .child_by_field_name("name")
                .is_some_and(|n| matches!(n.kind(), "object_pattern" | "array_pattern")))
        .then_some(parent),
        _ => None,
    }
}

pub(super) fn string_content<'s>(string: Node, src: &'s [u8]) -> &'s [u8] {
    let t = text(string, src);
    t.get(1..t.len().saturating_sub(1)).unwrap_or(b"")
}

fn is_weak_key_size(pair: Node, src: &[u8]) -> bool {
    let (Some(key), Some(value)) = (
        pair.child_by_field_name("key"),
        pair.child_by_field_name("value"),
    ) else {
        return false;
    };
    match text(key, src) {
        b"modulusLength" => {
            value.kind() == "number" && as_number(text(value, src)).is_some_and(|n| n < 2048)
        }
        _ => {
            value.kind() == "string"
                && matches!(
                    string_content(value, src),
                    b"secp112r1"
                        | b"secp112r2"
                        | b"secp128r1"
                        | b"secp128r2"
                        | b"secp160k1"
                        | b"secp160r1"
                        | b"secp160r2"
                        | b"secp192k1"
                        | b"prime192v1"
                        | b"P-192"
                        | b"sect163k1"
                        | b"sect163r1"
                        | b"sect163r2"
                        | b"sect193r1"
                        | b"sect193r2"
                )
        }
    }
}

fn accepts_any_identity(pair: Node, _: &[u8]) -> bool {
    let Some(f) = pair
        .child_by_field_name("value")
        .filter(|v| matches!(v.kind(), "arrow_function" | "function_expression"))
    else {
        return false;
    };
    match f.child_by_field_name("body") {
        Some(b) if b.kind() == "statement_block" => !contains(b, |n| {
            n.kind() == "return_statement"
                && n.named_child(0)
                    .is_some_and(|v| !matches!(v.kind(), "undefined" | "null" | "comment"))
        }),
        Some(b) => matches!(b.kind(), "undefined" | "null"),
        None => false,
    }
}

/// `node` is the first argument of a call to one of `names` (as a function
/// or a method). Checked only on rare strings, so the parent lookups stay
/// cheap.
fn is_first_argument_of(node: Node, names: &[&[u8]], src: &[u8]) -> bool {
    let Some(args) = node.parent().filter(|a| a.kind() == "arguments") else {
        return false;
    };
    args.named_child(0) == Some(node)
        && args
            .parent()
            .and_then(|call| call.child_by_field_name("function"))
            .map(|f| f.child_by_field_name("property").unwrap_or(f))
            .is_some_and(|name| names.contains(&text(name, src)))
}

const CIPHER_FACTORIES: &[&[u8]] = &[
    b"createCipheriv",
    b"createCipher",
    b"createDecipheriv",
    b"createDecipher",
];

fn is_cipher_algorithm(string: Node, src: &[u8]) -> bool {
    is_first_argument_of(string, CIPHER_FACTORIES, src)
}

fn is_cipher_algorithm_or_padding(node: Node, src: &[u8]) -> bool {
    match node.kind() {
        "string" => is_cipher_algorithm(node, src),
        _ => is_member_property(node, src),
    }
}

fn allows_none_algorithm(pair: Node, src: &[u8]) -> bool {
    let is_none =
        |n: Node| n.kind() == "string" && string_content(n, src).eq_ignore_ascii_case(b"none");
    pair.child_by_field_name("value")
        .is_some_and(|v| match v.kind() {
            "array" => {
                let mut cursor = v.walk();
                v.named_children(&mut cursor).any(is_none)
            }
            _ => is_none(v),
        })
}

/// A file mode literal: 0o755, 0755, 493 or "755".
fn file_mode(node: Node, src: &[u8]) -> Option<u32> {
    let t = std::str::from_utf8(text(node, src)).ok()?.replace('_', "");
    match node.kind() {
        "number" => {
            let lower = t.to_ascii_lowercase();
            if let Some(octal) = lower.strip_prefix("0o") {
                u32::from_str_radix(octal, 8).ok()
            } else if lower.len() > 1 && lower.starts_with('0') {
                u32::from_str_radix(&lower[1..], 8).ok()
            } else {
                lower.parse().ok()
            }
        }
        "string" => u32::from_str_radix(t.trim_matches(['\'', '"']), 8).ok(),
        _ => None,
    }
}

fn world_accessible_mode<'t>(name: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !is_called(name, src) {
        return None;
    }
    let parent = name.parent()?;
    let call = if parent.kind() == "member_expression" {
        parent.parent()?
    } else {
        parent
    };
    let mode = *arguments_of(call).get(1)?;
    file_mode(mode, src)
        .is_some_and(|m| m & 0o002 != 0)
        .then_some(mode)
}

fn open_without_noopener<'t>(callee: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let call = callee.parent().filter(|c| {
        c.kind() == "call_expression" && c.child_by_field_name("function") == Some(callee)
    })?;
    let args = arguments_of(call);
    let safe = args.get(2).is_some_and(|features| {
        features.kind() == "string" && {
            let f = string_content(*features, src);
            f.windows(8).any(|w| w == b"noopener") || f.windows(10).any(|w| w == b"noreferrer")
        }
    });
    (!safe).then_some(call)
}

fn blank_target_without_noopener(target: Node, src: &[u8]) -> bool {
    if static_value(target, src) != Some(b"_blank") {
        return false;
    }
    let Some(open) = target.parent() else {
        return false;
    };
    if has_spread(open) {
        return false;
    }
    let rel_ok = attribute(open, "rel", src)
        .and_then(|r| static_value(r, src))
        .is_some_and(|r| {
            r.windows(8).any(|w| w == b"noopener") || r.windows(10).any(|w| w == b"noreferrer")
        });
    let external = attribute(open, "href", src).is_some_and(|h| match static_value(h, src) {
        Some(v) => v.starts_with(b"http://") || v.starts_with(b"https://") || v.starts_with(b"//"),
        None => true, // dynamic: may be external
    });
    external && !rel_ok
}

fn command_by_name<'t>(name: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !is_called(name, src) {
        return None;
    }
    let parent = name.parent()?;
    let call = if parent.kind() == "member_expression" {
        let object = parent.child_by_field_name("object")?;
        if !matches!(
            text(object, src),
            b"child_process" | b"childProcess" | b"cp"
        ) {
            return None;
        }
        parent.parent()?
    } else {
        parent
    };
    let command = arguments_of(call)
        .into_iter()
        .next()
        .filter(|a| a.kind() == "string")?;
    let first_word = string_content(command, src)
        .split(u8::is_ascii_whitespace)
        .next()
        .unwrap_or(b"");
    (!first_word.is_empty() && !first_word.contains(&b'/')).then_some(command)
}

fn looks_like_a_secret_value(string: Node, src: &[u8]) -> bool {
    let v = string_content(string, src);
    v.len() >= 4
        && !v.iter().any(u8::is_ascii_whitespace)
        && !matches!(v.first(), Some(b'$' | b'<' | b'{' | b'/' | b'.' | b'*'))
        && !v.windows(2).all(|w| w[0] == w[1])
}

/// Long, mixed letters and digits, and varied: what generated keys look
/// like, unlike names, URLs or messages.
fn looks_random(string: Node, src: &[u8]) -> bool {
    let v = string_content(string, src);
    if v.len() < 16
        || v.iter().any(u8::is_ascii_whitespace)
        || v.windows(3).any(|w| w == b"://")
        || !v.iter().any(u8::is_ascii_digit)
        || !v.iter().any(u8::is_ascii_alphabetic)
    {
        return false;
    }
    let mut counts = [0usize; 256];
    for &b in v {
        counts[b as usize] += 1;
    }
    let n = v.len() as f64;
    let entropy: f64 = counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum();
    entropy >= 3.5
}

/// The options object of `res.cookie(...)`, or a `cookie: {...}` option.
fn in_cookie_options(pair: Node, src: &[u8]) -> bool {
    let Some(holder) = pair.parent().and_then(|o| o.parent()) else {
        return false;
    };
    match holder.kind() {
        "pair" => holder
            .child_by_field_name("key")
            .is_some_and(|k| text(k, src) == b"cookie"),
        "arguments" => holder
            .parent()
            .and_then(|c| c.child_by_field_name("function"))
            .and_then(|f| f.child_by_field_name("property"))
            .is_some_and(|p| text(p, src) == b"cookie"),
        _ => false,
    }
}

fn allows_any_origin<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    match node.kind() {
        "pair" => node
            .child_by_field_name("value")
            .is_some_and(|v| string_content(v, src) == b"*")
            .then_some(node),
        "string" => {
            let args = node.parent().filter(|a| a.kind() == "arguments")?;
            (args.named_child(0) == Some(node)
                && args
                    .named_child(1)
                    .is_some_and(|v| v.kind() == "string" && string_content(v, src) == b"*"))
            .then(|| args.parent())
            .flatten()
        }
        _ => {
            // `cors()` with no options allows every origin.
            let call = node.parent().filter(|c| {
                c.kind() == "call_expression" && c.child_by_field_name("function") == Some(node)
            })?;
            arguments_of(call).is_empty().then_some(call)
        }
    }
}

fn is_referrer_policy(string: Node, src: &[u8]) -> bool {
    let Some(parent) = string.parent() else {
        return false;
    };
    match parent.kind() {
        "pair" => parent
            .child_by_field_name("key")
            .is_some_and(|k| matches!(text(k, src), b"policy" | b"referrerPolicy")),
        "arguments" => parent.named_child(0).is_some_and(|h| {
            h.kind() == "string" && string_content(h, src).eq_ignore_ascii_case(b"referrer-policy")
        }),
        _ => false,
    }
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
        assert_eq!(flagged("js/jump-in-finally", JS, src), [3]);
        let inner = "try { f(); } finally {\n  for (;;) { if (a) { break; } continue; }\n  l: { break l; }\n  switch (x) { case 1: break; }\n}";
        assert!(flagged("js/jump-in-finally", JS, inner).is_empty());
    }

    #[test]
    fn typescript_parameters_and_members() {
        let params = "function f(a: number, b?: string, ...a: number[]) {}";
        assert_eq!(flagged("js/duplicate-parameter", TS, params), [1]);
        // Overload signatures and accessor pairs are not duplicates.
        let class = "class A {\n  m(x: number): void;\n  m(x: any) {}\n  get v() { return 1; }\n  set v(x) {}\n  v2 = 1;\n  v2 = 2;\n}";
        assert_eq!(flagged("js/duplicate-member", TS, class), [7]);
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
        let src = "if (a) {} else if (b) {}\nelse if (a) {}\nif (a) { if (a) {} }\nswitch (x) {\ncase 1: case 2:\ncase 1: }";
        assert_eq!(flagged("js/duplicate-condition", JS, src), [2, 6]);
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
        // Release builds must fit the default per-file timeout (10 s). Debug
        // builds run several times slower: a busy CI runner (Windows, tests in
        // parallel) reached 10 s here. The test guards against quadratic
        // blowups, not small slowdowns, so debug gets 30 s.
        let limit = if cfg!(debug_assertions) { 30 } else { 10 };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(limit);
        let file = analyze("t", JS, &src, &rules, &cfg, deadline).expect("finishes in time");
        assert!(file.issues.iter().any(|i| i.rule == "js/jump-in-finally"));
    }

    #[test]
    fn fall_through_cases() {
        let src = "switch (x) {
case 1: a();
case 2: b(); // falls through
case 3: { c(); break; }
case 4: if (y) { d(); } else { return; }
case 5:
case 6: e(); /* fall through */
default: f();
}";
        assert_eq!(flagged("js/switch-fallthrough", JS, src), [2]);
        let later = "switch (x) {\ncase 1: break;\ncase 2: if (y) { d(); } else { return; }\ncase 3: g();\n}";
        assert_eq!(flagged("js/switch-fallthrough", JS, later), [3]);
    }

    #[test]
    fn typescript_parameters_functions_and_classes() {
        let src = "function f(a: number = 1, b?: string, c: number) { h(); }
function g(a = 1, ...rest: number[]) { h(); }
abstract class A { abstract m(): void; n(): void; o() {} }
class B implements I {}
@dec class C {}";
        assert_eq!(flagged("js/default-param-not-last", TS, src), [1]);
        assert_eq!(flagged("js/empty-function", TS, src), [3]);
        assert!(flagged("js/empty-class", TS, src).is_empty());
        let ambient = "declare namespace M { class Projection {} }";
        assert!(flagged("js/empty-class", TS, ambient).is_empty());
        let generic = "const t = make<{\n  a: string;\n}>();";
        assert!(flagged("js/call-arguments-new-line", TS, generic).is_empty());
    }

    #[test]
    fn small_syntax_rules() {
        let src = "/* eslint-disable-next-line */
// eslint-disable-line -- because
// eslint-disabled-ish
x = 08;
y = '\\\\1';
z = a ? b : c ? d : e ? f : g;
w = (a ? b : c) ? d : e;
v = load
  (c)
  .then(f);";
        assert_eq!(flagged("js/eslint-disable-all", JS, src), [1, 2]);
        assert!(flagged("js/octal-literal", JS, src).is_empty());
        assert!(flagged("js/octal-escape", JS, src).is_empty());
        assert_eq!(flagged("js/nested-ternary", JS, src), [6, 6, 7]);
        let jsx = "const v = <div>{!rows ? <Spinner /> : rows.length ? <List /> : x ? <A /> : <B />}</div>;";
        assert!(flagged("js/nested-ternary", JS, jsx).is_empty());
        assert_eq!(flagged("js/call-arguments-new-line", JS, src), [9]);
        let jumps = "const f = () => { g(); return; };\nwhile (a) { b(); continue; }\nfunction h() { return; /* done */ }";
        assert_eq!(flagged("js/redundant-jump", TS, jumps), [1, 2]);
    }

    const TSX: Lang = Lang::Tsx;

    #[test]
    fn react_rules_in_tsx() {
        let src = "const L = ({ rows }: P) => (
  <ul>
    {rows.map((r: Row, i: number) => <li key={i}>{r.name}</li>)}
    {rows.map((r) => (
      <Item {...r} />
    ))}
    {rows.map((r) => {
      if (r.hidden) { return null; }
      return <Item name={r.name} />;
    })}
  </ul>
);";
        assert_eq!(flagged("js/jsx-index-key", TSX, src), [3]);
        assert_eq!(flagged("js/jsx-missing-key", TSX, src), [9]);
    }

    #[test]
    fn hooks_and_state() {
        let src = "function C({ a }) {
  const [v, setV] = React.useState(0);
  const x = a && useMemo(() => 1, []);
  for (const k of ks) { useRef(k); }
  const ok = useCallback(() => (a ? 1 : 2), [a]);
  if (useFlag()) { f(); }
  setV(v);
  return <b onClick={() => setV(v)} />;
}";
        assert_eq!(flagged("js/hook-in-condition", JS, src), [3, 4]);
        let helpers = "function build(gen) { return ok ? useFunc(gen) : null; }\nconst useThing = (a) => (a ? useMemo(f) : 1);";
        assert_eq!(flagged("js/hook-in-condition", JS, helpers), [2]);
        assert_eq!(flagged("js/set-state-in-render", JS, src), [7]);
        assert_eq!(flagged("js/state-setter-same-value", JS, src), [7]);
    }

    #[test]
    fn test_framework_rules() {
        let src = "describe('s', () => {
  it('a', () => { expect(x).not.toBe(x); expect(3).not.toEqual(y); });
  describe('inner', () => { it('a', () => {}); });
  it('a', () => {});
  afterEach(() => {});
});
it('a', () => {});
/* waiting on the vendor fix,
   see #12 */
xit('later', () => {});
test.skip('soon', () => {});";
        assert_eq!(flagged("js/duplicate-test-title", JS, src), [4]);
        assert_eq!(flagged("js/hook-after-test", JS, src), [5]);
        assert_eq!(flagged("js/assertion-same-argument", JS, src), [2]);
        assert_eq!(flagged("js/assertion-order", JS, src), [2]);
        assert_eq!(flagged("js/skipped-test-without-reason", JS, src), [11]);
        let throws = "expect(() => f()).not.toThrow();\nexpect(() => g()).toThrow();";
        assert_eq!(flagged("js/unspecified-throw", JS, throws), [2]);
        let state = "class Machine { go() { this.state = 1; } }\nclass C extends React.Component { go() { this.state = 1; } }";
        assert_eq!(flagged("js/state-mutation", JS, state), [2]);
        let spaced = "const v = <p>Text<> <button /></></p>;";
        assert!(flagged("js/redundant-fragment", JS, spaced).is_empty());
    }

    #[test]
    fn accessibility_on_components_is_left_alone() {
        let src = "const v = <>
  <Link accessKey=\"k\" onMouseOver={f} tabIndex={3} />
  <a href=\"/x\" aria-hidden>x</a>
  <a href={url}>{label}</a>
  <h1 aria-label=\"Title\" />
  <img alt={alt} src={s} />
</>;";
        for rule in [
            "js/accesskey",
            "js/mouse-without-keyboard",
            "js/tabindex-positive",
            "js/anchor-content",
            "js/heading-content",
            "js/img-alt",
        ] {
            assert!(flagged(rule, JS, src).is_empty(), "{rule}");
        }
        assert_eq!(flagged("js/aria-hidden-focusable", JS, src), [3]);
    }

    #[test]
    fn control_flow_bugs() {
        let src = "function f(x) {
  switch (x) { case 1: return 1; g(); }
  outer: while (true) { while (true) { break outer; } }
  while (true) { if (a) { continue; } tick(); }
  while (true) { yield next(); }
  for (;;) { for (const y of ys) { break; } }
  return 2;
  type T = number;
  function h() {}
}";
        assert_eq!(flagged("js/unreachable-code", TS, src), [2]);
        assert_eq!(flagged("js/infinite-loop", TS, src), [4, 6]);
    }

    #[test]
    fn optional_chains_and_super() {
        let src = "const a = (o?.p)();
const { b } = o?.q;
for (const c of o?.list) {}
f(...o?.args);
const d = { ...o?.rest };
const e = o?.p.q.r;";
        assert_eq!(
            flagged("js/unsafe-optional-chaining", JS, src),
            [1, 2, 3, 4]
        );
        let classes = "class A implements I { constructor() { super(); } }
class B extends C { constructor() { const f = () => 1; } }
class D extends C { constructor() { super(); } }";
        assert_eq!(flagged("js/super-call", TS, classes), [1, 2]);
    }

    #[test]
    fn secrets_and_options() {
        let src = "const token = 'Authorization';
const apiKey = 'https://api.example.com/v1/keys';
const secret = 'aB3dE5fG7hJ9kL1mN3pQ';
const pwd = '/usr/local/bin';
mailer.createTransport({ host, secure: false });
res.cookie('a', 'b', { secure: false });
m.set(k, 1);
m.set(k, 2);
m.set(j, m.get(j) + 1);
m.set(j, 3);";
        assert_eq!(flagged("js/hardcoded-secret", JS, src), [3]);
        assert!(flagged("js/hardcoded-password", JS, src).is_empty());
        assert_eq!(flagged("js/cookie-not-secure", JS, src), [6]);
        // One finding per block: Find reports the first.
        assert_eq!(flagged("js/overwritten-element", JS, src), [8]);
    }

    #[test]
    fn corpus_idioms_in_bug_rules() {
        let src =
            "class S { get shape() { defineLazy(this, 'shape', () => 1); return this.shape; } }
function ok(s) { try { new URL(s); return true; } catch { return false; } }
buf[++i] = x;
buf[++i] = y;
let // the value
  v = 1;";
        for rule in [
            "js/accessor-recursion",
            "js/new-result-dropped",
            "js/overwritten-element",
            "js/useless-expression",
        ] {
            assert!(flagged(rule, JS, src).is_empty(), "{rule}");
        }
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
