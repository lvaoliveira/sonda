use super::{Check, Example, Rule};
use crate::lang::{C_CPP, C_ONLY, JAVA, JS_TS, Lang, PYTHON, TS};
use crate::model::Category::{Bug, CodeSmell, Vulnerability};
use crate::model::Severity::{Blocker, Critical, Info, Major, Minor};
use tree_sitter::Node;

pub static RULES: &[Rule] = &[
    // ---- Structural rules (all languages, implemented in analysis.rs) ----
    Rule {
        id: super::COGNITIVE_COMPLEXITY,
        name: "Cognitive complexity of functions should not be too high",
        description: "Deeply nested and heavily branched functions are hard to understand and change. \
                      Cognitive complexity adds 1 per branch, loop, catch or boolean-operator sequence, \
                      plus the current nesting depth for nested structures. Threshold: `thresholds.cognitive_complexity`.",
        message: "",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        check: Check::Structural,
        example: None,
    },
    Rule {
        id: super::FUNCTION_LENGTH,
        name: "Functions should not be too long",
        description: "Long functions usually do too many things. Threshold: `thresholds.function_lines`.",
        message: "",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 20,
        check: Check::Structural,
        example: None,
    },
    Rule {
        id: super::TOO_MANY_PARAMETERS,
        name: "Functions should not have too many parameters",
        description: "Many parameters make calls hard to read; group them into an object. \
                      Threshold: `thresholds.parameters`.",
        message: "",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        check: Check::Structural,
        example: None,
    },
    Rule {
        id: super::TODO_COMMENT,
        name: "Track TODO and FIXME comments",
        description: "TODO, FIXME and XXX comments mark unfinished work that should be tracked.",
        message: "",
        category: CodeSmell,
        severity: Info,
        effort_minutes: 0,
        check: Check::Structural,
        example: None,
    },
    // ---- JavaScript / TypeScript ----
    Rule {
        id: "js/no-eval",
        name: "eval() should not be used",
        description: "eval() executes arbitrary strings as code and is a common injection vector.",
        message: "Remove this use of eval().",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 30,
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
    // ---- Python ----
    Rule {
        id: "py/no-eval",
        name: "eval() and exec() should not be used",
        description: "eval()/exec() run arbitrary code and are a common injection vector.",
        message: "Remove this use of eval()/exec().",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 30,
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (identifier) @f (#any-of? @f "eval" "exec")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "eval(user_input)\n",
            good: "ast.literal_eval(user_input)\n",
        }),
    },
    Rule {
        id: "py/subprocess-shell",
        name: "Commands should not be run through a shell",
        description: "shell=True passes the command through /bin/sh, enabling command injection.",
        message: "Pass the command as a list and drop shell=True.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 15,
        check: Check::Query {
            langs: PYTHON,
            query: r#"(keyword_argument name: (identifier) @n value: (true) (#eq? @n "shell")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "subprocess.run(cmd, shell=True)\n",
            good: "subprocess.run(['ls', '-l'])\n",
        }),
    },
    Rule {
        id: "py/pickle-load",
        name: "Untrusted data should not be unpickled",
        description: "pickle.load()/loads() can execute arbitrary code embedded in the data.",
        message: "Make sure this data is trusted, or use a safe format such as JSON.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 15,
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @a)
                        (#eq? @o "pickle") (#any-of? @a "load" "loads")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "data = pickle.loads(blob)\n",
            good: "data = json.loads(blob)\n",
        }),
    },
    Rule {
        id: "py/mutable-default",
        name: "Default arguments should not be mutable",
        description: "Default values are evaluated once, so a list/dict/set default is shared between calls.",
        message: "Use None as the default and create the value inside the function.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        check: Check::Query {
            langs: PYTHON,
            query: r#"[(default_parameter value: [(list) (dictionary) (set)] @match)
                       (typed_default_parameter value: [(list) (dictionary) (set)] @match)]"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "def f(items=[]):\n    return items\n",
            good: "def f(items=None):\n    return items or []\n",
        }),
    },
    Rule {
        id: "py/assert-tuple",
        name: "assert should not be called on a tuple",
        description: "`assert (cond, msg)` asserts a non-empty tuple, which is always true.",
        message: "Remove the parentheses: this assertion is always true.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        check: Check::Query {
            langs: PYTHON,
            query: "(assert_statement (tuple) @match)",
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "assert (x > 0, 'x must be positive')\n",
            good: "assert x > 0, 'x must be positive'\n",
        }),
    },
    Rule {
        id: "py/bare-except",
        name: "Bare except clauses should not be used",
        description: "`except:` also catches SystemExit and KeyboardInterrupt. Catch a specific exception.",
        message: "Catch a specific exception (at least 'Exception') instead of a bare except.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        check: Check::Query {
            langs: PYTHON,
            query: "(except_clause) @match",
            filter: Some(bare_except),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "try:\n    f()\nexcept:\n    pass\n",
            good: "try:\n    f()\nexcept ValueError:\n    pass\n",
        }),
    },
    Rule {
        id: "py/none-comparison",
        name: "None should be compared with 'is'",
        description: "`== None` can be overridden by __eq__; use `is None` / `is not None`.",
        message: "Use 'is None' or 'is not None' instead.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        check: Check::Query {
            langs: PYTHON,
            query: "(comparison_operator (none)) @match",
            filter: Some(has_equality_operator),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "if x == None:\n    pass\n",
            good: "if x is None:\n    pass\n",
        }),
    },
    // ---- Java ----
    Rule {
        id: "java/string-reference-equality",
        name: "Strings should be compared with equals()",
        description: "`==` compares references, not contents, so equal strings may compare unequal.",
        message: "Use equals() to compare strings.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        check: Check::Query {
            langs: JAVA,
            query: r#"(binary_expression operator: ["==" "!="]) @match"#,
            filter: Some(has_string_literal_operand),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { boolean f(String s) { return s == \"x\"; } }",
            good: "class A { boolean f(String s) { return \"x\".equals(s); } }",
        }),
    },
    Rule {
        id: "java/weak-hash",
        name: "Weak hashing algorithms should not be used",
        description: "MD2, MD5 and SHA-1 are broken for security purposes.",
        message: "Use a stronger algorithm such as SHA-256.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 15,
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation
                        object: (identifier) @o
                        name: (identifier) @n
                        arguments: (argument_list (string_literal) @alg)
                        (#eq? @o "MessageDigest") (#eq? @n "getInstance")
                        (#match? @alg "^\"(MD2|MD5|SHA-?1)\"$")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() throws Exception { MessageDigest.getInstance(\"MD5\"); } }",
            good: "class A { void f() throws Exception { MessageDigest.getInstance(\"SHA-256\"); } }",
        }),
    },
    Rule {
        id: "java/empty-catch",
        name: "Exceptions should not be silently swallowed",
        description: "An empty catch block hides failures. Handle the error or explain with a comment.",
        message: "Handle this exception or add a comment explaining why it is ignored.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        check: Check::Query {
            langs: JAVA,
            query: "(catch_clause body: (block) @match)",
            filter: Some(empty_block),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { try { g(); } catch (Exception e) {} } }",
            good: "class A { void f() { try { g(); } catch (Exception e) { log(e); } } }",
        }),
    },
    Rule {
        id: "java/print-stack-trace",
        name: "printStackTrace() should not be used",
        description: "Stack traces printed to stderr bypass logging and may leak internals.",
        message: "Use a logger instead of printStackTrace().",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "printStackTrace")) @match"#,
            filter: Some(no_arguments),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(Exception e) { e.printStackTrace(); } }",
            good: "class A { void f(Exception e) { log.error(\"failed\", e); } }",
        }),
    },
    Rule {
        id: "java/system-exit",
        name: "System.exit() should not be called",
        description: "System.exit() shuts down the whole JVM, which is rarely what library or server code wants.",
        message: "Throw an exception or return instead of calling System.exit().",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) @o name: (identifier) @n
                        (#eq? @o "System") (#eq? @n "exit")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { System.exit(1); } }",
            good: "class A { void f() { throw new IllegalStateException(); } }",
        }),
    },
    Rule {
        id: "java/system-out",
        name: "System.out and System.err should not be used for logging",
        description: "Use a logger so output can be filtered, formatted and routed.",
        message: "Replace this System.out/System.err call with a logger.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation
                        object: (field_access object: (identifier) @o field: (identifier) @f)
                        (#eq? @o "System") (#any-of? @f "out" "err")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { System.out.println(\"x\"); } }",
            good: "class A { void f() { log.info(\"x\"); } }",
        }),
    },
    // ---- C / C++ ----
    Rule {
        id: "c/no-gets",
        name: "gets() should never be used",
        description: "gets() cannot limit input size and always allows a buffer overflow.",
        message: "Replace gets() with fgets().",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 10,
        check: Check::Query {
            langs: C_CPP,
            query: r#"(call_expression function: (identifier) @f (#eq? @f "gets")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::C,
            bad: "void f(char *b) { gets(b); }",
            good: "void f(char *b, int n) { fgets(b, n, stdin); }",
        }),
    },
    Rule {
        id: "c/unsafe-string-function",
        name: "Unbounded string functions should not be used",
        description: "strcpy, strcat, sprintf and vsprintf do not check the destination size.",
        message: "Use a bounded alternative (strncpy/strlcpy, strncat/strlcat, snprintf).",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 10,
        check: Check::Query {
            langs: C_CPP,
            query: r#"(call_expression function: (identifier) @f
                        (#any-of? @f "strcpy" "strcat" "sprintf" "vsprintf")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::C,
            bad: "void f(char *d, const char *s) { strcpy(d, s); }",
            good: "void f(char *d, const char *s, int n) { snprintf(d, n, \"%s\", s); }",
        }),
    },
    Rule {
        id: "c/assignment-in-condition",
        name: "Assignments should not be used as conditions",
        description: "`if (x = y)` is almost always a typo for `==`. Use double parentheses if intended.",
        message: "Did you mean '=='? Move this assignment out of the condition.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        check: Check::Query {
            langs: C_ONLY,
            query: "(if_statement condition: (parenthesized_expression (assignment_expression) @match))",
            filter: None,
        },
        example: Some(Example {
            lang: Lang::C,
            bad: "void f(int x) { if (x = 5) { g(); } }",
            good: "void f(int x) { if (x == 5) { g(); } if ((x = h())) { g(); } }",
        }),
    },
    Rule {
        id: "c/goto",
        name: "goto should not be used",
        description: "goto makes control flow hard to follow.",
        message: "Restructure this code to avoid goto.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 10,
        check: Check::Query {
            langs: C_CPP,
            query: "(goto_statement) @match",
            filter: None,
        },
        example: Some(Example {
            lang: Lang::C,
            bad: "void f(void) { goto end; end: return; }",
            good: "void f(void) { return; }",
        }),
    },
];

fn empty_block(node: Node, _: &[u8]) -> bool {
    // Comments are named nodes, so a block holding only a comment is not empty.
    node.named_child_count() == 0
}

fn not_nullish_comparison(operator: Node, src: &[u8]) -> bool {
    let Some(expr) = operator.parent() else {
        return true;
    };
    let nullish = |field: &str| {
        expr.child_by_field_name(field).is_some_and(|n| {
            matches!(n.kind(), "null" | "undefined") || n.utf8_text(src) == Ok("undefined")
        })
    };
    !nullish("left") && !nullish("right")
}

fn bare_except(node: Node, _: &[u8]) -> bool {
    node.named_child(0).is_some_and(|c| c.kind() == "block")
}

fn has_equality_operator(node: Node, _: &[u8]) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .any(|c| matches!(c.kind(), "==" | "!="))
}

fn has_string_literal_operand(node: Node, _: &[u8]) -> bool {
    ["left", "right"].iter().any(|f| {
        node.child_by_field_name(f)
            .is_some_and(|n| n.kind() == "string_literal")
    })
}

fn no_arguments(node: Node, _: &[u8]) -> bool {
    node.child_by_field_name("arguments")
        .is_some_and(|a| a.named_child_count() == 0)
}
