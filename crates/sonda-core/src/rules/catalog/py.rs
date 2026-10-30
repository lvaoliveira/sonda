//! Python rules.

use super::*;

pub(super) static RULES: &[Rule] = &[
    // ---- Python ----
    Rule {
        id: "py/no-eval",
        name: "eval() and exec() should not be used",
        description: "eval()/exec() run arbitrary code and are a common injection vector.",
        message: "Remove this use of eval()/exec().",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 30,
        sonar: &[],
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
        sonar: &[],
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
        sonar: &[],
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
        sonar: &[related("S5717")],
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
        sonar: &[exact("S5905")],
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
        sonar: &[related("S5754")],
        check: Check::Query {
            langs: PYTHON,
            query: "(except_clause) @match",
            filter: Some(Keep(bare_except)),
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
        sonar: &[],
        check: Check::Query {
            langs: PYTHON,
            query: "(comparison_operator (none)) @match",
            filter: Some(Keep(has_equality_operator)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "if x == None:\n    pass\n",
            good: "if x is None:\n    pass\n",
        }),
    },
];
