//! C and C++ rules.

use super::*;

pub(super) static RULES: &[Rule] = &[
    // ---- C / C++ ----
    Rule {
        id: "c/no-gets",
        name: "gets() should never be used",
        description: "gets() cannot limit input size and always allows a buffer overflow.",
        message: "Replace gets() with fgets().",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 10,
        sonar: &[],
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
        sonar: &[],
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
        sonar: &[],
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
        sonar: &[],
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
