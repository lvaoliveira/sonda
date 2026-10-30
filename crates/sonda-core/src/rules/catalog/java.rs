//! Java rules.

use super::*;

pub(super) static RULES: &[Rule] = &[
    // ---- Java ----
    Rule {
        id: "java/string-reference-equality",
        name: "Strings should be compared with equals()",
        description: "`==` compares references, not contents, so equal strings may compare unequal.",
        message: "Use equals() to compare strings.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S4973")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(binary_expression operator: ["==" "!="]) @match"#,
            filter: Some(Keep(has_string_literal_operand)),
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
        sonar: &[exact("S4790")],
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
        sonar: &[related("S108")],
        check: Check::Query {
            langs: JAVA,
            query: "(catch_clause body: (block) @match)",
            filter: Some(Keep(empty_block)),
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
        sonar: &[],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "printStackTrace")) @match"#,
            filter: Some(Keep(no_arguments)),
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
        sonar: &[exact("S1147")],
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
        sonar: &[exact("S106")],
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
];
