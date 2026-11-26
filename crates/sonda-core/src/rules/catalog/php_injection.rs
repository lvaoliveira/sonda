//! PHP security rules: a request's value reaching a sink (ADR-0027). Taint
//! analysis only; the rules that look at a call's shape are in
//! `php_security.rs`.

use super::prelude::*;
use crate::lang::PHP;

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "php/sql-injection",
        name: "SQL queries should not be built from a request's values",
        description: "A value from the request (`$_GET`, `$_POST`, a header, a body) that reaches a query's text lets whoever sends it change what the query does. Use a prepared statement with placeholders (`?` or `:name`) and bind the value. The issue shows the path the value took (ADR-0027).",
        message: "Don't build this query from the request's values; bind them as parameters.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Taint {
            langs: PHP,
            find: sql_injection,
        },
        example: Some(Example {
            lang: Lang::Php,
            bad: "<?php\nfunction find($db) {\n    $id = $_GET['id'];\n    return mysqli_query($db, \"SELECT * FROM users WHERE id = '\" . $id . \"'\");\n}\n",
            good: "<?php\nfunction find($db) {\n    $st = $db->prepare('SELECT * FROM users WHERE id = ?');\n    $st->execute([$_GET['id']]);\n    return $st;\n}\n",
        }),
    },
    Rule {
        id: "php/command-injection",
        name: "OS commands should not be built from a request's values",
        description: "A value from the request that reaches a command lets whoever sends it run, or add to, a command on the server. Pass it through `escapeshellarg`, or avoid the shell (`proc_open` with an argument array). The issue shows the path the value took (ADR-0027).",
        message: "Don't build this command from the request's values.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Taint {
            langs: PHP,
            find: command_injection,
        },
        example: Some(Example {
            lang: Lang::Php,
            bad: "<?php\nfunction ping() {\n    $host = $_GET['host'];\n    return shell_exec('ping -c 1 ' . $host);\n}\n",
            good: "<?php\nfunction ping() {\n    $host = $_GET['host'];\n    return shell_exec('ping -c 1 ' . escapeshellarg($host));\n}\n",
        }),
    },
    Rule {
        id: "php/path-injection",
        name: "File paths should not be built from a request's values",
        description: "A value from the request that reaches a file path, or an `include`, lets whoever sends it read or run files outside the folder meant for them, with `../` or an absolute path. Choose from a fixed list, or take `basename` and check the result with `realpath`. The issue shows the path the value took (ADR-0027).",
        message: "Don't build this file path from the request's values.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Taint {
            langs: PHP,
            find: path_injection,
        },
        example: Some(Example {
            lang: Lang::Php,
            bad: "<?php\nfunction show() {\n    $name = $_GET['f'];\n    return file_get_contents('/srv/files/' . $name);\n}\n",
            good: "<?php\nfunction show() {\n    $name = basename($_GET['f']);\n    return file_get_contents('/srv/files/' . $name);\n}\n",
        }),
    },
    Rule {
        id: "php/open-redirect",
        name: "Redirects should not go where a request's values say",
        description: "A value from the request that reaches a redirect lets whoever sends it send visitors to a site of their choosing. Redirect to a path you build, or to an address you checked against a list. The issue shows the path the value took (ADR-0027).",
        message: "Don't redirect to an address taken from the request.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Taint {
            langs: PHP,
            find: open_redirect,
        },
        example: Some(Example {
            lang: Lang::Php,
            bad: "<?php\nfunction go() {\n    header('Location: ' . $_GET['next']);\n}\n",
            good: "<?php\nfunction go() {\n    header('Location: /home');\n}\n",
        }),
    },
    Rule {
        id: "php/ssrf",
        name: "Requests should not go where a request's values say",
        description: "A value from the request that reaches the address of a request the server makes lets whoever sends it reach hosts only the server can: internal services, cloud metadata. Use a fixed address, or check the host against a list. The issue shows the path the value took (ADR-0027).",
        message: "Don't make a request to an address taken from the request.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Taint {
            langs: PHP,
            find: ssrf,
        },
        example: Some(Example {
            lang: Lang::Php,
            bad: "<?php\nfunction proxy() {\n    return file_get_contents($_GET['url']);\n}\n",
            good: "<?php\nfunction proxy() {\n    return file_get_contents('https://api.example.com/data');\n}\n",
        }),
    },
    Rule {
        id: "php/code-injection",
        name: "Code should not be built from a request's values",
        description: "A value from the request that reaches `eval`, `assert` or `create_function`, or names the function `call_user_func` runs, lets whoever sends it run code on the server. Use a fixed set of functions, chosen by a checked key. The issue shows the path the value took (ADR-0027).",
        message: "Don't run code taken from the request.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Taint {
            langs: PHP,
            find: code_injection,
        },
        example: Some(Example {
            lang: Lang::Php,
            bad: "<?php\nfunction calc() {\n    $expr = $_GET['e'];\n    return eval('return ' . $expr . ';');\n}\n",
            good: "<?php\nfunction calc() {\n    $ops = ['add' => 'array_sum'];\n    $op = $ops[$_GET['op']] ?? 'array_sum';\n    return $op([1, 2]);\n}\n",
        }),
    },
    Rule {
        id: "php/xss",
        name: "Output should not include a request's values unescaped",
        description: "A value from the request that a page prints without escaping runs as script in the reader's browser: it can read the page, the cookies it can see and act as the user. Escape it for HTML with `htmlspecialchars($v, ENT_QUOTES)`, or use a template engine that does. The issue shows the path the value took (ADR-0027).",
        message: "Escape this value for HTML before printing it.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 20,
        sonar: &[],
        check: Check::Taint {
            langs: PHP,
            find: xss,
        },
        example: Some(Example {
            lang: Lang::Php,
            bad: "<?php\nfunction page() {\n    echo 'Hello ' . $_GET['name'];\n}\n",
            good: "<?php\nfunction page() {\n    echo 'Hello ' . htmlspecialchars($_GET['name'], ENT_QUOTES);\n}\n",
        }),
    },
];

pub(super) const OFF_BY_DEFAULT: &[&str] = &[];

taint_rule_fn!(php_taint, sql_injection, Sql);
taint_rule_fn!(php_taint, command_injection, Command);
taint_rule_fn!(php_taint, path_injection, Path);
taint_rule_fn!(php_taint, open_redirect, Redirect);
taint_rule_fn!(php_taint, ssrf, Ssrf);
taint_rule_fn!(php_taint, code_injection, Code);
taint_rule_fn!(php_taint, xss, Html);
