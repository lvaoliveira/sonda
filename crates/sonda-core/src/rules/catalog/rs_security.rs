//! Rust security rules: a request's value reaching a sink (ADR-0027). Taint
//! analysis only; the rules that look at a call's shape are in `rs.rs`.

use super::prelude::*;

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "rs/sql-injection",
        name: "SQL queries should not be built from a request's values",
        description: "A value from the request (a query string, a path segment, a JSON body, a form field, a header) that reaches a query's text lets whoever sends the request change what the query does. Bind it as a parameter (`sqlx::query(..).bind(v)`, a `?` or `$1` placeholder) instead. The issue shows the path the value took (ADR-0027).",
        message: "Don't build this query from the request's values; bind them as parameters.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Taint {
            langs: RUST,
            find: sql_injection,
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "use axum::extract::Query;\nasync fn orders(Query(p): Query<Params>) {\n    sqlx::query(&format!(\"SELECT * FROM o WHERE name = '{}'\", p.name)).fetch_all(&pool).await;\n}\nstruct Params { name: String }\n",
            good: "use axum::extract::Query;\nasync fn orders(Query(p): Query<Params>) {\n    sqlx::query(\"SELECT * FROM o WHERE name = $1\").bind(p.name).fetch_all(&pool).await;\n}\nstruct Params { name: String }\n",
        }),
    },
    Rule {
        id: "rs/command-injection",
        name: "OS commands should not be built from a request's values",
        description: "A value from the request that reaches a command lets whoever sends it run, or add to, a command on the server: as the program, or as part of a shell's command line. Run a fixed program with `Command::new`, passing the value as one of its arguments, without a shell. The issue shows the path the value took (ADR-0027).",
        message: "Don't build this command from the request's values.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Taint {
            langs: RUST,
            find: command_injection,
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "use axum::extract::Query;\nasync fn ping(Query(p): Query<Host>) {\n    Command::new(\"sh\").arg(\"-c\").arg(format!(\"ping {}\", p.host)).output();\n}\nstruct Host { host: String }\n",
            good: "use axum::extract::Query;\nasync fn ping(Query(p): Query<Host>) {\n    Command::new(\"ping\").arg(\"-c\").arg(\"1\").output();\n}\nstruct Host { host: String }\n",
        }),
    },
    Rule {
        id: "rs/path-injection",
        name: "File paths should not be built from a request's values",
        description: "A value from the request that reaches a file path lets whoever sends it read or write files outside the folder meant for them, with `../` or an absolute path. Join it to a fixed folder, `canonicalize()` the result and check that it `starts_with` the folder. The issue shows the path the value took (ADR-0027).",
        message: "Don't build this file path from the request's values.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Taint {
            langs: RUST,
            find: path_injection,
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "use axum::extract::Path;\nasync fn file(Path(name): Path<String>) -> Vec<u8> {\n    std::fs::read(format!(\"/srv/files/{}\", name)).unwrap()\n}\n",
            good: "use axum::extract::Path;\nasync fn file(Path(name): Path<String>) -> Vec<u8> {\n    if name.contains(\"..\") { return Vec::new(); }\n    std::fs::read(format!(\"/srv/files/{}\", name)).unwrap()\n}\n",
        }),
    },
    Rule {
        id: "rs/open-redirect",
        name: "Redirects should not go where a request's values say",
        description: "A value from the request that reaches a redirect lets whoever sends it send visitors to a site of their choosing. Redirect to a path you build, or to an address you checked against a list. The issue shows the path the value took (ADR-0027).",
        message: "Don't redirect to an address taken from the request.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Taint {
            langs: RUST,
            find: open_redirect,
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "use axum::{extract::Query, response::Redirect};\nasync fn go(Query(q): Query<Next>) -> Redirect {\n    Redirect::to(&q.next)\n}\nstruct Next { next: String }\n",
            good: "use axum::{extract::Query, response::Redirect};\nasync fn go(Query(q): Query<Next>) -> Redirect {\n    Redirect::to(\"/home\")\n}\nstruct Next { next: String }\n",
        }),
    },
    Rule {
        id: "rs/ssrf",
        name: "Requests to other servers should not go where a request's values say",
        description: "A value from the request that reaches the address of a request the server makes lets whoever sends it make the server call internal services or other hosts. Check the address against a list of hosts you allow. The issue shows the path the value took (ADR-0027).",
        message: "Don't call an address taken from the request.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Taint {
            langs: RUST,
            find: ssrf,
        },
        example: Some(Example {
            lang: Lang::Rust,
            bad: "use axum::extract::Query;\nasync fn proxy(Query(q): Query<Target>) {\n    reqwest::get(&q.url).await.unwrap();\n}\nstruct Target { url: String }\n",
            good: "use axum::extract::Query;\nasync fn proxy(Query(q): Query<Target>) {\n    reqwest::get(\"https://api.example.com/data\").await.unwrap();\n}\nstruct Target { url: String }\n",
        }),
    },
];

pub(super) const OFF_BY_DEFAULT: &[&str] = &[];

taint_rule_fn!(rs_taint, sql_injection, Sql);
taint_rule_fn!(rs_taint, command_injection, Command);
taint_rule_fn!(rs_taint, path_injection, Path);
taint_rule_fn!(rs_taint, open_redirect, Redirect);
taint_rule_fn!(rs_taint, ssrf, Ssrf);
