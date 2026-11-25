//! Go security rules: a request's value reaching a sink (ADR-0027). Taint
//! analysis only; the rules that look at a call's shape are in
//! `go_security.rs`.

use super::prelude::*;
use crate::lang::GO;

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "go/sql-injection",
        name: "SQL queries should not be built from a request's values",
        description: "A value from the request (a form field, a query parameter, a path parameter, a header, a body) that reaches a query's text lets whoever sends it change what the query does. Pass it as an argument (`?` or `$1`) to `Query`, `Exec` or a prepared statement. The issue shows the path the value took (ADR-0027).",
        message: "Don't build this query from the request's values; pass them as arguments.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Taint {
            langs: GO,
            find: sql_injection,
        },
        example: Some(Example {
            lang: Lang::Go,
            bad: "package p\n\nimport (\n\t\"database/sql\"\n\t\"net/http\"\n)\n\nfunc orders(db *sql.DB, r *http.Request) {\n\tname := r.FormValue(\"name\")\n\tdb.Query(\"SELECT * FROM o WHERE name = '\" + name + \"'\")\n}\n",
            good: "package p\n\nimport (\n\t\"database/sql\"\n\t\"net/http\"\n)\n\nfunc orders(db *sql.DB, r *http.Request) {\n\tname := r.FormValue(\"name\")\n\tdb.Query(\"SELECT * FROM o WHERE name = ?\", name)\n}\n",
        }),
    },
    Rule {
        id: "go/command-injection",
        name: "OS commands should not be built from a request's values",
        description: "A value from the request that reaches a command lets whoever sends it run, or add to, a command on the server: as the program, or as the script of a shell. Run a fixed program with `exec.Command`, passing the value as one of its arguments, without `sh -c`. The issue shows the path the value took (ADR-0027).",
        message: "Don't build this command from the request's values.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Taint {
            langs: GO,
            find: command_injection,
        },
        example: Some(Example {
            lang: Lang::Go,
            bad: "package p\n\nimport (\n\t\"net/http\"\n\t\"os/exec\"\n)\n\nfunc ping(r *http.Request) {\n\thost := r.URL.Query().Get(\"host\")\n\texec.Command(\"sh\", \"-c\", \"ping -c 1 \"+host).Run()\n}\n",
            good: "package p\n\nimport (\n\t\"net/http\"\n\t\"os/exec\"\n)\n\nfunc ping(r *http.Request) {\n\thost := r.URL.Query().Get(\"host\")\n\texec.Command(\"ping\", \"-c\", \"1\", host).Run()\n}\n",
        }),
    },
    Rule {
        id: "go/path-injection",
        name: "File paths should not be built from a request's values",
        description: "A value from the request that reaches a file path lets whoever sends it read or write files outside the folder meant for them, with `../` or an absolute path. Join it to a fixed folder with `filepath.Join`, then check that the result is still inside it (`filepath.IsLocal`, or `strings.HasPrefix` on the cleaned path). The issue shows the path the value took (ADR-0027).",
        message: "Don't build this file path from the request's values.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Taint {
            langs: GO,
            find: path_injection,
        },
        example: Some(Example {
            lang: Lang::Go,
            bad: "package p\n\nimport (\n\t\"net/http\"\n\t\"os\"\n)\n\nfunc file(r *http.Request) {\n\tname := r.FormValue(\"f\")\n\tos.Open(\"/srv/files/\" + name)\n}\n",
            good: "package p\n\nimport (\n\t\"net/http\"\n\t\"os\"\n\t\"strings\"\n)\n\nfunc file(r *http.Request) {\n\tname := r.FormValue(\"f\")\n\tif strings.HasPrefix(name, \"public/\") {\n\t\tos.Open(\"/srv/files/\" + name)\n\t}\n}\n",
        }),
    },
    Rule {
        id: "go/open-redirect",
        name: "Redirects should not go where a request's values say",
        description: "A value from the request that reaches a redirect lets whoever sends it send visitors to a site of their choosing. Redirect to a path you build, or to an address you checked against a list. The issue shows the path the value took (ADR-0027).",
        message: "Don't redirect to an address taken from the request.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Taint {
            langs: GO,
            find: open_redirect,
        },
        example: Some(Example {
            lang: Lang::Go,
            bad: "package p\n\nimport \"net/http\"\n\nfunc go_(w http.ResponseWriter, r *http.Request) {\n\thttp.Redirect(w, r, r.FormValue(\"next\"), http.StatusFound)\n}\n",
            good: "package p\n\nimport \"net/http\"\n\nfunc go_(w http.ResponseWriter, r *http.Request) {\n\thttp.Redirect(w, r, \"/home\", http.StatusFound)\n}\n",
        }),
    },
    Rule {
        id: "go/ssrf",
        name: "Requests should not go where a request's values say",
        description: "A value from the request that reaches the address of a request the server makes lets whoever sends it reach hosts only the server can: internal services, cloud metadata. Use a fixed address, or check the host against a list. The issue shows the path the value took (ADR-0027).",
        message: "Don't make a request to an address taken from the request.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Taint {
            langs: GO,
            find: ssrf,
        },
        example: Some(Example {
            lang: Lang::Go,
            bad: "package p\n\nimport \"net/http\"\n\nfunc proxy(w http.ResponseWriter, r *http.Request) {\n\thttp.Get(r.FormValue(\"url\"))\n}\n",
            good: "package p\n\nimport \"net/http\"\n\nfunc proxy(w http.ResponseWriter, r *http.Request) {\n\thttp.Get(\"https://api.example.com/data\")\n}\n",
        }),
    },
];

pub(super) const OFF_BY_DEFAULT: &[&str] = &[];

taint_rule_fn!(go_taint, sql_injection, Sql);
taint_rule_fn!(go_taint, command_injection, Command);
taint_rule_fn!(go_taint, path_injection, Path);
taint_rule_fn!(go_taint, open_redirect, Redirect);
taint_rule_fn!(go_taint, ssrf, Ssrf);
