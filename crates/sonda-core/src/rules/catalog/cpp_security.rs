//! C and C++ security rules: a request's value reaching a sink (ADR-0027).
//! Taint analysis only; the rules that look at a call's shape are in `c.rs`.

use super::prelude::*;

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "c/sql-injection",
        name: "SQL queries should not be built from a request's values",
        description: "A value from the request (a query parameter, a body, a header, bytes read from a socket) that reaches a query's text lets whoever sends it change what the query does. Bind it as a parameter (`sqlite3_bind_text`, `PQexecParams`, a prepared statement) instead. The issue shows the path the value took (ADR-0027).",
        message: "Don't build this query from the request's values; bind them as parameters.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Taint {
            langs: C_CPP,
            find: sql_injection,
        },
        example: Some(Example {
            lang: Lang::Cpp,
            bad: "#include <httplib.h>\nvoid orders(const httplib::Request& req, sqlite3* db) {\n    std::string q = \"SELECT * FROM o WHERE name = '\" + req.get_param_value(\"name\") + \"'\";\n    sqlite3_exec(db, q.c_str(), 0, 0, 0);\n}\n",
            good: "#include <httplib.h>\nvoid orders(const httplib::Request& req, sqlite3* db) {\n    sqlite3_stmt* st;\n    sqlite3_prepare_v2(db, \"SELECT * FROM o WHERE name = ?\", -1, &st, 0);\n    sqlite3_bind_text(st, 1, req.get_param_value(\"name\").c_str(), -1, SQLITE_TRANSIENT);\n}\n",
        }),
    },
    Rule {
        id: "c/command-injection",
        name: "OS commands should not be built from a request's values",
        description: "A value from the request that reaches a command lets whoever sends it run, or add to, a command on the server: as the program, or as part of a shell's command line. Run a fixed program with `execv`, passing the value as one of its arguments, without a shell (not `system` or `popen`). The issue shows the path the value took (ADR-0027).",
        message: "Don't build this command from the request's values.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Taint {
            langs: C_CPP,
            find: command_injection,
        },
        example: Some(Example {
            lang: Lang::Cpp,
            bad: "#include <httplib.h>\nvoid ping(const httplib::Request& req) {\n    std::string cmd = \"ping -c 1 \" + req.get_param_value(\"host\");\n    system(cmd.c_str());\n}\n",
            good: "#include <httplib.h>\nvoid ping(const httplib::Request& req) {\n    system(\"uptime\");\n}\n",
        }),
    },
    Rule {
        id: "c/path-injection",
        name: "File paths should not be built from a request's values",
        description: "A value from the request that reaches a file path lets whoever sends it read or write files outside the folder meant for them, with `../` or an absolute path. Join it to a fixed folder, resolve the result with `realpath` or `std::filesystem::weakly_canonical` and check that it starts with the folder. The issue shows the path the value took (ADR-0027).",
        message: "Don't build this file path from the request's values.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Taint {
            langs: C_CPP,
            find: path_injection,
        },
        example: Some(Example {
            lang: Lang::Cpp,
            bad: "#include <httplib.h>\nvoid file(const httplib::Request& req) {\n    std::string name = req.get_param_value(\"f\");\n    FILE* f = fopen((\"/srv/files/\" + name).c_str(), \"r\");\n}\n",
            good: "#include <httplib.h>\nvoid file(const httplib::Request& req) {\n    std::string name = req.get_param_value(\"f\");\n    if (name.find(\"..\") != std::string::npos) return;\n    FILE* f = fopen((\"/srv/files/\" + name).c_str(), \"r\");\n}\n",
        }),
    },
    Rule {
        id: "c/open-redirect",
        name: "Redirects should not go where a request's values say",
        description: "A value from the request that reaches a redirect lets whoever sends it send visitors to a site of their choosing. Redirect to a path you build, or to an address you checked against a list. The issue shows the path the value took (ADR-0027).",
        message: "Don't redirect to an address taken from the request.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Taint {
            langs: C_CPP,
            find: open_redirect,
        },
        example: Some(Example {
            lang: Lang::Cpp,
            bad: "#include <httplib.h>\nvoid go(const httplib::Request& req, httplib::Response& res) {\n    res.set_redirect(req.get_param_value(\"next\"));\n}\n",
            good: "#include <httplib.h>\nvoid go(const httplib::Request& req, httplib::Response& res) {\n    res.set_redirect(\"/home\");\n}\n",
        }),
    },
    Rule {
        id: "c/ssrf",
        name: "Requests should not go where a request's values say",
        description: "A value from the request that reaches the address of a request the server makes lets whoever sends it reach hosts only the server can: internal services, cloud metadata. Use a fixed address, or check the host against a list. The issue shows the path the value took (ADR-0027).",
        message: "Don't make a request to an address taken from the request.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Taint {
            langs: C_CPP,
            find: ssrf,
        },
        example: Some(Example {
            lang: Lang::Cpp,
            bad: "#include <httplib.h>\nvoid proxy(const httplib::Request& req, CURL* h) {\n    curl_easy_setopt(h, CURLOPT_URL, req.get_param_value(\"url\").c_str());\n}\n",
            good: "#include <httplib.h>\nvoid proxy(const httplib::Request& req, CURL* h) {\n    curl_easy_setopt(h, CURLOPT_URL, \"https://api.example.com/data\");\n}\n",
        }),
    },
    Rule {
        id: "c/format-string",
        name: "Format strings should not come from a request's values",
        description: "A value from the request that is the format of `printf`, `syslog` or `snprintf` lets whoever sends it read or write memory with `%x` and `%n`. Pass it as an argument to a fixed format: `printf(\"%s\", value)`. The issue shows the path the value took (ADR-0027).",
        message: "Don't use a request's value as the format; pass it as an argument.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 20,
        sonar: &[],
        check: Check::Taint {
            langs: C_CPP,
            find: format_string,
        },
        example: Some(Example {
            lang: Lang::Cpp,
            bad: "void echo(int s) {\n    char buf[100];\n    recv(s, buf, 99, 0);\n    printf(buf);\n}\n",
            good: "void echo(int s) {\n    char buf[100];\n    recv(s, buf, 99, 0);\n    printf(\"%s\", buf);\n}\n",
        }),
    },
];

pub(super) const OFF_BY_DEFAULT: &[&str] = &[];

taint_rule_fn!(cpp_taint, sql_injection, Sql);
taint_rule_fn!(cpp_taint, command_injection, Command);
taint_rule_fn!(cpp_taint, path_injection, Path);
taint_rule_fn!(cpp_taint, open_redirect, Redirect);
taint_rule_fn!(cpp_taint, ssrf, Ssrf);
taint_rule_fn!(cpp_taint, format_string, Format);
