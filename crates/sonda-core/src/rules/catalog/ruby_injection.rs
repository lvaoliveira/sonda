//! Ruby security rules: a request's value reaching a sink (ADR-0027). Taint
//! analysis only; the rules that look at a call's shape are in
//! `ruby_security.rs`.

use super::prelude::*;
use crate::lang::RUBY;

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "ruby/sql-injection",
        name: "SQL queries should not be built from a request's values",
        description: "A value from the request (`params`, `cookies`, a header, a body) that reaches a query's text lets whoever sends it change what the query does. Bind it: `where('name = ?', name)` or `where(name: name)`. The issue shows the path the value took (ADR-0027).",
        message: "Don't build this query from the request's values; bind them as parameters.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Taint {
            langs: RUBY,
            find: sql_injection,
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "def show\n  name = params[:name]\n  User.where(\"name = '#{name}'\")\nend\n",
            good: "def show\n  name = params[:name]\n  User.where('name = ?', name)\nend\n",
        }),
    },
    Rule {
        id: "ruby/command-injection",
        name: "OS commands should not be built from a request's values",
        description: "A value from the request that reaches a command lets whoever sends it run, or add to, a command on the server. Pass the program and its arguments separately (`system('ping', host)`), or escape the value with `Shellwords.escape`. The issue shows the path the value took (ADR-0027).",
        message: "Don't build this command from the request's values.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Taint {
            langs: RUBY,
            find: command_injection,
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "def ping\n  host = params[:host]\n  system(\"ping -c 1 #{host}\")\nend\n",
            good: "def ping\n  host = params[:host]\n  system('ping', '-c', '1', host)\nend\n",
        }),
    },
    Rule {
        id: "ruby/path-injection",
        name: "File paths should not be built from a request's values",
        description: "A value from the request that reaches a file path lets whoever sends it read or change files outside the folder meant for them, with `../` or an absolute path. Take `File.basename` of it, or choose from a fixed list. The issue shows the path the value took (ADR-0027).",
        message: "Don't build this file path from the request's values.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Taint {
            langs: RUBY,
            find: path_injection,
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "def download\n  name = params[:file]\n  send_file File.join(DIR, name)\nend\n",
            good: "def download\n  name = File.basename(params[:file])\n  send_file File.join(DIR, name)\nend\n",
        }),
    },
    Rule {
        id: "ruby/open-redirect",
        name: "Redirects should not go where a request's values say",
        description: "A value from the request that reaches a redirect lets whoever sends it send visitors to a site of their choosing. Redirect to a path you build, use `only_path: true`, or check the address against a list. The issue shows the path the value took (ADR-0027).",
        message: "Don't redirect to an address taken from the request.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Taint {
            langs: RUBY,
            find: open_redirect,
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "def go\n  redirect_to params[:next]\nend\n",
            good: "def go\n  redirect_to params[:next], only_path: true\nend\n",
        }),
    },
    Rule {
        id: "ruby/ssrf",
        name: "Outgoing requests should not go where a request's values say",
        description: "A value from the request that reaches the address of an outgoing request lets whoever sends it make the server call any host it can reach, such as internal services and cloud metadata. Build the address from a fixed host, or check it against a list. The issue shows the path the value took (ADR-0027).",
        message: "Don't send a request to an address taken from the request.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Taint {
            langs: RUBY,
            find: ssrf,
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "def fetch\n  Net::HTTP.get(URI(params[:url]))\nend\n",
            good: "def fetch\n  Net::HTTP.get(URI(\"https://api.example.com/items/#{params[:id].to_i}\"))\nend\n",
        }),
    },
    Rule {
        id: "ruby/code-injection",
        name: "Code should not be run from a request's values",
        description: "A value from the request that reaches `eval`, `send`, `constantize` or a template lets whoever sends it run code on the server. Choose from a fixed list of names and look the method or class up in it. The issue shows the path the value took (ADR-0027).",
        message: "Don't run code, or look up a method or class, from the request's values.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Taint {
            langs: RUBY,
            find: code_injection,
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "def run\n  params[:model].constantize.all\nend\n",
            good: "def run\n  MODELS.fetch(params[:model]).all\nend\n",
        }),
    },
    Rule {
        id: "ruby/xss",
        name: "Pages should not print a request's values unescaped",
        description: "A value from the request that `raw` or `html_safe` prints in a page runs as script in the reader's browser. Leave Rails to escape it, or pass it through `h` or `sanitize`. The issue shows the path the value took (ADR-0027).",
        message: "Don't print the request's values without escaping them.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Taint {
            langs: RUBY,
            find: xss,
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "def greet\n  raw(params[:name])\nend\n",
            good: "def greet\n  h(params[:name])\nend\n",
        }),
    },
];

taint_rule_fn!(ruby_taint, sql_injection, Sql);
taint_rule_fn!(ruby_taint, command_injection, Command);
taint_rule_fn!(ruby_taint, path_injection, Path);
taint_rule_fn!(ruby_taint, open_redirect, Redirect);
taint_rule_fn!(ruby_taint, ssrf, Ssrf);
taint_rule_fn!(ruby_taint, code_injection, Code);
taint_rule_fn!(ruby_taint, xss, Html);
