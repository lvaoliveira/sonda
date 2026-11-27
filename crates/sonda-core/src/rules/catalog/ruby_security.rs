//! Ruby security rules (ADR-0033): what the file's own text shows, with no
//! types and no flow. A call is matched by its method's name and what it's
//! called on; a rule that needs a value to be one a client chose looks for
//! `params` itself, and waits for taint analysis to do better.

use super::ruby::{arguments, method_name, receiver_text, text_of, visit};
use super::{is_credential_name, looks_like_a_secret, octal_value, prelude::*};
use crate::lang::RUBY;

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "ruby/eval",
        name: "\"eval\" should not be used",
        description: "`eval` and `instance_eval`, `class_eval` and `module_eval` with a string run it as code, \
                      so whatever builds the string can run anything on the server. Use a block, `send` with a \
                      checked name, or a data format.",
        message: "Don't run code from a string.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Query {
            langs: RUBY,
            query: "(call) @match",
            filter: Some(Keep(evaluates_a_string)),
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "def run(code)\n  eval(code)\nend\n",
            good: "def run(name)\n  ALLOWED.fetch(name).call\nend\n",
        }),
    },
    Rule {
        id: "ruby/command-execution",
        name: "OS commands should not be built from values",
        description: "`system`, `exec`, `spawn`, `IO.popen`, `Open3` and backticks run a command line, so any \
                      part of it that isn't fixed can add commands. Pass the program and its arguments \
                      separately: `system('ls', dir)`.",
        message: "Don't build this command from values; pass the arguments separately.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Query {
            langs: RUBY,
            query: "[(call) (subshell)] @match",
            filter: Some(Find(builds_a_command)),
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "def list(dir)\n  system(\"ls #{dir}\")\nend\n",
            good: "def list(dir)\n  system('ls', dir)\nend\n",
        }),
    },
    Rule {
        id: "ruby/sql-interpolation",
        name: "SQL queries should not be built from values",
        description: "A query made by putting a value in a string (`where(\"name = '#{name}'\")`) lets the value \
                      add SQL. Bind it: `where('name = ?', name)` or `where(name: name)`.",
        message: "Bind this value instead of putting it in the query.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Query {
            langs: RUBY,
            query: "(call) @match",
            filter: Some(Find(builds_a_query)),
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "def find(name)\n  User.where(\"name = '#{name}'\")\nend\n",
            good: "def find(name)\n  User.where('name = ?', name)\nend\n",
        }),
    },
    Rule {
        id: "ruby/unsafe-deserialization",
        name: "Untrusted data should not be deserialized into objects",
        description: "`Marshal.load` and `YAML.unsafe_load` make any object the data names, and a crafted one \
                      runs code while it loads. Use JSON, or `YAML.safe_load` with the classes you expect.",
        message: "Don't load objects from data; use `safe_load` or JSON.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Query {
            langs: RUBY,
            query: "(call) @match",
            filter: Some(Keep(loads_objects)),
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "def read(data)\n  Marshal.load(data)\nend\n",
            good: "def read(data)\n  JSON.parse(data)\nend\n",
        }),
    },
    Rule {
        id: "ruby/weak-hash",
        name: "Weak hashes should not be used",
        description: "MD5 and SHA-1 can be made to collide, so a hash of them can't vouch for data or hide a \
                      password. Use SHA-256 or better, and `bcrypt` or `argon2` for passwords.",
        message: "Use a stronger hash than MD5 or SHA-1.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 15,
        sonar: &[],
        check: Check::Query {
            langs: RUBY,
            query: "(scope_resolution) @match",
            filter: Some(Keep(is_a_weak_hash)),
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "def sum(data)\n  Digest::MD5.hexdigest(data)\nend\n",
            good: "def sum(data)\n  Digest::SHA256.hexdigest(data)\nend\n",
        }),
    },
    Rule {
        id: "ruby/weak-cipher",
        name: "Weak ciphers and modes should not be used",
        description: "DES, 3DES, RC2, RC4 and Blowfish are broken or too small, and ECB shows patterns of the \
                      text. Use AES-GCM.",
        message: "Use an authenticated cipher such as AES-256-GCM.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Query {
            langs: RUBY,
            query: "(call) @match",
            filter: Some(Keep(makes_a_weak_cipher)),
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "def cipher\n  OpenSSL::Cipher.new('DES-CBC')\nend\n",
            good: "def cipher\n  OpenSSL::Cipher.new('aes-256-gcm')\nend\n",
        }),
    },
    Rule {
        id: "ruby/weak-random",
        name: "Secrets should not come from a predictable generator",
        description: "`rand`, `Random` and `sample` can be predicted from a few of their values, so a token, a \
                      password or a salt made from them can be guessed. Use `SecureRandom`.",
        message: "Use `SecureRandom` for this secret.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 15,
        sonar: &[],
        check: Check::Query {
            langs: RUBY,
            query: "(assignment left: (_) right: (_)) @match",
            filter: Some(Find(secret_from_a_predictable_source)),
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "def make\n  token = rand(1_000_000)\n  token\nend\n",
            good: "def make\n  token = SecureRandom.hex(16)\n  token\nend\n",
        }),
    },
    Rule {
        id: "ruby/tls-unverified",
        name: "Certificates should be verified",
        description: "With `VERIFY_NONE` or `verify_ssl: false` any server passes, so anyone on the network can \
                      read and change the traffic.",
        message: "Verify the server's certificate.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[],
        check: Check::Query {
            langs: RUBY,
            query: "[(scope_resolution) (pair)] @match",
            filter: Some(Keep(turns_verification_off)),
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "def setup(http)\n  http.verify_mode = OpenSSL::SSL::VERIFY_NONE\nend\n",
            good: "def setup(http)\n  http.verify_mode = OpenSSL::SSL::VERIFY_PEER\nend\n",
        }),
    },
    Rule {
        id: "ruby/hardcoded-credentials",
        name: "Credentials should not be hard-coded",
        description: "A password or key in the source is in every copy of it, and in its history. Read it from \
                      the environment, Rails credentials or a secrets manager.",
        message: "Don't hard-code this credential.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Query {
            langs: RUBY,
            query: "[(assignment) (operator_assignment) (pair)] @match",
            filter: Some(Find(hardcoded_credential)),
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "DB_PASSWORD = 'hunter2-prod'\n",
            good: "DB_PASSWORD = ENV.fetch('DB_PASSWORD')\n",
        }),
    },
    Rule {
        id: "ruby/permissive-file-mode",
        name: "Files and directories should not be writable by everyone",
        description: "A mode such as `0777` or `0666` lets any user on the machine change the file.",
        message: "Don't let everyone write this; use `0755`, `0644` or tighter.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 5,
        sonar: &[],
        check: Check::Query {
            langs: RUBY,
            query: "(call) @match",
            filter: Some(Find(world_writable_mode)),
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "def open_up(path)\n  File.chmod(0777, path)\nend\n",
            good: "def open_up(path)\n  File.chmod(0644, path)\nend\n",
        }),
    },
    Rule {
        id: "ruby/reflection-from-params",
        name: "Names looked up by reflection should not come from a request",
        description: "`send`, `constantize` and `const_get` with a name the client chose let it call any method \
                      or build any class. Choose from a fixed list.",
        message: "Don't choose the method or class from the request.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Query {
            langs: RUBY,
            query: "(call) @match",
            filter: Some(Keep(reflects_on_params)),
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "def show\n  params[:model].constantize.find(1)\nend\n",
            good: "def show\n  MODELS.fetch(params[:model]).find(1)\nend\n",
        }),
    },
    Rule {
        id: "ruby/path-from-params",
        name: "File paths should not come from a request",
        description: "`File.read(params[:file])` and `send_file` with a name the client chose read any file the \
                      server can, with `../`. Choose from a fixed list, or use `File.basename` and a directory.",
        message: "Don't build this path from the request.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Query {
            langs: RUBY,
            query: "(call) @match",
            filter: Some(Keep(opens_a_path_from_params)),
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "def download\n  send_file params[:file]\nend\n",
            good: "def download\n  send_file File.join(DIR, File.basename(params[:file]))\nend\n",
        }),
    },
    Rule {
        id: "ruby/mass-assignment",
        name: "\"permit!\" should not be used",
        description: "`params.permit!` lets a request set every attribute, including ones such as `admin`. List \
                      the ones the form has: `params.permit(:name, :email)`.",
        message: "Permit only the attributes the form has.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[],
        check: Check::Query {
            langs: RUBY,
            query: "(call) @match",
            filter: Some(Keep(permits_everything)),
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "def user_params\n  params.require(:user).permit!\nend\n",
            good: "def user_params\n  params.require(:user).permit(:name, :email)\nend\n",
        }),
    },
    Rule {
        id: "ruby/html-safe",
        name: "Built or requested text should not be marked safe",
        description: "`html_safe` and `raw` turn off the escaping of a view, so a string that holds a value, or \
                      a request's, runs as script in the page. Escape it, or build it with `content_tag`.",
        message: "Don't mark text safe when it holds a value.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 15,
        sonar: &[],
        check: Check::Query {
            langs: RUBY,
            query: "(call) @match",
            filter: Some(Keep(marks_a_value_safe)),
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "def greet(name)\n  \"<b>#{name}</b>\".html_safe\nend\n",
            good: "def greet(name)\n  content_tag(:b, name)\nend\n",
        }),
    },
    Rule {
        id: "ruby/redirect-from-params",
        name: "Redirects should not go where a request says",
        description: "`redirect_to params[:url]` sends a user to any site, which phishing uses. Redirect to a \
                      path of the application, or check the host.",
        message: "Don't redirect to a request's value.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 15,
        sonar: &[],
        check: Check::Query {
            langs: RUBY,
            query: "(call) @match",
            filter: Some(Keep(redirects_to_params)),
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "def go\n  redirect_to params[:url]\nend\n",
            good: "def go\n  redirect_to root_path\nend\n",
        }),
    },
    Rule {
        id: "ruby/csrf-disabled",
        name: "Forgery protection should not be turned off",
        description: "Without the authenticity token a page can't tell a request the user made from one another \
                      site made for them.",
        message: "Keep the CSRF check on this action.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 15,
        sonar: &[],
        check: Check::Query {
            langs: RUBY,
            query: "[(call) (identifier)] @match",
            filter: Some(Keep(skips_csrf_protection)),
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "class A < ApplicationController\n  skip_before_action :verify_authenticity_token\nend\n",
            good: "class A < ApplicationController\n  protect_from_forgery with: :exception\nend\n",
        }),
    },
];

// ---------------------------------------------------------------- helpers

/// Methods whose result is the program's own: a number, a table's name, a
/// value quoted or escaped for where it goes.
const OWN_CALLS: &[&str] = &[
    "to_i",
    "to_f",
    "to_r",
    "id",
    "pid",
    "size",
    "length",
    "count",
    "table_name",
    "quoted_table_name",
    "quote_table_name",
    "quote_column_name",
    "quote",
    "quote_string",
    "sanitize_sql",
    "sanitize_sql_array",
    "sanitize_sql_like",
    "shellescape",
    "shelljoin",
    "escape",
    "h",
    "j",
    "html_escape",
    "escapeHTML",
    "escape_html",
    "escape_javascript",
    "sanitize",
    "strip_tags",
    "content_tag",
    "link_to",
    "safe_join",
];

/// Whether an interpolated value is the program's own and not a request's: a
/// constant, a number, `Rails.root`, a table's name, what a method made safe
/// for where it goes.
fn is_own(e: Node, src: &[u8]) -> bool {
    match e.kind() {
        "constant" | "scope_resolution" | "integer" | "float" | "self" | "simple_symbol"
        | "nil" | "true" | "false" => true,
        "string" => !interpolates(e),
        // `table_name`, `topic_id`, `limit`: a table's, a number's.
        "identifier" => {
            let t = text_of(e, src);
            matches!(
                t,
                "table_name" | "quoted_table_name" | "primary_key" | "limit" | "offset" | "id"
            ) || t.ends_with("_id")
                || t.ends_with("_ids")
        }
        "element_reference" => e
            .child_by_field_name("object")
            .is_some_and(|o| is_own(o, src)),
        "parenthesized_statements" | "binary" => {
            let mut c = e.walk();
            e.named_children(&mut c).all(|k| is_own(k, src))
        }
        "call" => {
            let name = method_name(e, src).unwrap_or_default();
            let receiver = e.child_by_field_name("receiver");
            OWN_CALLS.contains(&name)
                || receiver_text(e, src).is_some_and(|r| r.starts_with("Rails"))
                // `Notification.types`: what a class says of itself.
                || (arguments(e).is_empty()
                    && receiver.is_some_and(|r| matches!(r.kind(), "constant" | "scope_resolution")))
                || (receiver.is_some_and(|r| matches!(r.kind(), "constant" | "scope_resolution"))
                    && ["_name", "_path", "_dir", "_sql", "_column"]
                        .iter()
                        .any(|w| name.ends_with(w)))
        }
        _ => false,
    }
}

/// Whether a string has `#{}` in it.
fn interpolates(n: Node) -> bool {
    let mut c = n.walk();
    n.named_children(&mut c)
        .any(|k| k.kind() == "interpolation")
}

/// Whether `n` is built from a value that isn't the program's own: a string
/// with `#{x}` in it, or two strings joined with `+` or `<<` where one
/// isn't a literal.
fn is_built(n: Node, src: &[u8]) -> bool {
    match n.kind() {
        "string" | "subshell" | "heredoc_body" => {
            let mut c = n.walk();
            n.named_children(&mut c)
                .filter(|k| k.kind() == "interpolation")
                .any(|k| {
                    let mut c = k.walk();
                    k.named_children(&mut c).any(|e| !is_own(e, src))
                })
        }
        "binary" => {
            n.child_by_field_name("operator")
                .is_some_and(|o| matches!(text_of(o, src), "+" | "<<"))
                && ["left", "right"]
                    .iter()
                    .filter_map(|f| n.child_by_field_name(f))
                    .any(|o| !is_plain_literal(o) && !is_own(o, src))
        }
        "parenthesized_statements" => n.named_child(0).is_some_and(|i| is_built(i, src)),
        _ => false,
    }
}

/// A string with nothing in it to evaluate, or a number.
fn is_plain_literal(n: Node) -> bool {
    match n.kind() {
        "string" => {
            let mut c = n.walk();
            n.named_children(&mut c)
                .all(|k| k.kind() != "interpolation")
        }
        "integer" | "float" | "simple_symbol" => true,
        "binary" => {
            let mut c = n.walk();
            n.named_children(&mut c).all(is_plain_literal)
        }
        _ => false,
    }
}

/// Whether the client's `params` is anywhere in `n`.
fn mentions_params(n: Node, src: &[u8]) -> bool {
    let mut found = false;
    visit(n, &mut |c| {
        found |= c.kind() == "identifier" && text_of(c, src) == "params";
    });
    found
}

/// Whether a call is on nothing (`system(..)`) or on `Kernel`.
fn is_a_function_call(call: Node, src: &[u8]) -> bool {
    receiver_text(call, src).is_none_or(|r| r == "Kernel")
}

// ---------------------------------------------------------------- filters

fn evaluates_a_string(n: Node, src: &[u8]) -> bool {
    let Some(name) = method_name(n, src) else {
        return false;
    };
    let args = arguments(n);
    // A block, or `&block`, is the safe form.
    if n.child_by_field_name("block").is_some()
        || args.first().is_none_or(|a| a.kind() == "block_argument")
    {
        return false;
    }
    match name {
        "eval" => {
            is_a_function_call(n, src) || receiver_text(n, src).is_some_and(|r| r == "binding")
        }
        // With a string; a block is the safe form. A string with `#{}` in
        // it is how a library generates its methods, and the names in it are
        // the library's own.
        "instance_eval" | "class_eval" | "module_eval" => {
            !is_plain_literal(args[0]) && !interpolates(args[0])
        }
        _ => false,
    }
}

/// The first argument that isn't an environment hash (`system({"A" => "b"}, cmd)`).
fn command_argument<'t>(args: &[Node<'t>]) -> Option<Node<'t>> {
    args.iter().copied().find(|a| a.kind() != "hash")
}

fn builds_a_command<'t>(n: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if n.kind() == "subshell" {
        return is_built(n, src).then_some(n);
    }
    let (name, receiver) = (method_name(n, src)?, receiver_text(n, src));
    let runs = match (receiver, name) {
        (None | Some("Kernel"), "system" | "exec" | "spawn") => true,
        (Some("IO"), "popen") => true,
        (Some("Open3"), n) => n.starts_with("capture") || n.starts_with("popen") || n == "pipeline",
        (Some("PTY"), "spawn") => true,
        _ => false,
    };
    // A program and its arguments, separately, is the safe form.
    let args = arguments(n);
    let positional = args
        .iter()
        .filter(|a| a.kind() != "pair" && a.kind() != "hash");
    let command = command_argument(&args)?;
    (runs && positional.count() == 1 && is_built(command, src)).then_some(command)
}

/// Methods that take SQL, or a part of it.
const SQL_METHODS: &[&str] = &[
    "where",
    "find_by_sql",
    "execute",
    "exec_query",
    "select_all",
    "select_one",
    "select_value",
    "select_rows",
    "order",
    "reorder",
    "group",
    "having",
    "joins",
    "pluck",
    "from",
    "delete_all",
    "update_all",
    "count_by_sql",
];

fn builds_a_query<'t>(n: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let first = *arguments(n).first()?;
    (SQL_METHODS.contains(&method_name(n, src)?) && is_built(first, src)).then_some(first)
}

fn loads_objects(n: Node, src: &[u8]) -> bool {
    let (Some(name), Some(receiver)) = (method_name(n, src), receiver_text(n, src)) else {
        return false;
    };
    match (receiver.trim_start_matches("::"), name) {
        // `Marshal.load(Marshal.dump(x))` copies a value.
        ("Marshal", "load" | "restore") => arguments(n)
            .first()
            .is_none_or(|a| !text_of(*a, src).starts_with("Marshal.dump")),
        ("YAML" | "Psych", "unsafe_load" | "unsafe_load_file") => true,
        // `YAML.load(File.read(path))` is the program's own configuration.
        ("YAML" | "Psych", "load") => arguments(n).first().is_some_and(|a| {
            let text = text_of(*a, src);
            !matches!(a.kind(), "string")
                && !["File.read", "File.open", "IO.read", "File.binread"]
                    .iter()
                    .any(|r| text.contains(r))
        }),
        _ => false,
    }
}

fn is_a_weak_hash(n: Node, src: &[u8]) -> bool {
    matches!(
        text_of(n, src),
        "Digest::MD5"
            | "Digest::SHA1"
            | "Digest::MD4"
            | "OpenSSL::Digest::MD5"
            | "OpenSSL::Digest::SHA1"
            | "OpenSSL::Digest::MD4"
    )
}

fn makes_a_weak_cipher(n: Node, src: &[u8]) -> bool {
    let Some(receiver) = receiver_text(n, src) else {
        return false;
    };
    if method_name(n, src) != Some("new") {
        return false;
    }
    // `OpenSSL::Cipher::DES.new`, `OpenSSL::Cipher::RC4.new`.
    if let Some(kind) = receiver.strip_prefix("OpenSSL::Cipher::") {
        return is_a_weak_algorithm(&kind.to_ascii_lowercase());
    }
    receiver == "OpenSSL::Cipher"
        && arguments(n).first().is_some_and(|a| {
            a.kind() == "string" && is_a_weak_algorithm(&text_of(*a, src).to_ascii_lowercase())
        })
}

fn is_a_weak_algorithm(name: &str) -> bool {
    let name = name.trim_matches(['"', '\'']);
    ["des", "rc2", "rc4", "bf", "blowfish"]
        .iter()
        .any(|w| name.starts_with(w))
        || name.contains("ecb")
}

/// Words in a name that make what it holds a secret.
const SECRET_NAMES: &[&str] = &[
    "token", "secret", "password", "passwd", "otp", "nonce", "salt", "csrf", "api_key",
];

fn secret_from_a_predictable_source<'t>(n: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let left = text_of(n.child_by_field_name("left")?, src).to_ascii_lowercase();
    let right = n.child_by_field_name("right")?;
    if !SECRET_NAMES.iter().any(|w| left.contains(w))
        || text_of(right, src).contains("SecureRandom")
    {
        return None;
    }
    let mut predictable = false;
    visit(right, &mut |c| {
        predictable |= c.kind() == "call"
            && matches!(
                (receiver_text(c, src), method_name(c, src)),
                (Some("Random"), Some("rand" | "new"))
                    | (_, Some("sample" | "shuffle"))
                    | (None | Some("Kernel"), Some("rand" | "srand"))
            );
    });
    predictable.then_some(right)
}

fn turns_verification_off(n: Node, src: &[u8]) -> bool {
    if n.kind() == "scope_resolution" {
        return text_of(n, src).ends_with("::VERIFY_NONE");
    }
    let (Some(key), Some(value)) = (n.child_by_field_name("key"), n.child_by_field_name("value"))
    else {
        return false;
    };
    value.kind() == "false"
        && matches!(
            text_of(key, src).trim_matches([':', '"', '\'']),
            "verify_ssl" | "ssl_verify" | "verify_peer" | "ssl_verify_peer" | "verify_certificate"
        )
}

/// The name a value is given: `password`, `@api_key`, `config[:secret]`, `:token =>`.
fn assigned_name(n: Node, src: &[u8]) -> Option<String> {
    let name = match n.kind() {
        "identifier" | "constant" | "instance_variable" | "global_variable" | "class_variable"
        | "hash_key_symbol" | "simple_symbol" => text_of(n, src),
        "string" => text_of(n, src).trim_matches(['"', '\'']),
        "element_reference" => return assigned_name(n.named_child(1)?, src),
        "call" => text_of(n.child_by_field_name("method")?, src),
        _ => return None,
    };
    Some(name.trim_matches(['@', '$', ':']).to_string())
}

fn hardcoded_credential<'t>(n: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let (name, value) = if n.kind() == "pair" {
        (
            n.child_by_field_name("key")?,
            n.child_by_field_name("value")?,
        )
    } else {
        (
            n.child_by_field_name("left")?,
            n.child_by_field_name("right")?,
        )
    };
    let literal = text_of(value, src).trim_matches(['"', '\'']);
    // A string key that isn't a name (`"password-reset" => "static#show"`) is
    // a route.
    let named = name.kind() != "string"
        || text_of(name, src)
            .trim_matches(['"', '\''])
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_');
    (value.kind() == "string"
        && named
        && !interpolates(value)
        && is_credential_name(&assigned_name(name, src)?)
        && looks_like_a_secret(literal))
    .then_some(value)
}

/// A mode written as an octal literal: `0777`, `0o666`.
fn octal_mode(n: Node, src: &[u8]) -> Option<u32> {
    if n.kind() != "integer" {
        return None;
    }
    octal_value(text_of(n, src))
}

/// The mode of a call that creates or changes a file, when anyone can write
/// to the result.
fn world_writable_mode<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !matches!(
        method_name(call, src)?,
        "chmod" | "chmod_R" | "mkdir" | "mkdir_p" | "makedirs"
    ) {
        return None;
    }
    arguments(call).into_iter().find_map(|a| {
        let mode = if a.kind() == "pair" {
            a.child_by_field_name("value")?
        } else {
            a
        };
        (octal_mode(mode, src)? & 0o002 != 0).then_some(mode)
    })
}

fn reflects_on_params(n: Node, src: &[u8]) -> bool {
    let Some(name) = method_name(n, src) else {
        return false;
    };
    match name {
        "send"
        | "public_send"
        | "__send__"
        | "const_get"
        | "instance_variable_get"
        | "instance_variable_set" => arguments(n).iter().any(|a| mentions_params(*a, src)),
        "constantize" | "safe_constantize" => n
            .child_by_field_name("receiver")
            .is_some_and(|r| mentions_params(r, src)),
        _ => false,
    }
}

fn opens_a_path_from_params(n: Node, src: &[u8]) -> bool {
    let Some(name) = method_name(n, src) else {
        return false;
    };
    let reads = match receiver_text(n, src) {
        Some("File" | "IO" | "FileUtils" | "Pathname" | "Dir") => matches!(
            name,
            "read"
                | "readlines"
                | "binread"
                | "write"
                | "open"
                | "new"
                | "delete"
                | "unlink"
                | "rm"
                | "rm_f"
                | "rm_rf"
                | "cp"
                | "mv"
                | "foreach"
                | "exist?"
                | "entries"
                | "glob"
        ),
        None => matches!(name, "send_file" | "open"),
        _ => false,
    };
    let args = arguments(n);
    reads
        && args.iter().any(|a| mentions_params(*a, src))
        && !args.iter().any(|a| text_of(*a, src).contains("basename"))
}

fn permits_everything(n: Node, src: &[u8]) -> bool {
    method_name(n, src) == Some("permit!")
}

fn marks_a_value_safe(n: Node, src: &[u8]) -> bool {
    let value_in = |v: Node| is_built(v, src) || mentions_params(v, src);
    match method_name(n, src) {
        Some("html_safe") => n.child_by_field_name("receiver").is_some_and(value_in),
        Some("raw") if receiver_text(n, src).is_none() => {
            arguments(n).first().is_some_and(|a| value_in(*a))
        }
        _ => false,
    }
}

fn redirects_to_params(n: Node, src: &[u8]) -> bool {
    method_name(n, src) == Some("redirect_to")
        && receiver_text(n, src).is_none()
        && arguments(n)
            .first()
            .is_some_and(|a| mentions_params(*a, src) && !text_of(n, src).contains("only_path"))
}

fn skips_csrf_protection(n: Node, src: &[u8]) -> bool {
    // `skip_forgery_protection` alone is an identifier.
    if n.kind() == "identifier" {
        return text_of(n, src) == "skip_forgery_protection";
    }
    if receiver_text(n, src).is_some() {
        return false;
    }
    match method_name(n, src) {
        Some("skip_forgery_protection") => true,
        Some("skip_before_action" | "skip_before_filter") => arguments(n)
            .iter()
            .any(|a| text_of(*a, src) == ":verify_authenticity_token"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::tests::flagged_ruby as flagged;

    #[test]
    fn code_run_from_a_string_not_from_a_block() {
        let src = "eval(code)\neval('1 + 1')\nKernel.eval(code)\nobj.instance_eval(code)\nobj.instance_eval { 1 }\nobj.class_eval \"def #{n}; end\"\nobj.class_eval 'x'\n";
        assert_eq!(flagged("ruby/eval", src), [1, 2, 3, 4]);
    }

    #[test]
    fn a_command_is_built_only_when_it_is_one_string() {
        let src = "system(\"ls #{d}\")\nsystem('ls', d)\nsystem('ls ' + d)\nsystem('ls')\n`ls #{d}`\n`ls`\nIO.popen(\"x #{y}\")\nOpen3.capture2e(\"x #{y}\")\nexec({'A' => 'b'}, \"x #{y}\")\nbuild(\"#{x}\")\n";
        assert_eq!(flagged("ruby/command-execution", src), [1, 3, 5, 7, 8, 9]);
    }

    #[test]
    fn a_query_is_built_only_when_the_value_is_in_the_string() {
        let src = "User.where(\"name = '#{n}'\")\nUser.where('name = ?', n)\nUser.where(name: n)\nUser.order(\"#{col} desc\")\nUser.find_by_sql('select ' + cols)\nUser.find_by_sql('select 1')\nUser.group('a')\nlist.select(\"#{x}\")\n";
        assert_eq!(flagged("ruby/sql-interpolation", src), [1, 4, 5]);
    }

    #[test]
    fn objects_are_loaded_only_from_data_that_isnt_the_programs_own() {
        let src = "Marshal.load(data)\nMarshal.load(Marshal.dump(x))\nYAML.load(body)\nYAML.load(File.read(path))\nYAML.load('a: 1')\nYAML.unsafe_load(body)\nYAML.safe_load(body)\nJSON.load(body)\n";
        assert_eq!(flagged("ruby/unsafe-deserialization", src), [1, 3, 6]);
    }

    #[test]
    fn weak_hashes_ciphers_and_generators() {
        let src =
            "Digest::MD5.hexdigest(x)\nDigest::SHA256.hexdigest(x)\nOpenSSL::Digest::SHA1.new\n";
        assert_eq!(flagged("ruby/weak-hash", src), [1, 3]);
        let src = "OpenSSL::Cipher.new('DES-CBC')\nOpenSSL::Cipher.new('aes-128-ecb')\nOpenSSL::Cipher.new('aes-256-gcm')\nOpenSSL::Cipher::RC4.new\n";
        assert_eq!(flagged("ruby/weak-cipher", src), [1, 2, 4]);
        let src = "token = rand(10**6)\nname = rand(10)\npassword = chars.sample(8).join\nsalt = SecureRandom.hex(8)\napi_token = Random.new.rand\n";
        assert_eq!(flagged("ruby/weak-random", src), [1, 3, 5]);
    }

    #[test]
    fn verification_is_turned_off_by_a_constant_or_an_option() {
        let src = "h.verify_mode = OpenSSL::SSL::VERIFY_NONE\nh.verify_mode = OpenSSL::SSL::VERIFY_PEER\nget(url, verify_ssl: false)\nget(url, verify_ssl: true)\nget(url, verify: false)\n";
        assert_eq!(flagged("ruby/tls-unverified", src), [1, 3]);
    }

    #[test]
    fn what_looks_like_a_credential_is_one_only_with_a_value_that_could_be() {
        let src = "DB_PASSWORD = 'hunter2-prod'\npassword_env = 'DB_PASSWORD'\npassword = ''\nsecret = \"%s\"\nconfig[:api_key] = 's3cr3t-value1'\nOPTS = { password: 's3cr3t-value2', user: 'admin' }\npassword = ENV['P']\ntoken = \"a#{b}cdef\"\n";
        assert_eq!(flagged("ruby/hardcoded-credentials", src), [1, 5, 6]);
    }

    #[test]
    fn only_a_mode_everyone_can_write_is_permissive() {
        let src = "File.chmod(0777, p)\nFile.chmod(0644, p)\nFileUtils.mkdir_p(d, mode: 0o777)\nFileUtils.mkdir_p(d, mode: 0o755)\nFileUtils.chmod_R(0666, d)\n";
        assert_eq!(flagged("ruby/permissive-file-mode", src), [1, 3, 5]);
    }

    #[test]
    fn what_a_request_chooses_must_not_reach_reflection_or_paths() {
        let src = "params[:m].constantize\nMODELS.fetch(params[:m])\nobj.send(params[:a])\nobj.send(:a)\nKlass.const_get(params[:k])\n";
        assert_eq!(flagged("ruby/reflection-from-params", src), [1, 3, 5]);
        let src = "send_file params[:f]\nsend_file File.join(D, File.basename(params[:f]))\nFile.read(params[:f])\nFile.read('a')\nopen(params[:u])\n";
        assert_eq!(flagged("ruby/path-from-params", src), [1, 3, 5]);
    }

    #[test]
    fn views_forms_and_redirects() {
        let src = "a.permit!\na.permit(:b)\n";
        assert_eq!(flagged("ruby/mass-assignment", src), [1]);
        let src = "\"<b>#{x}</b>\".html_safe\n'<b>x</b>'.html_safe\nraw(\"#{x}\")\nraw(params[:h])\nraw(tag)\nx.html_safe\n";
        assert_eq!(flagged("ruby/html-safe", src), [1, 3, 4]);
        let src = "redirect_to params[:u]\nredirect_to root_path\nredirect_to params.permit(:x).merge(only_path: true)\n";
        assert_eq!(flagged("ruby/redirect-from-params", src), [1]);
        let src = "skip_before_action :verify_authenticity_token\nskip_before_action :login\nskip_forgery_protection\n";
        assert_eq!(flagged("ruby/csrf-disabled", src), [1, 3]);
    }

    #[test]
    fn the_programs_own_values_in_a_string_are_not_built_from_values() {
        // A constant, a table's name, a number, a value quoted for the query.
        let src = "User.where(\"#{User.table_name}.id = 1\")\nUser.where(\"id = #{Limit::MAX}\")\nUser.where(\"id = #{id.to_i}\")\nUser.where(\"n = #{connection.quote(n)}\")\nUser.where(\"n = #{n}\")\nUser.where(\"t = #{Notification.types[:a]} and u = #{user_id} and #{table_name}.x = 1\")\n";
        assert_eq!(flagged("ruby/sql-interpolation", src), [5]);
        // The report is at the argument, not at the start of the chain.
        let src = "User\n  .active\n  .where(\"n = #{n}\")\n";
        assert_eq!(flagged("ruby/sql-interpolation", src), [3]);
        let src = "system(\"ps -p #{pid.to_i}\")\nsystem(\"ls #{Rails.root}\")\nsystem(\"ls #{dir}\")\n`ls #{dir.shellescape}`\n";
        assert_eq!(flagged("ruby/command-execution", src), [3]);
    }

    #[test]
    fn escaped_values_in_a_string_marked_safe_are_not_a_finding() {
        let src = "\"<b>#{h name}</b>\".html_safe\n\"<b>#{CGI.escapeHTML(n)}</b>\".html_safe\n\"<b>#{name}</b>\".html_safe\n";
        assert_eq!(flagged("ruby/html-safe", src), [3]);
    }

    #[test]
    fn eval_of_a_block_a_route_and_a_programs_own_file() {
        let src = "instance_eval(&block)\ninstance_eval(code)\n";
        assert_eq!(flagged("ruby/eval", src), [2]);
        let src = "get \"password-reset\" => \"static#show\"\nOPTS = { \"password\" => \"s3cr3t-value\" }\n";
        assert_eq!(flagged("ruby/hardcoded-credentials", src), [2]);
        let src = "YAML.load(ERB.new(File.read(f)).result)\nYAML.load(body)\n";
        assert_eq!(flagged("ruby/unsafe-deserialization", src), [2]);
    }
}
