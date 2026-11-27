//! PHP security rules (ADR-0032): what the file's own text shows, with no
//! types and no flow. A function is matched by its name, which PHP reads
//! without regard to case; a rule that needs a value to be one a client
//! chose waits for taint analysis.

use super::php::{arguments, function_name, text_of, visit};
use super::prelude::*;
use super::{is_credential_name, looks_like_a_secret, octal_value};
use crate::lang::PHP;

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "php/eval",
        name: "\"eval\" should not be used",
        description: "`eval` runs a string as code, so whatever builds the string can run anything on the \
                      server. Use a function, a callback, or a data format instead.",
        message: "Don't run code from a string.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Query {
            langs: PHP,
            query: "(function_call_expression function: (_)) @match",
            filter: Some(Keep(evaluates_a_string)),
        },
        example: Some(Example {
            lang: Lang::Php,
            bad: "<?php\nfunction run($code) {\n    eval($code);\n}\n",
            good: "<?php\nfunction run($code) {\n    return json_decode($code, true);\n}\n",
        }),
    },
    Rule {
        id: "php/include-from-request",
        name: "Files to include should not be named by a request's values",
        description: "`include $_GET['page']` runs whatever file the client names, including one it uploaded, \
                      or a remote one when `allow_url_include` is on. Choose from a fixed list.",
        message: "Don't include a file named by the request.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Query {
            langs: PHP,
            query: "[(include_expression) (include_once_expression) (require_expression) (require_once_expression)] @match",
            filter: Some(Keep(includes_a_request_value)),
        },
        example: Some(Example {
            lang: Lang::Php,
            bad: "<?php\ninclude $_GET['page'] . '.php';\n",
            good: "<?php\n$pages = ['home', 'about'];\n$page = in_array($_GET['page'], $pages, true) ? $_GET['page'] : 'home';\ninclude __DIR__ . '/' . $page . '.php';\n",
        }),
    },
    Rule {
        id: "php/command-execution",
        name: "OS commands should not be built from values",
        description: "`system`, `exec`, `shell_exec`, `passthru`, `popen`, `proc_open` and backticks run a \
                      command line, so any part of it that isn't fixed can add commands. Pass the value through \
                      `escapeshellarg`, or run the program with an argument array (`proc_open`).",
        message: "Don't build this command from values; use `escapeshellarg`.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Query {
            langs: PHP,
            query: "[(function_call_expression function: (_)) (shell_command_expression)] @match",
            filter: Some(Keep(runs_a_built_command)),
        },
        example: Some(Example {
            lang: Lang::Php,
            bad: "<?php\nfunction ping($host) {\n    return shell_exec('ping -c 1 ' . $host);\n}\n",
            good: "<?php\nfunction ping($host) {\n    return shell_exec('ping -c 1 ' . escapeshellarg($host));\n}\n",
        }),
    },
    Rule {
        id: "php/sql-concatenation",
        name: "SQL queries should not be built from strings",
        description: "A query assembled with `.` or an interpolated string from a value the program doesn't \
                      control lets that value change the query. Use a prepared statement with placeholders.",
        message: "Pass these values as query parameters, not in the text.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Query {
            langs: PHP,
            query: "[(function_call_expression function: (_)) (member_call_expression) (scoped_call_expression)] @match",
            filter: Some(Find(built_query)),
        },
        example: Some(Example {
            lang: Lang::Php,
            bad: "<?php\nfunction find($db, $id) {\n    return mysqli_query($db, \"SELECT * FROM users WHERE id = '$id'\");\n}\n",
            good: "<?php\nfunction find($db, $id) {\n    $st = $db->prepare('SELECT * FROM users WHERE id = ?');\n    $st->execute([$id]);\n    return $st;\n}\n",
        }),
    },
    Rule {
        id: "php/unserialize",
        name: "\"unserialize\" should not be called on values the program doesn't control",
        description: "`unserialize` builds objects of any class the text names, and their magic methods run: \
                      a crafted string can run code. Use `json_decode`, or pass `['allowed_classes' => false]`.",
        message: "Use `json_decode`, or restrict `allowed_classes`.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 20,
        sonar: &[],
        check: Check::Query {
            langs: PHP,
            query: "(function_call_expression function: (_)) @match",
            filter: Some(Keep(unserializes_freely)),
        },
        example: Some(Example {
            lang: Lang::Php,
            bad: "<?php\nfunction load($data) {\n    return unserialize($data);\n}\n",
            good: "<?php\nfunction load($data) {\n    return unserialize($data, ['allowed_classes' => false]);\n}\n",
        }),
    },
    Rule {
        id: "php/weak-hash",
        name: "Weak hashes should not be used",
        description: "MD5, SHA-1 and CRC32 collide, so a signature, token or password hash built on them can be \
                      forged. Use `hash('sha256', ...)`, and `password_hash` for passwords.",
        message: "Use a stronger hash than MD5, SHA-1 or CRC32.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 20,
        sonar: &[],
        check: Check::Query {
            langs: PHP,
            query: "(function_call_expression function: (_)) @match",
            filter: Some(Keep(uses_weak_hash)),
        },
        example: Some(Example {
            lang: Lang::Php,
            bad: "<?php\nfunction digest($s) {\n    return md5($s);\n}\n",
            good: "<?php\nfunction digest($s) {\n    return hash('sha256', $s);\n}\n",
        }),
    },
    Rule {
        id: "php/weak-cipher",
        name: "Weak ciphers should not be used",
        description: "`mcrypt` was removed from PHP, and DES, RC4, RC2, Blowfish and ECB mode are broken or leak \
                      the plaintext's structure. Use `openssl_encrypt` with AES-GCM, or sodium.",
        message: "Use a modern cipher, such as AES-GCM.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Query {
            langs: PHP,
            query: "(function_call_expression function: (_)) @match",
            filter: Some(Keep(uses_weak_cipher)),
        },
        example: Some(Example {
            lang: Lang::Php,
            bad: "<?php\nfunction seal($data, $key, $iv) {\n    return openssl_encrypt($data, 'des-ede3', $key, 0, $iv);\n}\n",
            good: "<?php\nfunction seal($data, $key, $iv) {\n    return openssl_encrypt($data, 'aes-256-gcm', $key, 0, $iv);\n}\n",
        }),
    },
    Rule {
        id: "php/weak-random",
        name: "Secrets should not come from a predictable generator",
        description: "`rand`, `mt_rand` and `uniqid` are predictable, so a token, password or salt built from \
                      them can be guessed. Use `random_bytes` or `random_int`.",
        message: "Use `random_bytes` or `random_int` for a secret.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[],
        check: Check::Query {
            langs: PHP,
            query: "(assignment_expression left: (_) right: (_)) @match",
            filter: Some(Keep(secret_from_a_weak_generator)),
        },
        example: Some(Example {
            lang: Lang::Php,
            bad: "<?php\nfunction newToken() {\n    $token = md5(uniqid(mt_rand()));\n    return $token;\n}\n",
            good: "<?php\nfunction newToken() {\n    $token = bin2hex(random_bytes(16));\n    return $token;\n}\n",
        }),
    },
    Rule {
        id: "php/tls-unverified",
        name: "TLS certificates should be verified",
        description: "Turning off `CURLOPT_SSL_VERIFYPEER`, `CURLOPT_SSL_VERIFYHOST`, `verify_peer` or Guzzle's \
                      `verify` lets anyone on the path read and change the traffic.",
        message: "Don't turn off certificate verification.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 20,
        sonar: &[],
        check: Check::Query {
            langs: PHP,
            query: "[(function_call_expression function: (_)) (array_element_initializer)] @match",
            filter: Some(Keep(skips_verification)),
        },
        example: Some(Example {
            lang: Lang::Php,
            bad: "<?php\nfunction get($ch) {\n    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);\n}\n",
            good: "<?php\nfunction get($ch) {\n    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);\n}\n",
        }),
    },
    Rule {
        id: "php/hardcoded-credentials",
        name: "Credentials should not be hard-coded",
        description: "A password, secret or key in the source is in every clone, build and log of it, and can't \
                      be rotated without a release. Read it from the environment or a secret store.",
        message: "Remove this hard-coded credential.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Query {
            langs: PHP,
            query: "[(assignment_expression left: (_) right: (_)) (array_element_initializer) (function_call_expression function: (_)) (const_element)] @match",
            filter: Some(Find(hardcoded_credential)),
        },
        example: Some(Example {
            lang: Lang::Php,
            bad: "<?php\nfunction connect() {\n    $dbPassword = 'hunter2-prod';\n    return $dbPassword;\n}\n",
            good: "<?php\nfunction connect() {\n    $dbPassword = getenv('DB_PASSWORD');\n    return $dbPassword;\n}\n",
        }),
    },
    Rule {
        id: "php/permissive-file-mode",
        name: "Files and directories should not be writable by everyone",
        description: "A mode with the world-write bit (`0777`, `0666`) lets any user on the machine change the \
                      file or put files in the directory.",
        message: "Remove write permission for others from this mode.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 10,
        sonar: &[],
        check: Check::Query {
            langs: PHP,
            query: "(function_call_expression function: (_)) @match",
            filter: Some(Find(world_writable_mode)),
        },
        example: Some(Example {
            lang: Lang::Php,
            bad: "<?php\nfunction make($dir) {\n    return mkdir($dir, 0777, true);\n}\n",
            good: "<?php\nfunction make($dir) {\n    return mkdir($dir, 0750, true);\n}\n",
        }),
    },
    Rule {
        id: "php/extract-request",
        name: "Request values should not become variables",
        description: "`extract($_POST)` and `parse_str($query)` with no result array turn every key a client \
                      sends into a variable, overwriting the program's own (`register_globals` by another name).",
        message: "Read the values you need by name; don't import them all.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 20,
        sonar: &[],
        check: Check::Query {
            langs: PHP,
            query: "(function_call_expression function: (_)) @match",
            filter: Some(Keep(imports_request_variables)),
        },
        example: Some(Example {
            lang: Lang::Php,
            bad: "<?php\nfunction page() {\n    extract($_POST);\n}\n",
            good: "<?php\nfunction page() {\n    $name = $_POST['name'] ?? '';\n    return $name;\n}\n",
        }),
    },
    Rule {
        id: "php/phpinfo",
        name: "\"phpinfo\" should not be left in the code",
        description: "`phpinfo()` prints the PHP version, its modules, paths and environment variables: what an \
                      attacker needs to pick an exploit.",
        message: "Remove this call to `phpinfo`.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 2,
        sonar: &[],
        check: Check::Query {
            langs: PHP,
            query: "(function_call_expression function: (_)) @match",
            filter: Some(Keep(prints_the_configuration)),
        },
        example: Some(Example {
            lang: Lang::Php,
            bad: "<?php\nphpinfo();\n",
            good: "<?php\necho 'ok';\n",
        }),
    },
    Rule {
        id: "php/xxe",
        name: "XML external entities should not be resolved",
        description: "`LIBXML_NOENT` makes the parser replace entities, including ones that read local files or \
                      call internal URLs from a document the client sent. Parse without it.",
        message: "Don't pass `LIBXML_NOENT`: it resolves external entities.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[],
        check: Check::Query {
            langs: PHP,
            query: "(name) @match",
            filter: Some(Keep(is_libxml_noent)),
        },
        example: Some(Example {
            lang: Lang::Php,
            bad: "<?php\nfunction parse($xml) {\n    return simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT);\n}\n",
            good: "<?php\nfunction parse($xml) {\n    return simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NONET);\n}\n",
        }),
    },
];

// ---------------------------------------------------------------- helpers

fn is_literal(n: Node) -> bool {
    matches!(
        n.kind(),
        "string" | "integer" | "float" | "boolean" | "null"
    )
}

/// The superglobals a client fills.
const REQUEST_ARRAYS: &[&str] = &["$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES"];

fn mentions_request(n: Node, src: &[u8]) -> bool {
    let mut found = false;
    visit(n, &mut |c| {
        found |= c.kind() == "variable_name" && REQUEST_ARRAYS.contains(&text_of(c, src));
    });
    found
}

/// Whether the value of `n` can differ from one run to the next: it reads a
/// variable or calls something, except what makes a value safe for where it
/// goes (`safe` names the functions that do) or a number.
fn is_dynamic(n: Node, src: &[u8], safe: &[&str]) -> bool {
    match n.kind() {
        // A property (`$wpdb->posts`, `$this->table`) is the program's own: a
        // table name, say. A variable and an element (`$_GET['id']`) can be a
        // client's.
        "variable_name" | "subscript_expression" => true,
        "member_access_expression" | "scoped_property_access_expression" => false,
        "function_call_expression" => {
            !function_name(n, src).is_some_and(|f| safe.contains(&f.as_str()))
        }
        "member_call_expression" | "scoped_call_expression" => {
            let name = n
                .child_by_field_name("name")
                .map_or("", |x| text_of(x, src))
                .to_ascii_lowercase();
            !safe.contains(&name.as_str())
        }
        "cast_expression" => !n.child_by_field_name("type").is_some_and(|t| {
            matches!(
                text_of(t, src),
                "int" | "integer" | "float" | "double" | "bool" | "boolean"
            )
        }),
        _ => {
            let mut c = n.walk();
            n.named_children(&mut c).any(|k| is_dynamic(k, src, safe))
        }
    }
}

// ---------------------------------------------------------------- filters

fn evaluates_a_string(call: Node, src: &[u8]) -> bool {
    function_name(call, src).is_some_and(|f| f == "eval")
        && arguments(call).first().is_some_and(|a| !is_literal(*a))
}

fn includes_a_request_value(n: Node, src: &[u8]) -> bool {
    mentions_request(n, src)
}

const SHELL_FUNCTIONS: &[&str] = &[
    "system",
    "exec",
    "shell_exec",
    "passthru",
    "popen",
    "proc_open",
    "pcntl_exec",
    "expect_popen",
];

const SHELL_SAFE: &[&str] = &["escapeshellarg", "escapeshellcmd", "intval", "floatval"];

fn runs_a_built_command(n: Node, src: &[u8]) -> bool {
    if n.kind() == "shell_command_expression" {
        return is_dynamic(n, src, SHELL_SAFE);
    }
    function_name(n, src).is_some_and(|f| SHELL_FUNCTIONS.contains(&f.as_str()))
        && arguments(n)
            .first()
            .is_some_and(|a| is_dynamic(*a, src, SHELL_SAFE))
}

/// Where the query is among a SQL function's arguments.
fn query_position(function: &str) -> Option<usize> {
    match function {
        "mysql_query" | "mysql_unbuffered_query" | "sqlite_query" | "sqlite_exec" => Some(0),
        "mysqli_query" | "mysqli_multi_query" | "mysqli_real_query" | "pg_query"
        | "pg_send_query" | "odbc_exec" | "sqlsrv_query" | "mssql_query" => Some(1),
        _ => None,
    }
}

const SQL_SAFE: &[&str] = &[
    "intval",
    "floatval",
    "abs",
    "count",
    "strlen",
    "mysqli_real_escape_string",
    "mysql_real_escape_string",
    "mysqli_escape_string",
    "pg_escape_string",
    "pg_escape_literal",
    "esc_sql",
    "addslashes",
    "quote",
    "real_escape_string",
    "escape_string",
    "absint",
];

const SQL_WORDS: &[&str] = &[
    "select ", "insert ", "update ", "delete ", "where ", " from ", "union ",
];

/// The text a string or a concatenation spells out.
fn literal_text(n: Node, src: &[u8]) -> String {
    let mut out = String::new();
    visit(n, &mut |c| {
        if c.kind() == "string_content" {
            out.push_str(text_of(c, src));
        }
    });
    out.to_ascii_lowercase()
}

/// The query argument, if it's text joined with a value.
fn built_query<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let args = arguments(call);
    let at = if call.kind() == "function_call_expression" {
        let name = function_name(call, src)?;
        // `pg_query($sql)` has no connection first.
        match (name.as_str(), args.len()) {
            ("pg_query", 1) => 0,
            _ => query_position(&name)?,
        }
    } else {
        let name = text_of(call.child_by_field_name("name")?, src).to_ascii_lowercase();
        let is_query_method = matches!(
            name.as_str(),
            "query"
                | "exec"
                | "prepare"
                | "multi_query"
                | "real_query"
                | "get_results"
                | "get_row"
                | "get_var"
                | "get_col"
                | "unbuffered_query"
        );
        if !is_query_method {
            return None;
        }
        0
    };
    let arg = *args.get(at)?;
    let spelled = matches!(arg.kind(), "encapsed_string" | "binary_expression");
    let sql = || SQL_WORDS.iter().any(|w| literal_text(arg, src).contains(w));
    (spelled && is_dynamic(arg, src, SQL_SAFE) && sql()).then_some(arg)
}

fn unserializes_freely(call: Node, src: &[u8]) -> bool {
    function_name(call, src).is_some_and(|f| f == "unserialize")
        && arguments(call).first().is_some_and(|a| !is_literal(*a))
        && !text_of(call, src).contains("allowed_classes")
}

fn uses_weak_hash(call: Node, src: &[u8]) -> bool {
    let Some(name) = function_name(call, src) else {
        return false;
    };
    match name.as_str() {
        "md5" | "sha1" | "crc32" | "md5_file" | "sha1_file" => true,
        "hash" | "hash_file" | "hash_hmac" => arguments(call).first().is_some_and(|a| {
            let algorithm = text_of(*a, src)
                .trim_matches(['\'', '"'])
                .to_ascii_lowercase();
            matches!(
                algorithm.as_str(),
                "md2" | "md4" | "md5" | "sha1" | "crc32" | "crc32b"
            )
        }),
        _ => false,
    }
}

fn uses_weak_cipher(call: Node, src: &[u8]) -> bool {
    let Some(name) = function_name(call, src) else {
        return false;
    };
    if name.starts_with("mcrypt_") {
        return true;
    }
    if !matches!(name.as_str(), "openssl_encrypt" | "openssl_decrypt") {
        return false;
    }
    let Some(cipher) = arguments(call).get(1).filter(|a| is_literal(**a)).copied() else {
        return false;
    };
    let cipher = text_of(cipher, src)
        .trim_matches(['\'', '"'])
        .to_ascii_lowercase();
    ["des", "rc4", "rc2", "bf-", "-ecb"]
        .iter()
        .any(|w| cipher.contains(w))
}

const SECRET_WORDS: &[&str] = &[
    "token",
    "password",
    "passwd",
    "pwd",
    "secret",
    "salt",
    "nonce",
    "csrf",
    "apikey",
    "api_key",
    "otp",
    "sessionid",
];

const WEAK_GENERATORS: &[&str] = &[
    "rand",
    "mt_rand",
    "uniqid",
    "lcg_value",
    "shuffle",
    "str_shuffle",
    "array_rand",
];

fn secret_from_a_weak_generator(n: Node, src: &[u8]) -> bool {
    let (Some(left), Some(right)) = (
        n.child_by_field_name("left"),
        n.child_by_field_name("right"),
    ) else {
        return false;
    };
    let name = text_of(left, src).to_ascii_lowercase();
    if !SECRET_WORDS.iter().any(|w| name.contains(w)) {
        return false;
    }
    let mut weak = false;
    visit(right, &mut |c| {
        weak |= function_name(c, src).is_some_and(|f| WEAK_GENERATORS.contains(&f.as_str()));
    });
    weak
}

fn is_off(n: Node, src: &[u8]) -> bool {
    n.kind() == "boolean" && text_of(n, src).eq_ignore_ascii_case("false")
        || matches!(text_of(n, src), "0" | "'0'" | "\"0\"")
}

fn skips_verification(n: Node, src: &[u8]) -> bool {
    if n.kind() == "array_element_initializer" {
        let mut c = n.walk();
        let parts: Vec<Node> = n.named_children(&mut c).collect();
        let [key, value] = parts.as_slice() else {
            return false;
        };
        let key = text_of(*key, src).trim_matches(['\'', '"']);
        return match key {
            "verify_peer" | "verify_peer_name" | "verify" => is_off(*value, src),
            "allow_self_signed" => text_of(*value, src).eq_ignore_ascii_case("true"),
            _ => false,
        };
    }
    if !function_name(n, src).is_some_and(|f| f == "curl_setopt") {
        return false;
    }
    let args = arguments(n);
    let option = args.get(1).map_or("", |a| text_of(*a, src));
    matches!(option, "CURLOPT_SSL_VERIFYPEER" | "CURLOPT_SSL_VERIFYHOST")
        && args.get(2).is_some_and(|v| is_off(*v, src))
}

/// The literal a credential's name is bound to.
fn hardcoded_credential<'t>(n: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let (name, value) = match n.kind() {
        "assignment_expression" => (
            assigned_name(n.child_by_field_name("left")?, src)?,
            n.child_by_field_name("right")?,
        ),
        "array_element_initializer" => {
            let mut c = n.walk();
            let parts: Vec<Node> = n.named_children(&mut c).collect();
            let [key, value] = parts.as_slice() else {
                return None;
            };
            (
                text_of(*key, src).trim_matches(['\'', '"']).to_string(),
                *value,
            )
        }
        "const_element" => {
            let mut c = n.walk();
            let parts: Vec<Node> = n.named_children(&mut c).collect();
            let [key, value] = parts.as_slice() else {
                return None;
            };
            (text_of(*key, src).to_string(), *value)
        }
        _ => {
            // `define('DB_PASSWORD', 'secret')`
            if !function_name(n, src).is_some_and(|f| f == "define") {
                return None;
            }
            let args = arguments(n);
            (
                text_of(*args.first()?, src)
                    .trim_matches(['\'', '"'])
                    .to_string(),
                *args.get(1)?,
            )
        }
    };
    (is_credential_name(&name) && is_credential_value(value, src)).then_some(value)
}

/// The name an assignment assigns to: `$password`, `$this->password`.
fn assigned_name(left: Node, src: &[u8]) -> Option<String> {
    match left.kind() {
        "variable_name" => Some(text_of(left, src).trim_start_matches('$').to_string()),
        "member_access_expression" => left
            .child_by_field_name("name")
            .map(|n| text_of(n, src).to_string()),
        "subscript_expression" => {
            let mut c = left.walk();
            left.named_children(&mut c)
                .nth(1)
                .map(|k| text_of(k, src).trim_matches(['\'', '"']).to_string())
        }
        _ => None,
    }
}

/// A string that could be the credential itself: not empty, not a template
/// or a sentence, and not interpolating anything.
fn is_credential_value(v: Node, src: &[u8]) -> bool {
    if !matches!(v.kind(), "string" | "encapsed_string") {
        return false;
    }
    let mut interpolates = false;
    visit(v, &mut |c| interpolates |= c.kind() == "variable_name");
    !interpolates && looks_like_a_secret(text_of(v, src).trim_matches(['\'', '"']))
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
    let name = function_name(call, src)?;
    if !matches!(name.as_str(), "chmod" | "mkdir") {
        return None;
    }
    let mode = *arguments(call).get(1)?;
    (octal_mode(mode, src)? & 0o002 != 0).then_some(mode)
}

fn imports_request_variables(call: Node, src: &[u8]) -> bool {
    let Some(name) = function_name(call, src) else {
        return false;
    };
    let args = arguments(call);
    match name.as_str() {
        "extract" => args.first().is_some_and(|a| mentions_request(*a, src)),
        "parse_str" => args.len() == 1,
        "import_request_variables" => true,
        _ => false,
    }
}

fn prints_the_configuration(call: Node, src: &[u8]) -> bool {
    function_name(call, src).is_some_and(|f| matches!(f.as_str(), "phpinfo" | "phpcredits"))
}

fn is_libxml_noent(n: Node, src: &[u8]) -> bool {
    text_of(n, src) == "LIBXML_NOENT"
}

#[cfg(test)]
mod tests {
    use crate::analysis::tests::flagged_php as flagged;

    #[test]
    fn a_query_is_built_only_from_text_and_values_that_arent_made_safe() {
        let src = "function f($db, $id, $name) {\n    mysqli_query($db, \"SELECT * FROM t WHERE id = $id\");\n    mysqli_query($db, 'SELECT * FROM t WHERE id = ' . intval($id));\n    mysqli_query($db, \"SELECT * FROM t WHERE n = '\" . mysqli_real_escape_string($db, $name) . \"'\");\n    $db->query('SELECT * FROM t WHERE n = ' . $name);\n    $db->query('SELECT 1');\n    $db->query('DELETE FROM t WHERE id = ?', [$id]);\n    $x = 'hello ' . $name;\n}\n";
        assert_eq!(flagged("php/sql-concatenation", src), [2, 5]);
    }

    #[test]
    fn a_command_is_built_unless_its_value_is_escaped() {
        let src = "function f($host) {\n    shell_exec('ping ' . $host);\n    shell_exec('ping ' . escapeshellarg($host));\n    system('uptime');\n    $x = `ls $host`;\n    $y = `ls`;\n}\n";
        assert_eq!(flagged("php/command-execution", src), [2, 5]);
    }

    #[test]
    fn a_function_is_matched_whatever_its_case_and_namespace() {
        let src = "function f($s) {\n    MD5($s);\n    \\sha1($s);\n    hash('sha256', $s);\n    hash('MD5', $s);\n    md5_hash($s);\n}\n";
        assert_eq!(flagged("php/weak-hash", src), [2, 3, 5]);
    }

    #[test]
    fn what_looks_like_a_credential_is_one_only_with_a_value_that_could_be() {
        let src = "function f() {\n    $dbPassword = 'hunter2-prod';\n    $passwordEnv = 'DB_PASSWORD';\n    $password = '';\n    $secret = \"%s\";\n    $pwd = $_POST['pwd'];\n    $cfg = ['password' => 's3cr3t-value', 'user' => 'admin'];\n    define('API_SECRET', 'abcd-1234');\n}\n";
        assert_eq!(flagged("php/hardcoded-credentials", src), [2, 7, 8]);
    }

    #[test]
    fn a_property_is_not_a_clients_value_and_a_placeholder_is_not_a_secret() {
        let setting = "function g() {\n    $a = ['password' => 'FTP_PASS', 'api_key' => 'apiKey'];\n    $pwd = 'Pass1234!';\n}\n";
        assert_eq!(flagged("php/hardcoded-credentials", setting), [3]);
        let src = "function f($wpdb, $id) {\n    $wpdb->query(\"UPDATE $wpdb->posts SET a = 1\");\n    $wpdb->get_results($wpdb->prepare(\"SELECT * FROM {$this->table} WHERE id = %d\", $id));\n    $wpdb->query(\"DELETE FROM t WHERE id = $id\");\n    $pwd = 'password_here';\n    $secret = '*****';\n    $password_value = 'xxxx-xxxx';\n    $apiSecret = 'k3y-9f2a-77ab';\n}\n";
        assert_eq!(flagged("php/sql-concatenation", src), [4]);
        assert_eq!(flagged("php/hardcoded-credentials", src), [8]);
    }

    #[test]
    fn only_a_mode_anyone_can_write_is_flagged() {
        let src = "function f($p) {\n    chmod($p, 0755);\n    chmod($p, 0777);\n    mkdir($p, 0666, true);\n    mkdir($p, 0750);\n}\n";
        assert_eq!(flagged("php/permissive-file-mode", src), [3, 4]);
    }

    #[test]
    fn a_secret_is_weak_only_when_a_predictable_generator_makes_it() {
        let src = "function f() {\n    $token = md5(uniqid(mt_rand()));\n    $token = bin2hex(random_bytes(16));\n    $count = rand(1, 6);\n    $salt = str_shuffle('abc');\n}\n";
        assert_eq!(flagged("php/weak-random", src), [2, 5]);
    }

    #[test]
    fn verification_is_off_only_when_it_is_set_off() {
        let src = "function f($ch) {\n    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);\n    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);\n    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);\n    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);\n    $o = ['verify' => false, 'timeout' => 3];\n}\n";
        assert_eq!(flagged("php/tls-unverified", src), [2, 4, 6]);
    }

    #[test]
    fn unserialize_and_extract_and_parse_str() {
        let src = "function f($d, $q) {\n    unserialize($d);\n    unserialize($d, ['allowed_classes' => false]);\n    unserialize('a:0:{}');\n    extract($_POST);\n    extract($local);\n    parse_str($q);\n    parse_str($q, $out);\n}\n";
        assert_eq!(flagged("php/unserialize", src), [2]);
        assert_eq!(flagged("php/extract-request", src), [5, 7]);
    }
}
