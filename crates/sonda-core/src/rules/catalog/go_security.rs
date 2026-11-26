//! Go security rules (ADR-0031): what the file's own text shows, with no
//! types and no flow. A call is matched by the package its operand was
//! imported from (`md5.New` is `crypto/md5`'s only if the file imports it
//! under that name), so a local variable that happens to be called `md5`
//! isn't one.

use super::go::{call_arguments, package_call, text_of, visit};
use super::is_credential_name;
use super::prelude::*;
use crate::lang::GO;

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "go/hardcoded-credentials",
        name: "Credentials should not be hard-coded",
        description: "A password, secret or key in the source is in every clone, build and log of it, and \
                      can't be rotated without a release. Read it from the environment or a secret store.",
        message: "Remove this hard-coded credential.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Query {
            langs: GO,
            query: "[(assignment_statement left: (expression_list) right: (expression_list)) \
                     (short_var_declaration left: (expression_list) right: (expression_list)) \
                     (var_spec name: (identifier) value: (expression_list)) \
                     (const_spec name: (identifier) value: (expression_list)) \
                     (keyed_element)] @match",
            filter: Some(Find(hardcoded_credential)),
        },
        example: Some(Example {
            lang: Lang::Go,
            bad: "package p\n\nfunc f() string {\n\tdbPassword := \"hunter2-prod\"\n\treturn dbPassword\n}\n",
            good: "package p\n\nimport \"os\"\n\nfunc f() string {\n\tdbPassword := os.Getenv(\"DB_PASSWORD\")\n\treturn dbPassword\n}\n",
        }),
    },
    Rule {
        id: "go/weak-hash",
        name: "Weak hashes should not be used",
        description: "MD5 and SHA-1 collide, so a signature, certificate or password hash built on them can be \
                      forged. Use SHA-256 or better, and bcrypt, scrypt or argon2 for passwords.",
        message: "Use a stronger hash than MD5 or SHA-1.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 20,
        sonar: &[],
        check: Check::Query {
            langs: GO,
            query: "(call_expression function: (selector_expression operand: (identifier) @p field: (field_identifier) @f) (#any-of? @p \"md5\" \"sha1\") (#any-of? @f \"New\" \"Sum\")) @match",
            filter: Some(Keep(uses_weak_hash)),
        },
        example: Some(Example {
            lang: Lang::Go,
            bad: "package p\n\nimport \"crypto/md5\"\n\nfunc f(b []byte) [16]byte {\n\treturn md5.Sum(b)\n}\n",
            good: "package p\n\nimport \"crypto/sha256\"\n\nfunc f(b []byte) [32]byte {\n\treturn sha256.Sum256(b)\n}\n",
        }),
    },
    Rule {
        id: "go/weak-cipher",
        name: "Weak ciphers should not be used",
        description: "DES, 3DES and RC4 are broken or too small for today's attacks. Use AES with GCM, or \
                      ChaCha20-Poly1305.",
        message: "Use a modern cipher, such as AES-GCM.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Query {
            langs: GO,
            query: "(call_expression function: (selector_expression operand: (identifier) @p field: (field_identifier) @f) (#any-of? @p \"des\" \"rc4\") (#any-of? @f \"NewCipher\" \"NewTripleDESCipher\")) @match",
            filter: Some(Keep(uses_weak_cipher)),
        },
        example: Some(Example {
            lang: Lang::Go,
            bad: "package p\n\nimport \"crypto/rc4\"\n\nfunc f(key []byte) {\n\t_, _ = rc4.NewCipher(key)\n}\n",
            good: "package p\n\nimport \"crypto/aes\"\n\nfunc f(key []byte) {\n\t_, _ = aes.NewCipher(key)\n}\n",
        }),
    },
    Rule {
        id: "go/tls-unverified",
        name: "TLS certificates should be verified",
        description: "`InsecureSkipVerify` turns off the check that the server is who it says, so anyone on \
                      the path can read and change the traffic.",
        message: "Don't turn off certificate verification.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 20,
        sonar: &[],
        check: Check::Query {
            langs: GO,
            query: "[(keyed_element) (assignment_statement)] @match",
            filter: Some(Keep(skips_verification)),
        },
        example: Some(Example {
            lang: Lang::Go,
            bad: "package p\n\nimport \"crypto/tls\"\n\nvar c = &tls.Config{InsecureSkipVerify: true}\n",
            good: "package p\n\nimport \"crypto/tls\"\n\nvar c = &tls.Config{MinVersion: tls.VersionTLS12}\n",
        }),
    },
    Rule {
        id: "go/weak-tls",
        name: "TLS versions before 1.2 should not be allowed",
        description: "SSL 3.0 and TLS 1.0 and 1.1 have known attacks, and every browser dropped them.",
        message: "Require TLS 1.2 or later.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[],
        check: Check::Query {
            langs: GO,
            query: "[(keyed_element) (assignment_statement)] @match",
            filter: Some(Keep(allows_old_tls)),
        },
        example: Some(Example {
            lang: Lang::Go,
            bad: "package p\n\nimport \"crypto/tls\"\n\nvar c = &tls.Config{MinVersion: tls.VersionTLS10}\n",
            good: "package p\n\nimport \"crypto/tls\"\n\nvar c = &tls.Config{MinVersion: tls.VersionTLS12}\n",
        }),
    },
    Rule {
        id: "go/sql-concatenation",
        name: "SQL queries should not be built from strings",
        description: "A query assembled with `+` or `fmt.Sprintf` from a value the program doesn't control \
                      lets that value change the query. Pass values as arguments (`?` or `$1`) instead.",
        message: "Pass these values as query arguments, not in the text.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Query {
            langs: GO,
            query: "(call_expression function: (selector_expression field: (field_identifier) @f) (#any-of? @f \"Query\" \"QueryRow\" \"Exec\" \"Prepare\" \"Get\" \"Select\" \"NamedQuery\" \"NamedExec\" \"MustExec\" \"QueryContext\" \"QueryRowContext\" \"ExecContext\" \"PrepareContext\" \"GetContext\" \"SelectContext\" \"NamedQueryContext\" \"NamedExecContext\")) @match",
            filter: Some(Find(built_query)),
        },
        example: Some(Example {
            lang: Lang::Go,
            bad: "package p\n\nimport \"database/sql\"\n\nfunc f(db *sql.DB, id string) {\n\tdb.Query(\"SELECT * FROM users WHERE id = '\" + id + \"'\")\n}\n",
            good: "package p\n\nimport \"database/sql\"\n\nfunc f(db *sql.DB, id string) {\n\tdb.Query(\"SELECT * FROM users WHERE id = ?\", id)\n}\n",
        }),
    },
    Rule {
        id: "go/shell-command",
        name: "Shell commands should not be built from values",
        description: "`exec.Command(\"sh\", \"-c\", cmd)` runs `cmd` through a shell, so any part of it that \
                      isn't fixed can add commands. Run the program directly, with its arguments separate.",
        message: "Don't pass a computed string to a shell; run the program with its arguments.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Query {
            langs: GO,
            query: "(call_expression function: (selector_expression operand: (identifier) @p field: (field_identifier) @f) (#any-of? @p \"exec\") (#any-of? @f \"Command\" \"CommandContext\")) @match",
            filter: Some(Find(shell_script)),
        },
        example: Some(Example {
            lang: Lang::Go,
            bad: "package p\n\nimport \"os/exec\"\n\nfunc f(host string) {\n\texec.Command(\"sh\", \"-c\", \"ping \"+host).Run()\n}\n",
            good: "package p\n\nimport \"os/exec\"\n\nfunc f(host string) {\n\texec.Command(\"ping\", \"-c\", \"1\", host).Run()\n}\n",
        }),
    },
    Rule {
        id: "go/permissive-file-mode",
        name: "Files and directories should not be writable by everyone",
        description: "A mode with the world-write bit (`0777`, `0666`) lets any user on the machine change \
                      the file or put files in the directory.",
        message: "Remove write permission for others from this mode.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 10,
        sonar: &[],
        check: Check::Query {
            langs: GO,
            query: "(call_expression function: (selector_expression operand: (identifier) @p field: (field_identifier) @f) (#any-of? @p \"os\" \"ioutil\") (#any-of? @f \"Chmod\" \"Mkdir\" \"MkdirAll\" \"OpenFile\" \"WriteFile\")) @match",
            filter: Some(Find(world_writable_mode)),
        },
        example: Some(Example {
            lang: Lang::Go,
            bad: "package p\n\nimport \"os\"\n\nfunc f() error {\n\treturn os.MkdirAll(\"/tmp/app\", 0777)\n}\n",
            good: "package p\n\nimport \"os\"\n\nfunc f() error {\n\treturn os.MkdirAll(\"/tmp/app\", 0750)\n}\n",
        }),
    },
    Rule {
        id: "go/ssh-insecure-host-key",
        name: "SSH host keys should be verified",
        description: "`ssh.InsecureIgnoreHostKey()` accepts any server, so anyone on the path can pose as the \
                      host. Check the key against `known_hosts` or a pinned one.",
        message: "Verify the host key instead of ignoring it.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 20,
        sonar: &[],
        check: Check::Query {
            langs: GO,
            query: "(call_expression function: (selector_expression operand: (identifier) @p field: (field_identifier) @f) (#any-of? @p \"ssh\") (#any-of? @f \"InsecureIgnoreHostKey\")) @match",
            filter: Some(Keep(ignores_host_key)),
        },
        example: Some(Example {
            lang: Lang::Go,
            bad: "package p\n\nimport \"golang.org/x/crypto/ssh\"\n\nvar c = &ssh.ClientConfig{HostKeyCallback: ssh.InsecureIgnoreHostKey()}\n",
            good: "package p\n\nimport \"golang.org/x/crypto/ssh\"\n\nfunc f(cb ssh.HostKeyCallback) *ssh.ClientConfig {\n\treturn &ssh.ClientConfig{HostKeyCallback: cb}\n}\n",
        }),
    },
];

// ---------------------------------------------------------------- filters

/// A string literal that could be the credential itself: not empty, not a
/// template (`%s`, `{{.X}}`, `${X}`), not a sentence.
fn is_credential_value(v: Node, src: &[u8]) -> bool {
    let target = if v.kind() == "literal_element" {
        match v.named_child(0) {
            Some(inner) => inner,
            None => return false,
        }
    } else {
        v
    };
    if !matches!(
        target.kind(),
        "interpreted_string_literal" | "raw_string_literal"
    ) {
        return false;
    }
    let t = text_of(target, src).trim_matches(['"', '`']);
    t.len() >= 4
        && !t.contains(char::is_whitespace)
        && !t.contains(['%', '{', '$', '<'])
        && !t.eq_ignore_ascii_case("password")
}

/// The name an expression assigns to: a variable, a field (`cfg.Password`).
fn assigned_name<'a>(n: Node, src: &'a [u8]) -> Option<&'a str> {
    match n.kind() {
        "identifier" | "field_identifier" => Some(text_of(n, src)),
        "selector_expression" => n.child_by_field_name("field").map(|f| text_of(f, src)),
        "literal_element" => n.named_child(0).and_then(|x| assigned_name(x, src)),
        _ => None,
    }
}

fn named_children<'t>(n: Node<'t>) -> Vec<Node<'t>> {
    let mut c = n.walk();
    n.named_children(&mut c).collect()
}

/// The string literal a credential's name is bound to.
fn hardcoded_credential<'t>(n: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let pairs: Vec<(Node, Node)> = match n.kind() {
        "keyed_element" => {
            let kids = named_children(n);
            vec![(*kids.first()?, *kids.get(1)?)]
        }
        "var_spec" | "const_spec" => {
            let mut c = n.walk();
            let names: Vec<Node> = n.children_by_field_name("name", &mut c).collect();
            let values = named_children(n.child_by_field_name("value")?);
            names.into_iter().zip(values).collect()
        }
        _ => {
            let left = named_children(n.child_by_field_name("left")?);
            let right = named_children(n.child_by_field_name("right")?);
            left.into_iter().zip(right).collect()
        }
    };
    pairs.into_iter().find_map(|(name, value)| {
        (assigned_name(name, src).is_some_and(is_credential_name)
            && is_credential_value(value, src))
        .then_some(value)
    })
}

fn is_call_of(call: Node, src: &[u8], path: &str, funcs: &[&str]) -> bool {
    package_call(call, src, path).is_some_and(|f| funcs.contains(&f))
}

fn uses_weak_hash(call: Node, src: &[u8]) -> bool {
    is_call_of(call, src, "crypto/md5", &["New", "Sum"])
        || is_call_of(call, src, "crypto/sha1", &["New", "Sum"])
}

fn uses_weak_cipher(call: Node, src: &[u8]) -> bool {
    is_call_of(
        call,
        src,
        "crypto/des",
        &["NewCipher", "NewTripleDESCipher"],
    ) || is_call_of(call, src, "crypto/rc4", &["NewCipher"])
}

fn ignores_host_key(call: Node, src: &[u8]) -> bool {
    is_call_of(
        call,
        src,
        "golang.org/x/crypto/ssh",
        &["InsecureIgnoreHostKey"],
    )
}

/// `name` and its value, for a keyed element or an assignment of a field.
fn setting<'a, 't>(n: Node<'t>, src: &'a [u8]) -> Option<(&'a str, Node<'t>)> {
    match n.kind() {
        "keyed_element" => {
            let kids = named_children(n);
            let name = assigned_name(*kids.first()?, src)?;
            Some((name, *kids.get(1)?))
        }
        "assignment_statement" => {
            let left = named_children(n.child_by_field_name("left")?);
            let right = named_children(n.child_by_field_name("right")?);
            let (l, r) = (left.first()?, right.first()?);
            (l.kind() == "selector_expression").then_some(())?;
            Some((assigned_name(*l, src)?, *r))
        }
        _ => None,
    }
}

fn skips_verification(n: Node, src: &[u8]) -> bool {
    setting(n, src).is_some_and(|(name, value)| {
        name == "InsecureSkipVerify" && text_of(value, src).trim() == "true"
    })
}

fn allows_old_tls(n: Node, src: &[u8]) -> bool {
    setting(n, src).is_some_and(|(name, value)| {
        name == "MinVersion"
            && matches!(
                text_of(value, src).trim(),
                "tls.VersionTLS10" | "tls.VersionTLS11" | "tls.VersionSSL30"
            )
    })
}

/// Query methods of `database/sql` and the libraries over it, and the
/// position of the query text: after a context for the `...Context` ones.
fn query_position(method: &str) -> Option<usize> {
    match method {
        "Query" | "QueryRow" | "Exec" | "Prepare" | "Get" | "Select" | "NamedQuery"
        | "NamedExec" | "MustExec" => Some(0),
        "QueryContext" | "QueryRowContext" | "ExecContext" | "PrepareContext" | "GetContext"
        | "SelectContext" | "NamedQueryContext" | "NamedExecContext" => Some(1),
        _ => None,
    }
}

const SQL_WORDS: &[&str] = &[
    "select ", "insert ", "update ", "delete ", "where ", " from ",
];

fn reads_as_sql(literal: &str) -> bool {
    let lower = literal.to_ascii_lowercase();
    SQL_WORDS.iter().any(|w| lower.contains(w))
}

/// The query argument, if it's text joined with a value: `"..." + v`, or a
/// `fmt.Sprintf` whose format has a verb.
fn built_query<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let f = call.child_by_field_name("function")?;
    let method = text_of(f.child_by_field_name("field")?, src);
    let at = query_position(method)?;
    let arg = *call_arguments(call).get(at)?;
    let mut literal = String::new();
    let mut joined_with_value = false;
    match arg.kind() {
        "binary_expression" => {
            visit(arg, &mut |n| match n.kind() {
                "interpreted_string_literal" | "raw_string_literal" => {
                    literal.push_str(text_of(n, src));
                }
                "identifier" | "selector_expression" | "call_expression" | "index_expression" => {
                    joined_with_value = true;
                }
                _ => {}
            });
        }
        "call_expression" if package_call(arg, src, "fmt") == Some("Sprintf") => {
            let format = *call_arguments(arg).first()?;
            literal.push_str(text_of(format, src));
            joined_with_value = call_arguments(arg).len() > 1 && literal.contains('%');
        }
        _ => return None,
    }
    (joined_with_value && reads_as_sql(&literal)).then_some(arg)
}

const SHELLS: &[&str] = &[
    "sh",
    "bash",
    "/bin/sh",
    "/bin/bash",
    "zsh",
    "cmd",
    "powershell",
];
const SHELL_FLAGS: &[&str] = &["-c", "/c", "-Command", "-command"];

fn is_literal(n: Node) -> bool {
    matches!(
        n.kind(),
        "interpreted_string_literal" | "raw_string_literal"
    )
}

/// The script argument of `exec.Command("sh", "-c", script)`, when it isn't
/// a fixed string.
fn shell_script<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let name = package_call(call, src, "os/exec")?;
    let args = call_arguments(call);
    let args = match name {
        "Command" => &args[..],
        "CommandContext" => args.get(1..)?,
        _ => return None,
    };
    let unquoted = |n: &Node| text_of(*n, src).trim_matches(['"', '`']).to_string();
    let shell = args.first().filter(|a| is_literal(**a))?;
    let flag = args.get(1).filter(|a| is_literal(**a))?;
    let script = args.get(2)?;
    (SHELLS.contains(&unquoted(shell).as_str())
        && SHELL_FLAGS.contains(&unquoted(flag).as_str())
        && !is_literal(*script))
    .then_some(*script)
}

/// A mode written as an octal literal: `0777`, `0o666`.
fn octal_mode(n: Node, src: &[u8]) -> Option<u32> {
    let mut target = n;
    // `os.FileMode(0777)`
    if target.kind() == "call_expression" {
        target = *call_arguments(target).first()?;
    }
    if target.kind() != "int_literal" {
        return None;
    }
    let t = text_of(target, src).replace('_', "");
    let digits = t
        .strip_prefix("0o")
        .or_else(|| t.strip_prefix("0O"))
        .or_else(|| t.strip_prefix('0'))?;
    u32::from_str_radix(digits, 8).ok()
}

/// The mode of a call that creates or changes a file, when anyone can write
/// to the result.
fn world_writable_mode<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    // Where the mode is: after the path, or after the path and the flags.
    let at = match (
        package_call(call, src, "os"),
        package_call(call, src, "io/ioutil"),
    ) {
        (Some("Chmod" | "Mkdir" | "MkdirAll"), _) => 1,
        (Some("OpenFile" | "WriteFile"), _) | (_, Some("WriteFile")) => 2,
        _ => return None,
    };
    let mode = *call_arguments(call).get(at)?;
    (octal_mode(mode, src)? & 0o002 != 0).then_some(mode)
}
