//! Python security rules (ADR-0007, batch 4). Queries stay cheap on deep trees:
//! see the notes in `js_modern.rs`.

use super::*;

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "py/sql-built-dynamically",
        name: "SQL queries should not be built from strings",
        description: "Formatting values into a query lets an attacker change what it does; pass them as parameters.",
        message: "Use a parameterized query instead of formatting this string.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 15,
        sonar: &[related("S2077")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute attribute: (identifier) @m (#any-of? @m "execute" "executemany" "executescript" "raw")) arguments: (argument_list . (_) @a)) @match"#,
            filter: Some(Keep(sql_built_dynamically)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "cursor.execute(\"SELECT * FROM t WHERE id = %s\" % user_id)\n",
            good: "cursor.execute(\"SELECT * FROM t WHERE id = %s\", (user_id,))\n",
        }),
    },
    Rule {
        id: "py/cookie-not-secure",
        name: "Cookies should have the secure flag",
        description: "Without `secure`, the cookie is also sent over plain HTTP.",
        message: "Set the secure flag.",
        category: Vulnerability,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S2092")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(keyword_argument name: (identifier) @n (#eq? @n "secure") value: (false)) @match
(assignment left: (identifier) @l (#any-of? @l "SESSION_COOKIE_SECURE" "CSRF_COOKIE_SECURE") right: (false)) @match"#,
            filter: Some(Keep(is_cookie_setting)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "response.set_cookie('sid', sid, secure=False)\n",
            good: "response.set_cookie('sid', sid, secure=True)\n",
        }),
    },
    Rule {
        id: "py/cookie-not-httponly",
        name: "Cookies should have the HttpOnly flag",
        description: "Without HttpOnly, scripts on the page can read the cookie.",
        message: "Set the httponly flag.",
        category: Vulnerability,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S3330")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(keyword_argument name: (identifier) @n (#eq? @n "httponly") value: (false)) @match
(assignment left: (identifier) @l (#any-of? @l "SESSION_COOKIE_HTTPONLY" "CSRF_COOKIE_HTTPONLY") right: (false)) @match"#,
            filter: Some(Keep(is_cookie_setting)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "response.set_cookie('sid', sid, httponly=False)\n",
            good: "response.set_cookie('sid', sid, httponly=True)\n",
        }),
    },
    Rule {
        id: "py/tls-unverified",
        name: "Server certificates should be verified",
        description: "Turning verification off lets anyone on the network pose as the server.",
        message: "Remove 'verify=False' and trust the right CA instead.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S4830")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(keyword_argument name: (identifier) @n (#eq? @n "verify") value: (false)) @match
(attribute object: (identifier) @o attribute: (identifier) @a (#eq? @o "ssl") (#any-of? @a "CERT_NONE" "_create_unverified_context")) @match"#,
            filter: Some(Keep(is_not_jwt_decode)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "requests.get(url, verify=False)\n",
            good: "requests.get(url)\n",
        }),
    },
    Rule {
        id: "py/hostname-unverified",
        name: "Server hostnames should be verified",
        description: "Without a hostname check, a valid certificate for any other site is accepted.",
        message: "Keep check_hostname enabled.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S5527")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(assignment left: (attribute attribute: (identifier) @a (#eq? @a "check_hostname")) right: (false)) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "ctx.check_hostname = False\n",
            good: "ctx.check_hostname = True\n",
        }),
    },
    Rule {
        id: "py/cleartext-url",
        name: "Clear-text protocols should not be used",
        description: "http, ftp and telnet send data, including credentials, unencrypted. Loopback and private addresses are not reported.",
        message: "Use the encrypted version of this protocol.",
        category: Vulnerability,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[related("S5332")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"((string) @match (#match? @match "^[rbuRBU]*['\"]+(http|ftp|telnet)://"))"#,
            filter: Some(Keep(is_public_cleartext_url)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "api = 'http://api.example-shop.io/v1'\n",
            good: "api = 'https://api.example-shop.io/v1'\nlocal = 'http://localhost:8000'\n",
        }),
    },
    Rule {
        id: "py/random-secret",
        name: "Pseudorandom generators should not produce secrets",
        description: "random is predictable; tokens and passwords built from it can be guessed. Use the secrets module.",
        message: "Use the secrets module for this value.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 10,
        sonar: &[related("S2245")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @a (#eq? @o "random") (#any-of? @a "random" "randint" "choice" "choices" "randrange" "getrandbits" "sample"))) @match"#,
            filter: Some(Keep(random_feeds_a_secret)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "session_token = random.randint(0, 10**9)\n",
            good: "session_token = secrets.token_hex(16)\njitter = random.random()\n",
        }),
    },
    Rule {
        id: "py/weak-hash",
        name: "Weak hashing algorithms should not be used",
        description: "MD5 and SHA-1 have known collisions and are unsuitable for security purposes.",
        message: "Use SHA-256 or stronger.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S4790")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @a (#eq? @o "hashlib") (#any-of? @a "md5" "sha1" "new"))) @match"#,
            filter: Some(Keep(weak_hash_call)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "h = hashlib.md5(data)\n",
            good: "h = hashlib.sha256(data)\n",
        }),
    },
    Rule {
        id: "py/weak-cipher",
        name: "Cipher algorithms should be robust",
        description: "DES, RC2, RC4, Blowfish and similar ciphers are broken or have small blocks.",
        message: "Use AES.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 15,
        sonar: &[related("S5547")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @a (#eq? @a "new") (#any-of? @o "DES" "DES3" "ARC2" "ARC4" "Blowfish" "XOR"))) @match
(call function: (attribute object: (identifier) @o2 attribute: (identifier) @a2 (#eq? @o2 "algorithms") (#any-of? @a2 "TripleDES" "ARC4" "Blowfish" "CAST5" "IDEA" "SEED"))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "cipher = DES.new(key, DES.MODE_ECB)\n",
            good: "cipher = AES.new(key, AES.MODE_GCM)\n",
        }),
    },
    Rule {
        id: "py/xxe",
        name: "XML parsers should not be vulnerable to XXE attacks",
        description: "Resolving external entities lets a crafted document read local files or reach internal hosts.",
        message: "Disable entity resolution.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 10,
        sonar: &[exact("S2755")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(keyword_argument name: (identifier) @n (#eq? @n "resolve_entities") value: (true)) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "parser = etree.XMLParser(resolve_entities=True)\n",
            good: "parser = etree.XMLParser(resolve_entities=False)\n",
        }),
    },
    Rule {
        id: "py/world-permissions",
        name: "File permissions should not be world-accessible",
        description: "Mode bits for 'other' let every user on the machine read or change the file.",
        message: "Remove the permissions for others.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2612")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute attribute: (identifier) @a (#any-of? @a "chmod" "fchmod" "lchmod"))) @match"#,
            filter: Some(Keep(grants_permissions_to_others)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "os.chmod(path, 0o777)\n",
            good: "os.chmod(path, 0o600)\n",
        }),
    },
    Rule {
        id: "py/public-tmp",
        name: "Temporary files should not be created in publicly writable directories",
        description: "Other users can pre-create or swap files in /tmp, so a predictable path can be hijacked.",
        message: "Use tempfile to create the file.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5443")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"((string) @match (#match? @match "^[rbuRBU]*['\"]+/(tmp|var/tmp|dev/shm)(/|['\"])"))"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "path = '/tmp/report.csv'\n",
            good: "path = tempfile.mkstemp(suffix='.csv')[1]\n",
        }),
    },
    Rule {
        id: "py/mktemp",
        name: "Insecure temporary file creation methods should not be used",
        description: "tempfile.mktemp returns a name without creating the file, which leaves a window for an attacker.",
        message: "Use tempfile.mkstemp or NamedTemporaryFile.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5445")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @a (#eq? @o "tempfile") (#eq? @a "mktemp"))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "name = tempfile.mktemp()\n",
            good: "fd, name = tempfile.mkstemp()\n",
        }),
    },
    Rule {
        id: "py/weak-tls-version",
        name: "Weak SSL/TLS protocols should not be used",
        description: "SSLv2, SSLv3, TLS 1.0 and TLS 1.1 have known attacks.",
        message: "Require TLS 1.2 or later.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S4423")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(attribute object: (identifier) @o attribute: (identifier) @a (#eq? @o "ssl") (#match? @a "^(PROTOCOL_SSLv2|PROTOCOL_SSLv3|PROTOCOL_SSLv23|PROTOCOL_TLSv1|PROTOCOL_TLSv1_1)$")) @match
(attribute object: (attribute attribute: (identifier) @t (#eq? @t "TLSVersion")) attribute: (identifier) @a2 (#match? @a2 "^(SSLv3|TLSv1|TLSv1_1)$")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)\n",
            good: "ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n",
        }),
    },
    Rule {
        id: "py/weak-key-size",
        name: "Cryptographic keys should be generated with strong parameters",
        description: "RSA and DSA keys under 2048 bits can be factored with modest resources.",
        message: "Use at least 2048 bits.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S4426")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute attribute: (identifier) @a (#any-of? @a "generate" "generate_private_key"))) @match"#,
            filter: Some(Keep(key_size_below_2048)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "key = RSA.generate(1024)\n",
            good: "key = RSA.generate(3072)\n",
        }),
    },
    Rule {
        id: "py/jwt-unverified",
        name: "JWTs should be signed and verified",
        description: "Decoding without verification accepts tokens anyone could have forged.",
        message: "Verify the signature.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 10,
        sonar: &[exact("S5659")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(keyword_argument name: (identifier) @n (#eq? @n "verify") value: (false)) @match
(pair key: (string) @k value: (false)) @match"#,
            filter: Some(Keep(disables_jwt_verification)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "claims = jwt.decode(token, key, verify=False)\n",
            good: "claims = jwt.decode(token, key, algorithms=['HS256'])\n",
        }),
    },
    Rule {
        id: "py/autoescape-disabled",
        name: "Auto-escaping in HTML template engines should not be disabled",
        description: "Without auto-escaping, any variable rendered into a page can inject script.",
        message: "Keep autoescape enabled.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5247")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(keyword_argument name: (identifier) @n (#eq? @n "autoescape") value: (false)) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "env = Environment(autoescape=False)\n",
            good: "env = Environment(autoescape=True)\n",
        }),
    },
    Rule {
        id: "py/csrf-disabled",
        name: "CSRF protections should not be disabled",
        description: "Exempting a view, or turning the check off, lets other sites make requests as the signed-in user.",
        message: "Keep CSRF protection enabled.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[related("S4502")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(decorator (identifier) @d (#eq? @d "csrf_exempt")) @match
(decorator (attribute attribute: (identifier) @d2 (#eq? @d2 "csrf_exempt"))) @match
(assignment left: (identifier) @l (#eq? @l "WTF_CSRF_ENABLED") right: (false)) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "@csrf_exempt\ndef pay(request):\n    pass\n",
            good: "def pay(request):\n    pass\n",
        }),
    },
    Rule {
        id: "py/debug-enabled",
        name: "Debugging features should not be enabled in production",
        description: "Debug mode exposes stack traces and, in Flask, an interactive console.",
        message: "Don't enable debug mode in code that ships.",
        category: Vulnerability,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[related("S4507")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(keyword_argument name: (identifier) @n (#eq? @n "debug") value: (true)) @match
(assignment left: (identifier) @l (#eq? @l "DEBUG") right: (true)) @match"#,
            filter: Some(Keep(is_debug_setting)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "app.run(debug=True)\n",
            good: "app.run()\n",
        }),
    },
    Rule {
        id: "py/cors-any-origin",
        name: "CORS policies should be restricted to trusted origins",
        description: "Allowing every origin lets any site read the responses on behalf of a signed-in user.",
        message: "List the origins that need access.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 10,
        sonar: &[related("S5122")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(keyword_argument name: (identifier) @n (#any-of? @n "origins" "allow_origins" "allow_origin" "supports_credentials_origin") value: [(string) (list)] @v) @match
(assignment left: (identifier) @l (#any-of? @l "CORS_ORIGIN_ALLOW_ALL" "CORS_ALLOW_ALL_ORIGINS") right: (true)) @match"#,
            filter: Some(Keep(allows_every_origin)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "CORS(app, origins='*')\n",
            good: "CORS(app, origins=['https://app.example.com'])\n",
        }),
    },
    Rule {
        id: "py/hardcoded-credential",
        name: "Credentials should not be hard-coded",
        description: "A password or key in source is visible to everyone with the code and stays in its history.",
        message: "Read this credential from the environment or a secret store.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 15,
        sonar: &[related("S6437")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(assignment left: [(identifier) (attribute)] @l right: (string) @r) @match
(keyword_argument name: (identifier) @n value: (string) @r2) @match"#,
            filter: Some(Keep(is_hardcoded_credential)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "password = 'Tr0ub4dor&3'\n",
            good: "password = os.environ['DB_PASSWORD']\n",
        }),
    },
    Rule {
        id: "py/bind-all-interfaces",
        name: "Web servers should not bind to all network interfaces",
        description: "0.0.0.0 makes the service reachable from every network the machine is on.",
        message: "Bind to a specific interface.",
        category: Vulnerability,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S8392")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(keyword_argument name: (identifier) @n (#eq? @n "host") value: (string) @v (#match? @v "^['\"](0[.]0[.]0[.]0|::)['\"]$")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "app.run(host='0.0.0.0')\n",
            good: "app.run(host='127.0.0.1')\n",
        }),
    },
    Rule {
        id: "py/flask-secret-key",
        name: "Flask secret keys should not be disclosed",
        description: "A secret key in source lets anyone forge session cookies.",
        message: "Load the secret key from the environment.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 10,
        sonar: &[exact("S6779")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(assignment left: (attribute attribute: (identifier) @a (#eq? @a "secret_key")) right: (string) @s) @match
(assignment left: (subscript subscript: (string) @k) right: (string)) @match"#,
            filter: Some(Keep(sets_literal_secret_key)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "app.secret_key = 'dev-secret-123'\n",
            good: "app.secret_key = os.environ['SECRET_KEY']\n",
        }),
    },
    Rule {
        id: "py/jwt-literal-secret",
        name: "JWT secret keys should not be disclosed",
        description: "A signing key in source lets anyone mint valid tokens.",
        message: "Load the signing key from the environment.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 10,
        sonar: &[exact("S6781")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @a (#eq? @o "jwt") (#eq? @a "encode"))) @match"#,
            filter: Some(Keep(second_argument_is_literal)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "token = jwt.encode(payload, 'my-secret', algorithm='HS256')\n",
            good: "token = jwt.encode(payload, SECRET, algorithm='HS256')\n",
        }),
    },
    Rule {
        id: "py/aws-access-key",
        name: "Long-term AWS access keys should not be used directly in code",
        description: "An access key ID in source identifies a credential that can be abused if the code leaks.",
        message: "Use an IAM role or environment credentials.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 15,
        sonar: &[exact("S7625")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"((string) @match (#match? @match "AKIA[0-9A-Z]{16}"))"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "key = 'AKIAIOSFODNN7EXAMPLE'\n",
            good: "key = os.environ['AWS_ACCESS_KEY_ID']\n",
        }),
    },
    Rule {
        id: "py/empty-db-password",
        name: "A secure password should be used when connecting to a database",
        description: "An empty password means anyone who can reach the database can use it.",
        message: "Set a strong password.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 5,
        sonar: &[exact("S2115")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(keyword_argument name: (identifier) @n (#any-of? @n "password" "passwd" "pwd") value: (string) @v) @match"#,
            filter: Some(Keep(empty_password_to_connect)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "conn = psycopg2.connect(host=h, password='')\n",
            good: "conn = psycopg2.connect(host=h, password=pw)\n",
        }),
    },
    Rule {
        id: "py/torch-load-unsafe",
        name: "Models should not be loaded with torch.load without restricting deserialization",
        description: "torch.load unpickles its input, which can run arbitrary code from an untrusted file.",
        message: "Pass weights_only=True.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 5,
        sonar: &[related("S6985")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @a (#eq? @o "torch") (#eq? @a "load"))) @match"#,
            filter: Some(Keep(lacks_weights_only)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "model = torch.load(path)\n",
            good: "model = torch.load(path, weights_only=True)\n",
        }),
    },
];

// ---------------------------------------------------- filters

fn text<'a>(node: Node, src: &'a [u8]) -> &'a [u8] {
    &src[node.byte_range()]
}

fn contains_ignoring_case(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|w| w.eq_ignore_ascii_case(needle))
}

fn has_interpolation(string: Node) -> bool {
    let mut cursor = string.walk();
    string
        .children(&mut cursor)
        .any(|c| c.kind() == "interpolation")
}

/// A string literal's characters between its quotes; None for f-strings
/// that interpolate, whose value isn't known.
fn string_value<'s>(string: Node, src: &'s [u8]) -> Option<&'s [u8]> {
    if string.kind() != "string" || has_interpolation(string) {
        return None;
    }
    let t = text(string, src);
    let quote = t.iter().position(|&b| b == b'"' || b == b'\'')?;
    let rest = &t[quote..];
    let n = if rest.starts_with(b"\"\"\"") || rest.starts_with(b"'''") {
        3
    } else {
        1
    };
    (rest.len() >= 2 * n).then(|| &rest[n..rest.len() - n])
}

fn call_of(node: Node) -> Option<Node> {
    // keyword_argument -> argument_list -> call
    node.parent()
        .and_then(|a| a.parent())
        .filter(|c| c.kind() == "call")
}

fn callee_name<'s>(call: Node, src: &'s [u8]) -> &'s [u8] {
    let Some(function) = call.child_by_field_name("function") else {
        return b"";
    };
    match function.kind() {
        "attribute" => function
            .child_by_field_name("attribute")
            .map_or(&b""[..], |a| text(a, src)),
        _ => text(function, src),
    }
}

fn call_arguments(call: Node) -> Vec<Node> {
    let Some(args) = call.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut cursor = args.walk();
    args.named_children(&mut cursor)
        .filter(|a| a.kind() != "comment")
        .collect()
}

fn keyword_value<'t>(call: Node<'t>, name: &str, src: &[u8]) -> Option<Node<'t>> {
    call_arguments(call).into_iter().find_map(|a| {
        (a.kind() == "keyword_argument"
            && a.child_by_field_name("name")
                .is_some_and(|n| text(n, src) == name.as_bytes()))
        .then(|| a.child_by_field_name("value"))
        .flatten()
    })
}

fn sql_built_dynamically(call: Node, src: &[u8]) -> bool {
    let Some(query) = call_arguments(call).into_iter().next() else {
        return false;
    };
    match query.kind() {
        "string" => has_interpolation(query),
        "binary_operator" => {
            let op = query
                .child_by_field_name("operator")
                .map_or(&b""[..], |o| text(o, src));
            matches!(op, b"%" | b"+")
                && query
                    .child_by_field_name("left")
                    .is_some_and(|l| l.kind() == "string" || l.kind() == "binary_operator")
                && query
                    .child_by_field_name("right")
                    .is_some_and(|r| r.kind() != "string")
        }
        "call" => query.child_by_field_name("function").is_some_and(|f| {
            f.kind() == "attribute"
                && f.child_by_field_name("attribute")
                    .is_some_and(|a| text(a, src) == b"format")
                && f.child_by_field_name("object")
                    .is_some_and(|o| o.kind() == "string")
        }),
        _ => false,
    }
}

fn is_cookie_setting(node: Node, src: &[u8]) -> bool {
    if node.kind() == "assignment" {
        return true;
    }
    call_of(node).is_some_and(|c| {
        matches!(
            callee_name(c, src),
            b"set_cookie" | b"set_signed_cookie" | b"SimpleCookie" | b"Morsel"
        )
    })
}

fn is_not_jwt_decode(node: Node, src: &[u8]) -> bool {
    if node.kind() == "attribute" {
        // `ssl.CERT_NONE` matters when it is assigned or passed, not when it
        // is compared with.
        return text(node, src) != b"ssl.CERT_NONE"
            || node
                .parent()
                .is_some_and(|p| matches!(p.kind(), "assignment" | "keyword_argument"));
    }
    !call_of(node).is_some_and(|c| {
        c.child_by_field_name("function")
            .is_some_and(|f| text(f, src) == b"jwt.decode")
    })
}

fn is_public_cleartext_url(string: Node, src: &[u8]) -> bool {
    let Some(body) = string_value(string, src) else {
        return false;
    };
    let Some(rest) = body
        .windows(3)
        .position(|w| w == b"://")
        .map(|i| &body[i + 3..])
    else {
        return false;
    };
    let end = rest
        .iter()
        .position(|&b| matches!(b, b'/' | b':' | b'?' | b'#' | b'\\'))
        .unwrap_or(rest.len());
    let host = String::from_utf8_lossy(&rest[..end]).to_ascii_lowercase();
    if host.is_empty() || host.contains(['$', '{', '%', '<', '[', '@', ' ']) {
        return false;
    }
    !(is_private_host(&host) || is_namespace_host(&host))
}

fn is_private_host(host: &str) -> bool {
    if matches!(host, "localhost" | "0.0.0.0") {
        return true;
    }
    if [
        ".local",
        ".localhost",
        ".test",
        ".example",
        ".invalid",
        ".internal",
        ".lan",
    ]
    .iter()
    .any(|suffix| host.ends_with(suffix))
    {
        return true;
    }
    if matches!(
        host,
        "example.com" | "example.org" | "example.net" | "www.example.com" | "www.example.org"
    ) {
        return true;
    }
    let parts: Vec<&str> = host.split('.').collect();
    let octets: Vec<u8> = parts.iter().filter_map(|o| o.parse().ok()).collect();
    if parts.len() != 4 || octets.len() != 4 {
        // Single-label names (docker service names, hosts file entries).
        return !host.contains('.');
    }
    matches!(octets[0], 10 | 127)
        || (octets[0] == 192 && octets[1] == 168)
        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
        || (octets[0] == 169 && octets[1] == 254)
}

fn is_namespace_host(host: &str) -> bool {
    host.ends_with("w3.org")
        || host.ends_with("xmlsoap.org")
        || host.ends_with("openxmlformats.org")
        || host.ends_with("purl.org")
        || host.ends_with("json-schema.org")
        || host.ends_with("schema.org")
        || host.starts_with("schemas.")
        || host.starts_with("xmlns")
        || host.ends_with("xml.org")
        || host.ends_with("xml.python.org")
}

const SECRET_WORDS: &[&[u8]] = &[
    b"token",
    b"secret",
    b"password",
    b"passwd",
    b"session",
    b"nonce",
    b"salt",
    b"otp",
    b"csrf",
    b"apikey",
    b"api_key",
];

fn random_feeds_a_secret(call: Node, src: &[u8]) -> bool {
    let mut context = call.parent();
    while let Some(n) = context {
        if matches!(
            n.kind(),
            "expression_statement" | "return_statement" | "assignment" | "function_definition"
        ) {
            break;
        }
        context = n.parent();
    }
    let Some(statement) = context else {
        return false;
    };
    let mentions = |haystack: &[u8]| {
        SECRET_WORDS
            .iter()
            .any(|w| contains_ignoring_case(haystack, w))
    };
    if statement.kind() == "function_definition" {
        return false;
    }
    if mentions(text(statement, src)) {
        return true;
    }
    // `return random...` inside `def make_token()`.
    let mut owner = statement.parent();
    let mut hops = 0;
    while let Some(n) = owner {
        if n.kind() == "function_definition" {
            return n
                .child_by_field_name("name")
                .is_some_and(|name| mentions(text(name, src)));
        }
        hops += 1;
        if hops > 64 {
            return false;
        }
        owner = n.parent();
    }
    false
}

fn weak_hash_call(call: Node, src: &[u8]) -> bool {
    if callee_name(call, src) != b"new" {
        return true;
    }
    call_arguments(call).first().is_some_and(|a| {
        string_value(*a, src)
            .is_some_and(|v| v.eq_ignore_ascii_case(b"md5") || v.eq_ignore_ascii_case(b"sha1"))
    })
}

fn integer_value(node: Node, src: &[u8]) -> Option<u64> {
    if node.kind() != "integer" {
        return None;
    }
    let t = String::from_utf8_lossy(text(node, src)).replace('_', "");
    let t = t.to_ascii_lowercase();
    if let Some(oct) = t.strip_prefix("0o") {
        u64::from_str_radix(oct, 8).ok()
    } else if let Some(hex) = t.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else if let Some(bin) = t.strip_prefix("0b") {
        u64::from_str_radix(bin, 2).ok()
    } else {
        t.parse().ok()
    }
}

fn grants_permissions_to_others(call: Node, src: &[u8]) -> bool {
    call_arguments(call)
        .iter()
        .filter_map(|a| integer_value(*a, src))
        .any(|mode| mode & 0o007 != 0)
}

fn key_size_below_2048(call: Node, src: &[u8]) -> bool {
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    let named = text(function, src).to_ascii_lowercase();
    if !(named.windows(3).any(|w| w == b"rsa") || named.windows(3).any(|w| w == b"dsa")) {
        return false;
    }
    let small = |n: Node| integer_value(n, src).is_some_and(|v| v < 2048);
    keyword_value(call, "key_size", src).is_some_and(small)
        || (callee_name(call, src) == b"generate"
            && call_arguments(call).first().is_some_and(|a| small(*a)))
}

fn disables_jwt_verification(node: Node, src: &[u8]) -> bool {
    if node.kind() == "pair" {
        return node
            .child_by_field_name("key")
            .and_then(|k| string_value(k, src))
            .is_some_and(|k| k == b"verify_signature");
    }
    call_of(node).is_some_and(|c| {
        c.child_by_field_name("function")
            .is_some_and(|f| text(f, src) == b"jwt.decode")
    })
}

fn is_debug_setting(node: Node, src: &[u8]) -> bool {
    node.kind() == "assignment" || call_of(node).is_some_and(|c| callee_name(c, src) == b"run")
}

fn allows_every_origin(node: Node, src: &[u8]) -> bool {
    if node.kind() == "assignment" {
        return true;
    }
    let Some(value) = node.child_by_field_name("value") else {
        return false;
    };
    match value.kind() {
        "string" => string_value(value, src).is_some_and(|v| v == b"*"),
        "list" => {
            let mut cursor = value.walk();
            value
                .named_children(&mut cursor)
                .any(|e| string_value(e, src).is_some_and(|v| v == b"*"))
        }
        _ => false,
    }
}

fn is_hardcoded_credential(node: Node, src: &[u8]) -> bool {
    let (name, value) = if node.kind() == "assignment" {
        let Some(left) = node.child_by_field_name("left") else {
            return false;
        };
        let name = if left.kind() == "attribute" {
            left.child_by_field_name("attribute")
        } else {
            Some(left)
        };
        (name, node.child_by_field_name("right"))
    } else {
        (
            node.child_by_field_name("name"),
            node.child_by_field_name("value"),
        )
    };
    let (Some(name), Some(value)) = (name, value) else {
        return false;
    };
    let lowered = text(name, src).to_ascii_lowercase();
    let named_like_credential = [
        &b"password"[..],
        b"passwd",
        b"pwd",
        b"secret",
        b"api_key",
        b"apikey",
        b"access_key",
        b"private_key",
        b"auth_token",
        b"token",
    ]
    .iter()
    .any(|w| lowered.windows(w.len()).any(|x| x == *w));
    // `flask.secret_key = ...` has its own rule; `*_url`, `*_field` and
    // similar names describe where a credential is, not what it is.
    let describes_location = [
        &b"_url"[..],
        b"_file",
        b"_path",
        b"_field",
        b"_name",
        b"_header",
        b"_env",
        b"_prompt",
        b"_label",
        b"_type",
        b"_len",
    ]
    .iter()
    .any(|s| lowered.ends_with(s));
    let Some(literal) = string_value(value, src) else {
        return false;
    };
    named_like_credential
        && !describes_location
        && literal.len() >= 4
        && !literal.contains(&b' ')
        && !literal.contains(&b'{')
        && !literal.contains(&b'%')
        && !literal.starts_with(b"$")
        && !literal.starts_with(b"<")
        && !literal.iter().all(|&b| b == b'*' || b == b'x' || b == b'X')
}

fn sets_literal_secret_key(assignment: Node, src: &[u8]) -> bool {
    let (Some(left), Some(right)) = (
        assignment.child_by_field_name("left"),
        assignment.child_by_field_name("right"),
    ) else {
        return false;
    };
    let literal = string_value(right, src).is_some_and(|v| !v.is_empty());
    if left.kind() == "attribute" {
        return literal;
    }
    literal
        && left
            .child_by_field_name("subscript")
            .and_then(|k| string_value(k, src))
            .is_some_and(|k| k == b"SECRET_KEY")
}

fn second_argument_is_literal(call: Node, src: &[u8]) -> bool {
    call_arguments(call)
        .get(1)
        .is_some_and(|k| string_value(*k, src).is_some_and(|v| !v.is_empty()))
}

fn empty_password_to_connect(argument: Node, src: &[u8]) -> bool {
    argument
        .child_by_field_name("value")
        .and_then(|v| string_value(v, src))
        .is_some_and(<[u8]>::is_empty)
        && call_of(argument)
            .is_some_and(|c| contains_ignoring_case(callee_name(c, src), b"connect"))
}

fn lacks_weights_only(call: Node, src: &[u8]) -> bool {
    keyword_value(call, "weights_only", src).is_none_or(|v| v.kind() != "true")
}

#[cfg(test)]
mod tests {
    use crate::analysis::analyze;
    use crate::analysis::tests::far_deadline;
    use crate::config::Config;
    use crate::lang::Lang;
    use crate::rules::RuleSet;

    fn flagged(rule: &str, src: &str) -> Vec<usize> {
        let cfg = Config::default();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let file = analyze("t", Lang::Python, src, &rules, &cfg, far_deadline()).unwrap();
        file.issues
            .iter()
            .filter(|i| i.rule == rule)
            .map(|i| i.line)
            .collect()
    }

    #[test]
    fn sql_formatting_forms() {
        let src = "cur.execute(f\"SELECT {a}\")\ncur.execute(\"SELECT %s\" % a)\ncur.execute(\"SELECT \" + a)\ncur.execute(\"SELECT {}\".format(a))\ncur.execute(\"SELECT %s\", (a,))\ncur.execute(\"SELECT 1\")\ncur.execute(f\"SELECT 1\")";
        assert_eq!(flagged("py/sql-built-dynamically", src), [1, 2, 3, 4]);
    }

    #[test]
    fn verification_switches() {
        let src = "requests.get(u, verify=False)\njwt.decode(t, k, verify=False)\njwt.decode(t, k, options={'verify_signature': False})\nctx.check_hostname = False\nctx.verify_mode = ssl.CERT_NONE\nok = ctx.verify_mode != ssl.CERT_NONE";
        assert_eq!(flagged("py/tls-unverified", src), [1, 5]);
        assert_eq!(flagged("py/jwt-unverified", src), [2, 3]);
        assert_eq!(flagged("py/hostname-unverified", src), [4]);
    }

    #[test]
    fn cookies_only_where_cookies_are_set() {
        let src = "resp.set_cookie('a', 'b', secure=False)\nfoo(secure=False)\nSESSION_COOKIE_SECURE = False\nresp.set_cookie('a', 'b', httponly=False)";
        assert_eq!(flagged("py/cookie-not-secure", src), [1, 3]);
        assert_eq!(flagged("py/cookie-not-httponly", src), [4]);
    }

    #[test]
    fn cleartext_urls_and_public_tmp() {
        let src = "a = 'http://example-shop.io/x'\nb = 'http://localhost:3000'\nc = 'http://192.168.1.5/x'\nd = f'http://{host}/x'\ne = '/tmp/out.txt'\nf = '/home/tmp/out'\ng = 'http://xml.org/sax/features/x'";
        assert_eq!(flagged("py/cleartext-url", src), [1]);
        assert_eq!(flagged("py/public-tmp", src), [5]);
    }

    #[test]
    fn random_only_for_secrets() {
        let src = "token = random.randint(0, 9)\njitter = random.random()\ndef make_password():\n    return random.choice(chars)\ndef pick():\n    return random.choice(chars)";
        assert_eq!(flagged("py/random-secret", src), [1, 4]);
    }

    #[test]
    fn hashes_ciphers_and_keys() {
        let src = "hashlib.md5(d)\nhashlib.new('sha1')\nhashlib.new('sha256')\nhashlib.sha256(d)\nDES.new(k)\nRSA.generate(1024)\nRSA.generate(2048)\nrsa.generate_private_key(public_exponent=65537, key_size=1024)\nec.generate_private_key(curve)";
        assert_eq!(flagged("py/weak-hash", src), [1, 2]);
        assert_eq!(flagged("py/weak-cipher", src), [5]);
        assert_eq!(flagged("py/weak-key-size", src), [6, 8]);
    }

    #[test]
    fn permissions() {
        let src = "os.chmod(p, 0o777)\nos.chmod(p, 0o600)\nos.chmod(p, 0o644)\nos.chmod(p, 0o660)\nos.chmod(p, mode)";
        assert_eq!(flagged("py/world-permissions", src), [1, 3]);
    }

    #[test]
    fn credentials() {
        let src = "password = 'Tr0ub4dor&3'\nself.db_password = 'hunter2hunter2'\npassword = ''\npassword = 'xxxx'\npassword_field = 'abcdefgh'\nconnect(api_key='abcd1234')\nname = 'abcdefgh'\npassword = os.environ['X']\ntoken = 'a b c d'";
        assert_eq!(flagged("py/hardcoded-credential", src), [1, 2, 6]);
    }

    #[test]
    fn debug_and_cors_and_secrets() {
        let src = "app.run(debug=True)\nfoo(debug=True)\nDEBUG = True\nCORS(app, origins='*')\nCORS(app, origins=['*', 'x'])\nCORS(app, origins=['a'])\napp.secret_key = 'abc'\napp.config['SECRET_KEY'] = 'abc'\napp.config['OTHER'] = 'abc'\njwt.encode(p, 'abc')\njwt.encode(p, key)";
        assert_eq!(flagged("py/debug-enabled", src), [1, 3]);
        assert_eq!(flagged("py/cors-any-origin", src), [4, 5]);
        assert_eq!(flagged("py/flask-secret-key", src), [7, 8]);
        assert_eq!(flagged("py/jwt-literal-secret", src), [10]);
    }

    #[test]
    fn db_passwords_and_torch() {
        let src = "psycopg2.connect(password='')\nfoo(password='')\npsycopg2.connect(password=pw)\ntorch.load(p)\ntorch.load(p, weights_only=True)\ntorch.load(p, weights_only=False)";
        assert_eq!(flagged("py/empty-db-password", src), [1]);
        assert_eq!(flagged("py/torch-load-unsafe", src), [4, 6]);
    }
}
