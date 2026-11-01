//! C# security rules (ADR-0007, ADR-0015, batch 1). Queries stay cheap on
//! deep trees: see the notes in `js_modern.rs`.

use super::cs::{cs_string_value, simple_name};
use super::cs_bugs::{attribute_arguments, cs_call_arguments, cs_integer};
use super::java_bugs::operator_text;
use super::java_security::{contains_ignoring_case, find_node, is_public_cleartext_url, text};
use super::*;

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "cs/weak-hash",
        name: "Weak hashing algorithms should not be used",
        description: "MD5, SHA-1 and RIPEMD-160 are broken for security purposes: collisions can be computed.",
        message: "Use a stronger algorithm such as SHA-256.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 15,
        sonar: &[exact("S4790")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(invocation_expression function: (member_access_expression)) (object_creation_expression)] @match",
            filter: Some(Keep(uses_weak_hash)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { byte[] F(byte[] d) { return MD5.Create().ComputeHash(d); } }",
            good: "class A { byte[] F(byte[] d) { return SHA256.Create().ComputeHash(d); } }",
        }),
    },
    Rule {
        id: "cs/weak-cipher",
        name: "Weak cipher algorithms should not be used",
        description: "DES, 3DES and RC2 use keys or blocks small enough to break in practice.",
        message: "Use AES instead.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 15,
        sonar: &[exact("S5547")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(invocation_expression function: (member_access_expression)) (object_creation_expression)] @match",
            filter: Some(Keep(uses_weak_cipher)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { SymmetricAlgorithm F() { return DES.Create(); } }",
            good: "class A { SymmetricAlgorithm F() { return Aes.Create(); } }",
        }),
    },
    Rule {
        id: "cs/insecure-cipher-mode",
        name: "Encryption should use a secure mode and padding",
        description: "ECB mode encrypts equal blocks to equal ciphertext, which leaks patterns, and RSA with \
                      PKCS#1 v1.5 padding is open to padding-oracle attacks.",
        message: "Use an authenticated mode such as AES-GCM, and OAEP padding for RSA.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 20,
        sonar: &[exact("S5542")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(member_access_expression expression: (_) @t name: (identifier) @n
                        (#match? @t "(^|\\.)(CipherMode|RSAEncryptionPadding)$")
                        (#any-of? @n "ECB" "Pkcs1")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(Aes aes) { aes.Mode = CipherMode.ECB; } }",
            good: "class A { void F(RSA rsa, byte[] d) { rsa.Encrypt(d, RSAEncryptionPadding.OaepSHA256); } }",
        }),
    },
    Rule {
        id: "cs/weak-tls-version",
        name: "Weak SSL/TLS protocol versions should not be used",
        description: "SSL 2, SSL 3, TLS 1.0 and TLS 1.1 have known weaknesses. Leave the choice to the operating \
                      system, or require TLS 1.2 or later.",
        message: "Use TLS 1.2 or later, or let the operating system choose.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S4423")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(member_access_expression expression: (_) @t name: (identifier) @n
                        (#match? @t "(^|\\.)(SslProtocols|SecurityProtocolType)$")
                        (#any-of? @n "Ssl2" "Ssl3" "Tls" "Tls11")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F() { ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls; } }",
            good: "class A { void F() { ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12; } }",
        }),
    },
    Rule {
        id: "cs/weak-key-size",
        name: "RSA and DSA keys should be at least 2048 bits long",
        description: "Keys shorter than 2048 bits can be factored with today's computing power.",
        message: "Use a key size of at least 2048 bits.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S4426")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(invocation_expression function: (member_access_expression) arguments: (argument_list)) \
                     (object_creation_expression arguments: (argument_list))] @match",
            filter: Some(Keep(creates_short_key)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { RSA F() { return new RSACryptoServiceProvider(1024); } }",
            good: "class A { RSA F() { return RSA.Create(3072); } }",
        }),
    },
    Rule {
        id: "cs/certificate-validation-disabled",
        name: "Server certificates should be validated",
        description: "A certificate validation callback that always returns `true` accepts any certificate, \
                      so anyone on the network path can impersonate the server.",
        message: "Validate the certificate here, or remove this callback to use the default validation.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S4830")],
        check: Check::Query {
            langs: CSHARP,
            query: "(assignment_expression) @match",
            filter: Some(Keep(accepts_every_certificate)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(HttpClientHandler h) { h.ServerCertificateCustomValidationCallback = (m, c, ch, e) => true; } }",
            good: "class A { void F(HttpClientHandler h) { h.ServerCertificateCustomValidationCallback = (m, c, ch, e) => e == SslPolicyErrors.None; } }",
        }),
    },
    Rule {
        id: "cs/ldap-anonymous",
        name: "LDAP connections should be authenticated",
        description: "An anonymous or unauthenticated LDAP bind lets anyone who can reach the directory read it, \
                      and sometimes change it.",
        message: "Bind with credentials, for example AuthenticationTypes.Secure.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S4433")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(member_access_expression expression: (_) @t name: (identifier) @n
                        (#match? @t "(^|\\.)AuthenticationTypes$")
                        (#any-of? @n "None" "Anonymous")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(DirectoryEntry d) { d.AuthenticationType = AuthenticationTypes.None; } }",
            good: "class A { void F(DirectoryEntry d) { d.AuthenticationType = AuthenticationTypes.Secure; } }",
        }),
    },
    Rule {
        id: "cs/empty-db-password",
        name: "Database connection strings should not have an empty password",
        description: "A database reachable with an empty password is open to anyone who can connect to it.",
        message: "Set a strong password, read from configuration or a secret store.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[exact("S2115")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(string_literal) (verbatim_string_literal)] @match",
            filter: Some(Keep(has_empty_password)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { const string Db = \"Server=db;Database=app;User Id=app;Password=;\"; }",
            good: "class A { const string Db = \"Server=db;Database=app;Integrated Security=true;Password=;\"; }",
        }),
    },
    Rule {
        id: "cs/cleartext-url",
        name: "Clear-text protocols should not be used",
        description: "Data sent over http, ftp or telnet can be read and changed by anyone on the network path.",
        message: "Use the encrypted protocol (https, sftp, ssh) instead.",
        category: Vulnerability,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[related("S5332")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"((string_literal) @match (#match? @match "^\"(http|ftp|telnet)://"))"#,
            filter: Some(Keep(is_public_cleartext_cs_url)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { const string Api = \"http://api.payments.com/v1\"; }",
            good: "class A { const string Api = \"https://api.payments.com/v1\"; const string Ns = \"http://tempuri.org/\"; }",
        }),
    },
    // ---- Batch 2 ----
    Rule {
        id: "cs/hardcoded-credential",
        name: "Credentials should not be hard-coded",
        description: "A password or secret in source code is readable by everyone with the code, ends up in \
                      version history, and can't be rotated without a release.",
        message: "Read this credential from configuration or a secret store.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[related("S2068"), related("S6418")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(variable_declarator name: (identifier) [(string_literal) (verbatim_string_literal)]) \
                     (assignment_expression left: [(identifier) (member_access_expression)] \
                       right: [(string_literal) (verbatim_string_literal)]) \
                     (string_literal) (verbatim_string_literal)] @match",
            filter: Some(Keep(is_hardcoded_credential)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { const string ApiKey = \"k3y-8f2a9c\"; }",
            good: "class A { string PasswordLabel = \"Password\"; string Key(IConfiguration c) => c[\"ApiKey\"]; }",
        }),
    },
    Rule {
        id: "cs/sql-built-dynamically",
        name: "SQL queries should not be built from strings",
        description: "Formatting or concatenating values into a query lets an attacker change what it does; \
                      pass them as parameters.",
        message: "Use a parameterized query instead of building this string.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 20,
        sonar: &[related("S2077")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(object_creation_expression arguments: (argument_list)) \
                     (invocation_expression function: (member_access_expression)) \
                     (assignment_expression left: (member_access_expression))] @match",
            filter: Some(Keep(sql_built_dynamically)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(SqlConnection c, string id) { var cmd = new SqlCommand(\"SELECT * FROM t WHERE id = \" + id, c); } }",
            good: "class A { void F(SqlConnection c, string id) { var cmd = new SqlCommand(\"SELECT * FROM t WHERE id = @id\", c); } }",
        }),
    },
    Rule {
        id: "cs/cookie-not-secure",
        name: "Cookies should be sent over HTTPS only",
        description: "A cookie without `Secure` is also sent over plain HTTP, where anyone on the network can \
                      read it.",
        message: "Set Secure to true.",
        category: Vulnerability,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S2092")],
        check: Check::Query {
            langs: CSHARP,
            query: "(assignment_expression right: (boolean_literal)) @match",
            filter: Some(Keep(disables_secure)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { CookieOptions F() { return new CookieOptions { Secure = false }; } }",
            good: "class A { CookieOptions F() { return new CookieOptions { Secure = true }; } }",
        }),
    },
    Rule {
        id: "cs/cookie-not-httponly",
        name: "Cookies should not be readable from scripts",
        description: "Without `HttpOnly`, any script on the page, an injected one included, can read the cookie.",
        message: "Set HttpOnly to true.",
        category: Vulnerability,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S3330")],
        check: Check::Query {
            langs: CSHARP,
            query: "(assignment_expression right: (boolean_literal)) @match",
            filter: Some(Keep(disables_http_only)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F(HttpCookie c) { c.HttpOnly = false; } }",
            good: "class A { void F(HttpCookie c) { c.HttpOnly = true; } }",
        }),
    },
    Rule {
        id: "cs/custom-crypto",
        name: "Cryptographic algorithms should not be implemented by hand",
        description: "Home-made cryptography is almost always weaker than the standard algorithms, which have \
                      been studied for years.",
        message: "Use a standard algorithm from System.Security.Cryptography instead.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 60,
        sonar: &[exact("S2257")],
        check: Check::Query {
            langs: CSHARP,
            query: "(class_declaration name: (identifier) (base_list)) @match",
            filter: Some(Find(custom_crypto_name)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class MyHash : HashAlgorithm { }",
            good: "class Hasher { byte[] F(byte[] d) => SHA256.HashData(d); }",
        }),
    },
    Rule {
        id: "cs/xxe",
        name: "XML parsers should not resolve external entities",
        description: "Processing DTDs or resolving external resources lets a crafted document read local files \
                      or make requests from the server (XXE).",
        message: "Leave DTD processing prohibited and XmlResolver unset (null).",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 15,
        sonar: &[exact("S2755")],
        check: Check::Query {
            langs: CSHARP,
            query: "(assignment_expression) @match",
            filter: Some(Keep(enables_external_entities)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { XmlReaderSettings F() { return new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse }; } }",
            good: "class A { XmlReaderSettings F() { return new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit }; } }",
        }),
    },
    Rule {
        id: "cs/os-command-path",
        name: "Commands should be started by their full path",
        description: "A bare command name is looked up in the PATH, so whoever controls a directory in it \
                      chooses the program that runs.",
        message: "Start this program by its absolute path.",
        category: Vulnerability,
        severity: Minor,
        effort_minutes: 10,
        sonar: &[exact("S4036")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(invocation_expression function: (member_access_expression)) \
                     (object_creation_expression arguments: (argument_list)) \
                     (assignment_expression left: (identifier))] @match",
            filter: Some(Keep(starts_command_from_path)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F() { Process.Start(\"git\", \"status\"); } }",
            good: "class A { void F() { Process.Start(\"/usr/bin/git\", \"status\"); } }",
        }),
    },
    Rule {
        id: "cs/csrf-disabled",
        name: "CSRF protection should not be disabled",
        description: "Without an antiforgery token, another site can make a signed-in user's browser submit \
                      requests to this one.",
        message: "Remove this exemption from antiforgery validation.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S4502")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(attribute name: (_)) (object_creation_expression type: (_))] @match",
            filter: Some(Keep(ignores_antiforgery)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class C : Controller { [HttpPost, IgnoreAntiforgeryToken] public IActionResult Save() => Ok(); }",
            good: "class C : Controller { [HttpPost, ValidateAntiForgeryToken] public IActionResult Save() => Ok(); }",
        }),
    },
    Rule {
        id: "cs/debug-features",
        name: "Developer error pages should only be enabled in development",
        description: "The developer exception page shows stack traces, source and configuration to whoever \
                      triggers an error.",
        message: "Enable this only when env.IsDevelopment() is true.",
        category: Vulnerability,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S4507")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(invocation_expression
                        function: (member_access_expression name: (identifier) @n)
                        (#any-of? @n "UseDeveloperExceptionPage" "UseDatabaseErrorPage")) @match"#,
            filter: Some(Keep(outside_development_check)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class S { void Configure(IApplicationBuilder app) { app.UseDeveloperExceptionPage(); } }",
            good: "class S { void Configure(IApplicationBuilder app, IWebHostEnvironment env) { if (env.IsDevelopment()) { app.UseDeveloperExceptionPage(); } } }",
        }),
    },
    Rule {
        id: "cs/cors-any-origin",
        name: "CORS should not allow every origin",
        description: "Allowing any origin lets every website read this API's responses with the visitor's \
                      session, where the browser would otherwise block them.",
        message: "List the origins that may call this API instead of allowing all of them.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S5122")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(invocation_expression function: (member_access_expression)) \
                     (assignment_expression left: (element_access_expression))] @match",
            filter: Some(Keep(allows_every_origin)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class S { void F(CorsPolicyBuilder p) { p.AllowAnyOrigin(); } }",
            good: "class S { void F(CorsPolicyBuilder p) { p.WithOrigins(\"https://shop.example.com\"); } }",
        }),
    },
    Rule {
        id: "cs/weak-password-hashing",
        name: "Passwords should be hashed with enough iterations",
        description: "PBKDF2 with few iterations (the old default is 1,000) lets an attacker try billions of \
                      passwords against a stolen hash.",
        message: "Use at least 100,000 iterations, or a dedicated password hasher.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 15,
        sonar: &[exact("S5344")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(object_creation_expression arguments: (argument_list)) \
                     (invocation_expression function: (member_access_expression))] @match",
            filter: Some(Keep(too_few_pbkdf2_iterations)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { byte[] F(string p, byte[] s) { return new Rfc2898DeriveBytes(p, s).GetBytes(32); } }",
            good: "class A { byte[] F(string p, byte[] s) { return Rfc2898DeriveBytes.Pbkdf2(p, s, 600_000, HashAlgorithmName.SHA256, 32); } }",
        }),
    },
    Rule {
        id: "cs/public-tmp",
        name: "Files should not be created in shared temporary directories by name",
        description: "Other users can read files in `/tmp`, or create the same name first and have this program \
                      write into their file.",
        message: "Create the file with a random name and restricted permissions, in a private directory.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S5443")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(string_literal) (verbatim_string_literal)] @match",
            filter: Some(Keep(names_shared_tmp)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { void F() { File.WriteAllText(\"/tmp/report.txt\", \"x\"); } }",
            good: "class A { void F(string dir) { File.WriteAllText(Path.Combine(dir, \"report.txt\"), \"x\"); } }",
        }),
    },
    Rule {
        id: "cs/create-temp-file",
        name: "Path.GetTempFileName() should not be used",
        description: "It creates a predictable name in the shared temporary directory, and throws once 65,535 \
                      such files exist.",
        message: "Create a random file name in a private directory instead.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S5445")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(invocation_expression
                        function: (member_access_expression expression: (_) @t name: (identifier) @n)
                        (#match? @t "(^|\\.)Path$") (#eq? @n "GetTempFileName")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { string F() { return Path.GetTempFileName(); } }",
            good: "class A { string F(string dir) { return Path.Combine(dir, Path.GetRandomFileName()); } }",
        }),
    },
    Rule {
        id: "cs/jwt-unverified",
        name: "JWT signatures should be verified",
        description: "Accepting unsigned or unverified tokens lets anyone forge one with whatever claims they want.",
        message: "Require and verify the token's signature.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 15,
        sonar: &[exact("S5659")],
        check: Check::Query {
            langs: CSHARP,
            query: "[(assignment_expression right: (boolean_literal)) \
                     (invocation_expression function: (member_access_expression))] @match",
            filter: Some(Keep(skips_jwt_verification)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { TokenValidationParameters F() { return new TokenValidationParameters { RequireSignedTokens = false }; } }",
            good: "class A { TokenValidationParameters F() { return new TokenValidationParameters { RequireSignedTokens = true }; } }",
        }),
    },
    Rule {
        id: "cs/request-size-unlimited",
        name: "Request size limits should not be too large",
        description: "Very large or unlimited request bodies let one client exhaust the server's memory or disk.",
        message: "Keep the request size limit at 8 MB or less, or justify the larger limit for this endpoint.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5693")],
        check: Check::Query {
            langs: CSHARP,
            query: "(attribute name: (_)) @match",
            filter: Some(Keep(lifts_request_limit)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class C : Controller { [DisableRequestSizeLimit] public IActionResult Upload() => Ok(); }",
            good: "class C : Controller { [RequestSizeLimit(8_000_000)] public IActionResult Upload() => Ok(); }",
        }),
    },
    Rule {
        id: "cs/request-validation-disabled",
        name: "ASP.NET request validation should not be disabled",
        description: "Request validation rejects input that looks like markup or script; turning it off opens \
                      the way to cross-site scripting.",
        message: "Remove [ValidateInput(false)] and encode the input where it is used.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S5753")],
        check: Check::Query {
            langs: CSHARP,
            query: "(attribute name: (_)) @match",
            filter: Some(Keep(disables_request_validation)),
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class C : Controller { [ValidateInput(false)] public ActionResult Save(string html) => View(); }",
            good: "class C : Controller { public ActionResult Save(string html) => View(); }",
        }),
    },
    Rule {
        id: "cs/unsafe-code",
        name: "Unsafe code should be reviewed",
        description: "`unsafe` code works with raw pointers, outside the runtime's memory safety: an error \
                      there can corrupt memory or expose it.",
        message: "Make sure this unsafe code is needed and its pointer use is correct.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 15,
        sonar: &[exact("S6640")],
        check: Check::Query {
            langs: CSHARP,
            query: r#"(unsafe_statement) @match
((modifier) @match (#eq? @match "unsafe"))"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { unsafe void F(byte* p) { *p = 0; } }",
            good: "class A { void F(Span<byte> p) { p[0] = 0; } }",
        }),
    },
];

// ---------------------------------------------------- filters

/// The type a call or `new` names: `MD5` in `MD5.Create()` and in
/// `System.Security.Cryptography.MD5.HashData(x)`, `SHA1Managed` in
/// `new SHA1Managed()`. Also the called member, if it's a call.
fn type_and_member<'s>(node: Node, src: &'s [u8]) -> Option<(&'s [u8], &'s [u8])> {
    if node.kind() == "object_creation_expression" {
        let t = node.child_by_field_name("type")?;
        return Some((simple_name(t, src), b""));
    }
    let function = node.child_by_field_name("function")?;
    let receiver = function.child_by_field_name("expression")?;
    let member = function.child_by_field_name("name")?;
    Some((simple_name(receiver, src), text(member, src)))
}

/// `HashAlgorithm.Create("MD5")` and `CryptoConfig.CreateFromName("DES")`:
/// the algorithm named by the first string argument.
fn named_algorithm<'s>(node: Node, src: &'s [u8]) -> Option<&'s [u8]> {
    let (_, member) = type_and_member(node, src)?;
    if !matches!(member, b"Create" | b"CreateFromName") {
        return None;
    }
    let args = node.child_by_field_name("arguments")?;
    let first = args.named_child(0)?.named_child(0)?;
    cs_string_value(first, src)
}

fn uses_weak_hash(node: Node, src: &[u8]) -> bool {
    let Some((ty, member)) = type_and_member(node, src) else {
        return false;
    };
    let weak_factory = matches!(
        ty,
        b"MD5" | b"SHA1" | b"RIPEMD160" | b"HMACMD5" | b"HMACSHA1"
    ) && matches!(
        member,
        b"Create" | b"HashData" | b"HashDataAsync" | b"TryHashData"
    );
    let weak_class = member.is_empty()
        && matches!(
            ty,
            b"MD5CryptoServiceProvider"
                | b"MD5Cng"
                | b"SHA1Managed"
                | b"SHA1CryptoServiceProvider"
                | b"SHA1Cng"
                | b"RIPEMD160Managed"
                | b"HMACMD5"
                | b"HMACSHA1"
                | b"HMACRIPEMD160"
        );
    let weak_name = named_algorithm(node, src).is_some_and(|name| {
        [
            &b"MD5"[..],
            b"SHA1",
            b"SHA",
            b"RIPEMD160",
            b"HMACMD5",
            b"HMACSHA1",
        ]
        .iter()
        .any(|w| names_algorithm(name, w))
    });
    weak_factory || weak_class || weak_name
}

fn uses_weak_cipher(node: Node, src: &[u8]) -> bool {
    let Some((ty, member)) = type_and_member(node, src) else {
        return false;
    };
    let weak_factory = matches!(ty, b"DES" | b"TripleDES" | b"RC2") && member == b"Create";
    let weak_class = member.is_empty()
        && matches!(
            ty,
            b"DESCryptoServiceProvider"
                | b"TripleDESCryptoServiceProvider"
                | b"RC2CryptoServiceProvider"
        );
    let weak_name = named_algorithm(node, src).is_some_and(|name| {
        [&b"DES"[..], b"3DES", b"TripleDES", b"RC2"]
            .iter()
            .any(|w| names_algorithm(name, w))
    });
    weak_factory || weak_class || weak_name
}

/// `name` is `algorithm`, or a full name ending in `.algorithm`, ignoring case.
fn names_algorithm(name: &[u8], algorithm: &[u8]) -> bool {
    let Some(start) = name.len().checked_sub(algorithm.len()) else {
        return false;
    };
    name[start..].eq_ignore_ascii_case(algorithm) && (start == 0 || name[start - 1] == b'.')
}

fn creates_short_key(node: Node, src: &[u8]) -> bool {
    let Some((ty, member)) = type_and_member(node, src) else {
        return false;
    };
    let key_type = match member {
        b"" => matches!(
            ty,
            b"RSACryptoServiceProvider" | b"DSACryptoServiceProvider" | b"RSACng" | b"DSACng"
        ),
        b"Create" => matches!(ty, b"RSA" | b"DSA"),
        _ => false,
    };
    if !key_type {
        return false;
    }
    let size = node
        .child_by_field_name("arguments")
        .and_then(|a| a.named_child(0))
        .and_then(|arg| arg.named_child(0))
        .filter(|v| v.kind() == "integer_literal")
        .and_then(|v| {
            std::str::from_utf8(text(v, src))
                .ok()?
                .replace('_', "")
                .parse::<u64>()
                .ok()
        });
    size.is_some_and(|bits| bits < 2048)
}

fn accepts_every_certificate(node: Node, src: &[u8]) -> bool {
    if !matches!(operator_text(node, src), b"=" | b"+=") {
        return false;
    }
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return false;
    };
    let callback = matches!(
        simple_name(left, src),
        b"ServerCertificateValidationCallback"
            | b"ServerCertificateCustomValidationCallback"
            | b"RemoteCertificateValidationCallback"
    );
    callback
        && (always_returns_true(right, src)
            || simple_name(right, src) == b"DangerousAcceptAnyServerCertificateValidator")
}

/// `(...) => true`, `delegate { return true; }` and the like.
fn always_returns_true(function: Node, src: &[u8]) -> bool {
    if !matches!(
        function.kind(),
        "lambda_expression" | "anonymous_method_expression"
    ) {
        return false;
    }
    let body = function.child_by_field_name("body").or_else(|| {
        let mut cursor = function.walk();
        function
            .named_children(&mut cursor)
            .find(|c| c.kind() == "block")
    });
    let Some(body) = body else {
        return false;
    };
    let is_true = |n: Node| n.kind() == "boolean_literal" && text(n, src) == b"true";
    if body.kind() != "block" {
        return is_true(body);
    }
    let mut cursor = body.walk();
    let stmts: Vec<Node> = body
        .named_children(&mut cursor)
        .filter(|n| n.kind() != "comment")
        .collect();
    stmts.len() == 1
        && stmts[0].kind() == "return_statement"
        && stmts[0].named_child(0).is_some_and(is_true)
}

fn has_empty_password(node: Node, src: &[u8]) -> bool {
    let Some(value) = cs_string_value(node, src) else {
        return false;
    };
    // Windows authentication makes the password unused.
    if contains_ignoring_case(value, b"integrated security")
        || contains_ignoring_case(value, b"trusted_connection")
    {
        return false;
    }
    value.split(|&b| b == b';').any(|pair| {
        let mut kv = pair.splitn(2, |&b| b == b'=');
        let key = kv.next().unwrap_or_default();
        let key = String::from_utf8_lossy(key).trim().to_ascii_lowercase();
        matches!(kv.next(), Some(v) if v.iter().all(u8::is_ascii_whitespace))
            && matches!(key.as_str(), "password" | "pwd")
    })
}

fn is_public_cleartext_cs_url(node: Node, src: &[u8]) -> bool {
    // tempuri.org is the default XML namespace of WCF services, never fetched.
    !contains_ignoring_case(text(node, src), b"tempuri.org") && is_public_cleartext_url(node, src)
}

// ---------------------------------------------------- batch 2 filters

fn is_hardcoded_credential(node: Node, src: &[u8]) -> bool {
    let (name, value) = match node.kind() {
        "variable_declarator" => {
            let name = node.child_by_field_name("name");
            let mut cursor = node.walk();
            let value = node
                .named_children(&mut cursor)
                .find(|c| matches!(c.kind(), "string_literal" | "verbatim_string_literal"));
            (name.map(|n| text(n, src)), value)
        }
        "assignment_expression" => (
            node.child_by_field_name("left")
                .map(|l| simple_name(l, src)),
            node.child_by_field_name("right"),
        ),
        // A connection string: "...;Password=s3cret;...".
        _ => return has_connection_password(node, src),
    };
    let (Some(name), Some(value)) = (name, value) else {
        return false;
    };
    if operator_text(node, src) != b"=" && node.kind() == "assignment_expression" {
        return false;
    }
    let Some(literal) = cs_string_value(value, src) else {
        return false;
    };
    let lowered = name.to_ascii_lowercase();
    let credential_name = [
        &b"password"[..],
        b"passwd",
        b"pwd",
        b"secret",
        b"apikey",
        b"api_key",
        b"accesskey",
        b"access_key",
        b"privatekey",
        b"private_key",
        b"token",
    ]
    .iter()
    .any(|w| lowered.windows(w.len()).any(|x| x == *w));
    // PasswordLabel, TokenUrl, SecretName and the like describe a credential.
    let describes_it = [
        &b"url"[..],
        b"uri",
        b"file",
        b"path",
        b"field",
        b"name",
        b"header",
        b"env",
        b"prompt",
        b"label",
        b"type",
        b"pattern",
        b"param",
        b"key",
        b"message",
        b"text",
        b"format",
        b"regex",
        b"endpoint",
        b"section",
        b"policy",
        b"scheme",
        b"claim",
        b"hash",
    ]
    .iter()
    .any(|s| lowered.ends_with(s))
        && !lowered.ends_with(b"apikey")
        && !lowered.ends_with(b"privatekey")
        && !lowered.ends_with(b"accesskey");
    // "App:Secrets:Db" or "auth.token" names a configuration entry.
    let looks_like_key = literal
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':'))
        && literal.iter().any(|b| matches!(b, b'.' | b':'))
        && !literal.iter().any(u8::is_ascii_digit);
    credential_name
        && !describes_it
        && !looks_like_key
        && literal.len() >= 4
        && !literal.contains(&b' ')
        && !literal.contains(&b'{')
        && !literal.contains(&b'%')
        && !literal.starts_with(b"$")
        && !literal.starts_with(b"<")
        && !literal.iter().all(|&b| b == b'*' || b == b'x' || b == b'X')
        && !literal.eq_ignore_ascii_case(name)
}

fn has_connection_password(node: Node, src: &[u8]) -> bool {
    let Some(value) = cs_string_value(node, src) else {
        return false;
    };
    value.split(|&b| b == b';').any(|pair| {
        let mut kv = pair.splitn(2, |&b| b == b'=');
        let key = String::from_utf8_lossy(kv.next().unwrap_or_default())
            .trim()
            .to_ascii_lowercase();
        let secret = kv.next().map(|v| v.trim_ascii()).unwrap_or_default();
        matches!(key.as_str(), "password" | "pwd")
            && secret.len() >= 2
            && !secret.contains(&b'{')
            && !secret.starts_with(b"$")
            && !secret.starts_with(b"%")
            && !secret.iter().all(|&b| b == b'*')
    })
}

/// A query built by concatenation, interpolation or `string.Format`.
fn is_dynamic_string(expr: Node, src: &[u8]) -> bool {
    match expr.kind() {
        "interpolated_string_expression" => {
            let mut cursor = expr.walk();
            expr.named_children(&mut cursor)
                .any(|c| c.kind() == "interpolation")
        }
        "binary_expression" => {
            operator_text(expr, src) == b"+"
                && !is_constant_string(expr)
                && find_node(expr, |n| {
                    matches!(n.kind(), "string_literal" | "verbatim_string_literal")
                })
                .is_some()
        }
        "invocation_expression" => expr.child_by_field_name("function").is_some_and(|f| {
            matches!(
                text(f, src),
                b"string.Format" | b"String.Format" | b"string.Concat" | b"String.Concat"
            )
        }),
        "parenthesized_expression" => expr
            .named_child(0)
            .is_some_and(|e| is_dynamic_string(e, src)),
        _ => false,
    }
}

fn is_constant_string(expr: Node) -> bool {
    match expr.kind() {
        "string_literal" | "verbatim_string_literal" | "integer_literal" | "character_literal" => {
            true
        }
        "binary_expression" => {
            expr.child_by_field_name("left")
                .is_some_and(is_constant_string)
                && expr
                    .child_by_field_name("right")
                    .is_some_and(is_constant_string)
        }
        "parenthesized_expression" => expr.named_child(0).is_some_and(is_constant_string),
        _ => false,
    }
}

fn first_argument(call: Node) -> Option<Node> {
    cs_call_arguments(call).into_iter().next()
}

fn sql_built_dynamically(node: Node, src: &[u8]) -> bool {
    match node.kind() {
        "object_creation_expression" => {
            node.child_by_field_name("type").is_some_and(|t| {
                matches!(
                    simple_name(t, src),
                    b"SqlCommand"
                        | b"SqlDataAdapter"
                        | b"OracleCommand"
                        | b"OracleDataAdapter"
                        | b"NpgsqlCommand"
                        | b"MySqlCommand"
                        | b"SqliteCommand"
                        | b"SQLiteCommand"
                        | b"OleDbCommand"
                        | b"OdbcCommand"
                )
            }) && first_argument(node).is_some_and(|q| is_dynamic_string(q, src))
        }
        "invocation_expression" => {
            node.child_by_field_name("function")
                .and_then(|f| f.child_by_field_name("name"))
                .is_some_and(|n| {
                    matches!(
                        text(n, src),
                        b"ExecuteSqlRaw"
                            | b"ExecuteSqlRawAsync"
                            | b"FromSqlRaw"
                            | b"SqlQueryRaw"
                            | b"ExecuteSqlCommand"
                            | b"ExecuteSqlCommandAsync"
                    )
                })
                && first_argument(node).is_some_and(|q| is_dynamic_string(q, src))
        }
        _ => {
            operator_text(node, src) == b"="
                && node
                    .child_by_field_name("left")
                    .is_some_and(|l| simple_name(l, src) == b"CommandText")
                && node
                    .child_by_field_name("right")
                    .is_some_and(|r| is_dynamic_string(r, src))
        }
    }
}

fn sets_false(node: Node, property: &[u8], src: &[u8]) -> bool {
    operator_text(node, src) == b"="
        && node
            .child_by_field_name("left")
            .is_some_and(|l| simple_name(l, src) == property)
        && node
            .child_by_field_name("right")
            .is_some_and(|r| text(r, src) == b"false")
}

fn disables_secure(node: Node, src: &[u8]) -> bool {
    sets_false(node, b"Secure", src)
}

fn disables_http_only(node: Node, src: &[u8]) -> bool {
    sets_false(node, b"HttpOnly", src)
}

fn custom_crypto_name<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut cursor = class.walk();
    let base_list = class
        .named_children(&mut cursor)
        .find(|c| c.kind() == "base_list")?;
    let mut inner = base_list.walk();
    let derives = base_list.named_children(&mut inner).any(|b| {
        matches!(
            simple_name(b, src),
            b"HashAlgorithm"
                | b"KeyedHashAlgorithm"
                | b"HMAC"
                | b"SymmetricAlgorithm"
                | b"AsymmetricAlgorithm"
                | b"ICryptoTransform"
                | b"DeriveBytes"
                | b"AsymmetricKeyExchangeFormatter"
                | b"AsymmetricKeyExchangeDeformatter"
                | b"AsymmetricSignatureFormatter"
                | b"AsymmetricSignatureDeformatter"
        )
    });
    derives.then(|| class.child_by_field_name("name"))?
}

fn enables_external_entities(node: Node, src: &[u8]) -> bool {
    if operator_text(node, src) != b"=" {
        return false;
    }
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return false;
    };
    match simple_name(left, src) {
        b"DtdProcessing" => simple_name(right, src) == b"Parse",
        b"ProhibitDtd" => text(right, src) == b"false",
        b"XmlResolver" => {
            right.kind() == "object_creation_expression"
                && right.child_by_field_name("type").is_some_and(|t| {
                    matches!(
                        simple_name(t, src),
                        b"XmlUrlResolver" | b"XmlSecureResolver"
                    )
                })
        }
        _ => false,
    }
}

/// `"git"`: a program name without a directory.
fn is_bare_command(expr: Node, src: &[u8]) -> bool {
    cs_string_value(expr, src).is_some_and(|name| {
        !name.is_empty()
            && !name.contains(&b'/')
            && !name.contains(&b'\\')
            && !name.contains(&b' ')
            && !name.contains(&b':')
            && !name.contains(&b'{')
    })
}

fn starts_command_from_path(node: Node, src: &[u8]) -> bool {
    match node.kind() {
        "invocation_expression" => {
            node.child_by_field_name("function").is_some_and(|f| {
                matches!(
                    text(f, src),
                    b"Process.Start" | b"System.Diagnostics.Process.Start"
                )
            }) && first_argument(node).is_some_and(|a| is_bare_command(a, src))
        }
        "object_creation_expression" => {
            node.child_by_field_name("type")
                .is_some_and(|t| simple_name(t, src) == b"ProcessStartInfo")
                && first_argument(node).is_some_and(|a| is_bare_command(a, src))
        }
        // `FileName = "git"` in a ProcessStartInfo initializer.
        _ => {
            node.child_by_field_name("left")
                .is_some_and(|l| text(l, src) == b"FileName")
                && node
                    .child_by_field_name("right")
                    .is_some_and(|r| is_bare_command(r, src))
                && node
                    .parent()
                    .filter(|p| p.kind() == "initializer_expression")
                    .and_then(|p| p.parent())
                    .and_then(|o| o.child_by_field_name("type"))
                    .is_some_and(|t| simple_name(t, src) == b"ProcessStartInfo")
        }
    }
}

fn ignores_antiforgery(node: Node, src: &[u8]) -> bool {
    let name = match node.kind() {
        "attribute" => node.child_by_field_name("name"),
        _ => node.child_by_field_name("type"),
    };
    name.is_some_and(|n| {
        matches!(
            simple_name(n, src),
            b"IgnoreAntiforgeryToken" | b"IgnoreAntiforgeryTokenAttribute"
        )
    })
}

fn outside_development_check(node: Node, src: &[u8]) -> bool {
    // Walk up to the enclosing member; a few dozen levels is plenty.
    let mut current = node.parent();
    for _ in 0..64 {
        let Some(n) = current else {
            return true;
        };
        match n.kind() {
            "if_statement" | "conditional_expression" => {
                if n.child_by_field_name("condition")
                    .is_some_and(|c| contains_ignoring_case(text(c, src), b"IsDevelopment"))
                {
                    return false;
                }
            }
            "method_declaration" | "local_function_statement" | "class_declaration" => return true,
            _ => {}
        }
        current = n.parent();
    }
    true
}

fn allows_every_origin(node: Node, src: &[u8]) -> bool {
    let is_star = |n: Node| cs_string_value(n, src) == Some(b"*");
    let is_header = |n: Node| {
        cs_string_value(n, src)
            .is_some_and(|v| v.eq_ignore_ascii_case(b"Access-Control-Allow-Origin"))
    };
    if node.kind() == "assignment_expression" {
        // Headers["Access-Control-Allow-Origin"] = "*"
        let key = node
            .child_by_field_name("left")
            .and_then(|l| l.child_by_field_name("subscript"))
            .and_then(|s| s.named_child(0))
            .and_then(|a| a.named_child(0));
        return key.is_some_and(is_header)
            && node.child_by_field_name("right").is_some_and(is_star);
    }
    let Some(name) = node
        .child_by_field_name("function")
        .and_then(|f| f.child_by_field_name("name"))
    else {
        return false;
    };
    let args = cs_call_arguments(node);
    match text(name, src) {
        b"AllowAnyOrigin" => true,
        b"WithOrigins" => args.iter().any(|a| is_star(*a)),
        b"Add" | b"Append" | b"AppendHeader" | b"AddHeader" | b"TryAdd" => {
            matches!(args.as_slice(), [h, v] if is_header(*h) && is_star(*v))
        }
        _ => false,
    }
}

fn too_few_pbkdf2_iterations(node: Node, src: &[u8]) -> bool {
    let args = cs_call_arguments(node);
    let iterations_below = |position: usize| {
        let named = node.child_by_field_name("arguments").and_then(|list| {
            let mut cursor = list.walk();
            let found = list.named_children(&mut cursor).find(|a| {
                a.child_by_field_name("name")
                    .is_some_and(|n| matches!(text(n, src), b"iterations" | b"iterationCount"))
            });
            found.and_then(|a| a.named_children(&mut a.walk()).last())
        });
        match named.or_else(|| args.get(position).copied()) {
            Some(v) => cs_integer(v, src).is_some_and(|n| n < 100_000),
            // Rfc2898DeriveBytes's constructors without a count use 1,000.
            None => true,
        }
    };
    match node.kind() {
        "object_creation_expression" => {
            node.child_by_field_name("type")
                .is_some_and(|t| simple_name(t, src) == b"Rfc2898DeriveBytes")
                && iterations_below(2)
        }
        _ => {
            let Some(function) = node.child_by_field_name("function") else {
                return false;
            };
            let receiver = function
                .child_by_field_name("expression")
                .map_or(&b""[..], |e| simple_name(e, src));
            let method = function
                .child_by_field_name("name")
                .map_or(&b""[..], |n| text(n, src));
            match (receiver, method) {
                (b"Rfc2898DeriveBytes", b"Pbkdf2") => args.len() >= 3 && iterations_below(2),
                (b"KeyDerivation", b"Pbkdf2") => args.len() >= 4 && iterations_below(3),
                _ => false,
            }
        }
    }
}

fn names_shared_tmp(node: Node, src: &[u8]) -> bool {
    cs_string_value(node, src).is_some_and(|v| {
        let lower = v.to_ascii_lowercase();
        ["/tmp", "/var/tmp", "/usr/tmp", "/dev/shm"]
            .iter()
            .any(|d| {
                lower
                    .strip_prefix(d.as_bytes())
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with(b"/"))
            })
            || contains_ignoring_case(&lower, b":\\\\windows\\\\temp")
            || contains_ignoring_case(&lower, b":\\windows\\temp")
    })
}

fn skips_jwt_verification(node: Node, src: &[u8]) -> bool {
    if node.kind() == "assignment_expression" {
        return sets_false(node, b"RequireSignedTokens", src)
            || sets_false(node, b"ValidateIssuerSigningKey", src);
    }
    let Some(name) = node
        .child_by_field_name("function")
        .and_then(|f| f.child_by_field_name("name"))
    else {
        return false;
    };
    match text(name, src) {
        b"DoNotVerifySignature" => true,
        b"WithVerifySignature" => cs_call_arguments(node)
            .first()
            .is_some_and(|a| text(*a, src) == b"false"),
        // JWT.NET: decoder.Decode(token, key, verify: false)
        b"Decode" => node.child_by_field_name("arguments").is_some_and(|list| {
            let mut cursor = list.walk();
            let args: Vec<Node> = list.named_children(&mut cursor).collect();
            args.iter().any(|a| {
                a.child_by_field_name("name")
                    .is_some_and(|n| text(n, src) == b"verify")
                    && text(*a, src).ends_with(b"false")
            })
        }),
        _ => false,
    }
}

const REQUEST_LIMIT_BYTES: u64 = 8_000_000;

fn lifts_request_limit(attribute: Node, src: &[u8]) -> bool {
    let Some(name) = attribute.child_by_field_name("name") else {
        return false;
    };
    let name = simple_name(name, src);
    let name = name.strip_suffix(b"Attribute").unwrap_or(name);
    let args = attribute_arguments(attribute);
    match name {
        b"DisableRequestSizeLimit" => true,
        b"RequestSizeLimit" => args
            .first()
            .is_some_and(|(_, v)| cs_integer(*v, src).is_some_and(|n| n > REQUEST_LIMIT_BYTES)),
        b"RequestFormLimits" => args.iter().any(|(n, v)| {
            n.is_some_and(|n| text(n, src) == b"MultipartBodyLengthLimit")
                && cs_integer(*v, src).is_some_and(|n| n > REQUEST_LIMIT_BYTES)
        }),
        _ => false,
    }
}

fn disables_request_validation(attribute: Node, src: &[u8]) -> bool {
    let named = attribute.child_by_field_name("name").is_some_and(|n| {
        matches!(
            simple_name(n, src),
            b"ValidateInput" | b"ValidateInputAttribute"
        )
    });
    named
        && attribute_arguments(attribute)
            .first()
            .is_some_and(|(_, v)| text(*v, src) == b"false")
}

#[cfg(test)]
mod tests {
    use super::super::cs::tests::flagged;

    #[test]
    fn crypto() {
        let src = "class A {\nvoid F() {\nMD5.Create();\nSystem.Security.Cryptography.SHA1.HashData(d);\nnew SHA1Managed();\nHashAlgorithm.Create(\"MD5\");\nSHA256.Create();\nDES.Create();\nnew TripleDESCryptoServiceProvider();\nSymmetricAlgorithm.Create(\"RC2\");\nAes.Create();\naes.Mode = CipherMode.ECB;\naes.Mode = CipherMode.CBC;\nrsa.Encrypt(d, RSAEncryptionPadding.Pkcs1);\n}\n}";
        assert_eq!(flagged("cs/weak-hash", src), [3, 4, 5, 6]);
        assert_eq!(flagged("cs/weak-cipher", src), [8, 9, 10]);
        assert_eq!(flagged("cs/insecure-cipher-mode", src), [12, 14]);
    }

    #[test]
    fn protocols_and_keys() {
        let src = "class A {\nvoid F() {\np = SslProtocols.Tls11;\np = System.Security.Authentication.SslProtocols.Ssl3;\np = SslProtocols.Tls12 | SslProtocols.Tls13;\nnew RSACryptoServiceProvider(1024);\nRSA.Create(512);\nRSA.Create(2048);\nnew RSACryptoServiceProvider();\nd.AuthenticationType = AuthenticationTypes.Anonymous;\nd.AuthenticationType = AuthenticationTypes.Secure;\n}\n}";
        assert_eq!(flagged("cs/weak-tls-version", src), [3, 4]);
        assert_eq!(flagged("cs/weak-key-size", src), [6, 7]);
        assert_eq!(flagged("cs/ldap-anonymous", src), [10]);
    }

    #[test]
    fn certificate_callbacks() {
        let src = "class A {\nvoid F() {\nServicePointManager.ServerCertificateValidationCallback += (a, b, c, d) => true;\nh.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;\nvar h2 = new HttpClientHandler { ServerCertificateCustomValidationCallback = delegate { return true; } };\nh.ServerCertificateCustomValidationCallback = (a, b, c, d) => d == SslPolicyErrors.None;\nh.ServerCertificateCustomValidationCallback = (a, b, c, d) => { Log(d); return true; };\n}\n}";
        assert_eq!(
            flagged("cs/certificate-validation-disabled", src),
            [3, 4, 5]
        );
    }

    #[test]
    fn strings() {
        let src = "class A {\nconst string A1 = \"Server=x;Password=;\";\nconst string A2 = @\"Server=x;pwd=\";\nconst string A3 = \"Server=x;Password=secret\";\nconst string A4 = \"Server=x;Trusted_Connection=True;Password=;\";\nconst string U1 = \"http://payments.com/api\";\nconst string U2 = \"http://localhost:5000\";\nconst string U3 = \"https://payments.com\";\nconst string U4 = \"http://tempuri.org/IService/Get\";\nconst string U5 = \"http://schemas.microsoft.com/winfx/2006/xaml\";\n}";
        assert_eq!(flagged("cs/empty-db-password", src), [2, 3]);
        assert_eq!(flagged("cs/cleartext-url", src), [6]);
    }
    fn method(body: &str) -> String {
        format!("namespace N;\nclass A {{\nvoid F() {{\n{body}\n}}\n}}\n")
    }

    #[test]
    fn credentials() {
        let src = "namespace N;\nclass A {\nconst string Password = \"hunter22\";\nstring passwordLabel = \"Password\";\nstring ApiKey = \"k3y-8f2a9c\";\nstring SecretName = \"db-secret\";\nstring pwd = \"\";\nstring token = \"App:Auth:Token\";\nconst string Db = \"Server=x;User Id=a;Password=s3cr3t;\";\nconst string Db2 = \"Server=x;Password={0};\";\nvoid F() { o.Password = \"letmein1\"; }\nstring Token = \"****\";\nstring PasswordHash = \"VHdlZXQgJ1F1aWNr\";\n}";
        assert_eq!(flagged("cs/hardcoded-credential", src), [3, 5, 9, 11]);
    }

    #[test]
    fn sql() {
        let src = method(
            "new SqlCommand(\"SELECT * FROM t WHERE id = \" + id, c);\nnew SqlCommand($\"SELECT * FROM t WHERE id = {id}\", c);\nnew SqlCommand(\"SELECT * FROM t WHERE id = @id\", c);\ncmd.CommandText = string.Format(\"DELETE FROM t WHERE id = {0}\", id);\ndb.Database.ExecuteSqlRaw($\"DELETE FROM t WHERE id = {id}\");\ndb.Users.FromSqlInterpolated($\"SELECT * FROM u WHERE id = {id}\");\nnew SqlCommand(\"SELECT \" + \"1\", c);",
        );
        assert_eq!(flagged("cs/sql-built-dynamically", &src), [4, 5, 7, 8]);
    }

    #[test]
    fn cookies_and_xml() {
        let src = method(
            "var o = new CookieOptions { Secure = false, HttpOnly = false };\nc.Secure = true;\nc.HttpOnly = false;\ns.DtdProcessing = DtdProcessing.Parse;\ns.DtdProcessing = DtdProcessing.Prohibit;\nd.XmlResolver = new XmlUrlResolver();\nd.XmlResolver = null;\nr.ProhibitDtd = false;",
        );
        assert_eq!(flagged("cs/cookie-not-secure", &src), [4]);
        assert_eq!(flagged("cs/cookie-not-httponly", &src), [4, 6]);
        assert_eq!(flagged("cs/xxe", &src), [7, 9, 11]);
    }

    #[test]
    fn crypto_classes_and_hashing() {
        let src = "namespace N;\nclass H : HashAlgorithm { }\nclass S : System.Security.Cryptography.SymmetricAlgorithm { }\nclass L : List<int> { }\nclass K {\nvoid F() {\nnew Rfc2898DeriveBytes(p, s);\nnew Rfc2898DeriveBytes(p, s, 10_000);\nnew Rfc2898DeriveBytes(p, s, 600_000, HashAlgorithmName.SHA256);\nRfc2898DeriveBytes.Pbkdf2(p, s, 1000, HashAlgorithmName.SHA256, 32);\nKeyDerivation.Pbkdf2(p, s, KeyDerivationPrf.HMACSHA256, iterationCount: 100_000, numBytesRequested: 32);\nnew Rfc2898DeriveBytes(p, s, iterations);\n}\n}";
        assert_eq!(flagged("cs/custom-crypto", src), [2, 3]);
        assert_eq!(flagged("cs/weak-password-hashing", src), [7, 8, 10]);
    }

    #[test]
    fn processes_and_web() {
        let src = "namespace N;\nclass A {\n[IgnoreAntiforgeryToken] void A1() { }\n[DisableRequestSizeLimit] void A2() { }\n[RequestSizeLimit(100_000_000)] void A3() { }\n[RequestSizeLimit(1_000_000)] void A4() { }\n[RequestFormLimits(MultipartBodyLengthLimit = 209715200)] void A5() { }\n[ValidateInput(false)] void A6() { }\n[ValidateInput(true)] void A7() { }\nvoid F() {\nProcess.Start(\"git\");\nProcess.Start(\"/usr/bin/git\");\nnew ProcessStartInfo(\"cmd.exe\");\nvar i = new ProcessStartInfo { FileName = \"ls\" };\nProcess.Start(\"https://example.com\");\n}\n}";
        assert_eq!(flagged("cs/csrf-disabled", src), [3]);
        assert_eq!(flagged("cs/request-size-unlimited", src), [4, 5, 7]);
        assert_eq!(flagged("cs/request-validation-disabled", src), [8]);
        assert_eq!(flagged("cs/os-command-path", src), [11, 13, 14]);
    }

    #[test]
    fn hosting() {
        let src = "namespace N;\nclass S {\nvoid A(IApplicationBuilder app, IWebHostEnvironment env) {\napp.UseDeveloperExceptionPage();\nif (env.IsDevelopment()) { app.UseDeveloperExceptionPage(); }\nif (!env.IsProduction()) { app.UseDeveloperExceptionPage(); }\np.AllowAnyOrigin();\np.WithOrigins(\"*\");\np.WithOrigins(\"https://a.example\");\nResponse.Headers.Add(\"Access-Control-Allow-Origin\", \"*\");\nResponse.Headers[\"Access-Control-Allow-Origin\"] = \"*\";\n}\n}";
        assert_eq!(flagged("cs/debug-features", src), [4, 6]);
        assert_eq!(flagged("cs/cors-any-origin", src), [7, 8, 10, 11]);
    }

    #[test]
    fn temp_files_jwt_unsafe() {
        let src = "namespace N;\nclass A {\nunsafe void U() { }\nvoid F() {\nFile.WriteAllText(\"/tmp/a.txt\", x);\nvar d = @\"C:\\Windows\\Temp\\a\";\nvar e = \"/tmpfile\";\nvar t = Path.GetTempFileName();\nvar r = Path.GetRandomFileName();\nvar p = new TokenValidationParameters { RequireSignedTokens = false };\nvar j = new JwtBuilder().DoNotVerifySignature().Decode(token);\nvar k = decoder.Decode(token, key, verify: false);\nunsafe { G(); }\n}\n}";
        assert_eq!(flagged("cs/public-tmp", src), [5, 6]);
        assert_eq!(flagged("cs/create-temp-file", src), [8]);
        assert_eq!(flagged("cs/jwt-unverified", src), [10, 11, 12]);
        assert_eq!(flagged("cs/unsafe-code", src), [3, 13]);
    }
}
