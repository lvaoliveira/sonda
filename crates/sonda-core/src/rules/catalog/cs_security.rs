//! C# security rules (ADR-0007, ADR-0015, batch 1). Queries stay cheap on
//! deep trees: see the notes in `js_modern.rs`.

use super::cs::{cs_string_value, simple_name};
use super::java_bugs::operator_text;
use super::java_security::{contains_ignoring_case, is_public_cleartext_url, text};
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
}
