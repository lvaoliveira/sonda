//! Java security rules (ADR-0007, batch 6). Queries stay cheap on deep trees:
//! see the notes in `js_modern.rs`.

use super::*;

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "java/sql-built-dynamically",
        name: "SQL queries should not be built from strings",
        description: "Concatenating values into a query lets an attacker change what it does; pass them as parameters.",
        message: "Use a parameterized query instead of building this string.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 15,
        sonar: &[related("S2077")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "executeQuery" "executeUpdate" "execute" "addBatch" "prepareStatement" "prepareCall" "createQuery" "createNativeQuery" "createSQLQuery" "queryForList" "queryForObject" "queryForMap" "queryForRowSet")) @match"#,
            filter: Some(Keep(sql_built_dynamically)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { stmt.executeQuery(\"SELECT * FROM t WHERE id = \" + id); } }",
            good: "class A { void f() { stmt.executeQuery(\"SELECT 1\"); } }",
        }),
    },
    Rule {
        id: "java/cookie-not-secure",
        name: "Cookies should have the secure flag",
        description: "Without `secure`, the cookie is also sent over plain HTTP.",
        message: "Set the secure flag.",
        category: Vulnerability,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S2092")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "setSecure") arguments: (argument_list (false))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { cookie.setSecure(false); } }",
            good: "class A { void f() { cookie.setSecure(true); } }",
        }),
    },
    Rule {
        id: "java/cookie-not-httponly",
        name: "Cookies should have the HttpOnly flag",
        description: "Without HttpOnly, scripts on the page can read the cookie.",
        message: "Set the HttpOnly flag.",
        category: Vulnerability,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S3330")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "setHttpOnly") arguments: (argument_list (false))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { cookie.setHttpOnly(false); } }",
            good: "class A { void f() { cookie.setHttpOnly(true); } }",
        }),
    },
    Rule {
        id: "java/trust-manager-accepts-all",
        name: "Server certificates should be verified",
        description: "A trust manager whose check methods do nothing accepts every certificate.",
        message: "Implement the certificate check.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 30,
        sonar: &[exact("S4830")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration name: (identifier) @n (#any-of? @n "checkServerTrusted" "checkClientTrusted")) @match"#,
            filter: Some(Keep(method_body_is_empty)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class T { public void checkServerTrusted(X509Certificate[] c, String a) {} }",
            good: "class T { public void checkServerTrusted(X509Certificate[] c, String a) { validate(c); } }",
        }),
    },
    Rule {
        id: "java/hostname-verifier-accepts-all",
        name: "Server hostnames should be verified",
        description: "A hostname verifier that always returns true accepts a valid certificate for any other site.",
        message: "Verify the hostname.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 15,
        sonar: &[exact("S5527")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration name: (identifier) @n (#eq? @n "verify")) @match
(field_access field: (identifier) @f (#any-of? @f "ALLOW_ALL_HOSTNAME_VERIFIER" "INSTANCE")) @match"#,
            filter: Some(Keep(accepts_every_hostname)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class V { public boolean verify(String h, SSLSession s) { return true; } }",
            good: "class V { public boolean verify(String h, SSLSession s) { return check(h); } }",
        }),
    },
    Rule {
        id: "java/weak-hash-library",
        name: "Weak hashing algorithms should not be used",
        description: "MD5 and SHA-1 have known collisions and are unsuitable for security purposes.",
        message: "Use SHA-256 or stronger.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S4790")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) @o name: (identifier) @n (#any-of? @o "DigestUtils" "Hashing") (#any-of? @n "md5" "md5Hex" "md5Digest" "sha1" "sha1Hex" "sha1Digest" "getMd5Digest" "getSha1Digest" "md2Hex" "md2")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { DigestUtils.md5Hex(data); } }",
            good: "class A { void f() { DigestUtils.sha256Hex(data); } }",
        }),
    },
    Rule {
        id: "java/weak-cipher",
        name: "Cipher algorithms should be robust",
        description: "DES, RC2, RC4 and Blowfish are broken or have small blocks.",
        message: "Use AES.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 15,
        sonar: &[exact("S5547")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) @o name: (identifier) @n arguments: (argument_list . (string_literal) @a) (#eq? @o "Cipher") (#eq? @n "getInstance")) @match"#,
            filter: Some(Keep(is_weak_cipher_name)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Cipher.getInstance(\"DES/CBC/PKCS5Padding\"); } }",
            good: "class A { void f() { Cipher.getInstance(\"AES/GCM/NoPadding\"); } }",
        }),
    },
    Rule {
        id: "java/insecure-cipher-mode",
        name: "Encryption algorithms should be used with secure mode and padding",
        description: "ECB leaks patterns, and CBC with PKCS5 padding is open to padding-oracle attacks.",
        message: "Use an authenticated mode such as GCM.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 15,
        sonar: &[exact("S5542")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) @o name: (identifier) @n arguments: (argument_list . (string_literal) @a) (#eq? @o "Cipher") (#eq? @n "getInstance")) @match"#,
            filter: Some(Keep(is_insecure_cipher_mode)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Cipher.getInstance(\"AES/ECB/PKCS5Padding\"); } }",
            good: "class A { void f() { Cipher.getInstance(\"AES/GCM/NoPadding\"); } }",
        }),
    },
    Rule {
        id: "java/weak-tls-version",
        name: "Weak SSL/TLS protocols should not be used",
        description: "SSL, SSLv3, TLS 1.0 and TLS 1.1 have known attacks.",
        message: "Require TLS 1.2 or later.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S4423")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) @o name: (identifier) @n arguments: (argument_list . (string_literal) @a) (#eq? @o "SSLContext") (#eq? @n "getInstance")) @match"#,
            filter: Some(Keep(is_weak_tls_name)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { SSLContext.getInstance(\"TLSv1\"); } }",
            good: "class A { void f() { SSLContext.getInstance(\"TLSv1.3\"); } }",
        }),
    },
    Rule {
        id: "java/weak-key-size",
        name: "Cryptographic keys should be robust",
        description: "RSA and DSA keys under 2048 bits can be factored with modest resources.",
        message: "Use at least 2048 bits.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S4426")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "initialize")) @match
(object_creation_expression type: (type_identifier) @t (#eq? @t "RSAKeyGenParameterSpec")) @match"#,
            filter: Some(Keep(key_size_below_2048)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { KeyPairGenerator gen = KeyPairGenerator.getInstance(\"RSA\"); gen.initialize(1024); } }",
            good: "class A { void f() { KeyPairGenerator gen = KeyPairGenerator.getInstance(\"RSA\"); gen.initialize(3072); } }",
        }),
    },
    Rule {
        id: "java/jwt-unverified",
        name: "JWTs should be signed and verified",
        description: "Decoding without verifying accepts tokens anyone could have forged.",
        message: "Verify the signature.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 10,
        sonar: &[exact("S5659")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) @o name: (identifier) @n (#eq? @o "JWT") (#eq? @n "decode")) @match
(method_invocation object: (method_invocation name: (identifier) @p (#eq? @p "parser")) name: (identifier) @n2 (#eq? @n2 "parse")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { JWT.decode(token); } }",
            good: "class A { void f() { JWT.require(alg).build().verify(token); } }",
        }),
    },
    Rule {
        id: "java/csrf-disabled",
        name: "CSRF protections should not be disabled",
        description: "Turning the check off lets other sites make requests as the signed-in user.",
        message: "Keep CSRF protection enabled.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[related("S4502")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (method_invocation name: (identifier) @c (#eq? @c "csrf")) name: (identifier) @d (#eq? @d "disable")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { http.csrf().disable(); } }",
            good: "class A { void f() { http.csrf(); } }",
        }),
    },
    Rule {
        id: "java/session-fixation-disabled",
        name: "A new session should be created during user authentication",
        description: "Keeping the pre-login session lets an attacker who planted its id take over the account.",
        message: "Don't disable session fixation protection.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S5876")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (method_invocation name: (identifier) @c (#eq? @c "sessionFixation")) name: (identifier) @d (#eq? @d "none")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { http.sessionManagement().sessionFixation().none(); } }",
            good: "class A { void f() { http.sessionManagement().sessionFixation().newSession(); } }",
        }),
    },
    Rule {
        id: "java/cors-any-origin",
        name: "CORS policies should be restricted to trusted origins",
        description: "Allowing every origin lets any site read the responses on behalf of a signed-in user.",
        message: "List the origins that need access.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 10,
        sonar: &[related("S5122")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "allowedOrigins") arguments: (argument_list (string_literal) @s)) @match
(method_invocation name: (identifier) @n2 (#any-of? @n2 "setHeader" "addHeader")) @match
(marker_annotation name: (identifier) @a (#eq? @a "CrossOrigin")) @match
(annotation name: (identifier) @a2 (#eq? @a2 "CrossOrigin")) @match"#,
            filter: Some(Keep(allows_every_origin)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { response.setHeader(\"Access-Control-Allow-Origin\", \"*\"); } }",
            good: "class A { void f() { response.setHeader(\"Access-Control-Allow-Origin\", \"https://app.example.com\"); } }",
        }),
    },
    Rule {
        id: "java/hardcoded-credential",
        name: "Credentials should not be hard-coded",
        description: "A password or key in source is visible to everyone with the code and stays in its history.",
        message: "Read this credential from the environment or a secret store.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 15,
        sonar: &[related("S6437"), related("S2068"), related("S6418")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(variable_declarator name: (identifier) @n value: (string_literal) @v) @match
(assignment_expression left: [(identifier) (field_access)] @l right: (string_literal) @r) @match
(method_invocation name: (identifier) @m (#any-of? @m "setPassword" "setSecret" "setApiKey" "setToken") arguments: (argument_list . (string_literal) @a)) @match"#,
            filter: Some(Keep(is_hardcoded_credential)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { String password = \"Tr0ub4dor&3\"; } }",
            good: "class A { void f() { String password = System.getenv(\"DB_PASSWORD\"); } }",
        }),
    },
    Rule {
        id: "java/empty-db-password",
        name: "A secure password should be used when connecting to a database",
        description: "An empty password means anyone who can reach the database can use it.",
        message: "Set a strong password.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 5,
        sonar: &[exact("S2115")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) @o name: (identifier) @n (#eq? @o "DriverManager") (#eq? @n "getConnection")) @match"#,
            filter: Some(Keep(third_argument_is_empty)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { DriverManager.getConnection(url, user, \"\"); } }",
            good: "class A { void f() { DriverManager.getConnection(url, user, pw); } }",
        }),
    },
    Rule {
        id: "java/world-permissions",
        name: "File permissions should not be world-accessible",
        description: "Permissions for 'other' let every user on the machine use the file.",
        message: "Remove the permissions for others.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2612")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "fromString" "setReadable" "setWritable" "setExecutable")) @match"#,
            filter: Some(Keep(grants_permissions_to_others)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { PosixFilePermissions.fromString(\"rwxrwxrwx\"); } }",
            good: "class A { void f() { PosixFilePermissions.fromString(\"rw-------\"); } }",
        }),
    },
    Rule {
        id: "java/public-tmp",
        name: "Temporary files should not be created in publicly writable directories",
        description: "Other users can pre-create or swap files in /tmp, so a predictable path can be hijacked.",
        message: "Use Files.createTempFile to create the file.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5443")],
        check: Check::Query {
            langs: JAVA,
            query: r#"((string_literal) @match (#match? @match "^\"/(tmp|var/tmp|dev/shm)(/|\")"))"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { String p = \"/tmp/report.csv\"; } }",
            good: "class A { void f() { Path p = Files.createTempFile(\"report\", \".csv\"); } }",
        }),
    },
    Rule {
        id: "java/create-temp-file",
        name: "Insecure temporary file creation methods should not be used",
        description: "File.createTempFile creates the file with default permissions in a shared directory.",
        message: "Use Files.createTempFile.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5445")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) @o name: (identifier) @n (#eq? @o "File") (#eq? @n "createTempFile")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { File.createTempFile(\"a\", \".b\"); } }",
            good: "class A { void f() { Files.createTempFile(\"a\", \".b\"); } }",
        }),
    },
    Rule {
        id: "java/random-secret",
        name: "Pseudorandom generators should not produce secrets",
        description: "Random and Math.random are predictable; tokens and passwords built from them can be guessed.",
        message: "Use SecureRandom for this value.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 10,
        sonar: &[related("S2245")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(object_creation_expression type: (type_identifier) @t (#eq? @t "Random")) @match
(method_invocation object: (identifier) @o name: (identifier) @n (#eq? @o "Math") (#eq? @n "random")) @match"#,
            filter: Some(Keep(random_feeds_a_secret)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { String sessionToken = Long.toString(new Random().nextLong()); } }",
            good: "class A { void f() { String sessionToken = Long.toString(new SecureRandom().nextLong());\nint jitter = new Random().nextInt(10); } }",
        }),
    },
    Rule {
        id: "java/secure-random-seed",
        name: "Secure random number generators should not output predictable values",
        description: "Seeding SecureRandom with a fixed value makes its output reproducible.",
        message: "Don't seed SecureRandom.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S4347")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "setSeed")) @match
(object_creation_expression type: (type_identifier) @t (#eq? @t "SecureRandom") arguments: (argument_list (_))) @match"#,
            filter: Some(Keep(seeds_secure_random)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { SecureRandom r = new SecureRandom(\"seed\".getBytes()); } }",
            good: "class A { void f() { SecureRandom r = new SecureRandom(); } }",
        }),
    },
    Rule {
        id: "java/ldap-anonymous",
        name: "LDAP connections should be authenticated",
        description: "Authentication 'none' lets anyone read the directory.",
        message: "Authenticate the connection.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S4433")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "put") arguments: (argument_list (field_access field: (identifier) @f (#eq? @f "SECURITY_AUTHENTICATION")) (string_literal) @v (#eq? @v "\"none\""))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { env.put(Context.SECURITY_AUTHENTICATION, \"none\"); } }",
            good: "class A { void f() { env.put(Context.SECURITY_AUTHENTICATION, \"simple\"); } }",
        }),
    },
    Rule {
        id: "java/cleartext-url",
        name: "Clear-text protocols should not be used",
        description: "http, ftp and telnet send data, including credentials, unencrypted. Loopback and private addresses are not reported.",
        message: "Use the encrypted version of this protocol.",
        category: Vulnerability,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[related("S5332")],
        check: Check::Query {
            langs: JAVA,
            query: r#"((string_literal) @match (#match? @match "^\"(http|ftp|telnet)://"))"#,
            filter: Some(Keep(is_public_cleartext_url)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { String api = \"http://api.example-shop.io/v1\"; } }",
            good: "class A { void f() { String api = \"https://api.example-shop.io/v1\";\nString dev = \"http://localhost:8080\"; } }",
        }),
    },
    Rule {
        id: "java/os-command-path",
        name: "OS commands should not rely on PATH resolution",
        description: "A bare command name is looked up on PATH, which an attacker may control.",
        message: "Use the full path of the command.",
        category: Vulnerability,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S4036")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (method_invocation name: (identifier) @g (#eq? @g "getRuntime")) name: (identifier) @n (#eq? @n "exec") arguments: (argument_list . (string_literal) @c)) @match
(object_creation_expression type: (type_identifier) @t (#eq? @t "ProcessBuilder") arguments: (argument_list . (string_literal) @c2)) @match"#,
            filter: Some(Keep(command_is_resolved_through_path)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Runtime.getRuntime().exec(\"ls -l\"); } }",
            good: "class A { void f() { Runtime.getRuntime().exec(\"/bin/ls -l\"); } }",
        }),
    },
    Rule {
        id: "java/requested-session-id",
        name: "HttpServletRequest.getRequestedSessionId() should not be used",
        description: "It returns the id the client sent, which may be stale or forged.",
        message: "Use getSession().getId().",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S2254")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "getRequestedSessionId")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { String id = request.getRequestedSessionId(); } }",
            good: "class A { void f() { String id = request.getSession().getId(); } }",
        }),
    },
    Rule {
        id: "java/jackson-unsafe-typing",
        name: "Jackson deserialization should not use unsafe configuration",
        description: "Default typing lets the payload choose which classes to instantiate.",
        message: "Don't enable default typing.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 15,
        sonar: &[exact("S4544")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "enableDefaultTyping")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { mapper.enableDefaultTyping(); } }",
            good: "class A { void f() { mapper.disableDefaultTyping(); } }",
        }),
    },
    Rule {
        id: "java/aws-access-key",
        name: "Long-term AWS access keys should not be used directly in code",
        description: "An access key ID in source identifies a credential that can be abused if the code leaks.",
        message: "Use an IAM role or environment credentials.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 15,
        sonar: &[exact("S6263")],
        check: Check::Query {
            langs: JAVA,
            query: r#"((string_literal) @match (#match? @match "AKIA[0-9A-Z]{16}"))"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { String key = \"AKIAIOSFODNN7EXAMPLE\"; } }",
            good: "class A { void f() { String key = System.getenv(\"AWS_ACCESS_KEY_ID\"); } }",
        }),
    },
    Rule {
        id: "java/predictable-iv",
        name: "Cipher Block Chaining IVs should be unpredictable",
        description: "A fixed IV lets an attacker recognize repeated messages and mount chosen-plaintext attacks.",
        message: "Generate a random IV for every message.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S3329")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(object_creation_expression type: (type_identifier) @t (#eq? @t "IvParameterSpec") arguments: (argument_list [(array_creation_expression) (method_invocation object: (string_literal))])) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { new IvParameterSpec(\"0123456789abcdef\".getBytes()); } }",
            good: "class A { void f() { new IvParameterSpec(randomBytes); } }",
        }),
    },
    Rule {
        id: "java/request-mapping-any-method",
        name: "HTTP routes should restrict allowed HTTP methods",
        description: "Without a method, the route also answers state-changing verbs such as DELETE.",
        message: "Use @GetMapping or set the method.",
        category: Vulnerability,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S3752")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(marker_annotation name: (identifier) @a (#eq? @a "RequestMapping")) @match
(annotation name: (identifier) @a2 (#eq? @a2 "RequestMapping")) @match"#,
            filter: Some(Keep(request_mapping_lacks_method)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { @RequestMapping(\"/x\") void f() {} }",
            good: "class A { @GetMapping(\"/x\") void f() {} }",
        }),
    },
    Rule {
        id: "java/webview-file-access",
        name: "WebViews should not allow unrestricted file access",
        description: "File access from a WebView lets pages read local files.",
        message: "Disable this file access.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6363")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "setAllowFileAccess" "setAllowUniversalAccessFromFileURLs" "setAllowFileAccessFromFileURLs" "setAllowContentAccess") arguments: (argument_list (true))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { settings.setAllowFileAccess(true); } }",
            good: "class A { void f() { settings.setAllowFileAccess(false); } }",
        }),
    },
    Rule {
        id: "java/android-external-storage",
        name: "Sensitive data should not be stored in Android external storage",
        description: "Any app with storage permission can read external storage.",
        message: "Use internal storage for sensitive data.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S5324")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "getExternalStorageDirectory" "getExternalFilesDir" "getExternalStoragePublicDirectory" "getExternalCacheDir")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { File d = Environment.getExternalStorageDirectory(); } }",
            good: "class A { void f() { File d = context.getFilesDir(); } }",
        }),
    },
    Rule {
        id: "java/broadcast-without-permission",
        name: "Intents should not be broadcast or registered without a permission",
        description: "Without a permission, any app can receive or send the broadcast.",
        message: "Pass a permission.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5320")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "sendBroadcast" "registerReceiver")) @match"#,
            filter: Some(Keep(broadcast_lacks_permission)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { context.sendBroadcast(intent); } }",
            good: "class A { void f() { context.sendBroadcast(intent, \"com.example.PERM\"); } }",
        }),
    },
];

// ---------------------------------------------------- filters

pub(super) fn text<'a>(node: Node, src: &'a [u8]) -> &'a [u8] {
    &src[node.byte_range()]
}

pub(super) fn contains_ignoring_case(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|w| w.eq_ignore_ascii_case(needle))
}

/// A string literal's characters between its quotes; None for text blocks.
pub(super) fn string_value<'s>(string: Node, src: &'s [u8]) -> Option<&'s [u8]> {
    if string.kind() != "string_literal" {
        return None;
    }
    let t = text(string, src);
    if t.starts_with(b"\"\"\"") {
        return None;
    }
    (t.len() >= 2).then(|| &t[1..t.len() - 1])
}

pub(super) fn call_arguments(call: Node) -> Vec<Node> {
    let Some(args) = call.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut cursor = args.walk();
    args.named_children(&mut cursor)
        .filter(|a| !matches!(a.kind(), "line_comment" | "block_comment"))
        .collect()
}

pub(super) fn method_name<'s>(call: Node, src: &'s [u8]) -> &'s [u8] {
    call.child_by_field_name("name")
        .map_or(&b""[..], |n| text(n, src))
}

fn first_string(call: Node, src: &[u8]) -> Option<String> {
    call_arguments(call)
        .first()
        .and_then(|a| string_value(*a, src))
        .map(|v| String::from_utf8_lossy(v).into_owned())
}

fn integer_value(node: Node, src: &[u8]) -> Option<u64> {
    if node.kind() != "decimal_integer_literal" {
        return None;
    }
    String::from_utf8_lossy(text(node, src))
        .trim_end_matches(['l', 'L'])
        .replace('_', "")
        .parse()
        .ok()
}

fn sql_built_dynamically(call: Node, src: &[u8]) -> bool {
    let Some(query) = call_arguments(call).into_iter().next() else {
        return false;
    };
    match query.kind() {
        "binary_expression" => {
            let op = query
                .child_by_field_name("operator")
                .map_or(&b""[..], |o| text(o, src));
            op == b"+"
                && !is_all_literals(query)
                && find_node(query, |n| n.kind() == "string_literal").is_some()
        }
        "method_invocation" => {
            matches!(
                method_name(query, src),
                b"format" | b"formatted" | b"concat"
            ) && !call_arguments(query).is_empty()
        }
        _ => false,
    }
}

pub(super) fn is_all_literals(expr: Node) -> bool {
    match expr.kind() {
        "string_literal" | "decimal_integer_literal" | "character_literal" => true,
        "binary_expression" => {
            expr.child_by_field_name("left")
                .is_some_and(is_all_literals)
                && expr
                    .child_by_field_name("right")
                    .is_some_and(is_all_literals)
        }
        "parenthesized_expression" => expr.named_child(0).is_some_and(is_all_literals),
        _ => false,
    }
}

/// The first node below `root` that satisfies `pred`.
pub(super) fn find_node<'t>(root: Node<'t>, pred: impl Fn(Node<'t>) -> bool) -> Option<Node<'t>> {
    let mut cursor = root.walk();
    if !cursor.goto_first_child() {
        return None;
    }
    loop {
        if pred(cursor.node()) {
            return Some(cursor.node());
        }
        if cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return None;
            }
        }
    }
}

fn method_body_is_empty(method: Node, _: &[u8]) -> bool {
    method
        .child_by_field_name("body")
        .is_some_and(|b| b.named_child_count() == 0)
}

fn accepts_every_hostname(node: Node, src: &[u8]) -> bool {
    if node.kind() == "field_access" {
        let object = node
            .child_by_field_name("object")
            .map_or(&b""[..], |o| text(o, src));
        let field = node
            .child_by_field_name("field")
            .map_or(&b""[..], |o| text(o, src));
        return field == b"ALLOW_ALL_HOSTNAME_VERIFIER"
            || (field == b"INSTANCE" && object.ends_with(b"NoopHostnameVerifier"));
    }
    let Some(params) = node.child_by_field_name("parameters") else {
        return false;
    };
    if params.named_child_count() != 2 {
        return false;
    }
    let Some(body) = node.child_by_field_name("body") else {
        return false;
    };
    let mut cursor = body.walk();
    let statements: Vec<Node> = body
        .named_children(&mut cursor)
        .filter(|n| !matches!(n.kind(), "line_comment" | "block_comment"))
        .collect();
    matches!(statements.as_slice(), [only]
        if only.kind() == "return_statement" && only.named_child(0).is_some_and(|v| v.kind() == "true"))
}

fn is_weak_cipher_name(call: Node, src: &[u8]) -> bool {
    first_string(call, src).is_some_and(|name| {
        let head = name.split('/').next().unwrap_or("").to_ascii_lowercase();
        matches!(
            head.as_str(),
            "des" | "desede" | "rc2" | "rc4" | "arcfour" | "blowfish" | "tripledes"
        )
    })
}

fn is_insecure_cipher_mode(call: Node, src: &[u8]) -> bool {
    // A broken algorithm is reported by its own rule.
    if is_weak_cipher_name(call, src) {
        return false;
    }
    first_string(call, src).is_some_and(|name| {
        let lower = name.to_ascii_lowercase();
        lower == "aes"
            || lower.contains("/ecb")
            || lower.ends_with("/cbc/pkcs5padding")
            || (lower.starts_with("rsa") && lower.contains("pkcs1padding"))
    })
}

fn is_weak_tls_name(call: Node, src: &[u8]) -> bool {
    first_string(call, src).is_some_and(|name| {
        matches!(
            name.as_str(),
            "SSL" | "SSLv2" | "SSLv3" | "TLSv1" | "TLSv1.1"
        )
    })
}

fn key_size_below_2048(node: Node, src: &[u8]) -> bool {
    let small = |n: Node| integer_value(n, src).is_some_and(|v| v < 2048);
    if node.kind() == "object_creation_expression" {
        return call_arguments(node).first().is_some_and(|a| small(*a));
    }
    // `gen.initialize(1024)`: only receivers that look like a key generator.
    let receiver = node
        .child_by_field_name("object")
        .map_or(&b""[..], |o| text(o, src));
    let looks_like_key_generator = [&b"gen"[..], b"kpg", b"keypair", b"keygen"]
        .iter()
        .any(|w| contains_ignoring_case(receiver, w));
    looks_like_key_generator && call_arguments(node).first().is_some_and(|a| small(*a))
}

fn allows_every_origin(node: Node, src: &[u8]) -> bool {
    match node.kind() {
        "marker_annotation" => true,
        "annotation" => {
            let t = text(node, src);
            !t.windows(7).any(|w| w == b"origins") || t.windows(3).any(|w| w == b"\"*\"")
        }
        _ => {
            if method_name(node, src) == b"allowedOrigins" {
                return call_arguments(node)
                    .iter()
                    .any(|a| string_value(*a, src).is_some_and(|v| v == b"*"));
            }
            let args = call_arguments(node);
            matches!(args.as_slice(), [h, v]
                if string_value(*h, src).is_some_and(|h| h.eq_ignore_ascii_case(b"Access-Control-Allow-Origin"))
                    && string_value(*v, src).is_some_and(|v| v == b"*"))
        }
    }
}

fn is_hardcoded_credential(node: Node, src: &[u8]) -> bool {
    let (name, value) = match node.kind() {
        "variable_declarator" => (
            node.child_by_field_name("name"),
            node.child_by_field_name("value"),
        ),
        "assignment_expression" => {
            let left = node.child_by_field_name("left");
            let name = left.and_then(|l| {
                if l.kind() == "field_access" {
                    l.child_by_field_name("field")
                } else {
                    Some(l)
                }
            });
            (name, node.child_by_field_name("right"))
        }
        _ => (
            node.child_by_field_name("name"),
            call_arguments(node).first().copied(),
        ),
    };
    let (Some(name), Some(value)) = (name, value) else {
        return false;
    };
    let Some(literal) = string_value(value, src) else {
        return false;
    };
    let lowered = text(name, src).to_ascii_lowercase();
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
    .any(|w| lowered.windows(w.len()).any(|x| x == *w))
        || node.kind() == "method_invocation";
    let describes_location = [
        &b"url"[..],
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
    ]
    .iter()
    .any(|s| lowered.ends_with(s))
        && node.kind() != "method_invocation";
    // "java.net.socks.password" names a property; it is not a password.
    let looks_like_property_key = literal
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_'))
        && literal.iter().any(|b| matches!(b, b'.' | b'-'));
    credential_name
        && !describes_location
        && !looks_like_property_key
        && literal.len() >= 4
        && !literal.contains(&b' ')
        && !literal.contains(&b'{')
        && !literal.contains(&b'%')
        && !literal.starts_with(b"$")
        && !literal.starts_with(b"<")
        && !literal.iter().all(|&b| b == b'*' || b == b'x' || b == b'X')
}

fn third_argument_is_empty(call: Node, src: &[u8]) -> bool {
    call_arguments(call)
        .get(2)
        .and_then(|a| string_value(*a, src))
        .is_some_and(<[u8]>::is_empty)
}

fn grants_permissions_to_others(call: Node, src: &[u8]) -> bool {
    let args = call_arguments(call);
    match method_name(call, src) {
        b"fromString" => {
            let object = call
                .child_by_field_name("object")
                .map_or(&b""[..], |o| text(o, src));
            object.ends_with(b"PosixFilePermissions")
                && args
                    .first()
                    .and_then(|a| string_value(*a, src))
                    .is_some_and(|s| s.len() == 9 && &s[6..] != b"---")
        }
        _ => matches!(args.as_slice(), [_, owner_only] if owner_only.kind() == "false"),
    }
}

pub(super) const SECRET_WORDS: &[&[u8]] = &[
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

fn random_feeds_a_secret(node: Node, src: &[u8]) -> bool {
    let mut context = node.parent();
    let mut hops = 0;
    while let Some(n) = context {
        if matches!(
            n.kind(),
            "local_variable_declaration"
                | "expression_statement"
                | "return_statement"
                | "field_declaration"
        ) {
            break;
        }
        hops += 1;
        if hops > 64 {
            return false;
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
    if mentions(text(statement, src)) {
        return true;
    }
    let mut owner = statement.parent();
    let mut hops = 0;
    while let Some(n) = owner {
        if n.kind() == "method_declaration" {
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

fn seeds_secure_random(node: Node, src: &[u8]) -> bool {
    if node.kind() == "object_creation_expression" {
        return true;
    }
    node.child_by_field_name("object")
        .is_some_and(|o| contains_ignoring_case(text(o, src), b"secure"))
}

pub(super) fn is_public_cleartext_url(string: Node, src: &[u8]) -> bool {
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
        || host.ends_with("sun.com")
        || host.ends_with("java.com")
        || host.ends_with("jboss.org")
        || host.ends_with("springframework.org")
        || host.ends_with("apache.org")
        || host.ends_with("xml.org")
        || host.starts_with("schemas.")
        || host.starts_with("xmlns")
        || host.starts_with("maven.")
}

fn command_is_resolved_through_path(node: Node, src: &[u8]) -> bool {
    let command = call_arguments(node)
        .first()
        .and_then(|a| string_value(*a, src))
        .map(|c| String::from_utf8_lossy(c).into_owned());
    command.is_some_and(|c| {
        let first = c.split_whitespace().next().unwrap_or("");
        !first.is_empty() && !first.contains('/') && !first.contains('\\')
    })
}

fn request_mapping_lacks_method(annotation: Node, src: &[u8]) -> bool {
    // On a class it is only a path prefix.
    let on_method = annotation
        .parent()
        .and_then(|m| m.parent())
        .is_some_and(|d| d.kind() == "method_declaration");
    if !on_method {
        return false;
    }
    let t = text(annotation, src);
    !t.windows(6).any(|w| w == b"method")
}

fn broadcast_lacks_permission(call: Node, src: &[u8]) -> bool {
    let count = call_arguments(call).len();
    match method_name(call, src) {
        b"sendBroadcast" => count == 1,
        _ => count == 2,
    }
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
        let file = analyze("t", Lang::Java, src, &rules, &cfg, far_deadline()).unwrap();
        file.issues
            .iter()
            .filter(|i| i.rule == rule)
            .map(|i| i.line)
            .collect()
    }

    #[test]
    fn sql_formatting_forms() {
        let src = "class A { void f() {\ns.executeQuery(\"SELECT \" + id);\ns.executeQuery(String.format(\"SELECT %s\", id));\ns.executeQuery(\"SELECT \" + \"1\");\ns.executeQuery(\"SELECT 1\");\ns.prepareStatement(\"SELECT ?\");\ns.executeQuery(query);\n} }";
        assert_eq!(flagged("java/sql-built-dynamically", src), [2, 3]);
    }

    #[test]
    fn trust_and_hostname_checks() {
        let src = "class T {\npublic void checkServerTrusted(X509Certificate[] c, String a) {}\npublic void checkClientTrusted(X509Certificate[] c, String a) { check(c); }\npublic boolean verify(String h, SSLSession s) { return true; }\npublic boolean verify(String h, SSLSession s) { return h.equals(\"x\"); }\nObject o = NoopHostnameVerifier.INSTANCE;\nObject p = Foo.INSTANCE;\n}";
        assert_eq!(flagged("java/trust-manager-accepts-all", src), [2]);
        assert_eq!(flagged("java/hostname-verifier-accepts-all", src), [4, 6]);
    }

    #[test]
    fn ciphers_and_protocols() {
        let src = "class A { void f() throws Exception {\nCipher.getInstance(\"DES/CBC/PKCS5Padding\");\nCipher.getInstance(\"AES\");\nCipher.getInstance(\"AES/ECB/PKCS5Padding\");\nCipher.getInstance(\"AES/GCM/NoPadding\");\nSSLContext.getInstance(\"TLSv1\");\nSSLContext.getInstance(\"TLSv1.3\");\n} }";
        assert_eq!(flagged("java/weak-cipher", src), [2]);
        assert_eq!(flagged("java/insecure-cipher-mode", src), [3, 4]);
        assert_eq!(flagged("java/weak-tls-version", src), [6]);
    }

    #[test]
    fn key_sizes() {
        let src = "class A { void f() throws Exception {\nkeyGen.initialize(1024);\nkeyGen.initialize(4096);\nother.initialize(1024);\nnew RSAKeyGenParameterSpec(512, E);\n} }";
        assert_eq!(flagged("java/weak-key-size", src), [2, 5]);
    }

    #[test]
    fn credentials() {
        let src = "class A {\nString password = \"Tr0ub4dor&3\";\nString passwordField = \"abcdefgh\";\nString empty = \"\";\nString token = \"xxxx\";\nString JAVA_PASSWORD = \"java.net.socks.password\";\nvoid f() {\nthis.apiKey = \"abcd1234\";\nc.setPassword(\"hunter22\");\nc.setPassword(pw);\nString name = \"abcdefgh\";\n}\n}";
        assert_eq!(flagged("java/hardcoded-credential", src), [2, 8, 9]);
    }

    #[test]
    fn cors_forms() {
        let src = "class A {\n@CrossOrigin\nvoid a() {}\n@CrossOrigin(origins = \"*\")\nvoid b() {}\n@CrossOrigin(origins = \"https://x.io\")\nvoid c() {}\nvoid d() { r.addAllowedOrigins(); registry.allowedOrigins(\"*\"); registry.allowedOrigins(\"https://x.io\"); res.setHeader(\"Access-Control-Allow-Origin\", \"*\"); res.setHeader(\"X-Foo\", \"*\"); }\n}";
        assert_eq!(flagged("java/cors-any-origin", src), [2, 4, 8, 8]);
    }

    #[test]
    fn permissions_and_tmp() {
        let src = "class A { void f() {\nPosixFilePermissions.fromString(\"rwxrwxrwx\");\nPosixFilePermissions.fromString(\"rwx------\");\nPosixFilePermissions.fromString(\"rwxr-xr--\");\nfile.setReadable(true, false);\nfile.setReadable(true, true);\nfile.setReadable(true);\nString p = \"/tmp/x\";\nString q = \"/home/tmp\";\n} }";
        assert_eq!(flagged("java/world-permissions", src), [2, 4, 5]);
        assert_eq!(flagged("java/public-tmp", src), [8]);
    }

    #[test]
    fn random_and_secure_random() {
        let src = "class A {\nString token = Long.toString(new Random().nextLong());\nint jitter = new Random().nextInt(5);\nString makeSessionId() { return \"\" + Math.random(); }\nint pick() { return (int) Math.random(); }\nvoid f() { secureRandom.setSeed(1); random.setSeed(1); }\nSecureRandom s = new SecureRandom(seed);\nSecureRandom t = new SecureRandom();\nRandom u = new Random(); }";
        assert_eq!(flagged("java/random-secret", src), [2, 4]);
        assert_eq!(flagged("java/secure-random-seed", src), [6, 7]);
    }

    #[test]
    fn urls_and_commands() {
        let src = "class A { void f() throws Exception {\nString a = \"http://api.example-shop.io/x\";\nString b = \"http://localhost:8080\";\nString c = \"http://192.168.1.5/x\";\nString d = \"http://www.w3.org/1999/xhtml\";\nRuntime.getRuntime().exec(\"ls -l\");\nRuntime.getRuntime().exec(\"/bin/ls -l\");\nnew ProcessBuilder(\"git\", \"status\");\nnew ProcessBuilder(\"/usr/bin/git\");\n} }";
        assert_eq!(flagged("java/cleartext-url", src), [2]);
        assert_eq!(flagged("java/os-command-path", src), [6, 8]);
    }

    #[test]
    fn spring_and_android() {
        let src = "@RequestMapping(\"/base\")\nclass B {}\nclass A {\n@RequestMapping(\"/a\")\nvoid a() {}\n@RequestMapping(value = \"/b\", method = RequestMethod.POST)\nvoid b() {}\nvoid c() { ctx.sendBroadcast(i); ctx.sendBroadcast(i, p); ctx.registerReceiver(r, f); ctx.registerReceiver(r, f, p, h); }\n}";
        assert_eq!(flagged("java/request-mapping-any-method", src), [4]);
        assert_eq!(flagged("java/broadcast-without-permission", src), [8, 8]);
    }

    #[test]
    fn db_passwords() {
        let src = "class A { void f() throws Exception {\nDriverManager.getConnection(url, u, \"\");\nDriverManager.getConnection(url, u, pw);\nDriverManager.getConnection(url);\n} }";
        assert_eq!(flagged("java/empty-db-password", src), [2]);
    }
}
