//! Java rules, part 6 (ADR-0007, batch 13): Spring and persistence, Android
//! and web security, records and newer-Java idioms, and a set of bug and
//! convention checks. Queries stay cheap on deep trees: see `js_modern.rs`.

use super::java_bugs::{has_annotation, has_modifier, statements};
use super::java_extra::{class_members, declared_field, declared_type, name_text, type_text};
use super::java_last::{count_nodes, literal_kind};
use super::java_security::{call_arguments, find_node, method_name, string_value, text};
use super::java_smells::{children_of_kind, count_word, declarator_names};
use super::*;

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "java/configuration-field-injection",
        name: "Factory method injection should be used in @Configuration classes",
        description: "Autowired fields in a configuration class are injected before @Bean methods run, and hide the dependencies.",
        message: "Take the dependency as a @Bean method parameter.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S3305")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Find(configuration_autowires_a_field)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "@Configuration class A { @Autowired B b; }",
            good: "@Configuration class A { @Bean C c(B b) { return new C(b); } }",
        }),
    },
    Rule {
        id: "java/bean-method-name",
        name: "Bean names should adhere to the naming conventions",
        description: "The method name becomes the bean name.",
        message: "Use camelCase.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6830")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Keep(bean_method_name_is_wrong)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { @Bean B My_Bean() { return null; } }",
            good: "class A { @Bean B myBean() { return null; } }",
        }),
    },
    Rule {
        id: "java/bean-method-called-directly",
        name: "@Bean methods for Singleton should not be invoked in @Configuration when proxyBeanMethods is false",
        description: "Without the proxy each direct call builds a new instance.",
        message: "Take the bean as a parameter.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S6838")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Find(bean_method_called_without_proxy)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "@Configuration(proxyBeanMethods = false) class A { @Bean B b() { return new B(); } @Bean C c() { return new C(b()); } }",
            good: "@Configuration(proxyBeanMethods = false) class A { @Bean B b() { return new B(); } @Bean C c(B b) { return new C(b); } }",
        }),
    },
    Rule {
        id: "java/spel-unbalanced",
        name: "SpEL expression should have a valid syntax",
        description: "An unclosed #{ or ${ is a startup error.",
        message: "Close the expression.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6857")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(annotation name: (identifier) @n (#eq? @n "Value")) @match"#,
            filter: Some(Keep(spel_braces_are_unbalanced)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { @Value(\"#{systemProperties['x']\") String x; }",
            good: "class A { @Value(\"#{systemProperties['x']}\") String x; }",
        }),
    },
    Rule {
        id: "java/cache-on-interface",
        name: "@Cache* annotations should only be applied on concrete classes",
        description: "Proxy-based caching does not see annotations on interfaces under CGLIB.",
        message: "Annotate the implementation.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7180")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(interface_declaration) @match"#,
            filter: Some(Find(interface_has_cache_annotation)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "interface A { @Cacheable(\"x\") String f(); }",
            good: "interface A { String f(); }",
        }),
    },
    Rule {
        id: "java/debug-enabled",
        name: "Debugging features should not be enabled in production",
        description: "Debug output shows internals to anyone who can read it.",
        message: "Remove debug mode.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S4507")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(element_value_pair key: (identifier) @k (#eq? @k "debug") value: (true)) @match
(method_invocation name: (identifier) @n (#eq? @n "debug") arguments: (argument_list (true))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "@EnableWebSecurity(debug = true) class A {}",
            good: "@EnableWebSecurity class A {}",
        }),
    },
    Rule {
        id: "java/autoescape-disabled",
        name: "Auto-escaping in HTML template engines should not be disabled",
        description: "Without it every value is an XSS vector.",
        message: "Keep escaping on.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S5247")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "escapeHTML" "setAutoEscape" "setAutoescape") arguments: (argument_list (false))) @match
(field_access field: (identifier) @f (#eq? @f "DISABLE_AUTO_ESCAPING_POLICY")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Mustache.compiler().escapeHTML(false); } }",
            good: "class A { void f() { Mustache.compiler(); } }",
        }),
    },
    Rule {
        id: "java/upload-size-unlimited",
        name: "HTTP request content length should be limited",
        description: "Unbounded uploads exhaust memory and disk.",
        message: "Set a limit below 8 MB.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S5693")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "setMaxUploadSize" "setMaxFileSize" "setMaxRequestSize" "setMaxInMemorySize")) @match"#,
            filter: Some(Keep(size_limit_is_too_large)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { resolver.setMaxUploadSize(-1); } }",
            good: "class A { void f() { resolver.setMaxUploadSize(1000000); } }",
        }),
    },
    Rule {
        id: "java/server-version-disclosed",
        name: "Web application technologies should not disclose version information",
        description: "The version tells attackers which exploits to try.",
        message: "Turn the header off.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5689")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "setSendServerVersion" "setSendXPoweredBy") arguments: (argument_list (true))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { config.setSendServerVersion(true); } }",
            good: "class A { void f() { config.setSendServerVersion(false); } }",
        }),
    },
    Rule {
        id: "java/security-rule-order",
        name: "HttpSecurity URL patterns should be correctly ordered",
        description: "Rules after anyRequest() are never reached.",
        message: "Put specific patterns first.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S4601")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "antMatchers" "mvcMatchers" "regexMatchers" "requestMatchers")) @match"#,
            filter: Some(Keep(chain_has_any_request_before)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { http.authorizeRequests().anyRequest().authenticated().antMatchers(\"/open\").permitAll(); } }",
            good: "class A { void f() { http.authorizeRequests().antMatchers(\"/open\").permitAll().anyRequest().authenticated(); } }",
        }),
    },
    Rule {
        id: "java/password-fast-hash",
        name: "Passwords should not be stored in plaintext or with a fast hashing algorithm",
        description: "MD5 and SHA-2 are cheap to brute-force.",
        message: "Use bcrypt, scrypt or argon2.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 30,
        sonar: &[exact("S5344")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) @o name: (identifier) @n (#eq? @o "DigestUtils") (#match? @n "^(md5|sha1|sha256|sha384|sha512)")) @match"#,
            filter: Some(Keep(hashes_a_password)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { String h = DigestUtils.sha256Hex(password); } }",
            good: "class A { void f() { String h = encoder.encode(password); } }",
        }),
    },
    Rule {
        id: "java/receiver-without-permission",
        name: "Android broadcast receivers should not be registered without a permission",
        description: "Any app can send the broadcast.",
        message: "Pass a broadcast permission.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5322")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "registerReceiver")) @match"#,
            filter: Some(Keep(registers_with_two_arguments)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { registerReceiver(receiver, filter); } }",
            good: "class A { void f() { registerReceiver(receiver, filter, PERMISSION, null); } }",
        }),
    },
    Rule {
        id: "java/keystore-without-user-auth",
        name: "Android KeyStore keys should require user authentication",
        description: "A key anyone with the device can use protects nothing.",
        message: "Call setUserAuthenticationRequired(true).",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S6288")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "build")) @match"#,
            filter: Some(Keep(key_spec_lacks_user_authentication)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { KeyGenParameterSpec s = new KeyGenParameterSpec.Builder(\"k\", 3).setBlockModes(\"GCM\").build(); } }",
            good: "class A { void f() { KeyGenParameterSpec s = new KeyGenParameterSpec.Builder(\"k\", 3).setUserAuthenticationRequired(true).build(); } }",
        }),
    },
    Rule {
        id: "java/biometric-without-crypto",
        name: "Biometric authentication should be cryptographically bound",
        description: "Without a CryptoObject the result can be bypassed by hooking the callback.",
        message: "Pass a CryptoObject.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S6293")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "authenticate")) @match"#,
            filter: Some(Keep(prompt_authenticates_without_crypto)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { biometricPrompt.authenticate(info); } }",
            good: "class A { void f() { biometricPrompt.authenticate(info, cryptoObject); } }",
        }),
    },
    Rule {
        id: "java/database-key-literal",
        name: "Mobile database encryption keys should not be disclosed",
        description: "A key in the app is a key in every copy of the app.",
        message: "Derive it from the Keystore.",
        category: Vulnerability,
        severity: Blocker,
        effort_minutes: 15,
        sonar: &[exact("S6301")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "getWritableDatabase" "getReadableDatabase" "openOrCreateDatabase") arguments: (argument_list (string_literal))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { db.getWritableDatabase(\"secret\"); } }",
            good: "class A { void f() { db.getWritableDatabase(key); } }",
        }),
    },
    Rule {
        id: "java/webview-javascript-interface",
        name: "Native methods should not be exposed to untrusted WebView content",
        description: "A bridge object is callable from any script the page loads.",
        message: "Don't expose it, or only load trusted content.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 15,
        sonar: &[exact("S7409")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "addJavascriptInterface")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { webView.addJavascriptInterface(bridge, \"app\"); } }",
            good: "class A { void f() { webView.loadUrl(url); } }",
        }),
    },
    Rule {
        id: "java/persistent-device-id",
        name: "Avoid using persistent unique identifiers",
        description: "They track a user across apps and resets.",
        message: "Use an app-scoped identifier.",
        category: Vulnerability,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S7435")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "getDeviceId" "getImei" "getSimSerialNumber" "getSubscriberId" "getMeid")) @match
(field_access field: (identifier) @f (#eq? @f "ANDROID_ID")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { String id = tm.getImei(); } }",
            good: "class A { void f() { String id = UUID.randomUUID().toString(); } }",
        }),
    },
    Rule {
        id: "java/exact-alarm",
        name: "Exact alarms should not be abused",
        description: "They wake the device and cost battery.",
        message: "Use an inexact alarm.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S6891")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "setExact" "setExactAndAllowWhileIdle")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { alarm.setExact(0, 1L, intent); } }",
            good: "class A { void f() { alarm.set(0, 1L, intent); } }",
        }),
    },
    Rule {
        id: "java/sealed-permits-redundant",
        name: "Permitted types of a sealed class should be omitted if they are declared in the same file",
        description: "The compiler infers them.",
        message: "Remove the permits clause.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6217")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration (permits) @match)"#,
            filter: Some(Keep(permitted_types_are_in_the_file)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "sealed class A permits B {}\nfinal class B extends A {}",
            good: "sealed class A {}\nfinal class B extends A {}",
        }),
    },
    Rule {
        id: "java/record-serial-version-zero",
        name: "serialVersionUID field should not be set to 0L in records",
        description: "Records ignore it, and 0L suggests it was copied blindly.",
        message: "Remove the field.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6219")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(record_declaration) @match"#,
            filter: Some(Find(record_declares_zero_uid)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "record R(int x) implements Serializable { private static final long serialVersionUID = 0L; }",
            good: "record R(int x) implements Serializable { }",
        }),
    },
    Rule {
        id: "java/record-serialization-hooks",
        name: "Members ignored during record serialization should not be used",
        description: "Records are serialized by their components; these hooks are never called.",
        message: "Remove them.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6209")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(record_declaration) @match"#,
            filter: Some(Find(record_declares_ignored_hook)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "record R(int x) implements Serializable { private void writeObject(ObjectOutputStream o) {} }",
            good: "record R(int x) implements Serializable { }",
        }),
    },
    Rule {
        id: "java/unused-exception-parameter",
        name: "Unused exception parameter should use the unnamed variable pattern",
        description: "Java 22 allows _ for a name nobody reads.",
        message: "Rename it to _.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S7467")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(catch_clause) @match"#,
            filter: Some(Keep(catch_parameter_is_unused)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { try { g(); } catch (IOException e) { h(); } } }",
            good: "class A { void f() { try { g(); } catch (IOException _) { h(); } } }",
        }),
    },
    Rule {
        id: "java/redundant-explicit-type",
        name: "Local-Variable Type Inference should be used",
        description: "The type is already on the right-hand side.",
        message: "Use var.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S6212")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(local_variable_declaration type: (type_identifier) @t declarator: (variable_declarator value: (object_creation_expression type: (type_identifier) @c))) @match"#,
            filter: Some(Keep(declares_the_type_it_creates)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { StringBuilder sb = new StringBuilder(); } }",
            good: "class A { void f() { var sb = new StringBuilder(); } }",
        }),
    },
    Rule {
        id: "java/concatenated-text-block",
        name: "String multiline concatenation should be replaced with Text Blocks",
        description: "Three lines joined with + and \\n are a text block.",
        message: "Use a text block.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S6126")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(binary_expression operator: "+") @match"#,
            filter: Some(Keep(joins_lines_with_newlines)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { String s = \"a\\n\" + \"b\\n\" + \"c\"; }",
            good: "class A { String s = \"\"\"\n a\n b\n c\"\"\"; }",
        }),
    },
    Rule {
        id: "java/if-chain-to-switch",
        name: "Use switch instead of if-else chain to compare a variable against multiple cases",
        description: "A chain of comparisons with one variable is a switch.",
        message: "Use a switch.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S6880")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(if_statement) @match"#,
            filter: Some(Keep(compares_one_variable_in_a_chain)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(int x) { if (x == 1) { a(); } else if (x == 2) { b(); } else if (x == 3) { c(); } } }",
            good: "class A { void f(int x) { switch (x) { case 1 -> a(); case 2 -> b(); default -> c(); } } }",
        }),
    },
    Rule {
        id: "java/clamp",
        name: "Use built-in Math.clamp methods",
        description: "Math.min(Math.max(..)) says it indirectly.",
        message: "Use Math.clamp.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6885")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (identifier) @o name: (identifier) @n (#eq? @o "Math") (#any-of? @n "min" "max")) @match"#,
            filter: Some(Keep(nests_min_and_max)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { int v = Math.min(Math.max(x, 0), 10); } }",
            good: "class A { void f() { int v = Math.clamp(x, 0, 10); } }",
        }),
    },
    Rule {
        id: "java/redundant-time-conversion",
        name: "Redundant time instantiation patterns should be simplified",
        description: "LocalDateTime.now().toLocalDate() is LocalDate.now().",
        message: "Call now() on the target type.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S8695")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (method_invocation object: (identifier) @o name: (identifier) @a (#eq? @a "now")) name: (identifier) @n (#any-of? @n "toLocalDate" "toLocalTime" "toLocalDateTime")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { LocalDate d = LocalDateTime.now().toLocalDate(); } }",
            good: "class A { void f() { LocalDate d = LocalDate.now(); } }",
        }),
    },
    Rule {
        id: "java/value-based-identity",
        name: "Value-based classes should be compared using their value",
        description: "== on Optional or a java.time object compares identities, which are not meaningful.",
        message: "Use equals().",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S8696")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(binary_expression operator: ["==" "!="]) @match"#,
            filter: Some(Keep(compares_value_based_by_identity)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { boolean f(Optional<String> a, Optional<String> b) { return a == b; } }",
            good: "class A { boolean f(Optional<String> a, Optional<String> b) { return a.equals(b); } }",
        }),
    },
    Rule {
        id: "java/clock-in-test",
        name: "The system clock should not be used in unit tests",
        description: "A test that reads the clock is flaky.",
        message: "Inject a Clock.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S8692")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation) @match"#,
            filter: Some(Keep(reads_the_clock_in_a_test)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { @Test void t() { Instant.now(); } }",
            good: "class A { @Test void t() { Instant.now(clock); } }",
        }),
    },
    Rule {
        id: "java/scoped-value-ignored",
        name: "ScopedValue.where results should not be ignored",
        description: "The binding only exists inside the returned carrier's run or call.",
        message: "Call run() or call() on the result.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S8432")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(expression_statement (method_invocation object: (identifier) @o name: (identifier) @n (#eq? @o "ScopedValue") (#eq? @n "where")) @match)"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { ScopedValue.where(KEY, 1); } }",
            good: "class A { void f() { ScopedValue.where(KEY, 1).run(task); } }",
        }),
    },
    Rule {
        id: "java/startup-method",
        name: "Methods annotated with @Startup should be non-static, non-producer, and parameter-free",
        description: "Quarkus can't call them otherwise.",
        message: "Fix the signature.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S8911")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Keep(startup_method_has_bad_signature)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { @Startup static void init() {} }",
            good: "class A { @Startup void init() {} }",
        }),
    },
    Rule {
        id: "java/label-in-switch",
        name: "switch statements should not contain non-case labels",
        description: "A label that looks like a case but isn't compiles silently.",
        message: "Remove the label, or make it a case.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1219")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(switch_block_statement_group (labeled_statement) @match)"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(int x) { switch (x) { case 1: done: g(); } } }",
            good: "class A { void f(int x) { switch (x) { case 1: g(); } } }",
        }),
    },
    Rule {
        id: "java/parameter-overwritten",
        name: "Method parameters' initial values should not be ignored",
        description: "The first thing the method does is replace the argument it was given.",
        message: "Use the parameter, or drop it.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S1226")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Find(parameter_overwritten_first)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { int f(int x) { x = 1; return x; } }",
            good: "class A { int f(int x) { int y = x + 1; return y; } }",
        }),
    },
    Rule {
        id: "java/enum-key-map",
        name: "Maps with keys that are enum values should use the EnumMap implementation",
        description: "EnumMap is faster and smaller.",
        message: "Use EnumMap.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S1640")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(object_creation_expression type: (generic_type (type_identifier) @c (#any-of? @c "HashMap" "TreeMap") (type_arguments . (type_identifier) @k))) @match"#,
            filter: Some(Keep(key_type_is_an_enum_in_the_file)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "enum Color { RED }\nclass A { Object m = new HashMap<Color, String>(); }",
            good: "enum Color { RED }\nclass A { Object m = new EnumMap<Color, String>(Color.class); }",
        }),
    },
    Rule {
        id: "java/annotation-container",
        name: "Annotation repetitions should not be wrapped",
        description: "Repeatable annotations can be written one after another.",
        message: "Repeat the annotation.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S1710")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(annotation (annotation_argument_list (element_value_array_initializer) @match))"#,
            filter: Some(Keep(wraps_repeated_annotations)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "@Roles({@Role(\"a\"), @Role(\"b\")}) class A {}",
            good: "@Role(\"a\") @Role(\"b\") class A {}",
        }),
    },
    Rule {
        id: "java/dead-store",
        name: "Unused assignments should be removed",
        description: "The value assigned first is overwritten before anything reads it.",
        message: "Remove the first assignment.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S1854")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(block) @match"#,
            filter: Some(Find(assigned_then_overwritten)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { int x; x = compute(); x = other(); g(x); } }",
            good: "class A { void f() { int x; x = other(); g(x); } }",
        }),
    },
    Rule {
        id: "java/silly-equality",
        name: "Unnecessary equality checks should not be made",
        description: "Values of different kinds are never equal.",
        message: "Compare comparable values.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2159")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(binary_expression operator: ["==" "!="]) @match"#,
            filter: Some(Keep(equality_between_different_literals)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { boolean f() { return 1 == \"a\"; } }",
            good: "class A { boolean f(int x) { return x == 1; } }",
        }),
    },
    Rule {
        id: "java/multiplication-overflow",
        name: "Math operands should be cast before assignment",
        description: "The multiplication is done in int and only then widened, so it overflows first.",
        message: "Cast an operand to long.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2184")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(local_variable_declaration type: (_) @t declarator: (variable_declarator value: (binary_expression operator: ["*" "<<"]) @match))"#,
            filter: Some(Keep(widens_after_int_arithmetic)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { long f(int a, int b) { long r = a * b; return r; } }",
            good: "class A { long f(int a, int b) { long r = (long) a * b; return r; } }",
        }),
    },
    Rule {
        id: "java/byte-shift",
        name: "Raw byte values should not be used in bitwise operations in combination with shifts",
        description: "A byte is sign-extended, so the high bits are wrong.",
        message: "Mask with & 0xFF first.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3034")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(binary_expression operator: "<<") @match"#,
            filter: Some(Keep(shifts_a_byte_variable)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { int f(byte b) { return b << 8; } }",
            good: "class A { int f(byte b) { return (b & 0xFF) << 8; } }",
        }),
    },
    Rule {
        id: "java/builder-never-read",
        name: "StringBuilder data should be used",
        description: "Building text nobody reads is wasted work.",
        message: "Use it, or remove it.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3063")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration) @match"#,
            filter: Some(Find(builder_is_only_appended_to)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { StringBuilder sb = new StringBuilder(); sb.append(\"x\"); } }",
            good: "class A { String f() { StringBuilder sb = new StringBuilder(); sb.append(\"x\"); return sb.toString(); } }",
        }),
    },
    Rule {
        id: "java/lock-on-value-based",
        name: "Value-based classes should not be used for locking",
        description: "Boxed numbers and Optional may be shared or interned.",
        message: "Lock on a dedicated Object.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S3436")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(synchronized_statement (parenthesized_expression (identifier) @match))"#,
            filter: Some(Keep(is_value_based_variable)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { Integer n = 0; void f() { synchronized (n) { g(); } } }",
            good: "class A { Object lock = new Object(); void f() { synchronized (lock) { g(); } } }",
        }),
    },
    Rule {
        id: "java/varargs-array",
        name: "Arrays should not be created for varargs parameters",
        description: "The compiler builds the array.",
        message: "Pass the values directly.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S3878")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "format" "printf" "asList")) @match"#,
            filter: Some(Keep(passes_an_explicit_array)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { String s = String.format(\"%s\", new Object[] {x}); } }",
            good: "class A { void f() { String s = String.format(\"%s\", x); } }",
        }),
    },
    Rule {
        id: "java/getter-wrong-field",
        name: "Getters and setters should access the expected fields",
        description: "A getter that returns another field is a copy-paste bug.",
        message: "Return the field the name says.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S4275")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(class_declaration) @match"#,
            filter: Some(Find(accessor_touches_another_field)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { private int a; private int b; int getA() { return b; } }",
            good: "class A { private int a; private int b; int getA() { return a; } }",
        }),
    },
    Rule {
        id: "java/equals-nonnull-parameter",
        name: "equals method parameters should not be marked @Nonnull",
        description: "equals(null) must return false, not throw.",
        message: "Remove the annotation.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S4454")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration name: (identifier) @n (#eq? @n "equals")) @match"#,
            filter: Some(Keep(equals_parameter_is_nonnull)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { public boolean equals(@Nonnull Object o) { return true; } }",
            good: "class A { public boolean equals(Object o) { return true; } }",
        }),
    },
    Rule {
        id: "java/substring-index-of",
        name: "String offset-based methods should be preferred for finding substrings from offsets",
        description: "indexOf(x, from) avoids the copy.",
        message: "Pass the offset to indexOf.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S4635")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation object: (method_invocation name: (identifier) @s (#eq? @s "substring")) name: (identifier) @n (#any-of? @n "indexOf" "startsWith")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { int i = s.substring(3).indexOf(\"x\"); } }",
            good: "class A { void f() { int i = s.indexOf(\"x\", 3); } }",
        }),
    },
    Rule {
        id: "java/guava-replaceable",
        name: "Java features should be preferred to Guava",
        description: "The JDK has Optional, Function, Predicate and Supplier.",
        message: "Use the java.util equivalent.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S4738")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(import_declaration (scoped_identifier) @match)"#,
            filter: Some(Keep(imports_replaceable_guava)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "import com.google.common.base.Optional;",
            good: "import java.util.Optional;",
        }),
    },
    Rule {
        id: "java/checked-exception-test-body",
        name: "Only one method invocation is expected when testing checked exceptions",
        description: "Any other call in the try block could be the one that throws.",
        message: "Keep only the call under test.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5783")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(try_statement) @match"#,
            filter: Some(Keep(try_expects_exception_with_many_calls)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void t() { try { a(); b(); fail(); } catch (IOException e) { } } }",
            good: "class A { void t() { a(); try { b(); fail(); } catch (IOException e) { } } }",
        }),
    },
    Rule {
        id: "java/collect-with-add",
        name: "collect should be used with Streams instead of list::add",
        description: "forEach(list::add) mutates shared state.",
        message: "Use collect(Collectors.toList()).",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S2203")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#eq? @n "forEach") arguments: (argument_list (method_reference (identifier) "::" (identifier) @m (#eq? @m "add")))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { stream.forEach(list::add); } }",
            good: "class A { void f() { list = stream.collect(Collectors.toList()); } }",
        }),
    },
    Rule {
        id: "java/jdbc-update-in-loop",
        name: "Use batch Processing in JDBC",
        description: "One round trip per row is slow.",
        message: "Use addBatch() and executeBatch().",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S6912")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "executeUpdate" "execute") arguments: (argument_list)) @match"#,
            filter: Some(Keep(is_inside_a_loop)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { for (int i = 0; i < 3; i++) { ps.executeUpdate(); } } }",
            good: "class A { void f() { ps.executeBatch(); } }",
        }),
    },
    Rule {
        id: "java/throws-many-checked",
        name: "Public methods should throw at most one checked exception",
        description: "Callers have to handle each one.",
        message: "Wrap them in one.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S1160")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration (throws) @match)"#,
            filter: Some(Keep(throws_several_checked)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { public void f() throws IOException, SQLException {} }",
            good: "class A { public void f() throws IOException {} }",
        }),
    },
    Rule {
        id: "java/throws-checked",
        name: "Checked exceptions should not be thrown",
        description: "They force every caller to handle them.",
        message: "Throw an unchecked exception.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S1162")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(throw_statement (object_creation_expression type: (type_identifier) @t (#any-of? @t "Exception" "Throwable" "IOException" "SQLException" "TimeoutException"))) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { throw new IOException(\"x\"); } }",
            good: "class A { void f() { throw new UncheckedIOException(\"x\", e); } }",
        }),
    },
    Rule {
        id: "java/qualified-name",
        name: "Simple class names should be used",
        description: "A fully qualified name in code is noise.",
        message: "Import it.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S1942")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(local_variable_declaration type: (scoped_type_identifier) @match)
(field_declaration type: (scoped_type_identifier) @match)"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { java.util.List l = null; } }",
            good: "class A { void f() { List l = null; } }",
        }),
    },
    Rule {
        id: "java/one-type-per-file",
        name: "Files should contain only one top-level class or interface each",
        description: "Several types per file are hard to find.",
        message: "Move each to its own file.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 20,
        sonar: &[exact("S1996")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(program) @match"#,
            filter: Some(Find(second_top_level_type)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A {}\nclass B {}",
            good: "class A {}",
        }),
    },
    Rule {
        id: "java/package-private-field",
        name: "Member variable visibility should be specified",
        description: "A missing modifier is package visibility by accident.",
        message: "Add private, protected or public.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2039")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(field_declaration) @match"#,
            filter: Some(Keep(field_has_no_visibility)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { int n; }",
            good: "class A { private int n; }",
        }),
    },
    Rule {
        id: "java/boolean-method-name",
        name: "The names of methods with boolean return values should start with is or has",
        description: "Callers read isReady() as a question.",
        message: "Rename the method.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S2047")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_declaration type: (boolean_type) name: (identifier) @match)"#,
            filter: Some(Keep(boolean_method_name_is_wrong)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { boolean ready() { return true; } }",
            good: "class A { boolean isReady() { return true; } }",
        }),
    },
    Rule {
        id: "java/local-constant-name",
        name: "Local constants should follow naming conventions for constants",
        description: "final locals named like variables hide that they never change.",
        message: "Use UPPER_SNAKE_CASE.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S4174")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(local_variable_declaration (modifiers "final") declarator: (variable_declarator name: (identifier) @match value: (_)))"#,
            filter: Some(Keep(constant_name_is_lowercase)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { final int max = 3; } }",
            good: "class A { void f() { final int MAX = 3; } }",
        }),
    },
    Rule {
        id: "java/junit4-import",
        name: "Migrate your tests from JUnit4 to the new JUnit5 annotations",
        description: "JUnit 4 is in maintenance.",
        message: "Use org.junit.jupiter.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 10,
        sonar: &[exact("S5793")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(import_declaration (scoped_identifier) @match)"#,
            filter: Some(Keep(imports_junit4)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "import org.junit.Test;",
            good: "import org.junit.jupiter.api.Test;",
        }),
    },
    Rule {
        id: "java/operator-precedence",
        name: "Limited dependence should be placed on operator precedence",
        description: "a && b || c needs parentheses to be read at a glance.",
        message: "Add parentheses.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S864")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(binary_expression operator: "||") @match"#,
            filter: Some(Keep(mixes_and_with_or)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { boolean f(boolean a, boolean b, boolean c) { return a && b || c; } }",
            good: "class A { boolean f(boolean a, boolean b, boolean c) { return (a && b) || c; } }",
        }),
    },
    Rule {
        id: "java/increment-in-expression",
        name: "Increment and decrement operators should not be used in a method call or mixed with other operators in an expression",
        description: "i++ inside an expression is easy to misread.",
        message: "Move the increment to its own statement.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S881")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(update_expression) @match"#,
            filter: Some(Keep(update_is_inside_an_expression)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f(int i) { g(i++); } }",
            good: "class A { void f(int i) { g(i); i++; } }",
        }),
    },
    Rule {
        id: "java/magic-number",
        name: "Magic numbers should not be used",
        description: "A bare 86400 in code has no name.",
        message: "Use a named constant.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S109")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(decimal_integer_literal) @match"#,
            filter: Some(Keep(is_a_magic_number)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { int f(int x) { return x * 86400; } }",
            good: "class A { static final int DAY = 86400; int f(int x) { return x * DAY; } }",
        }),
    },
    Rule {
        id: "java/test-assertion-message",
        name: "Test assertions should include messages",
        description: "A failure without a message needs a debugger.",
        message: "Add a message.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S2698")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "assertEquals" "assertTrue" "assertFalse" "assertNull" "assertNotNull" "assertNotEquals")) @match"#,
            filter: Some(Keep(assertion_has_no_message)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void t() { assertTrue(x); } }",
            good: "class A { void t() { assertTrue(x, \"x holds\"); } }",
        }),
    },
];

// ---------------------------------------------------- filters

const LOOP_KINDS: &[&str] = &[
    "for_statement",
    "enhanced_for_statement",
    "while_statement",
    "do_statement",
];

fn chain_names<'s>(call: Node, src: &'s [u8]) -> Vec<&'s [u8]> {
    let mut names = Vec::new();
    let mut cur = Some(call);
    while let Some(c) = cur.filter(|c| c.kind() == "method_invocation") {
        names.push(method_name(c, src));
        cur = c.child_by_field_name("object");
    }
    names
}

fn declared_type_names<'s>(root: Node, kinds: &[&str], src: &'s [u8]) -> Vec<&'s [u8]> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        if kinds.contains(&n.kind()) {
            out.push(name_text(n, src));
        }
        let mut cursor = n.walk();
        stack.extend(n.named_children(&mut cursor));
    }
    out
}

fn root_of(node: Node) -> Node {
    let mut n = node;
    while let Some(p) = n.parent() {
        n = p;
    }
    n
}

fn base_type(t: &[u8]) -> &[u8] {
    t.split(|&b| b == b'<').next().unwrap_or(t)
}

// ---- Spring and persistence

fn configuration_autowires_a_field<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !has_annotation(class, b"Configuration", src) {
        return None;
    }
    class_members(class).into_iter().find(|m| {
        m.kind() == "field_declaration"
            && (has_annotation(*m, b"Autowired", src) || has_annotation(*m, b"Inject", src))
    })
}

fn bean_method_name_is_wrong(method: Node, src: &[u8]) -> bool {
    let n = name_text(method, src);
    has_annotation(method, b"Bean", src)
        && !(n.first().is_some_and(u8::is_ascii_lowercase)
            && n.iter().all(u8::is_ascii_alphanumeric))
}

fn bean_method_called_without_proxy<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let modifiers = class.child(0).filter(|m| m.kind() == "modifiers")?;
    let t = text(modifiers, src);
    if count_word(t, b"proxyBeanMethods") == 0 || count_word(t, b"false") == 0 {
        return None;
    }
    let beans: Vec<&[u8]> = class_members(class)
        .iter()
        .filter(|m| m.kind() == "method_declaration" && has_annotation(**m, b"Bean", src))
        .map(|m| name_text(*m, src))
        .collect();
    find_node(class.child_by_field_name("body")?, |n| {
        n.kind() == "method_invocation"
            && n.child_by_field_name("object").is_none()
            && beans.contains(&method_name(n, src))
            && enclosing_method_name(n, src).is_some_and(|m| m != method_name(n, src))
    })
}

fn enclosing_method_name<'s>(node: Node, src: &'s [u8]) -> Option<&'s [u8]> {
    let mut p = node.parent();
    while let Some(n) = p {
        if n.kind() == "method_declaration" {
            return Some(name_text(n, src));
        }
        p = n.parent();
    }
    None
}

fn spel_braces_are_unbalanced(annotation: Node, src: &[u8]) -> bool {
    let Some(literal) = find_node(annotation, |n| n.kind() == "string_literal") else {
        return false;
    };
    let Some(value) = string_value(literal, src) else {
        return false;
    };
    let uses = value.windows(2).any(|w| w == b"#{" || w == b"${");
    let open = value.iter().filter(|&&b| b == b'{').count();
    let close = value.iter().filter(|&&b| b == b'}').count();
    uses && open != close
}

fn interface_has_cache_annotation<'t>(iface: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    const CACHE: &[&[u8]] = &[b"Cacheable", b"CacheEvict", b"CachePut", b"Caching"];
    let annotated = |n: Node| CACHE.iter().any(|a| has_annotation(n, a, src));
    if annotated(iface) {
        return Some(iface);
    }
    class_members(iface).into_iter().find(|m| annotated(*m))
}

// ---- security

fn size_limit_is_too_large(call: Node, src: &[u8]) -> bool {
    call_arguments(call).first().is_some_and(|a| {
        let t = text(*a, src);
        if a.kind() == "unary_expression" {
            return t.starts_with(b"-");
        }
        let digits: String = String::from_utf8_lossy(t)
            .chars()
            .filter(|c| c.is_ascii_digit())
            .collect();
        a.kind() == "decimal_integer_literal" && digits.parse::<u64>().is_ok_and(|n| n > 8_000_000)
    })
}

fn chain_has_any_request_before(call: Node, src: &[u8]) -> bool {
    chain_names(call, src)
        .iter()
        .skip(1)
        .any(|n| *n == b"anyRequest")
}

fn hashes_a_password(call: Node, src: &[u8]) -> bool {
    call_arguments(call).first().is_some_and(|a| {
        ["password", "passwd", "pwd"]
            .iter()
            .any(|w| super::java_security::contains_ignoring_case(text(*a, src), w.as_bytes()))
    })
}

fn registers_with_two_arguments(call: Node, _: &[u8]) -> bool {
    call_arguments(call).len() == 2
}

fn key_spec_lacks_user_authentication(call: Node, src: &[u8]) -> bool {
    let t = text(call, src);
    count_word(t, b"KeyGenParameterSpec") > 0
        && count_word(t, b"Builder") > 0
        && !t
            .windows(33)
            .any(|w| w == b"setUserAuthenticationRequired(tru")
}

fn prompt_authenticates_without_crypto(call: Node, src: &[u8]) -> bool {
    let recv = call
        .child_by_field_name("object")
        .map_or(&b""[..], |o| text(o, src));
    call_arguments(call).len() == 1
        && ["biometric", "prompt"]
            .iter()
            .any(|w| super::java_security::contains_ignoring_case(recv, w.as_bytes()))
}

// ---- records and newer Java

fn permitted_types_are_in_the_file(permits: Node, src: &[u8]) -> bool {
    let names: Vec<&[u8]> = find_all_type_identifiers(permits, src);
    if names.is_empty() {
        return false;
    }
    let declared = declared_type_names(
        root_of(permits),
        &[
            "class_declaration",
            "interface_declaration",
            "record_declaration",
            "enum_declaration",
        ],
        src,
    );
    names.iter().all(|n| declared.contains(n))
}

fn find_all_type_identifiers<'s>(node: Node, src: &'s [u8]) -> Vec<&'s [u8]> {
    let mut out = Vec::new();
    let mut stack = vec![node];
    while let Some(n) = stack.pop() {
        if n.kind() == "type_identifier" {
            out.push(text(n, src));
        }
        let mut cursor = n.walk();
        stack.extend(n.named_children(&mut cursor));
    }
    out
}

fn record_declares_zero_uid<'t>(record: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let field = declared_field(record, b"serialVersionUID", src)?;
    let value = children_of_kind(field, "variable_declarator")
        .into_iter()
        .next()?
        .child_by_field_name("value")?;
    matches!(text(value, src), b"0L" | b"0l" | b"0").then_some(field)
}

fn record_declares_ignored_hook<'t>(record: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    class_members(record).into_iter().find(|m| match m.kind() {
        "method_declaration" => matches!(
            name_text(*m, src),
            b"readObject" | b"writeObject" | b"readObjectNoData"
        ),
        "field_declaration" => declarator_names(*m, src).contains(&&b"serialPersistentFields"[..]),
        _ => false,
    })
}

fn catch_parameter_is_unused(catch: Node, src: &[u8]) -> bool {
    let Some(param) = children_of_kind(catch, "catch_formal_parameter")
        .into_iter()
        .next()
    else {
        return false;
    };
    let name = name_text(param, src);
    name != b"_"
        && catch
            .child_by_field_name("body")
            .is_some_and(|b| count_word(text(b, src), name) == 0)
}

fn declares_the_type_it_creates(decl: Node, src: &[u8]) -> bool {
    let declared = decl.child_by_field_name("type").map(|t| text(t, src));
    let created = children_of_kind(decl, "variable_declarator")
        .into_iter()
        .next()
        .and_then(|d| d.child_by_field_name("value"))
        .and_then(|v| v.child_by_field_name("type"))
        .map(|t| text(t, src));
    declared.is_some() && declared == created
}

fn joins_lines_with_newlines(binary: Node, src: &[u8]) -> bool {
    if binary.parent().is_some_and(|p| {
        p.kind() == "binary_expression"
            && p.child_by_field_name("operator")
                .is_some_and(|o| text(o, src) == b"+")
    }) {
        return false;
    }
    let mut parts = Vec::new();
    let mut stack = vec![binary];
    while let Some(n) = stack.pop() {
        if n.kind() == "binary_expression"
            && n.child_by_field_name("operator")
                .is_some_and(|o| text(o, src) == b"+")
        {
            if let (Some(l), Some(r)) = (
                n.child_by_field_name("left"),
                n.child_by_field_name("right"),
            ) {
                stack.push(r);
                stack.push(l);
            }
        } else {
            parts.push(n);
        }
    }
    parts.len() >= 3
        && parts.iter().all(|p| p.kind() == "string_literal")
        && parts[..parts.len() - 1]
            .iter()
            .all(|p| text(*p, src).ends_with(b"\\n\""))
}

fn compares_one_variable_in_a_chain(if_statement: Node, src: &[u8]) -> bool {
    if if_statement.parent().is_some_and(|p| {
        p.kind() == "if_statement" && p.child_by_field_name("alternative") == Some(if_statement)
    }) {
        return false;
    }
    let tested = |cond: Node| -> Option<&[u8]> {
        let inner = if cond.kind() == "parenthesized_expression" {
            cond.named_child(0)?
        } else {
            cond
        };
        match inner.kind() {
            "binary_expression"
                if inner
                    .child_by_field_name("operator")
                    .is_some_and(|o| text(o, src) == b"==") =>
            {
                let (l, r) = (
                    inner.child_by_field_name("left")?,
                    inner.child_by_field_name("right")?,
                );
                if literal_kind(r).is_some() && l.kind() == "identifier" {
                    Some(text(l, src))
                } else if literal_kind(l).is_some() && r.kind() == "identifier" {
                    Some(text(r, src))
                } else {
                    None
                }
            }
            "method_invocation" if method_name(inner, src) == b"equals" => {
                let arg = call_arguments(inner).first().copied()?;
                let obj = inner.child_by_field_name("object")?;
                if obj.kind() == "identifier" && literal_kind(arg).is_some() {
                    Some(text(obj, src))
                } else {
                    None
                }
            }
            _ => None,
        }
    };
    let mut links = 0;
    let mut variable: Option<&[u8]> = None;
    let mut cur = if_statement;
    loop {
        let Some(v) = cur.child_by_field_name("condition").and_then(tested) else {
            return false;
        };
        if variable.is_some_and(|x| x != v) {
            return false;
        }
        variable = Some(v);
        links += 1;
        match cur.child_by_field_name("alternative") {
            Some(next) if next.kind() == "if_statement" => cur = next,
            _ => break,
        }
    }
    links >= 3
}

fn nests_min_and_max(call: Node, src: &[u8]) -> bool {
    let (outer, inner): (&[u8], &[u8]) = match method_name(call, src) {
        b"min" => (b"min", b"max"),
        _ => (b"max", b"min"),
    };
    let _ = outer;
    call_arguments(call).iter().any(|a| {
        a.kind() == "method_invocation"
            && method_name(*a, src) == inner
            && a.child_by_field_name("object")
                .is_some_and(|o| text(o, src) == b"Math")
    })
}

fn compares_value_based_by_identity(binary: Node, src: &[u8]) -> bool {
    const VALUE_BASED: &[&[u8]] = &[
        b"Optional",
        b"LocalDate",
        b"LocalDateTime",
        b"LocalTime",
        b"Instant",
        b"Duration",
        b"Period",
        b"ZonedDateTime",
        b"OffsetDateTime",
        b"YearMonth",
    ];
    let is_value_based = |n: Option<Node>| {
        n.is_some_and(|n| {
            n.kind() == "identifier"
                && VALUE_BASED.contains(&base_type(type_text(
                    declared_type(binary, text(n, src), src),
                    src,
                )))
        })
    };
    is_value_based(binary.child_by_field_name("left"))
        && is_value_based(binary.child_by_field_name("right"))
}

fn reads_the_clock_in_a_test(call: Node, src: &[u8]) -> bool {
    let name = method_name(call, src);
    let object = call
        .child_by_field_name("object")
        .map_or(&b""[..], |o| text(o, src));
    let clock = (name == b"now"
        && call_arguments(call).is_empty()
        && matches!(
            object,
            b"Instant"
                | b"LocalDate"
                | b"LocalDateTime"
                | b"LocalTime"
                | b"ZonedDateTime"
                | b"OffsetDateTime"
        ))
        || (name == b"currentTimeMillis" && object == b"System");
    if !clock {
        return false;
    }
    let mut p = call.parent();
    while let Some(n) = p {
        if n.kind() == "method_declaration" {
            return has_annotation(n, b"Test", src);
        }
        p = n.parent();
    }
    false
}

fn startup_method_has_bad_signature(method: Node, src: &[u8]) -> bool {
    has_annotation(method, b"Startup", src)
        && (has_modifier(method, "static")
            || has_annotation(method, b"Produces", src)
            || method
                .child_by_field_name("parameters")
                .is_some_and(|p| p.named_child_count() > 0))
}

// ---- bugs and smells

fn parameter_overwritten_first<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let params: Vec<&[u8]> = method
        .child_by_field_name("parameters")?
        .named_children(&mut method.walk())
        .filter_map(|p| p.child_by_field_name("name").map(|n| text(n, src)))
        .collect();
    let first = statements(method.child_by_field_name("body")?)
        .into_iter()
        .next()?;
    let assignment = first.named_child(0).filter(|a| {
        first.kind() == "expression_statement" && a.kind() == "assignment_expression"
    })?;
    let left = assignment.child_by_field_name("left")?;
    let right = assignment.child_by_field_name("right")?;
    let name = text(left, src);
    (left.kind() == "identifier"
        && params.contains(&name)
        && count_word(text(right, src), name) == 0)
        .then_some(first)
}

fn key_type_is_an_enum_in_the_file(creation: Node, src: &[u8]) -> bool {
    let Some(key) =
        find_node(creation, |n| n.kind() == "type_arguments").and_then(|a| a.named_child(0))
    else {
        return false;
    };
    declared_type_names(root_of(creation), &["enum_declaration"], src).contains(&text(key, src))
}

fn wraps_repeated_annotations(array: Node, src: &[u8]) -> bool {
    let items = named_children_of(array);
    items.len() >= 2
        && items.iter().all(|i| i.kind() == "annotation")
        && items
            .windows(2)
            .all(|w| name_text(w[0], src) == name_text(w[1], src))
}

fn named_children_of(node: Node) -> Vec<Node> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|n| !matches!(n.kind(), "line_comment" | "block_comment"))
        .collect()
}

fn assigned_then_overwritten<'t>(block: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let items = statements(block);
    items.windows(2).find_map(|w| {
        let assign = |s: Node<'t>| {
            (s.kind() == "expression_statement")
                .then(|| s.named_child(0))
                .flatten()
                .filter(|a| a.kind() == "assignment_expression")
        };
        let (a, b) = (assign(w[0])?, assign(w[1])?);
        let (l1, l2) = (
            a.child_by_field_name("left")?,
            b.child_by_field_name("left")?,
        );
        let (r1, r2) = (
            a.child_by_field_name("right")?,
            b.child_by_field_name("right")?,
        );
        let name = text(l1, src);
        let operator = |x: Node| {
            x.child_by_field_name("operator")
                .map_or(&b""[..], |o| text(o, src))
        };
        (l1.kind() == "identifier"
            && l2.kind() == "identifier"
            && name == text(l2, src)
            && operator(a) == b"="
            && operator(b) == b"="
            && !matches!(
                r1.kind(),
                "null_literal" | "true" | "false" | "decimal_integer_literal" | "string_literal"
            )
            && count_word(text(r2, src), name) == 0)
            .then_some(w[0])
    })
}

fn equality_between_different_literals(binary: Node, _: &[u8]) -> bool {
    let (Some(l), Some(r)) = (
        binary.child_by_field_name("left"),
        binary.child_by_field_name("right"),
    ) else {
        return false;
    };
    match (literal_kind(l), literal_kind(r)) {
        (Some(a), Some(b)) => a != b && !matches!((a, b), ("char", "number") | ("number", "char")),
        _ => false,
    }
}

fn widens_after_int_arithmetic(binary: Node, src: &[u8]) -> bool {
    let Some(decl) = binary.parent().and_then(|d| d.parent()) else {
        return false;
    };
    if !matches!(
        type_text(decl.child_by_field_name("type"), src),
        b"long" | b"double" | b"float"
    ) {
        return false;
    }
    let int_operand = |n: Option<Node>| {
        n.is_some_and(|n| match n.kind() {
            "decimal_integer_literal" => {
                !text(n, src).ends_with(b"L") && !text(n, src).ends_with(b"l")
            }
            "identifier" => matches!(
                type_text(declared_type(binary, text(n, src), src), src),
                b"int" | b"short" | b"byte" | b"char"
            ),
            _ => false,
        })
    };
    let (l, r) = (
        binary.child_by_field_name("left"),
        binary.child_by_field_name("right"),
    );
    int_operand(l)
        && int_operand(r)
        && (l.is_some_and(|n| n.kind() == "identifier")
            || r.is_some_and(|n| n.kind() == "identifier"))
}

fn shifts_a_byte_variable(binary: Node, src: &[u8]) -> bool {
    binary.child_by_field_name("left").is_some_and(|ident| {
        ident.kind() == "identifier"
            && type_text(declared_type(ident, text(ident, src), src), src) == b"byte"
    })
}

fn builder_is_only_appended_to<'t>(method: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let body = method.child_by_field_name("body")?;
    let declaration = find_node(body, |n| {
        n.kind() == "local_variable_declaration"
            && matches!(
                type_text(n.child_by_field_name("type"), src),
                b"StringBuilder" | b"StringBuffer"
            )
    })?;
    let declarator = children_of_kind(declaration, "variable_declarator")
        .into_iter()
        .next()?;
    let name_node = declarator.child_by_field_name("name")?;
    let name = text(name_node, src);
    let uses = count_nodes(body, &[], |n| {
        n.kind() == "identifier" && text(n, src) == name && n != name_node
    });
    let appends = count_nodes(body, &[], |n| {
        n.kind() == "method_invocation"
            && matches!(method_name(n, src), b"append" | b"insert")
            && n.child_by_field_name("object")
                .is_some_and(|o| o.kind() == "identifier" && text(o, src) == name)
            && n.parent()
                .is_some_and(|p| p.kind() == "expression_statement")
    });
    (uses > 0 && uses == appends).then_some(name_node)
}

fn is_value_based_variable(ident: Node, src: &[u8]) -> bool {
    matches!(
        base_type(type_text(declared_type(ident, text(ident, src), src), src)),
        b"Integer"
            | b"Long"
            | b"Short"
            | b"Byte"
            | b"Character"
            | b"Float"
            | b"Double"
            | b"Boolean"
            | b"Optional"
            | b"LocalDate"
            | b"LocalDateTime"
            | b"Instant"
            | b"Duration"
    )
}

fn passes_an_explicit_array(call: Node, _: &[u8]) -> bool {
    call_arguments(call).last().is_some_and(|a| {
        a.kind() == "array_creation_expression"
            && find_node(*a, |n| n.kind() == "array_initializer").is_some()
    })
}

fn accessor_touches_another_field<'t>(class: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let members = class_members(class);
    let fields: Vec<&[u8]> = members
        .iter()
        .filter(|m| m.kind() == "field_declaration")
        .flat_map(|m| declarator_names(*m, src))
        .collect();
    members.into_iter().find(|m| {
        if m.kind() != "method_declaration" {
            return false;
        }
        let name = name_text(*m, src);
        let property = name
            .strip_prefix(b"get")
            .or_else(|| name.strip_prefix(b"is"))
            .filter(|p| !p.is_empty());
        let Some(property) = property else {
            return false;
        };
        if m.child_by_field_name("parameters")
            .is_some_and(|p| p.named_child_count() > 0)
        {
            return false;
        }
        let own = fields.iter().any(|f| f.eq_ignore_ascii_case(property));
        let Some(body) = m.child_by_field_name("body") else {
            return false;
        };
        let items = statements(body);
        let [only] = items.as_slice() else {
            return false;
        };
        if only.kind() != "return_statement" {
            return false;
        }
        let returned = only.named_child(0).and_then(|v| match v.kind() {
            "identifier" => Some(text(v, src)),
            "field_access" => v.child_by_field_name("field").map(|f| text(f, src)),
            _ => None,
        });
        own && returned.is_some_and(|r| fields.contains(&r) && !r.eq_ignore_ascii_case(property))
    })
}

fn equals_parameter_is_nonnull(method: Node, src: &[u8]) -> bool {
    name_text(method, src) == b"equals"
        && method.child_by_field_name("parameters").is_some_and(|p| {
            let t = text(p, src);
            count_word(t, b"Nonnull") + count_word(t, b"NonNull") + count_word(t, b"NotNull") > 0
        })
}

fn imports_replaceable_guava(path: Node, src: &[u8]) -> bool {
    let t = text(path, src);
    t.starts_with(b"com.google.common.base.")
        && matches!(
            t.rsplit(|&b| b == b'.').next().unwrap_or(b""),
            b"Optional" | b"Function" | b"Predicate" | b"Supplier"
        )
}

fn try_expects_exception_with_many_calls(try_statement: Node, src: &[u8]) -> bool {
    let Some(body) = try_statement.child_by_field_name("body") else {
        return false;
    };
    let items = statements(body);
    let ends_with_fail = items.last().is_some_and(|s| {
        s.kind() == "expression_statement"
            && s.named_child(0)
                .is_some_and(|c| c.kind() == "method_invocation" && method_name(c, src) == b"fail")
    });
    ends_with_fail
        && !children_of_kind(try_statement, "catch_clause").is_empty()
        && count_nodes(body, &[], |n| {
            n.kind() == "method_invocation" && method_name(n, src) != b"fail"
        }) >= 2
}

fn is_inside_a_loop(call: Node, _: &[u8]) -> bool {
    let mut p = call.parent();
    while let Some(n) = p {
        if LOOP_KINDS.contains(&n.kind()) {
            return true;
        }
        if matches!(
            n.kind(),
            "method_declaration" | "lambda_expression" | "class_body"
        ) {
            return false;
        }
        p = n.parent();
    }
    false
}

fn throws_several_checked(throws: Node, src: &[u8]) -> bool {
    const UNCHECKED: &[&[u8]] = &[
        b"IllegalArgumentException",
        b"IllegalStateException",
        b"UnsupportedOperationException",
        b"NullPointerException",
        b"IndexOutOfBoundsException",
        b"ClassCastException",
        b"ArithmeticException",
        b"SecurityException",
        b"Error",
    ];
    throws.parent().is_some_and(|m| has_modifier(m, "public"))
        && named_children_of(throws)
            .iter()
            .filter(|n| {
                let t = text(**n, src);
                !t.ends_with(b"RuntimeException") && !UNCHECKED.contains(&t)
            })
            .count()
            > 1
}

fn second_top_level_type<'t>(program: Node<'t>, _: &[u8]) -> Option<Node<'t>> {
    named_children_of(program)
        .into_iter()
        .filter(|n| {
            matches!(
                n.kind(),
                "class_declaration"
                    | "interface_declaration"
                    | "enum_declaration"
                    | "record_declaration"
                    | "annotation_type_declaration"
            )
        })
        .nth(1)
}

fn field_has_no_visibility(field: Node, _: &[u8]) -> bool {
    !has_modifier(field, "public")
        && !has_modifier(field, "protected")
        && !has_modifier(field, "private")
        && field
            .parent()
            .and_then(|b| b.parent())
            .is_some_and(|c| c.kind() == "class_declaration")
}

fn boolean_method_name_is_wrong(name: Node, src: &[u8]) -> bool {
    let n = text(name, src);
    let Some(method) = name.parent() else {
        return false;
    };
    let prefixed =
        |p: &[u8]| n.starts_with(p) && n.get(p.len()).is_some_and(u8::is_ascii_uppercase);
    !prefixed(b"is")
        && !prefixed(b"has")
        && n != b"equals"
        && !has_annotation(method, b"Override", src)
        && !has_annotation(method, b"Test", src)
}

fn constant_name_is_lowercase(name: Node, src: &[u8]) -> bool {
    let literal_value = name
        .parent()
        .and_then(|d| d.child_by_field_name("value"))
        .is_some_and(|v| literal_kind(v).is_some());
    literal_value && text(name, src).iter().any(u8::is_ascii_lowercase)
}

fn imports_junit4(path: Node, src: &[u8]) -> bool {
    let t = text(path, src);
    t.starts_with(b"org.junit.")
        && !t.starts_with(b"org.junit.jupiter")
        && !t.starts_with(b"org.junit.platform")
        && !t.starts_with(b"org.junit.vintage")
}

fn mixes_and_with_or(binary: Node, src: &[u8]) -> bool {
    let and = |n: Option<Node>| {
        n.is_some_and(|n| {
            n.kind() == "binary_expression"
                && n.child_by_field_name("operator")
                    .is_some_and(|o| text(o, src) == b"&&")
        })
    };
    and(binary.child_by_field_name("left")) || and(binary.child_by_field_name("right"))
}

fn update_is_inside_an_expression(update: Node, _: &[u8]) -> bool {
    !update
        .parent()
        .is_some_and(|p| matches!(p.kind(), "expression_statement" | "for_statement"))
}

fn is_a_magic_number(literal: Node, src: &[u8]) -> bool {
    let t = text(literal, src);
    if matches!(t, b"0" | b"1" | b"2") {
        return false;
    }
    let mut p = literal.parent();
    while let Some(n) = p {
        match n.kind() {
            "field_declaration" if has_modifier(n, "final") => return false,
            "constant_declaration"
            | "annotation"
            | "element_value_pair"
            | "switch_label"
            | "enum_constant"
            | "array_access" => return false,
            "method_declaration" | "constructor_declaration" | "lambda_expression" => {
                return !matches!(name_text(n, src), b"hashCode");
            }
            _ => {}
        }
        p = n.parent();
    }
    false
}

fn assertion_has_no_message(call: Node, src: &[u8]) -> bool {
    let args = call_arguments(call).len();
    match method_name(call, src) {
        b"assertEquals" | b"assertNotEquals" => args == 2,
        _ => args == 1,
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
        let mut cfg = Config::default();
        cfg.rules.enabled = vec![rule.to_string()];
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let file = analyze("t", Lang::Java, src, &rules, &cfg, far_deadline()).unwrap();
        file.issues
            .iter()
            .filter(|i| i.rule == rule)
            .map(|i| i.line)
            .collect()
    }

    #[test]
    fn configuration_and_beans() {
        let src = "@Configuration(proxyBeanMethods = false)\nclass A {\n @Autowired B b;\n @Bean B b() { return new B(); }\n @Bean C c() { return new C(b()); }\n @Bean D d(B b) { return new D(b); }\n @Bean D Bad_Name() { return null; }\n}";
        assert_eq!(flagged("java/configuration-field-injection", src), [3]);
        assert_eq!(flagged("java/bean-method-called-directly", src), [5]);
        assert_eq!(flagged("java/bean-method-name", src), [7]);
    }

    #[test]
    fn security_calls() {
        let src = "class A {\n void f() {\n  http.authorizeRequests().anyRequest().authenticated().antMatchers(\"/x\");\n  http.authorizeRequests().antMatchers(\"/x\").anyRequest();\n  r.setMaxUploadSize(-1);\n  r.setMaxUploadSize(1000);\n  r.setMaxUploadSize(10000000);\n  DigestUtils.sha256Hex(userPassword);\n  DigestUtils.sha256Hex(data);\n  registerReceiver(r, f);\n  registerReceiver(r, f, p, null);\n }\n}";
        assert_eq!(flagged("java/security-rule-order", src), [3]);
        assert_eq!(flagged("java/upload-size-unlimited", src), [5, 7]);
        assert_eq!(flagged("java/password-fast-hash", src), [8]);
        assert_eq!(flagged("java/receiver-without-permission", src), [10]);
    }

    #[test]
    fn language_checks() {
        let src = "class A {\n void f(int x, byte b, long l) {\n  long r = x * x;\n  long q = (long) x * x;\n  int s = b << 8;\n  x = a();\n  x = b();\n  if (x == 1) { } else if (x == 2) { } else if (x == 3) { }\n  int m = Math.min(Math.max(x, 0), 9);\n }\n}";
        assert_eq!(flagged("java/multiplication-overflow", src), [3]);
        assert_eq!(flagged("java/byte-shift", src), [5]);
        assert_eq!(flagged("java/dead-store", src), [6]);
        assert_eq!(flagged("java/if-chain-to-switch", src), [8]);
        assert_eq!(flagged("java/clamp", src), [9]);
    }

    #[test]
    fn builders_and_accessors() {
        let src = "class A {\n private int a;\n private int b;\n int getA() { return b; }\n int getB() { return b; }\n void f() { StringBuilder sb = new StringBuilder(); sb.append(\"x\"); }\n String g() { StringBuilder sb = new StringBuilder(); sb.append(\"x\"); return sb.toString(); }\n}";
        assert_eq!(flagged("java/getter-wrong-field", src), [4]);
        assert_eq!(flagged("java/builder-never-read", src), [6]);
    }
}
