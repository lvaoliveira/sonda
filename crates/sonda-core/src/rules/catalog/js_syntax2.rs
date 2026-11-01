//! JavaScript and TypeScript rules, part 7 (ADR-0007, batch 22): session, parameter and
//! overload checks, static assets and Angular decorators.

use super::js::{has_token, text};
use super::js_extra::named;
use super::js_syntax::{is_function_kind, walk};
use super::*;

/// This module's rules that are off unless `rules.enabled` lists them
/// (see `catalog::OFF_BY_DEFAULT`).
pub(super) static OFF_BY_DEFAULT: &[&str] = &[
    "js/increment-in-expression",
    "js/overloads-not-grouped",
    "js/angular-standalone-false",
];

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "js/increment-in-expression",
        name: "Increment (++) and decrement (--) operators should not be used in a method call or mixed with other operators in an expression",
        description: "x++ inside a larger expression hides a side effect.",
        message: "Move the increment to its own statement.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S881")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(update_expression) @match"#,
            filter: Some(Keep(is_mixed_into_an_expression)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "f(i++);",
            good: "f(i); i++;",
        }),
    },
    Rule {
        id: "js/parameter-reassigned",
        name: "Initial values of parameters, caught exceptions, and loop variables should not be ignored",
        description: "Overwriting a parameter loses the value the caller passed.",
        message: "Use a new variable.",
        category: Bug,
        severity: Minor,
        effort_minutes: 3,
        sonar: &[exact("S1226")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(function_declaration) (function_expression) (arrow_function) (method_definition) (catch_clause)] @match"#,
            filter: Some(Find(reassigned_parameter)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function f(a) { a = 1; return a; }",
            good: "function f(a) { const b = 1; return a + b; }",
        }),
    },
    Rule {
        id: "js/table-for-layout",
        name: "HTML \"<table>\" should not be used for layout purposes",
        description: "A table that only positions content misleads screen readers.",
        message: "Use CSS for the layout.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5257")],
        check: Check::Query {
            langs: JSX,
            query: r#"(jsx_opening_element name: (identifier) @n (jsx_attribute (property_identifier) @a (string) @v) (#eq? @n "table") (#eq? @a "role") (#any-of? @v "\"presentation\"" "'presentation'" "\"none\"" "'none'")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const a = <table role=\"presentation\"><tbody /></table>;",
            good: "const a = <table><tbody /></table>;",
        }),
    },
    Rule {
        id: "js/static-assets-after-session",
        name: "Static Assets should not serve session cookies",
        description: "A session middleware ahead of express.static sets cookies on every image and script.",
        message: "Serve static files before the session middleware.",
        category: Vulnerability,
        severity: Minor,
        effort_minutes: 3,
        sonar: &[exact("S8441")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression object: (identifier) property: (property_identifier) @p) arguments: (arguments (call_expression function: (member_expression object: (identifier) @o property: (property_identifier) @s)))  (#eq? @p "use") (#eq? @o "express") (#eq? @s "static")) @match"#,
            filter: Some(Keep(session_middleware_comes_first)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const app = express(); app.use(session({ secret: s })); app.use(express.static('public'));",
            good: "const app = express(); app.use(express.static('public')); app.use(session({ secret: s }));",
        }),
    },
    Rule {
        id: "js/login-without-session-regeneration",
        name: "A new session should be created during user authentication",
        description: "Keeping the pre-login session id allows session fixation.",
        message: "Call req.session.regenerate before logging in.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S5876")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression object: (identifier) @o property: (property_identifier) @p) (#eq? @o "req") (#any-of? @p "login" "logIn")) @match"#,
            filter: Some(Keep(login_without_regenerate)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function h(req, res) { req.login(user, function () { res.end(); }); }",
            good: "function h(req, res) { req.session.regenerate(function () { req.login(user, function () { res.end(); }); }); }",
        }),
    },
    Rule {
        id: "js/overloads-not-grouped",
        name: "Method overloads should be grouped together",
        description: "Overloads separated by other members are easy to miss.",
        message: "Move this overload next to the others.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S4136")],
        check: Check::Query {
            langs: TS,
            query: r#"[(class_body) (program)] @match"#,
            filter: Some(Find(overload_out_of_place)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "class A { f(a: string): void; g(): void {} f(a: number): void; f(a: any) {} }",
            good: "class A { f(a: string): void; f(a: number): void; f(a: any) {} g(): void {} }",
        }),
    },
    Rule {
        id: "js/prefer-as-const",
        name: "\"as const\" assertions should be preferred",
        description: "'a' as 'a' repeats the literal.",
        message: "Use as const.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 1,
        sonar: &[exact("S6590")],
        check: Check::Query {
            langs: TS,
            query: r#"(as_expression (_) @v (literal_type) @t) @match"#,
            filter: Some(Keep(asserts_the_literal_it_has)),
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "const a = 'x' as 'x';",
            good: "const a = 'x' as const;",
        }),
    },
    Rule {
        id: "js/angular-standalone-false",
        name: "Components, Directives, and Pipes should use standalone architecture",
        description: "standalone: false keeps a declaration tied to an NgModule.",
        message: "Make it standalone.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 15,
        sonar: &[exact("S7648")],
        check: Check::Query {
            langs: TS,
            query: r#"(decorator (call_expression function: (identifier) @n arguments: (arguments (object (pair key: (property_identifier) @k value: (false))))) (#any-of? @n "Component" "Directive" "Pipe") (#eq? @k "standalone")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "@Component({ selector: 'a', standalone: false }) class A {}",
            good: "@Component({ selector: 'a' }) class A {}",
        }),
    },
    Rule {
        id: "js/angular-outputs-metadata",
        name: "The \"outputs\" metadata property should not be used in Angular components and directives",
        description: "The @Output decorator or output() function is checked by the compiler.",
        message: "Use output() or @Output.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7654")],
        check: Check::Query {
            langs: TS,
            query: r#"(decorator (call_expression function: (identifier) @n arguments: (arguments (object (pair key: (property_identifier) @k)))) (#any-of? @n "Component" "Directive") (#eq? @k "outputs")) @match"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "@Component({ selector: 'a', outputs: ['changed'] }) class A {}",
            good: "@Component({ selector: 'a' }) class A { changed = output(); }",
        }),
    },
    Rule {
        id: "js/angular-lifecycle-misplaced",
        name: "Angular lifecycle methods should be used in the correct context",
        description: "ngOnInit on a service is never called.",
        message: "Move the logic into a component, or call it yourself.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S7641")],
        check: Check::Query {
            langs: TS,
            query: r#"(class_declaration (decorator (call_expression function: (identifier) @n)) body: (class_body (method_definition name: (property_identifier) @match)) (#any-of? @n "Injectable" "Pipe") (#any-of? @match "ngOnInit" "ngOnChanges" "ngDoCheck" "ngAfterContentInit" "ngAfterContentChecked" "ngAfterViewInit" "ngAfterViewChecked"))"#,
            filter: None,
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "@Injectable() class S { ngOnInit() {} }",
            good: "@Component({ selector: 'a' }) class C { ngOnInit() {} }",
        }),
    },
];

fn is_mixed_into_an_expression(update: Node, _: &[u8]) -> bool {
    let Some(parent) = update.parent() else {
        return false;
    };
    match parent.kind() {
        "expression_statement" => false,
        "for_statement" => parent.child_by_field_name("increment") != Some(update),
        "sequence_expression" => !parent.parent().is_some_and(|g| g.kind() == "for_statement"),
        _ => true,
    }
}

fn parameter_names<'t>(node: Node<'t>, src: &'t [u8]) -> Vec<&'t [u8]> {
    let mut out = Vec::new();
    if node.kind() == "catch_clause" {
        if let Some(p) = node.child_by_field_name("parameter") {
            if p.kind() == "identifier" {
                out.push(text(p, src));
            }
        }
        return out;
    }
    if let Some(p) = node.child_by_field_name("parameter") {
        if p.kind() == "identifier" {
            out.push(text(p, src));
        }
    }
    if let Some(params) = node.child_by_field_name("parameters") {
        for p in named(params) {
            let id = match p.kind() {
                "identifier" => Some(p),
                "assignment_pattern" => p.child_by_field_name("left"),
                "required_parameter" | "optional_parameter" => p.child_by_field_name("pattern"),
                _ => None,
            };
            if let Some(id) = id.filter(|i| i.kind() == "identifier") {
                out.push(text(id, src));
            }
        }
    }
    out
}

fn reassigned_parameter<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let names = parameter_names(node, src);
    if names.is_empty() {
        return None;
    }
    let body = node.child_by_field_name("body")?;
    let mut found = None;
    walk(body, &mut |n| {
        if found.is_some() || is_function_kind(n.kind()) {
            return false;
        }
        let target = match n.kind() {
            "assignment_expression" | "augmented_assignment_expression" => {
                n.child_by_field_name("left")
            }
            "update_expression" => n.child_by_field_name("argument"),
            _ => None,
        };
        if target.is_some_and(|t| t.kind() == "identifier" && names.contains(&text(t, src))) {
            found = Some(n);
        }
        true
    });
    found
}

fn session_middleware_comes_first(call: Node, src: &[u8]) -> bool {
    let Some(app) = call
        .child_by_field_name("function")
        .and_then(|f| f.child_by_field_name("object"))
    else {
        return false;
    };
    let Some(statement) = call.parent().filter(|p| p.kind() == "expression_statement") else {
        return false;
    };
    let mut prev = statement.prev_named_sibling();
    while let Some(s) = prev {
        if let Some(c) = s.named_child(0).filter(|c| c.kind() == "call_expression") {
            let same_app = c.child_by_field_name("function").is_some_and(|f| {
                f.child_by_field_name("object")
                    .is_some_and(|o| text(o, src) == text(app, src))
                    && f.child_by_field_name("property")
                        .is_some_and(|p| text(p, src) == b"use")
            });
            let first_arg = c
                .child_by_field_name("arguments")
                .and_then(|a| a.named_child(0));
            if same_app
                && first_arg.is_some_and(|a| {
                    a.kind() == "call_expression"
                        && a.child_by_field_name("function").is_some_and(|f| {
                            matches!(
                                text(f, src),
                                b"session" | b"cookieSession" | b"expressSession"
                            )
                        })
                })
            {
                return true;
            }
        }
        prev = s.prev_named_sibling();
    }
    false
}

fn login_without_regenerate(call: Node, src: &[u8]) -> bool {
    let two_arguments = call
        .child_by_field_name("arguments")
        .is_some_and(|a| named(a).len() >= 2);
    if !two_arguments {
        return false;
    }
    let mut cur = call.parent();
    while let Some(p) = cur {
        if is_function_kind(p.kind()) {
            let t = text(p, src);
            if t.windows(10).any(|w| w == b"regenerate") {
                return false;
            }
        }
        cur = p.parent();
    }
    true
}

fn overload_out_of_place<'t>(container: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let members = named(container);
    let mut seen: Vec<(Vec<u8>, bool, usize)> = Vec::new();
    for (i, m) in members.iter().enumerate() {
        if !matches!(
            m.kind(),
            "method_definition"
                | "method_signature"
                | "abstract_method_signature"
                | "function_signature"
                | "function_declaration"
        ) || has_token(*m, "get")
            || has_token(*m, "set")
        {
            continue;
        }
        let Some(name) = m.child_by_field_name("name") else {
            continue;
        };
        let key = (text(name, src).to_vec(), has_token(*m, "static"));
        if let Some(prev) = seen.iter_mut().find(|s| (s.0.clone(), s.1) == key) {
            if prev.2 + 1 != i {
                return Some(*m);
            }
            prev.2 = i;
        } else {
            seen.push((key.0, key.1, i));
        }
    }
    None
}

fn asserts_the_literal_it_has(expr: Node, src: &[u8]) -> bool {
    let (Some(value), Some(ty)) = (expr.named_child(0), expr.named_child(1)) else {
        return false;
    };
    ty.kind() == "literal_type"
        && matches!(value.kind(), "string" | "number" | "true" | "false")
        && text(value, src) == text(ty, src)
}
