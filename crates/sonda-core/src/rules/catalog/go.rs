//! Go rules, batch 1 (ADR-0031): bugs and code smells that the file's own
//! text proves. SonarQube's Go rules aren't tracked in `docs/sonar-parity/`
//! yet, so these carry no SonarQube key; they follow `go vet`, staticcheck
//! and Effective Go. Types aren't known here, so a rule reports only what
//! needs none: an operand that is the same text on both sides, a call whose
//! result is thrown away because the package it comes from says so.

use super::prelude::*;
use crate::lang::GO;

/// What a file calls an imported package: its alias, or the last element of
/// its path (`math/rand/v2` is `rand`). None if the file doesn't import it.
pub(super) fn import_name(node: Node, src: &[u8], path: &str) -> Option<String> {
    let mut root = node;
    while let Some(p) = root.parent() {
        root = p;
    }
    let mut found = None;
    visit(root, &mut |n| {
        if n.kind() != "import_spec" {
            return;
        }
        let Some(p) = n.child_by_field_name("path") else {
            return;
        };
        if text_of(p, src).trim_matches(['"', '`']) != path {
            return;
        }
        found = match n.child_by_field_name("name") {
            Some(name) => Some(text_of(name, src))
                .filter(|s| *s != "_" && *s != ".")
                .map(str::to_string),
            None => {
                let mut parts = path.rsplit('/');
                let last = parts.next().unwrap_or(path);
                let is_version = last.len() > 1
                    && last.starts_with('v')
                    && last[1..].bytes().all(|b| b.is_ascii_digit());
                Some(
                    if is_version {
                        parts.next().unwrap_or(last)
                    } else {
                        last
                    }
                    .to_string(),
                )
            }
        };
    });
    found
}

/// Calls `f` for `n` and every node below it, in source order.
pub(super) fn visit<'t>(n: Node<'t>, f: &mut impl FnMut(Node<'t>)) {
    f(n);
    let mut c = n.walk();
    for child in n.children(&mut c) {
        visit(child, f);
    }
}

pub(super) fn text_of<'a>(n: Node, src: &'a [u8]) -> &'a str {
    std::str::from_utf8(&src[n.byte_range()]).unwrap_or_default()
}

/// A node's text without whitespace, so `a.b` and `a . b` compare equal.
fn squeezed(n: Node, src: &[u8]) -> String {
    text_of(n, src)
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect()
}

/// Whether evaluating `n` can have an effect, so two copies of it aren't the
/// same value: a call, or a receive from a channel.
fn has_effect(n: Node, src: &[u8]) -> bool {
    let mut found = false;
    visit(n, &mut |c| {
        found |= c.kind() == "call_expression"
            || (c.kind() == "unary_expression"
                && c.child_by_field_name("operator")
                    .is_some_and(|o| text_of(o, src) == "<-"));
    });
    found
}

/// The call a statement or expression is, and the package function it names
/// (`strings`, `ToUpper`), if its operand is an import of `path`.
pub(super) fn package_call<'a>(call: Node, src: &'a [u8], path: &str) -> Option<&'a str> {
    let f = call.child_by_field_name("function")?;
    if f.kind() != "selector_expression" {
        return None;
    }
    let operand = f.child_by_field_name("operand")?;
    let field = f.child_by_field_name("field")?;
    (operand.kind() == "identifier"
        && Some(text_of(operand, src)) == import_name(call, src, path).as_deref())
    .then(|| text_of(field, src))
}

/// The arguments of a call.
pub(super) fn call_arguments(call: Node) -> Vec<Node> {
    let Some(list) = call.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut c = list.walk();
    list.named_children(&mut c)
        .filter(|a| a.kind() != "comment")
        .collect()
}

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "go/self-assignment",
        name: "Variables should not be self-assigned",
        description: "Assigning a variable to itself does nothing: the statement is redundant, or the other \
                      side was meant to be a different value.",
        message: "Remove or correct this useless self-assignment.",
        category: Bug,
        severity: Major,
        effort_minutes: 3,
        sonar: &[],
        check: Check::Query {
            langs: GO,
            query: "(assignment_statement left: (expression_list) right: (expression_list)) @match",
            filter: Some(Keep(is_self_assignment)),
        },
        example: Some(Example {
            lang: Lang::Go,
            bad: "package p\n\nfunc f(a int) int {\n\tx := a\n\tx = x\n\treturn x\n}\n",
            good: "package p\n\nfunc f(a int) int {\n\tx := a\n\tx = a + 1\n\treturn x\n}\n",
        }),
    },
    Rule {
        id: "go/identical-operands",
        name: "Identical expressions should not be used on both sides of a binary operator",
        description: "`a && a`, `a - a` and `a < a` are constants or no-ops: one side is a mistake. (`x != x` \
                      on a name is how Go tests for NaN, so a comparison of a name with itself isn't reported.)",
        message: "Identical expressions are used on both sides of this operator.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[],
        check: Check::Query {
            langs: GO,
            query: "(binary_expression left: (_) right: (_)) @match",
            filter: Some(Keep(has_identical_operands)),
        },
        example: Some(Example {
            lang: Lang::Go,
            bad: "package p\n\nfunc f(a, b bool) bool {\n\treturn a && b || a && b\n}\n",
            good: "package p\n\nfunc f(a, b, c bool) bool {\n\treturn a && b || a && c\n}\n",
        }),
    },
    Rule {
        id: "go/same-condition-in-chain",
        name: "Related \"if/else if\" statements should not have the same condition",
        description: "A branch whose condition an earlier branch of the same chain already tested can never run.",
        message: "This condition was already tested earlier in the chain.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[],
        check: Check::Query {
            langs: GO,
            query: "(if_statement condition: (_)) @match",
            filter: Some(Find(repeated_condition)),
        },
        example: Some(Example {
            lang: Lang::Go,
            bad: "package p\n\nfunc f(a, b bool) int {\n\tif a {\n\t\treturn 1\n\t} else if b {\n\t\treturn 2\n\t} else if a {\n\t\treturn 3\n\t}\n\treturn 0\n}\n",
            good: "package p\n\nfunc f(a, b bool) int {\n\tif a {\n\t\treturn 1\n\t} else if b {\n\t\treturn 2\n\t} else if !a {\n\t\treturn 3\n\t}\n\treturn 0\n}\n",
        }),
    },
    Rule {
        id: "go/duplicate-case",
        name: "Switch cases should not have the same value",
        description: "A case whose value an earlier case of the same switch has can never match.",
        message: "This case repeats an earlier one.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[],
        check: Check::Query {
            langs: GO,
            query: "(expression_switch_statement) @match",
            filter: Some(Find(repeated_case)),
        },
        example: Some(Example {
            lang: Lang::Go,
            bad: "package p\n\nfunc f(a int) string {\n\tswitch a {\n\tcase 1:\n\t\treturn \"one\"\n\tcase 2, 1:\n\t\treturn \"again\"\n\t}\n\treturn \"\"\n}\n",
            good: "package p\n\nfunc f(a int) string {\n\tswitch a {\n\tcase 1:\n\t\treturn \"one\"\n\tcase 2, 3:\n\t\treturn \"other\"\n\t}\n\treturn \"\"\n}\n",
        }),
    },
    Rule {
        id: "go/defer-in-loop",
        name: "\"defer\" should not be used in a loop",
        description: "A deferred call runs when the function returns, not when the iteration ends, so a loop \
                      that defers a `Close` or an `Unlock` holds every resource until it's over. Put the body \
                      in a function, or call it directly.",
        message: "This deferred call waits for the function to return, not for the iteration.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[],
        check: Check::Query {
            langs: GO,
            query: "(defer_statement) @match",
            filter: Some(Keep(is_in_loop)),
        },
        example: Some(Example {
            lang: Lang::Go,
            bad: "package p\n\nimport \"os\"\n\nfunc f(names []string) {\n\tfor _, n := range names {\n\t\tfh, _ := os.Open(n)\n\t\tdefer fh.Close()\n\t}\n}\n",
            good: "package p\n\nimport \"os\"\n\nfunc f(names []string) {\n\tfor _, n := range names {\n\t\tfunc() {\n\t\t\tfh, _ := os.Open(n)\n\t\t\tdefer fh.Close()\n\t\t}()\n\t}\n}\n",
        }),
    },
    Rule {
        id: "go/empty-error-branch",
        name: "An error that is checked should be handled",
        description: "`if err != nil {}` tests for a failure and does nothing about it: the error is lost, and \
                      the code goes on as if the call had worked.",
        message: "Handle this error, or return it.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[],
        check: Check::Query {
            langs: GO,
            query: "(if_statement condition: (binary_expression)) @match",
            filter: Some(Keep(is_empty_error_branch)),
        },
        example: Some(Example {
            lang: Lang::Go,
            bad: "package p\n\nimport \"os\"\n\nfunc f() {\n\t_, err := os.Open(\"a\")\n\tif err != nil {\n\t}\n}\n",
            good: "package p\n\nimport \"os\"\n\nfunc f() error {\n\t_, err := os.Open(\"a\")\n\tif err != nil {\n\t\treturn err\n\t}\n\treturn nil\n}\n",
        }),
    },
    Rule {
        id: "go/unreachable-code",
        name: "Statements after a jump should not be unreachable",
        description: "Code after a `return`, `break`, `continue`, `goto` or `panic` in the same block never runs.",
        message: "Remove this unreachable code.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[],
        check: Check::Query {
            langs: GO,
            query: "(statement_list) @match",
            filter: Some(Find(unreachable_statement)),
        },
        example: Some(Example {
            lang: Lang::Go,
            bad: "package p\n\nfunc f() int {\n\treturn 1\n\tprintln(\"never\")\n\treturn 2\n}\n",
            good: "package p\n\nfunc f(a bool) int {\n\tif a {\n\t\treturn 1\n\t}\n\tprintln(\"sometimes\")\n\treturn 2\n}\n",
        }),
    },
    Rule {
        id: "go/ignored-result",
        name: "The result of a function that only computes one should be used",
        description: "`append(s, x)`, `strings.ToUpper(s)` and `fmt.Sprintf(...)` don't change what they're \
                      given: called as a statement, their result is thrown away and the call does nothing.",
        message: "This call only computes a value, and its result isn't used.",
        category: Bug,
        severity: Major,
        effort_minutes: 3,
        sonar: &[],
        check: Check::Query {
            langs: GO,
            query: "(expression_statement (call_expression)) @match",
            filter: Some(Find(ignored_result)),
        },
        example: Some(Example {
            lang: Lang::Go,
            bad: "package p\n\nfunc f(s []int) {\n\tappend(s, 1)\n}\n",
            good: "package p\n\nfunc f(s []int) []int {\n\ts = append(s, 1)\n\treturn s\n}\n",
        }),
    },
    Rule {
        id: "go/redundant-bool-literal",
        name: "Boolean literals should not be used in comparisons",
        description: "`x == true` is `x`, and `x == false` is `!x`.",
        message: "Remove the comparison with a boolean literal.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[],
        check: Check::Query {
            langs: GO,
            query: "(binary_expression left: (_) right: (_)) @match",
            filter: Some(Keep(compares_with_bool_literal)),
        },
        example: Some(Example {
            lang: Lang::Go,
            bad: "package p\n\nfunc f(ok bool) int {\n\tif ok == true {\n\t\treturn 1\n\t}\n\treturn 0\n}\n",
            good: "package p\n\nfunc f(ok bool) int {\n\tif ok {\n\t\treturn 1\n\t}\n\treturn 0\n}\n",
        }),
    },
    Rule {
        id: "go/collapsible-if",
        name: "Collapsible \"if\" statements should be merged",
        description: "An `if` whose only statement is another `if`, with no `else` on either, reads better as \
                      one `if` with `&&`.",
        message: "Merge this `if` with the one it contains.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[],
        check: Check::Query {
            langs: GO,
            query: "(if_statement condition: (_) consequence: (block)) @match",
            filter: Some(Keep(is_collapsible_if)),
        },
        example: Some(Example {
            lang: Lang::Go,
            bad: "package p\n\nfunc f(a, b bool) {\n\tif a {\n\t\tif b {\n\t\t\tprintln(\"both\")\n\t\t}\n\t}\n}\n",
            good: "package p\n\nfunc f(a, b bool) {\n\tif a && b {\n\t\tprintln(\"both\")\n\t}\n}\n",
        }),
    },
    Rule {
        id: "go/empty-function",
        name: "Functions should not be empty",
        description: "A function with no statement and no comment saying why is unfinished, or no longer needed.",
        message: "Add a statement or a comment saying why this function is empty.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[],
        check: Check::Query {
            langs: GO,
            query: "(function_declaration name: (identifier) body: (block)) @match",
            filter: Some(Keep(is_empty_function)),
        },
        example: Some(Example {
            lang: Lang::Go,
            bad: "package p\n\nfunc cleanup() {\n}\n",
            good: "package p\n\nfunc cleanup() {\n\t// Nothing to release yet.\n}\n",
        }),
    },
    Rule {
        id: "go/context-not-first",
        name: "A context should be the first parameter",
        description: "By convention a `context.Context` comes first and is named `ctx`, so a reader finds it \
                      without reading the whole signature.",
        message: "Make this context the first parameter.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[],
        check: Check::Query {
            langs: GO,
            query: "[(function_declaration) (method_declaration)] @match",
            filter: Some(Find(late_context)),
        },
        example: Some(Example {
            lang: Lang::Go,
            bad: "package p\n\nimport \"context\"\n\nfunc f(id int, ctx context.Context) {}\n",
            good: "package p\n\nimport \"context\"\n\nfunc f(ctx context.Context, id int) {}\n",
        }),
    },
    Rule {
        id: "go/error-not-last",
        name: "An error should be the last value a function returns",
        description: "By convention a function that returns an `error` returns it last, so callers write \
                      `v, err := f()`.",
        message: "Return the error last.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[],
        check: Check::Query {
            langs: GO,
            query: "[(function_declaration result: (parameter_list)) (method_declaration result: (parameter_list))] @match",
            filter: Some(Find(early_error)),
        },
        example: Some(Example {
            lang: Lang::Go,
            bad: "package p\n\nfunc f() (error, int) {\n\treturn nil, 0\n}\n",
            good: "package p\n\nfunc f() (int, error) {\n\treturn 0, nil\n}\n",
        }),
    },
    Rule {
        id: "go/shadowed-variable",
        name: "Variables should not shadow outer ones that are used afterwards",
        description: "A `:=` or `var` statement in an inner block with the name of a variable declared outside it makes a new \
                      variable, so the outer one keeps its old value: `err` assigned in an `if` and then \
                      returned unchanged is the usual bug. Only an outer variable that is used after the \
                      inner block is reported.",
        message: "This declaration hides a variable of an outer scope that is used after it.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[],
        check: Check::Semantic {
            langs: GO,
            find: shadowing_declarations,
        },
        example: Some(Example {
            lang: Lang::Go,
            bad: "package p\n\nfunc f() error {\n\tvar err error\n\tif true {\n\t\terr := g()\n\t\t_ = err\n\t}\n\treturn err\n}\n\nfunc g() error { return nil }\n",
            good: "package p\n\nfunc f() error {\n\tvar err error\n\tif true {\n\t\terr = g()\n\t}\n\treturn err\n}\n\nfunc g() error { return nil }\n",
        }),
    },
    Rule {
        id: "go/underscore-in-name",
        name: "Function names should not contain underscores",
        description: "Go names are MixedCaps, not snake_case: `parse_line` should be `parseLine`. Tests, \
                      benchmarks and examples (`Test_x`, `Example_y`) are the convention's exception.",
        message: "Rename this function in MixedCaps.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[],
        check: Check::Query {
            langs: GO,
            query: "[(function_declaration name: (identifier) @name) (method_declaration name: (field_identifier) @name)] @match",
            filter: Some(Find(underscored_name)),
        },
        example: Some(Example {
            lang: Lang::Go,
            bad: "package p\n\nfunc parse_line(s string) string { return s }\n",
            good: "package p\n\nfunc parseLine(s string) string { return s }\n",
        }),
    },
];

// ---------------------------------------------------------------- filters

/// Where the scope a name was declared in ends: the end of the statement or
/// block that holds its declaration.
fn scope_end(name: Node) -> usize {
    let mut p = name.parent();
    while let Some(x) = p {
        if matches!(
            x.kind(),
            "block"
                | "if_statement"
                | "for_statement"
                | "expression_switch_statement"
                | "type_switch_statement"
                | "select_statement"
                | "expression_case"
                | "default_case"
                | "type_case"
                | "communication_case"
                | "func_literal"
                | "function_declaration"
                | "method_declaration"
        ) {
            return x.end_byte();
        }
        p = x.parent();
    }
    name.end_byte()
}

/// Whether a declaration is a statement of a block, as `err := g()` is, and
/// not part of the head of an `if`, a `for` or a `switch`, whose variable
/// lives only as long as the statement does.
fn is_block_statement(declarator: Node) -> bool {
    let mut n = declarator;
    while let Some(p) = n.parent() {
        match p.kind() {
            "var_declaration" | "var_spec_list" => n = p,
            "statement_list" => return true,
            _ => return false,
        }
    }
    false
}

/// The declarations that hide a local of an outer scope that the code uses
/// after the inner one ends. Left alone: a variable of a statement's head
/// (`if err := f(); err != nil`, a `range`, a type switch), a parameter
/// (`t.Run("x", func(t *testing.T) {...})` is the idiom), and a declaration
/// that starts from the outer variable (`x := x`).
fn shadowing_declarations<'t>(m: &crate::semantic::Model<'t>, _src: &[u8]) -> Vec<Node<'t>> {
    use crate::semantic::DeclKind::{Const, Let, Param, Var};
    let local = |k| matches!(k, Var | Let | Param | Const);
    let mut found = Vec::new();
    for d in &m.decls {
        let Some(declarator) = d.declarator.filter(|n| is_block_statement(*n)) else {
            continue;
        };
        if d.kind != Var {
            continue;
        }
        let end = scope_end(d.node);
        let mut scope = m.scopes[d.scope].parent;
        while let Some(s) = scope.filter(|s| *s != 0) {
            let hidden = m.decls_named(s, &d.name).iter().copied().find(|&o| {
                let outer = &m.decls[o];
                let within = |r: &crate::semantic::Ref| {
                    r.node.start_byte() >= declarator.start_byte()
                        && r.node.end_byte() <= declarator.end_byte()
                };
                local(outer.kind)
                    && outer.node.start_byte() < d.node.start_byte()
                    && m.refs
                        .iter()
                        .any(|r| r.decl == Some(o) && r.node.start_byte() >= end)
                    && !m.refs.iter().any(|r| r.decl == Some(o) && within(r))
            });
            if hidden.is_some() {
                found.push(d.node);
                break;
            }
            scope = m.scopes[s].parent;
        }
    }
    found
}

fn is_self_assignment(n: Node, src: &[u8]) -> bool {
    let (Some(l), Some(r), Some(op)) = (
        n.child_by_field_name("left"),
        n.child_by_field_name("right"),
        n.child_by_field_name("operator"),
    ) else {
        return false;
    };
    // `x += x` doubles it, which is no self-assignment.
    if text_of(op, src) != "=" {
        return false;
    }
    let mut c = l.walk();
    let left: Vec<Node> = l.named_children(&mut c).collect();
    let mut c = r.walk();
    let right: Vec<Node> = r.named_children(&mut c).collect();
    left.len() == right.len()
        && left.iter().zip(&right).any(|(a, b)| {
            squeezed(*a, src) != "_"
                && squeezed(*a, src) == squeezed(*b, src)
                && !has_effect(*a, src)
        })
}

fn has_identical_operands(n: Node, src: &[u8]) -> bool {
    let (Some(l), Some(r), Some(op)) = (
        n.child_by_field_name("left"),
        n.child_by_field_name("right"),
        n.child_by_field_name("operator"),
    ) else {
        return false;
    };
    if squeezed(l, src) != squeezed(r, src) || has_effect(l, src) {
        return false;
    }
    match text_of(op, src) {
        "&&" | "||" | "<" | ">" | "<=" | ">=" | "-" | "/" | "%" | "^" | "&^" => true,
        // `f != f` is the NaN test: only a computed operand is a typo.
        "==" | "!=" => !matches!(
            l.kind(),
            "identifier" | "selector_expression" | "index_expression"
        ),
        _ => false,
    }
}

/// The condition of a later `else if` that repeats an earlier one.
fn repeated_condition<'t>(n: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    // Only the head of a chain: the rest are reached from it.
    if n.parent().is_some_and(|p| {
        p.kind() == "if_statement"
            && p.child_by_field_name("alternative")
                .is_some_and(|a| a.id() == n.id())
    }) {
        return None;
    }
    let mut seen: Vec<String> = Vec::new();
    let mut current = Some(n);
    while let Some(branch) = current {
        let cond = branch.child_by_field_name("condition")?;
        // A condition can depend on what an initializer declared.
        if branch.child_by_field_name("initializer").is_some() || has_effect(cond, src) {
            return None;
        }
        let key = squeezed(cond, src);
        if seen.contains(&key) {
            return Some(cond);
        }
        seen.push(key);
        current = branch
            .child_by_field_name("alternative")
            .filter(|a| a.kind() == "if_statement");
    }
    None
}

/// The case value that repeats an earlier one in the same switch.
fn repeated_case<'t>(n: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut seen: Vec<String> = Vec::new();
    let mut c = n.walk();
    for case in n
        .named_children(&mut c)
        .filter(|k| k.kind() == "expression_case")
    {
        let Some(values) = case.child_by_field_name("value") else {
            continue;
        };
        let mut vc = values.walk();
        for v in values.named_children(&mut vc) {
            if has_effect(v, src) {
                continue;
            }
            let key = squeezed(v, src);
            if seen.contains(&key) {
                return Some(v);
            }
            seen.push(key);
        }
    }
    None
}

/// Whether a `defer` is in a loop of its own function: a function literal
/// in the loop is a fresh function, so its deferred calls run at its end.
fn is_in_loop(n: Node, _src: &[u8]) -> bool {
    let mut p = n.parent();
    while let Some(x) = p {
        match x.kind() {
            "function_declaration" | "method_declaration" | "func_literal" => return false,
            "for_statement" => return true,
            _ => p = x.parent(),
        }
    }
    false
}

fn is_empty_error_branch(n: Node, src: &[u8]) -> bool {
    let (Some(cond), Some(body)) = (
        n.child_by_field_name("condition"),
        n.child_by_field_name("consequence"),
    ) else {
        return false;
    };
    if n.child_by_field_name("alternative").is_some() || body.named_child_count() != 0 {
        return false;
    }
    let (Some(l), Some(r), Some(op)) = (
        cond.child_by_field_name("left"),
        cond.child_by_field_name("right"),
        cond.child_by_field_name("operator"),
    ) else {
        return false;
    };
    let name = text_of(l, src);
    text_of(op, src) == "!="
        && text_of(r, src) == "nil"
        && l.kind() == "identifier"
        && (name == "err" || name.ends_with("Err") || name.ends_with("err"))
}

/// The first statement after one that always leaves the block.
fn unreachable_statement<'t>(n: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut c = n.walk();
    let mut jumped = false;
    for s in n.named_children(&mut c) {
        if s.kind() == "comment" {
            continue;
        }
        if jumped {
            // A label can be the target of a `goto`; declarations don't run.
            if matches!(
                s.kind(),
                "labeled_statement" | "function_declaration" | "type_declaration"
            ) {
                continue;
            }
            return Some(s);
        }
        jumped = match s.kind() {
            "return_statement" | "break_statement" | "continue_statement" | "goto_statement" => {
                true
            }
            "expression_statement" => s
                .named_child(0)
                .filter(|e| e.kind() == "call_expression")
                .and_then(|e| e.child_by_field_name("function"))
                .is_some_and(|f| f.kind() == "identifier" && text_of(f, src) == "panic"),
            _ => false,
        };
    }
    None
}

/// Package functions whose only effect is their result.
const PURE: &[(&str, &[&str])] = &[
    (
        "strings",
        &[
            "ToUpper",
            "ToLower",
            "TrimSpace",
            "Trim",
            "TrimLeft",
            "TrimRight",
            "TrimPrefix",
            "TrimSuffix",
            "Replace",
            "ReplaceAll",
            "Split",
            "Join",
            "Repeat",
            "Fields",
            "Contains",
            "HasPrefix",
            "HasSuffix",
            "Index",
        ],
    ),
    ("fmt", &["Sprintf", "Sprint", "Sprintln", "Errorf"]),
    ("errors", &["New"]),
    (
        "strconv",
        &["Itoa", "Quote", "FormatInt", "FormatBool", "FormatFloat"],
    ),
    ("path/filepath", &["Join", "Clean", "Base", "Dir", "Ext"]),
    ("path", &["Join", "Clean", "Base", "Dir", "Ext"]),
];

/// The call, if it's a statement whose value is all it does.
fn ignored_result<'t>(n: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let call = n.named_child(0).filter(|c| c.kind() == "call_expression")?;
    let f = call.child_by_field_name("function")?;
    if f.kind() == "identifier" {
        return matches!(text_of(f, src), "append" | "len" | "cap" | "make" | "new")
            .then_some(call);
    }
    // The field first: it's cheap, and finding what the operand imports isn't.
    let field = text_of(f.child_by_field_name("field")?, src);
    PURE.iter()
        .filter(|(_, funcs)| funcs.contains(&field))
        .any(|(path, _)| package_call(call, src, path).is_some())
        .then_some(call)
}

fn compares_with_bool_literal(n: Node, src: &[u8]) -> bool {
    let (Some(l), Some(r), Some(op)) = (
        n.child_by_field_name("left"),
        n.child_by_field_name("right"),
        n.child_by_field_name("operator"),
    ) else {
        return false;
    };
    let literal = |x: Node| matches!(text_of(x, src), "true" | "false") && x.kind() != "string";
    matches!(text_of(op, src), "==" | "!=") && (literal(l) || literal(r))
}

fn is_collapsible_if(n: Node, _src: &[u8]) -> bool {
    let plain = |i: Node| {
        i.child_by_field_name("alternative").is_none()
            && i.child_by_field_name("initializer").is_none()
    };
    if !plain(n) {
        return false;
    }
    let Some(body) = n.child_by_field_name("consequence") else {
        return false;
    };
    let mut c = body.walk();
    let statements: Vec<Node> = body
        .named_children(&mut c)
        .flat_map(|list| {
            let mut lc = list.walk();
            list.named_children(&mut lc).collect::<Vec<_>>()
        })
        .collect();
    matches!(statements.as_slice(), [only] if only.kind() == "if_statement" && plain(*only))
}

fn is_empty_function(n: Node, src: &[u8]) -> bool {
    let name = n
        .child_by_field_name("name")
        .map_or("", |x| text_of(x, src));
    // `init` runs by itself, and a `main` can be a stub to build against.
    !matches!(name, "init" | "main" | "_")
        && n.child_by_field_name("body")
            .is_some_and(|b| b.named_child_count() == 0)
}

/// The `context.Context` parameter that comes after another parameter.
fn late_context<'t>(n: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let params = n.child_by_field_name("parameters")?;
    let mut position = 0;
    let mut c = params.walk();
    for p in params.named_children(&mut c) {
        let names = p
            .children_by_field_name("name", &mut p.walk())
            .count()
            .max(1);
        let is_context = p
            .child_by_field_name("type")
            .is_some_and(|t| text_of(t, src) == "context.Context");
        if is_context && position > 0 {
            return Some(p);
        }
        position += names;
    }
    None
}

/// The result list, when an `error` in it isn't last.
fn early_error<'t>(n: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let result = n.child_by_field_name("result")?;
    let mut c = result.walk();
    let types: Vec<&str> = result
        .named_children(&mut c)
        .filter_map(|p| p.child_by_field_name("type"))
        .map(|t| text_of(t, src))
        .collect();
    let last = types.len().checked_sub(1)?;
    types[..last].contains(&"error").then_some(result)
}

fn underscored_name<'t>(n: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let name = n.child_by_field_name("name")?;
    let t = text_of(name, src);
    let convention = ["Test", "Benchmark", "Example", "Fuzz"]
        .iter()
        .any(|p| t.starts_with(p));
    (t.trim_start_matches('_').contains('_') && !convention).then_some(name)
}

#[cfg(test)]
mod tests {
    use crate::analysis::analyze;
    use crate::analysis::tests::far_deadline;
    use crate::config::Config;
    use crate::lang::Lang;
    use crate::rules::RuleSet;

    /// The lines `rule` flags in a Go file.
    fn flagged(rule: &str, body: &str) -> Vec<usize> {
        let cfg = Config::default();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let src = format!("package p\n\n{body}");
        let file = analyze("a.go", Lang::Go, &src, &rules, &cfg, far_deadline()).unwrap();
        file.issues
            .iter()
            .filter(|i| i.rule == rule)
            .map(|i| i.line - 2)
            .collect()
    }

    #[test]
    fn comparing_a_name_with_itself_is_the_nan_test() {
        let src = "func f(a float64, b, c bool) bool {\n\tif a != a {\n\t\treturn true\n\t}\n\treturn b && b || c\n}\n";
        assert_eq!(flagged("go/identical-operands", src), [5]);
        let sums = "func g(a, b int) bool { return a+b == a+b }\n";
        assert_eq!(flagged("go/identical-operands", sums), [1]);
    }

    #[test]
    fn self_assignment_is_only_a_plain_assignment_of_the_same_thing() {
        let src =
            "func f(a []int, x, y int) {\n\ta[0] = a[0]\n\tx += x\n\tx, y = y, x\n\tx = x\n}\n";
        assert_eq!(flagged("go/self-assignment", src), [2, 5]);
    }

    #[test]
    fn a_condition_with_a_call_isnt_a_repeat() {
        let src = "func f(next func() bool) {\n\tif next() {\n\t} else if next() {\n\t}\n}\n";
        assert!(flagged("go/same-condition-in-chain", src).is_empty());
    }

    #[test]
    fn a_defer_in_a_function_literal_in_a_loop_runs_with_the_literal() {
        let src = "func f(xs []int, c interface{ Close() }) {\n\tfor range xs {\n\t\tfunc() {\n\t\t\tdefer c.Close()\n\t\t}()\n\t}\n\tfor range xs {\n\t\tdefer c.Close()\n\t}\n}\n";
        assert_eq!(flagged("go/defer-in-loop", src), [8]);
    }

    #[test]
    fn code_after_a_jump_in_the_same_block_is_unreachable_not_after_a_branch() {
        let src = "func f(a bool) int {\n\tif a {\n\t\treturn 1\n\t}\n\treturn 2\n}\nfunc g() {\n\tpanic(\"x\")\n\tprintln(\"never\")\n}\nfunc h() {\nL:\n\tfor {\n\t\tbreak L\n\t}\n}\n";
        assert_eq!(flagged("go/unreachable-code", src), [9]);
    }

    #[test]
    fn a_name_that_is_not_the_imported_package_is_not_it() {
        let ok = "func f(b []byte) {\n\tmd5 := struct{ Sum func([]byte) }{}\n\tmd5.Sum(b)\n}\n";
        assert!(flagged("go/weak-hash", ok).is_empty());
        let hash = "import \"crypto/md5\"\n\nfunc f(b []byte) { _ = md5.Sum(b) }\n";
        assert_eq!(flagged("go/weak-hash", hash), [3]);
    }

    #[test]
    fn what_looks_like_a_credential_is_one_only_with_a_value_that_could_be() {
        let src = "type C struct{ Password string }\nfunc f(c *C) {\n\tc.Password = \"hunter2-prod\"\n\tpasswordEnv := \"DB_PASSWORD\"\n\tpassword := \"\"\n\tsecret := \"%s\"\n\t_ = C{Password: \"s3cr3t-value\"}\n\t_, _, _ = passwordEnv, password, secret\n}\n";
        assert_eq!(flagged("go/hardcoded-credentials", src), [3, 7]);
    }

    #[test]
    fn a_query_is_built_only_from_text_and_values() {
        let src = "import (\n\t\"database/sql\"\n\t\"fmt\"\n)\n\nfunc f(db *sql.DB, id, name string) {\n\tdb.Query(\"SELECT * FROM t WHERE id = ?\", id)\n\tdb.Query(fmt.Sprintf(\"SELECT * FROM t WHERE n = '%s'\", name))\n\tdb.Exec(\"DELETE FROM t WHERE id = \" + id)\n\tdb.Exec(\"VACUUM\")\n\tlog := \"hello \" + name\n\t_ = log\n}\n";
        assert_eq!(flagged("go/sql-concatenation", src), [8, 9]);
    }

    #[test]
    fn a_shell_runs_a_script_that_isnt_fixed() {
        let src = "import \"os/exec\"\n\nfunc f(x string) {\n\texec.Command(\"sh\", \"-c\", \"ls -l\")\n\texec.Command(\"ls\", x)\n\texec.Command(\"bash\", \"-c\", x)\n}\n";
        assert_eq!(flagged("go/shell-command", src), [6]);
    }

    #[test]
    fn only_a_mode_anyone_can_write_is_flagged() {
        let src = "import \"os\"\n\nfunc f(p string) {\n\tos.Chmod(p, 0755)\n\tos.Chmod(p, 0777)\n\tos.WriteFile(p, nil, 0o666)\n\tos.WriteFile(p, nil, 0o644)\n\tos.Chmod(p, os.FileMode(0602))\n}\n";
        assert_eq!(flagged("go/permissive-file-mode", src), [5, 6, 8]);
    }

    #[test]
    fn a_name_is_hidden_only_when_the_outer_one_is_used_after() {
        let src = "func g() error { return nil }\n\nfunc used() error {\n\tvar err error\n\tif true {\n\t\terr := g()\n\t\t_ = err\n\t}\n\treturn err\n}\n\nfunc unused() {\n\terr := g()\n\t_ = err\n\tif true {\n\t\terr := g()\n\t\t_ = err\n\t}\n}\n\nfunc siblings(a, b bool) {\n\tif a {\n\t\tx := 1\n\t\t_ = x\n\t}\n\tif b {\n\t\tx := 2\n\t\t_ = x\n\t}\n}\n";
        assert_eq!(flagged("go/shadowed-variable", src), [6]);
    }

    #[test]
    fn statement_heads_type_switches_and_copies_are_not_shadowing_slips() {
        let src = "func g() error { return nil }\n\nfunc f(v interface{}, xs []int) error {\n\tvar err error\n\tif err := g(); err != nil {\n\t\treturn err\n\t}\n\tswitch v := v.(type) {\n\tcase int:\n\t\t_ = v\n\t}\n\tfor _, x := range xs {\n\t\tx := x\n\t\t_ = x\n\t}\n\treturn err\n}\n";
        assert!(flagged("go/shadowed-variable", src).is_empty());
    }

    #[test]
    fn a_callbacks_parameter_named_like_a_variable_is_the_idiom() {
        let src = "func f(items []int) int {\n\tn := 0\n\tadd := func(n int) int { return n + 1 }\n\tfor _, i := range items {\n\t\tn += add(i)\n\t}\n\treturn n\n}\n";
        assert!(flagged("go/shadowed-variable", src).is_empty());
    }

    #[test]
    fn a_new_scan_skips_what_go_says_it_generated() {
        let license = "// Copyright 2024 Someone\n".repeat(12);
        let generated =
            format!("{license}\n// Code generated by protoc-gen-go. DO NOT EDIT.\n\npackage p\n");
        assert!(crate::scanner::go_generated_marker(&generated).is_some());
        let code = format!("{license}\npackage p\n\n// Code generated by hand. DO NOT EDIT.\n");
        assert!(crate::scanner::go_generated_marker(&code).is_none());
    }
}
