//! JavaScript and TypeScript rules on the semantic model (ADR-0008, phase
//! S1: scopes and symbols).

use super::*;
use crate::semantic::{DeclId, DeclKind, Model, ScopeKind};
use std::collections::{HashMap, HashSet};

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "js/unused-variable",
        name: "Unused local variables and functions should be removed",
        description: "A local that is never read is dead code, or a sign that something meant \
                      to use it doesn't. Names starting with `_`, and names that only leave a \
                      property out of a `...rest` destructuring, are ignored.",
        message: "Remove this unused local, or use it.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S1481")],
        check: Check::Semantic {
            langs: JS_TS,
            find: unused_locals,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function total(items) { const tax = 0.2; return items.length; }",
            good: "function total(items) { const tax = 0.2; return items.length * tax; }\n\
                   function pick({ secret, ...rest }) { return rest; }\n\
                   function f(_unused) { let _ignored = 1; }",
        }),
    },
    Rule {
        id: "js/unused-import",
        name: "Unused imports should be removed",
        description: "An import nothing uses adds a dependency and slows loading for nothing. \
                      Uses in types and JSX count; `React` counts as used in files with JSX.",
        message: "Remove this unused import.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S1128")],
        check: Check::Semantic {
            langs: JS_TS,
            find: unused_imports,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "import { readFile, writeFile } from 'node:fs';\nreadFile('a');",
            good: "import { readFile } from 'node:fs';\nimport React from 'react';\nreadFile('a');\nconst v = <div />;",
        }),
    },
    Rule {
        id: "js/const-reassigned",
        name: "Constants should not be reassigned",
        description: "Assigning to a `const` throws a TypeError at run time.",
        message: "This assigns to a constant; declare it with 'let' if it changes.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S3500")],
        check: Check::Semantic {
            langs: JS_TS,
            find: const_reassigned,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const count = 0;\ncount += 1;",
            good: "let count = 0;\ncount += 1;\nconst list = [];\nlist.push(1);",
        }),
    },
    Rule {
        id: "js/redeclared",
        name: "Variables and functions should not be redeclared",
        description: "Declaring a name twice in the same scope (with `var`, `function` or as a \
                      parameter) silently replaces the first one. TypeScript's declaration \
                      merging (interfaces, namespaces, enums) is fine.",
        message: "Rename this: an earlier declaration in the same scope has the same name.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2814")],
        check: Check::Semantic {
            langs: JS_TS,
            find: redeclared,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function load(url) { var url = normalize(url); return fetch(url); }",
            good: "function load(url) { const normalized = normalize(url); return fetch(normalized); }",
        }),
    },
    Rule {
        id: "js/implicit-global",
        name: "Variables should be declared before they are assigned",
        description: "Assigning to an undeclared name creates a global in sloppy mode (and \
                      throws in strict mode and modules), usually from a typo or a forgotten \
                      `let`.",
        message: "Declare this variable with 'let' or 'const'; it is assigned without a declaration.",
        category: CodeSmell,
        severity: Blocker,
        effort_minutes: 2,
        sonar: &[exact("S2703")],
        check: Check::Semantic {
            langs: JS_TS,
            find: implicit_globals,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function count(xs) { total = 0; for (const x of xs) { total += x; } return total; }",
            good: "function count(xs) { let total = 0; for (const x of xs) { total += x; } return total; }\nconsole.log(process.env.HOME);",
        }),
    },
    Rule {
        id: "js/import-reassigned",
        name: "Imported names should not be reassigned",
        description: "Imports are read-only bindings: assigning to one throws in modules.",
        message: "Copy this import into a local variable instead of assigning to it.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6522")],
        check: Check::Semantic {
            langs: JS_TS,
            find: import_reassigned,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "import { limit } from './config';\nlimit = 10;",
            good: "import { limit } from './config';\nlet max = limit;\nmax = 10;",
        }),
    },
    Rule {
        id: "js/unused-parameter",
        name: "Unused function parameters should be removed",
        description: "A parameter the function never reads is noise for callers. Only \
                      trailing ones are reported, since earlier ones hold later ones' \
                      positions, and only for functions whose arity callers can't depend \
                      on: not methods, callbacks, or functions passed by name (Express, for \
                      one, treats four-parameter middleware as error handlers).",
        message: "Remove this unused parameter.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1172")],
        check: Check::Semantic {
            langs: JS_TS,
            find: unused_params,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function area(width, height, unit) { return width * height; }\narea(1, 2);",
            good: "function area(width, height) { return width * height; }\n\
                   function onError(err, req, res, next) { res.status(500).end(); }\n\
                   app.use(onError);\nitems.map((item, index) => index);",
        }),
    },
    Rule {
        id: "js/shadowed-variable",
        name: "Variables should not shadow outer ones",
        description: "A declaration with the same name as one in an enclosing scope hides it, \
                      so code meaning the outer one silently gets the inner one.",
        message: "Rename this: it hides a variable with the same name in an enclosing scope.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1117")],
        check: Check::Semantic {
            langs: JS_TS,
            find: shadowed,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function total(items) { let sum = 0; for (const item of items) { const sum = item.price; } return sum; }",
            good: "function total(items) { let sum = 0; for (const item of items) { sum += item.price; } return sum; }",
        }),
    },
    Rule {
        id: "js/var-outside-block",
        name: "Variables should be used in the blocks where they are declared",
        description: "A `var` declared in a block is visible in the whole function, but using \
                      it outside that block relies on hoisting and is easy to misread. \
                      Declare it where it is used, or use `let`.",
        message: "Move this variable's declaration: it is declared in a block this use is outside of.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S2392")],
        check: Check::Semantic {
            langs: JS_TS,
            find: var_outside_block,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function find(xs, y) { for (var i = 0; i < xs.length; i++) { if (xs[i] === y) break; } return i; }",
            good: "function find(xs, y) { var i; for (i = 0; i < xs.length; i++) { if (xs[i] === y) break; } return i; }",
        }),
    },
    Rule {
        id: "js/prefer-const",
        name: "Variables that are never reassigned should be declared with const",
        description: "`const` tells readers, and the engine, that a binding never changes. \
                      Reported when every variable of a `let` declaration is initialized and \
                      never assigned again, so the fix is just the keyword.",
        message: "Declare this with 'const': it is never reassigned.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 1,
        sonar: &[exact("S3353")],
        check: Check::Semantic {
            langs: JS_TS,
            find: prefer_const,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "let limit = 10;\nexport const pages = limit * 2;",
            good: "const limit = 10;\nlet count = 0;\ncount++;\nlet a = 1, b = 2;\nb++;\nexport const pages = limit * 2 + count + a + b;",
        }),
    },
    Rule {
        id: "js/collection-never-read",
        name: "Collection contents should be used",
        description: "An array, set or map that is only ever added to costs memory and work \
                      for nothing: nothing reads what it holds.",
        message: "Use this collection's contents, or remove it.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S4030")],
        check: Check::Semantic {
            langs: JS_TS,
            find: collection_never_read,
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "function load(rows) { const seen = new Set(); for (const r of rows) { seen.add(r.id); } return rows.length; }",
            good: "function load(rows) { const seen = new Set(); for (const r of rows) { seen.add(r.id); } return seen.size; }",
        }),
    },
    Rule {
        id: "js/unused-private-field",
        name: "Unused private class fields should be removed",
        description: "A private field (`#name`, or TypeScript `private`) can only be used \
                      inside its class; if nothing there uses it, it is dead. Decorated \
                      fields are left alone, since frameworks use them.",
        message: "Remove this unused private field.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1068")],
        check: Check::Semantic {
            langs: JS_TS,
            find: unused_private_fields,
        },
        example: Some(Example {
            lang: Lang::TypeScript,
            bad: "class Cache { private hits = 0; #size = 0; get(k: string) { return k; } }",
            good: "class Cache { private hits = 0; #size = 0; constructor(private readonly store: Map<string, string>) {}\n  get(k: string) { this.hits++; this.#size = this.store.size; return this.store.get(k); } }",
        }),
    },
];

/// Per declaration, the indexes of the references that resolve to it.
fn refs_by_decl(m: &Model) -> Vec<Vec<usize>> {
    let mut by = vec![Vec::new(); m.decls.len()];
    for (i, r) in m.refs.iter().enumerate() {
        if let Some(d) = r.decl {
            by[d].push(i);
        }
    }
    by
}

/// Declarations by the id of their name node.
fn decl_by_node(m: &Model) -> HashMap<usize, DeclId> {
    m.decls
        .iter()
        .enumerate()
        .map(|(i, d)| (d.node.id(), i))
        .collect()
}

/// Whether `node` is `parent`'s `field`.
fn is_field(parent: Node, field: &str, node: Node) -> bool {
    parent.child_by_field_name(field) == Some(node)
}

fn unused_params<'t>(m: &Model<'t>, _: &[u8]) -> Vec<Node<'t>> {
    let mut found = Vec::new();
    let mut refs: Option<Vec<Vec<usize>>> = None;
    let mut decls: Option<HashMap<usize, DeclId>> = None;
    for f in &m.functions {
        let used = |p: &Vec<DeclId>| {
            p.is_empty()
                || p.iter()
                    .any(|&d| m.decls[d].reads > 0 || m.decls[d].name.starts_with('_'))
        };
        let start = f.params.iter().rposition(used).map_or(0, |i| i + 1);
        if start == f.params.len() || m.scopes[f.scope].uses_arguments {
            continue;
        }
        // The function's own name: declared, or the variable it initializes.
        let name = match f.node.kind() {
            "function_declaration" | "generator_function_declaration" => {
                f.node.child_by_field_name("name")
            }
            _ => f
                .node
                .parent()
                .filter(|p| p.kind() == "variable_declarator" && is_field(*p, "value", f.node))
                .and_then(|p| p.child_by_field_name("name"))
                .filter(|n| n.kind() == "identifier"),
        };
        // An exported signature is an API: callers may pass every argument.
        let Some(name) = name.filter(|_| !exported(f.node)) else {
            continue;
        };
        let refs = refs.get_or_insert_with(|| refs_by_decl(m));
        let Some(&decl) = decls.get_or_insert_with(|| decl_by_node(m)).get(&name.id()) else {
            continue;
        };
        // Passed or stored by name, its arity may be someone's contract.
        let only_called = refs[decl].iter().all(|&r| {
            let node = m.refs[r].node;
            node.parent()
                .is_some_and(|p| p.kind() == "call_expression" && is_field(p, "function", node))
        });
        if only_called {
            found.extend(f.params[start..].iter().flatten().map(|&d| m.decls[d].node));
        }
    }
    found
}

fn shadowed<'t>(m: &Model<'t>, _: &[u8]) -> Vec<Node<'t>> {
    m.decls
        .iter()
        .filter(|d| {
            d.kind != DeclKind::Type && !d.name.starts_with('_') && !own_function_name(d.node)
        })
        .filter(|d| {
            let Some(outer) = m.scopes[d.scope].parent.and_then(|p| m.lookup(p, &d.name)) else {
                return false;
            };
            let outer = &m.decls[outer];
            // One declared later only shadows through hoisting, which is
            // not what a reader sees.
            outer.kind != DeclKind::Type
                && !own_function_name(outer.node)
                && outer.node.start_byte() < d.node.start_byte()
        })
        .map(|d| d.node)
        .collect()
}

/// A function expression's own name, visible only inside it.
fn own_function_name(name: Node) -> bool {
    name.parent().is_some_and(|p| {
        matches!(
            p.kind(),
            "function_expression" | "function" | "generator_function"
        )
    })
}

fn var_outside_block<'t>(m: &Model<'t>, _: &[u8]) -> Vec<Node<'t>> {
    if !m
        .decls
        .iter()
        .any(|d| d.kind == DeclKind::Var && d.block != d.scope)
    {
        return Vec::new();
    }
    let refs = refs_by_decl(m);
    m.decls
        .iter()
        .enumerate()
        .filter(|(_, d)| d.kind == DeclKind::Var && d.block != d.scope)
        .filter_map(|(i, d)| {
            refs[i]
                .iter()
                .map(|&r| &m.refs[r])
                .find(|r| !m.within(r.scope, d.block))
                .map(|r| r.node)
        })
        .collect()
}

fn prefer_const<'t>(m: &Model<'t>, _: &[u8]) -> Vec<Node<'t>> {
    let mut found = Vec::new();
    let mut decls: Option<HashMap<usize, DeclId>> = None;
    let mut checked = HashSet::new();
    for d in &m.decls {
        if d.kind != DeclKind::Let || d.writes > 0 {
            continue;
        }
        let Some(declaration) = d
            .declarator
            .and_then(|p| p.parent())
            .filter(|p| p.kind() == "lexical_declaration")
        else {
            continue;
        };
        if !checked.insert(declaration.id()) {
            continue;
        }
        let decls = decls.get_or_insert_with(|| decl_by_node(m));
        // Every declarator a plain name, initialized and never reassigned.
        let mut names = Vec::new();
        let mut cursor = declaration.walk();
        let all = declaration
            .named_children(&mut cursor)
            .filter(|c| c.kind() == "variable_declarator")
            .all(|c| {
                let name = c.child_by_field_name("name");
                let ok = c.child_by_field_name("value").is_some()
                    && name.is_some_and(|n| {
                        decls.get(&n.id()).is_some_and(|&i| m.decls[i].writes == 0)
                    });
                names.extend(name);
                ok
            });
        if all {
            found.extend(names);
        }
    }
    found
}

/// Methods that only put things into an array, set or map.
const ADDERS: &[&str] = &["push", "unshift", "add", "set", "delete", "clear"];
const COLLECTIONS: &[&str] = &["Array", "Set", "Map", "WeakSet", "WeakMap"];

fn collection_never_read<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let text = |n: Node| n.utf8_text(src).unwrap_or_default();
    let mut found = Vec::new();
    let mut refs: Option<Vec<Vec<usize>>> = None;
    for (i, d) in m.decls.iter().enumerate() {
        if !matches!(d.kind, DeclKind::Var | DeclKind::Let | DeclKind::Const) || d.reads == 0 {
            continue;
        }
        let created = d
            .declarator
            .and_then(|p| p.child_by_field_name("value"))
            .is_some_and(|v| match v.kind() {
                "array" => true,
                "new_expression" => v
                    .child_by_field_name("constructor")
                    .is_some_and(|c| COLLECTIONS.contains(&text(c))),
                _ => false,
            });
        if !created || exported(d.node) {
            continue;
        }
        let refs = refs.get_or_insert_with(|| refs_by_decl(m));
        let only_added_to = refs[i].iter().all(|&r| {
            let node = m.refs[r].node;
            !m.refs[r].write
                && node.parent().is_some_and(|member| {
                    member.kind() == "member_expression"
                        && is_field(member, "object", node)
                        && member
                            .child_by_field_name("property")
                            .is_some_and(|p| ADDERS.contains(&text(p)))
                        && member.parent().is_some_and(|call| {
                            call.kind() == "call_expression"
                                && is_field(call, "function", member)
                                && call
                                    .parent()
                                    .is_some_and(|s| s.kind() == "expression_statement")
                        })
                })
        });
        if only_added_to {
            found.push(d.node);
        }
    }
    found
}

fn unused_private_fields<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let text = |n: Node| n.utf8_text(src).unwrap_or_default();
    let mut found = Vec::new();
    for &body in &m.classes {
        // Private fields, and TypeScript `private` constructor parameters.
        let mut fields: Vec<Node<'t>> = Vec::new();
        let mut cursor = body.walk();
        for member in body.named_children(&mut cursor) {
            match member.kind() {
                "public_field_definition" | "field_definition" => {
                    let name = member
                        .child_by_field_name("name")
                        .or_else(|| member.child_by_field_name("property"));
                    let mut c = member.walk();
                    let children: Vec<Node> = member.children(&mut c).collect();
                    let private = name.is_some_and(|n| n.kind() == "private_property_identifier")
                        || children
                            .iter()
                            .any(|c| c.kind() == "accessibility_modifier" && text(*c) == "private");
                    if private && !children.iter().any(|c| c.kind() == "decorator") {
                        fields.extend(name);
                    }
                }
                "method_definition" => {
                    let is_constructor = member
                        .child_by_field_name("name")
                        .is_some_and(|n| text(n) == "constructor");
                    if let Some(params) = member
                        .child_by_field_name("parameters")
                        .filter(|_| is_constructor)
                    {
                        let mut c = params.walk();
                        for p in params.named_children(&mut c) {
                            let mut pc = p.walk();
                            let private = p.children(&mut pc).any(|c| {
                                c.kind() == "accessibility_modifier" && text(c) == "private"
                            });
                            if let Some(name) = p
                                .child_by_field_name("pattern")
                                .filter(|n| private && n.kind() == "identifier")
                            {
                                fields.push(name);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        if fields.is_empty() {
            continue;
        }
        let own: HashSet<usize> = fields.iter().map(|f| f.id()).collect();
        let mut used: HashSet<&str> = HashSet::new();
        let mut c = body.walk();
        'walk: loop {
            let n = c.node();
            if !own.contains(&n.id()) {
                match n.kind() {
                    "private_property_identifier"
                    | "property_identifier"
                    | "shorthand_property_identifier_pattern"
                    | "string_fragment" => {
                        used.insert(text(n));
                    }
                    _ => {}
                }
            }
            if c.goto_first_child() {
                continue;
            }
            while !c.goto_next_sibling() {
                if !c.goto_parent() || c.node() == body {
                    break 'walk;
                }
            }
        }
        found.extend(fields.into_iter().filter(|f| !used.contains(text(*f))));
    }
    found
}

fn unused_locals<'t>(m: &Model<'t>, _: &[u8]) -> Vec<Node<'t>> {
    m.decls
        .iter()
        .filter(|d| {
            m.scopes[d.scope].kind != ScopeKind::Module
                && matches!(
                    d.kind,
                    DeclKind::Var
                        | DeclKind::Let
                        | DeclKind::Const
                        | DeclKind::Function
                        | DeclKind::Class
                )
                && d.reads == 0
                && !d.rest_sibling
                && !d.name.starts_with('_')
                // A function expression's own name is there for stack traces.
                && !d.node.parent().is_some_and(|p| {
                    matches!(p.kind(), "function_expression" | "function" | "generator_function")
                })
                && !exported(d.node)
        })
        .map(|d| d.node)
        .collect()
}

/// Whether the declaration naming `name` is exported, as members of a
/// TypeScript namespace can be.
fn exported(name: Node) -> bool {
    let mut n = name;
    while let Some(p) = n.parent() {
        match p.kind() {
            "export_statement" => return true,
            "statement_block" | "program" => return false,
            _ => n = p,
        }
    }
    false
}

fn unused_imports<'t>(m: &Model<'t>, _: &[u8]) -> Vec<Node<'t>> {
    m.decls
        .iter()
        .filter(|d| d.kind == DeclKind::Import && d.reads == 0 && !(m.has_jsx && d.name == "React"))
        .map(|d| d.node)
        .collect()
}

/// Writes to declarations of `kind`.
fn writes_to<'t>(m: &Model<'t>, kind: DeclKind) -> Vec<Node<'t>> {
    m.refs
        .iter()
        .filter(|r| r.write && r.decl.is_some_and(|d| m.decls[d].kind == kind))
        .map(|r| r.node)
        .collect()
}

fn const_reassigned<'t>(m: &Model<'t>, _: &[u8]) -> Vec<Node<'t>> {
    writes_to(m, DeclKind::Const)
}

fn import_reassigned<'t>(m: &Model<'t>, _: &[u8]) -> Vec<Node<'t>> {
    writes_to(m, DeclKind::Import)
}

/// Bindings CommonJS wraps every module in, assignable without a
/// declaration.
const COMMONJS: &[&str] = &["exports", "module", "require", "__filename", "__dirname"];

fn implicit_globals<'t>(m: &Model<'t>, _: &[u8]) -> Vec<Node<'t>> {
    m.refs
        .iter()
        .filter(|r| r.write && r.decl.is_none() && !COMMONJS.contains(&r.name.as_str()))
        .map(|r| r.node)
        .collect()
}

/// Every declaration of a name after the first in the same scope. Type
/// declarations merge in TypeScript and are left out.
fn redeclared<'t>(m: &Model<'t>, _: &[u8]) -> Vec<Node<'t>> {
    let mut found = Vec::new();
    for (_, decls) in m.names() {
        let values: Vec<_> = decls
            .iter()
            .map(|&d| &m.decls[d])
            .filter(|d| d.kind != DeclKind::Type)
            .collect();
        found.extend(values.iter().skip(1).map(|d| d.node));
    }
    found
}

#[cfg(test)]
mod tests {
    use crate::analysis::analyze;
    use crate::analysis::tests::far_deadline;
    use crate::config::Config;
    use crate::lang::Lang;
    use crate::rules::RuleSet;

    fn flagged(rule: &str, lang: Lang, src: &str) -> Vec<usize> {
        flagged_in("t", rule, lang, src)
    }

    fn flagged_in(path: &str, rule: &str, lang: Lang, src: &str) -> Vec<usize> {
        let mut cfg = Config::default();
        cfg.rules.enabled = vec![rule.into()];
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let file = analyze(path, lang, src, &rules, &cfg, far_deadline()).unwrap();
        file.issues
            .iter()
            .filter(|i| i.rule == rule)
            .map(|i| i.line)
            .collect()
    }

    #[test]
    fn type_signatures_and_function_expression_names() {
        let src = "function f() {\n  const h: Record<string, (...args: unknown[]) => void> = {};\n  const g = vi.fn(function named(p) { return p; });\n  return [h, g];\n}\ninterface I { m(x: number): void }";
        assert!(flagged("js/implicit-global", Lang::TypeScript, src).is_empty());
        assert!(flagged("js/unused-variable", Lang::TypeScript, src).is_empty());
    }

    #[test]
    fn declaration_files_are_skipped() {
        let src = "import * as g from './g';\ndeclare namespace N {\n  let width: number;\n}";
        assert!(
            flagged_in(
                "types/index.d.ts",
                "js/unused-import",
                Lang::TypeScript,
                src
            )
            .is_empty()
        );
        assert!(
            flagged_in(
                "types/index.d.ts",
                "js/unused-variable",
                Lang::TypeScript,
                src
            )
            .is_empty()
        );
        assert_eq!(
            flagged_in("src/index.ts", "js/unused-import", Lang::TypeScript, src),
            [1]
        );
    }

    #[test]
    fn commonjs_namespaces_and_named_function_expressions() {
        let js = "exports = module.exports = create;\nobj.range = function range(s) { var range = s.get(); return range; };";
        assert!(flagged("js/implicit-global", Lang::JavaScript, js).is_empty());
        assert!(flagged("js/redeclared", Lang::JavaScript, js).is_empty());
        let ts = "namespace util {\n  export const assertEqual = (x: number) => x;\n  const hidden = 1;\n}";
        assert_eq!(flagged("js/unused-variable", Lang::TypeScript, ts), [3]);
    }

    #[test]
    fn unused_parameters_only_where_arity_is_free() {
        let src = "function a(x, y) { return y; }\nfunction b(x, y) { return x; }\nb(1);\nexport function e(x, y) { return x; }\n\
                   function mw(err, req, res, next) { res.end(); }\napp.use(mw);\n\
                   const c = (p, q) => p;\nc(1);\nfunction d(p) { return arguments.length; }\n\
                   xs.forEach((v, i) => i);\nclass K { m(u) {} }";
        // `b`'s y (line 2) and `c`'s q (line 6): trailing, and only ever called.
        assert_eq!(
            flagged("js/unused-parameter", Lang::JavaScript, src),
            [2, 7]
        );
    }

    #[test]
    fn shadowing_skips_types_and_own_names() {
        let src = "const x = 1;\nfunction f(x: number) { return x; }\ntype T = number;\n\
                   function g() { const T = 1; return T; }\nconst h = function h() { const h = 2; return h; };\n\
                   function k() { for (let i = 0; i < 2; i++) {} let i = 5; return i; }";
        assert_eq!(flagged("js/shadowed-variable", Lang::TypeScript, src), [2]);
    }

    #[test]
    fn var_used_outside_its_block() {
        let src = "function f(c) {\n  if (c) { var a = 1; a++; }\n  var b = 2;\n  return a + b;\n}";
        assert_eq!(flagged("js/var-outside-block", Lang::JavaScript, src), [4]);
    }

    #[test]
    fn prefer_const_needs_the_whole_declaration() {
        let src = "let a = 1, b = 2;\nb++;\nlet c;\nc = 1;\nlet [d, e] = f();\nlet g = 1;\nfor (let i = 0; i < 3; i++) {}\nuse(a, b, c, d, e, g);";
        assert_eq!(flagged("js/prefer-const", Lang::JavaScript, src), [6]);
    }

    #[test]
    fn collections_read_any_way_are_used() {
        let src = "function f() {\n  const a = [];\n  a.push(1);\n  const b = [];\n  b.push(1);\n  return b;\n}\n\
                   function g() { const m = new Map(); m.set(1, 2); for (const x of m) {} const s = new Set(); const n = s.add(1); return n; }";
        assert_eq!(
            flagged("js/collection-never-read", Lang::JavaScript, src),
            [2]
        );
    }

    #[test]
    fn private_fields_used_any_way_are_used() {
        let src = "class A {\n  private a = 1;\n  private b = 2;\n  #c = 3;\n  @Input() private d = 4;\n  private e = 5;\n\
                   constructor(private f: number, public g: number) {}\n\
                   m() { const { e } = this; return this.a + this.#c + e; }\n}";
        assert_eq!(
            flagged("js/unused-private-field", Lang::TypeScript, src),
            [3, 7]
        );
    }

    #[test]
    fn module_scope_is_not_local() {
        // Top-level declarations may be used by other scripts or exported.
        let src = "const config = load();\nfunction helper() {}\nexport const x = 1;";
        assert!(flagged("js/unused-variable", Lang::JavaScript, src).is_empty());
    }

    #[test]
    fn typescript_merging_and_overloads_are_not_redeclarations() {
        let src = "interface A { x: number }\ninterface A { y: number }\nenum E { X }\nnamespace E { export const y = 1; }\n\
                   function f(a: string): void;\nfunction f(a: any) {}\nconst T = 1;\ntype T = number;";
        assert!(flagged("js/redeclared", Lang::TypeScript, src).is_empty());
    }

    #[test]
    fn types_count_as_uses_of_imports() {
        let src = "import type { Props } from './p';\nimport { helper, Unused } from './h';\nexport function f(p: Props) { return helper(p); }";
        assert_eq!(flagged("js/unused-import", Lang::TypeScript, src), [2]);
    }

    #[test]
    fn destructuring_assignments_write() {
        let src = "const a = 1;\n[a] = [2];\nlet b;\n({ b } = o);\n({ c } = o);";
        assert_eq!(flagged("js/const-reassigned", Lang::JavaScript, src), [2]);
        assert_eq!(flagged("js/implicit-global", Lang::JavaScript, src), [5]);
    }
}
