//! JavaScript and TypeScript rules on the semantic model (ADR-0008, phase
//! S1: scopes and symbols).

use super::*;
use crate::semantic::{DeclKind, Model, ScopeKind};

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
];

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
        let cfg = Config::default();
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
