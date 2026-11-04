//! C# rules on control flow and liveness (ADR-0008's S2 and S3,
//! `semantic/cs_cfg.rs`): values no path reads, parameters overwritten
//! before any path reads them, fields every method writes before reading,
//! and loops and recursion with no way out. Each function gets its graph
//! once per file; a function past the graph's bounds is skipped.

use super::prelude::*;
use crate::semantic::cs_cfg::{self, Access, Cfg, ENTRY, EXIT};
use crate::semantic::{DeclId, DeclKind, Model};
use std::collections::HashSet;

/// Rules that are off unless `rules.enabled` lists them: the one whose key
/// is outside SonarQube's default profile.
pub(super) static OFF_BY_DEFAULT: &[&str] = &["cs/parameter-overwritten"];

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "cs/infinite-loop-or-recursion",
        name: "Loops and recursion should not be infinite",
        description: "A loop no path leaves, a `goto` cycle, or a method that calls itself on every path never \
                      finishes, or ends in a StackOverflowException.",
        message: "Give this loop or recursion a way to end.",
        category: Bug,
        severity: Blocker,
        effort_minutes: 30,
        sonar: &[exact("S2190")],
        check: Check::Semantic {
            langs: CSHARP,
            find: endless,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int Pow(int n, int e) { return n * Pow(n, e - 1); } }",
            good: "class A { int Pow(int n, int e) { return e > 1 ? n * Pow(n, e - 1) : n; } }",
        }),
    },
    Rule {
        id: "cs/dead-store",
        name: "Values assigned to locals should be used",
        description: "A value that no path reads before it's overwritten or the method ends was computed for \
                      nothing, or the code that should read it is missing.",
        message: "Remove this assignment: the value is never read.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S1854")],
        check: Check::Semantic {
            langs: CSHARP,
            find: dead_stores,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int F(int y) { int x = Compute(); x = 200; return x + y; } }",
            good: "class A { int F(int y) { int x = 200; return x + y; } }",
        }),
    },
    Rule {
        id: "cs/parameter-overwritten",
        name: "Parameters and caught exceptions should be read before they're overwritten",
        description: "Assigning a parameter before any path reads it throws away the caller's argument; the \
                      method probably meant a local. The same goes for a caught exception.",
        message: "Read this value before overwriting it, or use a local variable.",
        category: Bug,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S1226")],
        check: Check::Semantic {
            langs: CSHARP,
            find: overwritten_before_read,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class A { int F(int limit) { limit = 10; return limit * 2; } }",
            good: "class A { int F(int limit) { limit = Math.Min(limit, 10); return limit * 2; } }",
        }),
    },
    Rule {
        id: "cs/field-could-be-local",
        name: "Private fields only used as locals should be locals",
        description: "A field that every method using it writes before any read carries no state between calls; \
                      as a field, it suggests otherwise and isn't thread-safe.",
        message: "Make this field a local variable in the methods that use it.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[exact("S1450")],
        check: Check::Semantic {
            langs: CSHARP,
            find: fields_used_as_locals,
        },
        example: Some(Example {
            lang: Lang::CSharp,
            bad: "class Foo { private int total; public int Sum(int x) { total = x + 5; if (x > 0) { total++; } return total * 2; } }",
            good: "class Foo { public int Sum(int x) { var total = x + 5; if (x > 0) { total++; } return total * 2; } }",
        }),
    },
];

// ---------------------------------------------------- graphs

/// A function with a body, and its graph.
struct Graph<'t> {
    function: Node<'t>,
    cfg: Cfg<'t>,
    /// The variables it declares, or for parameters, takes: not those of
    /// nested functions.
    own: HashSet<DeclId>,
}

const FUNCTIONS: &[&str] = &[
    "method_declaration",
    "constructor_declaration",
    "destructor_declaration",
    "operator_declaration",
    "conversion_operator_declaration",
    "accessor_declaration",
    "local_function_statement",
    "lambda_expression",
    "anonymous_method_expression",
];

/// Every function's graph, and the functions that got none (past the
/// bounds), whose reads stay unknown.
fn graphs<'t>(m: &Model<'t>, src: &[u8]) -> (Vec<Graph<'t>>, Vec<Node<'t>>) {
    let by_node = cs_cfg::decls_by_node(m);
    let functions: Vec<Node<'t>> = m
        .functions
        .iter()
        .map(|f| f.node)
        .filter(|f| FUNCTIONS.contains(&f.kind()))
        .collect();
    let mut built = Vec::new();
    let mut failed = Vec::new();
    for function in &functions {
        if function.child_by_field_name("body").is_none() {
            continue;
        }
        // Preprocessor branches put several configurations in one tree, and
        // a tree with errors has no reliable flow: their reads stay unknown.
        let text = function.utf8_text(src).unwrap_or_default();
        if function.has_error()
            || ["#if", "#else", "#elif", "#endif"]
                .iter()
                .any(|d| text.contains(d))
        {
            failed.push(*function);
            continue;
        }
        // Declarations inside this function and not inside a nested one.
        let nested: Vec<(usize, usize)> = functions
            .iter()
            .filter(|g| {
                g.id() != function.id()
                    && g.start_byte() >= function.start_byte()
                    && g.end_byte() <= function.end_byte()
            })
            .map(|g| (g.start_byte(), g.end_byte()))
            .collect();
        let inside = |n: Node| {
            n.start_byte() >= function.start_byte()
                && n.end_byte() <= function.end_byte()
                && !nested
                    .iter()
                    .any(|(a, b)| n.start_byte() >= *a && n.end_byte() <= *b)
        };
        let own: HashSet<DeclId> = m
            .decls
            .iter()
            .enumerate()
            .filter(|(_, d)| {
                matches!(
                    d.kind,
                    DeclKind::Let | DeclKind::Param | DeclKind::CatchParam
                ) && inside(d.node)
            })
            .map(|(i, _)| i)
            .collect();
        match cs_cfg::build(m, *function, src, &by_node) {
            Some(cfg) => built.push(Graph {
                function: *function,
                cfg,
                own,
            }),
            None => failed.push(*function),
        }
    }
    (built, failed)
}

/// Every write in a graph: (block, index of the event, the event's decl).
fn writes<'a, 't>(
    cfg: &'a Cfg<'t>,
) -> impl Iterator<Item = (usize, usize, &'a cs_cfg::Event<'t>)> + 'a {
    cfg.blocks
        .iter()
        .enumerate()
        .flat_map(|(i, b)| b.events.iter().enumerate().map(move |(k, e)| (i, k, e)))
        .filter(|(_, _, e)| e.access == Access::Write)
}

/// Every write that may not happen.
fn maybe_writes<'a, 't>(
    cfg: &'a Cfg<'t>,
) -> impl Iterator<Item = (usize, usize, &'a cs_cfg::Event<'t>)> + 'a {
    cfg.blocks
        .iter()
        .enumerate()
        .flat_map(|(i, b)| b.events.iter().enumerate().map(move |(k, e)| (i, k, e)))
        .filter(|(_, _, e)| e.access == Access::MaybeWrite)
}

/// Whether block `i` reads `decl` after its event `k`.
fn read_later_in_block(cfg: &Cfg, i: usize, k: usize, decl: DeclId) -> bool {
    cfg.blocks[i].events[k + 1..]
        .iter()
        .any(|e| e.decl == decl && e.access == Access::Read)
}

// ---------------------------------------------------- dead stores

/// Initializations SonarQube doesn't report: defaults and sentinels.
fn is_default_value(value: Node, src: &[u8]) -> bool {
    let mut v = value;
    while v.kind() == "parenthesized_expression" {
        match v.named_child(0) {
            Some(inner) => v = inner,
            None => break,
        }
    }
    matches!(
        v.utf8_text(src).unwrap_or_default(),
        "-1" | "0" | "1" | "null" | "true" | "false" | "\"\"" | "string.Empty" | "String.Empty"
    )
}

/// The value an assignment or declarator writes.
fn written_value(write: Node) -> Option<Node> {
    match write.kind() {
        "assignment_expression" => write.child_by_field_name("right"),
        "variable_declarator" => {
            write.named_child(write.named_child_count().saturating_sub(1) as u32)
        }
        _ => None,
    }
}

fn dead_stores<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let (graphs, _) = graphs(m, src);
    let mut found = Vec::new();
    for g in &graphs {
        // As documented: no issue in a method with try blocks.
        if !g.cfg.has_try {
            dead_stores_in(m, g, src, &mut found);
        }
    }
    found.sort_by_key(|n| n.start_byte());
    found.dedup_by_key(|n| n.id());
    found
}

/// The writes in one function that no path reads.
fn dead_stores_in<'t>(m: &Model<'t>, g: &Graph<'t>, src: &[u8], found: &mut Vec<Node<'t>>) {
    // Locals that something reads (S1481 covers the others), not captured.
    let tracked: HashSet<DeclId> = g
        .own
        .iter()
        .copied()
        .filter(|d| {
            m.decls[*d].kind == DeclKind::Let && m.decls[*d].reads > 0 && !g.cfg.escaped.contains(d)
        })
        .collect();
    if tracked.is_empty() {
        return;
    }
    let live = cs_cfg::live_after(&g.cfg, &tracked);
    for (i, k, e) in writes(&g.cfg) {
        if tracked.contains(&e.decl)
            && !live[i].contains(&e.decl)
            && !read_later_in_block(&g.cfg, i, k, e.decl)
            && discardable_store(e.node, src)
        {
            found.push(e.node);
        }
    }
}

/// Assignments, initializers, compound assignments and ++/--, other than of
/// a default value; not loop variables, patterns, catch variables or out
/// arguments.
fn discardable_store(node: Node, src: &[u8]) -> bool {
    matches!(
        node.kind(),
        "assignment_expression"
            | "variable_declarator"
            | "prefix_unary_expression"
            | "postfix_unary_expression"
    ) && !written_value(node).is_some_and(|v| is_default_value(v, src))
}

// ---------------------------------------------------- parameters

fn overwritten_before_read<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let (graphs, _) = graphs(m, src);
    let mut found = Vec::new();
    for g in &graphs {
        let candidates = bound_values(m, g, src);
        if candidates.is_empty() {
            continue;
        }
        let tracked: HashSet<DeclId> = candidates
            .iter()
            .map(|(d, _)| *d)
            .filter(|d| !g.cfg.escaped.contains(d))
            .collect();
        let live = cs_cfg::live_after(&g.cfg, &tracked);
        for (d, binding) in candidates {
            if tracked.contains(&d) && !live[binding].contains(&d) {
                found.extend(first_overwrite(&g.cfg, d, binding));
            }
        }
    }
    found.sort_by_key(|n| n.start_byte());
    found
}

/// The values a function receives, and the block that binds each:
/// parameters on entry (ref, out and in pass values through; `_` is a
/// discard, not a parameter anyone reads), caught exceptions by their
/// catch clause.
fn bound_values(m: &Model, g: &Graph, src: &[u8]) -> Vec<(DeclId, usize)> {
    let mut candidates: Vec<(DeclId, usize)> = Vec::new();
    for d in g.own.iter().copied().filter(|d| {
        m.decls[*d].kind == DeclKind::Param && !m.decls[*d].name.chars().all(|c| c == '_')
    }) {
        let passes = m.decls[d].declarator.is_some_and(|p| {
            let mut c = p.walk();
            p.kind() == "parameter"
                && p.named_children(&mut c).any(|x| {
                    x.kind() == "modifier" && matches!(x.utf8_text(src), Ok("ref" | "out" | "in"))
                })
        });
        if !passes {
            candidates.push((d, ENTRY));
        }
    }
    for (i, b) in g.cfg.blocks.iter().enumerate() {
        if b.syntax.is_some_and(|s| s.kind() == "catch_clause") {
            candidates.extend(
                b.events
                    .iter()
                    .filter(|e| m.decls[e.decl].kind == DeclKind::CatchParam)
                    .map(|e| (e.decl, i)),
            );
        }
    }
    candidates
}

/// Overwritten somewhere, and no path reads the passed value: the first
/// write is the one that throws it away.
fn first_overwrite<'t>(cfg: &Cfg<'t>, d: DeclId, binding: usize) -> Option<Node<'t>> {
    writes(cfg)
        .chain(maybe_writes(cfg))
        .filter(|(i, _, e)| e.decl == d && *i != binding)
        .map(|(_, _, e)| e.node)
        .min_by_key(|n| n.start_byte())
}

// ---------------------------------------------------- fields

fn fields_used_as_locals<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let candidates = plain_private_fields(m, src);
    if candidates.is_empty() {
        return Vec::new();
    }
    let (graphs, failed) = graphs(m, src);
    let tracked: HashSet<DeclId> = candidates.iter().copied().collect();
    let (carries_state, used) = field_states(&graphs, &tracked);
    candidates
        .into_iter()
        .filter(|d| used.contains(d) && !carries_state.contains(d))
        .filter(|d| {
            !m.refs
                .iter()
                .any(|r| r.decl == Some(*d) && outside_graphs(&graphs, &failed, r.node))
        })
        .map(|d| m.decls[d].node)
        .collect()
}

/// Plain private instance fields: no initializer, attributes or modifiers
/// beyond `private` and `readonly`, read somewhere.
fn plain_private_fields(m: &Model, src: &[u8]) -> Vec<DeclId> {
    let has = |n: Node, word: &str| {
        let mut c = n.walk();
        n.named_children(&mut c)
            .any(|x| x.kind() == "modifier" && x.utf8_text(src) == Ok(word))
    };
    m.decls
        .iter()
        .enumerate()
        .filter(|(_, d)| d.kind == DeclKind::Field && !d.is_static && d.reads > 0)
        .filter(|(_, d)| {
            let Some(declarator) = d
                .declarator
                .filter(|x| x.kind() == "variable_declarator" && x.named_child_count() == 1)
            else {
                return false;
            };
            let Some(field) = declarator
                .parent()
                .and_then(|v| v.parent())
                .filter(|f| f.kind() == "field_declaration")
            else {
                return false;
            };
            let mut c = field.walk();
            let attributed = field
                .named_children(&mut c)
                .any(|x| x.kind() == "attribute_list");
            !attributed
                && !["public", "protected", "internal", "volatile"]
                    .iter()
                    .any(|w| has(field, w))
        })
        .map(|(i, _)| i)
        .collect()
}

/// Per field: whether some function reads it before writing it, or a
/// closure captures it, so it carries state between calls; and whether
/// any function uses it at all.
fn field_states(graphs: &[Graph], tracked: &HashSet<DeclId>) -> (HashSet<DeclId>, HashSet<DeclId>) {
    let mut carries_state = HashSet::new();
    let mut used = HashSet::new();
    for g in graphs {
        let live = cs_cfg::live_after(&g.cfg, tracked);
        for b in &g.cfg.blocks {
            for e in b.events.iter().filter(|e| tracked.contains(&e.decl)) {
                used.insert(e.decl);
                // Captured by a closure: read at some later time.
                if g.cfg.escaped.contains(&e.decl) {
                    carries_state.insert(e.decl);
                }
            }
        }
        carries_state.extend(tracked.iter().filter(|d| live[ENTRY].contains(d)));
    }
    (carries_state, used)
}

/// Whether `n` sits where no graph sees: outside every function that has
/// one, or in one whose graph failed.
fn outside_graphs(graphs: &[Graph], failed: &[Node], n: Node) -> bool {
    let within = |f: Node| n.start_byte() >= f.start_byte() && n.end_byte() <= f.end_byte();
    !graphs.iter().any(|g| within(g.function)) || failed.iter().any(|f| within(*f))
}

// ---------------------------------------------------- endless loops

fn endless<'t>(m: &Model<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let (graphs, _) = graphs(m, src);
    let mut found = Vec::new();
    for g in &graphs {
        let reached = cs_cfg::reachable(&g.cfg, ENTRY, |_| false);
        let can_end = ends_from(&g.cfg);
        endless_loops(&g.cfg, &reached, &can_end, src, &mut found);
        found.extend(endless_recursion(m, g, &reached, &can_end, src));
    }
    found.sort_by_key(|n| n.start_byte());
    found.dedup_by_key(|n| n.id());
    found
}

/// The blocks from which the function can end: backwards from EXIT.
fn ends_from(cfg: &Cfg) -> Vec<bool> {
    let mut preds: Vec<Vec<usize>> = vec![Vec::new(); cfg.blocks.len()];
    for (i, b) in cfg.blocks.iter().enumerate() {
        for s in &b.succ {
            preds[*s].push(i);
        }
    }
    let mut can_end = vec![false; cfg.blocks.len()];
    let mut stack = vec![EXIT];
    while let Some(i) = stack.pop() {
        if !can_end[i] {
            can_end[i] = true;
            stack.extend(preds[i].iter().copied());
        }
    }
    can_end
}

/// A loop no edge leaves; a `goto` cycle from which the function can't
/// end. Generators may loop forever on purpose.
fn endless_loops<'t>(
    cfg: &Cfg<'t>,
    reached: &[bool],
    can_end: &[bool],
    src: &[u8],
    found: &mut Vec<Node<'t>>,
) {
    let within = |b: &cs_cfg::Block, s: Node| {
        b.syntax
            .is_some_and(|x| x.start_byte() >= s.start_byte() && x.end_byte() <= s.end_byte())
    };
    for (i, b) in cfg.blocks.iter().enumerate() {
        let Some(s) = b.loop_statement.filter(|_| reached[i]) else {
            continue;
        };
        if s.utf8_text(src)
            .unwrap_or_default()
            .contains("yield return")
        {
            continue;
        }
        let endless = if s.kind() == "labeled_statement" {
            !can_end[i]
        } else {
            // Every block of the loop only leads to blocks of the loop.
            !cfg.blocks
                .iter()
                .filter(|x| within(x, s))
                .any(|x| x.succ.iter().any(|t| !within(&cfg.blocks[*t], s)))
        };
        if endless {
            found.push(s);
        }
    }
}

/// A method every path to whose end goes through a call to itself: its
/// name.
fn endless_recursion<'t>(
    m: &Model<'t>,
    g: &Graph<'t>,
    reached: &[bool],
    can_end: &[bool],
    src: &[u8],
) -> Option<Node<'t>> {
    if g.function.kind() != "method_declaration" || calls_other_methods(g.function, src) {
        return None;
    }
    let name = g.function.child_by_field_name("name")?;
    let cfg = &g.cfg;
    let overloaded = m
        .decls
        .iter()
        .filter(|d| d.kind == DeclKind::Method && d.node.utf8_text(src) == name.utf8_text(src))
        .count()
        > 1;
    let recurses_somewhere = cfg
        .blocks
        .iter()
        .enumerate()
        .any(|(i, b)| b.recurses && reached[i]);
    let ends = cs_cfg::reachable(cfg, ENTRY, |i| cfg.blocks[i].recurses)[EXIT];
    (!overloaded && recurses_somewhere && !ends && can_end[ENTRY]).then_some(name)
}

/// Whether a call of the method's own name may be another method's: an
/// explicit implementation, an override or a hiding method, or one of a
/// class that may inherit overloads this file doesn't show.
fn calls_other_methods(function: Node, src: &[u8]) -> bool {
    let mut c = function.walk();
    let explicit = function
        .named_children(&mut c)
        .any(|x| x.kind() == "explicit_interface_specifier");
    let mut mc = function.walk();
    let redeclares = function
        .named_children(&mut mc)
        .any(|x| x.kind() == "modifier" && matches!(x.utf8_text(src), Ok("override" | "new")));
    let inherits = function
        .parent()
        .and_then(|l| l.parent())
        .is_some_and(|class| {
            let mut cc = class.walk();
            class
                .named_children(&mut cc)
                .find(|x| x.kind() == "base_list")
                .and_then(|b| b.named_child(0))
                .is_some_and(|first| {
                    let name = first.utf8_text(src).unwrap_or_default();
                    let mut chars = name.chars();
                    !(chars.next() == Some('I') && chars.next().is_some_and(char::is_uppercase))
                })
        });
    explicit || redeclares || inherits
}

#[cfg(test)]
mod tests {
    use super::super::cs::tests::flagged;

    fn class(body: &str) -> String {
        format!("namespace N;\nclass A {{\n{body}\n}}\n")
    }

    #[test]
    fn dead_stores_on_every_path() {
        let src = class(
            "int F(int y, bool c) {\nint x = Compute();\nx = 200;\nint w = Compute();\nif (c) { w = 1; } else { w = 2; }\nint v = 5;\nif (c) { v = 6; }\nint u = Read();\nwhile (c) { u = Next(u); }\nint t = Calc();\nt = 9;\nint s = Get();\nAction a = () => Use(s);\ns = 2;\nint z = 0;\nz = 7;\nint q = Read();\nUse(q);\nq = 3;\nreturn x + y + w + v + u + z;\n}\nint G(int y) { int x = Compute(); try { x = 2; } catch { } return x; }",
        );
        assert_eq!(flagged("cs/dead-store", &src), [4, 6, 21]);
    }

    #[test]
    fn parameters_and_exceptions() {
        let src = class(
            "int F(int limit, int keep, bool c, ref int r, out int o) {\nif (c) { keep = keep + 1; }\nlimit = 10;\nr = 1;\no = 2;\nreturn limit + keep;\n}\nint G(int a, bool c) {\nif (c) { a = 1; } else { a = 2; }\nreturn a;\n}\nint H(int b, bool c) {\nif (c) { b = 1; }\nreturn b;\n}\nvoid K() {\ntry { } catch (Exception e) { e = new Exception(); Log(e); }\n}",
        );
        assert_eq!(flagged("cs/parameter-overwritten", &src), [5, 11, 19]);
    }

    #[test]
    fn fields_written_before_read() {
        let src = "namespace N;\nclass Foo {\nprivate int total;\nprivate int kept;\nprivate int cond;\nprivate int lambda;\npublic int Sum(int x) { total = x + 5; if (x > 0) { total++; } return total * 2; }\npublic void Keep(int x) { kept += x; }\npublic int C(int x) { if (x > 0) { cond = x; } return cond; }\npublic void L(int x) { lambda = x; Run(() => Use(lambda)); }\n}";
        assert_eq!(flagged("cs/field-could-be-local", src), [3]);
    }

    #[test]
    fn endless_loops_and_recursion() {
        let src = class(
            "int Sum() {\nvar i = 0;\nwhile (true) { i++; }\n}\nint Bounded() {\nwhile (true) { if (Done()) { break; } }\nreturn 0;\n}\nint Pow(int n, int e) { return n * Pow(n, e - 1); }\nint Fine(int n, int e) { return e > 1 ? n * Fine(n, e - 1) : n; }\nIEnumerable<int> Gen() { while (true) { yield return 1; } }\nvoid Spin() {\nagain:\nWork();\ngoto again;\n}\nvoid Thrower() { while (true) { throw new X(); } }\nint F(int x) { if (x > 0) { return F(x - 1); } return F(x + 1); }\nvoid Outer() { while (true) { foreach (var y in ys) { Use(y); } } }\nbool Has(Exception e) => e switch { null => false, _ => Has(e.InnerException) };\nint I.Get(int x) => Get(x);",
        );
        assert_eq!(
            flagged("cs/infinite-loop-or-recursion", &src),
            [5, 11, 15, 20, 21]
        );
    }

    /// Shapes found reviewing the rules on real code, none of them reported.
    #[test]
    fn corpus_false_positives() {
        // A write on one side of && may not happen: the default survives.
        let src = class(
            "int F(string p) {\nvar d = Kind.Default;\nif (p.Length != 0 && TryGet(p, out d)) { p = p[1..]; }\nreturn Use(d, p);\n}\nint G(int i) {\nbool n;\n#if BIG\nif (i > 1) { n = true; }\nelse\n#endif\n{ n = false; }\nreturn n ? 1 : 0;\n}",
        );
        assert_eq!(flagged("cs/dead-store", &src), [0usize; 0]);
        let src = class("void H() { Action<int, int> a = (_, t) => _ = t; }");
        assert_eq!(flagged("cs/parameter-overwritten", &src), [0usize; 0]);
    }
}
