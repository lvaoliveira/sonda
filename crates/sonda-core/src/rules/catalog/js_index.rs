//! A file's declarations by name, for JavaScript and TypeScript rules that
//! look one up from wherever they matched: "is `x` declared as an array?",
//! "is `f` a function declaration?". Walking the whole file for each lookup
//! made a large file quadratic, and a 900 KB test file overran the per-file
//! timeout, losing its findings.
//!
//! `run_queries` indexes a tree once, in [`scope`], for as long as its rules
//! run; a lookup against any other tree, or with none indexed (a rule's unit
//! test), walks the tree as before. Either way the nodes are the same, in
//! the same (document) order.
//!
//! [`memo`] keeps anything else a rule computes about the whole file, or
//! about one node, for the same span.

use super::js_syntax::walk;
use std::any::Any;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use tree_sitter::Node;

/// The kinds indexed by their `name` field.
const KINDS: &[&str] = &[
    "variable_declarator",
    "function_declaration",
    "class_declaration",
    "interface_declaration",
    "type_alias_declaration",
];

/// (kind, name) to each node's byte range, in document order.
type ByName = HashMap<(&'static str, Vec<u8>), Vec<(usize, usize)>>;

struct Index {
    /// The tree indexed: its root's id, and the source's address and length.
    root: usize,
    src: (usize, usize),
    by_name: ByName,
    /// What [`memo`] computed, by its key.
    memo: HashMap<(&'static str, Vec<u8>), Rc<dyn Any>>,
}

thread_local! {
    static INDEX: RefCell<Vec<Index>> = const { RefCell::new(Vec::new()) };
}

/// Indexes `root`'s tree until the returned guard drops.
pub(crate) fn scope(root: Node, src: &[u8]) -> Scope {
    let mut by_name = ByName::new();
    let mut visit = |n: Node| {
        if let Some(kind) = KINDS.iter().find(|k| **k == n.kind())
            && let Some(name) = n.child_by_field_name("name")
        {
            by_name
                .entry((kind, src[name.byte_range()].to_vec()))
                .or_default()
                .push((n.start_byte(), n.end_byte()));
        }
        true
    };
    visit(root);
    walk(root, &mut visit);
    INDEX.with(|i| {
        i.borrow_mut().push(Index {
            root: root.id(),
            src: (src.as_ptr() as usize, src.len()),
            by_name,
            memo: HashMap::new(),
        });
    });
    Scope(())
}

/// Ends an index's [`scope`].
pub(crate) struct Scope(());

impl Drop for Scope {
    fn drop(&mut self) {
        INDEX.with(|i| {
            i.borrow_mut().pop();
        });
    }
}

/// `compute`'s value for `key`, computed once while the file whose source
/// is `src` has its rules run (and every time otherwise). The key names
/// what's computed, and what it's about: a node's id, say, or nothing for
/// the whole file. Filters only ever see the tree being queried, so the
/// innermost index over the same source is that tree's.
pub(super) fn memo<T: 'static>(
    src: &[u8],
    key: (&'static str, &[u8]),
    compute: impl FnOnce() -> T,
) -> Rc<T> {
    let here = (src.as_ptr() as usize, src.len());
    let found = INDEX.with(|i| {
        let i = i.borrow();
        let index = i.iter().rev().find(|x| x.src == here)?;
        Some(index.memo.get(&(key.0, key.1.to_vec())).cloned())
    });
    match found {
        // Indexed, and computed already.
        Some(Some(value)) => value.downcast::<T>().expect("one type per memo key"),
        // Indexed: compute it once. `compute` may use `memo` itself, so
        // nothing is borrowed while it runs.
        Some(None) => {
            let value = Rc::new(compute());
            INDEX.with(|i| {
                if let Some(index) = i.borrow_mut().iter_mut().rev().find(|x| x.src == here) {
                    index
                        .memo
                        .insert((key.0, key.1.to_vec()), value.clone() as Rc<dyn Any>);
                }
            });
            value
        }
        None => Rc::new(compute()),
    }
}

/// The nodes of one of `kinds` whose `name` field is `name`, in `node`'s
/// tree, in document order.
pub(super) fn named<'t>(node: Node<'t>, kinds: &[&str], name: &[u8], src: &[u8]) -> Vec<Node<'t>> {
    let root = super::js_syntax::root_node(node);
    let indexed = INDEX.with(|i| {
        let i = i.borrow();
        let index = i
            .iter()
            .rev()
            .find(|x| x.root == root.id() && x.src == (src.as_ptr() as usize, src.len()))?;
        let mut ranges: Vec<(usize, usize, &str)> = Vec::new();
        for kind in kinds {
            let Some(kind) = KINDS.iter().find(|k| *k == kind) else {
                // Not indexed: the caller gets a walk.
                return None;
            };
            if let Some(found) = index.by_name.get(&(*kind, name.to_vec())) {
                ranges.extend(found.iter().map(|&(s, e)| (s, e, *kind)));
            }
        }
        Some(ranges)
    });
    let Some(mut ranges) = indexed else {
        let mut out = Vec::new();
        let mut visit = |n: Node<'t>| {
            if kinds.contains(&n.kind())
                && n.child_by_field_name("name")
                    .is_some_and(|x| &src[x.byte_range()] == name)
            {
                out.push(n);
            }
            true
        };
        visit(root);
        walk(root, &mut visit);
        return out;
    };
    // Document order: by start, and an outer node before an inner one that
    // starts with it.
    ranges.sort_by_key(|&(s, e, _)| (s, std::cmp::Reverse(e)));
    ranges
        .into_iter()
        .filter_map(|(s, e, kind)| {
            let mut n = root.descendant_for_byte_range(s, e)?;
            while n.kind() != kind || n.byte_range() != (s..e) {
                n = n.parent()?;
            }
            Some(n)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lang::Lang;

    fn tree(src: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&Lang::TypeScript.grammar()).unwrap();
        parser.parse(src, None).unwrap()
    }

    #[test]
    fn lookups_find_the_same_nodes_indexed_or_not() {
        let src = "const a = [1];\nfunction a() {}\nfunction f() { let a = () => 1; class a {} }\n\
                   interface I {}\ntype I = string;\nconst b = new a();\n";
        let t = tree(src);
        let root = t.root_node();
        let probe = root.named_child(5).unwrap();
        let queries: [(&[&str], &[u8]); 4] = [
            (&["variable_declarator"], b"a"),
            (
                &[
                    "function_declaration",
                    "class_declaration",
                    "variable_declarator",
                ],
                b"a",
            ),
            (&["interface_declaration", "type_alias_declaration"], b"I"),
            (&["variable_declarator"], b"missing"),
        ];
        let walked: Vec<Vec<_>> = queries
            .iter()
            .map(|(k, n)| named(probe, k, n, src.as_bytes()))
            .collect();
        let _scope = scope(root, src.as_bytes());
        let indexed: Vec<Vec<_>> = queries
            .iter()
            .map(|(k, n)| named(probe, k, n, src.as_bytes()))
            .collect();
        assert_eq!(walked, indexed);
        fn kinds(v: &[Node]) -> Vec<String> {
            v.iter().map(|n| n.kind().to_string()).collect()
        }
        assert_eq!(
            kinds(&indexed[0]),
            ["variable_declarator", "variable_declarator"]
        );
        assert_eq!(
            kinds(&indexed[1]),
            [
                "variable_declarator",
                "function_declaration",
                "variable_declarator",
                "class_declaration"
            ]
        );
        assert_eq!(
            kinds(&indexed[2]),
            ["interface_declaration", "type_alias_declaration"]
        );
        assert!(indexed[3].is_empty());
    }

    #[test]
    fn another_tree_is_walked_not_looked_up() {
        let (s1, s2) = ("const a = 1;\n", "let x;\nconst a = 2;\n");
        let (t1, t2) = (tree(s1), tree(s2));
        let _scope = scope(t1.root_node(), s1.as_bytes());
        let found = named(
            t2.root_node(),
            &["variable_declarator"],
            b"a",
            s2.as_bytes(),
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].start_byte(), 13);
    }

    #[test]
    fn the_index_ends_with_its_scope() {
        let src = "const a = 1;\n";
        let t = tree(src);
        {
            let _scope = scope(t.root_node(), src.as_bytes());
            INDEX.with(|i| assert_eq!(i.borrow().len(), 1));
        }
        INDEX.with(|i| assert!(i.borrow().is_empty()));
    }

    #[test]
    fn memos_compute_once_while_indexed() {
        let src = "const a = 1;\n";
        let t = tree(src);
        let calls = std::cell::Cell::new(0);
        let get = || {
            *memo(src.as_bytes(), ("test", b"k"), || {
                calls.set(calls.get() + 1);
                7
            })
        };
        // Not indexed: every time.
        assert_eq!((get(), get()), (7, 7));
        assert_eq!(calls.get(), 2);
        {
            let _scope = scope(t.root_node(), src.as_bytes());
            assert_eq!((get(), get(), get()), (7, 7, 7));
            assert_eq!(calls.get(), 3);
        }
        // A new scope starts afresh.
        let _scope = scope(t.root_node(), src.as_bytes());
        get();
        assert_eq!(calls.get(), 4);
    }
}
