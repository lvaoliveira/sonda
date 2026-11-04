//! Rust code inside macro arguments ([ADR-0026](../../../docs/adr/0026-rust.md)).
//!
//! tree-sitter keeps a macro's arguments as raw tokens: in
//! `assert!(a == a, "msg")` there is no `==` expression for a rule to match,
//! though Clippy lints it. For the standard macros whose arguments are
//! expressions, this rewrites each `name!(` to `name (`, one space for the `!`
//! so every byte offset stays where it was, which parses as a call. The rules
//! run on that copy too, and report what they find inside the arguments.

use std::ops::Range;
use tree_sitter::Node;

/// Macros whose arguments are all expressions (and a format string). Not
/// `vec!`, whose brackets would read as an index, nor `matches!`, whose second
/// argument is a pattern.
const EXPRESSION_MACROS: &[&str] = &[
    "assert",
    "assert_eq",
    "assert_ne",
    "debug_assert",
    "debug_assert_eq",
    "debug_assert_ne",
    "println",
    "print",
    "eprintln",
    "eprint",
    "format",
    "format_args",
    "write",
    "writeln",
    "panic",
    "unreachable",
    "todo",
    "unimplemented",
    "dbg",
];

/// The file with its expression macros rewritten as calls, and where their
/// arguments are.
pub(crate) struct Shadow {
    pub(crate) source: String,
    /// Each call from its name to its closing parenthesis. Sorted, not
    /// overlapping: a nested macro is inside its outer one's.
    pub(crate) arguments: Vec<Range<usize>>,
}

impl Shadow {
    /// Whether a byte offset is inside some macro's arguments.
    pub(crate) fn covers(&self, offset: usize) -> bool {
        self.arguments
            .binary_search_by(|r| {
                if r.end <= offset {
                    std::cmp::Ordering::Less
                } else if r.start > offset {
                    std::cmp::Ordering::Greater
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .is_ok()
    }
}

/// The rewritten file, or None when it has no such macro call.
pub(crate) fn shadow(src: &str, root: Node) -> Option<Shadow> {
    let bytes = src.as_bytes();
    let mut rewritten = bytes.to_vec();
    let mut arguments: Vec<Range<usize>> = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        // A macro definition's body is a template, with `$x:expr` where a
        // value would be.
        if node.kind() == "macro_definition" {
            continue;
        }
        if node.kind() == "!"
            && let (Some(name), Some(args)) = (node.prev_sibling(), node.next_sibling())
            && name.kind() == "identifier"
            && args.kind() == "token_tree"
            && bytes.get(args.start_byte()) == Some(&b'(')
            && EXPRESSION_MACROS.contains(&&src[name.byte_range()])
        {
            rewritten[node.start_byte()] = b' ';
            // From the macro's name, where the call it became starts.
            arguments.push(name.start_byte()..args.end_byte());
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
    if arguments.is_empty() {
        return None;
    }
    arguments.sort_by_key(|r| r.start);
    // Keep the outermost of nested ones.
    let mut outer: Vec<Range<usize>> = Vec::with_capacity(arguments.len());
    for r in arguments {
        match outer.last() {
            Some(last) if r.start < last.end => {}
            _ => outer.push(r),
        }
    }
    // Only ASCII `!`s became spaces, so this is still UTF-8.
    let source = String::from_utf8(rewritten).ok()?;
    Some(Shadow {
        source,
        arguments: outer,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lang::Lang;

    fn shadow_of(src: &str) -> Option<Shadow> {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&Lang::Rust.grammar()).unwrap();
        let tree = parser.parse(src, None).unwrap();
        shadow(src, tree.root_node())
    }

    #[test]
    fn a_known_macro_becomes_a_call_of_the_same_length() {
        let src = "fn f() { assert!(a == a, \"m\"); }";
        let s = shadow_of(src).unwrap();
        assert_eq!(s.source, "fn f() { assert (a == a, \"m\"); }");
        assert_eq!(s.source.len(), src.len());
        assert_eq!(s.arguments.len(), 1);
        assert_eq!(&src[s.arguments[0].clone()], "assert!(a == a, \"m\")");
    }

    #[test]
    fn nested_macros_are_rewritten_and_only_the_outer_range_is_kept() {
        let src = "fn f() { println!(\"{}\", format!(\"{}\", x)); }";
        let s = shadow_of(src).unwrap();
        assert_eq!(s.source, "fn f() { println (\"{}\", format (\"{}\", x)); }");
        assert_eq!(s.arguments.len(), 1);
    }

    #[test]
    fn other_macros_bracketed_calls_and_definitions_are_left_alone() {
        assert!(shadow_of("fn f() { vec![1, 2]; matches!(x, Some(_)); }").is_none());
        assert!(shadow_of("fn f() { println!{\"x\"}; }").is_none());
        assert!(shadow_of("fn f() { std::println!(\"x\"); }").is_none());
        assert!(shadow_of("macro_rules! m { () => { println!(\"x\") } }").is_none());
        assert!(shadow_of("fn f() { let b = !x; }").is_none());
    }

    #[test]
    fn covers_says_whether_an_offset_is_in_some_arguments() {
        let src = "fn f() { println!(\"a\"); g(); println!(\"b\"); }";
        let s = shadow_of(src).unwrap();
        assert_eq!(s.arguments.len(), 2);
        assert!(s.covers(src.find("\"a\"").unwrap()));
        assert!(!s.covers(src.find("g()").unwrap()));
        assert!(s.covers(src.find("\"b\"").unwrap()));
    }
}
