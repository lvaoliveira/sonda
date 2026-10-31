//! A small YAML tree for lockfiles (`pnpm-lock.yaml`, Yarn 2+'s
//! `yarn.lock`), built from `yaml_rust2`'s event parser.
//!
//! Security: lockfiles come from the analyzed repository. `yaml_rust2`'s
//! own loader copies an anchor's node at every alias, so a few lines can
//! expand exponentially ("billion laughs"). This builder never expands
//! aliases (it rejects them: package managers don't write any), caps the
//! nesting depth, so building and dropping the tree can't exhaust the
//! stack, and keeps memory proportional to the input.

use yaml_rust2::Event;
use yaml_rust2::parser::Parser;

/// Lockfiles nest about five levels deep.
const MAX_DEPTH: usize = 64;

#[derive(Debug, Clone, PartialEq)]
pub(super) enum Node {
    /// Every scalar as written: `9.0`, `true` and `null` stay text.
    Scalar(String),
    Seq(Vec<Node>),
    /// Keys in file order; lockfiles only use scalar keys.
    Map(Vec<(String, Node)>),
}

impl Node {
    pub(super) fn get(&self, key: &str) -> Option<&Node> {
        match self {
            Node::Map(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub(super) fn str(&self) -> Option<&str> {
        match self {
            Node::Scalar(s) => Some(s),
            _ => None,
        }
    }

    pub(super) fn entries(&self) -> &[(String, Node)] {
        match self {
            Node::Map(entries) => entries,
            _ => &[],
        }
    }
}

/// A container being built, with the key it will be stored under.
enum Open {
    Seq(Vec<Node>),
    Map(Vec<(String, Node)>, Option<String>),
}

/// The first document of `text`. An error is a warning's text.
pub(super) fn load(text: &str) -> Result<Node, String> {
    load_all(text)?
        .into_iter()
        .next()
        .ok_or_else(|| "empty document".to_string())
}

/// Every document of `text` (pnpm 11 and later write two: the package
/// manager's own, then the project's). An error is a warning's text.
pub(super) fn load_all(text: &str) -> Result<Vec<Node>, String> {
    let mut parser = Parser::new_from_str(text);
    let mut stack: Vec<Open> = Vec::new();
    let mut documents = Vec::new();
    loop {
        let (event, mark) = parser
            .next_token()
            .map_err(|e| format!("not valid YAML ({e})"))?;
        let done = match event {
            Event::Scalar(value, ..) => add(&mut stack, Node::Scalar(value))?,
            Event::SequenceStart(..) | Event::MappingStart(..) => {
                if stack.len() >= MAX_DEPTH {
                    return Err(format!("nested deeper than {MAX_DEPTH} levels"));
                }
                if matches!(stack.last(), Some(Open::Map(_, None))) {
                    return Err(format!("line {}: a key that isn't text", mark.line()));
                }
                stack.push(if matches!(event, Event::SequenceStart(..)) {
                    Open::Seq(Vec::new())
                } else {
                    Open::Map(Vec::new(), None)
                });
                None
            }
            Event::SequenceEnd | Event::MappingEnd => match stack.pop() {
                Some(Open::Seq(items)) => add(&mut stack, Node::Seq(items))?,
                Some(Open::Map(entries, None)) => add(&mut stack, Node::Map(entries))?,
                _ => return Err("not valid YAML (unbalanced)".into()),
            },
            Event::Alias(_) => {
                return Err(format!(
                    "line {}: anchors and aliases aren't read in lockfiles",
                    mark.line()
                ));
            }
            Event::StreamEnd => {
                return if documents.is_empty() {
                    Err("empty document".into())
                } else {
                    Ok(documents)
                };
            }
            Event::Nothing | Event::StreamStart | Event::DocumentStart | Event::DocumentEnd => None,
        };
        if let Some(root) = done {
            documents.push(root);
        }
    }
}

/// Adds `node` to the innermost open container, as a map key or value or a
/// sequence item; returns it when there's none, as the document's root.
fn add(stack: &mut [Open], node: Node) -> Result<Option<Node>, String> {
    match stack.last_mut() {
        None => Ok(Some(node)),
        Some(Open::Seq(items)) => {
            items.push(node);
            Ok(None)
        }
        Some(Open::Map(entries, key)) => {
            match key.take() {
                Some(k) => entries.push((k, node)),
                None => match node {
                    Node::Scalar(k) => *key = Some(k),
                    _ => return Err("a key that isn't text".into()),
                },
            }
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn builds_maps_sequences_and_scalars() {
        let doc = load("a: '9.0'\nb:\n  - x\n  - {c: d}\nempty: {}\n").unwrap();
        assert_eq!(doc.get("a").and_then(Node::str), Some("9.0"));
        assert_eq!(
            doc.get("b"),
            Some(&Node::Seq(vec![
                Node::Scalar("x".into()),
                Node::Map(vec![("c".into(), Node::Scalar("d".into()))]),
            ]))
        );
        assert_eq!(doc.get("empty"), Some(&Node::Map(vec![])));
        assert_eq!(doc.get("missing"), None);
    }

    #[test]
    fn refuses_aliases_deep_nesting_and_odd_keys() {
        // "Billion laughs": each alias would copy the anchor's list.
        let laughs =
            "a: &a [x, x, x, x, x, x, x, x, x]\nb: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]\n";
        assert!(load(laughs).unwrap_err().contains("aliases"));
        let deep = format!("{}x{}", "[".repeat(200), "]".repeat(200));
        assert!(load(&deep).is_err());
        let mut indented = String::new();
        for depth in 0..100 {
            indented.push_str(&format!("{}k:\n", "  ".repeat(depth)));
        }
        indented.push_str(&format!("{}v: 1\n", "  ".repeat(100)));
        assert!(load(&indented).unwrap_err().contains("deeper"));
        assert!(load("? [a, b]\n: c\n").is_err());
        assert!(load("").is_err());
    }

    #[test]
    fn reads_every_document() {
        let docs = load_all("---\na: 1\n---\nb: 2\n").unwrap();
        assert_eq!(docs.len(), 2);
        assert_eq!(docs[1].get("b").and_then(Node::str), Some("2"));
    }

    proptest! {
        #![proptest_config(crate::test_support::proptest_config(256))]

        #[test]
        fn loader_accepts_any_input_without_panicking(
            text in prop_oneof![any::<String>(), "([a-z0-9:'\"@/\\[\\]{},&*?|>-]|\n  | )*"]
        ) {
            let _ = load(&text);
        }
    }
}
