//! Python syntax newer than tree-sitter-python's grammar (0.25), rewritten
//! for the parser without moving a byte, so every node keeps its position
//! in the real source, which rules still read:
//!
//! - **Lazy imports** (PEP 810, Python 3.15): `lazy import json` and `lazy
//!   from os import path`. The soft keyword `lazy` becomes four spaces: a
//!   lazy import binds the same names as an eager one.
//! - **Type parameter defaults** (PEP 696, Python 3.13): `def f[T = int]`,
//!   `class C[*Ts = *tuple[int]]`, `type A[**P = [int]] = ...`. The `= ...`
//!   becomes spaces, newlines kept: no rule reads a default.
//!
//! Upstream tracks both (tree-sitter-python #336 and #346). Without this,
//! each such file has a syntax error, and `lazy` reads as an undefined name.
//! Not covered: unpacking in comprehensions (PEP 798, `[*xs for xs in a]`,
//! #352), which text alone can't tell from a list display.

use std::borrow::Cow;

/// `src` as tree-sitter-python can parse it: the same length, and the same
/// lines. Borrowed when nothing needs rewriting.
pub(crate) fn for_parser(src: &str) -> Cow<'_, str> {
    if !src.contains("lazy") && !src.contains('[') {
        return Cow::Borrowed(src);
    }
    let bytes = src.as_bytes();
    let mut blank: Vec<(usize, usize)> = Vec::new();
    let mut at = 0;
    // Where the last type parameter list scanned ended: lines before it
    // were inside it, so the whole pass stays linear.
    let mut scanned = 0;
    for line in src.split_inclusive('\n') {
        let start = at;
        at += line.len();
        let indent = line.len() - line.trim_start_matches([' ', '\t']).len();
        let rest = &line[indent..];
        if let Some(after) = rest.strip_prefix("lazy")
            && let Some(stmt) = after.strip_prefix([' ', '\t'])
            && starts_with_word(stmt.trim_start_matches([' ', '\t']), &["import", "from"])
        {
            blank.push((start + indent, start + indent + 4));
        }
        if start >= scanned
            && let Some(open) = type_parameters(rest)
        {
            scanned = defaults(bytes, start + indent + open, &mut blank);
        }
    }
    if blank.is_empty() {
        return Cow::Borrowed(src);
    }
    let mut out = bytes.to_vec();
    for (from, to) in blank {
        for b in &mut out[from..to] {
            if *b != b'\n' && *b != b'\r' {
                *b = b' ';
            }
        }
    }
    // Every range starts and ends at an ASCII byte, so whole characters were
    // replaced by ASCII spaces.
    Cow::Owned(String::from_utf8(out).expect("whole characters replaced"))
}

/// `word` followed by a space, a tab or the end, for one of `words`.
fn starts_with_word(s: &str, words: &[&str]) -> bool {
    words.iter().any(|w| {
        s.strip_prefix(w)
            .is_some_and(|r| r.is_empty() || r.starts_with([' ', '\t', '\r', '\n']))
    })
}

/// Where a statement's type parameter list opens, as an offset into `stmt`
/// (a line without its indentation): after `def name`, `async def name`,
/// `class name` or `type name`.
fn type_parameters(stmt: &str) -> Option<usize> {
    let mut s = stmt;
    if let Some(r) = s.strip_prefix("async")
        && r.starts_with([' ', '\t'])
    {
        s = r.trim_start_matches([' ', '\t']);
    }
    let r = ["def", "class", "type"]
        .iter()
        .find_map(|k| s.strip_prefix(k).filter(|r| r.starts_with([' ', '\t'])))?;
    let r = r.trim_start_matches([' ', '\t']);
    let name = r
        .bytes()
        .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_' || !b.is_ascii())
        .count();
    if name == 0 {
        return None;
    }
    let r2 = r[name..].trim_start_matches([' ', '\t']);
    r2.starts_with('[').then(|| stmt.len() - r2.len())
}

/// Adds each default in the type parameter list opening at `open` (a `[`)
/// to `blank`: from its `=` to the `,` or `]` that ends the parameter.
/// Returns where the list ends (or the source, if it never closes).
fn defaults(bytes: &[u8], open: usize, blank: &mut Vec<(usize, usize)>) -> usize {
    let mut depth = 0usize;
    let mut default_from: Option<usize> = None;
    let mut i = open;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'\'' | b'"' => {
                // Skip a string, triple-quoted or not.
                let triple = bytes[i..].starts_with(&[b, b, b]);
                let quote: &[u8] = if triple {
                    &bytes[i..i + 3]
                } else {
                    &bytes[i..=i]
                };
                let mut j = i + quote.len();
                while j < bytes.len() && !bytes[j..].starts_with(quote) {
                    if bytes[j] == b'\\' {
                        j += 1;
                    } else if bytes[j] == b'\n' && !triple {
                        break;
                    }
                    j += 1;
                }
                i = j + quote.len();
                continue;
            }
            b'#' => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            b'[' | b'(' | b'{' => depth += 1,
            b']' | b')' | b'}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    if let Some(from) = default_from.take() {
                        blank.push((from, i));
                    }
                    return i + 1;
                }
            }
            b',' if depth == 1 => {
                if let Some(from) = default_from.take() {
                    blank.push((from, i));
                }
            }
            b'=' if depth == 1 && default_from.is_none() => {
                // Not part of `==`, `<=`, `>=` or `!=`: none belongs in a
                // type parameter list, but don't take them for a default.
                let prev = i.checked_sub(1).map(|p| bytes[p]);
                let next = bytes.get(i + 1).copied();
                if !matches!(prev, Some(b'=' | b'<' | b'>' | b'!')) && next != Some(b'=') {
                    default_from = Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    bytes.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lang::Lang;

    fn parses(src: &str) -> bool {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&Lang::Python.grammar()).unwrap();
        !parser.parse(src, None).unwrap().root_node().has_error()
    }

    #[test]
    fn lazy_imports_parse_as_imports() {
        let src = "lazy import json\nlazy from os import path\nif x:\n    lazy\timport a.b as c\n";
        assert!(!parses(src));
        let out = for_parser(src);
        assert_eq!(
            out,
            "     import json\n     from os import path\nif x:\n        \timport a.b as c\n"
        );
        assert!(parses(&out));
    }

    #[test]
    fn lazy_the_name_is_left_alone() {
        for src in [
            "lazy = 1\n",
            "lazy(import_this)\n",
            "lazyimport = 2\n",
            "lazy.imports = 3\n",
            "x = lazy\n",
            "def lazy(): pass\n",
            "lazy importer\n",
        ] {
            assert_eq!(for_parser(src), src, "{src:?}");
        }
    }

    #[test]
    fn type_parameter_defaults_are_blanked_in_place() {
        let cases = [
            (
                "def f[T = int](x: T) -> T: ...\n",
                "def f[T      ](x: T) -> T: ...\n",
            ),
            (
                "class C[K, V = dict[str, int], *Ts = *tuple[int]]: ...\n",
                "class C[K, V                 , *Ts              ]: ...\n",
            ),
            (
                "type A[**P = [int, str]] = Callable[P, None]\n",
                "type A[**P             ] = Callable[P, None]\n",
            ),
            (
                "async def g[T: str = \"a]\"]() -> T: ...\n",
                "async def g[T: str       ]() -> T: ...\n",
            ),
            // Across lines, which are kept.
            (
                "def h[\n    T = int,  # the default\n    U = str,\n](): ...\n",
                "def h[\n    T      ,  # the default\n    U      ,\n](): ...\n",
            ),
        ];
        for (src, want) in cases {
            assert!(!parses(src), "{src:?} already parses");
            let out = for_parser(src);
            assert_eq!(out, want);
            assert!(parses(&out), "{out:?}");
        }
    }

    #[test]
    fn everything_else_is_unchanged() {
        for src in [
            "def f[T](x: T) -> T: ...\n",
            "class C[T: int]: ...\n",
            "type A[T] = list[T]\n",
            "x[i] = 1\n",
            "d = {k: v for k, v in a[1:2]}\n",
            "def f(x=a[0]): ...\n",
            "s = \"lazy import x\"\n",
        ] {
            assert!(matches!(for_parser(src), Cow::Borrowed(_)), "{src:?}");
        }
    }

    #[test]
    fn rewriting_keeps_length_and_lines() {
        let src = "lazy import é\ndef f[T = \"ü\"]():\n    pass\n";
        let out = for_parser(src);
        assert_eq!(out.len(), src.len());
        assert_eq!(out.lines().count(), src.lines().count());
    }

    #[test]
    fn unclosed_lists_are_scanned_once() {
        // 20,000 unclosed lists: each would scan to the end of the file.
        let src = "def f[T = int\n".repeat(20_000);
        let started = std::time::Instant::now();
        let out = for_parser(&src);
        assert_eq!(out.len(), src.len());
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }
}
