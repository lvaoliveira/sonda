//! Qt's class macros, rewritten for tree-sitter-cpp without moving a byte,
//! so every node keeps its position in the real source, which rules still
//! read. moc and the preprocessor turn them into ordinary C++; the grammar
//! sees unknown words that break the class around them:
//!
//! - **Class body macros** on a line of their own: `Q_OBJECT`, `Q_GADGET`,
//!   `Q_NAMESPACE`, and one-line `Q_PROPERTY(...)`, `Q_ENUM(...)`,
//!   `Q_DISABLE_COPY(...)` and the like, become spaces.
//! - **Signal and slot sections**: `public slots:` loses `slots`, and
//!   `signals:` reads `public :`, as moc's headers define them.
//! - **`emit`** before a call, `emit changed(x);`, becomes spaces: Qt
//!   defines it as nothing.

use std::borrow::Cow;

/// Macros that stand alone on a line in a class body.
const BARE: &[&str] = &["Q_OBJECT", "Q_GADGET", "Q_NAMESPACE"];

/// Macros taking arguments, on a line of their own in a class body.
const CALLED: &[&str] = &[
    "Q_PROPERTY",
    "Q_ENUM",
    "Q_ENUMS",
    "Q_FLAG",
    "Q_FLAGS",
    "Q_INTERFACES",
    "Q_CLASSINFO",
    "Q_DISABLE_COPY",
    "Q_DISABLE_COPY_MOVE",
    "Q_DECLARE_PRIVATE",
    "Q_DECLARE_PUBLIC",
    "Q_PLUGIN_METADATA",
];

/// `src` as tree-sitter-cpp can parse it: the same length, and the same
/// lines. Borrowed when nothing needs rewriting.
pub(crate) fn for_parser(src: &str) -> Cow<'_, str> {
    if !src.contains("Q_")
        && !src.contains("signals")
        && !src.contains("slots")
        && !src.contains("emit")
    {
        return Cow::Borrowed(src);
    }
    let mut out: Option<Vec<u8>> = None;
    let mut at = 0;
    for line in src.split_inclusive('\n') {
        let start = at;
        at += line.len();
        let body = line.trim_end();
        let indent = body.len() - body.trim_start().len();
        let rest = &body[indent..];
        let mut edit = |from: usize, with: &[u8]| {
            let buf = out.get_or_insert_with(|| src.as_bytes().to_vec());
            buf[start + from..start + from + with.len()].copy_from_slice(with);
        };
        if let Some(len) = class_macro(rest) {
            edit(indent, &b" ".repeat(len));
        } else if let Some(word) = slots_word(rest) {
            edit(indent + word.0, &b" ".repeat(word.1));
        } else if rest.starts_with("signals") && rest[7..].trim_start().starts_with(':') {
            edit(indent, b"public ");
        } else if rest.starts_with("Q_SIGNALS") && rest[9..].trim_start().starts_with(':') {
            edit(indent, b"public   ");
        } else if let Some(len) = emit_word(rest) {
            edit(indent, &b" ".repeat(len));
        }
    }
    // Every edit replaced ASCII bytes with ASCII bytes.
    out.map_or(Cow::Borrowed(src), |b| {
        Cow::Owned(String::from_utf8(b).unwrap_or_else(|_| src.to_owned()))
    })
}

/// The length of a class body macro the line holds alone, its `;` too.
fn class_macro(line: &str) -> Option<usize> {
    let line_wo = line.strip_suffix(';').unwrap_or(line);
    if BARE.contains(&line_wo) {
        return Some(line.len());
    }
    let name = CALLED.iter().find(|m| {
        line_wo
            .strip_prefix(**m)
            .is_some_and(|r| r.trim_start().starts_with('(') && r.ends_with(')'))
    })?;
    let args = &line_wo[name.len()..];
    let balanced = args.bytes().fold(0i32, |depth, b| match b {
        b'(' => depth + 1,
        b')' => depth - 1,
        _ => depth,
    }) == 0;
    balanced.then_some(line.len())
}

/// Where `slots` or `Q_SLOTS` sits in `public slots:`, and its length.
fn slots_word(line: &str) -> Option<(usize, usize)> {
    let access = ["public", "protected", "private"]
        .iter()
        .find(|a| line.starts_with(**a))?;
    let after = &line[access.len()..];
    let gap = after.len() - after.trim_start().len();
    if gap == 0 {
        return None;
    }
    let word = ["Q_SLOTS", "slots"]
        .iter()
        .find(|w| after[gap..].starts_with(**w))?;
    after[gap + word.len()..]
        .trim_start()
        .starts_with(':')
        .then_some((access.len() + gap, word.len()))
}

/// The length of a statement's leading `emit` or `Q_EMIT` before a call.
fn emit_word(line: &str) -> Option<usize> {
    let word = ["Q_EMIT", "emit"].iter().find(|w| line.starts_with(**w))?;
    let after = &line[word.len()..];
    let next = after.trim_start();
    (after.len() > next.len() && next.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_'))
        .then_some(word.len())
}

#[cfg(test)]
mod tests {
    use super::for_parser;

    #[test]
    fn qt_macros_become_spaces_in_place() {
        let src = "class A : public QObject {\n    Q_OBJECT\n    Q_PROPERTY(int x READ x)\n  public slots:\n    void f();\n  signals:\n    void g();\n};\nvoid A::f() { emit g(); emit(g()); }\n";
        let out = for_parser(src);
        assert_eq!(out.len(), src.len());
        assert_eq!(out.lines().count(), src.lines().count());
        assert!(!out.contains("Q_OBJECT") && !out.contains("Q_PROPERTY"));
        assert!(out.contains("  public      :\n") && out.contains("  public :\n"));
        assert!(
            out.contains("{ emit g(); emit(g()); }"),
            "only a statement's own line start"
        );
        let plain = "int main() { return 0; }\n";
        assert!(matches!(for_parser(plain), std::borrow::Cow::Borrowed(_)));
    }
}
