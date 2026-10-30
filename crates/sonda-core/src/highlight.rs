//! Domain: syntax highlighting for showing code, e.g. the server's issue
//! view. A small lexer, not tree-sitter: it runs on uploaded code inside the
//! server process, where the C parsers must not (ADR-0003 confines them to
//! sandboxed workers). It only has to color code, not understand it, and is
//! linear in the source with no recursion.

use crate::lang::Lang;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Keyword,
    String,
    Number,
    Comment,
    Type,
    Punct,
    Plain,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Token {
    pub text: String,
    pub role: Role,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Line {
    /// 1-based.
    pub number: usize,
    pub tokens: Vec<Token>,
}

/// Lines `first..=last` (1-based, clamped to the file) of `src`, as tokens.
/// The whole file up to `last` is lexed, so a comment or string opened
/// before `first` is colored correctly. Each line's tokens concatenate to
/// exactly that line's text, without its line ending (`\n` or `\r\n`).
pub fn highlight(lang: Lang, src: &str, first: usize, last: usize) -> Vec<Line> {
    let syntax = Syntax::of(lang);
    let in_range = |n: usize| n >= first && n <= last;
    let mut lines = Vec::new();
    let mut current = Line {
        number: 1,
        tokens: Vec::new(),
    };
    let mut i = 0;
    while i < src.len() && current.number <= last {
        let (len, role) = next_token(&syntax, &src[i..]);
        // Tokens may span lines (block comments, strings): split them.
        let mut parts = src[i..i + len].split('\n').peekable();
        while let Some(part) = parts.next() {
            if in_range(current.number) && !part.is_empty() {
                push(&mut current.tokens, part, role);
            }
            if parts.peek().is_some() {
                strip_carriage_return(&mut current.tokens);
                let next = Line {
                    number: current.number + 1,
                    tokens: Vec::new(),
                };
                let done = std::mem::replace(&mut current, next);
                if in_range(done.number) {
                    lines.push(done);
                }
            }
        }
        i += len;
    }
    if i >= src.len() && in_range(current.number) {
        lines.push(current);
    }
    lines
}

/// Drops the `\r` of a `\r\n` line ending, which belongs to no line.
fn strip_carriage_return(tokens: &mut Vec<Token>) {
    if let Some(t) = tokens.last_mut()
        && t.text.ends_with('\r')
    {
        t.text.pop();
        if t.text.is_empty() {
            tokens.pop();
        }
    }
}

/// Appends `text`, merging it into the previous token if the role matches.
fn push(tokens: &mut Vec<Token>, text: &str, role: Role) {
    match tokens.last_mut() {
        Some(t) if t.role == role => t.text.push_str(text),
        _ => tokens.push(Token {
            text: text.to_string(),
            role,
        }),
    }
}

/// The length in bytes (always at least one character) and role of the
/// token at the start of `s`.
fn next_token(syntax: &Syntax, s: &str) -> (usize, Role) {
    if let Some(start) = syntax.line_comment.iter().find(|c| s.starts_with(**c)) {
        let end = s[start.len()..]
            .find('\n')
            .map_or(s.len(), |n| start.len() + n);
        return (end, Role::Comment);
    }
    if syntax.block_comments && s.starts_with("/*") {
        let end = s[2..].find("*/").map_or(s.len(), |n| n + 4);
        return (end, Role::Comment);
    }
    if syntax.triple_quotes {
        for q in ["\"\"\"", "'''"] {
            if s.starts_with(q) {
                let end = s[3..].find(q).map_or(s.len(), |n| n + 6);
                return (end, Role::String);
            }
        }
    }
    let c = s.chars().next().unwrap_or(' ');
    if c == '"' || c == '\'' || (c == '`' && syntax.backticks) {
        return (string_end(s, c), Role::String);
    }
    if c.is_ascii_digit() {
        let end = s
            .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '.' || ch == '_'))
            .unwrap_or(s.len());
        return (end, Role::Number);
    }
    if c.is_alphabetic() || c == '_' || c == '$' {
        let end = s
            .find(|ch: char| !(ch.is_alphanumeric() || ch == '_' || ch == '$'))
            .unwrap_or(s.len());
        let word = &s[..end];
        let role = if syntax.keywords.contains(&word) {
            Role::Keyword
        } else if syntax.types.contains(&word) || word.starts_with(char::is_uppercase) {
            Role::Type
        } else {
            Role::Plain
        };
        return (end, role);
    }
    if c.is_whitespace() {
        let end = s
            .find(|ch: char| !ch.is_whitespace() || ch == '\n')
            .unwrap_or(s.len());
        // A newline is its own token, so `highlight` can split lines.
        return (end.max(c.len_utf8()), Role::Plain);
    }
    (c.len_utf8(), Role::Punct)
}

/// End of a string starting with `quote`: after the closing quote, or at
/// the end of the line for a one-line string left open (the end of the file
/// for a backtick template).
fn string_end(s: &str, quote: char) -> usize {
    let mut escaped = false;
    for (i, ch) in s.char_indices().skip(1) {
        match ch {
            _ if escaped => escaped = false,
            '\\' => escaped = true,
            '\n' if quote != '`' => return i,
            _ if ch == quote => return i + ch.len_utf8(),
            _ => {}
        }
    }
    s.len()
}

struct Syntax {
    line_comment: &'static [&'static str],
    block_comments: bool,
    triple_quotes: bool,
    backticks: bool,
    keywords: &'static [&'static str],
    types: &'static [&'static str],
}

impl Syntax {
    fn of(lang: Lang) -> Self {
        match lang {
            Lang::JavaScript | Lang::TypeScript | Lang::Tsx => Self {
                line_comment: &["//"],
                block_comments: true,
                triple_quotes: false,
                backticks: true,
                keywords: JS_KEYWORDS,
                types: TS_TYPES,
            },
            Lang::Python => Self {
                line_comment: &["#"],
                block_comments: false,
                triple_quotes: true,
                backticks: false,
                keywords: PY_KEYWORDS,
                types: PY_TYPES,
            },
            Lang::Java => Self {
                line_comment: &["//"],
                block_comments: true,
                triple_quotes: true, // text blocks
                backticks: false,
                keywords: JAVA_KEYWORDS,
                types: JAVA_TYPES,
            },
            Lang::C | Lang::Cpp => Self {
                line_comment: &["//"],
                block_comments: true,
                triple_quotes: false,
                backticks: false,
                keywords: C_KEYWORDS,
                types: C_TYPES,
            },
        }
    }
}

const JS_KEYWORDS: &[&str] = &[
    "abstract",
    "as",
    "async",
    "await",
    "break",
    "case",
    "catch",
    "class",
    "const",
    "continue",
    "debugger",
    "declare",
    "default",
    "delete",
    "do",
    "else",
    "enum",
    "export",
    "extends",
    "false",
    "finally",
    "for",
    "from",
    "function",
    "get",
    "if",
    "implements",
    "import",
    "in",
    "instanceof",
    "interface",
    "keyof",
    "let",
    "namespace",
    "new",
    "null",
    "of",
    "private",
    "protected",
    "public",
    "readonly",
    "return",
    "set",
    "static",
    "super",
    "switch",
    "this",
    "throw",
    "true",
    "try",
    "type",
    "typeof",
    "undefined",
    "var",
    "void",
    "while",
    "with",
    "yield",
];
const TS_TYPES: &[&str] = &[
    "any", "bigint", "boolean", "never", "number", "object", "string", "symbol", "unknown",
];
const PY_KEYWORDS: &[&str] = &[
    "False", "None", "True", "and", "as", "assert", "async", "await", "break", "class", "continue",
    "def", "del", "elif", "else", "except", "finally", "for", "from", "global", "if", "import",
    "in", "is", "lambda", "match", "nonlocal", "not", "or", "pass", "raise", "return", "try",
    "while", "with", "yield",
];
const PY_TYPES: &[&str] = &[
    "bool", "bytes", "dict", "float", "int", "list", "set", "str", "tuple",
];
const JAVA_KEYWORDS: &[&str] = &[
    "abstract",
    "assert",
    "break",
    "case",
    "catch",
    "class",
    "continue",
    "default",
    "do",
    "else",
    "enum",
    "extends",
    "false",
    "final",
    "finally",
    "for",
    "if",
    "implements",
    "import",
    "instanceof",
    "interface",
    "native",
    "new",
    "null",
    "package",
    "private",
    "protected",
    "public",
    "record",
    "return",
    "static",
    "super",
    "switch",
    "synchronized",
    "this",
    "throw",
    "throws",
    "transient",
    "true",
    "try",
    "var",
    "volatile",
    "while",
    "yield",
];
const JAVA_TYPES: &[&str] = &[
    "boolean", "byte", "char", "double", "float", "int", "long", "short", "void",
];
const C_KEYWORDS: &[&str] = &[
    "auto",
    "break",
    "case",
    "catch",
    "class",
    "const",
    "constexpr",
    "continue",
    "default",
    "delete",
    "do",
    "else",
    "enum",
    "explicit",
    "extern",
    "false",
    "for",
    "friend",
    "goto",
    "if",
    "inline",
    "namespace",
    "new",
    "nullptr",
    "operator",
    "private",
    "protected",
    "public",
    "register",
    "return",
    "sizeof",
    "static",
    "struct",
    "switch",
    "template",
    "this",
    "throw",
    "true",
    "try",
    "typedef",
    "typename",
    "union",
    "using",
    "virtual",
    "volatile",
    "while",
];
const C_TYPES: &[&str] = &[
    "bool", "char", "double", "float", "int", "int16_t", "int32_t", "int64_t", "int8_t", "long",
    "short", "signed", "size_t", "uint16_t", "uint32_t", "uint64_t", "uint8_t", "unsigned", "void",
    "wchar_t",
];

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn roles(line: &Line) -> Vec<(&str, Role)> {
        line.tokens
            .iter()
            .map(|t| (t.text.as_str(), t.role))
            .collect()
    }

    #[test]
    fn colors_a_line_of_javascript() {
        let lines = highlight(Lang::JavaScript, "var x = \"a\" + 42; // note\n", 1, 1);
        use Role::*;
        assert_eq!(
            roles(&lines[0]),
            [
                ("var", Keyword),
                (" x ", Plain),
                ("=", Punct),
                (" ", Plain),
                ("\"a\"", String),
                (" ", Plain),
                ("+", Punct),
                (" ", Plain),
                ("42", Number),
                (";", Punct),
                (" ", Plain),
                ("// note", Comment),
            ]
        );
    }

    #[test]
    fn a_comment_opened_before_the_excerpt_still_colors_it() {
        let src = "/* starts here\nstill a comment\nends */ int x;\n";
        let lines = highlight(Lang::C, src, 2, 3);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].number, 2);
        assert_eq!(roles(&lines[0]), [("still a comment", Role::Comment)]);
        assert_eq!(lines[1].tokens[0].role, Role::Comment);
        assert!(
            lines[1]
                .tokens
                .iter()
                .any(|t| t.text == "int" && t.role == Role::Type)
        );
    }

    #[test]
    fn python_docstrings_and_hash_comments() {
        let src = "def f():\n    \"\"\"Doc\n    more\"\"\"\n    return None  # done\n";
        let lines = highlight(Lang::Python, src, 1, 4);
        assert_eq!(
            lines[0].tokens[0],
            Token {
                text: "def".into(),
                role: Role::Keyword
            }
        );
        assert_eq!(lines[2].tokens.last().unwrap().role, Role::String);
        assert_eq!(lines[3].tokens.last().unwrap().role, Role::Comment);
    }

    #[test]
    fn ranges_are_clamped_and_empty_lines_kept() {
        let lines = highlight(Lang::Java, "a\n\nb", 1, 99);
        assert_eq!(
            lines.iter().map(|l| l.number).collect::<Vec<_>>(),
            [1, 2, 3]
        );
        assert!(lines[1].tokens.is_empty());
        assert!(highlight(Lang::Java, "a\n", 5, 9).is_empty());
    }

    proptest! {
        #![proptest_config(crate::test_support::proptest_config(256))]

        /// Lossless and total: any input, any range, never panics, and each
        /// line's tokens rebuild that line exactly.
        #[test]
        fn tokens_rebuild_every_line(src in "[ -~\n\r\t\"'`/*#\\\\é]{0,200}", lang in 0usize..7) {
            let lang = crate::lang::ALL[lang];
            let lines = highlight(lang, &src, 1, usize::MAX);
            let segments: Vec<&str> = src.split('\n').collect();
            // A `\r` ends a line only right before `\n`.
            let expected: Vec<&str> = segments
                .iter()
                .enumerate()
                .map(|(k, s)| if k + 1 < segments.len() { s.strip_suffix('\r').unwrap_or(s) } else { s })
                .collect();
            prop_assert_eq!(lines.len(), expected.len());
            for (line, text) in lines.iter().zip(expected) {
                let rebuilt: String = line.tokens.iter().map(|t| t.text.as_str()).collect();
                prop_assert_eq!(rebuilt, text);
            }
        }
    }
}
