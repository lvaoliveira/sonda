//! Regular-expression rules for JavaScript and TypeScript (ADR-0013): the
//! pattern is read from a regex literal or `new RegExp(...)`, parsed by
//! `crate::regex` in its JavaScript dialect, and judged by the shared
//! analyses in `regex_checks`.

use super::js::{string_content, text};
use super::js_extra::named;
use super::js_more::is_provably_string;
use super::js_syntax::used_as_a_condition;
use super::regex_checks as checks;
use super::*;
use crate::regex::{Flags, Node as Rx, Regex, parse_js, walk as walk_regex};

/// This module's rules that are off unless `rules.enabled` lists them
/// (see `catalog::OFF_BY_DEFAULT`).
pub(super) static OFF_BY_DEFAULT: &[&str] = &["js/regex-unicode-flag"];

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "js/regex-empty-group",
        name: "Regular expressions should not contain empty groups",
        description: "An empty group matches nothing and captures nothing.",
        message: "Remove the empty group.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6331")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(regex) (new_expression constructor: (identifier) @c (#eq? @c "RegExp")) (call_expression function: (identifier) @c (#eq? @c "RegExp"))] @match"#,
            filter: Some(Find(find_has_empty_group)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const r = /a()b/;",
            good: "const r = /ab/;",
        }),
    },
    Rule {
        id: "js/regex-empty-alternative",
        name: "Alternation in regular expressions should not contain empty alternatives",
        description: "A stray | adds an alternative that matches everything.",
        message: "Remove the empty alternative, or make the group optional.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6323")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(regex) (new_expression constructor: (identifier) @c (#eq? @c "RegExp")) (call_expression function: (identifier) @c (#eq? @c "RegExp"))] @match"#,
            filter: Some(Find(find_has_empty_alternative)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const r = /(a|)b/;",
            good: "const r = /(a)?b/;",
        }),
    },
    Rule {
        id: "js/regex-single-character-class",
        name: "Character classes in regular expressions should not contain only one character",
        description: "[a] is a.",
        message: "Remove the brackets.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 1,
        sonar: &[exact("S6397")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(regex) (new_expression constructor: (identifier) @c (#eq? @c "RegExp")) (call_expression function: (identifier) @c (#eq? @c "RegExp"))] @match"#,
            filter: Some(Find(find_has_single_character_class)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const r = /[a]b/;",
            good: "const r = /ab/;",
        }),
    },
    Rule {
        id: "js/regex-concise-syntax",
        name: "Regular expression quantifiers and character classes should be used concisely",
        description: "[0-9] is \\d and a{1,} is a+.",
        message: "Use the shorter form.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S6353")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(regex) (new_expression constructor: (identifier) @c (#eq? @c "RegExp")) (call_expression function: (identifier) @c (#eq? @c "RegExp"))] @match"#,
            filter: Some(Find(find_could_be_concise)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const r = /[0-9]+/;",
            good: "const r = /\\d+/;",
        }),
    },
    Rule {
        id: "js/regex-single-character-alternation",
        name: "Single-character alternations in regular expressions should be replaced with character classes",
        description: "a|b|c is [abc].",
        message: "Use a character class.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[exact("S6035")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(regex) (new_expression constructor: (identifier) @c (#eq? @c "RegExp")) (call_expression function: (identifier) @c (#eq? @c "RegExp"))] @match"#,
            filter: Some(Find(find_has_single_character_alternation)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const r = /a|b|c/;",
            good: "const r = /[abc]/;",
        }),
    },
    Rule {
        id: "js/regex-multiple-spaces",
        name: "Regular expressions should not contain multiple spaces",
        description: "Several spaces in a row are hard to count.",
        message: "Use a quantifier: ' {3}'.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 1,
        sonar: &[exact("S6326")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(regex) (new_expression constructor: (identifier) @c (#eq? @c "RegExp")) (call_expression function: (identifier) @c (#eq? @c "RegExp"))] @match"#,
            filter: Some(Find(find_has_multiple_spaces)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const r = /a   b/;",
            good: "const r = /a {3}b/;",
        }),
    },
    Rule {
        id: "js/regex-duplicate-class-member",
        name: "Character classes in regular expressions should not contain the same character twice",
        description: "The second one does nothing.",
        message: "Remove the duplicate.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5869")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(regex) (new_expression constructor: (identifier) @c (#eq? @c "RegExp")) (call_expression function: (identifier) @c (#eq? @c "RegExp"))] @match"#,
            filter: Some(Find(find_class_repeats_a_character)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const r = /[aba]/;",
            good: "const r = /[ab]/;",
        }),
    },
    Rule {
        id: "js/regex-grapheme-in-class",
        name: "Unicode Grapheme Clusters should be avoided inside regex character classes",
        description: "A class matches single code points, not letters with accents.",
        message: "Match the cluster outside a class.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5868")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(regex) (new_expression constructor: (identifier) @c (#eq? @c "RegExp")) (call_expression function: (identifier) @c (#eq? @c "RegExp"))] @match"#,
            filter: Some(Find(find_class_splits_a_grapheme)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const r = /[\\u00e9\\u0301]/;",
            good: "const r = /(?:e\\u0301|x)/;",
        }),
    },
    Rule {
        id: "js/regex-repeat-matches-empty",
        name: "Repeated patterns in regular expressions should not match the empty string",
        description: "(a*)* matches nothing, forever.",
        message: "Make the repeated part non-empty.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5842")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(regex) (new_expression constructor: (identifier) @c (#eq? @c "RegExp")) (call_expression function: (identifier) @c (#eq? @c "RegExp"))] @match"#,
            filter: Some(Find(find_repeats_something_empty)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const r = /(a*)*b/;",
            good: "const r = /(a+)*b/;",
        }),
    },
    Rule {
        id: "js/regex-anchor-alternation",
        name: "Alternatives in regular expressions should be grouped when used with anchors",
        description: "^a|b$ anchors only the outer alternatives.",
        message: "Group the alternatives.",
        category: Bug,
        severity: Critical,
        effort_minutes: 3,
        sonar: &[exact("S5850")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(regex) (new_expression constructor: (identifier) @c (#eq? @c "RegExp")) (call_expression function: (identifier) @c (#eq? @c "RegExp"))] @match"#,
            filter: Some(Find(find_anchors_bind_one_alternative)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const r = /^a|b$/;",
            good: "const r = /^(?:a|b)$/;",
        }),
    },
    Rule {
        id: "js/regex-reluctant-at-end",
        name: "Reluctant quantifiers in regular expressions should be followed by an expression that can't match the empty string",
        description: "A lazy quantifier at the end matches as little as possible: nothing.",
        message: "Follow it with something, or make it greedy.",
        category: Bug,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S6019")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(regex) (new_expression constructor: (identifier) @c (#eq? @c "RegExp")) (call_expression function: (identifier) @c (#eq? @c "RegExp"))] @match"#,
            filter: Some(Find(find_ends_with_reluctant)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const r = /ab.*?/;",
            good: "const r = /ab.*?c/;",
        }),
    },
    Rule {
        id: "js/regex-too-complex",
        name: "Regular expressions should not be too complicated",
        description: "A pattern nobody can read is a pattern nobody can fix.",
        message: "Split the pattern.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 20,
        sonar: &[exact("S5843")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(regex) (new_expression constructor: (identifier) @c (#eq? @c "RegExp")) (call_expression function: (identifier) @c (#eq? @c "RegExp"))] @match"#,
            filter: Some(Find(find_is_too_complex)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const r = /((a|b)+(c|d)+)+((e|f)+(g|h)+)+((i|j)+(k|l)+)+/;",
            good: "const r = /(a|b)+/;",
        }),
    },
    Rule {
        id: "js/regex-polynomial-backtracking",
        name: "Regular expressions should not cause non-linear backtracking",
        description: "Adjacent repetitions over the same characters take polynomial time on input that almost matches.",
        message: "Merge the repetitions.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 20,
        sonar: &[exact("S8786")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(regex) (new_expression constructor: (identifier) @c (#eq? @c "RegExp")) (call_expression function: (identifier) @c (#eq? @c "RegExp"))] @match"#,
            filter: Some(Find(find_backtracks_polynomially)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const r = /\\d*\\d*x/;",
            good: "const r = /\\d+x/;",
        }),
    },
    Rule {
        id: "js/regex-catastrophic-backtracking",
        name: "Regular expressions should not cause catastrophic backtracking",
        description: "Nested repetitions that can match the same text take exponential time on input that almost matches.",
        message: "Make the repeated parts unambiguous.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 30,
        sonar: &[exact("S5852")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(regex) (new_expression constructor: (identifier) @c (#eq? @c "RegExp")) (call_expression function: (identifier) @c (#eq? @c "RegExp"))] @match"#,
            filter: Some(Find(find_backtracks_exponentially)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const r = /(a+)+b/;",
            good: "const r = /(a+b)+/;",
        }),
    },
    Rule {
        id: "js/regex-empty-class",
        name: "Empty character classes should not be used",
        description: "[] never matches anything.",
        message: "Remove the class, or use [^] to match any character.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S2639")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(regex) (new_expression constructor: (identifier) @c (#eq? @c "RegExp")) (call_expression function: (identifier) @c (#eq? @c "RegExp"))] @match"#,
            filter: Some(Find(find_has_empty_class)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const r = /a[]b/;",
            good: "const r = /a[^]b/;",
        }),
    },
    Rule {
        id: "js/regex-control-characters",
        name: "Regular expressions should not contain control characters",
        description: "Control characters in a pattern are invisible and nearly always a mistake.",
        message: "Remove the control character.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6324")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(regex) (new_expression constructor: (identifier) @c (#eq? @c "RegExp")) (call_expression function: (identifier) @c (#eq? @c "RegExp"))] @match"#,
            filter: Some(Find(find_text_has_control_characters)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const r = /\\x1f/;",
            good: "const r = /\\t/;",
        }),
    },
    Rule {
        id: "js/regex-unicode-flag",
        name: "Regular expressions using Unicode character classes or property escapes should enable the unicode flag",
        description: "Without u, \\p{L} matches the letters p, {, L and }.",
        message: "Add the u flag.",
        category: Bug,
        severity: Major,
        effort_minutes: 1,
        sonar: &[exact("S5867")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(regex) (new_expression constructor: (identifier) @c (#eq? @c "RegExp")) (call_expression function: (identifier) @c (#eq? @c "RegExp"))] @match"#,
            filter: Some(Find(find_text_needs_unicode_flag)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const r = /\\p{L}/;",
            good: "const r = /\\p{L}/u;",
        }),
    },
    Rule {
        id: "js/regex-named-group-by-index",
        name: "Names of regular expressions named groups should be used",
        description: "A named group read by number defeats the name.",
        message: "Refer to the group by name.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5860")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(regex) (new_expression constructor: (identifier) @c (#eq? @c "RegExp")) (call_expression function: (identifier) @c (#eq? @c "RegExp"))] @match"#,
            filter: Some(Find(find_named_group_used_by_index)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const r = /(?<year>\\d+)-\\1/;",
            good: "const r = /(?<year>\\d+)-\\k<year>/;",
        }),
    },
    Rule {
        id: "js/regex-invalid",
        name: "Regular expressions should be syntactically valid",
        description: "An invalid pattern throws a SyntaxError when it is built.",
        message: "Fix the pattern.",
        category: Bug,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[exact("S5856")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"[(regex) (new_expression constructor: (identifier) @c (#eq? @c "RegExp")) (call_expression function: (identifier) @c (#eq? @c "RegExp"))] @match"#,
            filter: Some(Find(find_regex_is_invalid)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const r = new RegExp('(a');",
            good: "const r = new RegExp('(a)');",
        }),
    },
    Rule {
        id: "js/regex-replacement-group-missing",
        name: "Replacement strings should reference existing regular expression groups",
        description: "$3 in a replacement for a pattern with two groups stays as the text $3.",
        message: "Reference a group the pattern has.",
        category: Bug,
        severity: Major,
        effort_minutes: 3,
        sonar: &[exact("S6328")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression property: (property_identifier) @p (#any-of? @p "replace" "replaceAll"))) @match"#,
            filter: Some(Find(find_replacement_group_missing)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const s = x.replace(/(a)(b)/, '$3');",
            good: "const s = x.replace(/(a)(b)/, '$2');",
        }),
    },
    Rule {
        id: "js/regex-exec-over-match",
        name: "\"RegExp.exec()\" should be preferred over \"String.match()\"",
        description: "exec says what is done: run one regex over one string.",
        message: "Use RegExp.exec().",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 1,
        sonar: &[exact("S6594")],
        check: Check::Query {
            langs: JS_TS,
            query: r#"(call_expression function: (member_expression property: (property_identifier) @p (#eq? @p "match"))) @match"#,
            filter: Some(Keep(match_could_be_exec)),
        },
        example: Some(Example {
            lang: Lang::JavaScript,
            bad: "const s = 'abc';\nconst m = s.match(/a(b)/);",
            good: "const s = 'abc';\nconst m = /a(b)/.exec(s);",
        }),
    },
];

// ---------------------------------------------------- extraction

/// A pattern found in the source: where it is, its text and its parse.
struct Pattern<'t> {
    node: Node<'t>,
    text: String,
    regex: Result<Regex, crate::regex::ParseError>,
}

/// The value of a JavaScript string literal, escapes resolved the way the
/// engine does (an unknown escape stands for the character itself).
fn unescape_js(raw: &str) -> String {
    let chars: Vec<char> = raw.chars().collect();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] != '\\' || i + 1 >= chars.len() {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        let next = chars[i + 1];
        i += 2;
        let hex = |from: usize, n: usize| -> Option<char> {
            let digits: String = chars.get(from..from + n)?.iter().collect();
            u32::from_str_radix(&digits, 16)
                .ok()
                .and_then(char::from_u32)
        };
        match next {
            'n' => out.push('\n'),
            't' => out.push('\t'),
            'r' => out.push('\r'),
            'b' => out.push('\u{8}'),
            'f' => out.push('\u{c}'),
            'v' => out.push('\u{b}'),
            '0' => out.push('\0'),
            'x' => match hex(i, 2) {
                Some(c) => {
                    out.push(c);
                    i += 2;
                }
                None => out.push('x'),
            },
            'u' => match hex(i, 4) {
                Some(c) => {
                    out.push(c);
                    i += 4;
                }
                None => out.push('u'),
            },
            '\n' => {}
            other => out.push(other),
        }
    }
    out
}

fn string_value(node: Node, src: &[u8]) -> Option<String> {
    match node.kind() {
        "string" => Some(unescape_js(&String::from_utf8_lossy(string_content(
            node, src,
        )))),
        "template_string" => {
            let t = String::from_utf8_lossy(text(node, src)).into_owned();
            if t.contains("${") {
                return None;
            }
            Some(unescape_js(t.get(1..t.len().saturating_sub(1))?))
        }
        _ => None,
    }
}

fn flags_from(letters: &str) -> Flags {
    Flags {
        ignore_case: letters.contains('i'),
        multiline: letters.contains('m'),
        dot_all: letters.contains('s'),
        unicode: letters.contains('u') || letters.contains('v'),
        ..Flags::default()
    }
}

fn pattern_in<'t>(node: Node<'t>, src: &[u8]) -> Option<Pattern<'t>> {
    let (text_, letters) = if node.kind() == "regex" {
        let pattern = node.child_by_field_name("pattern")?;
        let flags = node
            .child_by_field_name("flags")
            .map(|f| String::from_utf8_lossy(text(f, src)).into_owned())
            .unwrap_or_default();
        (
            String::from_utf8_lossy(text(pattern, src)).into_owned(),
            flags,
        )
    } else {
        let args = named(node.child_by_field_name("arguments")?);
        let value = string_value(*args.first()?, src)?;
        let letters = match args.get(1) {
            Some(f) => string_value(*f, src)?,
            None => String::new(),
        };
        (value, letters)
    };
    let regex = parse_js(&text_, flags_from(&letters));
    Some(Pattern {
        node,
        text: text_,
        regex,
    })
}

/// Reports the pattern when `check` holds for it.
fn find_in_pattern<'t>(
    node: Node<'t>,
    src: &[u8],
    check: impl Fn(&Regex) -> bool,
) -> Option<Node<'t>> {
    let p = pattern_in(node, src)?;
    p.regex.ok().filter(|r| check(r)).map(|_| p.node)
}

/// Reports the pattern when `check` holds for its text and parse.
fn find_in_pattern_text<'t>(
    node: Node<'t>,
    src: &[u8],
    check: impl Fn(&str, &Regex) -> bool,
) -> Option<Node<'t>> {
    let p = pattern_in(node, src)?;
    p.regex.ok().filter(|r| check(&p.text, r)).map(|_| p.node)
}

fn find_regex_is_invalid<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let p = pattern_in(node, src)?;
    match p.regex {
        Err(e) if !e.message.contains("analyze") => Some(p.node),
        _ => None,
    }
}

// ---------------------------------------------------- checks

fn has_empty_class(_: &str, r: &Regex) -> bool {
    let mut found = false;
    walk_regex(&r.root, &mut |n| {
        if matches!(n, Rx::Class { negated: false, items } if items.is_empty()) {
            found = true;
        }
    });
    found
}

fn text_has_control_characters(pattern: &str, _: &Regex) -> bool {
    let chars: Vec<char> = pattern.chars().collect();
    let is_control = |c: char| (c as u32) < 0x20 && !matches!(c, '\t' | '\n' | '\r');
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' {
            let rest: String = chars[i + 1..].iter().take(8).collect();
            let hex_value = |digits: &str| u32::from_str_radix(digits, 16).ok();
            let found = if let Some(d) = rest.strip_prefix('x') {
                d.get(..2).and_then(hex_value)
            } else if let Some(d) = rest.strip_prefix("u{") {
                d.split('}').next().and_then(hex_value)
            } else if let Some(d) = rest.strip_prefix('u') {
                d.get(..4).and_then(hex_value)
            } else {
                None
            };
            if found.is_some_and(|v| v < 0x20 && !matches!(v, 9 | 10 | 13)) {
                return true;
            }
            i += 2;
        } else {
            if is_control(chars[i]) {
                return true;
            }
            i += 1;
        }
    }
    false
}

fn text_needs_unicode_flag(pattern: &str, r: &Regex) -> bool {
    !r.flags.unicode
        && ["\\p{", "\\P{", "\\u{"]
            .iter()
            .any(|needle| pattern.contains(needle))
}

fn named_group_used_by_index(_: &str, r: &Regex) -> bool {
    if r.names.is_empty() {
        return false;
    }
    let mut found = false;
    walk_regex(&r.root, &mut |n| {
        if matches!(n, Rx::BackrefIndex(_)) {
            found = true;
        }
    });
    found
}

fn find_replacement_group_missing<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let args = named(call.child_by_field_name("arguments")?);
    let [pattern, replacement] = args.as_slice() else {
        return None;
    };
    let p = pattern_in(*pattern, src)?;
    let regex = p.regex.ok()?;
    let value = string_value(*replacement, src)?;
    let chars: Vec<char> = value.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] != '$' {
            i += 1;
            continue;
        }
        match chars.get(i + 1) {
            Some('<') if !regex.names.is_empty() => {
                let name: String = chars[i + 2..].iter().take_while(|c| **c != '>').collect();
                let closed = chars.get(i + 2 + name.chars().count()) == Some(&'>');
                if closed && !regex.names.contains(&name) {
                    return Some(*replacement);
                }
            }
            Some(d) if d.is_ascii_digit() => {
                let one = d.to_digit(10).unwrap_or(0) as usize;
                let two = chars
                    .get(i + 2)
                    .and_then(|e| e.to_digit(10))
                    .map(|e| one * 10 + e as usize);
                let n = match two {
                    Some(n) if (1..=regex.groups).contains(&n) => n,
                    _ => one,
                };
                if n > regex.groups {
                    return Some(*replacement);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn match_could_be_exec(call: Node, src: &[u8]) -> bool {
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return false;
    };
    let regex = arguments
        .named_child(0)
        .filter(|a| a.kind() == "regex" && arguments.named_child_count() == 1);
    let Some(regex) = regex else {
        return false;
    };
    // Reported where the receiver is known to be a string, as SonarQube does.
    if !call
        .child_by_field_name("function")
        .and_then(|f| f.child_by_field_name("object"))
        .is_some_and(|o| is_provably_string(o, src, 0))
    {
        return false;
    }
    let global = regex
        .child_by_field_name("flags")
        .is_some_and(|f| text(f, src).contains(&b'g'));
    let in_logic = call.parent().is_some_and(|p| {
        p.kind() == "binary_expression"
            && p.child_by_field_name("operator")
                .is_some_and(|o| matches!(text(o, src), b"&&" | b"||"))
    });
    !global && !in_logic && !used_as_a_condition(call, src)
}

fn find_has_empty_group<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(node, src, checks::has_empty_group)
}

fn find_has_empty_alternative<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(node, src, checks::has_empty_alternative)
}

fn find_has_single_character_class<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(node, src, checks::has_single_character_class)
}

fn find_could_be_concise<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(node, src, checks::could_be_concise)
}

fn find_has_single_character_alternation<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(node, src, checks::has_single_character_alternation)
}

fn find_has_multiple_spaces<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(node, src, checks::has_multiple_spaces)
}

fn find_class_repeats_a_character<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(node, src, checks::class_repeats_a_character)
}

fn find_class_splits_a_grapheme<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(node, src, checks::class_splits_a_grapheme)
}

fn find_repeats_something_empty<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(node, src, checks::repeats_something_empty)
}

fn find_anchors_bind_one_alternative<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(node, src, checks::anchors_bind_one_alternative)
}

fn find_ends_with_reluctant<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(node, src, checks::ends_with_reluctant)
}

fn find_is_too_complex<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(node, src, checks::is_too_complex)
}

fn find_backtracks_polynomially<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(node, src, checks::backtracks_polynomially)
}

fn find_backtracks_exponentially<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(node, src, checks::backtracks_exponentially)
}

fn find_has_empty_class<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern_text(node, src, has_empty_class)
}

fn find_text_has_control_characters<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern_text(node, src, text_has_control_characters)
}

fn find_text_needs_unicode_flag<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern_text(node, src, text_needs_unicode_flag)
}

fn find_named_group_used_by_index<'t>(node: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern_text(node, src, named_group_used_by_index)
}
