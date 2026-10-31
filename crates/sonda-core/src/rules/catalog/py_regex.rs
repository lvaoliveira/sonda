//! Regular-expression rules for Python (ADR-0013, phases R1 and R2): the
//! pattern is read from the `re` call, parsed by `crate::regex`, and each
//! rule reports the pattern's string when its analysis finds something.

use super::py_security::{call_arguments, callee_name, has_interpolation, string_value, text};
use super::regex_checks as checks;
use super::*;
use crate::regex::{Flags, Regex, parse};

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "py/regex-invalid",
        name: "Regular expressions should be syntactically valid",
        description: "An invalid pattern raises re.error when it is compiled.",
        message: "Fix the pattern.",
        category: Bug,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S5856")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @m (#eq? @o "re") (#any-of? @m "compile" "match" "search" "fullmatch" "sub" "subn" "split" "findall" "finditer"))) @match"#,
            filter: Some(Find(regex_is_invalid)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import re\np = re.compile('(a')\n",
            good: "import re\np = re.compile('(a)')\n",
        }),
    },
    Rule {
        id: "py/regex-empty-group",
        name: "Regular expressions should not contain empty groups",
        description: "An empty group matches nothing and captures nothing useful.",
        message: "Remove the group or fill it.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6331")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @m (#eq? @o "re") (#any-of? @m "compile" "match" "search" "fullmatch" "sub" "subn" "split" "findall" "finditer"))) @match"#,
            filter: Some(Find(regex_has_empty_group)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import re\np = re.compile('a()b')\n",
            good: "import re\np = re.compile('a(b)')\n",
        }),
    },
    Rule {
        id: "py/regex-empty-alternative",
        name: "Alternation in regular expressions should not contain empty alternatives",
        description: "An empty alternative matches everywhere, which is rarely meant.",
        message: "Remove the empty alternative, or make the group optional.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6323")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @m (#eq? @o "re") (#any-of? @m "compile" "match" "search" "fullmatch" "sub" "subn" "split" "findall" "finditer"))) @match"#,
            filter: Some(Find(regex_has_empty_alternative)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import re\np = re.compile('a|')\n",
            good: "import re\np = re.compile('a|b')\n",
        }),
    },
    Rule {
        id: "py/regex-single-character-class",
        name: "Character classes in regular expressions should not contain only one character",
        description: "[a] is just a.",
        message: "Write the character itself.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6397")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @m (#eq? @o "re") (#any-of? @m "compile" "match" "search" "fullmatch" "sub" "subn" "split" "findall" "finditer"))) @match"#,
            filter: Some(Find(regex_has_single_character_class)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import re\np = re.compile('[a]b')\n",
            good: "import re\np = re.compile('ab')\n",
        }),
    },
    Rule {
        id: "py/regex-useless-group",
        name: "Non-capturing groups without quantifier should not be used",
        description: "The group groups nothing.",
        message: "Remove the group.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6395")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @m (#eq? @o "re") (#any-of? @m "compile" "match" "search" "fullmatch" "sub" "subn" "split" "findall" "finditer"))) @match"#,
            filter: Some(Find(regex_has_useless_group)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import re\np = re.compile('(?:ab)c')\n",
            good: "import re\np = re.compile('(?:ab)+c')\n",
        }),
    },
    Rule {
        id: "py/regex-superfluous-braces",
        name: "Superfluous curly brace quantifiers should be avoided",
        description: "{1} repeats once.",
        message: "Remove the quantifier.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6396")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @m (#eq? @o "re") (#any-of? @m "compile" "match" "search" "fullmatch" "sub" "subn" "split" "findall" "finditer"))) @match"#,
            filter: Some(Find(regex_has_superfluous_braces)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import re\np = re.compile('a{1}')\n",
            good: "import re\np = re.compile('a{2}')\n",
        }),
    },
    Rule {
        id: "py/regex-concise-syntax",
        name: "Regular expression quantifiers and character classes should be used concisely",
        description: "\\d is shorter than [0-9], and + than {1,}.",
        message: "Use the short form.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6353")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @m (#eq? @o "re") (#any-of? @m "compile" "match" "search" "fullmatch" "sub" "subn" "split" "findall" "finditer"))) @match"#,
            filter: Some(Find(regex_could_be_concise)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import re\np = re.compile('[0-9]{1,}')\n",
            good: "import re\np = re.compile('\\\\d+')\n",
        }),
    },
    Rule {
        id: "py/regex-octal-escape",
        name: "Octal escape sequences should not be used in regular expressions",
        description: "They are easy to mistake for backreferences.",
        message: "Use a hexadecimal escape.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6537")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @m (#eq? @o "re") (#any-of? @m "compile" "match" "search" "fullmatch" "sub" "subn" "split" "findall" "finditer"))) @match"#,
            filter: Some(Find(regex_has_octal_escape)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import re\np = re.compile('\\\\012')\n",
            good: "import re\np = re.compile('\\\\x0a')\n",
        }),
    },
    Rule {
        id: "py/regex-backreference-order",
        name: "Back references in regular expressions should only refer to capturing groups that are matched before",
        description: "A group cannot refer to itself, so the reference never matches.",
        message: "Refer to a group that closed earlier.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6001")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @m (#eq? @o "re") (#any-of? @m "compile" "match" "search" "fullmatch" "sub" "subn" "split" "findall" "finditer"))) @match"#,
            filter: Some(Find(regex_backreferences_its_own_group)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import re\np = re.compile('(a\\\\1)')\n",
            good: "import re\np = re.compile('(a)\\\\1')\n",
        }),
    },
    Rule {
        id: "py/regex-replacement-groups",
        name: "Replacement strings should reference existing regular expression groups",
        description: "A missing group raises re.error at runtime.",
        message: "Reference a group the pattern defines.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6328")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @m (#eq? @o "re") (#any-of? @m "compile" "match" "search" "fullmatch" "sub" "subn" "split" "findall" "finditer"))) @match"#,
            filter: Some(Find(replacement_names_missing_group)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import re\ns = re.sub('(a)', '\\\\2', t)\n",
            good: "import re\ns = re.sub('(a)', '\\\\1', t)\n",
        }),
    },
    Rule {
        id: "py/regex-single-character-alternation",
        name: "Single-character alternations in regular expressions should be replaced with character classes",
        description: "a|b|c is [abc].",
        message: "Use a character class.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6035")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @m (#eq? @o "re") (#any-of? @m "compile" "match" "search" "fullmatch" "sub" "subn" "split" "findall" "finditer"))) @match"#,
            filter: Some(Find(regex_has_single_character_alternation)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import re\np = re.compile('a|b|c')\n",
            good: "import re\np = re.compile('[abc]')\n",
        }),
    },
    Rule {
        id: "py/regex-multiple-spaces",
        name: "Regular expressions should not contain multiple spaces",
        description: "Several spaces in a row are easy to miscount.",
        message: "Use ' {3}'.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6326")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @m (#eq? @o "re") (#any-of? @m "compile" "match" "search" "fullmatch" "sub" "subn" "split" "findall" "finditer"))) @match"#,
            filter: Some(Find(regex_has_multiple_spaces)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import re\np = re.compile('a   b')\n",
            good: "import re\np = re.compile('a {3}b')\n",
        }),
    },
    Rule {
        id: "py/regex-duplicate-class-member",
        name: "Character classes in regular expressions should not contain the same character twice",
        description: "The repeated member does nothing.",
        message: "Remove the duplicate.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5869")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @m (#eq? @o "re") (#any-of? @m "compile" "match" "search" "fullmatch" "sub" "subn" "split" "findall" "finditer"))) @match"#,
            filter: Some(Find(regex_class_repeats_a_character)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import re\np = re.compile('[aa]')\n",
            good: "import re\np = re.compile('[ab]')\n",
        }),
    },
    Rule {
        id: "py/regex-grapheme-in-class",
        name: "Unicode Grapheme Clusters should be avoided inside regex character classes",
        description: "A class matches one code point, so a cluster is split.",
        message: "Match the cluster with a group.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5868")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @m (#eq? @o "re") (#any-of? @m "compile" "match" "search" "fullmatch" "sub" "subn" "split" "findall" "finditer"))) @match"#,
            filter: Some(Find(regex_class_splits_a_grapheme)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import re\np = re.compile('[e\\u0301]')\n",
            good: "import re\np = re.compile('(?:e\\u0301)')\n",
        }),
    },
    Rule {
        id: "py/regex-repeat-matches-empty",
        name: "Repeated patterns in regular expressions should not match the empty string",
        description: "The loop can spin without consuming anything.",
        message: "Make the repeated part non-empty.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5842")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @m (#eq? @o "re") (#any-of? @m "compile" "match" "search" "fullmatch" "sub" "subn" "split" "findall" "finditer"))) @match"#,
            filter: Some(Find(regex_repeats_something_empty)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import re\np = re.compile('(a*)*')\n",
            good: "import re\np = re.compile('(a+)*')\n",
        }),
    },
    Rule {
        id: "py/regex-anchor-alternation",
        name: "Alternatives in regular expressions should be grouped when used with anchors",
        description: "In ^a|b|c$ the anchors bind only the first and last alternative.",
        message: "Group the alternatives.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5850")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @m (#eq? @o "re") (#any-of? @m "compile" "match" "search" "fullmatch" "sub" "subn" "split" "findall" "finditer"))) @match"#,
            filter: Some(Find(regex_anchors_bind_one_alternative)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import re\np = re.compile('^a|b|c$')\n",
            good: "import re\np = re.compile('^(?:a|b|c)$')\n",
        }),
    },
    Rule {
        id: "py/regex-redundant-alternative",
        name: "Regex alternatives should not be redundant",
        description: "An alternative another one already covers never decides the match.",
        message: "Remove it.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5855")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @m (#eq? @o "re") (#any-of? @m "compile" "match" "search" "fullmatch" "sub" "subn" "split" "findall" "finditer"))) @match"#,
            filter: Some(Find(regex_has_redundant_alternative)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import re\np = re.compile('a|a')\n",
            good: "import re\np = re.compile('a|b')\n",
        }),
    },
    Rule {
        id: "py/regex-possessive-always-fails",
        name: "Regex patterns following a possessive quantifier should not always fail",
        description: "A possessive quantifier takes everything it can match, leaving nothing for the next item.",
        message: "Remove the possessive quantifier or change the next item.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5994")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @m (#eq? @o "re") (#any-of? @m "compile" "match" "search" "fullmatch" "sub" "subn" "split" "findall" "finditer"))) @match"#,
            filter: Some(Find(regex_possessive_starves_next)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import re\np = re.compile('a*+a')\n",
            good: "import re\np = re.compile('a*+b')\n",
        }),
    },
    Rule {
        id: "py/regex-unmatchable-boundary",
        name: "Regex boundaries should not be used in a way that can never be matched",
        description: "Text after $ or before ^ cannot match.",
        message: "Move the anchor.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5996")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @m (#eq? @o "re") (#any-of? @m "compile" "match" "search" "fullmatch" "sub" "subn" "split" "findall" "finditer"))) @match"#,
            filter: Some(Find(regex_boundary_cannot_match)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import re\np = re.compile('a$b')\n",
            good: "import re\np = re.compile('^ab$')\n",
        }),
    },
    Rule {
        id: "py/regex-contradictory-lookaround",
        name: "Regex lookahead assertions should not be contradictory",
        description: "The next character is required and forbidden at once.",
        message: "Fix the assertion.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6002")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @m (#eq? @o "re") (#any-of? @m "compile" "match" "search" "fullmatch" "sub" "subn" "split" "findall" "finditer"))) @match"#,
            filter: Some(Find(regex_lookahead_contradicts_next)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import re\np = re.compile('(?=a)b')\n",
            good: "import re\np = re.compile('(?=a)ab')\n",
        }),
    },
    Rule {
        id: "py/regex-reluctant-at-end",
        name: "Reluctant quantifiers in regular expressions should be followed by an expression that can't match the empty string",
        description: "At the end of a pattern a reluctant quantifier matches as little as possible.",
        message: "Follow it with something, or make it greedy.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6019")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @m (#eq? @o "re") (#any-of? @m "compile" "match" "search" "fullmatch" "sub" "subn" "split" "findall" "finditer"))) @match"#,
            filter: Some(Find(regex_ends_with_reluctant)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import re\np = re.compile('ab.*?')\n",
            good: "import re\np = re.compile('ab.*?c')\n",
        }),
    },
    Rule {
        id: "py/regex-reluctant-instead-of-class",
        name: "Character classes should be preferred over reluctant quantifiers in regular expressions",
        description: "`\".*?\"` backtracks where `\"[^\"]*\"` does not.",
        message: "Use a negated class.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5857")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @m (#eq? @o "re") (#any-of? @m "compile" "match" "search" "fullmatch" "sub" "subn" "split" "findall" "finditer"))) @match"#,
            filter: Some(Find(regex_reluctant_dot_before_literal)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import re\np = re.compile('\"(.*?)\"')\n",
            good: "import re\np = re.compile('\"([^\"]*)\"')\n",
        }),
    },
    Rule {
        id: "py/regex-too-complex",
        name: "Regular expressions should not be too complicated",
        description: "A pattern nobody can read is a pattern nobody can fix.",
        message: "Split the pattern.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 20,
        sonar: &[exact("S5843")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @m (#eq? @o "re") (#any-of? @m "compile" "match" "search" "fullmatch" "sub" "subn" "split" "findall" "finditer"))) @match"#,
            filter: Some(Find(regex_is_too_complex)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import re\np = re.compile('((a|b)+(c|d)+)+((e|f)+(g|h)+)+((i|j)+(k|l)+)+')\n",
            good: "import re\np = re.compile('(a|b)+')\n",
        }),
    },
    Rule {
        id: "py/regex-catastrophic-backtracking",
        name: "Regular expressions should not cause catastrophic backtracking",
        description: "Nested repetitions that can match the same text take exponential time on input that almost matches.",
        message: "Make the repeated parts unambiguous.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 30,
        sonar: &[exact("S5852")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @m (#eq? @o "re") (#any-of? @m "compile" "match" "search" "fullmatch" "sub" "subn" "split" "findall" "finditer"))) @match"#,
            filter: Some(Find(regex_backtracks_exponentially)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import re\np = re.compile('(a+)+b')\n",
            good: "import re\np = re.compile('(a+b)+')\n",
        }),
    },
    Rule {
        id: "py/regex-polynomial-backtracking",
        name: "Regular expressions should not cause non-linear backtracking",
        description: "Adjacent repetitions over the same characters take polynomial time on input that almost matches.",
        message: "Merge the repetitions.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 20,
        sonar: &[exact("S8786")],
        check: Check::Query {
            langs: PYTHON,
            query: r#"(call function: (attribute object: (identifier) @o attribute: (identifier) @m (#eq? @o "re") (#any-of? @m "compile" "match" "search" "fullmatch" "sub" "subn" "split" "findall" "finditer"))) @match"#,
            filter: Some(Find(regex_backtracks_polynomially)),
        },
        example: Some(Example {
            lang: Lang::Python,
            bad: "import re\np = re.compile('\\\\d*\\\\d*x')\n",
            good: "import re\np = re.compile('\\\\d+x')\n",
        }),
    },
];

// ---------------------------------------------------- extraction

fn unescape_python(raw: &str) -> String {
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
        let take_hex = |i: &mut usize, n: usize| -> Option<char> {
            let digits: String = chars.get(*i..*i + n)?.iter().collect();
            let v = u32::from_str_radix(&digits, 16).ok()?;
            *i += n;
            char::from_u32(v)
        };
        match next {
            'n' => out.push('\n'),
            't' => out.push('\t'),
            'r' => out.push('\r'),
            'a' => out.push('\u{7}'),
            'b' => out.push('\u{8}'),
            'f' => out.push('\u{c}'),
            'v' => out.push('\u{b}'),
            '\\' | '\'' | '"' => out.push(next),
            '\n' => {}
            'x' => match take_hex(&mut i, 2) {
                Some(c) => out.push(c),
                None => out.push_str("\\x"),
            },
            'u' => match take_hex(&mut i, 4) {
                Some(c) => out.push(c),
                None => out.push_str("\\u"),
            },
            'U' => match take_hex(&mut i, 8) {
                Some(c) => out.push(c),
                None => out.push_str("\\U"),
            },
            '0'..='7' => {
                let mut v = next.to_digit(8).unwrap_or(0);
                for _ in 0..2 {
                    match chars.get(i).and_then(|c| c.to_digit(8)) {
                        Some(d) => {
                            v = v * 8 + d;
                            i += 1;
                        }
                        None => break,
                    }
                }
                out.push(char::from_u32(v).unwrap_or('\0'));
            }
            other => {
                out.push('\\');
                out.push(other);
            }
        }
    }
    out
}

/// The value of a string literal (or implicit concatenation of them) whose
/// text is fully known.
fn python_text(node: Node, src: &[u8]) -> Option<String> {
    match node.kind() {
        "string" => {
            if has_interpolation(node) {
                return None;
            }
            let t = text(node, src);
            let quote = t.iter().position(|&b| b == b'"' || b == b'\'')?;
            let prefix = &t[..quote];
            let raw = prefix.iter().any(|b| b.eq_ignore_ascii_case(&b'r'));
            let bytes = prefix.iter().any(|b| b.eq_ignore_ascii_case(&b'b'));
            if bytes || prefix.iter().any(|b| b.eq_ignore_ascii_case(&b'f')) {
                return None;
            }
            let body = String::from_utf8_lossy(string_value(node, src)?).into_owned();
            Some(if raw { body } else { unescape_python(&body) })
        }
        "concatenated_string" => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .filter(|c| c.kind() != "comment")
                .map(|c| python_text(c, src))
                .collect()
        }
        _ => None,
    }
}

fn flags_of(node: Option<Node>, src: &[u8]) -> Option<Flags> {
    let mut flags = Flags::default();
    let Some(node) = node else { return Some(flags) };
    for part in String::from_utf8_lossy(text(node, src)).split('|') {
        let name = part.trim().trim_start_matches("re.");
        match name {
            "I" | "IGNORECASE" => flags.ignore_case = true,
            "M" | "MULTILINE" => flags.multiline = true,
            "S" | "DOTALL" => flags.dot_all = true,
            "X" | "VERBOSE" => flags.verbose = true,
            "A" | "ASCII" => flags.ascii = true,
            "U" | "UNICODE" | "L" | "LOCALE" | "DEBUG" | "0" => {}
            _ => return None,
        }
    }
    Some(flags)
}

fn flags_position(function: &[u8]) -> usize {
    match function {
        b"compile" => 1,
        b"sub" | b"subn" => 4,
        b"split" => 3,
        _ => 2,
    }
}

/// The pattern argument of an `re` call and the parsed pattern.
fn pattern_of<'t>(call: Node<'t>, src: &[u8]) -> Option<(Node<'t>, Regex)> {
    let args = call_arguments(call);
    let pattern = args.iter().find(|a| a.kind() != "keyword_argument")?;
    let pattern_text = python_text(*pattern, src)?;
    let positional: Vec<&Node> = args
        .iter()
        .filter(|a| a.kind() != "keyword_argument")
        .collect();
    let flag_node = super::py_security::keyword_value(call, "flags", src).or_else(|| {
        positional
            .get(flags_position(callee_name(call, src)))
            .map(|n| **n)
    });
    let flags = flags_of(flag_node, src)?;
    let regex = parse(&pattern_text, flags).ok()?;
    Some((*pattern, regex))
}

/// Reports the pattern when `check` holds for it.
fn find_in_pattern<'t>(
    call: Node<'t>,
    src: &[u8],
    check: impl Fn(&Regex) -> bool,
) -> Option<Node<'t>> {
    let (pattern, regex) = pattern_of(call, src)?;
    check(&regex).then_some(pattern)
}

// ---------------------------------------------------- R1: syntax

fn regex_is_invalid<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let args = call_arguments(call);
    let pattern = args.iter().find(|a| a.kind() != "keyword_argument")?;
    let pattern_text = python_text(*pattern, src)?;
    let positional: Vec<&Node> = args
        .iter()
        .filter(|a| a.kind() != "keyword_argument")
        .collect();
    let flag_node = super::py_security::keyword_value(call, "flags", src).or_else(|| {
        positional
            .get(flags_position(callee_name(call, src)))
            .map(|n| **n)
    });
    let flags = flags_of(flag_node, src)?;
    match parse(&pattern_text, flags) {
        Err(e) if !e.message.contains("analyze") => Some(*pattern),
        _ => None,
    }
}

fn regex_has_empty_group<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::has_empty_group)
}

fn regex_has_empty_alternative<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::has_empty_alternative)
}

fn regex_has_single_character_class<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::has_single_character_class)
}

fn regex_has_useless_group<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::has_useless_group)
}

fn regex_has_superfluous_braces<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::has_superfluous_braces)
}

fn regex_could_be_concise<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::could_be_concise)
}

fn regex_has_octal_escape<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::has_octal_escape)
}

fn regex_backreferences_its_own_group<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::backreferences_its_own_group)
}

fn replacement_names_missing_group<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    if !matches!(callee_name(call, src), b"sub" | b"subn") {
        return None;
    }
    let (pattern, regex) = pattern_of(call, src)?;
    let args = call_arguments(call);
    let positional: Vec<&Node> = args
        .iter()
        .filter(|a| a.kind() != "keyword_argument")
        .collect();
    let repl = python_text(**positional.get(1)?, src)?;
    let chars: Vec<char> = repl.chars().collect();
    let mut i = 0;
    while i + 1 < chars.len() {
        if chars[i] != '\\' {
            i += 1;
            continue;
        }
        let next = chars[i + 1];
        if next.is_ascii_digit() && next != '0' {
            let mut n = next.to_digit(10).unwrap_or(0) as usize;
            if chars.get(i + 2).is_some_and(|c| c.is_ascii_digit()) {
                n = n * 10 + chars[i + 2].to_digit(10).unwrap_or(0) as usize;
            }
            if n > regex.groups {
                return Some(pattern);
            }
        } else if next == 'g' && chars.get(i + 2) == Some(&'<') {
            let end = chars[i + 3..].iter().position(|c| *c == '>')? + i + 3;
            let reference: String = chars[i + 3..end].iter().collect();
            let missing = match reference.parse::<usize>() {
                Ok(n) => n > regex.groups,
                Err(_) => !regex.names.contains(&reference),
            };
            if missing {
                return Some(pattern);
            }
        }
        i += 2;
    }
    None
}

fn regex_has_single_character_alternation<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::has_single_character_alternation)
}

fn regex_has_multiple_spaces<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::has_multiple_spaces)
}

// ---------------------------------------------------- R2: language

fn regex_class_repeats_a_character<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::class_repeats_a_character)
}

fn regex_class_splits_a_grapheme<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::class_splits_a_grapheme)
}

fn regex_repeats_something_empty<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::repeats_something_empty)
}

fn regex_anchors_bind_one_alternative<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::anchors_bind_one_alternative)
}

fn regex_has_redundant_alternative<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::has_redundant_alternative)
}

fn regex_possessive_starves_next<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::possessive_starves_next)
}

fn regex_boundary_cannot_match<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::boundary_cannot_match)
}

fn regex_lookahead_contradicts_next<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::lookahead_contradicts_next)
}

fn regex_ends_with_reluctant<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::ends_with_reluctant)
}

fn regex_reluctant_dot_before_literal<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::reluctant_dot_before_literal)
}

fn regex_is_too_complex<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::is_too_complex)
}

// ---------------------------------------------------- R3: backtracking

fn regex_backtracks_exponentially<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::backtracks_exponentially)
}

fn regex_backtracks_polynomially<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::backtracks_polynomially)
}

#[cfg(test)]
mod tests {
    use crate::analysis::analyze;
    use crate::analysis::tests::far_deadline;
    use crate::config::Config;
    use crate::lang::Lang;
    use crate::rules::RuleSet;

    fn flagged(rule: &str, src: &str) -> Vec<usize> {
        let cfg = Config::default();
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let file = analyze("t", Lang::Python, src, &rules, &cfg, far_deadline()).unwrap();
        file.issues
            .iter()
            .filter(|i| i.rule == rule)
            .map(|i| i.line)
            .collect()
    }

    #[test]
    fn patterns_are_read_through_escapes_and_flags() {
        let src = "import re\nre.compile('\\\\d+(')\nre.compile(r'\\d+(')\nre.compile('(a)' '(b')\nre.compile(f'{x}(')\nre.compile(p)\nre.compile('a b', re.X)";
        assert_eq!(flagged("py/regex-invalid", src), [2, 3, 4]);
    }

    #[test]
    fn syntax_findings() {
        let src = "import re\nre.search(r'a()b')\nre.search(r'[a]')\nre.search(r'[.]')\nre.search(r'(?:ab)c')\nre.search(r'(?:ab)+c')\nre.search(r'(?:a|b)c')\nre.search(r'(?i:a)')\nre.search(r'a{1}')\nre.search(r'a{1,}')\nre.search(r'a|b')\nre.search(r'ab|cd')\nre.search(r'a  b')";
        assert_eq!(flagged("py/regex-empty-group", src), [2]);
        assert_eq!(flagged("py/regex-single-character-class", src), [3]);
        assert_eq!(flagged("py/regex-useless-group", src), [5]);
        assert_eq!(flagged("py/regex-superfluous-braces", src), [9]);
        assert_eq!(flagged("py/regex-concise-syntax", src), [10]);
        assert_eq!(
            flagged("py/regex-single-character-alternation", src),
            [7, 11]
        );
        assert_eq!(flagged("py/regex-multiple-spaces", src), [13]);
    }

    #[test]
    fn replacement_groups() {
        let src = "import re\nre.sub(r'(a)', r'\\1', s)\nre.sub(r'(a)', r'\\2', s)\nre.sub(r'(?P<n>a)', r'\\g<n>', s)\nre.sub(r'(?P<n>a)', r'\\g<m>', s)\nre.sub(r'a', r'\\1', s)";
        assert_eq!(flagged("py/regex-replacement-groups", src), [3, 5, 6]);
    }

    #[test]
    fn language_findings() {
        let src = "import re\nre.search(r'[aa]')\nre.search(r'[a-cb]')\nre.search(r'[abc]')\nre.search(r'(a*)*')\nre.search(r'(a+)*')\nre.search(r'^a|b$')\nre.search(r'^(?:a|b)$')\nre.search(r'a|a')\nre.search(r'a*+a')\nre.search(r'a$b')\nre.search(r'^a$')\nre.search(r'(?=a)b')\nre.search(r'(?!a)a')\nre.search(r'ab.*?')\nre.search(r'\"(.*?)\"')";
        assert_eq!(flagged("py/regex-duplicate-class-member", src), [2, 3]);
        assert_eq!(flagged("py/regex-repeat-matches-empty", src), [5]);
        assert_eq!(flagged("py/regex-anchor-alternation", src), [7]);
        assert_eq!(flagged("py/regex-redundant-alternative", src), [9]);
        assert_eq!(flagged("py/regex-possessive-always-fails", src), [10]);
        assert_eq!(flagged("py/regex-unmatchable-boundary", src), [11]);
        assert_eq!(flagged("py/regex-contradictory-lookaround", src), [13, 14]);
        assert_eq!(flagged("py/regex-reluctant-at-end", src), [15]);
        assert_eq!(flagged("py/regex-reluctant-instead-of-class", src), [16]);
    }

    #[test]
    fn backtracking() {
        let src = "import re\nre.search(r'(a+)+b')\nre.search(r'(a+b)+')\nre.search(r'(a|a)*')\nre.search(r'(\\w+\\s?)*')\nre.search(r'(a|b)*')\nre.search(r'\\d*\\d*x')\nre.search(r'\\d*,\\d*')\nre.search(r'.*.*')";
        assert_eq!(
            flagged("py/regex-catastrophic-backtracking", src),
            [2, 4, 5]
        );
        assert_eq!(flagged("py/regex-polynomial-backtracking", src), [7, 9]);
    }
}
