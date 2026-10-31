//! Regular-expression rules for Python (ADR-0013, phases R1 and R2): the
//! pattern is read from the `re` call, parsed by `crate::regex`, and each
//! rule reports the pattern's string when its analysis finds something.

use super::py_security::{call_arguments, callee_name, has_interpolation, string_value, text};
use super::*;
use crate::regex::{
    Assertion, ClassItem, Flags, GroupKind, Mode, Node as Rx, Regex, Set, complexity, first_set,
    literal_text, nullable, parse, set_of, walk,
};

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

fn any_node(regex: &Regex, mut pred: impl FnMut(&Rx) -> bool) -> bool {
    let mut found = false;
    walk(&regex.root, &mut |n| {
        if !found && pred(n) {
            found = true;
        }
    });
    found
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
    find_in_pattern(call, src, |r| {
        any_node(
            r,
            |n| matches!(n, Rx::Group { inner, kind, .. } if **inner == Rx::Empty && *kind != GroupKind::Scoped),
        )
    })
}

fn regex_has_empty_alternative<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, |r| {
        any_node(
            r,
            |n| matches!(n, Rx::Alt(alts) if alts.contains(&Rx::Empty)),
        )
    })
}

fn regex_has_single_character_class<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, |r| {
        any_node(r, |n| {
            matches!(n, Rx::Class { negated: false, items }
                if matches!(items.as_slice(), [ClassItem::Char(c)] if !".*+?()[]{}|^$\\ -#&~".contains(*c) && !c.is_whitespace()))
        })
    })
}

fn group_is_useless(node: &Rx, in_repeat: bool) -> bool {
    match node {
        Rx::Group { kind, inner, .. } => {
            (*kind == GroupKind::NonCapture
                && !in_repeat
                && !matches!(**inner, Rx::Alt(_) | Rx::Empty))
                || group_is_useless(inner, false)
        }
        Rx::Repeat { inner, .. } => group_is_useless(inner, true),
        Rx::Look { inner, .. } => group_is_useless(inner, false),
        Rx::Conditional { yes, no } => {
            group_is_useless(yes, false) || no.as_ref().is_some_and(|n| group_is_useless(n, false))
        }
        Rx::Alt(items) => items.iter().any(|n| group_is_useless(n, false)),
        Rx::Concat(items) => items.iter().any(|n| group_is_useless(n, false)),
        _ => false,
    }
}

fn regex_has_useless_group<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, |r| {
        // A group that is the whole pattern still has no job.
        group_is_useless(&r.root, false)
    })
}

fn regex_has_superfluous_braces<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, |r| {
        any_node(r, |n| {
            matches!(
                n,
                Rx::Repeat {
                    min: 1,
                    max: Some(1),
                    braces: true,
                    ..
                }
            )
        })
    })
}

fn class_is_digits(items: &[ClassItem]) -> bool {
    matches!(items, [ClassItem::Range('0', '9')])
}

fn class_is_word(items: &[ClassItem]) -> bool {
    let (mut lower, mut upper, mut digit, mut underscore) = (false, false, false, false);
    for item in items {
        match item {
            ClassItem::Range('a', 'z') => lower = true,
            ClassItem::Range('A', 'Z') => upper = true,
            ClassItem::Range('0', '9') => digit = true,
            ClassItem::Char('_') => underscore = true,
            _ => return false,
        }
    }
    lower && upper && digit && underscore
}

fn regex_could_be_concise<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, |r| {
        any_node(r, |n| match n {
            Rx::Repeat {
                min,
                max,
                braces: true,
                ..
            } => matches!((min, max), (0, None) | (1, None) | (0, Some(1))),
            Rx::Class { items, .. } => class_is_digits(items) || class_is_word(items),
            _ => false,
        })
    })
}

fn regex_has_octal_escape<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, |r| any_node(r, |n| matches!(n, Rx::Octal(_))))
}

fn contains_backref_to(node: &Rx, index: usize, name: Option<&str>) -> bool {
    let mut found = false;
    walk(node, &mut |n| match n {
        Rx::BackrefIndex(i) if *i == index => found = true,
        Rx::BackrefName(s) if Some(s.as_str()) == name => found = true,
        _ => {}
    });
    found
}

fn regex_backreferences_its_own_group<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, |r| {
        any_node(r, |n| match n {
            Rx::Group { kind, index, inner } if *index > 0 => {
                let name = match kind {
                    GroupKind::Named(s) => Some(s.as_str()),
                    _ => None,
                };
                contains_backref_to(inner, *index, name)
            }
            _ => false,
        })
    })
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
    find_in_pattern(call, src, |r| {
        any_node(
            r,
            |n| matches!(n, Rx::Alt(alts) if alts.len() >= 2 && alts.iter().all(|a| matches!(a, Rx::Char(_)))),
        )
    })
}

fn regex_has_multiple_spaces<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, |r| {
        !r.flags.verbose
            && any_node(r, |n| match n {
                Rx::Concat(items) => items
                    .windows(2)
                    .any(|w| w[0] == Rx::Char(' ') && w[1] == Rx::Char(' ')),
                _ => false,
            })
    })
}

// ---------------------------------------------------- R2: language

fn regex_class_repeats_a_character<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, |r| {
        any_node(r, |n| {
            let Rx::Class { items, .. } = n else {
                return false;
            };
            let sets: Vec<Set> = items
                .iter()
                .filter_map(|i| {
                    set_of(
                        &Rx::Class {
                            negated: false,
                            items: vec![i.clone()],
                        },
                        &r.flags,
                    )
                })
                .collect();
            sets.iter()
                .enumerate()
                .any(|(i, a)| sets[i + 1..].iter().any(|b| a.overlaps(b)))
        })
    })
}

fn regex_class_splits_a_grapheme<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, |r| {
        any_node(r, |n| {
            let Rx::Class { items, .. } = n else {
                return false;
            };
            items.iter().any(|i| match i {
                ClassItem::Char(c) => {
                    ('\u{300}'..='\u{36f}').contains(c)
                        || matches!(*c, '\u{200d}' | '\u{fe0f}' | '\u{20e3}')
                        || ('\u{1f3fb}'..='\u{1f3ff}').contains(c)
                }
                _ => false,
            })
        })
    })
}

fn regex_repeats_something_empty<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, |r| {
        any_node(r, |n| {
            matches!(n, Rx::Repeat { inner, max, mode, .. }
                if *mode != Mode::Possessive
                    && max.is_none_or(|m| m > 1)
                    && !matches!(**inner, Rx::Assertion(_) | Rx::Look { .. })
                    && nullable(inner))
        })
    })
}

fn starts_with_anchor(node: &Rx) -> bool {
    match node {
        Rx::Assertion(Assertion::Start | Assertion::StartAbs) => true,
        Rx::Concat(items) => items.first().is_some_and(starts_with_anchor),
        _ => false,
    }
}

fn ends_with_anchor(node: &Rx) -> bool {
    match node {
        Rx::Assertion(Assertion::End | Assertion::EndAbs) => true,
        Rx::Concat(items) => items.last().is_some_and(ends_with_anchor),
        _ => false,
    }
}

fn regex_anchors_bind_one_alternative<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, |r| {
        let Rx::Alt(alts) = &r.root else { return false };
        let some_start = alts.iter().any(starts_with_anchor);
        let all_start = alts.iter().all(starts_with_anchor);
        let some_end = alts.iter().any(ends_with_anchor);
        let all_end = alts.iter().all(ends_with_anchor);
        (some_start && !all_start && starts_with_anchor(&alts[0]))
            || (some_end && !all_end && ends_with_anchor(&alts[alts.len() - 1]))
    })
}

fn regex_has_redundant_alternative<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, |r| {
        any_node(r, |n| {
            let Rx::Alt(alts) = n else { return false };
            alts.iter().enumerate().any(|(i, a)| {
                alts[..i].iter().any(|b| {
                    b == a
                        || (matches!(a, Rx::Char(_))
                            && matches!(b, Rx::Class { negated: false, .. })
                            && set_of(a, &r.flags)
                                .zip(set_of(b, &r.flags))
                                .is_some_and(|(x, y)| x.is_subset_of(&y)))
                })
            })
        })
    })
}

fn single_char_set(node: &Rx, flags: &Flags) -> Option<Set> {
    set_of(node, flags)
}

fn regex_possessive_starves_next<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, |r| {
        any_node(r, |n| {
            let Rx::Concat(items) = n else { return false };
            items.windows(2).any(|w| {
                let Rx::Repeat {
                    inner,
                    max: None,
                    mode: Mode::Possessive,
                    ..
                } = &w[0]
                else {
                    return false;
                };
                let Some(taken) = single_char_set(inner, &r.flags) else {
                    return false;
                };
                !nullable(&w[1]) && {
                    let next = first_set(&w[1], &r.flags);
                    !next.is_empty() && next.is_subset_of(&taken)
                }
            })
        })
    })
}

fn regex_boundary_cannot_match<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, |r| {
        any_node(r, |n| {
            let Rx::Concat(items) = n else { return false };
            items.windows(2).any(|w| match &w[0] {
                Rx::Assertion(Assertion::EndAbs) => !nullable(&w[1]),
                Rx::Assertion(Assertion::End) if !r.flags.multiline => {
                    !nullable(&w[1]) && !first_set(&w[1], &r.flags).contains('\n' as u32)
                }
                _ => match &w[1] {
                    Rx::Assertion(Assertion::StartAbs) => !nullable(&w[0]),
                    Rx::Assertion(Assertion::Start) if !r.flags.multiline => !nullable(&w[0]),
                    _ => false,
                },
            })
        })
    })
}

fn regex_lookahead_contradicts_next<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, |r| {
        any_node(r, |n| {
            let Rx::Concat(items) = n else { return false };
            items.windows(2).any(|w| {
                let Rx::Look {
                    ahead: true,
                    negative,
                    inner,
                } = &w[0]
                else {
                    return false;
                };
                if nullable(&w[1]) || nullable(inner) {
                    return false;
                }
                let (looked, next) = (first_set(inner, &r.flags), first_set(&w[1], &r.flags));
                if looked.is_empty() || next.is_empty() {
                    return false;
                }
                if *negative {
                    // (?!a)a: the whole lookahead is one character
                    single_char_set(inner, &r.flags).is_some_and(|l| next.is_subset_of(&l))
                } else {
                    !looked.overlaps(&next)
                }
            })
        })
    })
}

fn regex_ends_with_reluctant<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, |r| {
        let last = match &r.root {
            Rx::Concat(items) => items.last(),
            other => Some(other),
        };
        matches!(
            last,
            Some(Rx::Repeat {
                mode: Mode::Lazy,
                min: 0,
                max: None,
                ..
            })
        )
    })
}

fn regex_reluctant_dot_before_literal<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, |r| {
        let dot_lazy = |n: &Rx| matches!(n, Rx::Repeat { inner, max: None, mode: Mode::Lazy, .. } if **inner == Rx::Any);
        any_node(r, |n| match n {
            Rx::Concat(items) => items.windows(2).any(|w| {
                (dot_lazy(&w[0]) || matches!(&w[0], Rx::Group { inner, .. } if dot_lazy(inner)))
                    && matches!(w[1], Rx::Char(c) if !c.is_alphanumeric())
            }),
            _ => false,
        })
    })
}

fn regex_is_too_complex<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, |r| complexity(&r.root) > 20)
}

// ---------------------------------------------------- R3: backtracking

fn peel(node: &Rx) -> &Rx {
    match node {
        Rx::Group { inner, kind, .. } if *kind != GroupKind::Atomic => peel(inner),
        other => other,
    }
}

fn items_of(node: &Rx) -> Vec<&Rx> {
    match peel(node) {
        Rx::Concat(items) => items.iter().collect(),
        other => vec![other],
    }
}

fn is_unbounded(node: &Rx) -> bool {
    matches!(node, Rx::Repeat { max: None, mode, .. } if *mode != Mode::Possessive)
}

fn repeat_body_ambiguous(body: &Rx, flags: &Flags) -> bool {
    let body = peel(body);
    // (a|a)*, (a|ab)*: alternatives that can match a common prefix
    if let Rx::Alt(alts) = body {
        for (i, a) in alts.iter().enumerate() {
            for b in &alts[i + 1..] {
                if literal_text(a)
                    .zip(literal_text(b))
                    .is_some_and(|(x, y)| x.starts_with(&y) || y.starts_with(&x))
                {
                    return true;
                }
                if single_char_set(a, flags)
                    .zip(single_char_set(b, flags))
                    .is_some_and(|(x, y)| x.overlaps(&y))
                {
                    return true;
                }
            }
        }
        return false;
    }
    let items = items_of(body);
    let begin = first_set(body, flags);
    // an unbounded repeat at the end of the body whose characters can also
    // start the next iteration: (a+)+, (\w+\s?)*
    for (i, item) in items.iter().enumerate().rev() {
        if is_unbounded(item) {
            let Rx::Repeat { inner, .. } = item else {
                break;
            };
            let chars = first_set(inner, flags);
            if chars.overlaps(&begin) {
                return true;
            }
        }
        if !nullable(item) && i + 1 != items.len() {
            break;
        }
        if !nullable(item) {
            break;
        }
    }
    false
}

fn regex_backtracks_exponentially<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, |r| {
        any_node(r, |n| match n {
            Rx::Repeat {
                inner,
                max: None,
                mode,
                ..
            } if *mode != Mode::Possessive => repeat_body_ambiguous(inner, &r.flags),
            _ => false,
        })
    })
}

fn regex_backtracks_polynomially<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, |r| {
        any_node(r, |n| {
            let Rx::Concat(items) = n else { return false };
            (0..items.len()).any(|i| {
                let Rx::Repeat { inner: a, .. } = &items[i] else {
                    return false;
                };
                if !is_unbounded(&items[i]) {
                    return false;
                }
                let Some(sa) = single_char_set(a, &r.flags) else {
                    return false;
                };
                for later in &items[i + 1..] {
                    if let Rx::Repeat { inner: b, .. } = later
                        && is_unbounded(later)
                    {
                        return single_char_set(b, &r.flags).is_some_and(|sb| sa.overlaps(&sb));
                    }
                    if !nullable(later) {
                        return false;
                    }
                }
                false
            })
        })
    })
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
