//! Regular-expression rules for Java (ADR-0013): the pattern is read from
//! `Pattern.compile` and the `String` methods that take a regex, parsed by
//! `crate::regex` in its Java dialect, and judged by the shared analyses
//! in `regex_checks`.

use super::java_extra::declared_type;
use super::java_security::{call_arguments, method_name, string_value, text};
use super::regex_checks as checks;
use super::*;
use crate::regex::{Flags, Regex, parse_java};

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "java/regex-invalid",
        name: "Regular expressions should be syntactically valid",
        description: "An invalid pattern raises re.error when it is compiled.",
        message: "Fix the pattern.",
        category: Bug,
        severity: Critical,
        effort_minutes: 10,
        sonar: &[exact("S5856")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "compile" "matches" "replaceAll" "replaceFirst" "split")) @match"#,
            filter: Some(Find(regex_is_invalid)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Pattern p = Pattern.compile(\"(a\"); } }",
            good: "class A { void f() { Pattern p = Pattern.compile(\"(a)\"); } }",
        }),
    },
    Rule {
        id: "java/regex-empty-group",
        name: "Regular expressions should not contain empty groups",
        description: "An empty group matches nothing and captures nothing useful.",
        message: "Remove the group or fill it.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6331")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "compile" "matches" "replaceAll" "replaceFirst" "split")) @match"#,
            filter: Some(Find(regex_has_empty_group)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Pattern p = Pattern.compile(\"a()b\"); } }",
            good: "class A { void f() { Pattern p = Pattern.compile(\"a(b)\"); } }",
        }),
    },
    Rule {
        id: "java/regex-single-character-class",
        name: "Character classes in regular expressions should not contain only one character",
        description: "[a] is just a.",
        message: "Write the character itself.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6397")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "compile" "matches" "replaceAll" "replaceFirst" "split")) @match"#,
            filter: Some(Find(regex_has_single_character_class)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Pattern p = Pattern.compile(\"[a]b\"); } }",
            good: "class A { void f() { Pattern p = Pattern.compile(\"ab\"); } }",
        }),
    },
    Rule {
        id: "java/regex-useless-group",
        name: "Non-capturing groups without quantifier should not be used",
        description: "The group groups nothing.",
        message: "Remove the group.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6395")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "compile" "matches" "replaceAll" "replaceFirst" "split")) @match"#,
            filter: Some(Find(regex_has_useless_group)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Pattern p = Pattern.compile(\"(?:ab)c\"); } }",
            good: "class A { void f() { Pattern p = Pattern.compile(\"(?:ab)+c\"); } }",
        }),
    },
    Rule {
        id: "java/regex-superfluous-braces",
        name: "Superfluous curly brace quantifiers should be avoided",
        description: "{1} repeats once.",
        message: "Remove the quantifier.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6396")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "compile" "matches" "replaceAll" "replaceFirst" "split")) @match"#,
            filter: Some(Find(regex_has_superfluous_braces)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Pattern p = Pattern.compile(\"a{1}\"); } }",
            good: "class A { void f() { Pattern p = Pattern.compile(\"a{2}\"); } }",
        }),
    },
    Rule {
        id: "java/regex-concise-syntax",
        name: "Regular expression quantifiers and character classes should be used concisely",
        description: "\\d is shorter than [0-9], and + than {1,}.",
        message: "Use the short form.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6353")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "compile" "matches" "replaceAll" "replaceFirst" "split")) @match"#,
            filter: Some(Find(regex_could_be_concise)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Pattern p = Pattern.compile(\"[0-9]{1,}\"); } }",
            good: "class A { void f() { Pattern p = Pattern.compile(\"\\\\d+\"); } }",
        }),
    },
    Rule {
        id: "java/regex-backreference-order",
        name: "Back references in regular expressions should only refer to capturing groups that are matched before",
        description: "A group cannot refer to itself, so the reference never matches.",
        message: "Refer to a group that closed earlier.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6001")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "compile" "matches" "replaceAll" "replaceFirst" "split")) @match"#,
            filter: Some(Find(regex_backreferences_its_own_group)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Pattern p = Pattern.compile(\"(a\\\\1)\"); } }",
            good: "class A { void f() { Pattern p = Pattern.compile(\"(a)\\\\1\"); } }",
        }),
    },
    Rule {
        id: "java/regex-single-character-alternation",
        name: "Single-character alternations in regular expressions should be replaced with character classes",
        description: "a|b|c is [abc].",
        message: "Use a character class.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S6035")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "compile" "matches" "replaceAll" "replaceFirst" "split")) @match"#,
            filter: Some(Find(regex_has_single_character_alternation)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Pattern p = Pattern.compile(\"a|b|c\"); } }",
            good: "class A { void f() { Pattern p = Pattern.compile(\"[abc]\"); } }",
        }),
    },
    Rule {
        id: "java/regex-multiple-spaces",
        name: "Regular expressions should not contain multiple spaces",
        description: "Several spaces in a row are easy to miscount.",
        message: "Use ' {3}'.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6326")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "compile" "matches" "replaceAll" "replaceFirst" "split")) @match"#,
            filter: Some(Find(regex_has_multiple_spaces)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Pattern p = Pattern.compile(\"a   b\"); } }",
            good: "class A { void f() { Pattern p = Pattern.compile(\"a {3}b\"); } }",
        }),
    },
    Rule {
        id: "java/regex-duplicate-class-member",
        name: "Character classes in regular expressions should not contain the same character twice",
        description: "The repeated member does nothing.",
        message: "Remove the duplicate.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S5869")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "compile" "matches" "replaceAll" "replaceFirst" "split")) @match"#,
            filter: Some(Find(regex_class_repeats_a_character)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Pattern p = Pattern.compile(\"[aa]\"); } }",
            good: "class A { void f() { Pattern p = Pattern.compile(\"[ab]\"); } }",
        }),
    },
    Rule {
        id: "java/regex-grapheme-in-class",
        name: "Unicode Grapheme Clusters should be avoided inside regex character classes",
        description: "A class matches one code point, so a cluster is split.",
        message: "Match the cluster with a group.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5868")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "compile" "matches" "replaceAll" "replaceFirst" "split")) @match"#,
            filter: Some(Find(regex_class_splits_a_grapheme)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Pattern p = Pattern.compile(\"[e\\\\u0301]\"); } }",
            good: "class A { void f() { Pattern p = Pattern.compile(\"(?:e\\\\u0301)\"); } }",
        }),
    },
    Rule {
        id: "java/regex-repeat-matches-empty",
        name: "Repeated patterns in regular expressions should not match the empty string",
        description: "The loop can spin without consuming anything.",
        message: "Make the repeated part non-empty.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5842")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "compile" "matches" "replaceAll" "replaceFirst" "split")) @match"#,
            filter: Some(Find(regex_repeats_something_empty)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Pattern p = Pattern.compile(\"(a*)*\"); } }",
            good: "class A { void f() { Pattern p = Pattern.compile(\"(a+)*\"); } }",
        }),
    },
    Rule {
        id: "java/regex-anchor-alternation",
        name: "Alternatives in regular expressions should be grouped when used with anchors",
        description: "In ^a|b|c$ the anchors bind only the first and last alternative.",
        message: "Group the alternatives.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5850")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "compile" "matches" "replaceAll" "replaceFirst" "split")) @match"#,
            filter: Some(Find(regex_anchors_bind_one_alternative)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Pattern p = Pattern.compile(\"^a|b|c$\"); } }",
            good: "class A { void f() { Pattern p = Pattern.compile(\"^(?:a|b|c)$\"); } }",
        }),
    },
    Rule {
        id: "java/regex-redundant-alternative",
        name: "Regex alternatives should not be redundant",
        description: "An alternative another one already covers never decides the match.",
        message: "Remove it.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5855")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "compile" "matches" "replaceAll" "replaceFirst" "split")) @match"#,
            filter: Some(Find(regex_has_redundant_alternative)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Pattern p = Pattern.compile(\"a|a\"); } }",
            good: "class A { void f() { Pattern p = Pattern.compile(\"a|b\"); } }",
        }),
    },
    Rule {
        id: "java/regex-possessive-always-fails",
        name: "Regex patterns following a possessive quantifier should not always fail",
        description: "A possessive quantifier takes everything it can match, leaving nothing for the next item.",
        message: "Remove the possessive quantifier or change the next item.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5994")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "compile" "matches" "replaceAll" "replaceFirst" "split")) @match"#,
            filter: Some(Find(regex_possessive_starves_next)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Pattern p = Pattern.compile(\"a*+a\"); } }",
            good: "class A { void f() { Pattern p = Pattern.compile(\"a*+b\"); } }",
        }),
    },
    Rule {
        id: "java/regex-unmatchable-boundary",
        name: "Regex boundaries should not be used in a way that can never be matched",
        description: "Text after $ or before ^ cannot match.",
        message: "Move the anchor.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5996")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "compile" "matches" "replaceAll" "replaceFirst" "split")) @match"#,
            filter: Some(Find(regex_boundary_cannot_match)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Pattern p = Pattern.compile(\"a$b\"); } }",
            good: "class A { void f() { Pattern p = Pattern.compile(\"^ab$\"); } }",
        }),
    },
    Rule {
        id: "java/regex-contradictory-lookaround",
        name: "Regex lookahead assertions should not be contradictory",
        description: "The next character is required and forbidden at once.",
        message: "Fix the assertion.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6002")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "compile" "matches" "replaceAll" "replaceFirst" "split")) @match"#,
            filter: Some(Find(regex_lookahead_contradicts_next)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Pattern p = Pattern.compile(\"(?=a)b\"); } }",
            good: "class A { void f() { Pattern p = Pattern.compile(\"(?=a)ab\"); } }",
        }),
    },
    Rule {
        id: "java/regex-reluctant-at-end",
        name: "Reluctant quantifiers in regular expressions should be followed by an expression that can't match the empty string",
        description: "At the end of a pattern a reluctant quantifier matches as little as possible.",
        message: "Follow it with something, or make it greedy.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S6019")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "compile" "matches" "replaceAll" "replaceFirst" "split")) @match"#,
            filter: Some(Find(regex_ends_with_reluctant)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Pattern p = Pattern.compile(\"ab.*?\"); } }",
            good: "class A { void f() { Pattern p = Pattern.compile(\"ab.*?c\"); } }",
        }),
    },
    Rule {
        id: "java/regex-reluctant-instead-of-class",
        name: "Character classes should be preferred over reluctant quantifiers in regular expressions",
        description: "`\".*?\"` backtracks where `\"[^\"]*\"` does not.",
        message: "Use a negated class.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5857")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "compile" "matches" "replaceAll" "replaceFirst" "split")) @match"#,
            filter: Some(Find(regex_reluctant_dot_before_literal)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Pattern p = Pattern.compile(\"\\\"(.*?)\\\"\"); } }",
            good: "class A { void f() { Pattern p = Pattern.compile(\"\\\"([^\\\"]*)\\\"\"); } }",
        }),
    },
    Rule {
        id: "java/regex-too-complex",
        name: "Regular expressions should not be too complicated",
        description: "A pattern nobody can read is a pattern nobody can fix.",
        message: "Split the pattern.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 20,
        sonar: &[exact("S5843")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "compile" "matches" "replaceAll" "replaceFirst" "split")) @match"#,
            filter: Some(Find(regex_is_too_complex)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Pattern p = Pattern.compile(\"((a|b)+(c|d)+)+((e|f)+(g|h)+)+((i|j)+(k|l)+)+\"); } }",
            good: "class A { void f() { Pattern p = Pattern.compile(\"(a|b)+\"); } }",
        }),
    },
    Rule {
        id: "java/regex-catastrophic-backtracking",
        name: "Regular expressions should not cause catastrophic backtracking",
        description: "Nested repetitions that can match the same text take exponential time on input that almost matches.",
        message: "Make the repeated parts unambiguous.",
        category: Vulnerability,
        severity: Critical,
        effort_minutes: 30,
        sonar: &[exact("S5852")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "compile" "matches" "replaceAll" "replaceFirst" "split")) @match"#,
            filter: Some(Find(regex_backtracks_exponentially)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Pattern p = Pattern.compile(\"(a+)+b\"); } }",
            good: "class A { void f() { Pattern p = Pattern.compile(\"(a+b)+\"); } }",
        }),
    },
    Rule {
        id: "java/regex-polynomial-backtracking",
        name: "Regular expressions should not cause non-linear backtracking",
        description: "Adjacent repetitions over the same characters take polynomial time on input that almost matches.",
        message: "Merge the repetitions.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 20,
        sonar: &[exact("S8786")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "compile" "matches" "replaceAll" "replaceFirst" "split")) @match"#,
            filter: Some(Find(regex_backtracks_polynomially)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Pattern p = Pattern.compile(\"\\\\d*\\\\d*x\"); } }",
            good: "class A { void f() { Pattern p = Pattern.compile(\"\\\\d+x\"); } }",
        }),
    },
    Rule {
        id: "java/regex-ascii-letters",
        name: "Unicode-aware versions of character classes should be preferred",
        description: "[a-zA-Z] misses accented letters.",
        message: "Use \\p{L}.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[exact("S5867")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "compile" "matches" "replaceAll" "replaceFirst" "split")) @match"#,
            filter: Some(Find(has_ascii_letter_class)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Pattern p = Pattern.compile(\"[a-zA-Z]+\"); } }",
            good: "class A { void f() { Pattern p = Pattern.compile(\"\\\\p{L}+\"); } }",
        }),
    },
    Rule {
        id: "java/regex-multiline-empty-lines",
        name: "Empty lines should not be tested with regex MULTILINE flag",
        description: "With MULTILINE, ^$ also matches an empty string at the end of the input, not just blank lines.",
        message: "Match the line break explicitly.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5846")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "compile" "matches" "replaceAll" "replaceFirst" "split")) @match"#,
            filter: Some(Find(multiline_matches_empty_lines)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Pattern p = Pattern.compile(\"^$\", Pattern.MULTILINE); } }",
            good: "class A { void f() { Pattern p = Pattern.compile(\"^\\\\s*$\", Pattern.MULTILINE); } }",
        }),
    },
    Rule {
        id: "java/regex-canonical-equivalence",
        name: "Regexes containing characters subject to normalization should use the CANON_EQ flag",
        description: "A precomposed letter and its decomposed form look the same and don't match otherwise.",
        message: "Add Pattern.CANON_EQ.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5854")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "compile" "matches" "replaceAll" "replaceFirst" "split")) @match"#,
            filter: Some(Find(needs_canonical_equivalence)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Pattern p = Pattern.compile(\"\\u00e9\"); } }",
            good: "class A { void f() { Pattern p = Pattern.compile(\"\\u00e9\", Pattern.CANON_EQ); } }",
        }),
    },
    Rule {
        id: "java/regex-unicode-case",
        name: "Case insensitive Unicode regular expressions should enable the UNICODE_CASE flag",
        description: "CASE_INSENSITIVE alone only folds ASCII letters.",
        message: "Add Pattern.UNICODE_CASE.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[exact("S5866")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "compile" "matches" "replaceAll" "replaceFirst" "split")) @match"#,
            filter: Some(Find(needs_unicode_case)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Pattern p = Pattern.compile(\"\\u00e9\", Pattern.CASE_INSENSITIVE); } }",
            good: "class A { void f() { Pattern p = Pattern.compile(\"\\u00e9\", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE); } }",
        }),
    },
    Rule {
        id: "java/regex-stack-overflow",
        name: "Regular expressions should not overflow the stack",
        description: "Java matches a repeated alternation recursively, so long input throws StackOverflowError.",
        message: "Rewrite it without a repeated alternation.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[exact("S5998")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "compile" "matches" "replaceAll" "replaceFirst" "split")) @match"#,
            filter: Some(Find(repeats_an_alternation)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Pattern p = Pattern.compile(\"(a|b)*\"); } }",
            good: "class A { void f() { Pattern p = Pattern.compile(\"[ab]*\"); } }",
        }),
    },
    Rule {
        id: "java/regex-control-escape",
        name: "The regex escape sequence \\cX should only be used with characters in the @-_ range",
        description: "Other characters give a control character nobody expects.",
        message: "Use a hexadecimal escape.",
        category: Bug,
        severity: Major,
        effort_minutes: 2,
        sonar: &[exact("S6070")],
        check: Check::Query {
            langs: JAVA,
            query: r#"(method_invocation name: (identifier) @n (#any-of? @n "compile" "matches" "replaceAll" "replaceFirst" "split")) @match"#,
            filter: Some(Find(control_escape_out_of_range)),
        },
        example: Some(Example {
            lang: Lang::Java,
            bad: "class A { void f() { Pattern p = Pattern.compile(\"\\\\c1\"); } }",
            good: "class A { void f() { Pattern p = Pattern.compile(\"\\\\x01\"); } }",
        }),
    },
];

// ---------------------------------------------------- extraction

fn unescape_java(raw: &str) -> String {
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
        match next {
            'b' => out.push('\u{8}'),
            't' => out.push('\t'),
            'n' => out.push('\n'),
            'f' => out.push('\u{c}'),
            'r' => out.push('\r'),
            's' => out.push(' '),
            '"' | '\'' | '\\' => out.push(next),
            'u' => {
                while chars.get(i) == Some(&'u') {
                    i += 1;
                }
                let digits: String = chars.iter().skip(i).take(4).collect();
                match u32::from_str_radix(&digits, 16)
                    .ok()
                    .and_then(char::from_u32)
                {
                    Some(c) if digits.len() == 4 => {
                        out.push(c);
                        i += 4;
                    }
                    _ => out.push_str("\\u"),
                }
            }
            '0'..='7' => {
                let mut v = next.to_digit(8).unwrap_or(0);
                let max = if next <= '3' { 2 } else { 1 };
                for _ in 0..max {
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

/// The value of a string expression whose text is fully known: a literal,
/// or literals joined with `+`.
fn java_text(node: Node, src: &[u8], depth: usize) -> Option<String> {
    if depth > 16 {
        return None;
    }
    match node.kind() {
        "string_literal" => {
            let raw = string_value(node, src)?;
            Some(unescape_java(&String::from_utf8_lossy(raw)))
        }
        "parenthesized_expression" => java_text(node.named_child(0)?, src, depth + 1),
        "binary_expression" => {
            let op = node
                .child_by_field_name("operator")
                .map_or(&b""[..], |o| text(o, src));
            if op != b"+" {
                return None;
            }
            let left = java_text(node.child_by_field_name("left")?, src, depth + 1)?;
            let right = java_text(node.child_by_field_name("right")?, src, depth + 1)?;
            Some(left + &right)
        }
        _ => None,
    }
}

/// Reads `Pattern.X | Pattern.Y` or a literal integer; None when the flags
/// can't be known or the pattern is a literal.
fn flags_of(node: Option<Node>, src: &[u8]) -> Option<Flags> {
    let mut flags = Flags::default();
    let Some(node) = node else { return Some(flags) };
    for part in String::from_utf8_lossy(text(node, src)).split('|') {
        let name = part
            .trim()
            .trim_start_matches("Pattern.")
            .trim_start_matches("java.util.regex.");
        if let Ok(bits) = name.parse::<u32>() {
            flags.ignore_case |= bits & 2 != 0;
            flags.multiline |= bits & 8 != 0;
            flags.dot_all |= bits & 32 != 0;
            flags.verbose |= bits & 4 != 0;
            flags.unicode_case |= bits & 64 != 0;
            flags.canon_eq |= bits & 128 != 0;
            flags.unicode_class |= bits & 256 != 0;
            if bits & 16 != 0 {
                return None;
            }
            continue;
        }
        match name {
            "CASE_INSENSITIVE" => flags.ignore_case = true,
            "MULTILINE" => flags.multiline = true,
            "DOTALL" => flags.dot_all = true,
            "COMMENTS" => flags.verbose = true,
            "UNICODE_CASE" => flags.unicode_case = true,
            "CANON_EQ" => flags.canon_eq = true,
            "UNICODE_CHARACTER_CLASS" => flags.unicode_class = true,
            "UNIX_LINES" => {}
            _ => return None,
        }
    }
    Some(flags)
}

fn is_regex_receiver(object: Node, src: &[u8]) -> bool {
    let t = text(object, src);
    if object.kind() == "identifier" {
        let declared = declared_type(object, t, src);
        let name = declared.map_or(&b""[..], |d| text(d, src));
        if matches!(name, b"Pattern" | b"Matcher") {
            return false;
        }
    }
    if object.kind() == "identifier" && t.first().is_some_and(u8::is_ascii_uppercase) {
        return false;
    }
    let lower = t.to_ascii_lowercase();
    !["pattern", "regex", "splitter", "matcher"]
        .iter()
        .any(|w| lower.windows(w.len()).any(|x| x == w.as_bytes()))
}

/// The pattern argument of a regex-taking call, with its parsed form.
fn pattern_of<'t>(
    call: Node<'t>,
    src: &[u8],
) -> Option<(Node<'t>, Result<Regex, crate::regex::ParseError>)> {
    let args = call_arguments(call);
    let object = call.child_by_field_name("object");
    let is_pattern_class =
        object.is_some_and(|o| matches!(text(o, src), b"Pattern" | b"java.util.regex.Pattern"));
    let flag_node = match method_name(call, src) {
        b"compile" if is_pattern_class && !args.is_empty() => args.get(1).copied(),
        b"matches" if is_pattern_class && args.len() == 2 => None,
        b"matches" if object.is_some_and(|o| is_regex_receiver(o, src)) && args.len() == 1 => None,
        b"replaceAll" | b"replaceFirst"
            if args.len() == 2 && object.is_some_and(|o| is_regex_receiver(o, src)) =>
        {
            None
        }
        b"split"
            if (1..=2).contains(&args.len())
                && object.is_some_and(|o| is_regex_receiver(o, src)) =>
        {
            None
        }
        _ => return None,
    };
    let pattern = *args.first()?;
    let value = java_text(pattern, src, 0)?;
    let flags = flags_of(flag_node, src)?;
    Some((pattern, parse_java(&value, flags)))
}

/// Reports the pattern when `check` holds for it.
fn find_in_pattern<'t>(
    call: Node<'t>,
    src: &[u8],
    check: impl Fn(&Regex) -> bool,
) -> Option<Node<'t>> {
    let (pattern, regex) = pattern_of(call, src)?;
    regex.ok().filter(|r| check(r)).map(|_| pattern)
}

fn regex_is_invalid<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let (pattern, regex) = pattern_of(call, src)?;
    match regex {
        Err(e) if !e.message.contains("analyze") => Some(pattern),
        _ => None,
    }
}

fn control_escape_out_of_range<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::control_escape_out_of_range)
}

fn has_ascii_letter_class<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::has_ascii_letter_class)
}

fn multiline_matches_empty_lines<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::multiline_matches_empty_lines)
}

fn needs_canonical_equivalence<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::needs_canonical_equivalence)
}

fn needs_unicode_case<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::needs_unicode_case)
}

fn regex_anchors_bind_one_alternative<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::anchors_bind_one_alternative)
}

fn regex_backreferences_its_own_group<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::backreferences_its_own_group)
}

fn regex_backtracks_exponentially<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::backtracks_exponentially)
}

fn regex_backtracks_polynomially<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::backtracks_polynomially)
}

fn regex_boundary_cannot_match<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::boundary_cannot_match)
}

fn regex_class_repeats_a_character<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::class_repeats_a_character)
}

fn regex_class_splits_a_grapheme<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::class_splits_a_grapheme)
}

fn regex_could_be_concise<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::could_be_concise)
}

fn regex_ends_with_reluctant<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::ends_with_reluctant)
}

fn regex_has_empty_group<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::has_empty_group)
}

fn regex_has_multiple_spaces<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::has_multiple_spaces)
}

fn regex_has_redundant_alternative<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::has_redundant_alternative)
}

fn regex_has_single_character_alternation<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::has_single_character_alternation)
}

fn regex_has_single_character_class<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::has_single_character_class)
}

fn regex_has_superfluous_braces<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::has_superfluous_braces)
}

fn regex_has_useless_group<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::has_useless_group)
}

fn regex_is_too_complex<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::is_too_complex)
}

fn regex_lookahead_contradicts_next<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::lookahead_contradicts_next)
}

fn regex_possessive_starves_next<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::possessive_starves_next)
}

fn regex_reluctant_dot_before_literal<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::reluctant_dot_before_literal)
}

fn regex_repeats_something_empty<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::repeats_something_empty)
}

fn repeats_an_alternation<'t>(call: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    find_in_pattern(call, src, checks::repeats_an_alternation)
}

#[cfg(test)]
mod tests {
    use crate::analysis::analyze;
    use crate::analysis::tests::far_deadline;
    use crate::config::Config;
    use crate::lang::Lang;
    use crate::rules::RuleSet;

    fn flagged(rule: &str, src: &str) -> Vec<usize> {
        let mut cfg = Config::default();
        cfg.rules.enabled = vec![rule.to_string()];
        let rules = RuleSet::new(&cfg.rules).unwrap();
        let file = analyze("t", Lang::Java, src, &rules, &cfg, far_deadline()).unwrap();
        file.issues
            .iter()
            .filter(|i| i.rule == rule)
            .map(|i| i.line)
            .collect()
    }

    #[test]
    fn patterns_are_found_in_each_call_form() {
        let src = "class A {\n void f(String s, Matcher m, Pattern p) {\n  Pattern.compile(\"(a\");\n  s.matches(\"(b\");\n  s.replaceAll(\"(c\", \"x\");\n  s.split(\"(d\");\n  m.replaceAll(\"(e\");\n  p.split(\"(f\");\n  Pattern.compile(\"(\" + \"g\");\n  Pattern.compile(\"(a)\");\n  Splitter.on(\"(h\");\n  Pattern.compile(x);\n }\n}";
        assert_eq!(flagged("java/regex-invalid", src), [3, 4, 5, 6, 9]);
    }

    #[test]
    fn escapes_flags_and_dialect() {
        let src = "class A {\n void f() {\n  Pattern.compile(\"\\\\d{3}\");\n  Pattern.compile(\"a{\");\n  Pattern.compile(\"(?<n>a)\\\\k<n>\");\n  Pattern.compile(\"\\u00e9\");\n  Pattern.compile(\"\\u00e9\", Pattern.CANON_EQ);\n  Pattern.compile(\"\\u00e9\", Pattern.CASE_INSENSITIVE);\n  Pattern.compile(\"(a|b)*\");\n  Pattern.compile(\"^$\", Pattern.MULTILINE);\n  Pattern.compile(\"^$\");\n }\n}";
        assert_eq!(flagged("java/regex-invalid", src), [4]);
        assert_eq!(flagged("java/regex-canonical-equivalence", src), [6, 8]);
        assert_eq!(flagged("java/regex-unicode-case", src), [8]);
        assert_eq!(flagged("java/regex-stack-overflow", src), [9]);
        assert_eq!(flagged("java/regex-multiline-empty-lines", src), [10]);
    }
}
