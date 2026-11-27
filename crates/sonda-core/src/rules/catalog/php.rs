//! PHP rules, batch 1 (ADR-0032): bugs and code smells that the file's own
//! text proves. SonarQube's PHP rules aren't tracked in `docs/sonar-parity/`
//! yet, so these carry no SonarQube key; they follow PHPStan, Psalm and the
//! PSR standards. PHP is dynamic, so a rule reports only what needs no
//! types: an operand that is the same text on both sides, a function the
//! language removed, a block that can't be reached.

use super::prelude::*;
pub(super) use super::{squeezed, text_of, visit};
use crate::lang::PHP;

/// Whether evaluating `n` can have an effect, so two copies of it aren't the
/// same value.
fn has_effect(n: Node, src: &[u8]) -> bool {
    let mut found = false;
    visit(n, &mut |c| {
        found |= matches!(
            c.kind(),
            "function_call_expression"
                | "member_call_expression"
                | "scoped_call_expression"
                | "object_creation_expression"
                | "update_expression"
                | "assignment_expression"
                | "augmented_assignment_expression"
        );
    });
    let _ = src;
    found
}

/// The name a call calls, lowercased (PHP's function names ignore case) and
/// without a leading namespace: `\MD5($x)` is `md5`.
pub(super) fn function_name(call: Node, src: &[u8]) -> Option<String> {
    if call.kind() != "function_call_expression" {
        return None;
    }
    let f = call.child_by_field_name("function")?;
    let name = match f.kind() {
        "name" => f,
        "qualified_name" => {
            let mut c = f.walk();
            f.named_children(&mut c)
                .filter(|n| n.kind() == "name")
                .last()?
        }
        _ => return None,
    };
    Some(text_of(name, src).to_ascii_lowercase())
}

/// A call's arguments, each without its `name:` label.
pub(super) fn arguments(call: Node) -> Vec<Node> {
    let Some(list) = call.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut c = list.walk();
    list.named_children(&mut c)
        .filter(|a| a.kind() == "argument")
        .filter_map(|a| a.named_child(u32::try_from(a.named_child_count().checked_sub(1)?).ok()?))
        .collect()
}

/// Rules that are off unless `rules.enabled` lists them (see
/// `catalog::OFF_BY_DEFAULT`). PSR-1's camelCase isn't every project's
/// convention: WordPress and CodeIgniter name methods in snake_case on
/// purpose, and `php/method-name-underscore` reported thousands of them.
pub(super) static OFF_BY_DEFAULT: &[&str] = &["php/method-name-underscore"];

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "php/self-assignment",
        name: "Variables should not be self-assigned",
        description: "Assigning a variable to itself does nothing: the statement is redundant, or the other \
                      side was meant to be a different value.",
        message: "Remove or correct this useless self-assignment.",
        category: Bug,
        severity: Major,
        effort_minutes: 3,
        sonar: &[],
        check: Check::Query {
            langs: PHP,
            query: "(assignment_expression left: (_) right: (_)) @match",
            filter: Some(Keep(is_self_assignment)),
        },
        example: Some(Example {
            lang: Lang::Php,
            bad: "<?php\nfunction f($a) {\n    $x = $a;\n    $x = $x;\n    return $x;\n}\n",
            good: "<?php\nfunction f($a) {\n    $x = $a;\n    $x = $a + 1;\n    return $x;\n}\n",
        }),
    },
    Rule {
        id: "php/identical-operands",
        name: "Identical expressions should not be used on both sides of a binary operator",
        description: "`$a && $a`, `$a - $a` and `$a < $a` are constants or no-ops: one side is a mistake.",
        message: "Identical expressions are used on both sides of this operator.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[],
        check: Check::Query {
            langs: PHP,
            query: "(binary_expression left: (_) right: (_)) @match",
            filter: Some(Keep(has_identical_operands)),
        },
        example: Some(Example {
            lang: Lang::Php,
            bad: "<?php\nfunction f($a, $b) {\n    return $a && $b || $a && $b;\n}\n",
            good: "<?php\nfunction f($a, $b, $c) {\n    return $a && $b || $a && $c;\n}\n",
        }),
    },
    Rule {
        id: "php/same-condition-in-chain",
        name: "Related \"if/elseif\" statements should not have the same condition",
        description: "A branch whose condition an earlier branch of the same chain already tested can never run.",
        message: "This condition was already tested earlier in the chain.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[],
        check: Check::Query {
            langs: PHP,
            query: "(if_statement condition: (_)) @match",
            filter: Some(Find(repeated_condition)),
        },
        example: Some(Example {
            lang: Lang::Php,
            bad: "<?php\nfunction f($a, $b) {\n    if ($a) {\n        return 1;\n    } elseif ($b) {\n        return 2;\n    } elseif ($a) {\n        return 3;\n    }\n    return 0;\n}\n",
            good: "<?php\nfunction f($a, $b) {\n    if ($a) {\n        return 1;\n    } elseif ($b) {\n        return 2;\n    } elseif (!$a) {\n        return 3;\n    }\n    return 0;\n}\n",
        }),
    },
    Rule {
        id: "php/duplicate-case",
        name: "Switch cases should not have the same value",
        description: "A case whose value an earlier case of the same switch has can never match.",
        message: "This case repeats an earlier one.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[],
        check: Check::Query {
            langs: PHP,
            query: "(switch_statement) @match",
            filter: Some(Find(repeated_case)),
        },
        example: Some(Example {
            lang: Lang::Php,
            bad: "<?php\nfunction f($a) {\n    switch ($a) {\n        case 1:\n            return 'one';\n        case 1:\n            return 'again';\n    }\n    return '';\n}\n",
            good: "<?php\nfunction f($a) {\n    switch ($a) {\n        case 1:\n            return 'one';\n        case 2:\n            return 'two';\n    }\n    return '';\n}\n",
        }),
    },
    Rule {
        id: "php/unreachable-code",
        name: "Statements after a jump should not be unreachable",
        description: "Code after a `return`, `throw`, `break`, `continue`, `goto` or `exit` in the same block never runs.",
        message: "Remove this unreachable code.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[],
        check: Check::Query {
            langs: PHP,
            query: "(compound_statement) @match",
            filter: Some(Find(unreachable_statement)),
        },
        example: Some(Example {
            lang: Lang::Php,
            bad: "<?php\nfunction f() {\n    return 1;\n    echo 'never';\n}\n",
            good: "<?php\nfunction f($a) {\n    if ($a) {\n        return 1;\n    }\n    echo 'sometimes';\n    return 2;\n}\n",
        }),
    },
    Rule {
        id: "php/hash-loose-comparison",
        name: "Hashes should be compared with a strict comparison",
        description: "`==` converts both sides to numbers when they look like numbers, so two different hashes \
                      that start `0e` followed by digits (\"magic hashes\") compare equal. Compare hashes with \
                      `===`, or better `hash_equals`.",
        message: "Compare this hash with `hash_equals` or `===`, not `==`.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[],
        check: Check::Query {
            langs: PHP,
            query: "(binary_expression left: (_) right: (_)) @match",
            filter: Some(Keep(loosely_compares_a_hash)),
        },
        example: Some(Example {
            lang: Lang::Php,
            bad: "<?php\nfunction ok($pw, $stored) {\n    return md5($pw) == $stored;\n}\n",
            good: "<?php\nfunction ok($pw, $stored) {\n    return hash_equals($stored, md5($pw));\n}\n",
        }),
    },
    Rule {
        id: "php/empty-catch",
        name: "Exceptions should not be swallowed",
        description: "A `catch` with nothing in it hides the failure: the code goes on as if the call had worked. \
                      Handle it, log it, or say in a comment why it can be ignored.",
        message: "Handle this exception, or say why it's ignored.",
        category: Bug,
        severity: Major,
        effort_minutes: 10,
        sonar: &[],
        check: Check::Query {
            langs: PHP,
            query: "(catch_clause body: (compound_statement) @body) @match",
            filter: Some(Keep(catches_nothing)),
        },
        example: Some(Example {
            lang: Lang::Php,
            bad: "<?php\nfunction f() {\n    try {\n        g();\n    } catch (Exception $e) {\n    }\n}\n",
            good: "<?php\nfunction f() {\n    try {\n        g();\n    } catch (Exception $e) {\n        error_log($e->getMessage());\n    }\n}\n",
        }),
    },
    Rule {
        id: "php/removed-mysql-api",
        name: "The removed `mysql_*` functions should not be used",
        description: "The `mysql_` extension was deprecated in PHP 5.5 and removed in 7.0: calling it is a fatal \
                      error. Use `mysqli_` or PDO, with prepared statements.",
        message: "Replace this removed `mysql_` function with `mysqli_` or PDO.",
        category: Bug,
        severity: Major,
        effort_minutes: 30,
        sonar: &[],
        check: Check::Query {
            langs: PHP,
            query: "(function_call_expression function: (_)) @match",
            filter: Some(Keep(calls_removed_mysql)),
        },
        example: Some(Example {
            lang: Lang::Php,
            bad: "<?php\nfunction f($c) {\n    return mysql_query('SELECT 1', $c);\n}\n",
            good: "<?php\nfunction f($c) {\n    return mysqli_query($c, 'SELECT 1');\n}\n",
        }),
    },
    Rule {
        id: "php/error-suppression",
        name: "The error suppression operator should not be used",
        description: "`@` hides a warning or an error instead of handling it, and costs time even when nothing \
                      fails. Check the condition (`file_exists`) or handle the result.",
        message: "Remove the `@`, and handle the failure.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 10,
        sonar: &[],
        check: Check::Query {
            langs: PHP,
            query: "(error_suppression_expression) @match",
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Php,
            bad: "<?php\nfunction f($file) {\n    return @file_get_contents($file);\n}\n",
            good: "<?php\nfunction f($file) {\n    return is_readable($file) ? file_get_contents($file) : null;\n}\n",
        }),
    },
    Rule {
        id: "php/collapsible-if",
        name: "Collapsible \"if\" statements should be merged",
        description: "An `if` whose only statement is another `if`, with no `else` on either, reads better as \
                      one `if` with `&&`.",
        message: "Merge this `if` with the one it contains.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[],
        check: Check::Query {
            langs: PHP,
            query: "(if_statement condition: (_) body: (compound_statement)) @match",
            filter: Some(Keep(is_collapsible_if)),
        },
        example: Some(Example {
            lang: Lang::Php,
            bad: "<?php\nfunction f($a, $b) {\n    if ($a) {\n        if ($b) {\n            echo 'both';\n        }\n    }\n}\n",
            good: "<?php\nfunction f($a, $b) {\n    if ($a && $b) {\n        echo 'both';\n    }\n}\n",
        }),
    },
    Rule {
        id: "php/redundant-bool-literal",
        name: "Boolean literals should not be used in comparisons",
        description: "`$x == true` is `$x`, and `$x == false` is `!$x`. (`=== true` tests the type too, so it isn't \
                      the same.)",
        message: "Remove the comparison with a boolean literal.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[],
        check: Check::Query {
            langs: PHP,
            query: "(binary_expression left: (_) right: (_)) @match",
            filter: Some(Keep(compares_with_bool_literal)),
        },
        example: Some(Example {
            lang: Lang::Php,
            bad: "<?php\nfunction f($ok) {\n    if ($ok == true) {\n        return 1;\n    }\n    return 0;\n}\n",
            good: "<?php\nfunction f($ok) {\n    if ($ok) {\n        return 1;\n    }\n    return 0;\n}\n",
        }),
    },
    Rule {
        id: "php/empty-function",
        name: "Functions should not be empty",
        description: "A function with no statement and no comment saying why is unfinished, or no longer needed.",
        message: "Add a statement or a comment saying why this function is empty.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[],
        check: Check::Query {
            langs: PHP,
            query: "[(function_definition body: (compound_statement)) (method_declaration body: (compound_statement))] @match",
            filter: Some(Keep(is_empty_function)),
        },
        example: Some(Example {
            lang: Lang::Php,
            bad: "<?php\nfunction cleanup() {\n}\n",
            good: "<?php\nfunction cleanup() {\n    // Nothing to release yet.\n}\n",
        }),
    },
    Rule {
        id: "php/method-name-underscore",
        name: "Method names should be camelCase",
        description: "PSR-1 names methods in camelCase: `parse_line` should be `parseLine`. Magic methods \
                      (`__construct`) and PHPUnit's `test_` names are the exception.",
        message: "Rename this method in camelCase.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[],
        check: Check::Query {
            langs: PHP,
            query: "(method_declaration name: (name) @name) @match",
            filter: Some(Find(underscored_method)),
        },
        example: Some(Example {
            lang: Lang::Php,
            bad: "<?php\nclass Parser {\n    public function parse_line($s) {\n        return $s;\n    }\n}\n",
            good: "<?php\nclass Parser {\n    public function parseLine($s) {\n        return $s;\n    }\n}\n",
        }),
    },
    Rule {
        id: "php/debug-output",
        name: "Debugging output should not be left in the code",
        description: "`var_dump`, `print_r` and `debug_zval_dump` print a value for whoever reads the page; left \
                      in, they leak internals. Log it, or return it.",
        message: "Remove this debugging output.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 2,
        sonar: &[],
        check: Check::Query {
            langs: PHP,
            query: "(function_call_expression function: (_)) @match",
            filter: Some(Keep(prints_for_debugging)),
        },
        example: Some(Example {
            lang: Lang::Php,
            bad: "<?php\nfunction f($x) {\n    var_dump($x);\n    return $x;\n}\n",
            good: "<?php\nfunction f($x) {\n    error_log(print_r($x, true));\n    return $x;\n}\n",
        }),
    },
];

// ---------------------------------------------------------------- filters

fn is_self_assignment(n: Node, src: &[u8]) -> bool {
    let (Some(l), Some(r)) = (
        n.child_by_field_name("left"),
        n.child_by_field_name("right"),
    ) else {
        return false;
    };
    squeezed(l, src) == squeezed(r, src) && !has_effect(l, src)
}

fn has_identical_operands(n: Node, src: &[u8]) -> bool {
    let (Some(l), Some(r), Some(op)) = (
        n.child_by_field_name("left"),
        n.child_by_field_name("right"),
        n.child_by_field_name("operator"),
    ) else {
        return false;
    };
    squeezed(l, src) == squeezed(r, src)
        && !has_effect(l, src)
        && matches!(
            text_of(op, src).to_ascii_lowercase().as_str(),
            "&&" | "||"
                | "and"
                | "or"
                | "xor"
                | "=="
                | "==="
                | "!="
                | "!=="
                | "<>"
                | "<"
                | ">"
                | "<="
                | ">="
                | "<=>"
                | "-"
                | "/"
                | "%"
                | "^"
        )
}

/// The conditions of an `if` and of every `elseif` after it, however it's
/// written (`elseif`, `else if`).
fn chain_conditions<'t>(head: Node<'t>, out: &mut Vec<Node<'t>>) {
    out.extend(head.child_by_field_name("condition"));
    let mut c = head.walk();
    for alt in head.children_by_field_name("alternative", &mut c) {
        match alt.kind() {
            "else_if_clause" => out.extend(alt.child_by_field_name("condition")),
            "else_clause" => {
                if let Some(next) = alt
                    .child_by_field_name("body")
                    .filter(|b| b.kind() == "if_statement")
                {
                    chain_conditions(next, out);
                }
            }
            _ => {}
        }
    }
}

/// The condition of a later branch that repeats an earlier one.
fn repeated_condition<'t>(n: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    // Only the head of a chain: the rest are reached from it.
    if n.parent().is_some_and(|p| p.kind() == "else_clause") {
        return None;
    }
    let mut conditions = Vec::new();
    chain_conditions(n, &mut conditions);
    let mut seen: Vec<String> = Vec::new();
    for cond in conditions {
        if has_effect(cond, src) {
            return None;
        }
        let key = squeezed(cond, src);
        if seen.contains(&key) {
            return Some(cond);
        }
        seen.push(key);
    }
    None
}

/// The case value that repeats an earlier one in the same switch.
fn repeated_case<'t>(n: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let block = n.child_by_field_name("body")?;
    let mut seen: Vec<String> = Vec::new();
    let mut c = block.walk();
    for case in block
        .named_children(&mut c)
        .filter(|k| k.kind() == "case_statement")
    {
        let value = case.child_by_field_name("value")?;
        if has_effect(value, src) {
            continue;
        }
        let key = squeezed(value, src);
        if seen.contains(&key) {
            return Some(value);
        }
        seen.push(key);
    }
    None
}

/// Whether a statement always leaves its block.
fn jumps(s: Node) -> bool {
    match s.kind() {
        "return_statement" | "break_statement" | "continue_statement" | "exit_statement"
        | "goto_statement" => true,
        "expression_statement" => s
            .named_child(0)
            .is_some_and(|e| e.kind() == "throw_expression"),
        _ => false,
    }
}

/// The first statement after one that always leaves the block.
fn unreachable_statement<'t>(n: Node<'t>, _src: &[u8]) -> Option<Node<'t>> {
    let mut c = n.walk();
    let mut jumped = false;
    for s in n.named_children(&mut c) {
        if s.kind() == "comment" {
            continue;
        }
        if jumped {
            // A label can be the target of a `goto`; declarations are hoisted.
            if matches!(
                s.kind(),
                "named_label_statement" | "function_definition" | "class_declaration"
            ) {
                continue;
            }
            return Some(s);
        }
        jumped = jumps(s);
    }
    None
}

fn loosely_compares_a_hash(n: Node, src: &[u8]) -> bool {
    let (Some(l), Some(r), Some(op)) = (
        n.child_by_field_name("left"),
        n.child_by_field_name("right"),
        n.child_by_field_name("operator"),
    ) else {
        return false;
    };
    let hash = |x: Node| {
        function_name(x, src).is_some_and(|f| {
            matches!(
                f.as_str(),
                "md5"
                    | "sha1"
                    | "crc32"
                    | "md5_file"
                    | "sha1_file"
                    | "hash"
                    | "hash_hmac"
                    | "crypt"
            )
        })
    };
    matches!(text_of(op, src), "==" | "!=" | "<>") && (hash(l) || hash(r))
}

fn catches_nothing(n: Node, _src: &[u8]) -> bool {
    n.child_by_field_name("body")
        .is_some_and(|b| b.named_child_count() == 0)
}

fn calls_removed_mysql(call: Node, src: &[u8]) -> bool {
    function_name(call, src).is_some_and(|f| f.starts_with("mysql_"))
}

fn compares_with_bool_literal(n: Node, src: &[u8]) -> bool {
    let (Some(l), Some(r), Some(op)) = (
        n.child_by_field_name("left"),
        n.child_by_field_name("right"),
        n.child_by_field_name("operator"),
    ) else {
        return false;
    };
    // `=== true` is a different test from `if ($x)`: it's false for `1` and
    // `'a'`. Only a loose comparison with a boolean is the same as no
    // comparison.
    matches!(text_of(op, src), "==" | "!=" | "<>")
        && (l.kind() == "boolean" || r.kind() == "boolean")
}

fn is_collapsible_if(n: Node, _src: &[u8]) -> bool {
    let plain = |i: Node| i.child_by_field_name("alternative").is_none();
    if !plain(n) {
        return false;
    }
    let Some(body) = n.child_by_field_name("body") else {
        return false;
    };
    let mut c = body.walk();
    let statements: Vec<Node> = body.named_children(&mut c).collect();
    matches!(
        statements.as_slice(),
        [only] if only.kind() == "if_statement"
            && plain(*only)
            && only.child_by_field_name("body").is_some_and(|b| b.kind() == "compound_statement")
    )
}

fn is_empty_function(n: Node, src: &[u8]) -> bool {
    // An empty constructor is how a class declares promoted properties.
    let name = n
        .child_by_field_name("name")
        .map_or("", |x| text_of(x, src));
    name != "__construct"
        && n.child_by_field_name("body")
            .is_some_and(|b| b.named_child_count() == 0)
}

fn underscored_method<'t>(n: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let name = n.child_by_field_name("name")?;
    let t = text_of(name, src);
    (t.trim_start_matches('_').contains('_') && !t.starts_with("__") && !t.starts_with("test"))
        .then_some(name)
}

fn prints_for_debugging(call: Node, src: &[u8]) -> bool {
    let Some(name) = function_name(call, src) else {
        return false;
    };
    match name.as_str() {
        "var_dump" | "debug_zval_dump" | "debug_print_backtrace" => true,
        // `print_r($x, true)` returns the text instead.
        "print_r" | "var_export" => arguments(call)
            .get(1)
            .is_none_or(|a| text_of(*a, src) != "true"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::tests::flagged_php as flagged;

    #[test]
    fn code_after_a_jump_is_unreachable_not_after_a_branch() {
        let src = "function f($a) {\n    if ($a) {\n        return 1;\n    }\n    return 2;\n}\nfunction g() {\n    throw new Exception('x');\n    echo 'never';\n}\nfunction h() {\n    exit;\n    echo 'never';\n}\n";
        assert_eq!(flagged("php/unreachable-code", src), [9, 13]);
    }

    #[test]
    fn a_chain_repeats_a_condition_however_it_is_spelled() {
        let src = "function f($a, $b) {\n    if ($a) {\n    } elseif ($b) {\n    } else if ($a) {\n    }\n}\nfunction g($next) {\n    if ($next()) {\n    } elseif ($next()) {\n    }\n}\n";
        assert_eq!(flagged("php/same-condition-in-chain", src), [4]);
    }

    #[test]
    fn identical_operands_and_a_self_assignment_need_no_side_effect() {
        let src = "function f($a, $i) {\n    $a = $a;\n    $b = next($a) == next($a);\n    $c = $a['x'] == $a['x'];\n    $i = $i + 1;\n    return $a . $a;\n}\n";
        assert_eq!(flagged("php/self-assignment", src), [2]);
        assert_eq!(flagged("php/identical-operands", src), [4]);
    }

    #[test]
    fn a_hash_is_compared_strictly_or_not_at_all() {
        let src = "function f($pw, $h) {\n    $a = md5($pw) == $h;\n    $b = md5($pw) === $h;\n    $c = $h != sha1($pw);\n    $d = strlen($pw) == 3;\n}\n";
        assert_eq!(flagged("php/hash-loose-comparison", src), [2, 4]);
    }

    #[test]
    fn only_a_loose_comparison_with_a_boolean_is_redundant() {
        let src = "function f($ok) {\n    $a = $ok == true;\n    $b = $ok != false;\n    $c = $ok === true;\n    $d = $ok !== false;\n}\n";
        assert_eq!(flagged("php/redundant-bool-literal", src), [2, 3]);
    }

    #[test]
    fn debug_output_and_the_empty_cases() {
        let src = "function f($x) {\n    var_dump($x);\n    print_r($x);\n    $s = print_r($x, true);\n    try {\n        g();\n    } catch (Exception $e) {\n        // ignored\n    }\n}\nclass A {\n    public function __construct(private $x) {}\n    public function run() {}\n    public function parse_line() { return 1; }\n    public function test_it() { return 1; }\n}\n";
        assert_eq!(flagged("php/debug-output", src), [2, 3]);
        assert!(flagged("php/empty-catch", src).is_empty());
        assert_eq!(flagged("php/empty-function", src), [13]);
        assert_eq!(flagged("php/method-name-underscore", src), [14]);
    }
}
