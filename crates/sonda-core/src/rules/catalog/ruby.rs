//! Ruby rules, batch 1 (ADR-0033): bugs and code smells that the file's own
//! text proves. SonarQube's Ruby rules aren't tracked in `docs/sonar-parity/`
//! yet, so these carry no SonarQube key; they follow RuboCop. Ruby is
//! dynamic, so a rule reports only what needs no types: an operand that is
//! the same text on both sides, a block that can't be reached, a rescue that
//! hides every error.

use super::prelude::*;
use crate::lang::RUBY;

pub(super) fn text_of<'a>(n: Node, src: &'a [u8]) -> &'a str {
    std::str::from_utf8(&src[n.byte_range()]).unwrap_or_default()
}

/// Calls `f` for `n` and every node below it, in source order.
pub(super) fn visit<'t>(n: Node<'t>, f: &mut impl FnMut(Node<'t>)) {
    f(n);
    let mut c = n.walk();
    for child in n.children(&mut c) {
        visit(child, f);
    }
}

/// A node's text without whitespace.
fn squeezed(n: Node, src: &[u8]) -> String {
    text_of(n, src)
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect()
}

/// Whether evaluating `n` can have an effect, so two copies of it aren't the
/// same value.
fn has_effect(n: Node) -> bool {
    let mut found = false;
    visit(n, &mut |c| {
        found |= matches!(
            c.kind(),
            "call" | "assignment" | "operator_assignment" | "yield" | "subshell"
        );
    });
    found
}

/// The name a call calls: `puts` in `puts(x)` and `a.puts x`.
pub(super) fn method_name<'a>(call: Node, src: &'a [u8]) -> Option<&'a str> {
    if call.kind() != "call" {
        return None;
    }
    Some(text_of(call.child_by_field_name("method")?, src))
}

/// The text of what a call is made on, `Digest::MD5` in `Digest::MD5.new`.
pub(super) fn receiver_text<'a>(call: Node, src: &'a [u8]) -> Option<&'a str> {
    Some(text_of(call.child_by_field_name("receiver")?, src))
}

/// A call's arguments, in order: keyword arguments are `pair`s.
pub(super) fn arguments(call: Node) -> Vec<Node> {
    let Some(list) = call.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut c = list.walk();
    list.named_children(&mut c)
        .filter(|a| a.kind() != "comment")
        .collect()
}

/// The kinds of node whose children are statements.
const STATEMENT_LISTS: &[&str] = &[
    "program",
    "then",
    "else",
    "body_statement",
    "block_body",
    "begin",
    "ensure",
];

/// Rules that are off unless `rules.enabled` lists them (see
/// `catalog::OFF_BY_DEFAULT`). An empty method is an idiom in Ruby: a
/// Rails action that only renders its view, a hook a subclass overrides, a
/// null object. Rails alone has over 500.
pub(super) static OFF_BY_DEFAULT: &[&str] = &["ruby/empty-method"];

pub(super) static RULES: &[Rule] = &[
    Rule {
        id: "ruby/self-assignment",
        name: "Variables should not be self-assigned",
        description: "Assigning a variable to itself does nothing: the statement is redundant, or the other \
                      side was meant to be a different value.",
        message: "Remove or correct this useless self-assignment.",
        category: Bug,
        severity: Major,
        effort_minutes: 3,
        sonar: &[],
        check: Check::Query {
            langs: RUBY,
            query: "(assignment left: (_) right: (_)) @match",
            filter: Some(Keep(is_self_assignment)),
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "def f(a)\n  x = a\n  x = x\n  x\nend\n",
            good: "def f(a)\n  x = a\n  x = a + 1\n  x\nend\n",
        }),
    },
    Rule {
        id: "ruby/identical-operands",
        name: "Identical expressions should not be used on both sides of a binary operator",
        description: "`a && a`, `a - a` and `a < a` are constants or no-ops: one side is a mistake.",
        message: "Identical expressions are used on both sides of this operator.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[],
        check: Check::Query {
            langs: RUBY,
            query: "(binary left: (_) right: (_)) @match",
            filter: Some(Keep(has_identical_operands)),
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "def f(a, b)\n  a && b || a && b\nend\n",
            good: "def f(a, b, c)\n  a && b || a && c\nend\n",
        }),
    },
    Rule {
        id: "ruby/same-condition-in-chain",
        name: "Related \"if/elsif\" statements should not have the same condition",
        description: "A branch whose condition an earlier branch of the same chain already tested can never run.",
        message: "This condition was already tested earlier in the chain.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[],
        check: Check::Query {
            langs: RUBY,
            query: "(if) @match",
            filter: Some(Find(repeated_condition)),
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "def f(a, b)\n  if a\n    1\n  elsif b\n    2\n  elsif a\n    3\n  end\nend\n",
            good: "def f(a, b, c)\n  if a\n    1\n  elsif b\n    2\n  elsif c\n    3\n  end\nend\n",
        }),
    },
    Rule {
        id: "ruby/duplicate-when",
        name: "\"case\" statements should not have the same \"when\" value twice",
        description: "A `when` with a value an earlier one already tested can never run: Ruby takes the first \
                      that matches.",
        message: "This value was already tested by an earlier `when`.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[],
        check: Check::Query {
            langs: RUBY,
            query: "(case) @match",
            filter: Some(Find(repeated_when)),
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "def f(a)\n  case a\n  when 1 then :one\n  when 2, 1 then :two\n  end\nend\n",
            good: "def f(a)\n  case a\n  when 1 then :one\n  when 2, 3 then :two\n  end\nend\n",
        }),
    },
    Rule {
        id: "ruby/unreachable-code",
        name: "Statements after a jump should not be unreachable",
        description: "Code after a `return`, `break`, `next`, `redo`, `retry` or `raise` in the same block never runs.",
        message: "Remove this unreachable code.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[],
        check: Check::Query {
            langs: RUBY,
            query: "[(program) (then) (else) (body_statement) (block_body) (begin) (ensure)] @match",
            filter: Some(Find(unreachable_statement)),
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "def f\n  return 1\n  puts 'never'\nend\n",
            good: "def f(a)\n  return 1 if a\n  puts 'maybe'\nend\n",
        }),
    },
    Rule {
        id: "ruby/empty-rescue",
        name: "\"rescue\" clauses should not be empty",
        description: "A `rescue` with nothing in it hides the error: nobody finds out what failed. Handle it, \
                      log it, or say in a comment why it can be ignored.",
        message: "Handle this exception or explain in a comment why it can be ignored.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[],
        check: Check::Query {
            langs: RUBY,
            query: "(rescue) @match",
            filter: Some(Keep(is_empty_rescue)),
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "def f\n  risky\nrescue ArgumentError\nend\n",
            good: "def f\n  risky\nrescue ArgumentError\n  # a missing value is fine here\nend\n",
        }),
    },
    Rule {
        id: "ruby/rescue-exception",
        name: "\"Exception\" should not be rescued",
        description: "`rescue Exception` also catches `SystemExit`, `Interrupt` and `NoMemoryError`, so the \
                      program can't be stopped. Rescue `StandardError`, or the errors the code can handle.",
        message: "Rescue `StandardError`, not `Exception`.",
        category: Bug,
        severity: Major,
        effort_minutes: 5,
        sonar: &[],
        check: Check::Query {
            langs: RUBY,
            query: "(exceptions) @match",
            filter: Some(Find(rescued_exception)),
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "def f\n  risky\nrescue Exception => e\n  log(e)\nend\n",
            good: "def f\n  risky\nrescue StandardError => e\n  log(e)\nend\n",
        }),
    },
    Rule {
        id: "ruby/duplicate-hash-key",
        name: "Hash literals should not have the same key twice",
        description: "The later value replaces the earlier one, so one of them is dead: a key is mistyped.",
        message: "This key is already in the hash.",
        category: Bug,
        severity: Major,
        effort_minutes: 3,
        sonar: &[],
        check: Check::Query {
            langs: RUBY,
            query: "(hash) @match",
            filter: Some(FindAll(repeated_keys)),
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "OPTIONS = { name: 1, size: 2, name: 3 }\n",
            good: "OPTIONS = { name: 1, size: 2, title: 3 }\n",
        }),
    },
    Rule {
        id: "ruby/nil-comparison",
        name: "\"nil?\" should be used to test for nil",
        description: "`x == nil` is true only for nil, but `nil?` says so and can't be fooled by a class that \
                      redefines `==`.",
        message: "Use `nil?` instead of comparing with `nil`.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[],
        check: Check::Query {
            langs: RUBY,
            query: "(binary left: (_) right: (_)) @match",
            filter: Some(Keep(compares_with_nil)),
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "def f(a)\n  a == nil\nend\n",
            good: "def f(a)\n  a.nil?\nend\n",
        }),
    },
    Rule {
        id: "ruby/empty-method",
        name: "Methods should not be empty",
        description: "An empty method is a mistake or an unfinished one. Fill it, say in a comment why it is \
                      empty, or remove it.",
        message: "Add a body, or a comment saying why this method is empty.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[],
        check: Check::Query {
            langs: RUBY,
            query: "[(method) (singleton_method)] @match",
            filter: Some(Keep(is_empty_method)),
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "class A\n  def run\n  end\nend\n",
            good: "class A\n  def run\n    # subclasses override this\n  end\nend\n",
        }),
    },
    Rule {
        id: "ruby/debugger-call",
        name: "Debugger calls should not be left in the code",
        description: "`binding.pry`, `byebug` and `debugger` stop the program and wait for a person: left in \
                      code that ships, they hang a request.",
        message: "Remove this debugger call.",
        category: CodeSmell,
        severity: Critical,
        effort_minutes: 5,
        sonar: &[],
        check: Check::Query {
            langs: RUBY,
            query: "[(identifier) (call)] @match",
            filter: Some(Keep(is_a_debugger_call)),
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "def f(a)\n  binding.pry\n  a\nend\n",
            good: "def f(a)\n  a\nend\n",
        }),
    },
    Rule {
        id: "ruby/collapsible-if",
        name: "Collapsible \"if\" statements should be merged",
        description: "An `if` whose only statement is another `if`, with no `else` on either, is one test with \
                      `&&`.",
        message: "Merge this `if` with the one inside it.",
        category: CodeSmell,
        severity: Major,
        effort_minutes: 5,
        sonar: &[],
        check: Check::Query {
            langs: RUBY,
            query: "(if) @match",
            filter: Some(Keep(is_collapsible)),
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "def f(a, b)\n  if a\n    if b\n      run\n    end\n  end\nend\n",
            good: "def f(a, b)\n  run if a && b\nend\n",
        }),
    },
    Rule {
        id: "ruby/redundant-return",
        name: "\"return\" should not be the last statement of a method",
        description: "A method returns the value of its last expression, so a `return` there says nothing.",
        message: "Remove this `return`: the last expression is returned.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 1,
        sonar: &[],
        check: Check::Query {
            langs: RUBY,
            query: "[(method) (singleton_method)] @match",
            filter: Some(Find(final_return)),
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "def f(a)\n  return a + 1\nend\n",
            good: "def f(a)\n  a + 1\nend\n",
        }),
    },
    Rule {
        id: "ruby/method-name-camelcase",
        name: "Method names should be snake_case",
        description: "Ruby names methods in snake_case (RuboCop's `Naming/MethodName`); a camelCase name is one \
                      from another language.",
        message: "Rename this method in snake_case.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 5,
        sonar: &[],
        check: Check::Query {
            langs: RUBY,
            query: "[(method name: (identifier) @match) (singleton_method name: (identifier) @match)]",
            filter: Some(Keep(is_camel_case)),
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "class A\n  def getValue\n    1\n  end\nend\n",
            good: "class A\n  def get_value\n    1\n  end\nend\n",
        }),
    },
    Rule {
        id: "ruby/class-variable",
        name: "Class variables should not be assigned",
        description: "A `@@` variable is shared with every subclass, so one of them changes it for all the \
                      others. Use a class-level instance variable, or a constant.",
        message: "Don't share state through a class variable.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 15,
        sonar: &[],
        check: Check::Query {
            langs: RUBY,
            query: "(assignment left: (class_variable) @match)",
            filter: None,
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "class A\n  @@count = 0\nend\n",
            good: "class A\n  @count = 0\nend\n",
        }),
    },
    Rule {
        id: "ruby/global-variable",
        name: "Global variables should not be assigned",
        description: "A `$` variable is shared by the whole program, so anything can change it. Pass the value, \
                      or keep it in an object.",
        message: "Don't share state through a global variable.",
        category: CodeSmell,
        severity: Minor,
        effort_minutes: 15,
        sonar: &[],
        check: Check::Query {
            langs: RUBY,
            query: "(assignment left: (global_variable) @match)",
            filter: Some(Keep(is_custom_global)),
        },
        example: Some(Example {
            lang: Lang::Ruby,
            bad: "$counter = 0\n",
            good: "$stdout = StringIO.new\n",
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
    squeezed(l, src) == squeezed(r, src) && !has_effect(l)
}

fn has_identical_operands(n: Node, src: &[u8]) -> bool {
    let (Some(l), Some(r), Some(op)) = (
        n.child_by_field_name("left"),
        n.child_by_field_name("right"),
        n.child_by_field_name("operator"),
    ) else {
        return false;
    };
    // `0.0 / 0.0` is how a test gets NaN.
    squeezed(l, src) == squeezed(r, src)
        && !has_effect(l)
        && !matches!(l.kind(), "integer" | "float")
        && matches!(
            text_of(op, src),
            "&&" | "||"
                | "and"
                | "or"
                | "=="
                | "==="
                | "!="
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

/// The first `elsif` whose condition an earlier test of the chain was.
fn repeated_condition<'t>(n: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut seen = vec![squeezed(n.child_by_field_name("condition")?, src)];
    let mut next = n.child_by_field_name("alternative");
    while let Some(clause) = next.filter(|c| c.kind() == "elsif") {
        let cond = clause.child_by_field_name("condition")?;
        let text = squeezed(cond, src);
        if seen.contains(&text) && !has_effect(cond) {
            return Some(cond);
        }
        seen.push(text);
        next = clause.child_by_field_name("alternative");
    }
    None
}

/// The first value of a `when` an earlier one already had.
fn repeated_when<'t>(n: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut seen = Vec::new();
    let mut c = n.walk();
    for clause in n.named_children(&mut c).filter(|c| c.kind() == "when") {
        let mut p = clause.walk();
        for pattern in clause.children_by_field_name("pattern", &mut p) {
            let text = squeezed(pattern, src);
            if seen.contains(&text) && !has_effect(pattern) {
                return Some(pattern);
            }
            seen.push(text);
        }
    }
    None
}

/// Whether a statement always leaves the block it's in.
fn jumps(s: Node, src: &[u8]) -> bool {
    match s.kind() {
        "return" | "break" | "next" | "redo" | "retry" => true,
        // `raise` alone, or called.
        "identifier" => matches!(text_of(s, src), "raise" | "fail" | "exit" | "abort"),
        "call" => {
            s.child_by_field_name("receiver").is_none()
                && matches!(
                    method_name(s, src),
                    Some("raise" | "fail" | "exit" | "abort")
                )
        }
        _ => false,
    }
}

/// The first statement after one that always leaves the block.
fn unreachable_statement<'t>(n: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut c = n.walk();
    let mut jumped = false;
    for s in n.named_children(&mut c) {
        // A clause of a `begin` or a method is a block of its own.
        if matches!(
            s.kind(),
            "comment" | "rescue" | "ensure" | "else" | "elsif" | "heredoc_body"
        ) {
            continue;
        }
        if jumped {
            return Some(s);
        }
        jumped = jumps(s, src);
    }
    None
}

/// Whether a comment is among a node's children: it says why it's empty.
fn has_comment(n: Node) -> bool {
    let mut c = n.walk();
    n.named_children(&mut c).any(|k| k.kind() == "comment")
}

fn is_empty_rescue(n: Node, _src: &[u8]) -> bool {
    !has_comment(n)
        && n.child_by_field_name("body")
            .is_none_or(|b| b.named_child_count() == 0)
}

/// The `Exception` a `rescue` lists.
fn rescued_exception<'t>(n: Node<'t>, src: &[u8]) -> Option<Node<'t>> {
    let mut c = n.walk();
    n.named_children(&mut c)
        .find(|e| matches!(text_of(*e, src), "Exception" | "::Exception"))
}

/// A hash key's identity: `a:`, `:a` and `"a":` are the same symbol, `"a"` a
/// string, `1` a number.
fn key_identity(key: Node, src: &[u8]) -> Option<String> {
    let text = text_of(key, src);
    match key.kind() {
        "hash_key_symbol" | "simple_symbol" => Some(format!("s:{}", text.trim_matches(':'))),
        "string" => {
            let mut interpolates = false;
            visit(key, &mut |c| interpolates |= c.kind() == "interpolation");
            (!interpolates).then(|| format!("t:{}", text.trim_matches(['"', '\''])))
        }
        "integer" => Some(format!("i:{text}")),
        _ => None,
    }
}

/// The keys of a hash literal that an earlier pair had.
fn repeated_keys<'t>(n: Node<'t>, src: &[u8]) -> Vec<Node<'t>> {
    let mut seen = Vec::new();
    let mut repeated = Vec::new();
    let mut c = n.walk();
    for pair in n.named_children(&mut c).filter(|p| p.kind() == "pair") {
        let Some(key) = pair.child_by_field_name("key") else {
            continue;
        };
        let Some(id) = key_identity(key, src) else {
            continue;
        };
        if seen.contains(&id) {
            repeated.push(key);
        }
        seen.push(id);
    }
    repeated
}

fn compares_with_nil(n: Node, src: &[u8]) -> bool {
    let (Some(l), Some(r), Some(op)) = (
        n.child_by_field_name("left"),
        n.child_by_field_name("right"),
        n.child_by_field_name("operator"),
    ) else {
        return false;
    };
    matches!(text_of(op, src), "==" | "!=") && (r.kind() == "nil" || l.kind() == "nil")
}

fn is_empty_method(n: Node, _src: &[u8]) -> bool {
    !has_comment(n)
        && n.child_by_field_name("body")
            .is_none_or(|b| b.kind() == "body_statement" && b.named_child_count() == 0)
}

fn is_a_debugger_call(n: Node, src: &[u8]) -> bool {
    match n.kind() {
        // `byebug` alone is a statement: elsewhere it's a variable's name.
        "identifier" => {
            matches!(text_of(n, src), "byebug" | "debugger")
                && n.parent()
                    .is_some_and(|p| STATEMENT_LISTS.contains(&p.kind()))
        }
        _ => {
            n.child_by_field_name("receiver")
                .is_some_and(|r| text_of(r, src) == "binding")
                && matches!(method_name(n, src), Some("pry" | "irb" | "remote_pry"))
        }
    }
}

/// An `if` with another `if` for its only statement, and no `else`.
fn is_collapsible(n: Node, _src: &[u8]) -> bool {
    if n.child_by_field_name("alternative").is_some() {
        return false;
    }
    let Some(body) = n.child_by_field_name("consequence") else {
        return false;
    };
    let mut c = body.walk();
    let statements: Vec<Node> = body
        .named_children(&mut c)
        .filter(|s| s.kind() != "comment")
        .collect();
    matches!(statements.as_slice(), [inner] if inner.kind() == "if" && inner.child_by_field_name("alternative").is_none())
}

/// The `return` that ends a method.
fn final_return<'t>(n: Node<'t>, _src: &[u8]) -> Option<Node<'t>> {
    let body = n.child_by_field_name("body")?;
    if body.kind() != "body_statement" {
        return None;
    }
    let mut c = body.walk();
    let statements: Vec<Node> = body
        .named_children(&mut c)
        .filter(|s| s.kind() != "comment")
        .collect();
    // A `rescue` or `ensure` makes the last statement not the last thing run.
    if statements
        .iter()
        .any(|s| matches!(s.kind(), "rescue" | "ensure" | "else"))
    {
        return None;
    }
    statements.last().copied().filter(|s| s.kind() == "return")
}

fn is_camel_case(n: Node, src: &[u8]) -> bool {
    let name = text_of(n, src);
    !name.contains('_')
        && name.chars().any(|c| c.is_ascii_lowercase())
        && name.chars().any(|c| c.is_ascii_uppercase())
}

/// A global that isn't one of Ruby's own.
fn is_custom_global(n: Node, src: &[u8]) -> bool {
    let name = text_of(n, src);
    !matches!(
        name,
        "$stdout"
            | "$stderr"
            | "$stdin"
            | "$PROGRAM_NAME"
            | "$DEBUG"
            | "$VERBOSE"
            | "$LOAD_PATH"
            | "$LOADED_FEATURES"
            | "$FILENAME"
    ) && name
        .chars()
        .nth(1)
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
}

#[cfg(test)]
mod tests {
    use crate::analysis::tests::flagged_ruby as flagged;

    #[test]
    fn code_after_a_jump_is_unreachable_not_after_a_guard() {
        let src = "def f(a)\n  return 1 if a\n  return 2\nend\ndef g\n  raise 'x'\n  puts 'never'\nend\ndef h\n  begin\n    return 1\n  rescue\n    2\n  end\nend\ndef i\n  raise <<~MSG\n    text\n  MSG\nend\n";
        assert_eq!(flagged("ruby/unreachable-code", src), [7]);
    }

    #[test]
    fn a_chain_or_a_case_repeats_a_condition_however_it_is_spelled() {
        let src = "def f(a, b)\n  if a\n  elsif b\n  elsif a\n  end\n  if nxt()\n  elsif nxt()\n  end\nend\n";
        assert_eq!(flagged("ruby/same-condition-in-chain", src), [4]);
        let src = "case x\nwhen 1, 2 then a\nwhen :a, 2 then b\nwhen 'a', 'b' then c\nend\n";
        assert_eq!(flagged("ruby/duplicate-when", src), [3]);
    }

    #[test]
    fn identical_operands_and_a_self_assignment_need_no_side_effect() {
        let src = "def f(a, i)\n  a = a\n  b = a.next == a.next\n  c = a[:x] == a[:x]\n  i = i + 1\n  a + a\n  d = 0.0 / 0.0\nend\n";
        assert_eq!(flagged("ruby/self-assignment", src), [2]);
        assert_eq!(flagged("ruby/identical-operands", src), [4]);
    }

    #[test]
    fn a_hash_key_is_the_same_however_it_is_written() {
        let src = "A = { a: 1, :a => 2, 'a' => 3, 'a' => 4, 1 => 5, 1 => 6 }\n";
        assert_eq!(flagged("ruby/duplicate-hash-key", src), [1, 1, 1]);
    }

    #[test]
    fn rescues_that_hide_errors() {
        let src = "def f\n  a\nrescue ArgumentError\nrescue Exception, Foo => e\n  log(e)\nrescue ::Exception\n  # fine\nend\n";
        assert_eq!(flagged("ruby/empty-rescue", src), [3]);
        assert_eq!(flagged("ruby/rescue-exception", src), [4, 6]);
    }

    #[test]
    fn comparing_with_nil() {
        let src = "a == nil\nnil != b\nc == true\nd != false\ne === nil\nf == 1\n";
        assert_eq!(flagged("ruby/nil-comparison", src), [1, 2]);
    }

    #[test]
    fn empty_methods_and_final_returns() {
        let src = "class A\n  def a\n  end\n  def b\n    # why\n  end\n  def c = 1\n  def d\n    return 1\n  end\n  def e\n    return 1\n  rescue\n    2\n  end\n  def f(x)\n    return 1 if x\n    2\n  end\nend\n";
        assert_eq!(flagged("ruby/empty-method", src), [2]);
        assert_eq!(flagged("ruby/redundant-return", src), [9]);
    }

    #[test]
    fn debugger_calls_and_collapsible_ifs() {
        let src = "def f(byebug)\n  debugger\n  binding.pry\n  binding.local_variables\n  if a\n    if b\n      c\n    end\n  end\n  if a\n    if b\n      c\n    end\n    d\n  end\n  if a\n    if b\n    else\n    end\n  end\nend\n";
        assert_eq!(flagged("ruby/debugger-call", src), [2, 3]);
        assert_eq!(flagged("ruby/collapsible-if", src), [5]);
    }

    #[test]
    fn names_and_shared_state() {
        let src = "class A\n  @@n = 1\n  $count = 2\n  $stdout = nil\n  $0 = 'x'\n  def getValue; 1; end\n  def get_value; 1; end\n  def self.setUp; 1; end\n  def Integer(x); x; end\nend\n";
        assert_eq!(flagged("ruby/class-variable", src), [2]);
        assert_eq!(flagged("ruby/global-variable", src), [3]);
        assert_eq!(flagged("ruby/method-name-camelcase", src), [6, 8]);
    }
}
