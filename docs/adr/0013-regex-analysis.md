# ADR-0013: Analysis of regular expressions

- Status: **proposed**
- Date: 2026-10-31

## Context

[ADR-0007](0007-sonarqube-rule-parity.md) ports SonarQube's rules. Thirty-five
of the ones still open are about the regular expressions in the code, not the
code around them: about 85 rule instances across JavaScript/TypeScript,
Python and Java. They need to read a pattern as a pattern:

| Level | Examples | Rules |
|---|---|---|
| **Syntax** | an invalid pattern, an empty group, an empty alternative, a character class with one character, `\cX` outside `@-_`, an octal escape, a back reference to a group that does not exist | about 14 |
| **Language** | a repeated item that can match the empty string, an alternative that another alternative already covers, a character repeated in a class, `.*?` where a negated class is clearer, an anchor that can never match, a contradictory lookahead | about 14 |
| **Backtracking** | `(a+)+`, `\d*\d*`, `(a\|a)*`: patterns whose matching time is exponential (S5852) or polynomial (S8786) in the input | 3 |

tree-sitter sees a regex as a string or a literal token. A query can find
`new RegExp('...')` or `Pattern.compile("...")`, but it cannot tell whether
`(a|b|)` has an empty alternative. The syntactic tier of ADR-0007 stops
here, and about 40 rules per language wait behind it.

A regex rule also differs from the rules so far in that its finding is
*inside* a string: the pattern's position in the file, not a syntax node.

## Decision

A **regex layer** in sonda-core's domain, next to `semantic/`: a parser for
the three dialects, an extractor that finds patterns in each language, and
analyses over the parsed pattern. Rules gain a fourth kind of check, next to
query, structural and semantic: `Check::Regex`, a Rust function over one
parsed pattern that returns findings. The catalog, examples, false-positive
review and `sonar` references are unchanged (ADR-0007).

### Extraction: literals only

A pattern is analyzed only when its text is known without running anything:

| Language | Where patterns are found |
|---|---|
| JavaScript/TypeScript | regex literals (`/…/flags`); `new RegExp('…', 'flags')` and `RegExp('…')` with a string literal or an untagged template literal without substitutions |
| Python | the first argument of `re.compile`, `re.match`, `re.search`, `re.fullmatch`, `re.sub`, `re.subn`, `re.split`, `re.findall`, `re.finditer`, with flags read from the call when they are literal (`re.I`, `re.X`, …) |
| Java | the first argument of `Pattern.compile`, and the pattern argument of `String.matches`, `split`, `replaceAll` and `replaceFirst` |

The string's *value* is what is parsed, so an escaped string
(`"\\d+"`) and a raw string (`r"\d+"`) give the same pattern. Adjacent
literals joined with `+` are folded; anything with a variable in it is
skipped. Nothing here evaluates code.

### The parser

Written in this repository, about a thousand lines. It produces an AST with
byte spans, so a finding can point at the pattern in the file, and later at
the offending part of it.

Why not a crate: `regex-syntax` parses Rust's dialect, which has no
look-around and no back references, and its errors and flags differ from
all three dialects here. A parser per dialect on top of one AST is also what
lets a rule say "this is valid in Java and not in JavaScript".

Dialect differences it has to carry: named-group syntax (`(?<n>…)`,
`(?P<n>…)`), flags (`u`/`v`/`s`/`y` in JavaScript, `re.X` verbose mode in
Python, inline `(?i)` in Python and Java), possessive quantifiers and atomic
groups (Java only), `\p{…}` classes, character-class set operations (Java,
JavaScript `v`).

Safety, like the rest of analysis (ADR-0002):
- the parser is iterative, with an explicit stack, never recursive;
- a pattern longer than a fixed limit, nested deeper than a fixed limit, or
  with more nodes than a budget, is skipped with a warning and costs only
  its own findings;
- it runs in the sandboxed workers and is deterministic;
- it gets a fuzz target next to the existing ones.

### Phases

| Phase | Builds | Unlocks |
|---|---|---|
| **R1: syntax** | extraction, the parser, the span mapping | invalid patterns (S5856), empty groups and alternatives, single-character classes and alternations, superfluous braces, unused non-capturing groups, escapes, back references and replacement strings that name missing groups |
| **R2: language** | nullable and first-character analysis; a character-set algebra over ASCII, the common Unicode categories and the dialect's flags | repeats that match empty, redundant and overlapping alternatives, duplicate class members, anchors that cannot match, contradictory look-around, reluctant quantifiers, concise quantifiers, a complexity score |
| **R3: backtracking** | an ambiguity analysis over the pattern's automaton, with step caps | S5852 (exponential), S8786 (polynomial), S5998 (stack overflow) |

R1 is independent and ships first. R2 reuses its AST. R3 is the one with
real design risk, so it is described below.

### Backtracking (R3)

The goal is a *conservative* detector: report only the shapes that are
provably ambiguous, say which one, and stay quiet otherwise.

- **Exponential:** a quantifier whose body can match the same text in two
  ways, under an enclosing unbounded quantifier: `(a+)+`, `(a|a)*`,
  `(\w+\s?)*`, `(.*a){10}`.
- **Polynomial:** adjacent unbounded quantifiers whose character sets
  overlap with nothing forcing a boundary between them: `\d*\d*`,
  `.*foo.*bar`.

Both are decided on character sets and the pattern's structure, with a cap
on the work per pattern. A pattern that exceeds it is reported as
"too complex to analyze" by the complexity rule, not as vulnerable.

Considered and rejected: *running* the pattern on generated hostile input
and timing it. It is nondeterministic, it would execute an engine on
analyzed code's patterns inside the scanner, and a hang is the bug being
looked for.

### Locations

A finding has the pattern's span, mapped through the string's escapes to
file positions. R1 reports at the pattern; pointing at the exact group is a
later refinement that the span-carrying AST allows without redesign.

### Rules on top

Same as everywhere (ADR-0007): examples that the test suite runs, a
false-positive review on reference code, an actionable message, and the
SonarQube key recorded. The reference code for this layer is the CPython
standard library (Python's `re` is used heavily), Apache Commons Lang and
Spring PetClinic (Java), and the JavaScript and TypeScript already used for
the other batches. Patterns in the wild are the real test of a regex
analysis, so each phase also runs over a corpus of every pattern found
there and checks that the parser accepts what the language's own engine
does.

## Consequences

- **About 85 rule instances** become possible, which is most of what the
  syntactic tier of ADR-0007 has left after the query-based work.
- **A second pattern language to maintain**, with three dialects. The
  fuzz target and the corpus check are what keep it honest.
- **Unicode:** R2 needs category tables for `\p{…}`, `\w` and case folding.
  Start with ASCII and the Latin and common categories; unknown properties
  make a rule stay silent rather than guess.
- **Dynamic patterns are invisible.** `new RegExp(userInput)` is a
  different problem (ReDoS from input), and SonarQube has other rules for it;
  this layer does not claim it.
- **Per-file only**, like ADR-0008: a pattern defined in one file and used
  in another is analyzed where it is defined.

## Open questions, to settle when R1 starts

- The JavaScript `v` flag (set notation) and Java's character-class
  intersection: parse them in R1, or report "not analyzed" until R2?
- Python verbose mode (`re.X`): whitespace and comments inside the pattern
  need the flag known at extraction, which means resolving
  `re.compile(p, FLAGS)` when `FLAGS` is a module constant.
- Where to cap pattern length and node count; set from the corpus, not
  guessed.
- The complexity score for the "too complicated" rule (S5843): define our
  own measure, in the spirit of cognitive complexity, and document it.
