# ADR-0007: Compatibility with SonarQube's rules

- Status: **accepted**
- Date: 2026-10-30

## Context

Teams moving from SonarQube expect the checks they know. sonda has 31
rules. SonarQube 26.7 has 2,042 non-deprecated rules for the languages sonda
supports:

| Language | Rules |
|---|---|
| JavaScript | 461 |
| TypeScript | 481 (mostly the same rules as JavaScript) |
| Python | 397 |
| Java | 703 |

C and C++ rules come with SonarQube's commercial editions. The goal is to
offer an equivalent for each of these rules, in every language sonda
supports, so a team's familiar checks carry over. Each equivalent is
identified by the same rule key, for example `S3504`.

The rules themselves (their text and implementations) are SonarSource's
work. sonda writes its own.

## Decision

### Clean-room rules

Each rule is written from the *intent* of a SonarQube rule, in sonda's own
words:
- name, description, message and examples;
- its tree-sitter query or Rust check.

No SonarSource text, code or test fixtures are copied. A rule records which
SonarQube keys it corresponds to, in a `sonar` field (`exact("S3504")` or
`related("S1523")`). Keys are references, not content. Rule ids stay
sonda's (`js/no-var`). One sonda rule may cover several SonarQube keys, and
a rule for JavaScript also covers the TypeScript key with the same number.

### The compatibility table

`docs/sonar-parity/` tracks, for each SonarQube rule key, whether sonda has
an equivalent. It's one CSV per language plus a summary, with each key's:
- type and default severity;
- whether SonarQube enables it by default;
- a guess at the analysis it needs;
- sonda's status.

`scripts/sonar_parity.py` refreshes the table from a SonarQube server the
maintainer has access to, using the server's standard rules API. The table
holds rule keys and these few facts only. It is refreshed with every batch,
so progress is measured, not estimated.

### What a rule needs to merge

1. **Examples:** a noncompliant and a compliant example, which the test
   suite runs. Edge cases get their own tests.
2. **No false positives on real code.** The batch is scanned on reference
   projects (sonda itself, arandu, and a few large open-source projects per
   language), and every finding is reviewed. A rule that misfires is fixed
   or left out; it doesn't ship.
3. **No measurable slowdown.** Each batch is timed on a large repository.
   Queries are compiled lazily per language, so a rule costs nothing for
   languages a project doesn't have.
4. **An actionable message** that says what to change, not only what's wrong.

### Defaults

There will be hundreds of rules per language, and turning all of them on
would bury people in noise. A new rule is **on by default only if
SonarQube's default profile ("Sonar way") enables its key** and it passes
the false-positive review. Other rules are opt-in: the config gains
`[rules] enabled = [...]` next to `disabled` once the first opt-in rule
ships. Category and default severity start from SonarQube's type and
severity, adjusted where sonda's judgment differs (the rule says why).

### Order

Batches of about 25 rules, one language at a time, starting with
JavaScript/TypeScript, where arandu's Node code gives real-world
false-positive checks. Within a language:

1. Bugs and vulnerabilities in the default profile.
2. Code smells in the default profile.
3. The remaining rules.

Each step starts with the `syntactic` tier. Rules that need types or data
flow wait for the semantic layer ([ADR-0008](0008-semantic-layer.md)).

## Consequences

- **The catalog splits per language** (`rules/catalog/{common,js,py,java,c}.rs`)
  so no file grows to tens of thousands of lines.
- **Rule docs show compatibility:** `sonda rules --format json` exposes the
  `sonar` references for tools, and `docs/rules.md` shows them per rule.
- **"All rules" depends on the semantic layer.** About 80 JS/TS rules need
  type information, and Java's symbolic-execution rules need data flow.
  Python and Java have more type-dependent rules than their tags say. Until
  ADR-0008's later phases land, those stay `todo`, and the checklist says so
  honestly.
- **C/C++ parity** needs another source for the rule list (SonarQube's
  commercial editions, or SonarSource's public documentation pages read by
  hand). It waits until one is available.
- **Upkeep:** SonarQube adds rules with each release. Regenerating the
  checklist shows the new ones as `todo`.
