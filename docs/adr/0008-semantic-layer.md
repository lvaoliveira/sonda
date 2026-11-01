# ADR-0008: A semantic layer for deeper rules

- Status: **accepted; S1 in progress.** It's built in phases, after the
  first syntactic rule batches of [ADR-0007](0007-sonarqube-rule-parity.md).
  S1 is built for JavaScript/TypeScript (`semantic/`), with twelve rules,
  and for C# ([ADR-0015](0015-csharp.md)), whose declarations also keep
  their written types; the rest of S1 is on the [roadmap](../roadmap.md).
- Date: 2026-10-30

## Context

sonda's rules are tree-sitter queries with small Rust filters. They see
syntax, not meaning. Many of SonarQube's rules need more:

- **Names:** "unused local variable", "variable shadows a parameter", "used
  before it is declared". These need to know which declaration each name
  refers to.
- **Control flow:** "unreachable code", "all branches are identical",
  "function does not always return a value". These need the paths through a
  function.
- **Data flow:** "dead store", "condition is always true", "null
  dereference" (Java's symbolic-execution rules). These need values
  followed along those paths.
- **Types:** about 80 JS/TS rules tagged type-dependent, plus many untagged
  Python and Java rules ("comparing incompatible types", "awaiting a
  non-promise").

## Decision

A **semantic layer** in sonda-core's domain (`semantic/`), built per file
inside the sandboxed workers, like the rest of analysis. It comes in
phases, each unlocking a set of rules:

| Phase | Builds | Unlocks |
|---|---|---|
| **S1: scopes and symbols** | Declarations, references and resolution per scope. Each grammar's binding rules come from tree-sitter "locals" queries where a grammar ships them, plus small per-language Rust where it doesn't. | unused variables, imports and parameters; shadowing; undeclared and redeclared names |
| **S2: control flow** | A control-flow graph per function: branches, loops, `try`/`catch`/`finally`, early returns. | unreachable code; identical branches; inconsistent returns; empty or infinite loops |
| **S3: data flow** | Analyses over the graph: reaching definitions, constant propagation, and nullness. Each is a bounded fixed-point computation, never path enumeration. | dead stores; always-true or always-false conditions; null dereferences; values used before assignment |
| **S4: types** | **Open; needs its own ADR.** | type-dependent rules |

For S4, there are two options:
- **(a) Light inference:** literals, declared types (TypeScript, Java,
  Python annotations), and simple flow typing. Pure Rust and safe, but
  partial.
- **(b) Run the language's real type checker** (`tsc`, `javac`, a Python
  type checker). Complete, but it means running the analyzed project's
  toolchain and configuration, which collides with sonda's rule never to
  execute anything from the analyzed repository (ADR-0002, ADR-0003).

Type-dependent rules wait for that ADR.

### Rules on top

Rules gain a third kind of check, next to query and structural:
`Check::Semantic`, a Rust function over the file's semantic model that
returns findings. The rule catalog, examples, false-positive review and
`sonar` references are unchanged (ADR-0007).

### Safety and limits

Same guarantees as today:
- runs in the sandboxed workers;
- no recursion over trees;
- work bounded by the per-file time budget, with iteration caps on every
  fixed-point loop;
- deterministic output;
- fuzzed like the parser.

A file that exhausts a budget loses only its semantic findings, with a
warning, not its syntactic ones.

### Scope limits

**Per file only.** Cross-file rules (unused exports, call-graph taint)
need project-wide summaries. That's a later decision, because it touches
the worker model. [ADR-0019](0019-cross-file-declarations.md) takes the
first step without changing it: files report summaries of their
declarations, and rules that compare declarations across files run on an
index of them.

## Consequences

- **Each phase ships with the rules it unlocks**, so its value and cost are
  visible together. S1 comes first, because unused and undeclared names are
  among SonarQube's most common default rules.
- **Writing rules gets cheaper.** Rules written before a phase lands stay
  query-based. Rules that only approximate an idea syntactically are marked
  `related` in their `sonar` references until a semantic version replaces
  them.
- **Time budget:** the per-file budget now covers more work. Each phase is
  benchmarked like a rule batch, on a large repository.
