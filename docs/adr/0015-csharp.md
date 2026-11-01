# ADR-0015: C# support

- Status: **proposed**
- Date: 2026-10-31

## Context

The SonarQube rule parity effort ([ADR-0007](0007-sonarqube-rule-parity.md))
covers the languages sonda analyzes: JavaScript/TypeScript, Python, Java and
C/C++. C# is the next language teams moving from SonarQube ask about. Its
analyzer ships with SonarQube's free edition, so, unlike C/C++, the rule
list and the default profile are available from the same server the other
languages are measured against.

sonda doesn't parse C# yet. Rules need a grammar, and the metrics
(functions, complexity, comments, duplication) need C#'s node kinds.

## Decision

### Grammar

[tree-sitter-c-sharp](https://github.com/tree-sitter/tree-sitter-c-sharp)
0.23.5, the grammar maintained by the tree-sitter organization:
- MIT licensed, like the other grammars;
- generated C code plus an external scanner, so it joins the C surface that
  worker isolation ([ADR-0003](0003-isolate-parsing.md),
  [ADR-0004](0004-sandbox-workers.md)) contains and the fuzzer exercises. The
  `analyze` fuzz target picks languages from `lang::ALL`, so it covers C#
  once listed; a C# seed joins the corpus;
- no runtime dependencies beyond `tree-sitter-language`, already in the tree.

There is no maintained alternative. Roslyn, the real C# compiler, would need
.NET at scan time, which a single binary can't assume.

### The language

- `Lang::CSharp`, id `csharp`, for `.cs` files. It goes last in
  `lang::ALL`, whose order is a stable one-byte encoding.
- Metrics map C#'s declarations onto the shared `Syntax` table: methods,
  constructors, finalizers, operators, accessors, local functions, lambdas
  and anonymous methods are functions; `switch` statements and expressions
  are switches; their sections and arms are cases, except `default:` and the
  discard arm `_ =>`.
- Rule ids are `cs/...`, and the rules live in `rules/catalog/cs*.rs`.

### Rules

ADR-0007 applies unchanged: clean-room rules from each SonarQube rule's
intent, `sonar` references by key, a false-positive review on real code, a
timing check, and on by default only when SonarQube's default profile
enables the key. `scripts/sonar_parity.py` maps SonarQube's `cs` language to
sonda's `csharp`.

The first batch reviewed its findings on five open-source projects
(Newtonsoft.Json, Polly, AutoMapper, Serilog and MediatR, 2,646 files); the
scan took under a second per project.

### Preprocessor directives

tree-sitter doesn't run the preprocessor. `#if`/`#else` blocks that split a
declaration or an expression (both branches of a multi-targeted library,
say) parse with errors: about 3% of the reviewed files, most of them in
Newtonsoft.Json. sonda reports such files with its usual "contains syntax
errors" warning and still analyzes the rest of the tree. Rules must
not assume an error-free tree; the review showed no false positives from
the recovered parts.

### Semantic layer

C# gets ADR-0008's phase S1, scopes and symbols (`semantic/cs.rs`): one
iterative pass declares parameters, locals, `foreach`, pattern and `out`
variables, fields, properties and methods, and links every name in an
expression to its declaration, with `this.x` resolved in the enclosing type.
C# forbids using a local before its declaration and shadowing one, so
resolving within the whole scope finds what the compiler finds.

Each declaration also keeps the type written where it's declared: `int`
in `int x`, `T` in `var x = new T()`. That's syntax, not inference, so it
stays within S1 and needs none of S4's decisions. Rules use it to
approximate SonarQube's typed rules (`rules/catalog/cs_types.rs`): a
rule reports only what declarations in the file prove, and is `related`
to its SonarQube key when typed analysis would find more. What it can't
see: inherited members, types inferred across calls, and other files.

Rules that need declared types are `Check::Semantic`. Walking up from a
node to find its scope costs that node's depth for every `parent()`, which
made a query-based version quadratic on deeply nested code; the model is
built in one walk instead.

## Consequences

- One more grammar to keep updated and fuzz. Grammar updates follow the same
  process as the others.
- Rules that need declared types use the C# semantic model above. Rules
  that need flow or inference (nullable flow, values reaching a call) wait
  for ADR-0008's later phases.
- Some grammar quirks need a rule-side workaround. For example, the grammar
  reads `x is true || y` as `x is (true || y)`, so a rule about boolean
  literals ignores operators inside patterns.
- The parity table has a C# row and `cs.csv`. SonarQube 26.7 has 446 C#
  rules; the first batch covers 51 keys and partly covers 3. Three of its
  rules are outside the default profile, so they are opt-in.
