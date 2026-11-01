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

A rule on the model is `exact` when it implements its key's documented
behavior: SonarQube's description, examples and listed exceptions, no more
and no fewer. A name whose type the file doesn't declare then gives no
finding, which costs recall, not scope. It stays `related` when it checks
fewer patterns than documented, narrows them on purpose to avoid false
positives, or depends on declarations that usually live in other files
(base classes, interfaces, enums). Rules from the batches before the model
were re-audited against this bar; those it could make exact moved to
`cs_semantic.rs` with their ids unchanged.

Rules that need declared types are `Check::Semantic`. Walking up from a
node to find its scope costs that node's depth for every `parent()`, which
made a query-based version quadratic on deeply nested code; the model is
built in one walk instead.

### Project-level rules

Two rules need the whole project: a partial method implemented in no file
(S3251), and a missing NeutralResourcesLanguage in a project that uses
resources (S4026). They use the facts channel the Java package rules
introduced (`analysis.rs`): each C# file reports its partial methods, keyed
by namespace, type, name and arity, and whether it uses a ResourceManager.
A pass over all files then reports what no file completes. Generated files
(`.designer.cs`, `.g.cs`, an `<auto-generated>` header) declare optional
hooks on purpose, so only their implementations count.

Rules about assembly attributes (version, CLS compliance, COM visibility)
look at hand-written AssemblyInfo files only, the ones with AssemblyTitle
and the like. SDK-style projects generate those attributes from the project
file, which sonda doesn't read.

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
- Three SonarQube C# rules have no sonda counterpart, on purpose:
  - **S1944, invalid casts.** The compiler already rejects casts the
    declared types make impossible. What's left fails at run time:
    `object o = GetValue(); var i = (int)o;` throws when `GetValue()`
    returns a boxed `long`. Telling needs the values that reach the cast,
    and the return types of methods declared in other files, which
    SonarQube gets from data flow over typed code.
  - **S3220, calls resolving to a `params` overload.** It reports a call
    the compiler binds to a `params` overload while another overload also
    applies. Telling which overload a call binds to is C#'s overload
    resolution: argument types, implicit conversions, generics, inherited
    overloads.
  - **S6802, lambdas in loops in Blazor markup.** It checks `.razor` files,
    which mix HTML and C#; sonda parses `.cs` only.

  Approximating S1944 and S3220 from declarations would guess, and both are
  in SonarQube's default profile, so a guess would mean false positives in
  every project. What would unblock them: type checking (ADR-0008's phase
  S4, which needs its own ADR; running Roslyn was rejected above because it
  needs .NET at scan time) for S1944 and S3220, and a Razor grammar, with
  the same review this ADR gave tree-sitter-c-sharp, for S6802. The parity
  report lists them as known gaps (`scripts/sonar_parity.py`).
