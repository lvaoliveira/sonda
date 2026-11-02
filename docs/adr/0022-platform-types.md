# ADR-0022: Types from the platform's declarations

- Status: **proposed**
- Date: 2026-11-02

## Context

[ADR-0008](0008-semantic-layer.md) leaves phase S4, types, open between
two options: light inference in Rust, which is safe but partial, or the
language's own type checker, which is complete but means running the
analyzed project's toolchain. sonda's analysis runs in workers that parse
what they're given and nothing more ([ADR-0003](0003-isolate-parsing.md)):
they never open files, use the network or start processes
([ADR-0004](0004-sandbox-workers.md)).

C# is where the question is concrete. 61 of its SonarQube rules are
`related`, not `exact` ([ADR-0015](0015-csharp.md)). Read one by one, about
half of them aren't missing a type checker. They're missing what the .NET
platform declares, which no file of the project says:

| What's missing | Rules |
|---|---|
| A framework type's bases and interfaces: is a `FileStream` disposable, how deep is `Form`'s chain | S110, S2325, S2930, S2931, S3215, S3881 |
| The type of an expression that goes through a framework member: `GetItems().ToList()`, `File.OpenRead(p)`, `client.GetAsync(u)` | S1312, S1449, S1698, S1858, S1905, S3172, S3217, S3242, S4462, S5034, S6602, S6603, S6605, S6608, S6609, S6613, S6966 |
| A framework method's overloads, parameters and attributes: is there an `IFormatProvider` or `Uri` overload, is the method `[Pure]`, is the parameter `[Localizable]` | S2201, S2234, S3254, S4005, S4055, S4056, S4058 |
| What a framework namespace declares | S1128 |

Today these rules report only what a declaration in the project proves,
`var s = new FileStream(...)` but not `var s = File.OpenRead(...)`, which
keeps them free of false positives and short on recall.

The rest are out of this ADR's scope: four need the project file, not types
(SDK-style projects generate assembly attributes: S3904, S3990, S3992,
S4026), two need taint or inter-procedural analysis (S2077, S5766), and
about 24 were narrowed on purpose, security hotspots among them. Some of
those may move once framework types are known; each is re-audited then.

The platform's declarations are published as data. `Microsoft.NETCore.App.Ref`
and `Microsoft.AspNetCore.App.Ref` are the reference assemblies the compiler
itself reads: public signatures only, no code, MIT-licensed. .NET 8's has
163 assemblies, 5.7 MB, declaring about 4,000 types, 47,000 methods, 8,700
properties and 7,700 fields.

## Decision

**S4 is light inference over declared types, plus the platform's
declarations bundled with sonda as data.** sonda never runs the analyzed
project's toolchain, and never reads a machine's SDK or package cache: the
same scan gives the same result everywhere.

### The platform summary

- **Contents:** each public type's full name, arity, kind, base type,
  interfaces and a few attributes (`[Flags]`, `[Obsolete]`); each public
  member's kind, name, static or not, return type, and parameters (type,
  default, `params`, `this` for extension methods); and the attributes
  rules read (`[Pure]`, `[Localizable]`). Nothing else: no internal
  members, no documentation.
- **Source:** the reference packs of the current .NET LTS, .NET 8 first,
  downloaded by version and checksum.
- **Extraction** is a development tool in the repository (`tools/`), not
  part of the shipped crates. It reads the assemblies' metadata tables
  and writes the summary in a compact format: interned names, compressed.
  The output is committed, with the pack versions it came from, and
  regenerated on each LTS.
- **Loading:** workers never open files (ADR-0004), so the summary is
  embedded in the binary and decoded in memory, once per worker on first
  use. A compressed format needs a pure-Rust decoder, which goes through
  the dependency policy like any other.
- **Budget:** at most 2 MB in the binary, decoded in under 50 ms. Measured
  before this ADR is accepted.
- **Licensing:** the packs' MIT notice ships with the data.

### Inference on top

C#'s semantic model (`semantic/cs.rs`) and the project index
([ADR-0020](0020-cross-file-declarations.md)) already know declared types
and project declarations. Expression typing (`cs_types::expression_type`)
extends them with the summary:

- member access and calls on a known type, through its bases, the
  project's and the framework's: `File.OpenRead(p)` is a `FileStream`;
- one level of generic substitution: `List<Order>.Find(...)` is an `Order`,
  `Task<T>` awaited is a `T`;
- extension methods from the namespaces a file imports, LINQ first:
  `orders.Where(...).ToList()` is a `List<Order>`;
- `var`, `foreach` variables and lambda parameters from those.

What it doesn't do: overload resolution beyond the number of arguments and
literal kinds, type inference across method calls, nullable flow, and
dynamic. When it can't tell, an expression has no type, and rules report
nothing, which costs recall only. That keeps ADR-0015's bar for `exact`:
a rule implements its key's documented behavior, and a type nobody
declares, a third-party package's, costs recall.

### Framework versions

The summary describes one framework version, and projects target others.
Rules that only read declarations (is this type disposable?) are stable
across versions. Rules that recommend an API (use `string.Create`,
`Order.Find`) must not recommend one the project's target lacks: each
member records whether .NET Standard 2.0 has it, and rules recommending
one that it doesn't stay `related` until sonda reads the project's target
framework, which is a separate decision.

### Other languages

The same shape fits the others, each with its own decision: TypeScript's
`lib.d.ts`, the JDK's modules for Java, typeshed for Python. This ADR
settles ADR-0008's S4 question for all of them: bundled platform
declarations and light inference, not the project's own checker.

### Order of work

1. The extraction tool, the summary, its loader, and framework bases in the
   project index's inheritance: S110, S2325, S2930, S2931, S3215, S3881.
2. Expression typing through framework members: the 17 rules of the second
   row above.
3. Overloads, parameters and attributes: S2201, S2234, S3254, S4005, S4055,
   S4056, S4058, then S1128.

Each step re-audits its rules against the corpus, as ADR-0007 requires,
before marking them `exact`.

## Alternatives

- **Run Roslyn.** Complete, but it needs a .NET runtime next to sonda and
  the project's restore and build, which runs the project's MSBuild logic,
  outside the sandboxed workers of ADR-0003 and ADR-0004.
- **Read the machine's SDK or NuGet cache at scan time.** No data to ship,
  but results would change with what is installed, and workers can't open
  files.
- **Hand-written stubs for the types rules mention.** Small, but the
  questions are open-ended (which of hundreds of framework types are
  disposable, which methods have a culture overload), and stubs drift.

## Consequences

- A generated data file in the repository and about 1 MB more in the
  binary, regenerated on each .NET LTS.
- A development tool with its own metadata-reading dependency, outside the
  shipped crates and their dependency policy.
- About 31 C# rules can become `exact` without giving up the
  no-false-positive bar, and third-party types stay unknown.
- ADR-0008's S4 row points here.
