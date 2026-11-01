# ADR-0019: Declarations across files

- Status: **proposed**
- Date: 2026-11-01

## Context

[ADR-0008](0008-semantic-layer.md) builds the semantic layer per file and
leaves cross-file analysis for later, "because it touches the worker
model". Some rules can't be right per file:

- an override has to match the method it overrides, and an implementation
  the interface member it implements, usually in another file;
- inheritance depth, hidden base methods and base fields differing by case
  depend on base classes, usually in other files.

The C# versions of these rules (batch 12, [ADR-0015](0015-csharp.md))
compared with declarations in the same file only. On seven open-source
projects, `cs/parameter-name-mismatch` found 5 mismatches that way, and 88
once other files were visible. Those rules were marked `related` for that
reason.

Something already crosses the worker boundary: the facts each file reports,
small (kind, value) strings the scanner gathers after analysis. The Java
package rules (S4605, package-info) and two C# project rules (partial
methods, the neutral resources language) use them.

## Decision

**Each worker summarizes the declarations its file makes, and the scanner
indexes the summaries.** Rules that compare declarations across files run
once per scan, on that index.

- **The summary** (`semantic/cs_index.rs`):
  - the file's types, with their namespace, enclosing types, generic arity, modifiers, attributes and base types;
  - their members, with modifiers, return type and parameters (name, type, default, `params`);
  - positions as issue spans;
  - the file's `using` directives.

  It is extracted by one iterative walk that skips member bodies (C# declares no types there), and travels as one JSON fact per file.
- **No syntax tree leaves the sandbox.** The summary is data the scanner parses with serde. A malformed one (from a compromised worker, say) is dropped, and that file's declarations are missing from the index.
- **The index** (`ProjectIndex`):
  - It groups the parts of partial types by full name.
  - It resolves a type name as C# does at the level summaries allow: by simple name and arity, then narrowed to the namespaces visible from the referencing file (its own, enclosing ones, and its `using` directives).
  - A name that stays ambiguous resolves to nothing.
- **The rules** are `Check::Structural`. They keep their ids and their catalog entries, and their checks live in `rules/catalog/cs_project.rs`. Findings point at the exact parameter, member or type, not at column 1.
- **Their examples and tests** run the project pass over the example as a project of one file, so bad/good examples remain tests (ADR-0007).

The first rules on the index are ten C# rules:
- parameter names (S927), defaults (S1006) and `params` (S3262, S3600) against the declaration overridden or implemented;
- base methods hidden by private (S4015) or wider (S4019) methods;
- inheritance depth (S110);
- colliding interface members (S3444);
- base fields differing by case (S4025);
- the dispose pattern (S3881).

## Consequences

- **What stays unseen:** types from referenced assemblies (NuGet packages, the framework) aren't in the project, so they resolve to nothing. That costs recall: an `Equals(object other)` override isn't compared with `object.Equals(object obj)`. By ADR-0015's bar, a rule that implements its key's documented behavior on every declaration in the project is `exact`. Eight of the ten are now. S110 stays `related`, because SonarQube counts framework base classes too. S3881 stays `related`, because it checks part of SonarQube's list.
- **Cost:** extraction skips member bodies, so the scan time of the seven reference projects is unchanged (3.0 s). The project pass parses one JSON summary per C# file. The summaries hold declarations only, a small fraction of each file's size.
- **The worker model is unchanged.** Workers still analyze one file each and return facts; only what a fact can carry grew. A rule that needs more than declarations from other files (call graphs, data flow across calls) still needs a decision of its own.
- **More rules can move to the index:**
  - bitwise operations on enums declared elsewhere (S3265);
  - arrays passed to `params` methods of other files (S3878);
  - extensions in the namespace of the extended type (S4226);
  - action models declared elsewhere (S6964);
  - shared MEF parts and durable entity interfaces (S4277, S6424).

  Other languages can use the same scheme when their rules need it, Java first.
