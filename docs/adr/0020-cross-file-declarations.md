# ADR-0020: Declarations across files

- Status: **accepted; built** (2026-11-07). Each worker summarizes its
  file's declarations, and the C# rules that compare with base types,
  interfaces and partial methods read the index (`semantic/cs_index.rs`).
  Recorded as accepted when the 1.0 plan checked each ADR's status against
  what's built. Extended to Java on 2026-11-11 (`semantic/java_index.rs`,
  [below](#java)), and to C++ on 2026-11-14 (`semantic/cpp_index.rs`,
  [below](#c)).
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
- **Use sites.** A use in one file can need a declaration from another: `Color.Red | Color.Blue` is wrong only if `Color` has no `[Flags]`. So the summary also lists such sites, by kind, with the type or method they name, their namespace, the type they're written in, and their span. A site that names a variable needs its declared type, which the semantic model gives. The extractor builds the model only when such a site exists.
- **The rules** are `Check::Structural`. They keep their ids and their catalog entries, and their checks live in `rules/catalog/cs_project.rs`. Findings point at the exact parameter, member or type, not at column 1.
- **Their examples and tests** run the project pass over the example as a project of one file, so bad/good examples remain tests (ADR-0007).

The rules on the index are eighteen C# rules:
- parameter names (S927), defaults (S1006) and `params` (S3262, S3600) against the declaration overridden or implemented;
- base methods hidden by private (S4015) or wider (S4019) methods;
- inheritance depth (S110);
- colliding interface members (S3444);
- base fields differing by case (S4025);
- the dispose pattern (S3881);
- disposable fields in classes that aren't disposable (S2931);
- on use sites:
  - bitwise operations on enums without `[Flags]` (S3265);
  - arrays written out for `params` parameters (S3878);
  - shared MEF parts created with `new` (S4277);
  - extensions in the namespace of the type they extend (S4226);
  - durable entity interfaces (S6424);
  - controller action models with under-posted value types (S6964);
  - interface references cast to concrete types (S3215).

## Java

Compared with SonarQube on Apache Commons Lang, about seventy of the Java
differences left came from declarations in another file: an override whose
parent is elsewhere, a field whose type is, a superclass defining `equals`,
a constructor taking varargs. Java uses the same scheme:

- **The summary** (`semantic/java_index.rs`) holds the file's package, its
  single-type and on-demand imports, the types it declares at any depth
  (kind, modifiers, type parameters and their bounds, superclass and
  interfaces, fields, methods and constructors with their parameter types,
  varargs, annotations, and whether a method only calls the same method of
  `super`), and the calls whose last argument is an array literal. It
  travels as one JSON fact per file, `java-index`.
- **Names resolve as Java resolves them**, at the level summaries allow:
  the types nested in the enclosing types and their supertypes, the file's
  single-type imports, its package, then its on-demand imports, where a
  name found twice resolves to nothing. A qualified name is a full name or
  a type nested in one the file sees.
- **The JDK isn't in the project.** A few of its types are known by name:
  which classes are serializable or define `equals`, which aren't
  serializable, how deep common superclasses are. Any other outside type
  gets the benefit of the doubt.
- **The rules** move from per-file queries to `Check::Structural`, checked
  in `rules/catalog/java_project.rs`, with the same ids: useless overrides
  (S1185), non-serializable fields (S1948), subclasses adding fields to an
  `equals` (S2160), arrays passed as varargs (S3878), abstract methods an
  interface declares (S3038), overrides dropping `synchronized` (S3551),
  inheritance depth (S110), and, after a Spring Boot application's
  comparison, overrides without `@Override` (S1161), static methods
  reached through a subclass (S3252) and class coupling (S6539), which
  counts the project's types and not a library's; then, after eGovFrame's,
  generic exceptions declared without a callee passing one on (S112) and
  wildcards in return types, at the interface (S1452), from the calls and
  return types the summary also records. Each was measured on
  SonarQube 26.7 with files of their own, the parent or the callee in
  another file.
- **Suppressions**: the summary's file also reports its lines with
  `NOSONAR` or `sonda-ignore`, and the declarations `@SuppressWarnings`
  covers, which silence what the project pass finds.

On Commons Lang, the seven rules went from 73 differences to none. Its scan
(638 Java files) takes 3.9 s where it took 3.7 s, median of five on 12
workers.

## C++

Compared with SonarCloud on roo_display and qutepart-cpp, a C++ class's
bases are usually in another file: a header the class's file includes.
S1242, a member function hiding a base's function of the same name, can't be
decided without them. C++ uses the same scheme, with less to resolve by:

- **The summary** (`semantic/cpp_index.rs`) holds the classes and structs
  the file defines, at any depth, a class defined in a function body
  included: the namespaces and classes around each, its bases as written
  (without template arguments), its member functions (name, parameter
  types, whether `virtual`, `override` or `final`, `static`, private), its
  data members (name, type) and the names its `using Base::name;`
  declarations bring in. It travels as one JSON fact per file, `cpp-index`.
- **Names resolve by namespace, not by include.** C++ has no imports to
  narrow a name: which declarations a file sees depends on its `#include`s
  and the build's flags, which sonda doesn't know. A base resolves by its
  simple name, among the classes whose namespaces end with how it's
  qualified (`gfx::Output`), to the one sharing most of the derived class's
  namespaces; two equally close candidates resolve to nothing, unless
  they're the same class in two files (a header copied into a test).
- **Parameter types compare without namespaces** (`Color*` and
  `roo_display::Color*` are one type), with whitespace removed, as written:
  a typedef and its target don't match.
- **The rule** is `cpp/hidden-inherited-function` (S1242), checked in
  `rules/catalog/cpp_project.rs`: a public or protected member function
  named like a function of one of its bases, which it hides, when that one
  isn't private nor virtual (nor virtual further up, with as many
  parameters), or when the bases' are all virtual and some aren't
  overridden here. Every base counts, as SonarCloud counts them: a function
  an intermediate class hides already is reported again in the classes
  below. A `using Base::name;` in the class brings the bases' back.

On roo_display it finds 30 of SonarCloud's 32, and 20 it doesn't. The 2 left
derive from Arduino's `Print`, outside the project. 18 of the 20 are three
font classes overriding `Font`'s virtual overloads while `Font` also has
non-virtual ones, the shape SonarCloud reports for every other base, which
nothing visible sets apart; one more derives from a class template's
instance. qutepart-cpp's 2 derive from Qt classes, which aren't in the
project. Scanning roo_display (479 C and C++ files) takes 0.67 s
where it took 0.61 s, and qutepart-cpp 0.36 s as before, median of five on
12 workers.

## Consequences

- **What stays unseen:** types from referenced packages aren't in the project, so they resolve to nothing. That costs recall. The framework's own types do resolve, through the summary of its reference packs ([ADR-0022](0022-platform-types.md)). By ADR-0015's bar, a rule that implements its key's documented behavior on every declaration in the project is `exact`, and all eighteen are.
- **Cost:** extraction is one cursor walk that copies no member bodies, and builds the semantic model only for files with a site that needs it. The scan time of the seven reference projects is unchanged (3.0 s). The project pass parses one JSON summary per C# file. The summaries hold declarations and sites only, a small fraction of each file's size.
- **The worker model is unchanged.** Workers still analyze one file each and return facts; only what a fact can carry grew. A rule that needs more than declarations from other files (call graphs, data flow across calls) still needs a decision of its own.
- **Other languages can use the same scheme** when their rules need it; Java
  does since 2026-11-11, C++ since 2026-11-14.
- **C++ resolves less than C# or Java.** Without the build's includes and
  flags, a base resolves by namespace alone, every `#if` branch is read,
  and a macro is taken as written. A rule on the C++ index reports nothing
  about a base it can't settle, so what this costs is recall.
