# ADR-0022: Types from the platform's declarations

- Status: **accepted; steps 1 and 2 built, step 3 in part.** The summary,
  its loader, framework base types in the project index, expression
  typing and overload resolution, with twenty-six rules (below).
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
30 of them aren't missing a type checker. They're missing what the .NET
platform declares, which no file of the project says:

| What's missing | Rules |
|---|---|
| A framework type's bases and interfaces: is a `FileStream` disposable, how deep is `Exception`'s chain | S110, S2931, S3215, S3881 |
| The type of an expression or name that goes through a framework member: `GetItems().ToList()`, `File.OpenRead(p)`, an inherited instance member | S1312, S1449, S1698, S1858, S1905, S2325, S3172, S3217, S3242, S4462, S5034, S6602, S6603, S6605, S6608, S6609, S6613, S6966 |
| A framework method's overloads and parameters: is there an `IFormatProvider` or `Uri` overload | S2201, S2234, S3254, S4005, S4055, S4056, S4058 |
| What a framework namespace declares | S1128 |

Today these rules report only what a declaration in the project proves,
`var s = new FileStream(...)` but not `var s = File.OpenRead(...)`, which
keeps them free of false positives and short on recall.

The rest are out of this ADR's scope: four need the project file, not types
(SDK-style projects generate assembly attributes: S3904, S3990, S3992,
S4026), two need taint or inter-procedural analysis (S2077, S5766), and
about 25 were narrowed on purpose, security hotspots among them. Some of
those may move once framework types are known; each is re-audited then.
S2930, first counted with the hierarchy row, is one of them: its
documentation tracks nine named types and four factory methods, not every
disposable.

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
  interfaces and a few attributes (`[Flags]`, `[Obsolete]`, abstract,
  sealed, static); each public or protected member's kind, name, static or
  not, return type, generic arity, and parameters (type, name, `ref`/`out`/`in`,
  optional and its constant default, `params`, caller-information
  attributes, `[StringSyntax]` such as `Regex` or `Uri`), with extension
  methods marked; a constant field's value, an enum member's among them.
  Nothing else: no internal members, no
  documentation. Reference assemblies define `[Pure]` and `[Localizable]`
  but apply them nowhere, so rules that SonarQube documents through them
  (S2201, S4055) can't read them from the summary.
- **Source:** the reference packs of the current .NET LTS, .NET 8 first,
  downloaded by version and checksum.
- **Extraction** is a development tool in the repository (`tools/netref`,
  its own workspace), not part of the shipped crates. It reads the
  assemblies' metadata tables with `cildec` (no dependencies, no unsafe
  code) and writes deflated JSON. `tools/netref/regenerate.sh` downloads
  the packs and checks their SHA-256; the output is committed
  (`crates/sonda-core/data`), deterministic, and regenerated on each LTS.
- **Loading:** workers never open files (ADR-0004), so the summary is
  embedded in the binary and decoded in memory, once per worker on first
  use, with `flate2`'s pure-Rust backend, already a dependency of the CLI
  and server.
- **Budget:** at most 2 MB in the binary, decoded in under 50 ms. Measured:
  .NET 8's two packs give 6,697 types and 63,034 members, 640 KB deflated
  with defaults and constant values, decoded in under 40 ms in a release
  build. Scan time on the seven-project corpus didn't change.
- **Licensing:** the packs' MIT notice ships with the data.

### Names to platform types

The project index ([ADR-0020](0020-cross-file-declarations.md)) resolves
a type name the way C# does, as far as declarations tell:

1. a type nested in the enclosing types, then a project type, which shadows
   a platform type of the same name;
2. a platform type through the namespace and those enclosing it, the
   file's `using` directives, and the project's `global using` ones;
3. the SDK's implicit usings (`System`, `System.IO`, `System.Linq` and the
   rest of `Microsoft.NET.Sdk`'s), when every namespace the file imports is
   the project's or the platform's, so a third-party type of the same name
   can't be taken for a platform one, or when the file imports none of
   those namespaces itself, which projects without implicit usings nearly
   always do (`using System;`).

A name that stays ambiguous or unknown resolves to nothing.

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
`Order.Find`) must not recommend one the project's target lacks. Each
member records whether .NET Standard 2.0 has it with the same signature
(`NETStandard.Library` 2.0.3, read only for that), and a rule recommending
one that it doesn't stays `related` until sonda reads the project's target
framework, which is a separate decision. S6966 is such a rule: its own
example, `File.ReadAllLinesAsync`, and `CancellationTokenSource.CancelAsync`
came after .NET Standard 2.0, so it recommends only what that has.

Overloads follow the same line. A rule that recommends one (S4005, S4056,
S4058) recommends it only when .NET Standard 2.0 has both it and the one
the call binds to, so the call binds the same on every target; their
documented examples all qualify, so the rules are exact, and a newer
overload, `Contains(string, StringComparison)`, costs recall only. Leaving
an argument out (S3254) relies on the parameter's default: the summary
leaves out a default .NET Standard 2.0 doesn't declare for the same member,
as it does for `StreamReader`'s constructors, which gained theirs later.
.NET Standard 2.0 declares no optional parameters at all, so a newer API's
default is kept: a call to it compiles only on a target that has it, and
one that gained its default after it came is the remaining risk.

### Other languages

The same shape fits the others, each with its own decision: TypeScript's
`lib.d.ts`, the JDK's modules for Java, typeshed for Python. This ADR
settles ADR-0008's S4 question for all of them: bundled platform
declarations and light inference, not the project's own checker.

### Order of work

1. **Built.** The extraction tool, the summary, its loader, and framework
   types in the project index. Exact now:
   - S110: depth counts framework base classes, and Object, as
     SonarQube's documentation counts "starting from Object";
   - S3881: the whole documented pattern, including a re-listed
     `IDisposable` when a base already implements it, explicit
     implementations, and base calls in derived classes;
   - S2931: fields a class creates with `new`, in an initializer or any
     member, whose type is disposable through the project or the platform;
   - S3215: casts of a variable whose declared type is an interface to a
     class or struct, both resolved in the project or the platform.

   On the corpus, the new findings are all true positives under the
   documentation: explicit `IDisposable.Dispose` (JsonReader, JsonWriter),
   classes listing `IDisposable` without `Dispose(bool)` next to a project
   base class, `StringWriter` and `TextWriter` fields in non-disposable
   classes, and generic interface casts. Casts of third-party interfaces
   (xUnit's `ITestOutputHelper`) are no longer reported: their type is
   unknown.
2. Expression typing through framework members (`semantic/cs_infer.rs`):
   a type for names, `var` initializers, member access, calls (overloads
   by number of arguments, all candidates agreeing), `new`, casts,
   `await`, indexers, literals and `foreach` variables; members found on
   the nearest type declaring the name, base classes before interfaces,
   with generic arguments substituted; extension methods from imported
   namespaces, binding the method's type parameters from the receiver.
   Object's own methods (`ToString`, `GetType`) type on any receiver.

   **2a, built.** Exact now: S1449, S1858, S4462, S6602, S6603, S6605,
   S6608, S6609 and S6613; S6966 stays `related` (above). Each was
   re-audited against its documentation, which changed two of them beyond
   types: S1858 no longer reports value types, its documented exception,
   or interpolation, which it doesn't document; S4462 reports
   `Task.WaitAny`, `Task.WaitAll` and `Thread.Sleep` in async methods, and
   leaves out what its documentation does (Main methods, tasks from
   `Task.Run` or `Task.Factory.StartNew`), while a task awaited through
   `Task.WhenAll`, which it doesn't document, is now reported. A call on an
   `IQueryable`, which may be `Queryable`'s, isn't taken for LINQ's.

   The SDK's implicit usings apply when nothing a file imports could
   declare a name instead, or when the file imports none of their
   namespaces itself: projects without implicit usings write `using
   System;` in nearly every file.

   On the corpus, the collection rules went from 12 findings to 49, mostly
   arrays from reflection (`GetMethods()`, `GetInterfaces()`) and lists
   returned by calls, all true positives; the others' new findings are too.
   Calls on lambda parameters and on types from other files of the project
   stay unknown.

   **2b, built.** Conversions between types: identity, implicit (to a base
   class or an interface, boxing, a wider number, a nullable), explicit,
   and through a conversion operator one of the types declares; and C#'s
   numeric promotion, which `i + 42` needs. Exact now:
   - S1905: casts to the type a value already has, anywhere, but to float
     or double of a computed value, which the cast rounds; implicit ones
     where the context asks for that type anyway (a declared variable's
     initializer, a plain assignment, what a member returns); and
     `Cast<T>()` on a sequence of T, `OfType<T>()` on one of a value type.
   - S3217: `foreach` conversions only a cast makes; collections of
     objects and conversion operators are left alone, as documented.
   - S3172: also through a variable holding a chain, as the documented
     example subtracts one.
   - S5034: a ValueTask consumed twice, by `await`, `AsTask()`, `.Result`
     or `GetResult()`, reported at the second; `.Result` before
     `IsCompleted` says it's done, also on a call's result. Uses in a loop
     and in exclusive branches aren't counted.
   - S1312: fields of the documented frameworks' logger types, however
     they're created, as the documentation says; a name resolves through
     usings and enclosing namespaces, and one two frameworks in scope
     declare is left alone, as C# leaves it ambiguous.
   - S1698: `==` on an interface that a class overriding Equals implements,
     the platform's or the file's, or on a class overriding Equals without
     `==`; the documented exceptions are kept.
   - S2325: methods and properties of any accessibility, as documented,
     inherited instance members counted through base classes that
     resolve. Left out, besides the documented ASP.NET events: what can't
     be static (overrides, interface implementations, and the public
     methods of controllers, pages, components and hubs, which ASP.NET
     calls on an instance, by the documentation's own reason for its
     exceptions), members with attributes, and types whose base class
     doesn't resolve, which may be Windows Forms' or WPF's.
   - S3242: any base class or interface declaring every member a
     parameter's uses reach, with the same signatures, extension methods
     binding alike; not only `IEnumerable<T>`. Parameters used otherwise,
     `params` arrays, attributed ones, and those of methods that can't
     change their signature are left alone.

   Re-auditing changed four beyond types: S1312 now reports injected
   loggers, which the documentation's own example is; S3217 no longer
   reports collections of objects, a documented exception; S2325 reports
   public members and properties; S3242 suggests any base type.

   On the corpus: S1312 went from 7 findings to 30, S1698 from 0 to 1,
   S1905 from 39 to 50, S2325 from 72 to 132 and S3242 from 13 to 34, all
   true positives under the documentation; S3172, S3217 and S5034 find
   nothing there, as before. S2325 no longer reports 15 members of classes
   whose first base type is declared in another file, which may be a base
   class; S3242 no longer reports 4 parameters whose element type is.
   Scan time didn't change; the file's declarations are read once and
   shared by every rule that types expressions.
3. Overloads and parameters (`semantic/cs_infer/resolve.rs`): the method
   a call binds to, chosen as C# chooses, among the methods its name finds
   through the type's base classes (an override counted with what it
   overrides, a derived type's applicable methods hiding a base type's),
   then extension methods: by the parameter each argument goes to (named,
   optional, `params` expanded or not), whether each converts implicitly
   (a constant to a narrower integer, `null`, `default`), the method's own
   type parameters bound from the arguments, and the better conversion
   between candidates. A lambda for a delegate parameter, an argument of
   unknown type for anything but `object`, a partial type, or a base type
   that doesn't resolve leaves the call unresolved. Constants evaluate too:
   literals, `default`, constant fields and enum members.

   **3a, built.** Exact now:
   - S2234: two variables passed positionally, named after parameters of
     the method the call binds to, in the other order.
   - S3254: an argument equal to its parameter's default that the call can
     leave out and still bind to the same method: a named one, or a
     positional one with only such arguments, or named ones, after it.
     Parameters an attribute fills (`[CallerMemberName]`) are left alone.
   - S4005: a string passed to a parameter whose name contains "uri",
     "urn" or "url" (in either case of their first letter), when the type
     declaring the method has the same overload with a `System.Uri` there.
   - S4056: a member called without an `IFormatProvider` or `CultureInfo`
     when the same overload with one more exists and isn't obsolete.
     Constructors count, as the documentation says members; its three
     named methods, and those whose documentation says the provider is
     reserved or ignored (`bool`, `char` and `string`'s `ToString`,
     `Guid.ToString(string)`, `Convert` of a bool, char or string), are
     left alone; `Convert.ToString(object)` is reported only for a value
     that formats, and `TimeSpan.ToString(string)` only for a standard
     format, as a custom one ignores the provider.
   - S4058: a string method called without a `StringComparison` when the
     same overload with one exists: `Compare` and `Equals`, as documented,
     and `StartsWith`, `EndsWith`, `IndexOf`, `LastIndexOf`.

   Re-auditing changed three beyond types: S4056 reports any member with
   such an overload, `int.Parse`, `ToUpper()`, `new StringWriter()`,
   instead of formatting calls only; S4058 reports `Equals`; S2234 no
   longer needs every argument to be a variable.

   On the corpus: S4005 went from 0 findings to 32 (`HttpClient` calls
   with a string address), S3254 from 1 to 2, S4056 from 47 to 447 (238 of
   them `StringWriter` constructors in tests), S4058 from 68 to 54, all
   true positives under the documentation; S2234 finds nothing there, as
   before. Of those no longer reported, 3 were false positives
   (`Guid.ToString("N")`, Newtonsoft's own `StringReference.StartsWith`);
   the others have receivers whose type doesn't resolve (lambda
   parameters, other files' types), a `using static` constant, or a type
   newer than .NET Standard 2.0 (`DateOnly`). With the default rules, scan
   time didn't change; each of the five, off by default but S2234, adds
   at most 0.15 s to the largest project, since a call is resolved only
   when its name or arguments could matter.

   **3b:** S1128; S2201 and S4055 with their documented lists.

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

- A generated data file in the repository and 640 KB more in the binary,
  regenerated on each .NET LTS.
- A development tool with its own metadata-reading dependency, outside the
  shipped crates and their dependency policy.
- About 30 C# rules can become `exact` without giving up the
  no-false-positive bar, and third-party types stay unknown. Steps 1 to 3a
  made 26 exact.
- ADR-0008's S4 row points here.
